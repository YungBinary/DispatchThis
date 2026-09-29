"""OLLVM_XOR_64: 64-bit state split across a register pair, recombined with XOR.

The dispatcher does not hold its state in one variable. Two registers (``r14``
and ``rdi`` in the reference sample) carry halves, and the dispatcher head
rebuilds the state with a single 64-bit XOR::

    rax_4 = r14
    rax_5 = rax_4 ^ rdi          <- the state the compare tree routes on

Routing is a binary search tree over that state. Interior nodes compare
relationally; leaves compare for equality, and a leaf's *equal* edge falls into
an original block while its other edge goes back to the dispatcher. Neither kind
compares against a bare immediate -- an ``lea`` materialises the compare value as
``base + displacement``, where ``base`` is a 64-bit value the caller supplies
under a non-standard calling convention. The comparison is also routinely
computed in the interior node's block and consumed by an ``MLIL_IF`` several
blocks later::

    rcx_11 = arg6 + 0x2834a30d
    cond:1_1 = rax_5 != rcx_11   <- computed here...
    ...
    if (cond:1_1) then <dispatcher> else <original block>   <- ...consumed here

Original blocks transition by overwriting both halves with constants chosen so
their XOR is the successor state. Conditional transitions use ``cmov`` to select
one half between two values, leaving the other fixed, so the XOR lands on one of
two successors.

Why this shape needs its own solver rather than a variation of the original one:

  * The state is 64-bit, so nothing may be masked to 32 bits.
  * The state variable cannot be found by counting equality compares, because
    the interior nodes are relational. It is found from the XOR instead, which
    inverts the dependency: the dispatcher identifies the state variable rather
    than the reverse.
  * A state value is symbolic, so the compare bases must be resolved (from the
    callers, or by voting) before the state map can be keyed by concrete values.
  * A transition is a *pair* of half-writes that need not share a block, so it
    belongs to an original block's forward *region* rather than to a single
    store instruction.

Nothing here is erased. There are no decode gadgets, so there is no gadget map,
and the shared gadget cleanup cannot be reused anyway: it treats any constant
wider than 32 bits as a decode key, which is every state constant in this shape.
Once every region branches to its successor directly the dispatcher and the whole
compare tree are unreachable and Binary Ninja drops them on its own; the
per-block half-writes and their stack mirrors stay, being still reachable, and
are left in place deliberately rather than for want of a pass to remove them.
"""

from collections import Counter, defaultdict, deque

from binaryninja import (
    ILSourceLocation,
    MediumLevelILLabel,
    MediumLevelILOperation,
    Settings,
    SettingsScope,
)

from ..utils.const_eval import (
    U64,
    bind_bases_from_callers,
    eval_consts,
    solve_base_by_voting,
    split_base_disp,
)
from ..utils.log import log_debug, log_error, log_info, log_warn
from .base import MODE_XOR64, FlattenerShape, ShapeResult

_VAR_OPS = ("MLIL_VAR", "MLIL_VAR_FIELD")
_EQ_OPS = (MediumLevelILOperation.MLIL_CMP_E, MediumLevelILOperation.MLIL_CMP_NE)

# How far to chase single-definition copy chains.
_COPY_LIMIT = 8

# A solved base has to be agreed on by at least two independent observations.
# One agreement is no evidence at all: a single symbolic write paired with N
# candidate states yields N distinct values that each "fit" exactly once.
_MIN_VOTES = 2


# ---------------------------------------------------------------- MLIL helpers


def _label(operand):
    lbl = MediumLevelILLabel()
    lbl.operand = operand
    return lbl


def _resolve_cond(if_il):
    """The comparison behind an ``MLIL_IF``, in non-SSA form.

    A leaf's comparison is usually not on the ``MLIL_IF`` itself: this flattener
    spills it to a variable in the interior node's block and branches on that
    variable blocks later, so the definition has to be followed. SSA is what
    picks the *reaching* definition for this particular use, but the expression
    it yields has ``MLIL_VAR_SSA`` operands, so it is mapped back to non-SSA
    form. Without that the state variable inside it would not compare equal to
    the one the dispatcher defines, and every deferred leaf would be missed.
    """
    cond = if_il.condition
    if cond.operation != MediumLevelILOperation.MLIL_VAR:
        return cond
    try:
        defn = cond.function.ssa_form.get_ssa_var_definition(cond.ssa_form.src)
    except Exception:  # noqa: BLE001
        return cond
    if defn is None:
        return cond
    non_ssa = getattr(defn, "non_ssa_form", None)
    if non_ssa is not None:
        defn = non_ssa
    return getattr(defn, "src", cond)


def _is_state(expr, state_var):
    """True if ``expr`` reads the state variable, in either SSA or non-SSA form."""
    op = expr.operation.name
    if op == "MLIL_VAR":
        return expr.src == state_var
    if op == "MLIL_VAR_SSA":
        return expr.src.var == state_var
    return False


def _follow_copies(mlil, var):
    """Follow unambiguous copies to the variable actually being maintained.

    The dispatcher reads one half through a scratch copy (``rax_4 = r14``, then
    ``rax_5 = rax_4 ^ rdi``), so an XOR operand is not the variable the original
    blocks write. A variable with several definitions is already a real half, so
    only single-definition copies are followed.
    """
    for _ in range(_COPY_LIMIT):
        defs = mlil.get_var_definitions(var)
        if len(defs) != 1:
            return var
        src = getattr(defs[0], "src", None)
        if src is None or src.operation.name not in _VAR_OPS:
            return var
        var = src.src
    return var


def _deref_temp(mlil, expr):
    """Replace a single-assignment temp with its defining expression.

    Leaves compare against a temp (``rcx_11``) rather than against the
    ``base + displacement`` expression itself. A variable with no definition is a
    parameter, so it is already a base; one with several definitions is ambiguous
    and is left alone.
    """
    for _ in range(_COPY_LIMIT):
        if expr is None or expr.operation.name not in _VAR_OPS:
            return expr
        defs = mlil.get_var_definitions(expr.src)
        if len(defs) != 1:
            return expr
        src = getattr(defs[0], "src", None)
        if src is None:
            return expr
        expr = src
    return expr


# ------------------------------------------------------- dispatcher and leaves


def find_dispatcher(mlil):
    """Locate the state combine: ``(bb, state_var, (half_a, half_b), incoming)``.

    Found by its defining instruction -- a 64-bit XOR of two variables -- then
    disambiguated by incoming edges. Other blocks may hold such an XOR (the
    reference sample also XORs vector registers for buffer crypto), but only the
    dispatcher is the block every original block routes back through, so the
    candidate with the most incoming edges is the dispatcher.
    """
    best = None
    for bb in mlil.basic_blocks:
        for ins in bb:
            if ins.operation != MediumLevelILOperation.MLIL_SET_VAR:
                continue
            src = ins.src
            if src.operation != MediumLevelILOperation.MLIL_XOR or src.size != 8:
                continue
            if src.left.operation.name != "MLIL_VAR":
                continue
            if src.right.operation.name != "MLIL_VAR":
                continue
            incoming = len(bb.incoming_edges)
            if best is None or incoming > best[0]:
                best = (incoming, bb, ins)

    if best is None:
        return None
    incoming, bb, ins = best
    half_a = _follow_copies(mlil, ins.src.left.src)
    half_b = _follow_copies(mlil, ins.src.right.src)
    if half_a == half_b:
        return None  # `x ^ x` is zero, not a split state
    return (bb, ins.dest, (half_a, half_b), incoming)


def _leaf_nodes(mlil, state_var):
    """``[(if_il, value_expr, match_bb)]`` for every equality leaf of the tree.

    ``match_bb`` is the original-block head entered when the state equals the
    leaf's value: the false edge of a ``!=`` leaf, the true edge of an ``==``
    one. Interior nodes compare relationally and are skipped.
    """
    leaves = []
    for bb in mlil.basic_blocks:
        if bb.end <= bb.start:
            continue
        if_il = mlil[bb.end - 1]
        if if_il.operation != MediumLevelILOperation.MLIL_IF:
            continue
        cmp_il = _resolve_cond(if_il)
        if getattr(cmp_il, "operation", None) not in _EQ_OPS:
            continue
        for side, other in ((cmp_il.left, cmp_il.right), (cmp_il.right, cmp_il.left)):
            if not _is_state(side, state_var):
                continue
            is_ne = cmp_il.operation == MediumLevelILOperation.MLIL_CMP_NE
            match_bb = mlil[if_il.false if is_ne else if_il.true].il_basic_block
            leaves.append((if_il, _deref_temp(mlil, other), match_bb))
            break
    return leaves


_TAILCALL_OPS = (
    MediumLevelILOperation.MLIL_TAILCALL,
    MediumLevelILOperation.MLIL_TAILCALL_SSA,
    MediumLevelILOperation.MLIL_TAILCALL_UNTYPED,
    MediumLevelILOperation.MLIL_TAILCALL_UNTYPED_SSA,
)


def _handoff_targets(mlil):
    """Addresses this function tail-calls, forwarding the live state to them.

    A compare tree large enough gets partitioned: this function's tree covers
    one range of the state space and tail-calls a sibling fragment for the rest,
    handing over the state and both halves in registers. Binary Ninja sees those
    fragments as separate functions, so a state dispatched by one of them simply
    is not in this function's map. Knowing where the hand-offs go turns that from
    an unexplained miss into a boundary that can be reported accurately.
    """
    targets = set()
    for bb in mlil.basic_blocks:
        for ins in bb:
            if ins.operation not in _TAILCALL_OPS:
                continue
            dest = getattr(ins, "dest", None)
            if dest is None or not hasattr(dest, "operation"):
                continue
            if dest.operation.name in ("MLIL_CONST", "MLIL_CONST_PTR"):
                targets.add(dest.constant & U64)
    return targets


# ------------------------------------------------------------------- regions
#
# A transition here is a pair of half-writes that need not share a block, so it
# is attributed to an original block's *region*: the blocks forward-reachable
# from its head without passing through the dispatcher. Resolving a half over
# that region is what makes the result path-sensitive, which matters because the
# flattener shares its cmov tail between sibling blocks -- a sibling's body is
# not forward-reachable from this head and so drops out, while the shared cmov
# arm is in the region and still contributes its alternate value.


def _forward_region(mlil, head, disp_start):
    """Block starts reachable from ``head`` without entering the dispatcher."""
    region = set()
    queue = deque([head])
    while queue:
        bb = queue.popleft()
        if bb.start in region:
            continue
        region.add(bb.start)
        for edge in bb.outgoing_edges:
            succ = edge.target
            if succ.start == disp_start or succ.start in region:
                continue
            queue.append(succ)
    return region


def _prologue(mlil, disp_start):
    """``(region, exit_jump)`` for the entry path that seeds the initial state."""
    # The first trip through this flattener can bypass the XOR-combine block:
    # the prologue writes both halves *and* the already-combined state, then
    # jumps straight to the compare-tree root. Later transitions enter the
    # combine block and reach that same root through its sole outgoing edge.
    # Treat both as dispatcher entries or the prologue walk crosses the compare
    # tree, visits every OBB, and appears to write dozens of values per half.
    stops = {disp_start}
    try:
        disp_bb = mlil[disp_start].il_basic_block
        stops.update(e.target.start for e in disp_bb.outgoing_edges)
    except Exception:  # noqa: BLE001
        pass

    region, exit_jump = set(), None
    queue = deque([mlil.basic_blocks[0]])
    while queue:
        bb = queue.popleft()
        if bb.start in region:
            continue
        region.add(bb.start)
        for edge in bb.outgoing_edges:
            succ = edge.target
            if succ.start in stops:
                if exit_jump is None:
                    exit_jump = mlil[bb.end - 1]
                continue
            if succ.start not in region:
                queue.append(succ)
    return region, exit_jump


def _region_exit(mlil, head, region, disp_start, leaf_starts):
    """Terminating jump of the last block this region privately owns.

    Walked breadth-first so the *nearest* merge point wins. If the region flows
    into a block that sibling regions also feed (the flattener's shared cmov
    tail), the jump into that block is this region's real exit; otherwise the
    only merge point is the dispatcher, and the jump into it is the exit.
    Dispatcher leaves are never merge points -- every region's head is entered
    from one.
    """
    seen = set()
    queue = deque([head])
    while queue:
        bb = queue.popleft()
        if bb.start in seen:
            continue
        seen.add(bb.start)
        for edge in bb.outgoing_edges:
            succ = edge.target
            if succ.start == disp_start or any(
                e.source.start not in region and e.source.start not in leaf_starts
                for e in succ.incoming_edges
            ):
                return mlil[bb.end - 1]
            if succ.start not in seen:
                queue.append(succ)
    return None


def _enumerate_regions(mlil, leaves, disp_start, leaf_starts):
    """``[(head, region, exit_jump)]`` for the prologue and every original block."""
    regions = []
    prolog, prolog_exit = _prologue(mlil, disp_start)
    if prolog_exit is None:
        log_warn("[xor64] the entry path never reaches the dispatcher")
    else:
        regions.append((mlil.basic_blocks[0], prolog, prolog_exit))

    seen = {mlil.basic_blocks[0].start}
    for _if_il, _val, head in leaves:
        if head.start in seen:
            continue
        seen.add(head.start)
        region = _forward_region(mlil, head, disp_start)
        regions.append(
            (head, region, _region_exit(mlil, head, region, disp_start, leaf_starts))
        )
    return regions


# -------------------------------------------------------------- half analysis


def _half_values(func, mlil, half, region, bases):
    """Values ``half`` is assigned inside ``region``."""
    vals = set()
    for d in mlil.get_var_definitions(half):
        if d.il_basic_block.start not in region:
            continue
        vals |= eval_consts(func, getattr(d, "src", None), bases, region)
    return vals


def _half_symbols(func, mlil, half, region, bases):
    """``{(base_var, disp)}`` for in-region writes of ``half`` still unresolved.

    These are writes whose value depends on a parameter that is not yet known,
    e.g. ``rdi = arg16`` or ``rdi = arg8 + 0x53c6a0dc``.
    """
    syms = set()
    for d in mlil.get_var_definitions(half):
        if d.il_basic_block.start not in region:
            continue
        src = getattr(d, "src", None)
        if eval_consts(func, src, bases, region):
            continue
        bd = split_base_disp(_deref_temp(mlil, src))
        if bd is not None and bd[0] not in bases:
            syms.add(bd)
    return syms


def _cmov_arm(func, mlil, half, region, bases, leaf_starts):
    """The cmov arm overwriting ``half``: ``(value, if_il, then_is_true)`` or None.

    The arm is the in-region definition hanging off a program predicate. A head
    block's own unconditional half-write is excluded, because its sole
    predecessor is a dispatcher leaf -- itself an ``MLIL_IF``, which would
    otherwise masquerade as a second arm.
    """
    # The selected variable is often not the half itself. In the common
    # lowering the diamond selects ``rax_3``, then a many-consumer join copies
    # ``rax_3`` into ``var_70``. Follow region-local pure-copy sources until the
    # definition hanging off the predicate is found. Looking only at the
    # half's definitions sees the join block and misses every such cmov.
    arms, seen_vars = [], set()
    queue = deque([(half, 0)])
    while queue:
        var, depth = queue.popleft()
        if var in seen_vars or depth > _COPY_LIMIT:
            continue
        seen_vars.add(var)
        for d in mlil.get_var_definitions(var):
            blk = d.il_basic_block
            if blk.start not in region:
                continue

            if len(blk.incoming_edges) == 1:
                pred = blk.incoming_edges[0].source
                if pred.start not in leaf_starts:
                    if_il = mlil[pred.end - 1]
                    if if_il.operation == MediumLevelILOperation.MLIL_IF:
                        vals = eval_consts(
                            func, getattr(d, "src", None), bases, region
                        )
                        if len(vals) == 1:
                            arms.append(
                                (
                                    vals.pop(),
                                    if_il,
                                    mlil[if_il.true].il_basic_block.start
                                    == blk.start,
                                )
                            )

            src = getattr(d, "src", None)
            if src is not None and src.operation.name in _VAR_OPS:
                queue.append((src.src, depth + 1))

    if len(arms) != 1:
        if arms:
            log_debug(f"[xor64] {half} is selected by {len(arms)} arms, not one cmov")
        return None
    return arms[0]


def _through_ssa_copies(ssa, instr, limit=8):
    """The instruction really producing ``instr``'s value, following pure copies.

    Stops at anything that is not a copy of one SSA variable, which includes a
    phi -- a phi's ``src`` is a list of versions rather than an expression, so it
    has no ``operation`` to test.
    """
    for _ in range(limit):
        if instr is None:
            return None
        src = getattr(instr, "src", None)
        if not hasattr(src, "operation"):
            return instr
        if src.operation != MediumLevelILOperation.MLIL_VAR_SSA:
            return instr
        instr = ssa.get_ssa_var_definition(src.src)
    return None


def _liftable_operands(mlil, expr):
    """True if every ``MLIL_VAR`` ``expr`` reads has at most one definition in
    the whole function, i.e. ``expr`` is safe to copy to a new location.

    A variable written at most once in the whole function still holds the
    value it was tested against wherever the copy lands. One written in
    several places might not, and deciding which write reaches the new site is
    exactly the analysis this is trying to avoid, so those are refused.
    """
    for node in expr.traverse(lambda x: x):
        if node.operation == MediumLevelILOperation.MLIL_VAR:
            if len(mlil.get_var_definitions(node.src)) > 1:
                return False
    return True


def _liftable_condition(mlil, if_il):
    """``if_il``'s condition as an expression safe to re-evaluate elsewhere, or None."""
    cond = _resolve_cond(if_il)
    if cond is None or not hasattr(cond, "operation"):
        return None
    if not _liftable_operands(mlil, cond):
        return None
    return cond


def _phi_selection(func, mlil, half, region, bases):
    """A two-value selection decided outside ``region`` and carried into it, or None.

    The obfuscator sometimes decides a transition long before the block that
    performs it: a ``cmov`` near the function entry picks one of two half values,
    parks it in a stack slot, and a region far downstream copies that slot into
    the half. :func:`_half_values` cannot see this, because it resolves with the
    region as scope while the deciding writes sit outside it. Widening the scope
    is not an option -- it exists to stop sibling regions that share a state-store
    tail from reading each other's values.

    SSA names the selection directly and with no scope to widen: the carried
    value is a phi of the two candidate versions. Following the half's SSA
    definition through copies to that phi yields both values, and the arm each
    was written in yields the predicate.

    Returns ``{"values", "alt_val", "if_il", "then_is_true", ...}``, where *alt*
    means the same as in :func:`_cmov_arm`: the value written by the arm
    hanging off the ``MLIL_IF``. The last key is either ``"cond_src"`` (the
    diamond's own condition, lifted verbatim) or ``"cmp_src"``/``"cmp_val"``/
    ``"cmp_size"`` (see the fallback below).
    """
    def decline(why):
        log_debug(f"[xor64] {half}: no remote selection recovered, {why}")
        return None

    defs = [
        d for d in mlil.get_var_definitions(half)
        if d.il_basic_block.start in region
    ]
    if len(defs) != 1:
        return decline(f"{len(defs)} in-region write(s) of it, need exactly one")

    # A shared final state-store block introduces a phi containing values from
    # every region. Starting SSA traversal at the half write therefore lands
    # on that many-way routing phi rather than on this region's two-way remote
    # selection. Peel region-local copies first (``var_70 = rax_3`` followed by
    # this region's ``rax_3 = var_58``); SSA can then follow ``var_58`` back to
    # the actual two-input phi near the prologue.
    seed = defs[0]
    for _ in range(_COPY_LIMIT):
        src = getattr(seed, "src", None)
        if src is None or src.operation.name not in _VAR_OPS:
            break
        src_defs = [
            d
            for d in mlil.get_var_definitions(src.src)
            if d.il_basic_block.start in region
        ]
        if len(src_defs) != 1:
            break
        seed = src_defs[0]
    try:
        ssa = mlil.ssa_form
        phi = _through_ssa_copies(ssa, seed.ssa_form)
    except Exception as exc:  # noqa: BLE001
        return decline(f"its SSA form was unavailable ({exc})")
    if phi is None or phi.operation != MediumLevelILOperation.MLIL_VAR_PHI:
        got = "nothing" if phi is None else phi.operation.name
        return decline(f"its SSA definition chain ends at {got}, not a phi")

    values, arms = set(), []
    for version in phi.src:
        try:
            defn = _through_ssa_copies(ssa, ssa.get_ssa_var_definition(version))
            nz = None if defn is None else defn.non_ssa_form
        except Exception as exc:  # noqa: BLE001
            return decline(f"phi operand {version} would not resolve ({exc})")
        if nz is None:
            return decline(f"phi operand {version} has no non-SSA definition")
        blk = _block_of(nz)
        if blk is None:
            return decline(f"phi operand {version}'s definition is in no block")
        # Scoped to the defining block so this cannot wander back out into the
        # whole function and undo the point of the region scope.
        vals = eval_consts(func, getattr(nz, "src", None), bases, {blk.start})
        if len(vals) != 1:
            return decline(
                f"phi operand {version} resolves to {len(vals)} value(s), not one"
            )
        val = vals.pop()
        values.add(val)
        # An arm is a block entered by exactly one edge, from an ``MLIL_IF``.
        if len(blk.incoming_edges) == 1:
            if_il = mlil[blk.incoming_edges[0].source.end - 1]
            if if_il.operation == MediumLevelILOperation.MLIL_IF:
                arms.append(
                    (val, if_il, mlil[if_il.true].il_basic_block.start == blk.start)
                )

    if len(values) != 2:
        return decline(f"the phi selects {len(values)} distinct value(s), not two")
    if len(arms) != 1:
        return decline(f"{len(arms)} of its phi operands hang off an if, need one")
    alt_val, if_il, then_is_true = arms[0]
    cond_src = _liftable_condition(mlil, if_il)
    if cond_src is not None:
        return {
            "values": values,
            "alt_val": alt_val,
            "if_il": if_il,
            "then_is_true": then_is_true,
            "cond_src": cond_src,
        }

    # The diamond's own decision register can be a scratch value reused for
    # unrelated purposes elsewhere in the function even when the value it
    # decided is not: that value is exactly what this region already copies
    # in (``defs[0].src``, e.g. a stack slot the diamond writes exactly once
    # and nothing else ever touches again). Comparing that copy against the
    # alternate value is just as good a stand-in for "did the diamond fire",
    # and unlike the diamond's own condition, it is always safe to
    # re-evaluate at this region's own tail.
    carried = getattr(defs[0], "src", None)
    if (
        carried is None
        or not hasattr(carried, "operation")
        or not _liftable_operands(mlil, carried)
    ):
        return decline(
            f"the condition of the diamond @ {hex(if_il.address)} reads a variable "
            f"written more than once, so it cannot be lifted safely, and the value "
            f"it carries in is no safer to compare instead"
        )
    return {
        "values": values,
        "alt_val": alt_val,
        "if_il": if_il,
        "then_is_true": True,
        "cmp_src": carried,
        "cmp_val": alt_val,
        "cmp_size": carried.size or 8,
    }


def _solve_half_bases(func, mlil, regions, halves, bases, state_map):
    """Solve parameters used by the half-writes, now that the state map is known.

    A half written as ``base + disp`` against a fixed other half ``h`` has to
    land on a real state, so ``base == (state ^ h) - disp``. Every candidate is
    tallied across every region and the most agreed-on value wins -- the same
    argument as the compare-base vote, but over XOR rather than addition.
    """
    tally = defaultdict(Counter)
    for _head, region, _exit in regions:
        vals = [_half_values(func, mlil, h, region, bases) for h in halves]
        for i in (0, 1):
            if len(vals[1 - i]) != 1:
                continue
            fixed = next(iter(vals[1 - i]))
            for base, disp in _half_symbols(func, mlil, halves[i], region, bases):
                for state in state_map:
                    tally[base][((state ^ fixed) - disp) & U64] += 1

    solved = {}
    for base, counts in tally.items():
        value, votes = counts.most_common(1)[0]
        if votes < _MIN_VOTES:
            # Not a failure on its own. A half that voting cannot pin down is
            # usually one selected outside its region, which the region planner
            # recovers from SSA instead -- and voting can never settle such a
            # half anyway, since only the single region using it ever votes. The
            # planner reports the regions that really are left intact, so this
            # no longer claims to.
            log_info(
                f"[xor64] half base {base} could not be solved by voting (no "
                f"candidate fits more than {votes} transition(s)); the region(s) "
                f"using it fall back to recovering the selection from SSA"
            )
            continue
        solved[base] = value
        log_info(f"[xor64] solved half base {base}={value:#x} by voting ({votes} agree)")
    return solved


# --------------------------------------------------------------- plan building


class _Ctx:
    """Everything the per-region planner needs that does not vary per region."""

    def __init__(self, func, mlil, halves, bases, state_map, leaf_starts, handoffs):
        self.func = func
        self.mlil = mlil
        self.halves = halves
        self.bases = bases
        self.state_map = state_map
        self.leaf_starts = leaf_starts
        self.handoffs = handoffs
        # Tallies for the closing summary, so a partial recovery can say which
        # kind of partial it is.
        self.handed_off = set()
        self.terminal = 0
        self.unresolved = 0


def _handoff_note(ctx):
    if not ctx.handoffs:
        return ""
    return (
        "; this function's tree covers only part of the state space and "
        "tail-calls " + ", ".join(hex(a) for a in sorted(ctx.handoffs)) + " for the rest"
    )


def _missing_states(ctx, where, states):
    """Record and report states this function's tree does not dispatch."""
    ctx.handed_off.update(states)
    log_info(
        f"[xor64] {where}: successor state(s) {[hex(s) for s in sorted(states)]} "
        f"not dispatched here{_handoff_note(ctx)}; left intact"
    )


def _region_plan(ctx, head, region, exit_jump):
    """The redirection plan for one region, or None if its shape isn't recognised."""
    mlil, func, halves, bases = ctx.mlil, ctx.func, ctx.halves, ctx.bases
    state_map, leaf_starts = ctx.state_map, ctx.leaf_starts
    where = hex(mlil[head.start].address)

    # A region with no jump back to the dispatcher does not transition at all --
    # it returns, or tail-calls out. There is nothing to recover, so this is not
    # a failure.
    if exit_jump is None:
        ctx.terminal += 1
        log_debug(
            f"[xor64] {where}: terminal region (returns or tail-calls out rather "
            f"than routing back to the dispatcher); no transition to recover"
        )
        return None

    vals = [_half_values(func, mlil, h, region, bases) for h in halves]

    # A half the region only copies in, whose value was selected somewhere else,
    # resolves to nothing under the region scope. Recover it from SSA before
    # giving up, and remember that the selection is remote: its diamond must not
    # be treated as this region's own.
    outside = None
    for i in (0, 1):
        if vals[i]:
            continue
        sel = _phi_selection(func, mlil, halves[i], region, bases)
        if sel is None:
            continue
        vals[i] = set(sel["values"])
        outside = sel
        log_info(
            f"[xor64] {where}: half {halves[i]} is selected by a diamond @ "
            f"{hex(sel['if_il'].address)} outside this region and carried in"
        )

    if not vals[0] or not vals[1]:
        ctx.unresolved += 1
        unknown = ", ".join(str(h) for h, v in zip(halves, vals) if not v)
        log_warn(f"[xor64] {where}: no resolvable value for half {unknown}")
        return None

    # Unconditional: both halves fixed, so their XOR names a single successor.
    if len(vals[0]) == 1 and len(vals[1]) == 1:
        state = (next(iter(vals[0])) ^ next(iter(vals[1]))) & U64
        if state not in state_map:
            _missing_states(ctx, where, {state})
            return None
        target = state_map[state]
        log_info(f"[xor64] {where} => uncond {state:#x} -> {target.start}")
        return {"kind": "uncond", "obb": head, "jump": exit_jump, "target_bb": target}

    # Conditional: exactly one half is cmov-selected between two values.
    fixed_i, vary_i = sorted(range(2), key=lambda i: len(vals[i]))
    if len(vals[fixed_i]) != 1 or len(vals[vary_i]) != 2:
        ctx.unresolved += 1
        log_warn(
            f"[xor64] {where}: half values {[len(v) for v in vals]} are not a "
            f"single cmov selection; left intact"
        )
        return None

    arm = (
        (outside["alt_val"], outside["if_il"], outside["then_is_true"])
        if outside is not None
        else _cmov_arm(func, mlil, halves[vary_i], region, bases, leaf_starts)
    )
    if arm is None:
        ctx.unresolved += 1
        log_warn(f"[xor64] {where}: could not identify the cmov arm; left intact")
        return None
    alt_val, if_il, then_is_true = arm
    others = [v for v in vals[vary_i] if v != alt_val]
    if len(others) != 1:
        ctx.unresolved += 1
        log_warn(
            f"[xor64] {where}: the cmov arm's value is not one of the two the half "
            f"resolves to; left intact"
        )
        return None

    fixed_val = next(iter(vals[fixed_i]))
    alt_state = (alt_val ^ fixed_val) & U64
    default_state = (others[0] ^ fixed_val) & U64
    missing = {s for s in (alt_state, default_state) if s not in state_map}
    if missing:
        # Both arms have to land somewhere known: half a diamond cannot be
        # rewritten without changing what the other arm does.
        _missing_states(ctx, where, missing)
        return None
    alt_succ = state_map[alt_state]
    default_succ = state_map[default_state]

    # Is the selecting diamond private to this region, or shared with siblings?
    # Leaf predecessors don't count: a head block is always entered from one.
    # A remote selection is never this region's own diamond, however its
    # predecessors look: its arms sit outside the region, so re-pointing them
    # would skip everything between them and here.
    shared = outside is not None or any(
        e.source.start not in region and e.source.start not in leaf_starts
        for e in if_il.il_basic_block.incoming_edges
    )

    if not shared:
        # Re-point the diamond's own arms. The half-writes and the path back to
        # the dispatcher are orphaned and dropped as dead.
        log_info(
            f"[xor64] {where}: private cmov diamond @ {hex(if_il.address)} alt "
            f"{alt_state:#x} / default {default_state:#x} (then_is_true={then_is_true})"
        )
        return {
            "kind": "cmov_diamond",
            "obb": head,
            "if_il": if_il,
            "then_is_true": then_is_true,
            "alt_succ": alt_succ,
            "default_succ": default_succ,
            "alt_state": alt_state,
            "default_state": default_state,
        }

    # Shared diamond: re-pointing its arms would collapse every sibling onto this
    # region's two successors. Rewrite this region's own tail instead, so each
    # consumer branches on its own predicate; the shared diamond is left untouched
    # and is dropped as dead once every consumer is rewritten.
    if exit_jump.operation.name != "MLIL_GOTO":
        ctx.unresolved += 1
        log_warn(
            f"[xor64] {where}: shared diamond, but this region's exit is a "
            f"{exit_jump.operation.name} rather than a goto; left intact"
        )
        return None

    cond = if_il.condition
    cmp_info = None
    if outside is not None:
        # Already resolved to a liftable expression (or a liftable stand-in --
        # see ``_phi_selection``), and its definition is out of region by
        # construction, so the in-region checks below cannot apply.
        cond_def = None
        if "cond_src" in outside:
            cond_src = outside["cond_src"]
        else:
            cond_src = None
            cmp_info = (outside["cmp_src"], outside["cmp_val"], outside["cmp_size"])
    elif cond.operation.name == "MLIL_VAR":
        cdefs = [
            d
            for d in mlil.get_var_definitions(cond.src)
            if d.il_basic_block.start in region
        ]
        if len(cdefs) != 1:
            ctx.unresolved += 1
            log_warn(
                f"[xor64] {where}: {len(cdefs)} in-region definition(s) of the "
                f"shared diamond's condition, need exactly one; left intact"
            )
            return None
        cond_def, cond_src = cdefs[0], cdefs[0].src
    else:
        cond_def, cond_src = None, cond

    # The condition is lifted verbatim, so its operands must still be live where
    # the branch is dropped -- only guaranteed if it is computed in that block.
    if (
        cond_def is not None
        and cond_def.il_basic_block.start != exit_jump.il_basic_block.start
    ):
        ctx.unresolved += 1
        log_warn(
            f"[xor64] {where}: the shared diamond's condition is computed outside "
            f"the exit block, so it cannot be lifted there; left intact"
        )
        return None

    if then_is_true:
        true_succ, false_succ = alt_succ, default_succ
    else:
        true_succ, false_succ = default_succ, alt_succ

    log_info(
        f"[xor64] {where}: shared cmov diamond @ {hex(if_il.address)}; rewrite tail "
        f"{hex(exit_jump.address)} -> true {true_succ.start} / false {false_succ.start}"
    )
    return {
        "kind": "cmov_obb",
        "obb": head,
        "tail_goto": exit_jump,
        "cond_src": cond_src,
        "cmp_info": cmp_info,
        "true_succ": true_succ,
        "false_succ": false_succ,
        "alt_state": alt_state,
        "default_state": default_state,
    }


# ------------------------------------------------------------------- rewriting


def _apply_uncond(mlil, r):
    """Replace a region's exit jump with a direct ``goto`` to its successor."""
    jump = r["jump"]
    target = r["target_bb"].start
    mlil.replace_expr(
        jump.expr_index,
        mlil.goto(_label(target), ILSourceLocation.from_instruction(jump)),
    )
    log_info(
        f"[xor64] {r['obb'].start}: redirect {hex(jump.address)} -> "
        f"{target} ({hex(mlil[target].address)})"
    )
    return 1


def _apply_cmov_diamond(mlil, r):
    """Re-point a private cmov diamond's arms at the two real successors."""
    if_il = r["if_il"]
    then_is_true = r["then_is_true"]
    alt_arm = mlil[if_il.true if then_is_true else if_il.false].il_basic_block
    def_arm = mlil[if_il.false if then_is_true else if_il.true].il_basic_block
    alt_tail = mlil[alt_arm.end - 1]
    def_tail = mlil[def_arm.end - 1]
    mlil.replace_expr(
        alt_tail.expr_index,
        mlil.goto(
            _label(r["alt_succ"].start), ILSourceLocation.from_instruction(alt_tail)
        ),
    )
    mlil.replace_expr(
        def_tail.expr_index,
        mlil.goto(
            _label(r["default_succ"].start),
            ILSourceLocation.from_instruction(def_tail),
        ),
    )
    log_info(
        f"[xor64] {r['obb'].start}: cmov diamond @ {hex(if_il.address)} -> alt "
        f"{r['alt_succ'].start} / default {r['default_succ'].start}"
    )
    return 1


def _apply_cmov_obb(mlil, r):
    """Replace a region's exit goto into a shared diamond with its own branch.

    ``cmp_info`` stands in for ``cond_src`` when the diamond's own condition
    could not be lifted (see ``_phi_selection``): rather than copying that
    condition, it compares the value this region already carries in against
    the alternate value it can hold, freshly built here since no such
    comparison exists anywhere in the original IL.
    """
    goto_il = r["tail_goto"]
    loc = ILSourceLocation.from_instruction(goto_il)
    cmp_info = r.get("cmp_info")
    if cmp_info is not None:
        src, val, size = cmp_info
        cond_expr = mlil.compare_equal(
            1, mlil.copy_expr(src), mlil.const(size, val, loc), loc
        )
    else:
        cond_expr = mlil.copy_expr(r["cond_src"])
    mlil.replace_expr(
        goto_il.expr_index,
        mlil.if_expr(
            cond_expr,
            _label(r["true_succ"].start),
            _label(r["false_succ"].start),
            loc,
        ),
    )
    log_info(
        f"[xor64] {r['obb'].start}: region-tail branch @ {hex(goto_il.address)} -> "
        f"true {r['true_succ'].start} / false {r['false_succ'].start}"
    )
    return 1


_HANDLERS = {
    "uncond": _apply_uncond,
    "cmov_diamond": _apply_cmov_diamond,
    "cmov_obb": _apply_cmov_obb,
}


def _block_of(il):
    """``il``'s basic block, or None.

    Cannot be called bare: the property asserts rather than returning None when
    the instruction is not in a block, and the SSA mapping does hand back
    instructions that are not.
    """
    try:
        return il.il_basic_block
    except Exception:  # noqa: BLE001
        return None


_TAIL_CALL_SETTINGS = (
    "core.function.analyzeTailCalls",
    "core.function.translateTailCalls",
)


def _disable_tail_call_settings(bv, tag="xor64"):
    """Turn off tail-call analysis and translation for the whole binary, if
    either is still on, and request a full reanalysis.

    Both settings mask the same shape -- a real, returning call whose return
    address happens to be the entry of another already-defined function
    (typically one split off by the same ``.pdata``/Guard CF marks
    ``_absorb_split_body`` cleans up after the fact) -- but at different
    stages. ``analyzeTailCalls`` acts during function-boundary discovery: it
    is the actual root cause of that fragmentation, since it is what decides
    a real, returning call doesn't return and carves out a separate function
    for what comes after. ``translateTailCalls`` acts later, during IL
    lifting, rewriting the call into a synthetic ``tailcall`` even once the
    function boundaries are otherwise correct. Disabling only one leaves the
    other still producing wrong function boundaries or wrong IL for functions
    elsewhere in the binary this pass never visits, so both are flipped at
    binary scope rather than per-function -- the fragmentation is a property
    of the whole analysis, not of whichever function happened to be solved
    first.

    Returns True if either setting was on and got flipped (the caller must
    stop -- every function's boundaries and IL can change), False if both
    were already off.
    """
    settings = Settings()
    changed = False
    for key in _TAIL_CALL_SETTINGS:
        if not settings.get_bool(key, bv):
            continue
        applied = settings.set_bool(key, False, bv, SettingsScope.SettingsResourceScope)
        now = settings.get_bool(key, bv)
        if not applied or now:
            log_warn(
                f"[{tag}] {bv.file.filename}: set_bool({key}, False) returned "
                f"{applied} and it now reads {now} -- the override did not "
                f"take"
            )
            continue
        changed = True
        log_info(f"[{tag}] {bv.file.filename}: disabled {key} binary-wide")
    if changed:
        log_info(
            f"[{tag}] {bv.file.filename}: reanalysing the whole binary now "
            f"that tail-call handling is off"
        )
        bv.reanalyze()
    return changed


# Fragments already undefined, as (filename, start). Removal is meant to be
# permanent, so this only matters if one ever fails to stick: without it a
# fragment that keeps reappearing would be undefined again on every pass.
_ABSORBED = set()


def _last_instruction(bv, arch, blk):
    """The ``InstructionInfo`` of ``blk``'s final instruction, or None if unsure.

    Walked from the block start because a basic block records only its bounds,
    not where the last instruction within it begins.
    """
    addr, info = blk.start, None
    while addr < blk.end:
        data = bv.read(addr, min(arch.max_instr_length, blk.end - addr))
        if not data:
            return None
        info = arch.get_instruction_info(data, addr)
        if info is None or info.length == 0:
            return None
        addr += info.length
    # Decoding that does not land exactly on the block end disagrees with the
    # one Binary Ninja made, so nothing here is worth trusting.
    return info if addr == blk.end else None


def _runs_into(bv, arch, func, blk):
    """The function ``blk`` falls straight into, or None.

    A block with no outgoing edge normally ends the function: a ``ret``, an
    unresolved jump, a call that does not return. A block that merely ran out of
    room looks identical, though -- its edge is missing only because the next
    address now belongs to another function.

    The two are separated at the byte level, by asking the architecture about the
    last instruction rather than reading the IL, which by this point has been
    rewritten into a tail call. An instruction that reports no branches of any
    kind is one that continues to the following address; ``ret``, ``jmp`` and
    calls all report one, so only a real fall-through survives this.
    """
    try:
        other = bv.get_function_at(blk.end)
    except Exception:  # noqa: BLE001
        return None
    if other is None or other.start == func.start:
        return None
    info = _last_instruction(bv, arch, blk)
    return other if info is not None and not info.branches else None


def _absorb_split_body(bv, func, tag="xor64"):
    """Undefine the functions this body runs into, so their blocks come back.

    Binary Ninja starts a function wherever anything names one, and this
    obfuscator leaves such marks all through a flattened body: ``.pdata`` unwind
    ranges, Guard CF entries, ordinary prologues, direct calls. Each mark splits
    off another function, and each fragment then reaches only the part of the
    compare tree its own entry leads to, its leaves comparing against whatever
    parameters that entry happens to receive rather than folded constants. A
    fragment therefore solves to a state map that is quietly missing states.

    No loader or analysis setting prevents the split, because a mark can be an
    ordinary direct call and a call always starts a function. So the marks are
    not worth telling apart; what gives the split away is that the body runs
    straight into the fragment, which real control flow does not do.

    ``remove_user_function`` rather than ``remove_function``, because the mark is
    still in the file: a plain removal would be undone the next time analysis
    looked, and this would fire again on every pass.

    Returns True when anything was removed, in which case the caller must stop --
    ``func`` and its MLIL no longer describe the body that is now there.
    """
    arch = func.arch
    fname = getattr(getattr(bv, "file", None), "filename", "")
    victims = {}
    for blk in func.basic_blocks:
        if blk.outgoing_edges:
            continue
        other = _runs_into(bv, arch, func, blk)
        if other is not None and (fname, other.start) not in _ABSORBED:
            victims[other.start] = other

    removed = []
    for start, other in sorted(victims.items()):
        # A fragment can be both fallen into and called for real -- a .pdata
        # entry that also has a genuine caller. Absorbing it still wins, since
        # the compare tree is only whole one way, but say so: those callers are
        # left calling into the middle of the merged function.
        try:
            callers = sorted({
                ref.function.name for ref in bv.get_code_refs(start)
                if ref.function is not None and ref.function.start != func.start
            })
        except Exception:  # noqa: BLE001
            callers = []
        name = other.name
        try:
            bv.remove_user_function(other)
        except Exception as exc:  # noqa: BLE001
            log_error(f"[{tag}] {func.name}: could not undefine {name}: {exc}")
            continue
        _ABSORBED.add((fname, start))
        removed.append(name)
        if callers:
            log_warn(
                f"[{tag}] {func.name}: undefined {name} @ {hex(start)} to absorb its "
                f"blocks, but it is called from {', '.join(callers)}, which now call "
                f"into the middle of {func.name}"
            )
        else:
            log_info(
                f"[{tag}] {func.name}: undefined {name} @ {hex(start)}; this body runs "
                f"straight into it, so its blocks belong here"
            )

    if not removed:
        return False
    log_info(
        f"[{tag}] {func.name}: absorbed {len(removed)} fragment(s), reanalysing; "
        f"solving once the merged body settles"
    )
    try:
        func.reanalyze()
    except Exception as exc:  # noqa: BLE001
        log_error(f"[{tag}] {func.name}: could not request reanalysis: {exc}")
    return True


# ----------------------------------------------------------------- the shape


class XorSplit64Shape(FlattenerShape):
    name = "xor_split64"
    mode = MODE_XOR64
    uses_gadget_cleanup = False

    def recognise(self, bv, func, mlil):
        if find_dispatcher(mlil) is None:
            return (False, "no 64-bit XOR of two variables found")
        return (True, "")

    def solve(self, bv, func, mlil):
        found = find_dispatcher(mlil)
        if found is None:
            log_warn(
                f"[xor64] {func.name}: no 64-bit XOR of two variables; this does "
                f"not look like an OLLVM_XOR_64 function"
            )
            return ShapeResult()
        disp_bb, state_var, halves, incoming = found
        disp_addr = mlil[disp_bb.start].address
        log_info(
            f"[xor64] {func.name}: dispatcher @ {hex(disp_addr)} "
            f"({incoming} incoming edges), state {state_var} = "
            f"{halves[0]} ^ {halves[1]}"
        )
        if _disable_tail_call_settings(bv):
            return ShapeResult()
        if _absorb_split_body(bv, func):
            return ShapeResult()

        leaves = _leaf_nodes(mlil, state_var)
        if not leaves:
            log_warn(f"[xor64] {func.name}: the dispatcher has no equality leaves")
            return ShapeResult()
        leaf_starts = {if_il.il_basic_block.start for if_il, _, _ in leaves}

        # Separate leaves that already compare a concrete value from those that
        # compare `base + displacement`.
        concrete, symbolic = [], []
        disps_by_base = defaultdict(set)
        for if_il, val, match_bb in leaves:
            direct = eval_consts(func, val)
            if len(direct) == 1:
                concrete.append((next(iter(direct)), match_bb))
                continue
            bd = split_base_disp(val)
            if bd is None:
                log_debug(
                    f"[xor64] leaf @ {hex(if_il.address)}: compare value is neither "
                    f"a constant nor base+displacement; skipped"
                )
                continue
            symbolic.append((bd[0], bd[1], match_bb))
            disps_by_base[bd[0]].add(bd[1])
        log_info(
            f"[xor64] {func.name}: {len(concrete)} concrete and {len(symbolic)} "
            f"symbolic leaf/leaves over {len(disps_by_base)} compare base(s)"
        )

        regions = _enumerate_regions(mlil, leaves, disp_bb.start, leaf_starts)

        # Every parameter standing in the way: the compare bases, plus any the
        # half-writes themselves lean on. Bind whatever the callers make concrete
        # in one pass, before falling back to voting for the remainder.
        half_bases = set()
        for _head, region, _exit in regions:
            for half in halves:
                for base, _disp in _half_symbols(func, mlil, half, region, {}):
                    half_bases.add(base)
        bases = dict(
            bind_bases_from_callers(bv, func, set(disps_by_base) | half_bases)
        )

        # States that resolve with no unknown base are what the compare-base vote
        # is scored against.
        observed = {s for s, _ in concrete}
        for _head, region, _exit in regions:
            a = _half_values(func, mlil, halves[0], region, bases)
            b = _half_values(func, mlil, halves[1], region, bases)
            if a and b and len(a) * len(b) <= 4:
                observed |= {(x ^ y) & U64 for x in a for y in b}

        for base in set(disps_by_base) - set(bases):
            disps = disps_by_base[base]
            value, votes = solve_base_by_voting(disps, observed)
            if value is None or votes < _MIN_VOTES:
                log_warn(
                    f"[xor64] {func.name}: could not resolve compare base {base} "
                    f"({len(disps)} displacement(s) against {len(observed)} "
                    f"observed state(s), best agreement {votes})"
                )
                continue
            bases[base] = value
            log_info(
                f"[xor64] {func.name}: solved compare base {base}={value:#x} by "
                f"voting ({votes} of {len(disps)} displacement(s) agree)"
            )

        state_map = {s: bb for s, bb in concrete}
        dropped = 0
        for base, disp, match_bb in symbolic:
            if base not in bases:
                dropped += 1
                continue
            state_map[(bases[base] + disp) & U64] = match_bb
        if dropped:
            log_warn(
                f"[xor64] {func.name}: {dropped} leaf/leaves dropped for an "
                f"unresolved compare base"
            )
        if not state_map:
            log_warn(f"[xor64] {func.name}: the state map is empty")
            return ShapeResult()
        log_info(f"[xor64] {func.name}: state map has {len(state_map)} entry/entries")

        # Parameters used by the half-writes can now be solved against the map.
        bases.update(_solve_half_bases(func, mlil, regions, halves, bases, state_map))

        ctx = _Ctx(
            func, mlil, halves, bases, state_map, leaf_starts, _handoff_targets(mlil)
        )
        plans, anchors = [], set()
        for head, region, exit_jump in regions:
            plan = _region_plan(ctx, head, region, exit_jump)
            if plan is None:
                continue
            anchor = plan.get("jump") or plan.get("if_il") or plan.get("tail_goto")
            if anchor.expr_index in anchors:
                continue
            anchors.add(anchor.expr_index)
            plans.append(plan)

        log_info(
            f"[xor64] {func.name}: recovered {len(plans)} transition(s) from "
            f"{len(regions)} region(s)"
        )
        if ctx.terminal:
            log_info(
                f"[xor64] {func.name}: {ctx.terminal} region(s) return or tail-call "
                f"out and have no successor state"
            )
        if ctx.handed_off:
            log_info(
                f"[xor64] {func.name}: {len(ctx.handed_off)} successor state(s) are "
                f"dispatched elsewhere{_handoff_note(ctx)}, so those region(s) still "
                f"route through the dispatcher"
            )
        if ctx.unresolved:
            log_warn(
                f"[xor64] {func.name}: {ctx.unresolved} region(s) left intact because "
                f"their transition could not be recovered"
            )
        return ShapeResult(
            state_var=state_var,
            state_map=state_map,
            redirections=plans,
            state_write_vars={state_var, *halves},
            notes={
                "dispatcher": disp_bb.start,
                "halves": halves,
                "bases": bases,
            },
        )

    def apply(self, mlil, result):
        applied = 0
        for r in result.redirections:
            handler = _HANDLERS.get(r["kind"])
            if handler is None:
                continue
            try:
                applied += handler(mlil, r)
            except Exception as e:  # noqa: BLE001
                anchor = r.get("jump") or r.get("if_il") or r.get("tail_goto")
                where = anchor.address if anchor is not None else 0
                log_warn(f"[xor64] failed to rewrite {hex(where)}: {e}")
        if applied:
            mlil.finalize()
            mlil.generate_ssa_form()
        return applied
