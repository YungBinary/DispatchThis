"""OLLVM_DIRECT_32: XOR64-style regions with one plain 32-bit state.

The dispatcher copies a maintained 32-bit state into a comparison scratch and
routes it through a binary-search tree. Original blocks write the next state and
jump back to the dispatcher. Conditional transitions select between two state
constants with a small diamond; sometimes that selection is made earlier and
carried into the region through an SSA phi.

This is the single-state sibling of :mod:`xor_split64`, not a variant of the
legacy indirect-jump solver. It uses the same dispatcher-leaf, per-original-
block region, SSA selection, and MLIL rewrite model as XOR64. The only state
arithmetic is truncation to 32 bits -- there are no XOR halves or decode gadgets.
"""

from collections import Counter, deque

from binaryninja import ILSourceLocation, MediumLevelILLabel, MediumLevelILOperation

from ..utils.const_eval import U32, eval_consts
from ..utils.log import log_debug, log_info, log_warn
from .base import MODE_DIRECT_32, FlattenerShape, ShapeResult
from .xor_split64 import _absorb_split_body, _disable_tail_call_settings


_VAR_OPS = ("MLIL_VAR", "MLIL_VAR_FIELD")
_EQ_OPS = (MediumLevelILOperation.MLIL_CMP_E, MediumLevelILOperation.MLIL_CMP_NE)
_REL_OPS = {
    MediumLevelILOperation.MLIL_CMP_E,
    MediumLevelILOperation.MLIL_CMP_NE,
    MediumLevelILOperation.MLIL_CMP_SLT,
    MediumLevelILOperation.MLIL_CMP_SLE,
    MediumLevelILOperation.MLIL_CMP_SGE,
    MediumLevelILOperation.MLIL_CMP_SGT,
    MediumLevelILOperation.MLIL_CMP_ULT,
    MediumLevelILOperation.MLIL_CMP_ULE,
    MediumLevelILOperation.MLIL_CMP_UGE,
    MediumLevelILOperation.MLIL_CMP_UGT,
}
_COPY_LIMIT = 8


def _label(operand):
    label = MediumLevelILLabel()
    label.operand = operand
    return label


def _resolve_cond(if_il):
    """Comparison feeding an IF, following a deferred condition through SSA."""
    cond = if_il.condition
    if cond.operation != MediumLevelILOperation.MLIL_VAR:
        return cond
    try:
        defn = cond.function.ssa_form.get_ssa_var_definition(cond.ssa_form.src)
    except Exception:  # noqa: BLE001
        return cond
    if defn is None:
        return cond
    defn = getattr(defn, "non_ssa_form", None) or defn
    return getattr(defn, "src", cond)


def _follow_copies(mlil, var):
    """Follow a unique copy from the compare scratch to maintained state."""
    for _ in range(_COPY_LIMIT):
        defs = mlil.get_var_definitions(var)
        if len(defs) != 1:
            return var
        src = getattr(defs[0], "src", None)
        if src is None or src.operation.name not in _VAR_OPS:
            return var
        var = src.src
    return var


def _is_state_expr(mlil, expr, state_var):
    """Whether ``expr`` is the state or a unique chain of copies from it."""
    op = getattr(getattr(expr, "operation", None), "name", "")
    if op == "MLIL_VAR":
        return _follow_copies(mlil, expr.src) == state_var
    if op == "MLIL_VAR_SSA":
        return _follow_copies(mlil, expr.src.var) == state_var
    return False


def _is_routed_expr(mlil, expr, compare_var, state_var):
    return _is_state_expr(mlil, expr, compare_var) or _is_state_expr(
        mlil, expr, state_var
    )


def _deref_temp(mlil, expr):
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


def _vars_in(expr):
    if expr is None or not hasattr(expr, "traverse"):
        return set()
    out = set()
    for node in expr.traverse(lambda x: x):
        if node.operation.name == "MLIL_VAR":
            out.add(node.src)
        elif node.operation.name == "MLIL_VAR_SSA":
            out.add(node.src.var)
    return out


def find_dispatcher(mlil):
    """Return ``(dispatcher, compare_var, state_var, incoming)``."""
    counts = Counter()
    for bb in mlil.basic_blocks:
        if bb.end <= bb.start:
            continue
        tail = mlil[bb.end - 1]
        if tail.operation != MediumLevelILOperation.MLIL_IF:
            continue
        cmp_il = _resolve_cond(tail)
        if getattr(cmp_il, "operation", None) not in _EQ_OPS:
            continue
        for side in (cmp_il.left, cmp_il.right):
            if side.operation.name == "MLIL_VAR" and (side.size or 4) <= 4:
                counts[_follow_copies(mlil, side.src)] += 1
            elif side.operation.name == "MLIL_VAR_SSA" and (side.size or 4) <= 4:
                counts[_follow_copies(mlil, side.src.var)] += 1
    if not counts:
        return None
    compare_var, comparisons = counts.most_common(1)[0]
    if comparisons < 3:
        return None
    candidates = []
    for bb in mlil.basic_blocks:
        if bb.end <= bb.start or len(bb.incoming_edges) < 2:
            continue
        tail = mlil[bb.end - 1]
        if tail.operation != MediumLevelILOperation.MLIL_IF:
            continue
        cond = _resolve_cond(tail)
        if getattr(cond, "operation", None) not in _REL_OPS:
            continue
        if not any(
            _follow_copies(mlil, var) == compare_var for var in _vars_in(cond)
        ):
            continue
        candidates.append((len(bb.incoming_edges), bb))
    if not candidates:
        return None
    incoming, dispatcher = max(candidates, key=lambda item: item[0])
    state_var = compare_var
    # The compare scratch may have partial-register writes elsewhere, making a
    # whole-function copy chase ambiguous. Its dispatcher-local seed is still
    # explicit (for example ``rax_10 = i``), so use that source as maintained
    # state even when ``rax_10.al`` is also written in OBBs.
    for ins in dispatcher:
        if ins.operation != MediumLevelILOperation.MLIL_SET_VAR:
            continue
        if ins.dest != compare_var:
            continue
        src = getattr(ins, "src", None)
        if src is not None and src.operation.name in _VAR_OPS:
            state_var = _follow_copies(mlil, src.src)
            break
    return dispatcher, compare_var, state_var, incoming


def _state_write_in(bb, state_var, before):
    writes = [
        ins for ins in bb
        if ins.instr_index < before.instr_index
        and ins.operation == MediumLevelILOperation.MLIL_SET_VAR
        and ins.dest == state_var
    ]
    return writes[-1] if writes else None


def _is_passthrough(mlil, write, compare_var, state_var):
    src = getattr(write, "src", None)
    return src is not None and _is_routed_expr(
        mlil, src, compare_var, state_var
    )


def _leaf_nodes(mlil, compare_var, state_var, disp_start):
    """Equality leaves, including original blocks fused into a leaf itself."""
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
            if not _is_routed_expr(mlil, side, compare_var, state_var):
                continue
            is_ne = cmp_il.operation == MediumLevelILOperation.MLIL_CMP_NE
            match = mlil[if_il.false if is_ne else if_il.true].il_basic_block
            inline = False
            if match.start == disp_start:
                write = _state_write_in(bb, state_var, if_il)
                if write is not None and not _is_passthrough(
                    mlil, write, compare_var, state_var
                ):
                    match = bb
                    inline = True
            leaves.append((if_il, _deref_temp(mlil, other), match, inline))
            break
    return leaves


def _signed(value, size):
    bits = (size or 4) * 8
    value &= (1 << bits) - 1
    sign = 1 << (bits - 1)
    return value - (1 << bits) if value & sign else value


def _condition_for_state(func, mlil, if_il, compare_var, state_var, state):
    """Evaluate a dispatcher comparison for one concrete state, or None."""
    cmp_il = _resolve_cond(if_il)
    if getattr(cmp_il, "operation", None) not in _REL_OPS:
        return None

    def operand(expr):
        if _is_routed_expr(mlil, expr, compare_var, state_var):
            return state & U32
        values = eval_consts(func, _deref_temp(mlil, expr))
        return (next(iter(values)) & U32) if len(values) == 1 else None

    left, right = operand(cmp_il.left), operand(cmp_il.right)
    if left is None or right is None:
        return None
    op = cmp_il.operation
    if op == MediumLevelILOperation.MLIL_CMP_E:
        return left == right
    if op == MediumLevelILOperation.MLIL_CMP_NE:
        return left != right
    if op in {
        MediumLevelILOperation.MLIL_CMP_SLT,
        MediumLevelILOperation.MLIL_CMP_SLE,
        MediumLevelILOperation.MLIL_CMP_SGE,
        MediumLevelILOperation.MLIL_CMP_SGT,
    }:
        size = cmp_il.left.size or cmp_il.right.size or 4
        left, right = _signed(left, size), _signed(right, size)
    if op in {MediumLevelILOperation.MLIL_CMP_SLT, MediumLevelILOperation.MLIL_CMP_ULT}:
        return left < right
    if op in {MediumLevelILOperation.MLIL_CMP_SLE, MediumLevelILOperation.MLIL_CMP_ULE}:
        return left <= right
    if op in {MediumLevelILOperation.MLIL_CMP_SGE, MediumLevelILOperation.MLIL_CMP_UGE}:
        return left >= right
    if op in {MediumLevelILOperation.MLIL_CMP_SGT, MediumLevelILOperation.MLIL_CMP_UGT}:
        return left > right
    return None


def _route_state(func, mlil, dispatcher, compare_var, state_var, state, known):
    """Run a concrete state through the comparison tree to its OBB head."""
    block, seen = dispatcher, set()
    while block.start not in seen:
        seen.add(block.start)
        if block.start != dispatcher.start and block.start in known:
            return block
        if block.end <= block.start:
            return None
        tail = mlil[block.end - 1]
        if tail.operation != MediumLevelILOperation.MLIL_IF:
            return block if block.start != dispatcher.start else None
        decision = _condition_for_state(
            func, mlil, tail, compare_var, state_var, state
        )
        if decision is None:
            return block if block.start != dispatcher.start else None
        target = tail.true if decision else tail.false
        block = mlil[target].il_basic_block
    return None


def _reaches_dispatcher(block, disp_start):
    seen, queue = set(), deque([block])
    while queue:
        current = queue.popleft()
        if current.start == disp_start:
            return True
        if current.start in seen:
            continue
        seen.add(current.start)
        queue.extend(edge.target for edge in current.outgoing_edges)
    return False


def _augment_state_map(func, mlil, dispatcher, compare_var, state_var, state_map):
    """Add implicit/default leaves by concretely routing observed state writes.

    A binary-search dispatcher need not equality-test every legal state. One
    value can be identified solely by the range constraints leading to the
    default leaf. Those states still appear as constants written by OBBs, so
    route each observed write through the tree and recover its target.
    """
    observed = set(state_map)
    for defn in mlil.get_var_definitions(state_var):
        if not _reaches_dispatcher(defn.il_basic_block, dispatcher.start):
            continue
        observed |= {
            value & U32
            for value in eval_consts(
                func,
                getattr(defn, "src", None),
                scope={defn.il_basic_block.start},
            )
        }

    known_heads = {bb.start for bb in state_map.values()}
    added = 0
    for state in observed - set(state_map):
        target = _route_state(
            func, mlil, dispatcher, compare_var, state_var, state, known_heads
        )
        if target is None or target.start == dispatcher.start:
            continue
        state_map[state] = target
        known_heads.add(target.start)
        added += 1
        log_debug(
            f"[direct32] implicit state {state:#x} routes to "
            f"{mlil[target.start].address:#x}"
        )
    return added


def _forward_region(head, disp_start):
    region, queue = set(), deque([head])
    while queue:
        bb = queue.popleft()
        if bb.start in region:
            continue
        region.add(bb.start)
        for edge in bb.outgoing_edges:
            if edge.target.start != disp_start and edge.target.start not in region:
                queue.append(edge.target)
    return region


def _prologue(mlil, disp_start):
    stops = {disp_start}
    try:
        stops.update(e.target.start for e in mlil[disp_start].il_basic_block.outgoing_edges)
    except Exception:  # noqa: BLE001
        pass
    region, exit_il = set(), None
    queue = deque([mlil.basic_blocks[0]])
    while queue:
        bb = queue.popleft()
        if bb.start in region:
            continue
        region.add(bb.start)
        for edge in bb.outgoing_edges:
            if edge.target.start in stops:
                if exit_il is None:
                    exit_il = mlil[bb.end - 1]
            elif edge.target.start not in region:
                queue.append(edge.target)
    return region, exit_il


def _region_exit(mlil, head, region, disp_start, leaf_blocks):
    seen, queue = set(), deque([head])
    while queue:
        bb = queue.popleft()
        if bb.start in seen:
            continue
        seen.add(bb.start)
        for edge in bb.outgoing_edges:
            succ = edge.target
            if succ.start == disp_start or any(
                e.source.start not in region and e.source.start not in leaf_blocks
                for e in succ.incoming_edges
            ):
                return mlil[bb.end - 1]
            if succ.start not in seen:
                queue.append(succ)
    return None


def _enumerate_regions(mlil, leaves, disp_start, extra_heads=()):
    leaf_blocks = {if_il.il_basic_block.start for if_il, _, _, _ in leaves}
    regions = []
    prologue, prologue_exit = _prologue(mlil, disp_start)
    if prologue_exit is not None:
        regions.append((mlil.basic_blocks[0], prologue, prologue_exit, False))
    else:
        log_warn("[direct32] the entry path never reaches the dispatcher")
    seen = {mlil.basic_blocks[0].start}
    for if_il, _value, head, inline in leaves:
        if head.start in seen:
            continue
        seen.add(head.start)
        if inline:
            regions.append((head, {head.start}, if_il, True))
            continue
        region = _forward_region(head, disp_start)
        regions.append(
            (
                head,
                region,
                _region_exit(mlil, head, region, disp_start, leaf_blocks),
                False,
            )
        )
    for head in extra_heads:
        if head.start in seen or head.start == disp_start:
            continue
        seen.add(head.start)
        region = _forward_region(head, disp_start)
        regions.append(
            (
                head,
                region,
                _region_exit(mlil, head, region, disp_start, leaf_blocks),
                False,
            )
        )
    return regions, leaf_blocks


def _definition_reaches_exit(mlil, defn, state_var, region, exit_il):
    """Whether ``defn`` can reach the region exit without being overwritten."""
    if exit_il is None:
        return True
    exit_start = exit_il.il_basic_block.start
    start = defn.il_basic_block
    queue, seen = deque([start]), set()
    while queue:
        block = queue.popleft()
        if block.start in seen:
            continue
        seen.add(block.start)
        writes = [
            ins for ins in block
            if ins.operation == MediumLevelILOperation.MLIL_SET_VAR
            and ins.dest == state_var
            and (block.start != start.start or ins.instr_index > defn.instr_index)
        ]
        if writes:
            continue
        if block.start == exit_start:
            return True
        for edge in block.outgoing_edges:
            if edge.target.start in region and edge.target.start not in seen:
                queue.append(edge.target)
    return False


def _state_values(func, mlil, state_var, region, exit_il=None):
    values = set()
    for defn in mlil.get_var_definitions(state_var):
        if (
            defn.il_basic_block.start in region
            and _definition_reaches_exit(
                mlil, defn, state_var, region, exit_il
            )
        ):
            values |= {
                value & U32
                for value in eval_consts(func, getattr(defn, "src", None), scope=region)
            }
    return values


def _cmov_arm(func, mlil, state_var, region, leaf_blocks):
    arms, seen_vars = [], set()
    queue = deque([(state_var, 0)])
    while queue:
        var, depth = queue.popleft()
        if var in seen_vars or depth > _COPY_LIMIT:
            continue
        seen_vars.add(var)
        for defn in mlil.get_var_definitions(var):
            block = defn.il_basic_block
            if block.start not in region:
                continue
            if len(block.incoming_edges) == 1:
                pred = block.incoming_edges[0].source
                if pred.start not in leaf_blocks:
                    if_il = mlil[pred.end - 1]
                    if if_il.operation == MediumLevelILOperation.MLIL_IF:
                        values = {
                            value & U32
                            for value in eval_consts(
                                func, getattr(defn, "src", None), scope=region
                            )
                        }
                        if len(values) == 1:
                            pred_writes_state = any(
                                candidate.operation
                                == MediumLevelILOperation.MLIL_SET_VAR
                                and candidate.dest == state_var
                                for candidate in pred
                            )
                            arms.append(
                                (
                                    values.pop(),
                                    if_il,
                                    mlil[if_il.true].il_basic_block.start == block.start,
                                    pred_writes_state,
                                )
                            )
            src = getattr(defn, "src", None)
            if src is not None and src.operation.name in _VAR_OPS:
                queue.append((src.src, depth + 1))
    # Nested flattened code inside an OBB can put the default state write in a
    # block that itself hangs off an unrelated predicate. The real cmov arm is
    # the one whose predicate block contains the other/default state write.
    preferred = [arm for arm in arms if arm[3]]
    if len(preferred) == 1:
        arms = preferred
    if len(arms) != 1:
        if arms:
            log_debug(
                f"[direct32] {state_var} is selected by {len(arms)} arms, not one"
            )
        return None
    return arms[0][:3]


def _through_ssa_copies(ssa, instr):
    for _ in range(_COPY_LIMIT):
        if instr is None:
            return None
        src = getattr(instr, "src", None)
        if not hasattr(src, "operation"):
            return instr
        if src.operation != MediumLevelILOperation.MLIL_VAR_SSA:
            return instr
        instr = ssa.get_ssa_var_definition(src.src)
    return None


def _block_of(il):
    try:
        return il.il_basic_block
    except Exception:  # noqa: BLE001
        return None


def _liftable_operands(mlil, expr):
    for node in expr.traverse(lambda x: x):
        if (
            node.operation == MediumLevelILOperation.MLIL_VAR
            and len(mlil.get_var_definitions(node.src)) > 1
        ):
            return False
    return True


def _liftable_condition(mlil, if_il):
    cond = _resolve_cond(if_il)
    if cond is None or not hasattr(cond, "operation"):
        return None
    return cond if _liftable_operands(mlil, cond) else None


def _phi_selection(func, mlil, state_var, region):
    """Two-state selection made outside the region and carried in through SSA."""
    def decline(reason):
        log_debug(f"[direct32] {state_var}: no remote selection: {reason}")
        return None

    defs = [
        d for d in mlil.get_var_definitions(state_var)
        if d.il_basic_block.start in region
    ]
    if len(defs) != 1:
        return decline(f"{len(defs)} in-region state writes, need one")
    seed = defs[0]
    for _ in range(_COPY_LIMIT):
        src = getattr(seed, "src", None)
        if src is None or src.operation.name not in _VAR_OPS:
            break
        src_defs = [
            d for d in mlil.get_var_definitions(src.src)
            if d.il_basic_block.start in region
        ]
        if len(src_defs) != 1:
            break
        seed = src_defs[0]
    try:
        ssa = mlil.ssa_form
        phi = _through_ssa_copies(ssa, seed.ssa_form)
    except Exception as exc:  # noqa: BLE001
        return decline(f"SSA unavailable ({exc})")
    if phi is None or phi.operation != MediumLevelILOperation.MLIL_VAR_PHI:
        got = "nothing" if phi is None else phi.operation.name
        return decline(f"SSA chain ends at {got}, not a phi")
    values, arms = set(), []
    for version in phi.src:
        try:
            defn = _through_ssa_copies(ssa, ssa.get_ssa_var_definition(version))
            non_ssa = None if defn is None else defn.non_ssa_form
        except Exception as exc:  # noqa: BLE001
            return decline(f"phi operand {version} did not resolve ({exc})")
        if non_ssa is None:
            return decline(f"phi operand {version} has no non-SSA definition")
        block = _block_of(non_ssa)
        if block is None:
            return decline(f"phi operand {version} is in no block")
        resolved = eval_consts(
            func, getattr(non_ssa, "src", None), scope={block.start}
        )
        if len(resolved) != 1:
            return decline(f"phi operand {version} has {len(resolved)} values")
        value = next(iter(resolved)) & U32
        values.add(value)
        if len(block.incoming_edges) == 1:
            if_il = mlil[block.incoming_edges[0].source.end - 1]
            if if_il.operation == MediumLevelILOperation.MLIL_IF:
                arms.append(
                    (
                        value,
                        if_il,
                        mlil[if_il.true].il_basic_block.start == block.start,
                    )
                )
    if len(values) != 2 or len(arms) != 1:
        return decline(f"phi has {len(values)} values and {len(arms)} predicate arms")
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
    carried = getattr(defs[0], "src", None)
    if (
        carried is None
        or not hasattr(carried, "operation")
        or not _liftable_operands(mlil, carried)
    ):
        return decline("neither predicate nor carried value is safe to lift")
    return {
        "values": values,
        "alt_val": alt_val,
        "if_il": if_il,
        "then_is_true": True,
        "cmp_src": carried,
        "cmp_val": alt_val,
        "cmp_size": carried.size or 4,
    }


class _Context:
    def __init__(self, func, mlil, state_var, state_map, leaf_blocks):
        self.func = func
        self.mlil = mlil
        self.state_var = state_var
        self.state_map = state_map
        self.leaf_blocks = leaf_blocks
        self.terminal = 0
        self.unresolved = 0
        self.missing = set()


def _region_plan(ctx, head, region, exit_il, inline):
    where = hex(ctx.mlil[head.start].address)
    if exit_il is None:
        ctx.terminal += 1
        return None
    values = _state_values(
        ctx.func, ctx.mlil, ctx.state_var, region, exit_il
    )
    outside = None
    if not values:
        outside = _phi_selection(ctx.func, ctx.mlil, ctx.state_var, region)
        if outside is not None:
            values = set(outside["values"])
            log_info(
                f"[direct32] {where}: state selected outside the region by "
                f"diamond @ {outside['if_il'].address:#x}"
            )
    if not values:
        ctx.unresolved += 1
        log_warn(f"[direct32] {where}: no resolvable next-state value")
        return None
    if len(values) == 1:
        state = next(iter(values)) & U32
        if state not in ctx.state_map:
            ctx.missing.add(state)
            log_info(f"[direct32] {where}: state {state:#x} is not dispatched here")
            return None
        return {
            "kind": "uncond",
            "obb": head,
            "jump": exit_il,
            "target_bb": ctx.state_map[state],
        }
    if len(values) != 2:
        ctx.unresolved += 1
        log_warn(
            f"[direct32] {where}: state resolves to {len(values)} values, not one "
            "conditional selection"
        )
        return None
    arm = (
        (outside["alt_val"], outside["if_il"], outside["then_is_true"])
        if outside is not None
        else _cmov_arm(ctx.func, ctx.mlil, ctx.state_var, region, ctx.leaf_blocks)
    )
    if arm is None:
        ctx.unresolved += 1
        log_warn(f"[direct32] {where}: could not identify the conditional state arm")
        return None
    alt_val, if_il, then_is_true = arm
    alt_val &= U32
    defaults = [value for value in values if value != alt_val]
    if len(defaults) != 1:
        ctx.unresolved += 1
        return None
    default_val = defaults[0] & U32
    missing = {value for value in (alt_val, default_val) if value not in ctx.state_map}
    if missing:
        ctx.missing.update(missing)
        log_info(
            f"[direct32] {where}: successor state(s) "
            f"{[hex(v) for v in sorted(missing)]} are not dispatched here"
        )
        return None
    alt_succ, default_succ = ctx.state_map[alt_val], ctx.state_map[default_val]
    shared = inline or outside is not None or any(
        edge.source.start not in region and edge.source.start not in ctx.leaf_blocks
        for edge in if_il.il_basic_block.incoming_edges
    )
    if not shared:
        return {
            "kind": "cmov_diamond",
            "obb": head,
            "if_il": if_il,
            "then_is_true": then_is_true,
            "alt_succ": alt_succ,
            "default_succ": default_succ,
            "alt_state": alt_val,
            "default_state": default_val,
        }
    cond_src, cmp_info = None, None
    if outside is not None:
        if "cond_src" in outside:
            cond_src = outside["cond_src"]
        else:
            cmp_info = (
                outside["cmp_src"], outside["cmp_val"], outside["cmp_size"]
            )
        cond_def = None
    else:
        cond = if_il.condition
        if cond.operation.name == "MLIL_VAR":
            defs = [
                d for d in ctx.mlil.get_var_definitions(cond.src)
                if d.il_basic_block.start in region
            ]
            if len(defs) != 1:
                ctx.unresolved += 1
                return None
            cond_def, cond_src = defs[0], defs[0].src
        else:
            cond_def, cond_src = None, cond
        if cond_def is not None and cond_def.il_basic_block.start != exit_il.il_basic_block.start:
            ctx.unresolved += 1
            return None
    if then_is_true:
        true_succ, false_succ = alt_succ, default_succ
    else:
        true_succ, false_succ = default_succ, alt_succ
    return {
        "kind": "cmov_obb",
        "obb": head,
        "tail_goto": exit_il,
        "cond_src": cond_src,
        "cmp_info": cmp_info,
        "true_succ": true_succ,
        "false_succ": false_succ,
        "alt_state": alt_val,
        "default_state": default_val,
    }


def _apply_uncond(mlil, plan):
    jump = plan["jump"]
    mlil.replace_expr(
        jump.expr_index,
        mlil.goto(_label(plan["target_bb"].start), ILSourceLocation.from_instruction(jump)),
    )
    return 1


def _apply_cmov_diamond(mlil, plan):
    if_il = plan["if_il"]
    then_is_true = plan["then_is_true"]
    alt_arm = mlil[if_il.true if then_is_true else if_il.false].il_basic_block
    default_arm = mlil[if_il.false if then_is_true else if_il.true].il_basic_block
    alt_tail, default_tail = mlil[alt_arm.end - 1], mlil[default_arm.end - 1]
    mlil.replace_expr(
        alt_tail.expr_index,
        mlil.goto(_label(plan["alt_succ"].start), ILSourceLocation.from_instruction(alt_tail)),
    )
    mlil.replace_expr(
        default_tail.expr_index,
        mlil.goto(
            _label(plan["default_succ"].start),
            ILSourceLocation.from_instruction(default_tail),
        ),
    )
    return 1


def _apply_cmov_obb(mlil, plan):
    tail = plan["tail_goto"]
    location = ILSourceLocation.from_instruction(tail)
    if plan.get("cmp_info") is not None:
        src, value, size = plan["cmp_info"]
        condition = mlil.compare_equal(
            1, mlil.copy_expr(src), mlil.const(size, value, location), location
        )
    else:
        condition = mlil.copy_expr(plan["cond_src"])
    mlil.replace_expr(
        tail.expr_index,
        mlil.if_expr(
            condition,
            _label(plan["true_succ"].start),
            _label(plan["false_succ"].start),
            location,
        ),
    )
    return 1


_HANDLERS = {
    "uncond": _apply_uncond,
    "cmov_diamond": _apply_cmov_diamond,
    "cmov_obb": _apply_cmov_obb,
}


class Direct32Shape(FlattenerShape):
    name = "ollvm_direct_32"
    mode = MODE_DIRECT_32
    uses_gadget_cleanup = False

    def recognise(self, bv, func, mlil):
        if find_dispatcher(mlil) is None:
            return (False, "no high-fan-in 32-bit relational dispatcher found")
        return (True, "")

    def solve(self, bv, func, mlil):
        found = find_dispatcher(mlil)
        if found is None:
            log_warn(f"[direct32] {func.name}: no 32-bit dispatcher found")
            return ShapeResult()
        disp_bb, compare_var, state_var, incoming = found
        log_info(
            f"[direct32] {func.name}: dispatcher @ {mlil[disp_bb.start].address:#x} "
            f"({incoming} incoming), compare {compare_var}, state {state_var}"
        )
        if _disable_tail_call_settings(bv, "direct32"):
            return ShapeResult()
        if _absorb_split_body(bv, func, "direct32"):
            return ShapeResult()
        leaves = _leaf_nodes(mlil, compare_var, state_var, disp_bb.start)
        if not leaves:
            log_warn(f"[direct32] {func.name}: dispatcher has no equality leaves")
            return ShapeResult()
        state_map = {}
        for if_il, value_expr, head, _inline in leaves:
            values = {value & U32 for value in eval_consts(func, value_expr)}
            if len(values) == 1:
                state_map[next(iter(values))] = head
            else:
                log_debug(
                    f"[direct32] leaf @ {if_il.address:#x}: compare value is not constant"
                )
        if len(state_map) < 3:
            log_warn(f"[direct32] {func.name}: only {len(state_map)} concrete states")
            return ShapeResult()
        implicit = _augment_state_map(
            func, mlil, disp_bb, compare_var, state_var, state_map
        )
        if implicit:
            log_info(
                f"[direct32] {func.name}: recovered {implicit} implicit/default "
                "dispatcher state(s) from observed transitions"
            )
        regions, leaf_blocks = _enumerate_regions(
            mlil, leaves, disp_bb.start, set(state_map.values())
        )
        ctx = _Context(func, mlil, state_var, state_map, leaf_blocks)
        plans, anchors = [], set()
        for head, region, exit_il, inline in regions:
            plan = _region_plan(ctx, head, region, exit_il, inline)
            if plan is None:
                continue
            anchor = plan.get("jump") or plan.get("if_il") or plan.get("tail_goto")
            if anchor.expr_index in anchors:
                continue
            anchors.add(anchor.expr_index)
            plans.append(plan)
        log_info(
            f"[direct32] {func.name}: {len(state_map)} states, "
            f"{len(plans)}/{len(regions)} region transitions recovered"
        )
        if ctx.terminal:
            log_info(f"[direct32] {func.name}: {ctx.terminal} terminal region(s)")
        if ctx.missing:
            log_info(
                f"[direct32] {func.name}: {len(ctx.missing)} successor state(s) "
                "are dispatched outside this function"
            )
        if ctx.unresolved:
            log_warn(f"[direct32] {func.name}: {ctx.unresolved} transition(s) unresolved")
        return ShapeResult(
            state_var=state_var,
            state_map=state_map,
            redirections=plans,
            state_write_vars={state_var, compare_var},
            notes={
                "dispatcher": disp_bb.start,
                "compare_var": compare_var,
                "regions": len(regions),
                "unresolved": ctx.unresolved,
            },
        )

    def apply(self, mlil, result):
        applied = 0
        for plan in result.redirections:
            handler = _HANDLERS.get(plan["kind"])
            if handler is None:
                continue
            try:
                applied += handler(mlil, plan)
            except Exception as exc:  # noqa: BLE001
                anchor = plan.get("jump") or plan.get("if_il") or plan.get("tail_goto")
                where = 0 if anchor is None else anchor.address
                log_warn(f"[direct32] failed to rewrite {where:#x}: {exc}")
        if applied:
            mlil.finalize()
            mlil.generate_ssa_form()
        return applied
