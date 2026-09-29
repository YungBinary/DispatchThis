"""Constant evaluation for dispatcher-state recovery.

Flatteners rarely hand the dispatcher a bare immediate. The OLLVM_XOR_64 shape
materialises each compare value as ``base + displacement``, where ``base`` is a
64-bit integer handed in by the caller under a non-standard calling convention,
and builds each next-state value by XOR-ing a register pair. Recovering the
state map therefore needs a small evaluator over MLIL expressions rather than a
pattern match against ``MLIL_CONST``.

Two pieces:

  * :func:`eval_consts` -- evaluate an MLIL expression to the set of concrete
    64-bit values it can hold, following variable definitions and folding
    add/sub/xor.
  * :func:`bind_bases_from_callers` / :func:`solve_base_by_voting` -- pin a
    function's parameters to concrete values. A parameter has no definition
    inside its own function (an SSA version-0 variable has no defining
    instruction), so its value has to come from the callers, or be solved from
    the function's own internal consistency. These are primitives, not a
    pipeline: the order to try them in, and what a vote is scored against, are
    shape-specific, so each shape orchestrates them itself.

Deliberately narrow: only the operations the supported shapes actually use are
folded. Widening it is how a future shape gets support, and an unrecognised
operation yields the empty set, which every caller already treats as "unknown".
"""

from collections import Counter

from .log import log_debug, log_info, log_warn

U32 = 0xFFFFFFFF
U64 = 0xFFFFFFFFFFFFFFFF

# Guards against pathological expression graphs. A legitimate state value
# resolves to one constant, and a cmov-selected one to two; anything that fans
# out past MAX_RESULTS is a merge point we cannot attribute to a single block.
MAX_DEPTH = 32
MAX_RESULTS = 8

_CONST_OPS = ("MLIL_CONST", "MLIL_CONST_PTR")
_VAR_OPS = ("MLIL_VAR", "MLIL_VAR_FIELD")

_FOLD = {
    "MLIL_ADD": lambda a, b: (a + b) & U64,
    "MLIL_SUB": lambda a, b: (a - b) & U64,
    "MLIL_XOR": lambda a, b: (a ^ b) & U64,
}

# Every MLIL flavour of a call, including the tail-call family. The OLLVM_XOR_64
# sample reaches its flattened worker by tail call, so matching only MLIL_CALL
# would find no call sites at all and silently lose every base binding.
_CALL_OPS = (
    "MLIL_CALL", "MLIL_CALL_SSA", "MLIL_CALL_UNTYPED", "MLIL_CALL_UNTYPED_SSA",
    "MLIL_TAILCALL", "MLIL_TAILCALL_SSA",
    "MLIL_TAILCALL_UNTYPED", "MLIL_TAILCALL_UNTYPED_SSA",
)


def mask_for_size(size):
    """Constant mask for an MLIL expression of the given byte width."""
    return (1 << ((size or 8) * 8)) - 1


def eval_consts(func, expr, bases=None, scope=None, _depth=0, _seen=None):
    """Concrete 64-bit values ``expr`` can hold; empty set when unknown.

    ``bases`` maps ``Variable`` to a known constant, used for parameters that
    cannot be resolved from inside the function.

    ``scope`` optionally restricts which basic blocks' definitions may be
    followed, by block *start* index. That makes resolution path-sensitive,
    which matters when the obfuscator shares a state-store tail across several
    original blocks: a global resolve then sees every sibling's value, while a
    resolve scoped to one block's forward region sees only its own.
    """
    if expr is None or _depth > MAX_DEPTH:
        return set()
    if not hasattr(expr, "operation"):
        return set()
    if bases is None:
        bases = {}
    if _seen is None:
        _seen = frozenset()

    op = expr.operation.name

    if op in _CONST_OPS:
        return {expr.constant & U64}

    if op in _VAR_OPS:
        var = expr.src
        if var in bases:
            return {bases[var] & U64}
        if var in _seen:
            return set()
        inner = _seen | {var}
        out = set()
        for defn in func.mlil.get_var_definitions(var):
            if scope is not None and defn.il_basic_block.start not in scope:
                continue
            out |= eval_consts(
                func, getattr(defn, "src", None), bases, scope, _depth + 1, inner
            )
            if len(out) > MAX_RESULTS:
                return set()
        return out

    fold = _FOLD.get(op)
    if fold is not None:
        left = eval_consts(func, expr.left, bases, scope, _depth + 1, _seen)
        if not left:
            return set()
        right = eval_consts(func, expr.right, bases, scope, _depth + 1, _seen)
        if not right:
            return set()
        if len(left) * len(right) > MAX_RESULTS:
            return set()
        return {fold(a, b) for a in left for b in right}

    return set()


def eval_defn_consts(func, instr, bases=None, scope=None):
    """Values assigned by ``instr``, i.e. :func:`eval_consts` over its source."""
    return eval_consts(func, getattr(instr, "src", None), bases, scope)


def split_base_disp(expr):
    """Decompose ``base + disp`` / ``base - disp`` into ``(base_var, disp)``.

    Returns ``(Variable, signed_displacement)`` or ``None``. A bare variable
    yields a displacement of 0, so ``cmp state, arg6`` is handled alongside
    ``cmp state, arg6 + 0x4e71d78f``.
    """
    if expr is None or not hasattr(expr, "operation"):
        return None
    op = expr.operation.name

    if op in _VAR_OPS:
        return (expr.src, 0)

    if op in ("MLIL_ADD", "MLIL_SUB"):
        sign = 1 if op == "MLIL_ADD" else -1
        left, right = expr.left, expr.right
        if left.operation.name in _VAR_OPS and right.operation.name in _CONST_OPS:
            return (left.src, (sign * right.constant) & U64)
        # Only ADD commutes; `disp - base` is not a base-plus-displacement.
        if (
            op == "MLIL_ADD"
            and right.operation.name in _VAR_OPS
            and left.operation.name in _CONST_OPS
        ):
            return (right.src, left.constant & U64)
    return None


def _parameter_vars(func):
    """This function's parameter variables, or [] if BN cannot supply them."""
    try:
        return list(func.parameter_vars)
    except Exception:  # noqa: BLE001
        log_debug("[const] parameter_vars unavailable; caller binding disabled")
        return []


def iter_call_sites(bv, func):
    """Every MLIL call or tail call in the view whose destination is ``func``.

    Driven off code refs rather than ``Function.caller_sites`` so tail calls are
    included regardless of whether that API reports them.
    """
    callers = {}
    try:
        refs = bv.get_code_refs(func.start)
    except Exception:  # noqa: BLE001
        return
    for ref in refs:
        caller = getattr(ref, "function", None)
        if caller is not None:
            callers[caller.start] = caller

    for caller in callers.values():
        mlil = caller.medium_level_il
        if mlil is None:
            continue
        for ins in mlil.instructions:
            if ins.operation.name not in _CALL_OPS:
                continue
            dest = getattr(ins, "dest", None)
            if dest is None or not hasattr(dest, "operation"):
                continue
            if dest.operation.name not in _CONST_OPS:
                continue
            if (dest.constant & U64) == (func.start & U64):
                yield caller, ins


def _arg_consts(caller, arg):
    """Values of one call argument.

    Untyped call variants list their parameters as bare variables rather than as
    expressions, so those are resolved through their definitions instead.
    """
    if hasattr(arg, "operation"):
        return eval_consts(caller, arg)
    out = set()
    try:
        defs = caller.mlil.get_var_definitions(arg)
    except Exception:  # noqa: BLE001
        return set()
    for d in defs:
        out |= eval_consts(caller, getattr(d, "src", None))
    return out


def bind_bases_from_callers(bv, func, base_vars):
    """Bind parameters in ``base_vars`` to the constant the call sites agree on.

    Returns ``{Variable: value}``. Only sites that actually reduce to a constant
    get a say. A flattened function is typically reached through a chain of tail
    calls that forward the bases along -- one site passes literals while the next
    forwards its own parameters -- so demanding that *every* site be concrete
    would bind nothing at all. Sites that stay symbolic are therefore ignored.

    Two sites that disagree on a *concrete* value do leave the parameter
    unbound: the compare tree can only be keyed by one value, so a genuine
    contradiction means this is the wrong way to obtain it and the caller should
    fall back to voting.
    """
    wanted = set(base_vars)
    if not wanted:
        return {}

    params = _parameter_vars(func)
    indices = {i: v for i, v in enumerate(params) if v in wanted}
    if not indices:
        log_debug(
            f"[const] none of the {len(wanted)} base(s) are parameters of "
            f"{func.name}; caller binding skipped"
        )
        return {}

    observed = {i: set() for i in indices}
    unresolved = {i: 0 for i in indices}
    sites = 0
    for caller, call_il in iter_call_sites(bv, func):
        sites += 1
        args = call_il.params
        for i in indices:
            if i >= len(args):
                # This site passes fewer arguments than BN inferred parameters.
                unresolved[i] += 1
                continue
            vals = _arg_consts(caller, args[i])
            if len(vals) == 1:
                observed[i].add(next(iter(vals)))
            else:
                unresolved[i] += 1

    if not sites:
        log_debug(f"[const] {func.name}: no call sites found; caller binding empty")
        return {}

    bases = {}
    for i, var in indices.items():
        if len(observed[i]) == 1:
            bases[var] = next(iter(observed[i]))
        elif len(observed[i]) > 1:
            log_warn(
                f"[const] {func.name}: {var} (parameter {i}) is passed "
                f"{len(observed[i])} different constants "
                f"({', '.join(hex(v) for v in sorted(observed[i]))}); left unbound"
            )
        else:
            log_debug(
                f"[const] {func.name}: {var} (parameter {i}) is not concrete at any "
                f"of the {sites} call site(s)"
            )

    bound = ", ".join(f"{v}={bases[v]:#x}" for v in bases) or "none"
    log_info(
        f"[const] {func.name}: {sites} call site(s) bound {len(bases)}/"
        f"{len(indices)} base(s): {bound}"
    )
    return bases


def solve_base_by_voting(displacements, target_states):
    """Solve a compare base from internal consistency alone.

    The state map keys are ``base + disp`` and the transitions produce concrete
    states, so the true base is the value that makes the most displacements land
    on a state the function actually transitions to. Candidates are exactly
    ``state - disp``, and the correct base is the one many pairs agree on.

    Returns ``(base_value, votes)``, or ``(None, 0)``.
    """
    if not displacements or not target_states:
        return (None, 0)
    tally = Counter(
        ((s - d) & U64) for s in target_states for d in displacements
    )
    if not tally:
        return (None, 0)
    base, votes = tally.most_common(1)[0]
    return (base, votes)
