"""Workflow activity callbacks for DispatchThis.

The deflatten activity is shared by every mode, so it resolves the mode enabled
on the function and dispatches to that shape's pipeline. OLLVM_INDIRECT_32 runs
the original sequence (state machine, gadget-shape redirections, cleanup), while
OLLVM_DIRECT_32 and OLLVM_XOR_64 hand the whole job to their shape modules.

The indirect jump/call resolvers are not part of either pipeline. They are their
own toggle, INDIRECT_JUMP_CALL, because resolving obfuscated jumps is useful on a
function that is not flattened at all. OLLVM_INDIRECT_32 turns them on as well,
since its dispatcher cannot be recovered until they have reconnected the CFG.
"""

from binaryninja import AnalysisContext, Settings

from .passes.medium.deflatten import apply_redirections_il, compute_redirections
from .passes.medium.nop_pass import clean_resolved_gadget_jumps
from .passes.medium.indirect_calls import patch_indirect_calls
from .shapes import MODE_INDIRECT_32, MODES, for_mode
from .utils import StateMachine
from .passes.low.gadget_llil import resolve_and_rewrite_llil_jumps
from .utils.log import log_info, log_warn, log_debug


def _active_mode(func):
    """The mode enabled on ``func``, or None.

    Queried in precedence order so that if more than one toggle is somehow
    enabled, the first wins and the rest are reported as ignored rather than
    silently combined into a pipeline nobody designed.
    """
    settings = Settings()
    enabled = [mode for mode in MODES if settings.get_bool(mode, func)]
    if not enabled:
        return None
    if len(enabled) > 1:
        log_warn(
            f"[workflow] {func.name}: {len(enabled)} modes enabled; using "
            f"{enabled[0]}, ignoring {', '.join(enabled[1:])}"
        )
    return enabled[0]


def workflow_resolve_jumps_llil(analysis_context: AnalysisContext):
    func = analysis_context.function
    bv = analysis_context.view

    log_info(f"[dispatchthis] resolve_llil invoked @ {func.start:#x}")
    llil = analysis_context.llil
    gadget_map = bv.session_data.setdefault("dispatchthis_gadget_map", {})
    func_map = gadget_map.setdefault(func.start, {})
    resolved = resolve_and_rewrite_llil_jumps(bv, llil, func_map)
    log_info(f"[dispatchthis] resolve_llil @ {func.start:#x}: rewrote {len(resolved)} jump(s)")
    if resolved:
        func_map.update(resolved)
        log_info(f"[workflow] {func.name}: rewrote {len(resolved)} indirect jump(s) to direct")
    else:
        llil_stable = bv.session_data.setdefault("dispatchthis_llil_stable", {})
        log_info(f"All of {func.name}'s indirect jumps have been resolved")
        llil_stable[func.start] = True


def workflow_resolve_calls_mlil(analysis_context: AnalysisContext):
    func = analysis_context.function
    bv = analysis_context.view

    mlil = analysis_context.mlil
    if mlil is None:
        return
    n = patch_indirect_calls(bv, mlil)
    if n:
        log_info(f"[workflow] {func.name}: resolved {n} indirect call(s)")


def _deflatten_indirect(bv, func, mlil):
    """OLLVM_INDIRECT_32: 32-bit state behind decode-gadget jumps."""
    # Don't deflatten until the LLIL pass has drained every indirect jump --
    # otherwise the CFG is still incomplete and the state machine is partial.
    llil_stable = bv.session_data.setdefault("dispatchthis_llil_stable", {})
    if not llil_stable.get(func.start):
        return

    # MLIL rewrites are overlays on LLIL and reverted on each regeneration, so deflatten re-applies every pass.
    sm = StateMachine(bv, func).analyze()
    if sm.state_var is None:
        return

    # {jump_addr: target} recovered by the LLIL pass that resolved indirect jumps
    gadget_map = bv.session_data.get("dispatchthis_gadget_map", {}).get(func.start, {})
    if not gadget_map:
        log_warn(f"[workflow] {func.name}: no resolved gadget map; nothing to deflatten")
        return

    # Stash state constants and variable aliases so cleanup can precisely NOP state writes.
    state_consts = set(sm.backbone.keys())
    bv.session_data.setdefault("dispatchthis_state_consts", {})[func.start] = state_consts
    bv.session_data.setdefault("dispatchthis_state_vars", {})[func.start] = sm.state_write_vars
    log_info(f"[workflow] {func.name}: recorded {len(state_consts)} dispatcher state constant(s)")

    redirections = compute_redirections(bv, func, sm=sm, gadget_map=gadget_map)
    applied = apply_redirections_il(func.medium_level_il, redirections) if redirections else 0

    if applied:
        mlil_stable = bv.session_data.setdefault("dispatchthis_mlil_stable", {})
        log_info(f"{func.name} has been deflattened")
        mlil_stable[func.start] = True


def _deflatten_shape(bv, func, mlil, mode):
    """Any mode whose shape owns its own solving and rewriting."""
    shape = for_mode(mode)
    if shape is None:
        log_warn(f"[workflow] {func.name}: no shape registered for {mode}")
        return

    # Advisory only. The mode is authoritative, so a mismatch is reported and the
    # shape still runs -- a deliberately forced mode has to be able to run.
    ok, reason = shape.recognise(bv, func, mlil)
    if not ok:
        log_warn(
            f"[workflow] {func.name}: {shape.name} selected but {reason}; "
            f"running anyway"
        )

    result = shape.solve(bv, func, mlil)
    if not result.ok:
        return

    bv.session_data.setdefault("dispatchthis_state_consts", {})[func.start] = set(
        result.state_map
    )
    bv.session_data.setdefault("dispatchthis_state_vars", {})[func.start] = (
        result.state_write_vars
    )

    applied = shape.apply(func.medium_level_il, result)
    if not applied:
        return
    log_info(f"{func.name} has been deflattened ({applied} rewrite(s), {shape.name})")

    # ``dispatchthis_mlil_stable`` is what releases the separate gadget-cleanup
    # activity, so it is only set for shapes that explicitly want it. Direct32
    # has no decode gadgets, and XOR64's 64-bit state constants resemble keys.
    if shape.uses_gadget_cleanup:
        bv.session_data.setdefault("dispatchthis_mlil_stable", {})[func.start] = True


def workflow_deflatten_mlil(analysis_context: AnalysisContext):
    func = analysis_context.function
    bv = analysis_context.view
    mlil = func.mlil
    if mlil is None:
        return

    # Eligibility already gated this activity on *some* mode being enabled; which
    # one decides the pipeline.
    mode = _active_mode(func)
    if mode is None:
        log_debug(f"[workflow] {func.name}: no mode enabled, skipping deflatten")
        return

    if mode == MODE_INDIRECT_32:
        _deflatten_indirect(bv, func, mlil)
    else:
        _deflatten_shape(bv, func, mlil, mode)


def workflow_cleanup(analysis_context: AnalysisContext):
    func = analysis_context.function
    bv = analysis_context.view
    mlil = func.mlil
    if mlil is None:
        return

    # Skip until deflatten has stabilized; reapply every pass since MLIL rewrites are reverted by each regeneration.
    mlil_stable = bv.session_data.setdefault("dispatchthis_mlil_stable", {})
    if not mlil_stable.get(func.start):
        log_debug(f"[workflow] {func.name}: deflattener has not run yet, skipping cleanup")
        return

    # Convert remaining gadget jumps to gotos and NOP dead decode gadgets.
    clean_resolved_gadget_jumps(bv, func)

    log_info(f"{func.name} has been cleaned")
