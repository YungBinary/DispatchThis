"""DispatchThis -- IL-level deflattener for OLLVM-style control-flow flatteners.

Registers a clone of ``core.function.metaAnalysis``. Each supported flattener
shape is exposed as its own per-function mode in Function Analysis settings, and
the indirect jump/call resolvers are a toggle of their own:

  * ``INDIRECT_JUMP_CALL`` -- resolve decode-gadget indirect jumps and calls into
    direct ones, leaving any dispatcher alone. Not a flattener shape: it recovers
    no state and selects no solver. It stands alone because a function can have
    obfuscated jumps without being flattened.
  * ``OLLVM_INDIRECT_32`` -- decode-gadget indirect jumps/calls with a 32-bit
    dispatcher state. Implies ``INDIRECT_JUMP_CALL``, since the dispatcher cannot
    be recovered until the CFG is reconnected, then runs deflatten and the gadget
    cleanup.
  * ``OLLVM_DIRECT_32`` -- a 32-bit equality dispatcher whose original blocks
    return through ordinary direct gotos. Uses the same per-OBB region and SSA
    transition model as ``OLLVM_XOR_64``, reduced to one plain 32-bit state;
    it does not run indirect resolvers or signature-based gadget cleanup.
  * ``OLLVM_XOR_64`` -- 64-bit dispatcher state split across a register pair and
    recombined with XOR, with no indirect jumps or calls, so the resolvers do not
    apply. Deflattens only, with no cleanup: the shared gadget cleanup would
    read this shape's 64-bit state constants as decode keys, so it is off, and
    the dead state writes are left in place. A flattened body in this shape
    usually arrives
    split into several overlapping functions, because the body is littered with
    things Binary Ninja reads as function starts; the shape undefines the pieces
    its body falls into so their blocks come back.

Everything defaults to off, so the plugin stays inert until something is enabled
on a function. Where a mode is concerned it is authoritative: it selects which
shape solver runs, and a shape that does not recognise the function warns rather
than silently switching.
"""

import json
from binaryninja import Activity, Workflow, Settings
from .utils.log import log_warn

# Activity names double as per-function setting identifiers: BN's
# ``eligibility.auto`` generates a Function Analysis toggle whose ID is the
# activity name. They are defined in ``shapes/base.py`` so that shape modules can
# reference them without importing this package while it is still initialising.
from .shapes.base import (
    MODE_DIRECT_32,
    MODE_INDIRECT_32,
    MODE_XOR64,
    SETTING_INDIRECT_JUMP_CALL,
)
from .workflow import (
    workflow_resolve_jumps_llil,
    workflow_resolve_calls_mlil,
    workflow_deflatten_mlil,
    workflow_cleanup
)

# The resolvers run under either toggle: OLLVM_INDIRECT_32 cannot recover its
# dispatcher until they have reconnected the CFG, so it implies them.
_RESOLVE_OR_INDIRECT_32 = {
    "predicates": [
        {"type": "setting", "identifier": SETTING_INDIRECT_JUMP_CALL, "value": True},
        {"type": "setting", "identifier": MODE_INDIRECT_32, "value": True},
    ],
    "logicalOperator": "or",
}
# Deflatten is shared by every mode; the shape is chosen inside the callback.
_ANY_MODE = {
    "predicates": [
        {"type": "setting", "identifier": MODE_INDIRECT_32, "value": True},
        {"type": "setting", "identifier": MODE_DIRECT_32, "value": True},
        {"type": "setting", "identifier": MODE_XOR64, "value": True},
    ],
    "logicalOperator": "or",
}
# Gadget cleanup is signature-driven and only valid for the indirect 32-bit shape.
_INDIRECT_32_ONLY = {
    "predicates": [
        {"type": "setting", "identifier": MODE_INDIRECT_32, "value": True},
    ],
}


def register_workflows():
    workflow = Workflow("core.function.metaAnalysis").clone()

    # Toggles. These carry no action -- their ``eligibility.auto`` is what
    # surfaces the per-function checkbox in Function Analysis.
    workflow.register_activity(Activity(json.dumps({
        "name": SETTING_INDIRECT_JUMP_CALL,
        "title": "INDIRECT_JUMP_CALL",
        "description": (
            "Resolve this function's decode-gadget indirect jumps and calls into "
            "direct ones, leaving any flattened dispatcher intact. Useful on its "
            "own for a function that is obfuscated but not flattened; "
            "OLLVM_INDIRECT_32 turns it on as well."
        ),
        "eligibility": {"auto": {"default": False}},
    }), action=lambda analysis_context: None))

    workflow.register_activity(Activity(json.dumps({
        "name": MODE_INDIRECT_32,
        "title": "OLLVM_INDIRECT_32",
        "description": (
            "Deflatten a function whose dispatcher routes on a 32-bit state and "
            "whose blocks are chained by decode-gadget indirect jumps. Implies "
            "INDIRECT_JUMP_CALL, then rewrites the OBB->dispatcher edges into "
            "direct gotos and erases the dead decode gadgets."
        ),
        "eligibility": {"auto": {"default": False}},
    }), action=lambda analysis_context: None))

    workflow.register_activity(Activity(json.dumps({
        "name": MODE_DIRECT_32,
        "title": "OLLVM_DIRECT_32",
        "description": (
            "Deflatten a function whose dispatcher routes on a 32-bit state and "
            "whose original blocks return to it with ordinary direct gotos. "
            "Uses per-block regions and SSA-carried state selections; does not "
            "run indirect-jump resolution or decode-gadget cleanup."
        ),
        "eligibility": {"auto": {"default": False}},
    }), action=lambda analysis_context: None))

    workflow.register_activity(Activity(json.dumps({
        "name": MODE_XOR64,
        "title": "OLLVM_XOR_64",
        "description": (
            "Deflatten a function whose dispatcher state is 64-bit and split "
            "across two registers recombined with XOR at the dispatcher head. "
            "Assumes no indirect jumps or calls. Cleanup of the dead state "
            "writes is not implemented for this mode yet."
        ),
        "eligibility": {"auto": {"default": False}},
    }), action=lambda analysis_context: None))

    # Indirect-jump resolver (LLIL).
    workflow.register_activity(Activity(json.dumps({
        "name": "extension.DispatchThis.IndirectPatcher",
        "title": "DispatchThis: Resolve Indirect Jumps",
        "description": "Rewrite decode-gadget jump(reg) into jump(const target).",
        "eligibility": _RESOLVE_OR_INDIRECT_32,
    }), action=workflow_resolve_jumps_llil))
    workflow.insert("core.function.generateMediumLevelIL", [
        SETTING_INDIRECT_JUMP_CALL,
        MODE_INDIRECT_32,
        MODE_DIRECT_32,
        MODE_XOR64,
        "extension.DispatchThis.IndirectPatcher",
    ])

    # Indirect-call resolver (MLIL).
    workflow.register_activity(Activity(json.dumps({
        "name": "extension.DispatchThis.IndirectCallPatcher",
        "title": "DispatchThis: Resolve Indirect Calls",
        "description": "Rewrite decode-gadget call(reg) into call(const target).",
        "eligibility": _RESOLVE_OR_INDIRECT_32,
    }), action=workflow_resolve_calls_mlil))

    # Deflattener (MLIL), shared by every mode.
    workflow.register_activity(Activity(json.dumps({
        "name": "extension.DispatchThis.Deflatten",
        "title": "DispatchThis: Deflatten",
        "description": (
            "Unflatten this function's control flow by rewriting OBB->dispatcher "
            "jumps into direct gotos, using the solver for the selected mode."
        ),
        "eligibility": _ANY_MODE,
    }), action=workflow_deflatten_mlil))

    # Gadget cleanup (MLIL), indirect 32-bit shape only. It finds gadgets by constant
    # width, so on OLLVM_XOR_64 it would read that shape's 64-bit state constants
    # as decode keys and NOP real code. That shape has no cleanup of its own.
    workflow.register_activity(Activity(json.dumps({
        "name": "extension.DispatchThis.Cleanup",
        "title": "DispatchThis: Cleanup",
        "description": "Erase dead decode gadgets and collapse opaque predicates.",
        "eligibility": _INDIRECT_32_ONLY,
    }), action=workflow_cleanup))

    workflow.insert("core.function.generateHighLevelIL", [
            "extension.DispatchThis.IndirectCallPatcher",
            "extension.DispatchThis.Deflatten",
            "extension.DispatchThis.Cleanup"
    ])
    workflow.register()
    log_warn("DispatchThis's workflow has been registered!")


# Raise analysis limits for large flattened functions.
Settings().set_integer("analysis.limits.maxFunctionSize", 0)
Settings().set_integer("analysis.limits.expressionValueComputeMaxDepth", 99999)
Settings().set_integer("analysis.limits.maxFunctionAnalysisTime", 600000)
Settings().set_integer("analysis.limits.maxFunctionUpdateCount", 0)

# Prevent BN from lowering 32-bit state writes into __builtin_strncpy intrinsics,
# which the MLIL_STORE/SET_VAR matcher won't recognize.
Settings().set_bool("analysis.outlining.builtins", False)

register_workflows()
