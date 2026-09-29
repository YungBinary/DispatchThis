"""OLLVM_INDIRECT_32: 32-bit state routed through decode-gadget jumps.

The shape DispatchThis was originally written for. The dispatcher compares a
32-bit state variable against ``==`` constants, original blocks are chained by
indirect jumps through decode gadgets, and the state is stored as a plain 32-bit
constant (or selected between two by a cmov).

This module holds no solving or rewriting logic on purpose. That shape's
pipeline predates the shape framework and lives in ``utils/state_machine.py``,
``passes/`` and ``workflow.py``; it is driven there, unchanged. What is left here
is the descriptor -- which mode selects it, whether cleanup exists for it, and a
recognition check for the mode-mismatch warning -- so that the original path
cannot be regressed by work on another shape: there is nothing here to diverge.
"""

from ..utils.state_machine import get_most_compared_eq_var
from .base import MODE_INDIRECT_32, FlattenerShape


class FortiGadgetShape(FlattenerShape):
    name = "forti_gadget"
    mode = MODE_INDIRECT_32
    uses_legacy_pipeline = True
    uses_gadget_cleanup = True

    def recognise(self, bv, func, mlil):
        if get_most_compared_eq_var(mlil) is None:
            return (False, "no variable is compared against equality constants")
        return (True, "")
