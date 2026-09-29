"""Shape solver registry.

The per-function mode toggle selects the shape, so this is a straight mapping
from mode identifier to solver -- no scoring and no auto-detection. Registering
a new shape is the whole cost of supporting a new flattener.
"""

from .base import (
    FlattenerShape,
    ShapeResult,
    MODE_INDIRECT_32,
    MODE_DIRECT_32,
    MODE_XOR64,
    MODES,
    SETTING_INDIRECT_JUMP_CALL,
)
from ..utils.log import log_warn

_REGISTRY = {}


def register(shape):
    """Register a shape instance under its mode identifier."""
    if shape.mode is None:
        raise ValueError(f"shape {shape.name!r} has no mode identifier")
    if shape.mode in _REGISTRY:
        log_warn(f"[shapes] {shape.mode} already registered; replacing")
    _REGISTRY[shape.mode] = shape
    return shape


def for_mode(mode):
    """The shape registered for ``mode``, or None."""
    return _REGISTRY.get(mode)


def registered():
    """Every registered shape, in mode precedence order."""
    return tuple(_REGISTRY[m] for m in MODES if m in _REGISTRY)


from .forti_gadget import FortiGadgetShape  # noqa: E402
from .direct32 import Direct32Shape  # noqa: E402
from .xor_split64 import XorSplit64Shape  # noqa: E402

register(FortiGadgetShape())
register(Direct32Shape())
register(XorSplit64Shape())

__all__ = [
    "FlattenerShape",
    "ShapeResult",
    "FortiGadgetShape",
    "Direct32Shape",
    "XorSplit64Shape",
    "MODE_INDIRECT_32",
    "MODE_DIRECT_32",
    "MODE_XOR64",
    "MODES",
    "SETTING_INDIRECT_JUMP_CALL",
    "register",
    "for_mode",
    "registered",
]
