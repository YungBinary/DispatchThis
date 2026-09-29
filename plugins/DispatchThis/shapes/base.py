"""Flattener shape solvers: the common contract.

A *shape* is one concrete control-flow-flattening construction. Shapes differ in
how the dispatcher state is encoded, how it is transitioned, and therefore in
what a "transition" even is -- one shape's transition is a single constant store,
another's is a pair of half-writes spread across a region. So a shape owns both
halves of the job: recovering the state map, and rewriting the control flow it
implies.

Each shape is self-contained in its own module. It does not share solving or
rewriting code with other shapes, because the shared-looking parts (which block
is the dispatcher, where a block's forward region ends, what its exit jump is)
are exactly the parts that differ. What *is* common is only the vocabulary:

  * ``state_var``        -- the value the dispatcher routes on
  * ``state_map``        -- ``{state_value: dispatcher leaf MLIL block}``
  * ``redirections``     -- the rewrites the recovered edges imply
  * ``state_write_vars`` -- the state variable and every alias written to it

The active shape is chosen by the per-function mode toggle, never by detection.
:meth:`FlattenerShape.recognise` exists only to warn when the selected mode does
not match what the function actually looks like; it never reroutes to another
shape, so a deliberately forced mode still runs.
"""

# Mode identifiers double as Function Analysis setting IDs. They live here, in a
# module with no plugin-internal imports, so shape modules can reference them
# without importing the plugin root package while that package is still
# initialising.
#
# The identifiers are the ones the plugin used before the two toggles were briefly
# merged into one, so a function that already had them set keeps its setting.
MODE_INDIRECT_32 = "analysis.plugins.dispatchThis.deflatten"
MODE_DIRECT_32 = "analysis.plugins.dispatchThis.ollvmDirect32"
MODE_XOR64 = "analysis.plugins.dispatchThis.ollvmXor64"

# Precedence order, consulted when resolving the active mode for a function. If
# more than one toggle is somehow enabled, the earlier entry wins.
MODES = (MODE_INDIRECT_32, MODE_DIRECT_32, MODE_XOR64)

# Not a mode: it selects no shape and recovers no state map, it just turns the
# indirect jump/call resolvers on. It is kept out of :data:`MODES` for that
# reason -- ``_active_mode`` must never resolve to it. ``OLLVM_INDIRECT_32``
# implies it, because that shape cannot be solved until the resolvers have
# reconnected the CFG, but it is separately available for reading a function
# whose jumps are obfuscated and whose control flow is not flattened.
SETTING_INDIRECT_JUMP_CALL = "analysis.plugins.dispatchThis.indirectJumpsCalls"


class ShapeResult:
    """What a shape hands back: the state map and the rewrites it implies."""

    def __init__(
        self,
        state_var=None,
        state_map=None,
        redirections=None,
        state_write_vars=None,
        notes=None,
    ):
        self.state_var = state_var
        self.state_map = dict(state_map or {})
        self.redirections = list(redirections or [])
        self.state_write_vars = set(state_write_vars or ())
        # Free-form diagnostics (dispatcher address, halves, resolved bases) for
        # logging only; nothing depends on these.
        self.notes = dict(notes or {})

    @property
    def ok(self):
        return self.state_var is not None and bool(self.state_map)

    def __repr__(self):
        return (
            f"<ShapeResult state_var={self.state_var} "
            f"states={len(self.state_map)} redirections={len(self.redirections)}>"
        )


class FlattenerShape:
    """Base class for a flattener shape."""

    #: Short identifier used in log lines.
    name = "unnamed"
    #: Function Analysis setting identifier that selects this shape.
    mode = None
    #: True for the original shape, whose pipeline predates this framework and
    #: is driven directly by ``workflow.py`` rather than through :meth:`solve`.
    uses_legacy_pipeline = False
    #: Whether the separate gadget-cleanup activity applies to this shape. It is
    #: signature-driven -- it reads any constant wider than 32 bits as a decode
    #: key -- so a shape whose state constants are 64-bit must leave it off and
    #: keep its dead state writes.
    uses_gadget_cleanup = False

    def recognise(self, bv, func, mlil):
        """Return ``(looks_right, reason)``. Advisory: the mode still decides."""
        return (True, "")

    def solve(self, bv, func, mlil):
        """Recover the state map and plan the rewrites. Returns a ShapeResult."""
        raise NotImplementedError

    def apply(self, mlil, result):
        """Perform this shape's rewrites. Returns the number applied."""
        raise NotImplementedError
