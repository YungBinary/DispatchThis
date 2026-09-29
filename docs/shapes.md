# Flattener shapes

A **shape** is one concrete control-flow-flattening construction. DispatchThis
started as a deobfuscator for a single one; it is now organised so that each shape
it supports is a self-contained solver selected by a per-function toggle.

Two shapes ship today:

| Mode | Shape module | State | Block chaining | Cleanup |
| --- | --- | --- | --- | --- |
| `OLLVM_INDIRECT_32` | `shapes/forti_gadget.py` | 32-bit, one variable | decode-gadget `jump(reg)` | yes |
| `OLLVM_XOR_64` | `shapes/xor_split64.py` | 64-bit, split across a register pair | direct jumps | no |

`INDIRECT_JUMP_CALL` is **not** a shape - it is a third toggle that turns on the
indirect jump/call resolvers alone. See [Modes](#modes-are-not-the-same-as-shapes).

## Why per-shape solvers rather than one parameterised one

The two shapes agree only on the *idea*: a dispatcher routes on a state value, and
recovering the flattening means recovering the map from state values to original
blocks. Almost everything needed to build that map differs, including what a
"transition" is:

| | `OLLVM_INDIRECT_32` | `OLLVM_XOR_64` |
| --- | --- | --- |
| Find the state variable | the variable in the most `==` compares | the halves of the dispatcher's 64-bit `XOR` |
| Compare tree | equality throughout | relational interior nodes, equality only at leaves |
| Compare values | immediate constants | `base + displacement`, base supplied by the caller |
| A transition is | one state store | a **pair** of half-writes, which need not share a block |
| Conditional transitions | `cmov` chains, classified with Z3 | a `cmov` on one half; no solver needed |
| Needs the CFG repaired first | yes, via the resolvers | no, the jumps are already direct |

The parts that *look* shareable - which block is the dispatcher, where a block's
forward region ends, what its exit jump is - are exactly the parts that differ. A
single parameterised solver would be a pile of per-shape branches in shared code,
and every new shape would be a chance to regress an existing one. So each shape
owns both halves of its job: recovering the state map, and rewriting the control
flow that map implies.

## The contract

`shapes/base.py` defines it. What is common is only the vocabulary.

`ShapeResult` - what a solver hands back:

| Field | Meaning |
| --- | --- |
| `state_var` | the value the dispatcher routes on |
| `state_map` | `{state_value: dispatcher leaf MLIL block}` |
| `redirections` | the rewrites the recovered edges imply |
| `state_write_vars` | the state variable and every alias written to it |
| `notes` | free-form diagnostics (dispatcher address, halves, resolved bases); nothing depends on these |

`result.ok` is true when a state variable was found and the map is non-empty.

`FlattenerShape` - what a solver implements:

| Member | Role |
| --- | --- |
| `name` | short identifier used in log lines |
| `mode` | the Function Analysis setting that selects this shape |
| `recognise(bv, func, mlil)` | returns `(looks_right, reason)`; **advisory only** |
| `solve(bv, func, mlil)` | recover the state map and plan the rewrites |
| `apply(mlil, result)` | perform the rewrites, returning how many |
| `uses_legacy_pipeline` | true for the original shape, whose pipeline predates this framework |
| `uses_gadget_cleanup` | whether the shared cleanup activity applies |

`uses_gadget_cleanup` is a real constraint, not a preference. That pass identifies
gadgets by **signature** - among other things, it reads any constant wider than
32 bits as a decode key. Every state constant in `OLLVM_XOR_64` is 64-bit, so
running it there would NOP real code. It is off for that shape, which consequently
keeps its dead state writes.

## Modes are not the same as shapes

Three toggles appear under **Function Settings**, and only two of them select a
shape:

- **`INDIRECT_JUMP_CALL`** selects no shape, recovers no state, and runs no
  solver. It turns on the indirect jump/call resolvers, which is useful on its own
  for a function whose jumps are obfuscated but whose control flow is not
  flattened. It is deliberately excluded from the mode precedence list so that
  mode resolution can never land on it.
- **`OLLVM_INDIRECT_32`** selects the original shape and *implies*
  `INDIRECT_JUMP_CALL`, because its dispatcher cannot be recovered until the
  resolvers have reconnected the CFG.
- **`OLLVM_XOR_64`** selects the split-state shape. Its jumps are already direct,
  so the resolvers do not apply.

> [!NOTE]
> The setting identifiers are unchanged from before these were renamed
> (`…dispatchThis.indirectJumpsCalls` and `…dispatchThis.deflatten`), so a
> function that already had the old **Indirect Jumps/Calls** or **Deflatten**
> toggle set keeps it. Only the labels moved.

**The mode is authoritative.** It decides which solver runs; nothing is
auto-detected. `recognise` exists only to warn when the selected mode does not
match what the function looks like - it never reroutes to another shape, so a
deliberately forced mode still runs and still reports what it found.

## The registry

`shapes/__init__.py` is a straight mapping from mode identifier to solver
instance - no scoring, no detection:

```python
register(FortiGadgetShape())
register(XorSplit64Shape())
```

`for_mode(mode)` returns the solver for a mode; `registered()` returns every
solver in mode precedence order. The single deflatten activity resolves the mode
enabled on the function and dispatches through `for_mode`, which is why adding a
shape needs no new activity and no change to the workflow wiring.

## Adding a shape

1. Add the mode identifier to `shapes/base.py` and list it in `MODES` (precedence
   order; the earliest enabled toggle wins if several are somehow set).
2. Write `shapes/<name>.py` as a self-contained solver subclassing
   `FlattenerShape`. Do not reach into another shape's module.
3. `register()` it in `shapes/__init__.py`.
4. Register the toggle activity in `__init__.py` with
   `"eligibility": {"auto": {"default": False}}`, which is what surfaces the
   per-function checkbox, and add the mode to the deflatten activity's
   eligibility predicate.

Everything defaults to off, so a new shape stays inert until it is enabled on a
function.

## Where each shape is documented

- `OLLVM_INDIRECT_32` - [`obfuscation.md`](obfuscation.md) for the construction,
  [`conditional-deflattening.md`](conditional-deflattening.md) for its Z3 path.
- `OLLVM_XOR_64` - [`obfuscation-xor64.md`](obfuscation-xor64.md) for both the
  construction and how it is solved.
