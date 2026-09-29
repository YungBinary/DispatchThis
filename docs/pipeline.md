# The pipeline

DispatchThis registers a **clone of `core.function.metaAnalysis`** and inserts its
own activities into it. Everything is IL expression rewriting - no bytes are patched.

## Registration and ordering

From `__init__.py` / `workflow.py`, four working activities are inserted:

| Activity ID | Stage | Inserted before | Runs for |
| --- | --- | --- | --- |
| `extension.DispatchThis.IndirectPatcher` | LLIL | `core.function.generateMediumLevelIL` | `INDIRECT_JUMP_CALL` or `OLLVM_INDIRECT_32` |
| `extension.DispatchThis.IndirectCallPatcher` | MLIL | `core.function.generateHighLevelIL` | `INDIRECT_JUMP_CALL` or `OLLVM_INDIRECT_32` |
| `extension.DispatchThis.Deflatten` | MLIL | `core.function.generateHighLevelIL` | `OLLVM_INDIRECT_32` or `OLLVM_XOR_64` |
| `extension.DispatchThis.Cleanup` | MLIL | `core.function.generateHighLevelIL` | `OLLVM_INDIRECT_32` |

The indirect-jump resolver runs **before MLIL is generated**, because a shape that depends
on it needs the CFG already reconnected (the indirect jumps resolved to real edges) before
MLIL analysis. The other three run before HLIL generation, in the order call-resolve →
deflatten → cleanup.

## The toggles

Three further activities are registered that carry **no action** at all:

| Activity / setting ID | Shown as |
| --- | --- |
| `analysis.plugins.dispatchThis.indirectJumpsCalls` | `INDIRECT_JUMP_CALL` |
| `analysis.plugins.dispatchThis.deflatten` | `OLLVM_INDIRECT_32` |
| `analysis.plugins.dispatchThis.ollvmXor64` | `OLLVM_XOR_64` |

They exist because an activity name doubles as a per-function setting identifier: Binary
Ninja's `eligibility.auto` generates a Function Analysis toggle whose ID is the activity
name. Declaring them with `{"auto": {"default": False}}` is what surfaces the checkboxes,
and the working activities above then reference those IDs in their own `eligibility`
predicates. Everything defaults to off, so the plugin stays inert until something is
enabled on a function.

The identifiers are the ones the plugin used under the older **Indirect Jumps/Calls** and
**Deflatten** labels, so an existing database keeps whatever was set on its functions.

`MODES` in `shapes/base.py` lists the two flattener modes in precedence order, consulted
when resolving which one is active; if several are somehow enabled, the earliest wins.
`INDIRECT_JUMP_CALL` is deliberately **not** in that list - it selects no shape, so mode
resolution must never land on it.

## The activities

### 1. Indirect jump resolver (LLIL) - `passes/low/gadget_llil.py`

`resolve_and_rewrite_llil_jumps`. Parses each decode-gadget `jump(reg)` (and tail-call
form), decodes its target from the relocated jump table, and rewrites the jump destination
into `jump(const)`. A constant jump target is a *direct* branch, so Binary Ninja then
disassembles the target, defines it as code, and reconnects the CFG - which exposes the
next layer of gadgets.

Because the function grows, the workflow re-runs and the next layer resolves, **iterating
to a fixpoint** with no manual loop and no byte patching. Targets are resolved read-only
first, then all rewrites are applied and SSA is rebuilt once. When no jumps remain, the
function is marked stable (`dispatchthis_llil_stable[start] = True`).

### 2. Indirect call resolver (MLIL) - `passes/medium/indirect_calls.py`

`patch_indirect_calls`. Folds each import call's decode (`target = (encoded + key) mod
2^48`) and rewrites the call's **destination expression** into a `const_pointer`. It also
folds the spilled decode definition (`var = encoded + key` → `var = const`) so the dead
decode collapses cleanly.

After the destination is a bare constant, the call carries only calling-convention guesses
and no prototype, so HLIL would render arguments as `/* nop */`. The pass fixes this by
**pinning the callee prototype** at the call site via `set_call_type_adjustment`.

> [!IMPORTANT]
> `set_call_type_adjustment` is a *function-level* edit that schedules a fresh reanalysis
> (unlike `replace_expr`, which the current pass simply consumes). Applying it every run
> would loop analysis forever, so it is applied **at most once per call site per session**,
> tracked in `dispatchthis_call_types_set`.

### 3. Deflattener (MLIL) - `workflow.py` → a shape solver

**One activity, one per shape solver behind it.** The callback resolves the mode enabled on
the function, looks the solver up with `shapes.for_mode`, and dispatches. The two pipelines
have nothing in common beyond producing a deflattened function, so the callback branches
once, at the top, on `shape.uses_legacy_pipeline`. See [`shapes.md`](shapes.md).

**`OLLVM_INDIRECT_32`** runs the original sequence, which predates the shape framework and
still lives in `utils/state_machine.py` and `passes/medium/deflatten.py`. It only proceeds
once the LLIL stage has drained every indirect jump - otherwise the CFG, and the recovered
state machine, would be incomplete.

- `StateMachine(bv, func).analyze()` (`utils/state_machine.py`) recovers the state
  variable, the backbone `{state_value -> comparator block}`, and each OBB's real
  successor(s).
- `compute_redirections` + `apply_redirections_il` rewrite each `OBB → dispatcher`
  `MLIL_JUMP_TO` into a direct `goto` to the real successor. Conditional (cmov-selected)
  transitions are reconstructed into `if`/branch control flow using Z3 - see
  [`conditional-deflattening.md`](conditional-deflattening.md).
- The resolved dispatcher state values and the state variable's alias set are recorded to
  `session_data` so the cleanup can NOP the state writes precisely (by value and by var).

**`OLLVM_XOR_64`** hands the whole job to its shape module, `shapes/xor_split64.py`, via
the `solve` → `apply` contract. It has no LLIL prerequisite, because the jumps in that
shape are already direct. It has a prerequisite of its own, though: a flattened body in
this shape usually arrives split across several overlapping functions, so `solve` may
undefine the fragments the body falls into, request reanalysis, and return an empty result
to be re-entered once the merged body settles. Details in
[`obfuscation-xor64.md`](obfuscation-xor64.md#how-it-is-solved).

Before rewriting, the callback records the solved state values and
`result.state_write_vars` to `session_data` for every shape, so the keys below mean the
same thing whichever solver produced them.

### 4. Cleanup / NOP pass (MLIL) - `passes/medium/nop_pass.py`

**`OLLVM_INDIRECT_32` only.** It identifies gadgets by *signature*, which includes reading
any constant wider than 32 bits as a decode key - and every state constant in
`OLLVM_XOR_64` is 64-bit, so running it there would NOP real code. That shape has no
cleanup of its own either, so its dead state writes survive.

It acts only once deflatten has rewritten the OBB exits in this pass, which the deflatten
callback signals by setting `dispatchthis_mlil_stable` - and it sets that **only** for a
shape whose `uses_gadget_cleanup` is true, which is what keeps this pass off the other
shape in practice as well as by eligibility. `clean_resolved_gadget_jumps` then, to a
fixpoint:

- converts every single-target `MLIL_JUMP_TO` into a `goto`;
- collapses each always-true opaque predicate (its condition reads a gadget-tainted
  variable, and its branches reconverge) into a `goto` the common join;
- NOPs gadget-tainted pure assignments, the dead decode residue, and the state writes.

Gadgets are identified by **signature** (the 64-bit decode keys and the repeatedly-loaded
table slots), not by slicing the already-folded jump. The safety floor: only pure
assignments / phis are ever NOP'd - never a call, store, or control-flow instruction.

## Why the MLIL passes reapply every run

The deflatten and cleanup MLIL rewrites are *overlays* derived from the (unchanged) LLIL.
Each reanalysis regenerates MLIL from LLIL and reverts them, so both passes **re-run every
pass** to keep their rewrites in place rather than latching off after the first apply.
Deflatten runs before cleanup so that cleanup sees the gotos and leaves the
`OBB → dispatcher` exits alone.

## `session_data` keys

| Key | Meaning |
| --- | --- |
| `dispatchthis_llil_stable` | `{start: bool}` - LLIL indirect jumps fully resolved |
| `dispatchthis_gadget_map` | `{start: {jump_addr: target}}` - resolved jump targets |
| `dispatchthis_mlil_stable` | `{start: bool}` - deflatten has rewritten exits; **set only for a shape with `uses_gadget_cleanup`**, since it is what releases the cleanup activity |
| `dispatchthis_state_consts` | `{start: set(state_value)}` - for state-write NOP |
| `dispatchthis_state_vars` | `{start: set(var)}` - state var + aliases |
| `dispatchthis_call_types_set` | `{start: set(call_addr)}` - once-guard for type adjust |

## Analysis limits

The plugin raises several Binary Ninja analysis limits at import (max function size,
expression-value compute depth, max analysis time, max update count) because flattened
functions are large and need many reanalysis passes to reach a fixpoint.
