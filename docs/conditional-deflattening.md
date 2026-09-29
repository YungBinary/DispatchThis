# Conditional deflattening (the Z3 path)

> [!NOTE]
> This is the `OLLVM_INDIRECT_32` path, and the only one that uses Z3. `OLLVM_XOR_64`
> reconstructs its conditional transitions structurally instead - a `cmov` selects one
> half of the split state, so the two candidate successors follow from the XOR without
> anything to solve. See
> [`obfuscation-xor64.md`](obfuscation-xor64.md#4-enumerate-regions-and-plan-the-rewrites).

Most flattened transitions are **unconditional**: an OBB sets the state variable to a
single constant and jumps to the dispatcher, which routes it to one successor. Those are
handled directly - the dispatcher exit jump is rewritten into a `goto` to the real
successor block.

Some transitions are **conditional**. The original `if`/branch was flattened by having the
OBB select the *next state* from a small set of constants via one or more `cmov`s (compound
`||` / `&&` conditions), then store that state and jump to the dispatcher. Reconstructing
the real branch is what this path does. It requires **Z3** to be installed (see the
README's Prerequisites).

## What the analysis recovers

A conditional OBB is a linear chain of `cmov` selections that write a state temp, followed
by a store, the decode gadget, and the indirect jump. The analysis walks that chain and
recovers, for each selection, a `(condition, alternate-state-value)` pair plus the default
value, and maps each state constant to its successor via the backbone.

## Monotone vs. non-monotone

Z3 classifies the chain by how the `cmov`s compose:

- **Monotone** - the selections route forward consistently (each `cmov` that fires commits
  to the alternate). The original `MLIL_IF`s are kept and their edges are re-pointed to the
  real successors.
- **Non-monotone** - a later `cmov` can re-select the default (e.g. some `&&` forms). Here
  the routing predicate is reconstructed as a sum-of-products over the *real* `cmov`
  conditions, and a single `if (predicate) goto succ_alt else goto succ_default` replaces
  the gadget jump. The state temp and `cmov` chain are then orphaned and drop out as dead
  code.

In both cases only **terminators** are rewritten; orphaned obfuscation is left for Binary
Ninja's dead-code elimination, so real instructions are never hand-deleted.

## Why Z3

The classification (does a given `cmov` chain route monotonically, or does a later
selection override an earlier one?) and the predicate reconstruction are solved
symbolically rather than pattern-matched, which keeps the handling correct across the
`||` / `&&` / De Morgan variants the obfuscator emits.

## Reference example

A fully annotated example - disassembly, the recovered conditions, and the resulting
control flow - lives alongside the code at
[`plugins/DispatchThis/passes/medium/REFERENCE_conditional_obb.md`](../plugins/DispatchThis/passes/medium/REFERENCE_conditional_obb.md)
(canonical block `0x140082b3e` in `detect_browsers` @ `0x14006f570`).

## Status

This path is the least battle-tested part of the plugin. It decompiles the canonical cases
cleanly, but conditional reconstruction is inherently the most fragile area - see
[`known-issues.md`](known-issues.md).
