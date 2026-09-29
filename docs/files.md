# Source layout

```
DispatchThis/
├── __init__.py                 Plugin entry point: registers the workflow, the three
│                               per-function toggles, the four working activities and
│                               their eligibility, and the analysis-limit overrides.
├── workflow.py                 The four workflow activity callbacks (LLIL jump resolve,
│                               MLIL call resolve, deflatten, cleanup), their gating,
│                               and the mode -> shape dispatch inside deflatten.
├── shapes/
│   ├── base.py                 The shape contract: FlattenerShape, ShapeResult, and the
│   │                           mode / setting identifiers.
│   ├── __init__.py             Mode -> solver registry (register / for_mode / registered).
│   ├── forti_gadget.py         OLLVM_INDIRECT_32 descriptor. Holds no solving logic: that
│   │                           shape's pipeline predates the framework and runs as it was.
│   └── xor_split64.py          OLLVM_XOR_64, self-contained: dispatcher discovery, fragment
│                               absorption, compare-base resolution, region planning, and
│                               the rewrites.
├── utils/
│   ├── log.py                  Shared "DispatchThis" logger.
│   ├── const_eval.py           Constant evaluation and parameter binding: eval_consts,
│   │                           bind_bases_from_callers, solve_base_by_voting,
│   │                           split_base_disp.
│   └── state_machine.py        StateMachine: recovers the state variable, the backbone
│                               map {state -> comparator block}, and OBB -> successor links.
├── passes/
│   ├── low/
│   │   └── gadget_llil.py      LLIL decode-gadget resolver: jump(reg) -> jump(const),
│   │                           including opaque-predicate offset selection.
│   └── medium/
│       ├── indirect_calls.py   MLIL indirect-call decode fold + call-type adjustment.
│       ├── deflatten.py        Computes and applies the OBB -> goto redirections,
│       │                       including the conditional/Z3 path.
│       ├── nop_pass.py         Signature-based gadget cleanup, dead-decode residue
│       │                       removal, and precise state-write NOPing.
│       └── REFERENCE_conditional_obb.md   Annotated reference example for the
│                                          conditional transition handling.
├── docs/                       This documentation (incl. assets/, the screenshots).
├── README.md
└── LICENSE
```

Everything under `passes/`, plus `utils/state_machine.py`, belongs to
`OLLVM_INDIRECT_32`. `shapes/xor_split64.py` shares none of it - only `utils/`'s logger
and `const_eval`.

## Module responsibilities

### `__init__.py`
Clones `core.function.metaAnalysis`; registers the three action-free toggle activities
(`INDIRECT_JUMP_CALL`, `OLLVM_INDIRECT_32`, `OLLVM_XOR_64`) whose names double as the
per-function setting IDs, then the four working activities with the eligibility predicates
that map modes to passes, plus their insertion points; and raises the analysis limits.

### `workflow.py`
The activity callbacks invoked by the workflow per function. Each is thin: it reads the
relevant IL off the `AnalysisContext`, calls into a pass module or a shape solver, and
manages the `session_data` gating (LLIL stability, MLIL stability, recorded state
constants/vars). The deflatten callback additionally resolves which mode is enabled and
dispatches to that shape - the one place the two pipelines meet.

### `shapes/`
The shape framework: the contract in `base.py`, the registry in `__init__.py`, and one
module per supported flattener. `for_mode` is how `workflow.py` reaches a solver.
Registering a new shape is the whole cost of supporting a new flattener - see
[`shapes.md`](shapes.md).

### `shapes/xor_split64.py`
The `OLLVM_XOR_64` solver, and the only shape written against the framework. Finds the
dispatcher from its 64-bit XOR, undefines the fragments the body falls into so the compare
tree is whole, resolves the caller-supplied compare bases, enumerates each OBB's forward
region, and plans one rewrite per region (direct `goto`, private cmov diamond, or a lifted
branch on the region's own tail). See
[`obfuscation-xor64.md`](obfuscation-xor64.md#how-it-is-solved).

### `utils/const_eval.py`
Shared constant machinery. `eval_consts` folds an expression to the set of constants it
can take within a scope; `split_base_disp` splits a compare value into
`(parameter, displacement)`; `bind_bases_from_callers` reads a function's call sites
(including tail calls) to bind its symbolic parameters; `solve_base_by_voting` recovers a
base the callers do not pin down by scoring candidates against already-known states.

### `utils/state_machine.py`
Read-only analysis. `StateMachine.analyze()` finds the state variable (the variable in the
most equality compares), builds the backbone from its constant compares, enumerates every
state write (direct and through aliases / pointer stores), and resolves each write to the
real successor(s) via `match_successor`. Produces `CFGLink`s the deflattener consumes.

### `passes/low/gadget_llil.py`
Parses the three-step decode gadget backwards (`parse_jump_gadget`), recovers
`(slot, displacement, key, offset)`, decodes the jump target via a per-function key, and
rewrites the jump. Includes the opaque-predicate evaluator and the phi/VSA constant
recovery for the displacement/key registers the dispatcher merges.

### `passes/medium/indirect_calls.py`
Folds the call-gadget decode (`eval_const`), rewrites the call destination to a const
pointer, folds the spilled decode definition, and pins the callee prototype once per call
site per session.

### `passes/medium/deflatten.py`
`compute_redirections` turns the state-machine links + resolved gadget map into a set of
jump re-pointings; `apply_redirections_il` rewrites the terminators. Handles both
unconditional and conditional (cmov-selected) transitions; see
[`conditional-deflattening.md`](conditional-deflattening.md).

### `passes/medium/nop_pass.py`
`clean_resolved_gadget_jumps` runs after the deflattener: converts remaining single-target
jumps to gotos, collapses always-true opaque predicates, and NOPs the gadget taint set,
dead decode residue, and state writes - all to a fixpoint, pure IL only. Signature-driven,
which is why it is `OLLVM_INDIRECT_32` only.
