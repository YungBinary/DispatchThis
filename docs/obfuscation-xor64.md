# The obfuscation: `OLLVM_XOR_64`

The second flattener shape DispatchThis handles: a **64-bit dispatcher state split
across a register pair and recombined with XOR**. Addresses and constants below are
from function `sub_14024849c` (dispatcher at `0x140248513`) in the implanted
`mscopilot.exe` sample - see [the README](../README.md#the-samples).

This shape shares no solving code with `OLLVM_INDIRECT_32`; the reasons are
tabulated in [`shapes.md`](shapes.md#why-per-shape-solvers-rather-than-one-parameterised-one).
There are **no decode gadgets here** - every jump is already direct - so the
indirect-jump and indirect-call resolvers do not apply, and there is no gadget map.
That alone made the original pipeline unable to touch it: it refused to deflatten a
function whose gadget map was empty.

## High-level shape

Control flow is flattened the familiar way - original blocks (**OBBs**) no longer
branch to one another, and a single dispatcher decides what runs next - but the
state is not held in one variable. **Two registers carry halves of it** (`r14` and
`rdi` in this sample), and the dispatcher head rebuilds the state with a single
64-bit XOR:

```
rax_4 = r14
rax_5 = rax_4 ^ rdi          <- the state the compare tree routes on
```

Run-time flow for one transition:

```
OBB body  ->  overwrite both halves  ->  jump to dispatcher
          ->  XOR halves  ->  compare tree  ->  next OBB
```

### The initial state

The prologue seeds the pair, so the first OBB's state is their XOR:

```python
>>> r14 = 0x1d149371eb6e9b2d
>>> rdi = 0x925fe62087c2e97c
>>> hex(r14 ^ rdi)
'0x8f4b75516cac7251'
```

## The compare tree

Routing is a **binary search tree** over the 64-bit state, not a flat chain of
equality tests:

- **interior nodes compare relationally**, narrowing the range;
- **leaves compare for equality**. A leaf's *equal* edge falls into an OBB, and its
  other edge goes back to the dispatcher.

Two things make the leaves harder to read than a plain `state == K`.

**Compare values are computed, not immediate.** An `lea` materialises each one as
`base + displacement`, where `base` is a 64-bit value **the caller supplies** under
a non-standard calling convention. Continuing the example above, the first OBB's
leaf resolves as:

```python
>>> state = 0x8f4b75516cac7251
>>> arg3  = 0x8f4b755122564d81     # base, from the caller
>>> hex(state - arg3)
'0x4a5624d0'                       # the displacement in the leaf
```

**The comparison is consumed far from where it is computed.** The compare is
routinely built in the interior node's own block and read by an `MLIL_IF` several
blocks later:

```
rcx_11 = arg6 + 0x2834a30d
cond:1_1 = rax_5 != rcx_11   <- computed here...
...
if (cond:1_1) then <dispatcher> else <original block>   <- ...consumed here
```

## Transitions

**Unconditional.** The OBB overwrites *both* halves with constants chosen so their
XOR is the successor's state, then jumps to the dispatcher. The two writes need not
be adjacent, or even in the same basic block.

**Conditional.** A `cmov` selects one half between two values while the other half
stays fixed, so the XOR lands on one of two successors. Both arms then converge on
the same unconditional jump back to the dispatcher. This is how an original
`if`/branch was flattened: the CPU flags are set by the OBB's real logic, and the
`cmov` - not a `Jcc` - turns that predicate into a choice of next state.

## How it is solved

`shapes/xor_split64.py`, self-contained. **Z3 is not used**; the conditional
handling here is structural rather than symbolic.

### 1. Find the dispatcher

Inverted relative to the original shape. There, the state variable is found first
(most `==` compares) and the dispatcher follows from it; that cannot work when the
interior nodes are relational. Here the **dispatcher is found first**, by its
defining instruction - a 64-bit `XOR` of two variables - and the state variable and
its two halves fall out of it.

Other blocks can hold such an XOR (this sample also XORs vector registers for
buffer crypto), so candidates are disambiguated by **incoming edges**: only the
dispatcher is the block every OBB routes back through. In `sub_14024849c` it has 68.

### 2. Absorb split-off fragments

A flattened body in this shape usually arrives **split across several overlapping
functions**, and a fragment solves to a state map that is quietly missing states -
it reaches only the part of the compare tree its own entry leads to, and its leaves
compare against whatever parameters that entry happens to receive rather than
folded constants.

Binary Ninja starts a function wherever anything names one, and this obfuscator
leaves such marks all through a flattened body: `.pdata` unwind ranges, Guard CF
entries, ordinary prologues, direct calls. No loader or analysis setting prevents
the split, because a mark can be an ordinary direct call and a call always starts a
function.

So the marks are not worth telling apart. What gives a split away is that **the
body runs straight into the fragment**, which real control flow does not do. For
each block with no outgoing edge, the last instruction is decoded at the byte level
and asked whether it branches at all: `ret`, `jmp` and calls all report a branch, so
only a genuine fall-through survives. The fragment it falls into is undefined with
`remove_user_function` - not `remove_function`, since the mark is still in the file
and a plain removal would be undone on the next pass - and the function is
reanalysed. Solving resumes once the merged body settles.

In the reference function this absorbs `sub_140248b22` and `sub_140249198`, taking
the dispatcher from 61 incoming edges to 68.

> [!NOTE]
> A fragment can be both fallen into *and* called for real - a `.pdata` entry that
> also has a genuine caller. Absorbing it still wins, since the compare tree is only
> whole one way, but the log says so: those callers are left calling into the middle
> of the merged function.

### 3. Resolve the compare bases

State values are symbolic until each `base` is concrete, so the map cannot be keyed
until they are. Two mechanisms, in order:

1. **Caller binding.** The bases are parameters, so the call sites are read and any
   base every resolved site agrees on is bound. Tail calls count as call sites.
2. **Voting.** For a base the callers do not pin down, the states that *are* already
   concrete become the scoring set: each candidate value is the one that makes the
   most of that base's displacements line up with an observed state. A candidate
   needs at least two agreeing displacements to be accepted.

A base neither mechanism resolves has its leaves dropped from the map, and the log
says how many.

### 4. Enumerate regions and plan the rewrites

Because a transition is a *pair* of half-writes that need not share a block, it does
not belong to any single instruction - it belongs to an OBB's forward **region**:
the blocks reachable from the OBB head before control returns to the dispatcher. Each
region is planned independently:

| Plan | When | Rewrite |
| --- | --- | --- |
| `uncond` | both halves resolve to one value each | exit jump becomes a direct `goto` to the successor |
| `cmov_diamond` | a `cmov` diamond selects a half, and the diamond is **private** to this region | the diamond's own arms are re-pointed at the two successors |
| `cmov_obb` | the selecting diamond is **shared** with sibling regions | this region's tail `goto` becomes an `if` on the lifted condition |

The private/shared distinction matters: re-pointing a shared diamond's arms would
collapse every sibling region onto *this* region's two successors. Rewriting the
region's own tail instead lets each consumer branch on its own predicate, and the
shared diamond is dropped as dead once every consumer has been rewritten. A shared
diamond's condition is lifted verbatim into the exit block, so it is only usable when
it is computed there - its operands have to still be live where the branch lands.

### 5. Recover a half selected elsewhere

A half can be selected by a diamond **outside** the region and merely carried in -
in the reference function, a `cmov` diamond at the function entry stores into a stack
slot that a later region copies. Constant evaluation scoped to the region resolves
nothing for such a half, and voting can never settle it either, since only the single
region using it ever votes.

These are recovered from **SSA** instead: the half's definition is followed through
copies to a `phi`, the two constant values are read off its operands, and the
`MLIL_IF` that selects between them supplies the condition. The selection is then
marked remote, so its diamond is never mistaken for the region's own and re-pointed.

This is what closes the last gap in the reference function: 38 of 39 regions
recovered, the remaining one being a region that returns or tail-calls out and
therefore has no successor state at all.

## What is left behind

**Nothing is erased in this shape.** The shared gadget cleanup is off, for the reason
in [`shapes.md`](shapes.md#the-contract): it reads any constant wider than 32 bits as
a decode key, which is every state constant here.

That splits the leftovers in two:

- **The dispatcher and the whole compare tree disappear on their own.** Once every
  region branches to its successor directly they are unreachable, and Binary Ninja
  drops unreachable blocks without being asked.
- **The per-block half-writes and their stack mirrors remain**, because they are
  still in reachable code. They are dead bookkeeping and they do clutter the
  pseudocode.

Removing the second group is not yet implemented - see
[`known-issues.md`](known-issues.md#ollvm_xor_64).

## Reading the log

One line per region, then one per applied rewrite. The vocabulary:

| Line | Meaning |
| --- | --- |
| `dispatcher @ … (N incoming edges), state X = A ^ B` | step 1 succeeded; `A`/`B` are the halves |
| `undefined … to absorb its blocks` | step 2 removed a fragment; solving restarts |
| `N concrete and M symbolic leaf/leaves over K compare base(s)` | how much of the tree needs base resolution |
| `bound N/M base(s)` / `solved compare base X=… by voting` | step 3 |
| `=> uncond <state> -> <block>` | an unconditional region resolved |
| `private` / `shared cmov diamond @ …` | a conditional region resolved, and which way it will be rewritten |
| `half X is selected by a diamond @ … outside this region and carried in` | step 5 fired |
| `state … has no dispatcher leaf` | the successor state is not in the map; region left intact |
| `could not be solved by voting` | an underdetermined base; regions using it fall back to SSA recovery |
| `N region(s) left intact because their transition could not be recovered` | the honest total - anything not listed was rewritten |
