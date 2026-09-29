# The obfuscation: `OLLVM_INDIRECT_32`

This document describes the **first** of the two control-flow flattening schemes
DispatchThis targets: a 32-bit dispatcher state with original blocks chained by
decode-gadget indirect jumps. All the run-time addresses and constants below are
from the sample (`FortiEndpoint_Patch.exe`), function `0x140088ad0`
(`reg_read_str`).

For the other shape - a 64-bit state split across a register pair and recombined
with XOR, with no gadgets at all - see
[`obfuscation-xor64.md`](obfuscation-xor64.md). For why they get separate solvers
rather than one parameterised one, see [`shapes.md`](shapes.md).

## High-level shape

Control flow is **flattened**: the original basic blocks (referred to here as **OBBs** -
original basic blocks) no longer branch to one another directly. Instead a single
**dispatcher** decides which block runs next, based on a 32-bit **state variable**. Each
OBB ends by setting the state to the value of its real successor and then jumping back into
the dispatcher.

Run-time flow for a single transition:

```
OBB body  ->  set state = <next>  ->  decode gadget  ->  jump to dispatcher
          ->  compare tree (dispatcher)  ->  next OBB
```

## The state variable and dispatcher

The **state variable** is a 32-bit value. The dispatcher is a **compare tree**: a chain of
comparisons of the state variable against constants. Each leaf is a comparator of the form
`if (state == K) goto real_block_for_K`. The set of `(K -> comparator block)` pairs is the
**backbone** - one entry per reachable original block.

The plugin recovers the state variable heuristically as *the variable that appears in the
most equality comparisons* across the function (the dispatcher compares it far more than
anything else). From there it builds the backbone and, for each place an OBB writes the
state (directly or through an alias/pointer store), resolves the real successor(s) the
dispatcher would route to.

## Decode-gadget indirect jumps

OBBs do not jump to the dispatcher with a direct branch. They jump through a **decode
gadget** that recovers the destination from a **relocated jump table** at run time, so the
target is opaque to static analysis (`jump(reg)`):

```
rax = OFFSET + [&SLOT]        ; table_base   = entry_offset + *slot
rax = [DISPLACEMENT + rax]    ; encoded_entry = *(table_base + displacement)
rax = rax (+/-) KEY           ; target        = encoded_entry + key   (mod 2^48)
jump(rax)                     ; unresolved indirect jump
```

The decode is closed-form:

```
table_base = (*slot + displacement) mod 2^48
entry      = *(table_base + entry_offset)
target     = (entry + key) mod 2^48
```

`slot` is a constant pointer read straight from the gadget; `*slot` (the relocated table
base) and the encoded entry are read from the image at resolve time. The plugin parses this
fixed three-step shape backwards rather than constant-folding the whole expression, which
avoids diving into the loop-carried register chains the dispatcher introduces.

## Opaque predicates (entry-offset selection)

The `entry_offset` above is not a plain constant. It is chosen by an **always-true opaque
predicate** - an `if` / `cmov` that appears to select between the real offset and a decoy,
but whose condition is constant in practice (e.g. `0 == 0xa`, or `((0 - 1) * 0) & 1 == 0`).
The resolver evaluates the predicate controlling the live edge to recover which offset is
actually used.

## Import call gadgets

Calls to imported functions use the **same decode shape**, folded down to a single add at
the MLIL level:

```
rax_8 = *(encoded_entry)      ; loaded encoded target
rax_9 = rax_8 + KEY           ; decode add (KEY is constant)
call(rax_9)                   ; indirect call; target is an IAT slot
```

so `target = (encoded + key) mod 2^48`, where the target resolves to an Import Address
Table entry. A variant calls *through* the decoded slot (`call([rax + KEY])`), wrapping the
decode add in an outer load.

## Conditional transitions

Some OBBs do not pick a single next state - they select the next state from a small set of
constants via one or more `cmov`s (compound `||` / `&&` conditions). The dispatcher then
routes each chosen state to its own successor, which is how the original conditional branch
was flattened. Reconstructing these back into real `if`/branch control flow is handled by
the conditional path of the deflattener; see
[`conditional-deflattening.md`](conditional-deflattening.md).

## Concrete signature constants (sample)

From function `0x140088ad0` (`reg_read_str`):

- **Decode keys** (64-bit; the gadget signature): `0x489b85b10a15a8c7`,
  `0x782b82e30bd1bc4f`, `0x7218190ceaade73c`.
- **Jump dispatcher table slots**: `0x140307b20` / `b28` / `b30`.
- **Import decode table slots**: `0x140303d20` / `d28` / `d30`.
- **Resolved import IAT targets**: `0x1402ea290` (RegQueryValueExA), `0x1402ea298`
  (RegOpenKeyExA), `0x1402ea2a8` (RegCloseKey).

The cleanup pass keys off these signatures - the 64-bit decode keys (constants `> 2^32`
that are not valid mapped addresses) and the repeatedly-loaded table-slot pointers - to
identify and erase gadget code, since real code never references them.
