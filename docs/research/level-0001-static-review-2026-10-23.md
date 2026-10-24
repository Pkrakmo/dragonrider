# Level `(1,0,0)` static-review handoff — 2026-10-23

## Scope and provenance

This is a documentation-only review of the existing bounded evidence. It does
not add a binary observation, open a Ghidra database, read private media, or
run the game. The underlying input and evidence scope remain the unpatched US
retail executable, SHA-256
`23630f48e20e8a9f42026501165ae1df407cfcee545a784ec930a4c25ee70648`, and
the hash-checked installed-US samples described in
[the prefix trace](level-0001-prefix.md),
[the block trace](level-0001-blocks.md), and
[the cell/draw trace](level-cell-draw-behavior.md).

## Observed in the existing evidence

- The loader's selected `(1,0,0)` path at `0x00421c30` constructs 168-byte
  runtime entries, stores the serialized discriminator at entry `+0x28`, and
  later reads per-entry block data. The inspected path does not establish a
  complete serialized-entry specification.
- The bounded draw-path evidence at `0x0043fe40` tests the discriminator after
  rectangle intersection. It constructs separate chains for value 2 and
  non-2, then traverses the non-2 chain before the value-2 chain. This proves
  an order on that path only; it does not identify the discriminator or prove
  a visual effect.
- The bounded query helper at `0x00420e10` applies discriminator-dependent
  rejection under several query flags. The observed call from `0x0043fe40`
  supplies literal flag value 4, so that call does not enable the documented
  bit-`0x10` rejection. Other callers and their flags have not been enumerated.
- Static analysis also shows a mutable per-cell pointer-list structure and an
  object-update call for selected members. Neither that membership nor the
  update establishes a relationship to the serialized discriminator.

The sampled US-level distribution (`0`: 2,523; `1`: 1,413; `2`: 509) and its
post-name-flag correlation remain sample measurements, not runtime evidence.

## Unknown

The discriminator's semantic role, the identities and effects of all query
flags, the set of callers that exercise each discriminator branch, object
membership criteria, rendering consequences, and behavior in other editions
remain unknown. In particular, the observed chain order does not justify
assigning a transparency, layering, collision, or gameplay meaning to value 2.

## One bounded next static procedure

The narrowest next question is which *direct* callers of `0x00420e10` provide
which query flags. With the GUI closed and without opening a Ghidra project,
run the following against the pinned executable. It intentionally limits the
call-site list and the instruction windows; an empty direct-call result would
not exclude indirect calls.

```sh
sha256sum research/binaries/us/Drakan.exe
objdump --version | head -n 1
objdump -d -Mintel research/binaries/us/Drakan.exe \
  | rg -n 'call[[:space:]].*<.*420e10>|call[[:space:]]+0x420e10' \
  | head -n 32
# For each recorded direct caller only, inspect a bounded 96-byte window
# around the call address and record the immediately established flag argument.
objdump -d -Mintel --start-address=0x0043fe60 --stop-address=0x0043ff10 \
  research/binaries/us/Drakan.exe
```

For each result, record the executable hash, caller address, exact bounded
window, flag provenance (literal, register, or unresolved), and confidence.
Do not treat a register-derived value as a constant without tracing its bounded
definition. Corroborate any consequential finding with a separately bounded
raw disassembly window. This procedure can classify direct call sites; it
cannot establish feasible runtime execution, virtual/indirect callers, object
identity, or visible behavior.
