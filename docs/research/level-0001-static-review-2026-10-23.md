# Level `(1,0,0)` static-review handoff — 2026-10-23

## Scope and provenance

This note synthesizes the bounded reports linked below; it contains no
reproduced executable bytes or bulk disassembly. Those reports use the
unpatched US retail executable, SHA-256
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
  bit-`0x10` rejection. The later direct-caller sweep found 23 relative calls:
  17 pass literal 5, five pass literal 4, and one forwards a caller-derived
  value. The `0x0044cb63` value was traced to a fifth argument whose sole
  direct caller passes 5. The `0x00420d93` value is gated by an enclosing bit
  test and nonzero check; direct zero-valued callers cannot reach that branch
  as shown, while recursive and wrapper forwarding remain unresolved.
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

## Completed bounded direct-caller procedure

The direct-caller procedure below was completed against the pinned executable
with GNU objdump 2.45.1-5.fc43. Its bounded results, per-call windows, and
hash-pinned verifier are recorded in the [direct-caller report](level-0001-query-callers-2026-10-23.md).
The seven query-branch anchors are independently guarded by the
[branch verifier](level-0001-query-flag-branches-2026-10-23.md).

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

Those observations classify direct relative calls only. The numeric value and
source of the remaining wrapper-forwarded argument, indirect and virtual
entries, path feasibility, flag meanings, discriminator semantics, and visual
effect remain unknown. The wrapper table/raw-section scans are documented in
[the wrapper follow-up](level-0001-wrapper-table-2026-10-23.md) and
[the indirect-call note](level-0001-indirect-40cc15-2026-10-23.md); the static
evidence does not identify a further bounded direct edge to trace.
