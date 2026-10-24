# Conditional interface dispatch that clears input callbacks

## Evidence and recovery

Date: 2026-10-23. US retail Dragon.rfl SHA-256
`9b6496b65e962cf35dd1e18f424f2c8af08ceade78331dcc0b6da332ce844ac3`.
Static only; no original program executed. Ghidra 12.1.4/OpenJDK 25.0.4.1
and independent GNU objdump 2.42/PE raw-byte checks agree on the bounded
path below. This closes function ownership and local reachability for the
explicit clear site identified in [the shutdown report](module-shutdown-boundary-2026-10-23.md).
It does not establish reachability from shutdown.

The earlier ownership query found no function containing `0x10150f3c`.
Instead of guessing a nearby start, the independent raw check found pointer
`[0x1016b7bc]=0x10150b60`: slot +0x28 of the established RFL interface table
`0x1016b794`. This and the coherent entry/return instructions support function
entry `0x10150b60`. The hash-gated Ghidra script explicitly recovered body
`0x10150b60..0x10150fd6` in a read-only session, which completed successfully.
The transient definition was discarded. Old ownership output remains a record
of the earlier database state, not evidence against the recovered function.

## Observed dispatch and preconditions

The function consumes three stack arguments and returns with `ret 0xc`.
The first is treated as a payload pointer; the third is passed to an earlier
lookup helper. Argument names and protocol meaning remain unknown.

At `0x10150c29`, it reads the first payload byte; `0x10150c2b` subtracts 0x1e.
An unsigned range check accepts indices 0..0x0d, then `0x10150c37` dispatches
through table `0x10150fd8`. Entry index 0x0a at `0x10151000` contains
`0x10150f16`. Therefore **payload byte 0x28 selects the clear block**, provided
execution reaches this dispatch.

Earlier gates matter:

- The entry dereferences host state +0x1ac and nested fields before its first
  helper call, with no initial null guards in this slice. Valid state is a
  precondition, not established by the later tests.
- Helper `0x10014520` is called at `0x10150b7c`. A nonnull return whose dword
  +8 is 7 causes return zero at `0x10150b8d..0x10150b96`.
- Another conditional path checks host +0x1ac, its pointer +0x46 and that
  pointed object's dword +8 for 0 or 1. It calls `0x1000e860` at `0x10150bcd`.
  If the returned AL is nonzero, the computed record exists, and record
  dword +0x0c has any mask 0xf000 bits, only payload byte 0x23 is permitted.
  Other bytes, including 0x28, return zero before dispatch.

Thus a payload beginning with 0x28 is not sufficient by itself to guarantee
callback clearing, and the observed byte must not be assigned a gameplay
label without tracing its producer.

## Observed clear block

Assuming preceding gates pass and each callee returns, block
`0x10150f16..0x10150f5b` performs these operations in order:

1. Store boolean `[0x1017ae6c]!=0` in global `0x1017aa44`.
2. At `0x10150f35`, call `0x10129650` with ECX receiver `0x1017ae08` and
   stack arguments `(0x18,0,1,1)`.
3. At `0x10150f3c`, call `0x1000e900(0)`, with explicit zero pushed at
   `0x10150f3a`. The [binding report](input-callback-binding-2026-10-23.md)
   establishes that this helper clears the two host input callbacks after
   its own earlier calls return, then continues other logic.
4. At `0x10150f45`, call `0x1014b8e0` with the unaligned dword at payload +6.
5. Return 1. Callee return values do not determine that result.

This is a conditional module-interface path to clearing, not a proof of
unconditional shutdown cleanup, complete module teardown, or payload validity.
The body has no local payload-length validation for these reads; caller
validation and actual runtime sources are outside this slice.

## Conditional EXE caller bridge

Canonical EXE SHA-256:
`23630f48e20e8a9f42026501165ae1df407cfcee545a784ec930a4c25ee70648`.
An independent raw check identified `0x451761`, inside `0x451610`, as a call
through module object `0x483bf4` slot +0x28. Ghidra independently agrees on
the call and record arguments; its existing body is `0x451610..0x45186c`.

The record container is obtained from `0x4507d0` at `0x45161d`. An index
comes from the original receiver +0x74, or container +0x20 when that is -1.
After index bounds and active-record checks, the record address is
`container[+4] + index*0x148`. Payload is record +0x18, the second module
argument is record dword +0x144, and the third is record dword +0x10.
The slot +0x28 branch requires the third argument nonzero and unsigned first
payload byte >0x1d (`0x45172a..0x451761`). Thus byte 0x28 is eligible.

This gives a structural EXE-to-RFL route, conditional on valid preceding
state/helper calls, the pinned module interface, a suitable active record,
and the RFL pre-dispatch gates. It does not prove production of a 0x28 record,
network origin, shutdown relevance, or runtime delivery. Only this caller's
selection boundary was cross-checked; record mutation/removal and producer
semantics are outside the report. A filtered literal-global/nearby-call scan
found this match, not an exhaustive set of alias-mediated callers.

## Reproduction

Verify the hash above; use the private existing RFL project and the environment
from [callback binding](input-callback-binding-2026-10-23.md). Keep outputs private.

```sh
sha256sum "$DR_RFL" "$DR_EXE"
objdump -d -Mintel --start-address=0x451610 --stop-address=0x45178b "$DR_EXE"
objdump -s --start-address=0x1016b7bc --stop-address=0x1016b7c0 "$DR_RFL"
objdump -d -Mintel --start-address=0x10150b60 --stop-address=0x10150c3e "$DR_RFL"
objdump -s --start-address=0x10151000 --stop-address=0x10151004 "$DR_RFL"
objdump -d -Mintel --start-address=0x10150f16 --stop-address=0x10150f5c "$DR_RFL"
```

Ghidra query: `InspectPinnedRetailFunctions.java 0x10150b60` with
`-process Dragon.rfl -readOnly -noanalysis` and the included support script.
A separate existing EXE-project query used `InspectWindowLifecycle.java
0x451610`, also successfully in read-only mode. The independent raw
pointer/table check preceded RFL function creation. Confidence
is high in this dispatch boundary; callers, payload source, state ownership
and shutdown linkage remain separate questions.
