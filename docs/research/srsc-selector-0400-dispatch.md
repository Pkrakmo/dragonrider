# Conditional selector 0x0400 dispatch

**Input:** US retail `research/binaries/us/Drakan.exe`, SHA-256
`23630f48e20e8a9f42026501165ae1df407cfcee545a784ec930a4c25ee70648`.
**Method:** read-only GNU objdump 2.45.1 disassembly and PE data bytes,
2026-10-18, corroborated by Ghidra 12.1.4 `-readOnly -noanalysis` on the
disposable project using `TraceSrscIndirectLookup.java` (private run
`dragonrider-0400-yjPbwZoG`). **Confidence:** high for the instructions and the conditional
dispatch; runtime receiver identity and actual invocations remain unknown.
No persistent Ghidra project was accessed and no retail executable code was run.

## Observed

- The two previously identified object tables at `0x004756ec` and
  `0x004757ac` contain `0x0042b1a0` at slot `+8` and `0x0042c240` at slot
  `+0x40`. The constructor paths that install these tables are recorded in
  [lookup order](srsc-lookup-order.md#follow-up-third-word-consumers).
- The routine at `0x0042c240` takes four stack arguments. At
  `0x0042c24a`–`0x0042c25e`, it supplies the fourth argument, constant
  `0x0400`, and the first argument to a dispatch through its receiver's slot
  `+8`. If that receiver uses either table and its loader at `+0x11c` is
  non-null, the `0x0042b1a0` wrapper calls `0x0045f910` with selector tuple
  `(0x0400, first argument low 16 bits, fourth argument low 16 bits)`.
  On a negative lookup result the routine returns an error; on the successful
  branch it calls slot `+0x0c` with the found index, the second and third
  arguments, and zero. The subsequent path selects the smaller of the indexed
  runtime record's `+6` length and the third argument minus one, then uses
  that value as the limit of a byte loop that XORs bytes with a rotating
  dword. This is an instruction trace, not a safety guarantee for malformed
  state or invalid buffer sizes.
- Two indirect slot `+0x40` calls at `0x0042a338` and `0x00437a71` load
  their receiver from the same global pointer at `0x00483ad8` and supply
  zero as the fourth stack argument. If that receiver uses either observed
  table, those specific calls request third word zero. The global pointer's
  dynamic value was not established. Other slot `+0x40` calls need not target
  this object or use the same method signature.

## Inferred and unknown

The method can *accept* a nonzero third word and pass it into a full lookup;
this does not show that any execution actually supplies one. This path
concerns kind `0x0400`, so it does not establish resolution or semantics for
the candidate links between kinds `0x0101`, `0x0201`, and `0x0301`. It also
does not identify a consumer of the copied `+4` word in the 26-byte runtime
record. In particular, calls through object tables are conditional static
observations, not proof of a runtime receiver, successful lookup, or intended
meaning. Error handling, all callers, and other executable editions remain
unexamined.

## Bounded sample comparison

On 2026-10-18, `measure_srsc_0400_payloads.py` rechecked the recorded hashes
of 178 installed-US SRSC files and measured 426 `0x0400` records in one file;
all 426 have third word zero and nonempty payloads. The script independently
applies the loop's low-byte XOR and 32-bit rotate to each complete payload,
resetting the state for each record. It classifies bytes in memory and emits
only aggregate counts. The result was entirely ASCII printable in 425 payloads;
one contained at least one byte above `0x7f`, and none contained a NUL or
ASCII control byte. Before the transform, two payloads were entirely printable
and 31 contained a NUL. Printable means byte values `0x20` through `0x7e`;
these counts do not establish an encoding, language, or actual display.

This full-payload simulation is comparable to the static loop only if a
successful runtime call supplies a destination capacity greater than the
payload length and the receiver dispatches through the traced methods. Runtime
file association and invocation remain unknown. The sample is not evidence
that all `0x0400` records have zero third words or require printable output;
the high-byte exception is retained. Payload reads are capped at 65,536 bytes
and checked against the pre-table range; the table is reread after hashing,
so concurrent modification cannot be ruled out. No payload contents are output.

## Reproduction

```sh
sha256sum research/binaries/us/Drakan.exe
objdump --version | head -1
objdump -s --start-address=0x4756ec --stop-address=0x4757fc research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x42b1a0 --stop-address=0x42b1c7 research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x45f910 --stop-address=0x45fa0d research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x42c240 --stop-address=0x42c2c9 research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x42a31f --stop-address=0x42a33b research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x437a60 --stop-address=0x437a74 research/binaries/us/Drakan.exe
python3 tools/research/measure_srsc_0400_payloads.py research/installed/us research/exports/srsc-records/us.json
python3 -m unittest discover -s tools/research -p 'test_measure_srsc_0400_payloads.py' -v
```

The disposable Ghidra invocation is shown in the reproduction section of
[lookup order](srsc-lookup-order.md#reproduction); the same script includes
the table entries and instruction windows described here.
