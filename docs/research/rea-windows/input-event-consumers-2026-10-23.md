# Bounded input event-consumer contracts

## Scope and provenance

Date: 2026-10-23. Observed static transformations; device and gameplay meanings
remain partly inferred. US retail executable SHA-256:
`23630f48e20e8a9f42026501165ae1df407cfcee545a784ec930a4c25ee70648`.
Canonical input rechecked; no original executable/DLL run. Tools: Ghidra 12.1.4,
JDK 25.0.4.1, Ubuntu objdump 2.42, Python 3.12.3 standard-library PE decoding.

Ghidra examined `0x405cd0..0x405d07`, `0x405d10..0x405fbf`, and
`0x405fc0..0x406217` in the existing private scratch project with
`-process -readOnly -noanalysis`. A separate agent independently checked all
three functions with raw disassembly and decoded their referenced float32
constants from PE sections. No source implementation was copied.

## Shared call boundaries

Each function uses an ECX receiver and three stack arguments, here named
`offset`, `data`, and `third`; return pops 12 bytes. Those descriptive names
are not recovered source types. The [polling boundary](input-activation-poll-boundary-2026-10-23.md)
provides the upstream 16-byte event-element context; the third argument's
meaning is not independently established.

Callbacks are pointer **fields**, not vtable slots:

| Field | Observed four arguments |
| --- | --- |
| this+0x5c4 | zero-extended mapping word, transformed code, status, third |
| this+0x5c8 | kind, code, this+8, this+0xc |

The mapping word is at this+0x338+2*code. Calls are followed by caller stack
cleanup of 16 bytes. These slices have no callback-null guard or result handling.
Upstream mode/callback gates do not prove safety of arbitrary direct calls.

## First consumer: `0x405cd0`

Unsigned offset 1..0xff is accepted by comparisons at `0x405cd4`/`0x405cd9`.
Status is `(data>>7)&1`; the function reads the mapping word for that offset
and calls +0x5c4 at `0x405cfc`. Other offsets return without a callback.
There is no local state/table update. A keyboard-like role follows from the
upstream device path, but the code is not itself an operating-system keycode.

## Second consumer: `0x405d10`

| Offset / gate | Observed transformation |
| --- | --- |
| 0x0c..0x0f | Code = offset+0xf4 (0x100..0x103). Update corresponding mask in this+0x1c4 using data mask 0x80. |
| Same offsets, mode this+0x5bc = 0 | If this+0x28 is nonzero, swap codes 0x100 and 0x101. Call +0x5c8 at `0x405d9d` with status, code and current +8/+0xc. |
| Same offsets, nonzero mode | Call +0x5c4 at `0x405dc5` with the unswapped code and mapping. |
| Offsets 0..8 | Index = offset>>2. **No alignment check**: neighboring byte offsets alias an index. Other offsets outside the button range return. |

For mode 1, each index selects a 12-byte record at this+0x124+12*index.
Record first dword -1 skips accumulation. Otherwise signed data is converted
to float, multiplied by float32 at `0x475428` (0.0016666667070239782,
approximately 1/600), clamped to [-2,+2], multiplied by record+8 and this+4,
and added to this+0x2f8+4*record[0] (`0x405e0a..0x405e56`). Index bounds for
that mapped destination depend on earlier configuration and are not proved here.

Index 2 also selects code 0x114 for nonnegative data or 0x115 for negative
data. Status is signed absolute-data >0x32, with x86 negation/wrap behavior
at extreme values. Only status 1 calls +0x5c4 at `0x405e9b`; the status is
stored at +0x194 or +0x198 at `0x405ea4`. This branch does not issue a matching
release callback when status becomes zero.

For mode other than 1, the numeric path additionally requires this+0x2c=1:

- Thresholds +0x10 and +0x14 separately compare with signed absolute original
  data. The first can select twice the data; the second overrides with four
  times the data (`0x405ebb..0x405ef1`).
- Multiply by this+0x1c, add remainder at +0x20+4*index, divide by 10 with
  signed truncation toward zero, and retain the signed remainder. This is not
  unsigned division or floor division for negative values.
- Indices 0/1 update +8/+0xc and clamp against zero and object `0x48390c`
  dimensions +0x660/+0x664 minus 1. Callback +0x5c8 at `0x405f83` receives
  `(2,0,+8,+0xc)` only if the quotient is nonzero. Positive/sensible dimensions
  are assumptions required for interpreting those as bounded coordinates.
- Index 2 additionally requires this+0x13c != -1; callback kind 3 uses code
  0x115/0x114/0 for negative/positive/zero original data. This path bypasses
  the quotient-nonzero gate (`0x405f93..0x405fbe`).

## Third consumer: `0x405fc0`

Offsets 0x30..0x4f select code offset+0xf0 (0x120..0x13f), update the
corresponding bit in this+0x2b0 from data mask 0x80, then call +0x5c4 at
`0x406020`. The mapping and boolean status use the shared contract.

Offsets 0..0x1c require mode 1. Again index=offset>>2 without an alignment
check. A 12-byte record at this+0x210+12*index must have first dword != -1.
Center data by subtracting 0x8000; values strictly inside the interval bounded
by plus/minus this+0x30 become zero. Scale by float32 1/32768 at `0x475430`,
clamp to [-1,+1], multiply by record+8 and **overwrite** record+4
(`0x406064..0x4060c8`). This differs from the second consumer's accumulation.
No callback occurs on this branch.

Offsets 0x20..0x2c all share four boolean fields; they do not select separate
offset-indexed directional state. Low 16 bits of data equal to 0xffff produce
four zero booleans. Otherwise unsigned comparisons produce:

| Code | True condition | State field | Callback site |
| --- | --- | --- | --- |
| 0x13c | data <0x1a5e or >0x7242 | +0x2a0 | `0x40617c` |
| 0x13d | 0x2bf2 < data < 0x60ae | +0x2a4 | `0x40619e` |
| 0x13f | 0x08ca < data < 0x3d86 | +0x2ac | `0x4061c6` |
| 0x13e | 0x4f1a < data < 0x83d6 | +0x2a8 | `0x4061e8` |

Each +0x5c4 callback occurs only on a change from stored state. All four state
stores occur after the callbacks (`0x4061f9..0x40620b`); reentrant callback
effects are not established. Direction names and active device selection remain
unknown. Code range overlap with the button path is observed, not resolved
into a unique gameplay meaning here.

## Reproduction, confidence and implications

Use [the existing lifecycle procedure](lifecycle-reproduction-2026-10-23.md)
and query the included script with `0x405cd0 0x405d10 0x405fc0` in a serialized
read-only project session. Observed Ghidra exit 0. Independent raw windows:

```sh
objdump -d -Mintel --start-address=0x405cd0 --stop-address=0x406200 "$DR_EXE"
objdump -d -Mintel --start-address=0x4061f1 --stop-address=0x406220 "$DR_EXE"
```

Map float VAs 0x475384, 0x475420, 0x475424, 0x475428, 0x47542c and
0x475430 through raw-backed PE sections and decode four bytes as `<f`.
They are respectively +1, -2, +2, approximately 1/600, -1 and 1/32768.
Keep raw exports private. No external game implementation was consulted.

High confidence in the checked numeric gates, field offsets and callback
arguments; lower confidence in device labels and all gameplay associations.
For portable input design, separate raw event offsets, mapping codes, boolean
transitions, accumulated versus absolute axes, and coordinate callbacks.
Future synthetic contract checks could cover signed division, endpoint
inequalities, unaligned offsets and neutral-state transitions. No engine
implementation or assumption of valid arbitrary input follows from this note.
The subsequent [binding report](input-callback-binding-2026-10-23.md) identifies
the installed callbacks conditionally. Configuration of mapping/axis records
remains a separate question before assigning actions or device semantics.
