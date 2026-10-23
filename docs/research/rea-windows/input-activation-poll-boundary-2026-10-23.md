# Input activation, vtable and polling boundary

Date: 2026-10-23. Observed static linkage; runtime dispatch remains conditional.
US retail SHA-256:
`23630f48e20e8a9f42026501165ae1df407cfcee545a784ec930a4c25ee70648`.
Canonical hash rechecked. Ubuntu GNU objdump 2.42, Python 3.12.3,
Ghidra 12.1.4/JDK 25.0.4.1. No original executable or DLL run.
This follows [input initialization](input-initialization-2026-10-23.md) and
[window lifetime](window-lifetime-2026-10-23.md).

## Observed table assignment and separate release route

An independent raw-byte/disassembly check established this chain:

- `0x407320` loads receiver `0x47fb20`; `0x407325` jumps to constructor `0x405830`.
- Constructor instruction `0x40587d` writes table address `0x47539c` to [this].
- Its raw dwords map slots +0 to `0x405a60`, +8 to `0x4059d0`,
  +0x14 to `0x406370`, +0x18 to `0x4063e0`. The coordinator separately
  rechecked +8/+0x14/+0x18 and read +0x6c as `0x406d70`.
- `0x4059d0` clears 16 dwords at this+0x2f8: virtual +8 is a 64-byte
  state clear, **not retained-interface release**.
- `0x4063e0(index)` accepts signed indices 0..2 only, requires mask 0x02
  in [this+0x34+index*0xec] and a nonnull device [this+0xdc+index*0xec].
  Index 1 restores the cursor counter through ShowCursor(1); device slot
  +0x20 is called at `0x406437`. It returns 1 only for a zero device result.
- `0x407340` loads receiver `0x47fb20`, then jumps to `0x4058c0` at `0x407345`.
  `0x4058c0` resets the table pointer and tail-jumps release helper `0x4059f0`.
- `0x407330` supplies callback `0x407340` to `0x466d38` at `0x407335`.
  Wrapper `0x407310` calls the constructor wrapper and jumps to this registration
  wrapper. Registration-helper semantics and invocation from runtime shutdown
  have not been proved; a registered-destructor candidate is the justified label.

Consequently, the window deactivation helper clears transient input state,
invokes the three guarded device-slot +0x20 operations, then clears +0x5b8.
This statement assumes the observed constructor-installed table remains selected;
it does not prove every runtime dispatch or identify the device method by name.

## Observed polling gate and retry boundary

Ghidra recovered `0x405a60..0x405cc1` using the existing private project with
`-process -readOnly -noanalysis`. The coordinator independently checked the
following prefix with objdump and mapped the relevant table slots from raw bytes:

- `0x405a6b`: virtual +8 clears transient state even before the polling gate.
- `0x405a6e..0x405a93`: mode field +0x5bc and fields +0x5c4/+0x5c8 can
  short-circuit the operation. Meanings of these additional gates remain unknown.
- `0x405a9d`: virtual +0x6c returns this+0x5b8 via `0x406d70`; zero exits.
  This connects the window activation field to permission to enter device work.
- `0x405b02` optionally calls device slot +0x64. That result, or the result of
  device slot +0x28 at `0x405b47`, is compared with `0x8007000c` and `0x8007001e`.
  Matching values invoke object virtual +0x14(index) at `0x405b18`.
- With table `0x47539c`, +0x14 resolves to `0x406370`: signed index 0..2,
  mask 0x02 and nonnull-device checks precede device slot +0x1c at `0x4063c8`.
  Index 1 first decrements the cursor display counter through ShowCursor(0)
  until negative. The helper returns 1 for a zero device result, else zero.
- A nonzero helper return decrements the iteration index at `0x405b23`, allowing
  the loop to retry the same device. This prefix does not establish a retry cap.
- The slot +0x28 read uses element size 0x10 and requested count 0x40.
  Later event dispatch and per-device interpretation were not independently
  checked in this slice and remain outside this report.

## Reproduction

Use the hash-gated probe and scratch-project procedure in
[lifecycle reproduction](lifecycle-reproduction-2026-10-23.md). Add this query:

```sh
"$GHIDRA_HOME/support/analyzeHeadless" "$dr_project" WindowLifecycle \
  -process Drakan.exe -readOnly -noanalysis -scriptPath "$dr_scripts" \
  -postScript InspectWindowLifecycle.java 0x405a60
objdump -d -Mintel --start-address=0x407310 --stop-address=0x407350 "$DR_EXE"
objdump -d -Mintel --start-address=0x405830 --stop-address=0x4058d0 "$DR_EXE"
objdump -d -Mintel --start-address=0x4059d0 --stop-address=0x4059f0 "$DR_EXE"
objdump -d -Mintel --start-address=0x406370 --stop-address=0x406440 "$DR_EXE"
objdump -d -Mintel --start-address=0x406d70 --stop-address=0x406d80 "$DR_EXE"
objdump -d -Mintel --start-address=0x405a60 --stop-address=0x405b60 "$DR_EXE"
```

For table slots, subtract image base from `0x47539c+slot`, locate the raw-backed
PE section, compute raw offset + RVA - section RVA, then decode one little-endian
uint32. Apply this to slots 0, 8, 0x14, 0x18 and 0x6c; no bulk export is needed.
Ghidra processing exited 0; raw values agreed with the constructor/table chain.

High confidence in these bounded static links. Unknown: initializer-table
reachability, registration helper semantics, later table replacement, full event
mapping, and actual device behavior. A portable implementation can separate
transient-state clear, activation permission, acquire-like retry, device disable
and interface release. Next bounded question: trace callback registration
`0x466d38` and the event-consumer boundaries `0x405cd0`, `0x405d10`, `0x405fc0`.
