# Input-object construction and normal-return cleanup

## Scope and method

Date: 2026-10-23. Observed static linkage, conditional on successful registration
and reaching normal termination. US retail executable SHA-256:
`23630f48e20e8a9f42026501165ae1df407cfcee545a784ec930a4c25ee70648`;
canonical hash verified again. No original executable or DLL was run.

This closes the registration question in the
[input activation report](input-activation-poll-boundary-2026-10-23.md).
Tools: Ubuntu GNU objdump 2.42, Python 3.12.3 standard-library PE parsing,
Ghidra 12.1.4/OpenJDK 25.0.4.1. Ghidra processed the existing private scratch
project sequentially with `-readOnly -noanalysis`; a separate agent traced
the initializer tables, registration and exit walk from raw bytes/instructions
without Ghidra. Symbolic CRT names are unnecessary for the conclusion.

## Observed startup chain

| Site | Evidence |
| --- | --- |
| `0x468ec5` | PE entry `0x468e20` calls `0x4692b0`. |
| `0x4692b0` | Dispatches [0x47b0bc,0x47b0d0), then [0x47b000,0x47b0b8) through `0x4693b6`. |
| `0x4693c7` | Walker invokes each nonnull pointer, advancing four bytes. |
| `0x47b0c0` | Raw pointer `0x466d4a` in the first range. That function allocates 0x80 bytes, sets base `0x487e50`, zeros the first entry, and sets end `0x487e4c` equal to base. |
| `0x47b044` | Raw pointer `0x407310` in the second range. |
| `0x407310..0x407325` | Calls constructor wrapper, which supplies receiver `0x47fb20` to `0x405830`; then branches to registration wrapper `0x407330`. |
| `0x407330..0x407335` | Supplies callback `0x407340` to `0x466d38`. The wrapper's result is not checked here. |

`0x466d38` calls `0x466cba` at `0x466d3c`. The latter checks allocation capacity
against the end pointer, optionally grows storage, and updates both base/end if
the block moves. At `0x466d24`, it writes the supplied callback at the current
end; `0x466d26` advances end by four bytes. Growth failure returns zero without
appending. For this nonnull supplied callback, `0x466d38` returns 0 on success
and -1 on failure. Allocation/locking-helper internals are outside this slice.

## Observed normal-return exit chain

1. Entry calls application `0x412010` at `0x468efb` and forwards its return
   value to `0x4692dd` at `0x468f04`.
2. `0x4692dd` calls `0x4692ff(status,0,0)`.
3. With second argument zero, `0x4692ff` walks the registered table in reverse:
   from [0x487e4c]-4 down through [0x487e50]. It skips null entries and invokes
   each nonnull pointer at `0x469356`.
4. For successfully registered callback `0x407340`, `0x407345` transfers to
   `0x4058c0` with receiver `0x47fb20`. That helper resets the object's table
   pointer and jumps at `0x4058c6` to actual interface release `0x4059f0`.
5. The exit helper subsequently walks [0x47b0d4,0x47b0dc) and
   [0x47b0e0,0x47b0e8). With third argument zero it calls ExitProcess(status)
   at `0x46939c`, independently resolved through IAT `0x475138`.

This connects the cleanup helper to ordinary application return, rather than
merely inferring ownership from matching field offsets. It also separates
process-lifetime interface release from window deactivation's state clear and
device operations. See the [window report](window-lifetime-2026-10-23.md).

## Counterexamples and confidence

High confidence in the static table entries, registration and reverse invocation
chain: Ghidra findings agree with independent disassembly/PE data checks.
It is **not** a guarantee of cleanup on all exits:

- Wrapper `0x4692ee` supplies second argument 1, bypassing the registered
  callback walk and the first termination range.
- If [0x486560] is already 1, calls at `0x469314`/`0x46931b` invoke
  GetCurrentProcess/TerminateProcess; successful termination bypasses cleanup.
- Registration failure, earlier startup termination, or an earlier callback
  not returning can prevent reaching this input callback.
- Runtime callback insertion/removal, reentrancy and all allocation failures
  have not been exercised. No original runtime behavior is claimed.

For portable lifecycle design, construction, successful cleanup registration,
normal-return destruction and emergency exit should be explicit concepts.
Do not assume a window-close notification alone releases all process objects.

## Reproduction

Use the canonical-hash gate and pinned environment from
[lifecycle reproduction](lifecycle-reproduction-2026-10-23.md). In its existing
private project run the included script with arguments `0x466d38 0x466cba
0x4692ff 0x466d4a 0x4692b0`; retain `-process Drakan.exe -readOnly -noanalysis`.
The investigation used three sequential passes, all successful. Independently:

```sh
objdump -p "$DR_EXE"
objdump -s --start-address=0x47b000 --stop-address=0x47b0ec "$DR_EXE"
objdump -d -Mintel --start-address=0x466cba --stop-address=0x466d79 "$DR_EXE"
objdump -d -Mintel --start-address=0x4692b0 --stop-address=0x4693d0 "$DR_EXE"
objdump -d -Mintel --start-address=0x468ec0 --stop-address=0x468f10 "$DR_EXE"
objdump -d -Mintel --start-address=0x407310 --stop-address=0x407350 "$DR_EXE"
objdump -d -Mintel --start-address=0x4058c0 --stop-address=0x4058d0 "$DR_EXE"
```

Map VAs 0x47b0c0 and 0x47b044 through the PE section table and decode one
little-endian uint32 each; compare with 0x466d4a and 0x407310. All raw outputs
stay outside Git. Remaining work concerns exceptional/reentrant paths, not a
missing ordinary-return linkage.

The PE header's ImageBase plus AddressOfEntryPoint gives 0x468e20.
Use ImageBase plus the import descriptor's FirstThunk plus four times the
zero-based index of ExitProcess to reproduce IAT VA 0x475138.
