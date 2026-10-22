# Retail startup and import map

Date: 2026-10-22. Bounded static baseline; subsystem internals remain open.
Input SHA-256: `23630f48e20e8a9f42026501165ae1df407cfcee545a784ec930a4c25ee70648`.
Addresses are preferred-image VAs, base `0x400000`. See the
[loader benchmark](retail-loader-benchmark.md) for provenance and the
[toolchain report](ubuntu-toolchain-validation.md) for pinned versions.
No original executable, installer or DLL was run.

## Method

Following the loader benchmark, REA 6.7.0/Ghidra 12.1.4 analyzed four sequential
fresh imports using open_binary, analyze_function and close_binary. Input hashes
were checked each time. A separate PE parser and bounded objdump disassembly
confirmed entry arguments, message-loop calls, window creation and import counts.
That independent check does not cover all descendants. All raw outputs stay private.
Names below are interpretations unless explicitly imported API names.

## Address-indexed observations

| Address | Observation | Interpretation or limit |
| --- | --- | --- |
| `0x468e20` | PE entry RVA 0x68e20; environment, command-line and initializer setup | Runtime entry |
| `0x468efb` | Calls `0x412010` with module handle, zero, command-line helper result and show-state | WinMain-style entry; original symbol unknown |
| `0x412017` | CoInitialize(NULL), negative result exits | COM setup |
| `0x412072` | Calls `0x4082c0` with command-line remainder and callback `0x408210` | Option semantics untraced |
| `0x41207f` | Calls `0x4128f0`; zero prevents normal startup | Configuration gate |
| `0x412094`, `0x4120a5` | Calls `0x460240`, then `0x412170` | State setup then window/application initialization |
| `0x4121bc`, `0x412209` | Window-class callback `0x412350`, then RegisterClassA | Window procedure identified; body untraced |
| `0x412248`, `0x412250` | CreateWindowExA, style 0xca0000, initial 320x200; HWND stored at `0x484028` | Not established gameplay resolution |
| `0x4122a6` | Calls `0x407780`; caller rejects -12 and -10 | Engine setup candidate; not every nonzero result is fatal here |
| `0x4122e5`, `0x4122f2` | ShowWindow, UpdateWindow | Successful window path |
| `0x4120e4`, `0x4120fb`, `0x412128` | PeekMessageA for ranges 0x100..0x108, 0x200..0x209, then unfiltered | Message polling |
| `0x412101`, `0x41212a` | Tests message 0x12; surrounding paths translate/dispatch messages | Quit handling |
| `0x412142` | Calls `0x407d00` between setting/clearing `0x484034` | Application iteration |
| `0x412156`, `0x412160` | CoUninitialize and `0x460250`; returns message wParam | Normal return, not complete teardown map |
| `0x468f04`, `0x4692e5` | Application result to `0x4692dd`, then `0x4692ff` | Runtime termination |
| `0x46939c` | ExitProcess after cleanup on traced terminating path | Reentrant guard also has TerminateProcess path |

## Descendants and remaining uncertainty

`0x4128f0` checks Shift at `0x412911`, calls `0x4149d0`, and conditionally
enters configuration UI logic. DirectDrawEnumerateA is reached through `0x462808`
at `0x4129b1`, callback `0x4144e0`. DSOUND ordinal 2 is reached through `0x461460`
at `0x412a62`, callback `0x414860`. The latter looks enumeration-like; its API
name remains unresolved. Device selection and persistence are not yet mapped.

`0x407780` calls timer-state candidates `0x411d00`/`0x411d30` at
`0x4078d0`/`0x4078db`, then `0x437ab0` at `0x407906`. Its successful branch
uses constructor-like helpers `0x4387f0`/`0x43b810` at `0x407998`/`0x4079c8`,
storing objects at `0x48390c`/`0x483908`. Call `0x4389b0` at `0x4079e8`
precedes virtual dispatch through +0x48, +0x40, +0x30 and +0x3c. Exact interfaces
remain unknown. A conditional call to `0x4058d0` at `0x407ab4` is associated
with input-device failure diagnostics: a strong input-initialization candidate.
Later calls include `0x408bd0` at `0x407b19` and object `0x483bf4` slot +8 at
`0x407b32`; nonzero from that virtual call produces -6.

`0x460240`/`0x460250` wrap `0x460260`/`0x460340` with state `0x485288`.
The first calls WS2_32 ordinal 115 at `0x460276` with 0x202 and an output
buffer, checks version bytes, and may call ordinal 116 at `0x46032a`.
Cleanup calls ordinal 116 at `0x46034b`, disposes two objects and clears state.
Network-library lifecycle is inferred; ordinal API names remain unresolved.

`0x407d00` has inactive and active branches. The active path selects GetTickCount
at `0x407d68` or QueryPerformanceCounter at `0x407dfc`, updates timing globals,
and computes an eight-iteration rate. Direct and virtual calls follow, including
`0x423280` with a time-like value. Rendering/gameplay order is not established.

`0x4692b0` and `0x4692ff` use pointer-range walker `0x4693b6`. Startup ranges
include [0x47b0bc,0x47b0d0) and [0x47b000,0x47b0b8). Termination includes reverse
dynamic cleanup and ranges [0x47b0d4,0x47b0dc), [0x47b0e0,0x47b0e8).
Runtime initializer/cleanup labels are inferred. Exception exits and object
destruction remain open. Decompiler register/type artifacts are not proven bugs.

## Import inventory

Independent PE parsing found 13 descriptors and 207 thunk entries, not necessarily
unique functions or imports used at startup.

| DLL | Entries |
| --- | ---: |
| KERNEL32.dll | 104 |
| USER32.dll | 55 |
| WS2_32.dll | 22 |
| ADVAPI32.dll | 7 |
| GDI32.dll | 4 |
| COMCTL32.dll | 3 |
| ole32.dll | 3 |
| DSOUND.dll | 2 |
| DDRAW.dll | 2 |
| comdlg32.dll | 2 |
| DINPUT.dll | 1 |
| MPR.dll | 1 |
| WINMM.dll | 1 |

## Reproduction and next steps

With the canonical hash and pinned toolchain, analyze these groups sequentially:

1. `0x468e20`.
2. `0x412010`, `0x4692dd`, `0x4692b0`.
3. `0x412170`, `0x4128f0`, `0x460240`, `0x460250`, `0x407d00`, `0x4692ff`, `0x4693b6`.
4. `0x407780`, `0x460260`, `0x460340`.

Compare call sites against bounded `objdump -d -Mintel` windows; independently
parse the PE import directory. Confidence is high for observed constants/calls,
lower for subsystem labels and indirect targets. Next inspect `0x412350` for
window lifetime and `0x4058d0` for input initialization. Resolve vtables before
naming graphics interfaces. See the existing README backlog for ownership.
No external community research, engine changes or runtime compatibility claims.
