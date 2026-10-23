# Module shutdown, handle ownership and normal exit order

## Scope and evidence

Date: 2026-10-23. US retail inputs, verified again before analysis:

- Drakan.exe SHA-256 `23630f48e20e8a9f42026501165ae1df407cfcee545a784ec930a4c25ee70648`.
- Dragon.rfl SHA-256 `9b6496b65e962cf35dd1e18f424f2c8af08ceade78331dcc0b6da332ce844ac3`.

No original code was executed. Ghidra 12.1.4/OpenJDK 25.0.4.1 processed private
projects sequentially with `-readOnly -noanalysis`; all queries completed.
Independent raw checks used GNU objdump 2.42 and Python 3.12.3 PE decoding.
Two reviewers separately checked RFL shutdown/action dispatch and EXE handle
ownership. Conclusions distinguish observed instructions from conditional
runtime linkage. This extends [callback binding](input-callback-binding-2026-10-23.md)
and [normal exit registration](input-exit-registration-2026-10-23.md).

## Loaded handle is not an initialization-success flag

EXE wrapper `0x4072e0` passes receiver `0x4800f0` to `0x411be0`, which zeros
its handle field. The loader at `0x437b61` supplies that receiver to
`0x411c00` at `0x437b67`. Observed handle-loading paths:

| Stage | Outcome |
| --- | --- |
| LoadLibraryA at `0x411c0a` returns null | Return -9; no new handle retained. |
| RiotDllIdentifier export missing or returns neither 0x101 nor 0x80000101 | FreeLibrary on the new handle at `0x411c32` or `0x411c54`; return -11. |
| Accepted version | If an old retained handle exists, FreeLibrary at `0x411c6d`; store the new handle at `0x411c97`; return 0. |

Only afterward does the caller resolve GetRFLInterface at `0x437b80`.
The null-export branch returns -11 at `0x437b8c` without clearing/freeing the
retained handle in that bounded branch. Module initialization via interface
slot +8 happens later at `0x407b32`. Its nonzero-result diagnostic path returns
-6 at `0x407b50`; the check does not write the handle field.

Shutdown helper `0x407b70` tests that retained handle, skipping the interface
call only when zero at `0x407b77`. Otherwise it calls interface `0x483bf4`
slot +0x0c at `0x407b81`, without a local interface-null guard. Therefore this
gate alone proves neither completed module initialization nor a valid current
interface. Surrounding failure-path reachability remains unverified; this
report does not claim an observed crash or vulnerability.

## Observed RFL shutdown body

For the initialized retail RFL table, slot +0x0c is
`0x100139c0..0x10013a66`. Ghidra initially lacked this function; it was explicitly
recovered and cross-checked against raw instructions. Its ordered calls are:

| Condition | Site and boundary |
| --- | --- |
| Global 0x1017aea4 equals 2 or 4 | `0x100139d1` -> `0x100247f0(1)` |
| Host field +0x1ac nonnull | `0x100139e8` -> `0x1014d4e0`, using that receiver |
| Global 0x1017aea8 nonnull | `0x10013a05` -> host field +0x1a0 object's slot +0x14(global); then `0x10013a0a` -> host function at 0x1017af00(0) |
| Always if prior calls return | `0x10013a1a` -> `0x1012a090(this=0x1017ae08,1)`; `0x10013a26` -> `0x10129fd0(this=0x1017ae08,0)` |
| Always if prior calls return | `0x10013a35` -> host function at 0x1017aed4(addresses 0x1017aa28,0x1017aa2c); `0x10013a43` -> `0x10023be0(this=0x1017aa00)` |
| Global 0x1017ae9c nonnull | `0x10013a5c` -> `0x1000c6c0(0x4004,0,1,0)` |

It returns zero. No direct call to callback-clear helper `0x1000e900(0)`
appears in this body. Callee effects cannot be inferred from this absence.

For the conditional 0x4004 dispatch, raw table decoding gives index
`0x4004-0x4002=2`, byte at `0x1000e1d6` = 0x28, and target dword at
`0x1000e1d0` = `0x1000d6e6`, a return-zero path. However, earlier state gates
can intercept it: host field +0x1ac, globals 0x1017a99c/0x1017a9f8 and nested
state can lead to `0x1000e610`, `0x1000e470` or `0x10024540`, or an early return
one. Their effects were not traced. Thus neither unconditional callback
clearing nor an unconditional no-op follows from action 0x4004.

## Normal process-exit ordering

Raw initializer entries are adjacent: `0x47b040` -> `0x4072d0` for the module
handle, followed by `0x47b044` -> `0x407310` for input. The existing initializer
walker visits in increasing order. Module initializer `0x4072d0` initializes
the handle then reaches `0x4072f0`, which registers callback `0x407300` through
`0x466d38` at `0x4072f5`. Input registers `0x407340` afterward at `0x407335`.

Under successful registrations, unchanged registration order and normal exit's
reverse callback walk, **input destruction `0x407340` precedes module-handle
release `0x407300`**. Input destruction reaches actual device/interface release
`0x4059f0`, as established in the exit report. Module wrapper `0x407300` supplies
receiver `0x4800f0` to `0x411bf0`, which tail-jumps to `0x411ca0`.

`0x411ca0..0x411cbe` skips a null handle; otherwise it calls FreeLibrary at
`0x411cac`, clears the stored handle at `0x411cb2`, and returns 1. It does not
check the FreeLibrary result before clearing. This proves the order of release
attempts, not that the module is actually unmapped. PE import decoding resolves
IAT 0x475090/0x475094/0x475098 to FreeLibrary/GetProcAddress/LoadLibraryA.

This relative ordering does not establish every callback-clear path or protect
against prior nonreturning callbacks, registration failure, reentrancy, module
replacement or exceptional process termination. Those are separate from the
ordinary-return chain. In particular, a valid handle is not sufficient evidence
to invoke a successfully initialized module's shutdown routine.

## Further bounded evidence and open work

A filtered linear-disassembly scan found direct `0x1000e900` calls with explicit
argument 1 at 0x10013789, 0x101489ce, 0x10148a05 and 0x1014acb6; explicit
argument **0 at 0x10150f3c** (push at 0x10150f3a); and register EBX at
0x10152043, whose value was not established in that initial scan. The subsequent
[producer report](input-clear-producer-2026-10-23.md) proves zero on its
selector 0x12/0x14 paths. These are not exhaustive indirect
xrefs. The explicit clear site is verified locally but not linked to shutdown.
At this stage its containing function was undefined; no function start was
guessed. The subsequent [dispatch investigation](input-clear-dispatch-2026-10-23.md)
recovered the entry using the interface table and established its local gates. The other site belongs to 0x101516b0, with a large
body, and is left for a separate bounded control-flow question.

For a portable lifecycle, distinguish handle acquisition, interface provisioning,
successful initialization, callback registration, shutdown and release. This is
an implementation implication, not a claim that the original models each state
explicitly. Next questions are the explicit-clear site's reachability and the
early-init-failure route into host shutdown.

## Reproduction

Use the existing pinned tools and private projects; verify both hashes first.
Raw commands sufficient for the new bounded claims:

```sh
objdump -d -Mintel --start-address=0x4072d0 --stop-address=0x40734a "$DR_EXE"
objdump -s --start-address=0x47b040 --stop-address=0x47b048 "$DR_EXE"
objdump -d -Mintel --start-address=0x407b19 --stop-address=0x407b99 "$DR_EXE"
objdump -d -Mintel --start-address=0x411be0 --stop-address=0x411cbf "$DR_EXE"
objdump -d -Mintel --start-address=0x437b61 --stop-address=0x437c09 "$DR_EXE"
objdump -p "$DR_EXE"
objdump -d -Mintel --start-address=0x100139c0 --stop-address=0x10013a67 "$DR_RFL"
objdump -d -Mintel --start-address=0x1000c6c0 --stop-address=0x1000c99a "$DR_RFL"
objdump -d -Mintel --start-address=0x1000c9ce --stop-address=0x1000ca10 "$DR_RFL"
objdump -s --start-address=0x1000e1d0 --stop-address=0x1000e1d7 "$DR_RFL"
objdump -d -Mintel --start-address=0x1000d6e6 --stop-address=0x1000d6f3 "$DR_RFL"
objdump -d -Mintel --start-address=0x10150f16 --stop-address=0x10150f5c "$DR_RFL"
```

For IAT identification, use ImageBase + FirstThunk + four times the import's
zero-based index. Ghidra RFL query: `InspectPinnedRetailFunctions.java 0x100139c0`.
EXE queries, sequentially: `InspectWindowLifecycle.java 0x407b70`, then
`InspectWindowLifecycle.java 0x411ca0 0x411c00`. For registration walk semantics,
use the linked exit report. The included [FindRetailOwners.java](support/FindRetailOwners.java) reproduces
function ownership with arguments `0x10150f3c 0x10152043` in the same RFL
project and read-only mode; its hash guard accepts only the pinned RFL.
This ownership query also completed successfully. Keep all raw outputs/decompilation
outside Git. No new external implementation or runtime observation was used.

Follow-up: [initialization failure](module-init-failure-2026-10-23.md) now
traces the -6 result through caller fall-through and conditional later shutdown.
