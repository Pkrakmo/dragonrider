# Module initialization failure and caller fall-through

## Scope and method

Date: 2026-10-23. US retail Drakan.exe SHA-256
`23630f48e20e8a9f42026501165ae1df407cfcee545a784ec930a4c25ee70648`.
Hash reverified; no original executable run. Ghidra 12.1.4/OpenJDK 25.0.4.1
and an independent GNU objdump 2.42/PE-import check agree on the control flow.
Ghidra processed the existing private EXE project, `-readOnly -noanalysis`,
querying `0x412170 0x412010`; both existing functions completed successfully.

This follows the [handle and shutdown report](module-shutdown-boundary-2026-10-23.md).
Confidence is high in the static return-value checks and call order. Runtime
message delivery, reentrancy, safe operation and a particular failure occurring
are not established.

## Observed -6 path

| Site | Instruction-level outcome |
| --- | --- |
| `0x407b32` | Call module interface slot +8. |
| `0x407b35` | Nonzero result takes diagnostic branch. |
| `0x407b46` | Invoke global 0x483af8 object's slot +4. |
| `0x407b50..0x407b63` | If diagnostic returns, set result -6 and return. |
| `0x4122a6` | Caller invokes 0x407780. |
| `0x4122ae..0x4122b6` | Reject only -12 and -10; **-6 falls through**. |
| `0x4122c6` | SetClassLongA restores the cursor. |
| `0x4122c8..0x4122d0` | If global 0x48390c is nonnull, clear 0x484030. |
| `0x4122e5`, `0x4122f2` | ShowWindow and UpdateWindow. |
| `0x4122fa..0x412306` | Return 1 from 0x412170. |

The outer application entry calls 0x412170 at `0x4120a5`. A nonzero return
branches at `0x4120af` to `0x4120c0`, entering the PeekMessageA/DispatchMessageA
loop. This loop can call application iteration `0x407d00` at `0x412142`.
Thus a normally returned module-initialization failure does **not** trigger an
immediate failure return or direct shutdown in these checked callers.

This differs from -12/-10, which cause 0x412170 to return zero. The outer
zero-result path calls `0x460250` at `0x4120b1` and returns zero without entering
the message loop. Other startup failures and 0x460250's internals are not a
complete teardown map here.

## Conditional later shutdown

The independently checked [window lifetime](window-lifetime-2026-10-23.md)
provides a conditional later route:

1. Window-procedure message 2 calls `0x412320` at `0x412461`, then posts quit.
2. `0x412320` sets 0x484030 to 1, calls `0x408050(0)`, then calls `0x407b70`
   at `0x412334`.
3. `0x407b70` checks retained handle 0x4800f0 and, if nonzero, invokes module
   interface slot +0x0c at `0x407b81`. It does not locally test an independent
   successful-initialization flag or check that the interface pointer is nonnull.

Message 0x10 has a DestroyWindow path after an optional receiver operation;
actual subsequent destruction/quit-message delivery was not observed. The
diagnostic, window APIs, message dispatch and other calls may reenter code or
fail to return. The report therefore establishes a **possible static route**
from failed initialization through normal loop entry to later message-driven
shutdown, not guaranteed shutdown, a demonstrated crash, or safe recovery.

The portable-design implication is to represent initialization success separately
from a loaded handle, and make the selected failure policy explicit. That is
an implementation recommendation derived from the boundary, not an instruction
to modify the engine or reproduce a presumed original defect.

## Reproduction

Use the pinned environment and included script from
[lifecycle reproduction](lifecycle-reproduction-2026-10-23.md). Verify the
canonical hash, then keep raw outputs private:

```sh
sha256sum "$DR_EXE"
objdump -d -Mintel --start-address=0x407b19 --stop-address=0x407b84 "$DR_EXE"
objdump -d -Mintel --start-address=0x412170 --stop-address=0x412191 "$DR_EXE"
objdump -d -Mintel --start-address=0x41229e --stop-address=0x412313 "$DR_EXE"
objdump -d -Mintel --start-address=0x412093 --stop-address=0x412170 "$DR_EXE"
objdump -d -Mintel --start-address=0x412320 --stop-address=0x412342 "$DR_EXE"
objdump -d -Mintel --start-address=0x412461 --stop-address=0x41249c "$DR_EXE"
objdump -p "$DR_EXE"
```

PE import decoding identifies the named Windows calls; include ImageBase and
FirstThunk when matching IAT addresses. Ghidra query:
`InspectWindowLifecycle.java 0x412170 0x412010`, with `-process Drakan.exe
-readOnly -noanalysis`. This complements earlier startup results rather than
changing the documented -12/-10 checks or claiming all nonzero results are fatal.
