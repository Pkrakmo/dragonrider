# Retail window-procedure lifetime

## Scope

- Date: 2026-10-23. Observed static control flow; inferred subsystem roles.
- Question: how does the registered window callback handle closing, destruction,
  activation, paint and deferred state changes?
- US retail executable SHA-256:
  `23630f48e20e8a9f42026501165ae1df407cfcee545a784ec930a4c25ee70648`;
  canonical match independently rechecked before analysis.
- Main range: `0x412350..0x41275d` inclusive, preferred image base `0x400000`.
- Related helpers: `0x412320`, `0x406d80`, `0x408050`, `0x407b70`.

## Method and provenance

Ubuntu 24.04.5, Python 3.12.3, GNU objdump 2.42, Ghidra 12.1.4,
OpenJDK 25.0.4.1; REA 6.7.0 with Ghidra provider initially attempted
`analyze_function` at `0x412350` after a fresh import. It returned
"No procedure exists". This is a recovery limitation, not absence of code:
the [startup map](startup-map.md) records the callback assignment at `0x4121bc`.

A separate fresh headless project also had no defined function there. The
[bounded script](support/InspectWindowLifecycle.java) explicitly disassembled
and created the candidate at that observed address, then decompiled it and
listed call sites. It recovered the range above. Subsequent queries used the
same private project sequentially with `-process -readOnly -noanalysis`.
No persistent pre-existing database was overwritten; no original was executed.

A separate agent independently inspected raw objdump instructions and parsed
PE imports without Ghidra. It agreed on message discriminants, call positions,
activation tests, default handling, `0x412320` ordering and `0x406d80` behavior.
The deeper `0x407b70` and `0x408050` summaries below have Ghidra evidence only.
See [reproduction procedure](lifecycle-reproduction-2026-10-23.md).

## Observed lifetime boundaries

| Message / site | Static behavior |
| --- | --- |
| `0x10`, `0x412478..0x41248c` | If global receiver `0x48390c` is nonnull, call its virtual slot +0x28 at `0x412484`; then DestroyWindow(hwnd) at `0x41248c`. Returns zero. |
| `2`, `0x412461..0x412468` | Call `0x412320`, then PostQuitMessage(0). Returns zero. |
| Helper `0x412320..0x412341` | Set global `0x484030` to 1; call `0x408050(0)` at `0x41232c`, `0x407b70()` at `0x412334`, and ClipCursor(NULL) at `0x41233b`, in that order. |
| `6`, `0x4123f8..0x412451` | Convert low 16 bits of wParam to boolean and call `0x406d80` with receiver `0x47fb20` at `0x41240a`. |
| Message 6 inactive | Call `0x4317f0` on `0x482c10` at `0x412419`, then global `0x48390c` virtual +0x28 at `0x412426`. This slice has no null guard on that receiver. |
| Message 6 active | Call `0x431810` on `0x482c10` at `0x412433`, then `0x439be0` at `0x41243e`; PostMessageA(hwnd,0x84c,0,0) at `0x412451`. |
| `0x84c`, `0x412707..0x41271a` | If receiver `0x48390c` exists, call virtual +0x24 with its field +0x5c. Deferred behavior remains unnamed. |
| `0x211` or `0x231` | Call `0x406d80(receiver=0x47fb20,0)` at `0x4126cd`. |
| `0x232`, or `0x212` with nonzero wParam | Call GetActiveWindow/IsIconic, then `0x406d80` at `0x41274f` with true when this HWND is active **or is not iconic**; false otherwise. `0x212` with zero wParam returns zero directly. |

Message constants 0x10 and 2 correspond to
[WM_CLOSE](https://learn.microsoft.com/en-us/windows/win32/winmsg/wm-close) and
[WM_DESTROY](https://learn.microsoft.com/en-us/windows/win32/winmsg/wm-destroy).
These Microsoft definitions label observed constants; they are not evidence
that a particular event occurred during gameplay. The program was not run.

`0x406d80..0x406db8` establishes an important distinction: a zero argument calls
receiver virtual +8 at `0x406d8f`, then virtual +0x18 for indices 0, 1 and 2
at `0x406d99`, and stores zero at receiver +0x5b8. A nonzero argument only
stores that value at +0x5b8. Thus reactivation does not itself demonstrate
device acquisition; the field's consumers and the virtual targets remain open.

## Paint and dispatch boundaries

Message `0xf` returns zero while global `0x484030` is nonzero or the window is
iconic. Otherwise BeginPaint at `0x4123c3` precedes conditional `0x43abf0`
(only when `0x484034` is zero), receiver `0x48390c` slot +0x60 at `0x4123df`,
and EndPaint at `0x4123e8`. This supports an iteration/paint guard association
with the startup map; it does not identify the virtual method as presentation.

Other explicit message values are `0x100`, `0x101`, `0x102`, `0x104`, `0x105`
and `0x106`; there is no explicit `0x103` branch. Paths dispatch to receiver
`0x483bf4` slots +0x20/+0x24, or `0x483af8` slot +0x24, under state and key
conditions. Selected default paths are suppressed when receiver `0x48390c`
exists and byte [receiver+0x30] has mask 0x02 set. Other default paths call
DefWindowProcA and preserve its return value; handled paths return zero.
This is a boundary inventory, not a complete keybinding specification.

## Deeper teardown observations and limits

`0x408050(0)` calls `0x406de0` on `0x47fb20` with argument 1 at `0x408065`
and sets `0x47f458` to zero; its mask-0x02 transition/redraw branch is bypassed.
The meaning of `0x406de0` is not established in this slice.

`0x407b70` conditionally invokes object `0x483bf4` slot +0xc, then invokes
receiver `0x48390c` slot +0x3c, followed by helpers `0x414ac0`, `0x438c40`,
`0x407c20(0)`, `0x427ea0`, `0x430ae0`, and `0x40a430`. Later guarded paths call
`0x43b910`/`0x466d79` for object `0x483908` and `0x438940`/`0x466d79` for
object `0x48390c`. This is destruction-like behavior; the whole descendant
cleanup graph, repeat-call safety and indirect interface ownership are unknown.
The early receiver use also limits any assumption that this helper accepts
arbitrary partially initialized state.

## Assessment and next action

High confidence: directly cross-checked message tests, call order, constants,
return handling and the activation helper's asymmetric behavior. Medium
confidence: destruction-like labels for the Ghidra-only descendants. Unknown:
runtime reachability on failed startup, exact graphics vtables, asynchronous
reentrancy and complete resource ownership. No demonstrated runtime bug is
claimed from unchecked pointers or decompiler artifacts.

For a portable `platform`/`game` boundary, retain separate concepts for close
request, destruction, quit notification, input enable state and deferred work.
Future synthetic lifecycle tests could check those transitions independently;
this report does not prescribe copying the original implementation.
The subsequent [activation/polling follow-up](input-activation-poll-boundary-2026-10-23.md)
resolves selected `0x47fb20` virtual slots and connects +0x5b8 to a polling gate;
runtime dispatch and complete teardown remain conditional.
