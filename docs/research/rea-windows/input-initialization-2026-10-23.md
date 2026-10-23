# Retail input initialization and ownership boundaries

## Scope and provenance

- Date: 2026-10-23. Observed static behavior; device/method roles partly inferred.
- Question: what does initialization require, which state receives interfaces,
  and how are failure and cleanup boundaries represented?
- US retail executable SHA-256:
  `23630f48e20e8a9f42026501165ae1df407cfcee545a784ec930a4c25ee70648`;
  independently checked canonical match before investigation.
- Primary function `0x4058d0..0x4059c0`, image base `0x400000`.
- Supporting ranges: `0x406930..0x406a4f`, `0x406a50..0x406be7`,
  `0x406bf0..0x406c0e`, `0x406c10..0x406d63`, `0x4059f0..0x405a58`.
- Tools: REA 6.7.0/Ghidra 12.1.4, JDK 25.0.4.1, Python 3.12.3,
  GNU objdump 2.42, Ubuntu 24.04.5. No original program or DLL executed.

REA `analyze_function` recovered the main function. Headless Ghidra examined
the supporting functions in a separate private project; callback `0x406bf0`
required explicit transient definition. The device helpers produced decompiler
stack/prototype artifacts, so their call arguments and result conditions were
checked independently against raw instructions by a separate agent without
Ghidra. PE imports and raw GUIDs were decoded with Python's standard library.
[Exact reproduction and limitations](lifecycle-reproduction-2026-10-23.md).

## Observed top-level initialization

The [startup map](startup-map.md) places the call at `0x407ab4` on a conditional
engine-initialization path with receiver `0x47fb20`. ECX carries that receiver;
Ghidra's source-level convention/type labels remain provisional.

| Site | Observed behavior |
| --- | --- |
| Prefix before `0x405923` | Derive two half-sized values from receiver `0x48390c` fields +0x660/+0x664; clear 0x280 bytes starting at this+0x338 and selected state fields. |
| `0x405923` | Call this-object virtual slot +8. Exact target not resolved here. |
| `0x405944` | Call thunk `0x46146c` through IAT `0x47503c`, independently resolved as DINPUT.dll!DirectInputCreateA. Arguments: instance at `0x48402c`, version 0x500, output this+0x5cc, NULL. Any nonzero result returns -3. |
| `0x405957`, `0x405962` | Call `0x406930`, then `0x406a50`; a nonzero helper status propagates and skips subsequent initialization. |
| `0x40597a` | Root interface slot +0x10 with arguments 4, callback `0x406bf0`, this, 1. Any nonzero result returns -3. Enumeration-like role is inferred from callback behavior. |
| `0x405999`, `0x4059a5`, `0x4059a9` | SystemParametersInfoA actions 3 and 0x70, then GetSystemMetrics(0x17). Store results/state, set this+0x5b8 to 1 and return zero. The two SPI return values are not used as failure gates here. |

The function has no local rollback on the traced failure exits. This is not
proof of a resource leak: caller cleanup, later retry and object lifetime
must be traced before making that claim. Its caller's selective treatment of
-12/-10, recorded in the startup map, also prevents assuming any nonzero
return always aborts process startup.

## Device helper contracts

All numbers in the following table are hexadecimal. Virtual method names are
left as slots; no third-party interface implementation was used.

| Helper | Identifier bytes interpreted as GUID | Retained interface | Configuration arguments |
| --- | --- | --- | --- |
| `0x406930` | At `0x476c30`: `6f1d2b61-d5a0-11cf-bfc7-444553540000` | this+0xdc | Slot +0x34: HWND and flags 5; slot +0x2c: format pointer `0x462480`; slot +0x18: property 1, five dwords [14,10,0,0,40]. |
| `0x406a50` | At `0x476c20`: `6f1d2b60-d5a0-11cf-bfc7-444553540000` | this+0x1c8 | Slot +0x34: HWND and flags 5; slot +0x2c: `0x462510`; slot +0x18: property 2 with [14,10,0,0,1], then property 1 with final dword 40. |

Both first call root-interface slots +0x14 and +0xc, rejecting any nonzero
return. They then call temporary-interface slot 0 with IID at `0x476b40`
(`5944e682-c92e-11cf-bfc7-444553540000`) and an output to the retained field.
Temporary-interface slot +8 is called at `0x40699f`/`0x406ac6` **before** the
query result is checked. The query and property result tests reject any
nonzero result and return -3. The retained interface is not locally released
on a later property failure in these slices.

Configuration calls at `0x4069c0`/`0x406aea` (+0x34) and
`0x4069cd`/`0x406af7` (+0x2c) have **unchecked** results. Property calls at
`0x406a04`, `0x406b2e` and `0x406b57` are checked. The first helper copies a
keyboard label and sets state bits; keyboard/mouse roles are reasonable working
labels, but GUID symbolic names, structure types and full interface contracts
are not established solely by this report.

## Enumerated-device path is different

Callback `0x406bf0` returns 1 unless descriptor byte +0x24 equals 4; for that
case it calls `0x406c10` at `0x406bff` and returns that helper's result.

`0x406c10` uses the descriptor GUID at +4 in root-interface slot +0xc at
`0x406c4f`. A nonzero result returns 1. A slot-0 interface query at `0x406c78`
uses the same IID as above and writes this+0x2b4; temporary slot +8 is called
at `0x406c83` before checking the query result.

Here the query and property gates reject **signed-negative** results, rather
than every nonzero result. Unchecked configuration calls use flags 6 and format
pointer `0x4627f0` at `0x406ca7`/`0x406cb4`. Checked property calls are at
`0x406cdf` (property 2, final value 0) and `0x406d08` (property 1, final value
0x40). A later slot +0xc call at `0x406d2f` conditionally contributes capability
bit 8 to state bit 4; the successful tail ORs 0xb and returns zero.

Failure/skip returns 1 and success returns zero, consistent with continuing
versus stopping enumeration. This interpretation does not establish which
device is chosen on a real machine. No local retained-pointer rollback appears
on the later failure branches; repetition/ownership consequences remain open.

## Cleanup and activation boundary

The separately observed cleanup helper `0x4059f0` clears this+0x5b8, walks
three fields (this+0xdc, +0x1c8, +0x2b4), invokes interface slot +8 for each
nonnull pointer and clears it. It then does the same for root this+0x5cc.
Calls at `0x405a47`/`0x405a4f` invoke ShowCursor(1) until its result is
nonnegative. No explicit device-unacquire call appears in this helper.
The route from the application's teardown to this exact helper is not yet
resolved; identifying matching fields alone is insufficient proof of dispatch.

[Window activation](window-lifetime-2026-10-23.md) reaches `0x406d80`, which
clears input state through object virtual calls on a zero argument but only
stores +0x5b8 on a nonzero argument. Acquisition, polling, and release must
therefore remain separate questions until the object's vtable is identified.

## Assessment and portable implications

High confidence: direct imported function identity, field offsets, argument
constants, callback tests and the difference between nonzero and signed-negative
failure gates, corroborated across Ghidra and raw disassembly. Medium confidence:
device roles and enumeration semantics. Unknown: exact virtual interface types,
actual runtime device availability, failure recovery, input mapping and polling.

For a portable `platform` implementation, interface ownership, partial-failure
cleanup, activation state and device enumeration should be explicit boundaries.
Future synthetic tests could inject failures at each setup step and distinguish
positive status from negative failure. These are design considerations, not
authorization to implement speculative original contracts.
The subsequent [activation/polling follow-up](input-activation-poll-boundary-2026-10-23.md)
resolves the constructor-installed vtable, a destructor callback candidate,
and the +0x5b8 polling gate. Invocation of that callback from process shutdown
and complete device behavior still require investigation.
