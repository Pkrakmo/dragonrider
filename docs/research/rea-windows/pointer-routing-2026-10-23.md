# Retail pointer routing and selection boundaries

## Scope and method

Date: 2026-10-23. Observed static behavior in US retail Dragon.rfl,
SHA-256 `9b6496b65e962cf35dd1e18f424f2c8af08ceade78331dcc0b6da332ce844ac3`.
The supporting EXE query uses Drakan.exe SHA-256
`23630f48e20e8a9f42026501165ae1df407cfcee545a784ec930a4c25ee70648`.
Both hashes were reverified. No original program was executed.

Ghidra 12.1.4/OpenJDK 25.0.4.1 processed existing private projects sequentially
with `-readOnly -noanalysis`. GNU objdump 2.42 supplied an independent raw
check of both RFL functions; the coordinator checked the EXE query against
its actual instructions and table bytes. All three Ghidra queries completed.
The RFL functions were already defined; EXE `0x4066c0` required explicit
recovery. Confidence is high in these bounded paths, not in widget semantics.

This extends [the pointer callback boundary](input-pointer-callback-2026-10-23.md).
Both RFL helpers use ECX receiver plus three stack arguments `(mask,x,y)` and
return with `ret 0xc`. Field names below describe observations, not source types.

## Common geometry and child scan

Receiver rectangle fields are signed dwords at +0x18/+0x1c (left/top), with
sizes +0x20/+0x24. The initial check accepts `left <= x < left+width` and
`top <= y < top+height`. Children form a list starting at receiver +0x38,
with next pointer at child +4; first matching child wins. Candidate dwords
+0x28 and +0x2c must both be nonzero.

Child geometry uses signed **16-bit** fields at +0x18/+0x1a/+0x1c/+0x1e.
It accepts `left <= x < left+width` but **`top < y < top+height`**.
Top equality is rejected at `0x101287bc` and `0x101288e3`.
These mixed widths and endpoint rules are observed; positivity, valid ranges
and overflow-free additions are not established.

## Mask-driven dispatch: `0x10128710..0x10128841`

| Condition | Observed action |
| --- | --- |
| `mask & 0x01` is zero | Read global `0x1017b484`. If null, return 0; otherwise clear that global at `0x10128731`, call the saved object's virtual slot +0x10(mask,x,y) at `0x10128744`, and return 1. This precedes geometry tests. |
| `mask & 0x01` is nonzero, receiver contains coordinates | Scan eligible children using the geometry above. No match returns 0. |
| `mask & 0x01` is nonzero, receiver does not contain coordinates | If receiver +0x10 is nonnull and `(receiver[+0x44] & 6)==2`, recursively invoke this helper on that pointer at `0x10128834`. Discard its return; return 0. |

On a child match, if receiver +0x3c is nonnull and different, notify the
**receiver's** virtual slot +0x10(previous,0x0b) at `0x101287ea`.
When the pre-notification +0x3c was nonnull, reload +0x3c and clear bit
0x40 in its unaligned dword field +0x12. An initially null pointer skips
that clear.
There is no new null test after the notification. Store the matching child
in receiver +0x3c, set its bit 0x40, store it in global `0x1017b484`, call its
slot +0x10(mask,x,y) at `0x10128811`, and return 1. If the old pointer was
already the matching child, the bit clear/set and dispatch still occur.

This is consistent with a press/release target and selected-child state,
but those semantic names are inferred. Global storage is not per receiver;
concurrent/reentrant behavior is not proven safe. Clearing the global before
dispatch is an observed ordering requirement.

## Coordinate routing: `0x10128850..0x101289ba`

If receiver +0x40 is nonnull, invoke that object's slot +0x14(mask,x,y) at
`0x1012886e` before doing hit tests. Then call the host input interface
slot +0x48 with argument 0x100 at `0x10128883`; nonzero returns 1 immediately.
The [EXE/RFL bridge](input-callback-binding-2026-10-23.md) supplies this interface.

After that gate, scan the receiver and children as above:

- Matching child already equals +0x40: return 1 without another child call.
- A different matching child: call its slot +0x14 at `0x1012896d`. If its
  unaligned dword +0x12 has bit 0x400, notify receiver slot +0x10(child,0x12)
  at `0x10128983`. Otherwise, if the current +0x40 child has bit 0x400,
  notify receiver slot +0x10(NULL,0x12) at `0x101289a9`. Store the match to
  +0x40 and return 1. Checks after callbacks observe current memory.
- No match or outside: if current +0x40 has bit 0x400, issue the NULL/0x12
  notification at `0x1012890d`; then clear +0x40 at `0x10128913`.

The no-match path may recursively forward to receiver +0x10 if nonnull and
`(receiver[+0x44]&6)==2`. Its outside test differs: it forwards only for
`x<left || x>left+width || y<top || y>top+height`. Exact right/bottom equality
can therefore fail the initial selection test **without** forwarding.
The recursive call at `0x1012894f` has its result discarded; caller returns 0.
Virtual-call return values likewise do not control the documented results.

## Host query gate

EXE table `0x47539c` slot +0x48 contains `0x4066c0` (raw pointer at
`0x4753e4`). Its bounded body `0x4066c0..0x406749` accepts unsigned codes
0x100..0x10f and tests bit `code-0x100` in receiver +0x1c4. When +0x28 is
nonzero and mode +0x5bc is zero, it swaps codes 0x100 and 0x101 before that
test. Thus this RFL query can test either bit 0 or bit 1, depending on mode
and the swap setting; it is not an unconditional physical-button identity.

Codes 0x120..0x12f similarly test bit `code-0x120` in +0x2b0; all others
return 0. Results are normalized 0/1. This query's accepted range is narrower
than the event consumer's 0x120..0x13f update range. The raw instruction at
`0x4066fa` assigns 0x100 in the swap path; a decompiler may simplify this to
zero when folding a masked shift, so source-like constants are not proof of
the intermediate register value.

## Implications and remaining questions

Separate coordinate hit-testing, current target, global press/release target,
receiver notifications and optional forwarding. A return value of 0 does not
mean no event was delivered: recursive paths may deliver and still return 0.
Callback mutation and the second receiver reload in the caller also matter.

Ownership/lifetime of +0x3c/+0x40, actual child virtual targets, meaning of
notifications 0x0b/0x12, and recursion termination remain unknown. No exact
UI class, thread model or complete portable implementation is established.

## Reproduction

Verify both hashes first. Keep raw outputs private. Use the pinned environment
and scripts from [the binding report](input-callback-binding-2026-10-23.md).

```sh
sha256sum "$DR_RFL" "$DR_EXE"
objdump -d -Mintel --start-address=0x10128710 --stop-address=0x10128842 "$DR_RFL"
objdump -d -Mintel --start-address=0x10128850 --stop-address=0x101289bb "$DR_RFL"
objdump -s --start-address=0x4753e4 --stop-address=0x4753e8 "$DR_EXE"
objdump -d -Mintel --start-address=0x4066c0 --stop-address=0x40674a "$DR_EXE"
```

Ghidra RFL query: `InspectPinnedRetailFunctions.java 0x10128850 0x10128710`.
Separate EXE query: `InspectWindowLifecycle.java 0x4066c0`. Use each existing
project's proper program name, `-readOnly -noanalysis`, and serialize access.
The raw RFL cross-check initially covered through 0x10128a00; conclusions
above stop at the verified function return boundaries.
