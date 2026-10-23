# Individual sending and the external transport boundary

## Scope and method

Date: 2026-10-23. Static US retail Drakan.exe, SHA-256
`23630f48e20e8a9f42026501165ae1df407cfcee545a784ec930a4c25ee70648`,
reverified before analysis. No original program was executed or traffic sent.
Ghidra 12.1.4/OpenJDK 25.0.4.1 processed existing private functions sequentially
with `-readOnly -noanalysis`. Independent GNU objdump 2.42 and raw PE/import
checks verified dispatch arguments, byte writes, GUIDs and return handling.
Confidence is high in this boundary; actual delivery remains unobserved.

This extends [sender construction and fan-out](input-sender-boundary-2026-10-23.md).
Let S be that sender object and M=S[+0x46] its transport-manager object.
The reports keep raw interface identity and slot numbers rather than assigning
API names based solely on a familiar layout.

## Interface creation

Constructor `0x450330` clears M[+0x7c] at `0x450390`. Helper
`0x450a20..0x450a5c` returns zero if that field is already nonnull. Otherwise,
PE-import-resolved CoCreateInstance at `0x450a3a` receives:

| Argument | Observed value |
| --- | --- |
| CLSID, bytes at 0x476de0 | `d1eb6d20-8923-11d0-9d97-00a0c90a43cb` |
| Outer object | NULL |
| Context | 1 |
| IID, bytes at 0x476dd0 | `0ab1c531-4745-11d1-a7a1-0000f803abfc` |
| Output | Address of M[+0x7c] |

On a signed-negative creation result with nonnull output, the helper calls
that interface's slot +8 at `0x450a4f`, then clears the field. It returns the
creation result. This proves how the interface pointer is obtained; it does
not identify the runtime provider, selected medium or successful initialization.

## Individual-target path

The earlier -2 fan-out helper reenters sender `0x456a80` with identifiers
from its array. For an identifier taking the ordinary individual path:

- Earlier lookup/accounting calls at 0x456b41 and 0x456b5e/0x456b67 precede
  sending; the call at 0x456b55 is conditional on earlier lookup checks.
  Their effects remain outside this slice.
- Flags -1 select S[+0x10] at `0x456b75`; flags -2 select S[+0x14] at
  `0x456b7f`. Other flags retain their supplied value.
- If flag mask 0x200 is set, mask 0x400 is added at `0x456b87`.
- `0x456b99` calls `0x4508d0`, receiver M, with arguments
  `(M[+0x70], identifier, transformed_flags, payload, length)`.

Special identifiers take other branches; the -2 case has its separate fan-out
gate. No assumption that all array identifiers are ordinary is made here.
The first post-call check compares EAX with 0x8000000a at `0x456b9e`; complete
sender error semantics and all special cases are not claimed.

## Observed payload mutation and dispatch

Function `0x4508d0..0x450925` uses an ECX receiver and five stack arguments,
here named `(arg1,arg2,flags,payload,length)`. It returns with `ret 0x14`.

1. Write the current receiver dword +0x18 to unaligned payload +1 at
   `0x4508da`, then increment receiver +0x18 at `0x4508dd..0x4508e5`.
2. Read payload byte +5. Set its bit 0 if `flags&1` is nonzero; otherwise
   clear bit 0. Store at `0x450905`, **preserving the upper seven bits**.
3. Load interface receiver[+0x7c], then call its slot +0xc4 at `0x45091a`
   with stack arguments `(interface,arg1,arg2,flags,payload,length,0,0,0,0)`.
4. Return with **EAX unchanged** from that interface call. Ghidra's inferred
   `void` label is not the machine-level return contract.

There is no local payload-length guard, payload/interface null check, copy,
retry or result test. Mutation and counter advance happen before dispatch,
regardless of the interface's eventual result. The wrapper does not prove
synchronous consumption, buffer lifetime beyond the call, or delivery.

If the [0x28 producer's buffer](input-clear-producer-2026-10-23.md) reaches
this wrapper, bytes 1..4 are supplied here, and bit 0 of byte 5 is determined
by flags. **Byte 5's upper seven bits remain unestablished** by these paths.
The producer's known writes at byte 0 and bytes 6..9 therefore do not alone,
or with this wrapper, prove a fully initialized ten-byte payload.

## Link to the receiving side

The [receive queue report](receive-queue-2026-10-23.md) establishes count and
receive calls through the same manager's interface field, and insertion into
the queue consumed by 0x451610. This brackets the external transport boundary;
it does not prove that a particular sent message returns to this process or
arrives unchanged at a particular peer. Provider behavior and wire format are
outside the executable paths examined here.

## Reproduction

Use the pinned environment and support script from
[lifecycle reproduction](lifecycle-reproduction-2026-10-23.md), verify the hash,
and keep outputs private:

```sh
sha256sum "$DR_EXE"
objdump -d -Mintel --start-address=0x450330 --stop-address=0x4503e2 "$DR_EXE"
objdump -d -Mintel --start-address=0x450a20 --stop-address=0x450a5d "$DR_EXE"
objdump -s --start-address=0x476dd0 --stop-address=0x476df0 "$DR_EXE"
objdump -d -Mintel --start-address=0x456b2f --stop-address=0x456ba3 "$DR_EXE"
objdump -d -Mintel --start-address=0x4508d0 --stop-address=0x450926 "$DR_EXE"
objdump -p "$DR_EXE"
```

Decode GUIDs using little-endian first dword/two words and the eight trailing
bytes in order. CoCreateInstance is IAT 0x475368. Ghidra queries included
`InspectWindowLifecycle.java 0x4508d0`, `0x450330`, and `0x450a20`, all successful
in the existing read-only EXE project. These claims rely on input bytes and
imports, not an external implementation or an assumed transport API name.
