# Producer of the 0x28 callback-clear payload

## Scope and evidence

Date: 2026-10-23. Static US retail Dragon.rfl, SHA-256
`9b6496b65e962cf35dd1e18f424f2c8af08ceade78331dcc0b6da332ce844ac3`,
reverified before analysis. No original program was executed. Ghidra
12.1.4/OpenJDK 25.0.4.1 processed the existing private RFL project with
`-readOnly -noanalysis`; query `0x101516b0` completed successfully. An
independent GNU objdump 2.42/raw PE check verified selector tables, register
values, stack offsets and the emission boundary. Confidence is high in this
local producer path, not in delivery or upstream action meaning.

This extends [the clear dispatch report](input-clear-dispatch-2026-10-23.md).
A filtered linear disassembly scan found a literal byte write of 0x28 at
`0x10152069`. This is a discovered producer, not proof of a unique producer:
computed writes, copied data and indirect paths are not covered by that scan.

## Observed selectors and local clearing

Existing function `0x101516b0..0x101521a1` reads its first stack argument as
a selector. At `0x101516dc`, it subtracts 7 and accepts unsigned indices
0..0x1d. Byte table `0x101521e8` maps selectors **0x12 and 0x14** to index
0x0a; target table `0x101521a4` entry 0x0a contains `0x10152015`.

EBX is zeroed at `0x101516d6` on this direct dispatch path. Another selector
branch changes it, but that instruction is not on the two paths above.
Assuming earlier calls return and preserve their expected ABI:

1. `0x10152017` calls `0x10024680(1)`.
2. Store `[0x1017ae6c]!=0` into global `0x1017aa44` at `0x10152037`.
3. `0x1015203d` calls `0x10129650`, ECX receiver `0x1017ae08`, stack
   arguments `(0x18,0,1,1)`.
4. `0x10152043` calls **`0x1000e900(0)`** using zero EBX. This resolves the
   formerly unknown argument at this site in the shutdown report.
5. ESI becomes the first dword addressed by the second stack argument if that
   argument is nonnull, otherwise zero (`0x10152052..0x10152058`).
6. `0x1015205c` calls `0x1014b8e0(ESI)`.

The binding report establishes the helper's callback-clearing operations,
conditional on its own preceding calls returning. Clearing is local and
**precedes payload emission** in this branch; it does not depend on proving
that another recipient subsequently receives the payload.

## Observed payload and emission boundary

The branch then prepares a stack payload:

| Offset | Proven write |
| --- | --- |
| +0 | Byte 0x28 at `0x10152069` |
| +6..+9 | Unaligned dword ESI at `0x1015206e` |
| +1..+5 | Initialization/content not established on the traced direct path |

At `0x10152085`, it invokes the object from host-state field +0x1ac, virtual
slot +0x60, with stack arguments **`(-2, payload_pointer, 10, -1)`**.
The pointer refers to the same stack bytes despite intervening pushes. Do not
infer a completely initialized ten-byte message or assign names to the two
negative arguments. No local receiver-null guard or delivery-result check is
present in this emission slice.

This matches the downstream consumer's read of payload byte 0 and dword +6.
The [EXE caller bridge](input-clear-dispatch-2026-10-23.md) separately accepts
eligible active records containing byte 0x28. However, the host +0x60 method,
its transport/copy behavior, and insertion into those records have not yet
been linked. A matching payload layout is not proof of actual end-to-end
delivery or network origin.

After the emission call returns, the function continues selector-specific
work through `0x10012ae0`; this is not the whole function's teardown or return
boundary. Callers that supply selectors 0x12/0x14 and the meaning/lifetime of
the second argument remain unknown. No shutdown linkage is established.

## Reproduction

Verify the input hash, retain raw output privately, and use the environment
and hash-gated script in [callback binding](input-callback-binding-2026-10-23.md).

```sh
sha256sum "$DR_RFL"
objdump -d -Mintel --start-address=0x101516b0 --stop-address=0x101516f7 "$DR_RFL"
objdump -s --start-address=0x101521a4 --stop-address=0x10152206 "$DR_RFL"
objdump -d -Mintel --start-address=0x10152015 --stop-address=0x101520e8 "$DR_RFL"
```

For selectors 0x12/0x14, decode byte entries at `0x101521f3`/`0x101521f5`
and the little-endian dword at `0x101521cc`. Track pushes when comparing
payload offsets. Ghidra query: `InspectPinnedRetailFunctions.java 0x101516b0`
with `-process Dragon.rfl -readOnly -noanalysis`. This function was already
defined; no ownership was guessed. Only the selected branches were independently
cross-checked, not the entire large function or other selector semantics.
