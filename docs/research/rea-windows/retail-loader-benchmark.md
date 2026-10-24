# Independent retail loader benchmark

## Scope and provenance

- Date: 2026-10-22; contributor: isolated Ubuntu VM research assistant.
- Status: **Observed static benchmark passed**. No game process was executed.
- Question: does the canonical retail loader open an SRSC resource, read a
  12-byte header, require version 0x0100, and read 14-byte table entries?
- Input: user-supplied US retail CD archive; original files remain outside Git.
- ZIP SHA-256: `27fc386f88127df3dd23248267fcdcb3090046222e947d66a971d735663875f2`.
- Extracted Mode-1 ISO SHA-256:
  `256a4e51020b06c551cc310895e245f1df8790be0af230711a727ecbf29d079c`.
- Executable SHA-256:
  `23630f48e20e8a9f42026501165ae1df407cfcee545a784ec930a4c25ee70648`.
- Canonical-reference match: **yes**, independently calculated in the VM.
- Executable: 552,960 bytes, PE32 i386, four sections, preferred image base
  `0x00400000`; header entry RVA `0x68e20`, VA `0x00468e20`.

## Method

Python's ZIP reader extracted only the exactly named Track 1 and CUE members
to a fresh private directory. The reviewed repository Mode-1 converter produced
a fresh ISO; xorriso extracted only `/Setup/data1.cab`. Unshield selected only
`Drakan.exe`; no setup executable or driver installer was run. The extracted
executable was made non-writable before analysis.

REA 6.7.0 / Ghidra 12.1.4 / OpenJDK 25.0.4.1 ran in the Ubuntu 24.04.5 VM
described in [the toolchain report](ubuntu-toolchain-validation.md).
A hash-gated, agent-initiated stdio MCP client made these requests:

1. `open_binary` with the absolute private executable path and `provider_id=ghidra`.
2. `binary_overview` (fresh Ghidra import/analysis, 36.47 seconds in this run).
3. `read_bytes` at `0x47d900`, length 4.
4. `analyze_function` and `procedure_assembly` for `0x45edc0`.
5. `close_binary`.

All calls succeeded. A separate agent, without Ghidra access, independently
parsed the PE headers/imports and checked a bounded `objdump -d -Mintel` window.
Raw binary data and provider outputs remain private; the table below is an
independently written summary, not copied implementation code.

## Address-indexed evidence

| Observation | Instruction/data address | Result |
| --- | --- | --- |
| Object/state base comes from ECX | `0x45edc8` | ESI receives ECX; exact source-level calling convention remains provisional |
| File path and open | `0x45edd8`, `0x45edf9` | Path at state +0x30 passed to imported CreateFileA; read access and open-existing disposition |
| Store handle | `0x45ee02` | Handle stored at state +0x1c |
| Header read | `0x45ee1f`–`0x45ee27` | ReadFile targets state +0x20 with requested length 12 |
| Header length validation | `0x45ee29`–`0x45ee36` | Requires successful call and exactly 12 returned bytes |
| Signature | `0x47d900` | Ghidra and raw PE offset `0x7d900` both give `53 52 53 43` (SRSC) |
| Signature comparison | `0x45ee3c`–`0x45ee4e` | Four-byte comparison against the signature; mismatch branches to failure |
| Version | `0x45ee54` | Word at state +0x24 (header +4) compared to 0x0100 |
| Table offset | `0x45ee65`–`0x45ee73` | Dword at state +0x26 (header +6) passed to SetFilePointer; result compared to requested offset |
| Record count | `0x45ee79`–`0x45ee84` | Zero-extended word at state +0x2a (header +10); zero rejected; stored at state +0x10 |
| Allocation length | `0x45ee8a`–`0x45ee9f` | `(count*8-count)*2`, i.e. count*14, passed through GlobalAlloc/GlobalLock |
| Table read | `0x45eecc`–`0x45eedd` | Same count*14 length passed to ReadFile |
| Table length validation | `0x45eee3`–`0x45eef7` | Requires exactly count*14 returned bytes |
| Success state | `0x45eef9`–`0x45ef15` | State +4 = 0, state +0 = 1, state +0xc = -1; return 0 |

The function's observed Ghidra body is `0x45edc0` through `0x45ef61`, inclusive
(418 bytes). Failure branches return -3 for open failure, -8 for signature,
version or zero-count rejection, -11 for the checked allocation/lock failure,
and -2 on the other traced read/seek failures. These are observed numeric return
values, not established public error names. Table-read failure includes handle
conversion, unlock/free, and file closure; runtime error behavior was not tested.

## Call relationships

The fresh Ghidra analysis reports seven containing caller functions:
`0x40bb40`, `0x40bcf0`, `0x40bf30`, `0x41e470`, `0x42aef0`, `0x436eb0`,
and `0x437960`. This is the observed database result, not an exhaustive graph.

Resolved calls include CreateFileA, ReadFile, SetFilePointer, CloseHandle,
GlobalAlloc, GlobalLock, GlobalHandle, GlobalUnlock, GlobalFree, and the
comparison helper at `0x4678a0` identified by Ghidra as `_strncmp`.
The disassembly shows 14 call instructions, including repeated cleanup and
register-indirect calls; this is different from a count of unique callees.

## Assessment and limits

Confidence is high for the signature, header layout, version check, count
arithmetic, and selected control-flow observations: the Ghidra results agree
with independently decoded PE bytes and disassembly. No discrepancy was found
in the four benchmark expectations. This independently validates the benchmark;
it does not discover a new format beyond the maintainer's earlier research.

The decompiler labels the function `__fastcall`, while machine code establishes
only an ECX-carried state pointer in this slice; C++ class identity and precise
calling convention require caller analysis. The 14-byte entries' semantic
fields, logical asset resolution, runtime loading and compatibility with other
editions are not established here. No external Windows DLL implementation was
loaded or run. Analysis completeness, indirect dispatch and function recovery
are not guaranteed by a successful import.

Next bounded action: map the PE entry point `0x468e20` through its first
application-level entry, then identify startup and shutdown calls. Preserve
unknown names rather than assigning subsystem semantics from import presence.

## Reproduction

Use the exact input SHA-256 above. Parse the PE section table to map VAs to raw
offsets; compare four bytes at raw offset `0x7d900`. A bounded independent check:

```sh
sha256sum "$DR_EXE"
objdump -d -Mintel --start-address=0x45edc0 --stop-address=0x45ef62 "$DR_EXE"
```

Repeat the listed MCP requests with the pinned toolchain, then compare the
address-indexed facts. Keep output private. No OpenDrakan format documentation,
community patch sources, proprietary code publication, or GitHub push was used.

## Reproduction follow-up, 2026-10-23

See the [reproduction audit](reproduction-audit-2026-10-23.md) for exact
Ubuntu tool versions, the independent raw-check method, a versioned PE probe,
and commands. Original observations above are preserved as historical evidence.
