# Loader/startup reproducibility addendum

Companion script: [PE metadata probe](support/pe_metadata_probe.py).

Date: 2026-10-23. Documentation-only follow-up to the 2026-10-22 loader
benchmark and startup map. Reviewed source reports at
`origin/research/rea-windows` commit
`968dd505b3c7cc6ccb151b1a216390c29c74eee5`.

## What was checked when

**Observed on 2026-10-22:** a separate agent, without Ghidra access, parsed the
same canonical PE with an ad hoc inline Python standard-library script
(`struct`/`pathlib`) and inspected bounded GNU objdump Intel-syntax
disassembly. That parser was not pefile or a versioned third-party PE package;
no standalone parser version was recorded. GNU objdump was Ubuntu Binutils
2.42. Do not attribute today's versioned script to that historical run.

The independent checker mapped raw-backed section RVAs to file offsets,
decoded import descriptors and lookup thunks, and associated IAT slots with
import names or unresolved ordinals. This let it check indirect imported calls
without trusting Ghidra's names. It compared the 12-byte header request/returned
length, signature, version 0x0100, and count*14 table length in the loader.
For startup it checked entry argument setup/call, application/message-loop
calls, window-class callback and window creation against raw instructions.
This was corroboration by a separate tool path on the same input, not independent
runtime execution or a check of every descendant in the startup report.

**Observed on 2026-10-23 at 07:12:28 UTC:** the attached
metadata probe version 1 was run inside the Ubuntu VM against the private
original. The script was supplied through standard input without creating a
guest script file; the executable was read from its private VM path.
It rechecked the hash, PE headers, sections and import inventory; it queried the
installed objdump version but did **not** rerun instruction disassembly or Ghidra.
The metadata agrees with the existing reports. No game, installer or original DLL
was executed. No original bytes or bulk tool output were copied into this draft.

Today's tool versions: Python **3.12.3**, GNU objdump (GNU Binutils for Ubuntu)
**2.42**. The Fedora maintainer audit's **2.45.1-5.fc43** is a separate run and
must not be substituted for the contributor's Ubuntu version.

## Reproduced metadata

- SHA-256: `23630f48e20e8a9f42026501165ae1df407cfcee545a784ec930a4c25ee70648`.
- Size: 552,960 bytes; PE32 machine 0x014c; four sections.
- Image base 0x00400000; entry RVA 0x68e20; entry VA 0x00468e20.
- Import descriptors: 13; thunk entries: 207 (182 named, 25 ordinal).
  Counts are entries, not unique functions, dynamically loaded APIs, or calls
  proven to occur at startup.

| DLL | Entries | Named | Ordinal |
| --- | ---: | ---: | ---: |
| DSOUND.dll | 2 | 0 | 2 |
| DINPUT.dll | 1 | 1 | 0 |
| DDRAW.dll | 2 | 2 | 0 |
| COMCTL32.dll | 3 | 2 | 1 |
| KERNEL32.dll | 104 | 104 | 0 |
| USER32.dll | 55 | 55 | 0 |
| GDI32.dll | 4 | 4 | 0 |
| comdlg32.dll | 2 | 2 | 0 |
| ADVAPI32.dll | 7 | 7 | 0 |
| ole32.dll | 3 | 3 | 0 |
| MPR.dll | 1 | 1 | 0 |
| WS2_32.dll | 22 | 0 | 22 |
| WINMM.dll | 1 | 1 | 0 |

## Exact reproducible procedure

From the repository root,
set `DR_EXE` to the private executable path; do not commit that path
or output. Run inside the analysis VM:

```sh
python3 --version
objdump --version
python3 docs/research/rea-windows/support/pe_metadata_probe.py "$DR_EXE"
```

The script version is 1; SHA-256 of the supplied file:
`2eba125063b5d73adfeeeeb54bcf2df0e14fedd526dc0fac78e1cbe5a2cd7501`.
It uses only Python's standard library. It rejects a noncanonical hash before
PE parsing, accepts PE32 only, reads headers via e_lfanew, reads the import
directory at optional-header offset 104, iterates 20-byte descriptors through
the zero terminator, and uses OriginalFirstThunk (or FirstThunk when zero).
Each 32-bit lookup entry is classified by bit 31 as ordinal or name RVA.
Named entries require a bounded terminated ASCII name after the two-byte hint.
RVA reads must map uniquely within raw-backed section ranges; file reads,
descriptor counts, thunk counts and strings are bounded. It emits only metadata
JSON, including parser/runtime/tool versions. It is a canonical-input research
utility, not a general-purpose PE validator.

Validation performed today: canonical-input execution passed with the metadata
above. A negative check called the unchanged `inspect` function with
`Path("/dev/null")` and asserted the exact empty-file SHA-256 mismatch exception;
it passed, rejecting the input before any PE parsing. No synthetic PE or altered
original was needed.

To repeat the prior **bounded disassembly method** separately, after the
script succeeds, run the following and keep output private. These are
reproduction commands, not claims that disassembly was rerun today:

```sh
objdump -s --start-address=0x47d900 --stop-address=0x47d904 "$DR_EXE"
objdump -d -Mintel --start-address=0x45edc0 --stop-address=0x45efb0 "$DR_EXE"
objdump -d -Mintel --start-address=0x468e20 --stop-address=0x468f50 "$DR_EXE"
objdump -d -Mintel --start-address=0x412010 --stop-address=0x412500 "$DR_EXE"
```

The loader's observed body ends at 0x45ef61; the historical raw window extends
past it to provide boundary context. The application window likewise includes
the start of the adjacent window procedure and does not establish its full
behavior. For exact imported targets, decode the matching FirstThunk slot from
the PE import data; an ordinal's API name remains unresolved without additional
evidence. The script deliberately prints aggregate counts rather than a bulk
symbol/IAT export. Main report addresses and interpretations remain unchanged;
today's rerun adds no new runtime or engine-semantics claim.
