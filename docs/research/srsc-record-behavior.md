# SRSC record selection and reads

**Date:** 2026-10-17. **Input:** unpatched US retail
`research/binaries/us/Drakan.exe`, SHA-256
`23630f48e20e8a9f42026501165ae1df407cfcee545a784ec930a4c25ee70648`
(verified with `sha256sum` during this investigation). **Method:** Ghidra
12.1.4 headless, existing `Drakan_US_Retail` project, `-process Drakan.exe
-readOnly -noanalysis`, bounded instruction windows and call references via
`tools/ghidra/scripts/TraceSrscRecords.java`; independently checked with GNU
`objdump` disassembly and PE imports. Private log:
`research/ghidra-logs/srsc-record-behavior/run-9K4nbbcc/`. **Confidence:**
high for these specific instructions and the relationship between the two
fields and the file operations; extrapolation to other versions is unverified.
Existing analysis and xref completeness are unknown.

## Observed

- The loader at `0x0045EDC0` stores the raw `count * 14` table read at object
  offset `0x2c`, as detailed in `riot-file-loading.md`. On the index-based
  selection path at `0x0045F270`, the code computes `table + 14 * index`.
  It passes the 32-bit value at record offset 6 to `SetFilePointer` with a
  null high-order pointer and origin zero (`FILE_BEGIN`), and compares the
  return value with that record value. After success it copies the 32-bit
  value at record offset 10 into the object at offset `0x18` and saves the
  selected index at object offset `0x0c`. The PE import table identifies
  `0x004750C4` as `SetFilePointer`.
- The method at `0x0045F2D0` checks the object mode and selected index, then
  compares the requested read size against the value at object offset `0x18`.
  A request greater than that value calls `ReadFile` for the remaining value,
  sets the remaining value to zero and returns an error. Otherwise it calls
  `ReadFile` for the requested size and subtracts either the requested number
  on an exact successful read or the returned byte count on a short/error path.
  The PE import table identifies `0x004750C8` as `ReadFile`.
- Another selection path, `0x0045F0D0`, compares three 16-bit arguments with
  the words at record offsets 0, 2 and 4 (`0x0045F18A–0x0045F1A8` on its
  linear-search branch). On a match it selects that record; at
  `0x0045F1D5–0x0045F201` it seeks using record offset 6 and initializes the
  same remaining-byte state from record offset 10. The three values therefore
  act as a lookup tuple on this path. The routine also has an alternate branch;
  this observation does not establish uniqueness, ordering or all search
  behavior.
- Retail PE32 i386 is little-endian. Consequently these instructions consume
  the four bytes at offset 6 as a little-endian 32-bit seek argument, the four
  at offset 10 as a little-endian 32-bit initial read budget, and the first six
  bytes as three little-endian 16-bit comparison values on the paths above.
  The measurements in `srsc-record-observations.md` independently found that
  offset/length interpretations partition the data region in 178 installed US
  examples; they do not establish a required layout.
- Ghidra's current database has 26 direct calls to `0x0045F0D0`, 19 to
  `0x0045F270`, and at least 40 to `0x0045F2D0` (the script caps output at 40).
  Xrefs can be incomplete, and these counts are not a full execution trace.

## Inferred and unknown

The evidence supports describing record offset 6 as a file-position field and
record offset 10 as the selected resource's byte length/read budget for these
paths. It is appropriate to validate the offset and length against file size
before exposing bytes in the independent engine; this is a safety policy, not
a claim that the original loader performs that validation. The semantic names
of the three lookup words, what the payload represents, zero-length entries,
alternate editions, and general ordering or uniqueness requirements remain
unknown. The retail measurements already include duplicate complete six-byte
tuples. Do not impose contiguity, nonzero payload length, ordering, uniqueness,
or table-at-EOF conditions solely from the scanned samples. `SetFilePointer`
has a signed low-order distance argument when its high-order pointer is null;
this static trace alone does not settle practical support for offsets at or
above 2 GiB.

## Reproduction

Close any Ghidra GUI using this project and run in a dedicated shell. A process
listing cannot prove GUI closure; the lock below is cooperative among wrapper-based runs. List the
project and verify the input before invoking headless:

```bash
find research/ghidra-projects -maxdepth 1 -name '*.gpr' -print
sha256sum research/binaries/us/Drakan.exe
exec 9>research/ghidra-projects/.drakan-loader-probe.lock
flock -n 9 || exit 1
mkdir -p research/ghidra-logs/srsc-record-behavior
run=$(mktemp -d "$PWD/research/ghidra-logs/srsc-record-behavior/run-XXXXXXXX")
mkdir -p "$run/config" "$run/cache"
export XDG_CONFIG_HOME="$run/config" XDG_CACHE_HOME="$run/cache"
"$GHIDRA_HOME/support/analyzeHeadless" \
  "$PWD/research/ghidra-projects" Drakan_US_Retail -process Drakan.exe \
  -readOnly -noanalysis -scriptPath "$PWD/tools/ghidra/scripts" \
  -postScript TraceSrscRecords.java -log "$run/ghidra.log" \
  -scriptlog "$run/script.log" > "$run/console.log" 2>&1
exec 9>&-
```

The script limits each instruction window and caller list; its output and all
binary inputs remain private. The independent import and instruction checks
were run with:

```bash
objdump -p research/binaries/us/Drakan.exe | rg 'SetFilePointer|ReadFile|WriteFile'
objdump -d -Mintel --start-address=0x45eec2 --stop-address=0x45ef10 research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x45f0d0 --stop-address=0x45f228 research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x45f270 --stop-address=0x45f36e research/binaries/us/Drakan.exe
```
