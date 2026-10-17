# Level selector `(1,0,0)` prefix

**Date:** 2026-10-17. **Input:** unpatched US retail `Drakan.exe`,
SHA-256 `23630f48e20e8a9f42026501165ae1df407cfcee545a784ec930a4c25ee70648`;
installed-US level files are checked against their individual hashes in the
private asset inventory. **Method:** GNU objdump 2.45.1 bounded disassembly,
and Python 3.14.7 measurement of bytes. No Ghidra project was accessed for
this investigation. **Confidence:** high for the stated instructions and
sample measurements, limited to this path and the inventoried files.

## Observed

- The level-loading path calls `0x00421c30` with the resource object after
  processing the database list; see [the earlier trace](level-directory-behavior.md).
  At `0x00421c43`–`0x00421c5b`, this function selects `(1,0,0)` and reads
  a four-byte outer count. The loop at `0x00421d34`–`0x004220cc` uses a
  signed positive comparison, and each iteration populates a 168-byte runtime
  object. This size is an in-memory stride, not a file record size.
- On its successful path each iteration reads seven four-byte values, a
  two-byte-length-prefixed byte sequence via `0x0045f430`, six more four-byte
  values, then a four-byte inner count and `count * 4` bytes via `0x0045f2d0`.
  The four-byte helper `0x0045f370` requests exactly four bytes. The reader
  skips the length-prefixed bytes with a null buffer; their meaning and encoding
  are unknown. The call at `0x00421d9e` allocates based on two of the first
  values and may take an error path before the rest is read.
- On this path the inner dwords are copied into 16-bit runtime entries
  (`0x00422088`–`0x004220a6`); a subsequent loop uses these entries as indices
  into the runtime object array (`0x00422145`–`0x0042215d`). This does not
  establish valid indices for arbitrary files, or their broader meaning.
- After the first loop the function reads another dword at `0x004221f7` and
  enters further per-object processing. The prefix scan leaves that data opaque;
  subsequent investigation is recorded in [the block trace](level-0001-blocks.md).

## Measured samples

The script below verifies the inventory hash and SRSC table bounds and selects
exactly one `(1,0,0)` record in each candidate `.lvl`. It parses the successful
path prefix only, with measurement limits of 4,096 for either count. All
**23/23** files passed: 4,445 outer entries, 1–941 per file, and 207,353 inner
dwords, 1–162 per entry. None of these dwords was at least its file's outer
count or exceeded 65,535. Skipped byte-sequence lengths ranged from 2 to 32;
opaque trailing data ranged from 59 to 389,404 bytes per record. These are
sample observations, not format constraints, and the script does not verify
the trailing data or simulate allocations, errors, or runtime behavior.

## Unknown and reproduction

The names and meanings of the fields, their coordinate or rendering role,
other versions, and actual level geometry remain unresolved. Later findings
and bounded block inspection are documented in [the block trace](level-0001-blocks.md).
Original read return values on this path are not
uniformly checked; the measurement script independently checks bounds.

```sh
sha256sum research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x421c30 --stop-address=0x422350 research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x4226c0 --stop-address=0x422756 research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x45f2d0 --stop-address=0x45f4c3 research/binaries/us/Drakan.exe
python3 tools/research/measure_level_0001.py research/installed/us research/exports/asset-inventory/us.json
python3 -m unittest discover -s tools/research -p test_measure_level_0001.py -v
```
