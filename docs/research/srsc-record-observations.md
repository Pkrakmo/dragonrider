# SRSC record measurements

**Date:** 2026-10-17. **Source:** unpatched US retail extraction at
`research/installed/us`; files and generated per-file metadata remain private.
**Method:** raw-byte measurements with Python 3.14.7 using
`tools/research/analyze_srsc_records.py`; no Ghidra database was accessed.
**Confidence:** high for the measured arithmetic on this particular extraction;
low for any broader format rule or interpretation. The extraction has not been
proved complete or unmodified. The private JSON contains each examined file's
path and SHA-256, allowing the inputs to be identified precisely.

## Observed

The script selects regular non-symlink files with a 12-byte `SRSC` header,
version `0x0100`, nonzero count and table fitting the file, with a table start
at least 12 bytes in. It does not include other files or claim to validate SRSC.
It measured 178 such files, and skipped no matching complete headers for these
bounds. These contain 38,926 records, interpreting each as 14 bytes.

For each record, interpreting bytes 6–9 and 10–13 as little-endian unsigned
32-bit integers `a` and `b` respectively:

- All 38,926 satisfy `12 <= a <= a + b <= table offset`; none has `b == 0`.
- In all 178 files, the first record has `a == 12`, the last has
  `a + b == table offset`, and the table ends at EOF.
- All 38,748 adjacent pairs satisfy `a[i] + b[i] == a[i+1]` in table order.
  Thus these candidate ranges partition the bytes between header and table in
  each scanned file, without gaps or overlaps.
- Reading the first 2 bytes and next 4 bytes as a pair gives three repeated
  occurrences beyond the first within the same file: one in `Dragon.rrc` and
  two in `Rift Crystal.ssd`. Therefore treating that pair as a unique key
  would not hold even for this sample.

For a bounded, independently identifiable example, `Dragon.rrc`, SHA-256
`fb1e403bd33b370cc64fe1ac296b3cf889e524ff2279eca2a27b65911f0ca72a`,
has table offset 3,689,295 and count 559. Its first record is
`40 00 00 11 00 00 0c 00 00 00 01 03 00 00`: `a = 12`, `b = 769`.
The second has `a = 781`, `b = 67410`; 12 + 769 = 781. The other duplicate
example, `Rift Crystal.ssd`, has SHA-256
`de113fdd43cc366b5be9f981541c1819fe3a8512dc785bccc74edb1abaf402ec`.
Independent `sha256sum` confirmed both hashes.

## Inferred and unknown

The arithmetic strongly suggests `a` and `b` describe a payload location and
length in the sampled files. Later independent executable analysis confirms
seek and read-budget uses on selected paths; see `srsc-record-behavior.md`.
The sample arithmetic alone does not establish how the game consumes
records, the meaning of the first six bytes, uniqueness or ordering rules, valid
zero-length entries, gaps, alternate versions, or requirements for any other
edition or file. Do not turn the sampled contiguity or EOF conditions into
rejection rules without further evidence. Correlate record access in the
executable and examine independent files before implementing record semantics.

## Reproduce

```sh
python3 tools/research/analyze_srsc_records.py research/installed/us research/exports/srsc-records/us.json
python3 tools/research/analyze_srsc_records.py research/installed/us research/exports/srsc-records/us-repeat.json
cmp research/exports/srsc-records/us.json research/exports/srsc-records/us-repeat.json
python3 -m unittest discover -s tools/research -p 'test_*.py' -v
```

The two outputs compared identical; all four research-tool tests passed,
including synthetic contiguous, duplicate, noncontiguous, out-of-range,
trailing-data and truncated-table cases. These are tests of measurement, not
proof of original loader behavior. Raw retail samples are not included in tests.

## Hash-checked cross-extension recheck, 2026-10-23

`tools/research/measure_srsc_payload_layout_inventory.py` re-read each of the
178 entries in the private US SRSC inventory, rejected unsafe paths, and
verified each file's recorded size and SHA-256 before measuring its table.
The fresh scan found 38,926 records across `.adb` (12 files), `.lvl` (23),
`.mod` (29), `.odb` (39), `.rrc` (2), `.sdb` (19), `.ssd` (16), and `.txd`
(38). Every record range fits between the 12-byte header and the table; none
has zero length. All 38,748 adjacent table-order pairs are contiguous, all
178 first ranges start at byte 12, all 178 last ranges end at the table, and
all 178 tables end at EOF. This reproduces the earlier aggregate measurement
with explicit inventory hash checks; it does not show how every runtime path
uses those ranges or establish these sample patterns as format requirements.
Eight per-file table/layout fields, including record count and endpoint/
adjacency statistics, also matched the earlier `analyze_srsc_records.py`
output for the same hash-verified inputs.

The debug and release inspectors independently matched the first 50 records
in all 178 files. `tools/research/verify_srsc_inspector.py` now verifies each
manifest file's size, SHA-256, safe non-symlink path, and table bounds before
invoking the inspector. It passes those exact verified bytes to the inspector
through a temporary snapshot, avoiding a reopen race; it also rejects
manifest file-count mismatches and duplicate/invalid paths. Six scanner tests
and four inspector-verifier tests cover contiguous, gap, overlap, table-bound,
hash, path, and symlink cases.
The 178 SRSC paths, sizes and SHA-256 values also exactly match the
`candidate_table` subset of the separate 337-file installed-asset inventory.

## Seek-width boundary recheck, 2026-10-23

The pinned US executable's reader passes record offset `+6` to the imported
`SetFilePointer` with a null high-order pointer and `FILE_BEGIN`; the following
instruction compares the returned low-order position with the stored field.
The hash-checked cross-extension scan also measured the largest record start
and end: 57,579,987 and 57,579,991 bytes, respectively. In the sampled files
all positions are well below the signed-offset limit described by the
[Microsoft `SetFilePointer` documentation](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-setfilepointer),
so these assets do not exercise large-file behavior. The API documentation
states that `lDistanceToMove` is a signed 32-bit value when the high-order
pointer is null and gives a maximum of 2^31−2. This API contract and sample
measurement do not establish behavior for unobserved multi-gigabyte inputs or
other executable versions.

## Original inventory snapshot recheck, 2026-10-23

`analyze_srsc_records.py` now checks the 12-byte header, then reads each SRSC
candidate once and hashes and parses the header/table from that same byte
string. Non-SRSC files are skipped after the header read. Its fresh private
178-file inventory reproduced 38,926 records, 38,926 in-bounds ranges, 38,748
contiguous adjacent pairs, three repeated keys, and all previous per-extension
counts. The regenerated inventory compared byte-for-byte with the prior
private JSON. Three synthetic tests passed, including malformed headers and
range gaps. The independent hash-pinned cross-extension measurement above remains
the verification of these aggregate findings. This makes the inventory's own
record metadata and digest refer to one snapshot; it does not change the
observed record patterns into validity requirements.

Reproduce the retail instruction evidence with:

```sh
objdump -d -Mintel --start-address=0x0045F1D5 --stop-address=0x0045F201 research/binaries/us/Drakan.exe
python3 tools/research/measure_srsc_payload_layout_inventory.py research/installed/us research/exports/srsc-records/us.json
```

Reproduction:

```sh
python3 tools/research/measure_srsc_payload_layout_inventory.py research/installed/us research/exports/srsc-records/us.json
python3 tools/research/verify_srsc_inspector.py build/debug/dragonrider_inspect research/installed/us research/exports/asset-inventory/us.json
python3 tools/research/verify_srsc_inspector.py build/release/dragonrider_inspect research/installed/us research/exports/asset-inventory/us.json
```

## Full physical-manifest verifier snapshot recheck, 2026-10-23

`verify_srsc_manifest.py` now checks each manifest entry's safe path, recorded
size, SHA-256, and candidate table bounds before comparing its decoded records
with the inspector. The inspector receives a temporary copy of those same
verified bytes, so the comparison cannot silently use a later version of the
source file. Synthetic tests cover exact snapshot handoff, stale hashes, and
symlink rejection. Debug and release inspectors each matched all 178 manifest
files and 38,926 record ranges. This validates the comparison workflow; it
does not strengthen any claim about runtime use or general SRSC rules.

Reproduce with:

```sh
python3 tools/research/verify_srsc_manifest.py build/debug/dragonrider_inspect research/installed/us research/exports/asset-inventory/us.json
python3 tools/research/verify_srsc_manifest.py build/release/dragonrider_inspect research/installed/us research/exports/asset-inventory/us.json
```
