# SRSC candidate payload prefix measurements

**Date and source:** 2026-10-17, unpatched US retail files in
`research/installed/us`. The private per-file output records each source path,
SHA-256 and candidate record coordinates under `research/exports/srsc-payloads/`.
**Method:** Python 3.14.7 raw byte measurements using
`tools/research/analyze_srsc_payloads.py`; no Ghidra database was accessed.
**Confidence:** high for the measured arithmetic in these files, not for a
format specification. Completeness and immutability of extraction are unknown.

## Observed

Select `SRSC`, version `0x0100`, nonzero-count files with a table at or after
byte 12 that fits within the file. Interpret each 14-byte entry as little-endian
`<HIII`; select entries whose first 16-bit value is `0x0040`, whose candidate
range from entry offsets 6 and 10 fits between byte 12 and the table, and whose
length is at least 16. Read four little-endian 32-bit integers `a, b, c, d`
from the start of each such range. This method does not validate the format.

- 39 files yielded 5,993 selected records: 5,878 in `.txd` and 115 in `.rrc`.
  No selected ranges failed the stated bounds; no matching headers were skipped.
- All 5,993 satisfy `c * 8 == a * (d & 0xffff)`. The observed `d` values are
  `8` (1,030 records), `16` (3,158), `24` (2), `65552` (13), `262160`
  (1,788), and `524304` (2). Their low 16 bits are 8, 16, or 24.
- `a == b` for 5,823 records; both are powers of two for 5,991. These counts
  rule out treating either square values or powers of two as universal.
- For 5,990 records, the candidate range length is smaller than `a * b * 2`.
  This arithmetic alone does not establish compression or an encoding.

### Bounded examples and counterexamples

- `English_-_Single-Player_Data_Files/Common/NPC/NPCs.txd`, SHA-256
  `fdb4edf1ab3bf06eb79ed4e045f3a0ecb981df7b3495f897168725ed7744f84c`,
  record index 7, has range offset 7,169, length 1,105, and prefix values
  `(32, 96, 32, 8)`. The second value is not a power of two, but the stated
  multiplication holds.
- `English_-_Common_Data_Files/Dragon.rrc`, SHA-256
  `fb1e403bd33b370cc64fe1ac296b3cf889e524ff2279eca2a27b65911f0ca72a`,
  record index 474, has offset 3,687,612, length 187, and prefix values
  `(192, 64, 384, 16)`. The first is not a power of two. Record index 67,
  offset 2,950,439 and length 2,098, begins `(32, 32, 64, 262160)`;
  its length is greater than `32 * 32 * 2`, unlike most selected records.
- `sha256sum` independently verified both file digests above.

## Inferred and unknown

The relationship between these prefix values is consistent with a structured
payload associated with the selected table value. Whether these values encode
image dimensions, a row stride, pixel depth, flags, compression, or something
else remains unknown. The arithmetic relationship is not established as a rule
for other record types, editions, or future files, and should not become a
rejection condition. No payload decoder or record semantics are established.
Further investigate game code that consumes record value `0x0040`, and test any
hypothesis against additional independently sourced inputs.

## Reproduction

```sh
python3 tools/research/analyze_srsc_payloads.py research/installed/us research/exports/srsc-payloads/us.json
python3 tools/research/analyze_srsc_payloads.py research/installed/us research/exports/srsc-payloads/us-repeat.json
cmp research/exports/srsc-payloads/us.json research/exports/srsc-payloads/us-repeat.json
python3 -m unittest discover -s tools/research -p 'test_*.py' -v
```

The two outputs were identical; all five research-tool tests passed. The new
synthetic test exercises a measured prefix, two invalid ranges and a different
record value. It tests the measurement code, not the original game's behavior.

## Single-snapshot recheck, 2026-10-23

`analyze_srsc_payloads.inspect_with_snapshot` now returns the exact byte
snapshot used for parsing and SHA-256 calculation. Files without an `SRSC`
header are skipped after reading 12 bytes. The related
`measure_selector_0040.py` consumes its selected ranges from those bytes rather
than reopening each file after the prefix scan. The synthetic payload test and
two selector-`0x0040` tests passed. Fresh scans reproduced the earlier results:
39 files and 5,993 candidates (5,878 `.txd`, 115 `.rrc`), with all 5,993
satisfying the observed multiplication; the bounded follow-up again found
5,991 complete zlib streams and two zero-word records. Private aggregate
outputs were written under `/tmp`; each compared byte-for-byte with its
previous private inventory. This makes hashing, prefix parsing and bounded
payload measurement refer to one snapshot; it does not establish format
semantics or runtime decoding.
