# Selector 0x0040 payload storage measurements

**Date and source:** 2026-10-17; unpatched US retail files under
`research/installed/us`. The private JSON output identifies each examined
file by relative path and SHA-256, and each record by index and range.
Extraction completeness and immutability are not established. **Method:** Python
3.14.7 raw-byte and standard-library zlib measurements; no Ghidra project was
accessed. **Confidence:** high for these measured files; not a format
specification or evidence about other editions.

## Observed

Selection uses the same bounds and candidate prefix as
`srsc-payload-observations.md`: 39 files, 5,993 selector `0x0040` records,
all with range length at least 16 and within the data area. Values below are
little-endian and offsets are relative to the selected record's start. The
measurement applies a 16 MiB limit independently to the input range and to
zlib output; none of these samples reached either cap.

- Every selected payload has a 32-bit word at offset 46. It is 1 in 5,991
  records and 0 in the other two.
- For each of the 5,991 with a value of 1, the 32-bit value at offset 50 fits
  within the range following offset 54. Python's zlib decoder consumes exactly
  that many bytes starting at offset 54, reaches end-of-stream, and produces
  `u32_at_4 * u32_at_8` bytes. This establishes a valid zlib stream for these
  samples; it does not determine how the decompressed bytes should be used.
- In 5,989 of those 5,991 the stream ends at the end of the record. The
  remaining two have a trailing block: its first four bytes, interpreted as a
  little-endian integer, equal the remaining trailing byte count. Their values
  at offset 12 are both `0x00080010`; the purpose of the trailing data is
  unknown and its contents have not been decoded.
- Both records with zero at offset 46 contain exactly
  `u32_at_4 * u32_at_8` bytes following offset 50. Their data content and
  relation to the zlib output are not established. A zero word followed by
  that many bytes is an observation, not proof of original loader semantics.

### Independently identified exceptions

- `English_-_Common_Data_Files/Dragon.rrc`, SHA-256
  `fb1e403bd33b370cc64fe1ac296b3cf889e524ff2279eca2a27b65911f0ca72a`,
  records 67 and 457 start at 2,950,439 and 3,566,373, have lengths 2,098 and
  32,818, respectively, and contain 2,048 and 32,768 bytes after offset 50.
- `English_-_Common_Data_Files/Common/FX/FX.txd`, SHA-256
  `e3c775f276b1dc92a0f73fbb920e2016be75090ff421a2c76bc7afd1378dd564`,
  record 517, start 1,599,508, length 1,302, has a 622-byte zlib stream and a
  626-byte trailing block.
- `English_-_Common_Data_Files/Common/Resources/Resources.txd`, SHA-256
  `9c428b14e1cf20432a4d67cc9469db7245ac4d95d41cb99b8d64db14fc19cf71`,
  record 374, start 954,783, length 116, has a 29-byte zlib stream and a
  33-byte trailing block.

`sha256sum` independently verified these three file hashes.

## Inferred and unknown

The two layouts are consistent with compressed and uncompressed data storage,
with a possible additional component on the two records with trailing data.
Measurements alone do not establish whether the word at offset 46 controls
storage, what the product or other prefix fields mean, whether the trailing
block is compressed, pixel format, image orientation, valid flags, or allowed
bounds across editions. Do not impose these patterns as format validity rules.
Trace executable code that reads these bytes, independently verify any format
hypotheses, and retain strict limits for decompression of untrusted input.

## Reproduction

```sh
python3 tools/research/measure_selector_0040.py research/installed/us research/exports/selector-0040-samples/us.json
python3 tools/research/measure_selector_0040.py research/installed/us research/exports/selector-0040-samples/us-repeat.json
cmp research/exports/selector-0040-samples/us.json research/exports/selector-0040-samples/us-repeat.json
python3 -m unittest discover -s tools/research -p 'test_*.py' -v
```

The private outputs compared identical. All seven research-tool tests passed,
including synthetic complete/incomplete zlib streams, trailing blocks,
non-zlib data, an out-of-range stored size and the configured cap. These
exercise measurement, not game behavior. No original payloads are included.

On 2026-10-17 the independent C++ inspector's texture-header output matched
these measurements for all 5,993 selected records. To repeat after a release
preset build:

```sh
python3 tools/research/verify_texture_inspector.py build/release/dragonrider_inspect research/installed/us research/exports/selector-0040-samples/us.json
```

This compares reported header fields; it does not verify a texture decoder or
the correctness of the pixel data.

## Single-snapshot recheck, 2026-10-23

The candidate prefix scanner now calculates SHA-256 and reads record prefixes
from one in-memory input snapshot. `measure_selector_0040.py` receives that
snapshot and applies its bounded raw/zlib checks to slices from the same bytes,
avoiding a second path open after inspection. Fresh scans reproduced 39 files,
5,993 selected records, 5,991 complete zlib streams with decoded lengths
matching the measured product, and two zero-word records. The prefix test and
both selector measurement tests passed. Each fresh output compared
byte-for-byte with its earlier private counterpart. Output remains
aggregate/private as before; this changes provenance consistency only.

The independent `verify_texture_inspector.py` comparison now checks each
source file's manifest SHA-256 and passes those exact bytes to the inspector
through a per-file temporary snapshot. Two synthetic tests passed, including
a stale-hash rejection; the debug and release inspectors each matched all
5,993 texture headers again. This confirms the header comparison against the
hashed manifest input and does not verify visual output.

```sh
python3 tools/research/verify_texture_inspector.py build/debug/dragonrider_inspect research/installed/us research/exports/selector-0040-samples/us.json
python3 tools/research/verify_texture_inspector.py build/release/dragonrider_inspect research/installed/us research/exports/selector-0040-samples/us.json
```
