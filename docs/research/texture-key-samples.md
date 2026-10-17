# Texture offset-18 values and indexed row comparisons

**Date and source:** 2026-10-17, unpatched US installed files under
`research/installed/us`; private output includes relative paths, file SHA-256,
and record indices. Extraction completeness and input immutability are not
established. **Method:** bounded Python byte-level measurements with
`tools/research/key_texture_samples.py`, independent of Ghidra and C++.
**Confidence:** high for this selection; these observations do not prove a
format rule or visible transparency. This complements the static
[color-key trace](texture-fallback-behavior.md).

## Observed

The scan selects SRSC version `0x0100` containers whose full table fits and
selector-`0x0040` records whose ranges lie between header and table. Payloads
and decoded base rows are each capped at 16 MiB. For the 1,030 depth-8
records, it counts equality between the **file's full 32-bit offset-18 value**
and each of the first `width` bytes in each decoded row. Padding is excluded;
row stride below width is rejected. Raw/nonpositive and storage-word-1 zlib
rows are handled as in the earlier [indexed scan](indexed-texture-samples.md).
The output contains aggregate statistics and provenance, not texture rows.

| Depth | Offset-18 values | Records |
| --- | --- | ---: |
| 8 | `0xffffffff` | 966 |
| 8 | `0` | 42 |
| 8 | `255` | 22 |
| 16 | `0xffffffff` | 4,933 |
| 16 | `0` | 10 |
| 16 | `22` | 16 |
| 16 | `31` | 2 |
| 24 | `0xffffffff` | 2 |

All 5,993 selected records in 39 files had headers within the cap, and all
1,030 depth-8 records were decoded for this comparison. For the 42 records
with offset-18 value 0, all contained matching index bytes: 66,483 matches
among 296,960 visible indices. For the 22 records with value 255, no visible
indices matched among 59,392. A byte cannot equal `0xffffffff`, so the 966
sentinel records necessarily have zero direct full-dword matches; their
4,281,344 visible indices are not evidence of transparency.

## Interpretation and limits

On the traced conditional path the game passes the non-sentinel file value to
a surface method, then compares indices against a **device-returned** dword.
That returned value may differ or the call may fail, and runtime state chooses
the conversion path. Therefore file-value equality does not establish how
many pixels render transparent. This scan does not compare 16-bit pixels,
identify palette associations, establish image orientation or color, or
assess alternate game paths, editions, or display devices. The selection and
limits are measurement policy, not universal validity rules.

## Reproduction

```sh
python3 tools/research/key_texture_samples.py research/installed/us research/exports/key-texture-samples/us.json
python3 tools/research/key_texture_samples.py research/installed/us research/exports/key-texture-samples/us-repeat.json
cmp research/exports/key-texture-samples/us.json research/exports/key-texture-samples/us-repeat.json
python3 -m unittest discover -s tools/research -p 'test_*.py' -v
```

Both private metadata reports matched on 2026-10-17; the research suite passed
24 tests, including four synthetic cases for equality, padding, sentinel and
out-of-byte-range dwords, malformed streams, and bounds.
