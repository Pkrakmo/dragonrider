# Texture sample layout and exceptional blocks

**Date/source:** 2026-10-17, unpatched US installed files under
`research/installed/us`. Each examined file's path and SHA-256 and each
record's index and range are retained in the ignored private measurement JSON.
Extraction completeness and immutability are unverified. **Method:** Python 3.14.7
standard-library bounded input and zlib measurements with
`tools/research/measure_texture_layout.py`; no Ghidra database or game code
execution. **Confidence:** high for these samples, not a specification or a
claim about other editions. Selection follows the candidate range policy in
`srsc-payload-observations.md` and excludes ranges outside the data area.

## Observed

- Among 5,993 selected records in 39 files, 4,961 have depth 16, 1,030 depth 8,
  and two depth 24. Every selected record satisfies
  `row_bytes * 8 == width * depth`. This is an observation, **not** a rule for
  rejecting other data. It does not establish byte order, channels, masks,
  padding in other editions, palette contents, or vertical orientation.
- All 5,991 word-at-46 value 1 entries yielded complete zlib streams with
  exact `height * row_bytes` output, no leftover declared compressed bytes,
  and no unconsumed input. The two value 0 entries have exactly that amount of
  data following the 50-byte header. Both input and decompressed output were
  capped at 16 MiB; no selected input or output hit the caps.
- Exactly two records have flag `0x100` in the word at offset 34; these are
  precisely the two entries with trailing data. Each has a four-byte
  little-endian trailing length equal to the following bytes. The bytes after
  the length did **not** decode as complete zlib-wrapped streams with Python's
  `zlib.decompressobj()`, nor as complete raw DEFLATE streams using its
  negative window-bits setting, with a 16 MiB output cap. Other encodings and
  framing remain untested. This supports the previously observed runtime skip, not a meaning
  for the extra block.
- The depth-24 counterexamples, both compressed without trailing data, are in
  `English_-_Single-Player_Data_Files/Common/NPC/NPCs.txd` (SHA-256
  `fdb4edf1ab3bf06eb79ed4e045f3a0ecb981df7b3495f897168725ed7744f84c`):
  index 162, offset 3,729,973, 64×64 with row size 192; and index 215, offset
  4,233,246, 128×128 with row size 384. The particular traced loader rejects
  depth 24; the reachability and consumer for these records are unknown.
- The trailing cases are index 517 in `Common/FX/FX.txd` (SHA-256
  `e3c775f276b1dc92a0f73fbb920e2016be75090ff421a2c76bc7afd1378dd564`)
  and index 374 in `Common/Resources/Resources.txd` (SHA-256
  `9c428b14e1cf20432a4d67cc9469db7245ac4d95d41cb99b8d64db14fc19cf71`),
  relative to `English_-_Common_Data_Files`. Both are 32×32, depth 16,
  row size 64, and their offset-34 word is 266 (`0x10a`). Their trailing
  lengths including the four-byte prefixes are 626 and 33 respectively.

## Inferred and unknown

The row equality is consistent with tightly packed pixels in this sample set,
though numerical equality alone does not identify their meaning. It would be
unsafe to pick RGB565, RGB555, BGR ordering, palette or row orientation based
on this statistic. The exceptional blocks might be compressed using another
wrapper or represent unrelated data; their content and function remain
unknown. The two depth-24 examples demonstrate why the particular loader's
accepted depths must not become a general container validity check.

## Reproduction and verification

```sh
python3 tools/research/measure_texture_layout.py research/installed/us research/exports/texture-pixel-samples/us.json
python3 tools/research/measure_texture_layout.py research/installed/us research/exports/texture-pixel-samples/us-repeat.json
cmp research/exports/texture-pixel-samples/us.json research/exports/texture-pixel-samples/us-repeat.json
python3 -m unittest discover -s tools/research -p 'test_*.py' -v
```

The two outputs matched; all 10 research-tool tests passed, including three
synthetic tests for the new measurement's raw/compressed paths, exceptional
blocks, limits, malformed streams and range errors. Private measurement JSON
contains metadata only, not decoded image content; original asset inputs and
private output are not committed. The corpus was not compared against a
running game or another edition.

The C++ base-row implementation was independently compared with Python zlib
and CRC32 for all selected records on 2026-10-17:

```sh
python3 tools/research/verify_texture_rows.py build/debug/dragonrider_inspect research/installed/us research/exports/selector-0040-samples/us.json
```

All 5,993 row lengths and CRC32 values matched. CRC32 is not collision-resistant;
this is a useful cross-check, not proof of rendered appearance or a substitute
for validating other editions. The private manifest and assets remain local.

## Inspector snapshot recheck, 2026-10-23

`verify_texture_rows.py` now checks each input file's manifest SHA-256, decodes
selected rows from those same bytes, and gives that exact snapshot to the
inspector through a temporary file. Two synthetic verifier tests passed,
including stale-hash rejection. Both GCC debug and release inspectors matched
the independently calculated lengths and CRC32 values for all 5,993 records
again. This removes the prior second read of each source path during the
comparison; CRC32 and these samples do not establish rendered correctness.

```sh
python3 tools/research/verify_texture_rows.py build/debug/dragonrider_inspect research/installed/us research/exports/selector-0040-samples/us.json
python3 tools/research/verify_texture_rows.py build/release/dragonrider_inspect research/installed/us research/exports/selector-0040-samples/us.json
```
