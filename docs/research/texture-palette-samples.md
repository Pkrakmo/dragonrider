# Selector 0x0030 and depth-8 sample association

**Date and source:** 2026-10-17, unpatched US installed files under
`research/installed/us`. The ignored output JSON records every examined file's
relative path and SHA-256, and candidate record coordinates. Extraction
completeness and immutability are unverified. **Method:** bounded Python 3.14.7
reads by `tools/research/palette_measure.py`; no Ghidra database or game-code
execution. **Confidence:** high for these byte counts and sample associations;
not a specification or evidence of rendered colors or other editions.

The selector and count hypothesis was guided by independent static executable
analysis: one palette-related path selects table word `0x0030`, filters the
word at entry offset 4 to zero, reads a little-endian 16-bit count and then
four bytes per entry. That path has a separate record gate: table words
`(0x0402, 0, 0)` and a first little-endian 32-bit payload value `0x204`.
The measurements below check these quantities, without assuming that the
runtime selected or displayed each record. See the companion executable trace
for the path and its limits.

## Observed

The tool selects regular, non-symlink files with an `SRSC` header, version
`0x0100`, table offset at least 12, and a complete 14-byte-per-record table.
It considers selector-`0x0030`, selector-`0x0402`, and selector-`0x0040`
payload ranges only when they lie between offset 12 and the table. This is a
sample-selection policy, not a universal format validity rule. Selector-`0x0040`
records of at least 14 bytes whose little-endian depth field at offset 12 is 8
are counted as depth-8 candidates.

- 178 files were examined. Their 39 selected `0x0030` records all have a zero
  word at entry offset 4 and length exactly `2 + 4 * count`: 36 have count 256
  and 3 have count zero. No entry contents were written or interpreted.
- 38 examined files have at least one in-range `(0x0402, 0, 0)` entry with
  first payload dword `0x204`. The gate measurement uses **any** matching entry;
  it does not claim to duplicate a runtime search's duplicate-handling order.
- The 1,030 depth-8 candidates occur in 24 files. Every one of those files has
  a selected `0x0030` record and a matching gate. In 23 of these files at least
  one `0x0030` record with zero offset-4 word has nonzero count; the remaining
  file has two depth-8 candidates and only a count-zero `0x0030` record.
- That counterexample is
  `English_-_Common_Data_Files/Mountain_World/Intro_Level/Intro Level.txd`,
  SHA-256 `79198853c73fe596c9ef1f0761b66e1a84834758cf13554427c772ce1fa54586`.
  Its index-1 candidate starts at offset 16, length 2 and count 0. The game may
  resolve such textures through a runtime association not evident from the file;
  the measurement alone does not establish a fallback.
- The `Dragon.rrc` candidate, SHA-256
  `fb1e403bd33b370cc64fe1ac296b3cf889e524ff2279eca2a27b65911f0ca72a`,
  is selector `0x0030`, index 471, offset 3,682,417, length 1,026 and count 256.
  Its offset-2 table word is 2, unlike the other 38 candidates' value 0, and
  this file has no matching gate. It illustrates why the scan does not promote
  a static-path condition into a global container requirement.

## Unknown

Numerical co-occurrence does not identify the runtime namespace for each
texture or establish that a texture uses its containing file's candidate.
Channel order, alpha/flags, palette mutation, rendering, orientation and the
other editions remain unverified. Count zero is observed and must not be
rejected merely because these depth-8 candidates exist. No game media,
palette bytes or images are emitted by the tool.

## Reproduction

```sh
python3 tools/research/palette_measure.py research/installed/us research/exports/palette-samples/us.json
python3 tools/research/palette_measure.py research/installed/us research/exports/palette-samples/us-repeat.json
cmp research/exports/palette-samples/us.json research/exports/palette-samples/us-repeat.json
python3 -m unittest discover -s tools/research -p 'test_*.py' -v
```

On 2026-10-17 the metadata outputs compared identical and all 14 research-tool
tests passed. The four new synthetic tests cover exact, zero, short and trailing
entries, table/range errors, depth-8 association and both gate selector keys and
the gate value. These test the measurement tool, not original-game behavior.

The C++ inspector was independently compared with the entry counts and CRC32
of the 39 selected records using:

```sh
python3 tools/research/verify_palette_inspector.py build/debug/dragonrider_inspect research/installed/us research/exports/asset-inventory/us.json
```

All 39 matched. CRC32 is a comparison aid, not a cryptographic proof, and
these inspections do not establish which records the game loads.
