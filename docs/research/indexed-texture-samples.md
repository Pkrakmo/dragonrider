# Depth-8 row indices and same-file palette candidates

**Date and source:** 2026-10-17, unpatched US installed files under
`research/installed/us`. The ignored output records each examined file's
relative path and SHA-256 and the record indices. Extraction completeness and
input immutability are unverified. **Method:** bounded Python 3.14.7 byte-level
measurement in `tools/research/indexed_texture_samples.py`, independent of
Ghidra and C++ implementation; no game execution. **Confidence:** high for
these particular measurements, not a format specification or proof of
rendered appearance or another edition's behavior.

## Observed

The measurement selects SRSC tables and selector-`0x0040` payload ranges using
the bounded data-area policy in [the palette sample scan](texture-palette-samples.md).
For each depth-8 record, it checks the 50-byte header, a 16 MiB limit on both
input and decoded base rows, exact declared zlib consumption and output
length on storage word 1, or bounded raw rows on a nonpositive storage word.
It rejects a row size smaller than width. It counts only the first `width`
bytes of each of `height` rows, excluding any remaining stride bytes. Other
positive storage words are not measured. These acceptance choices are
measurement constraints, not universal format rules.

A candidate count is compared only if the file contains **exactly one**
selector-`0x0030` record with table offset-4 word zero and that candidate has
enough bytes for its declared entries. The comparison does not apply the
runtime version gate and does not establish that this is the palette the game
uses. It does not write palette entries or decoded pixel bytes.

- All 1,030 selected depth-8 records in 24 files were measured, comprising
  4,637,696 visible row bytes. No selected row had stride greater than width.
- The 1,028 records in 23 files with one nonzero qualified same-file candidate
  all have candidate count 256. No byte is greater than or equal to 256;
  this is automatic for any byte and is **not** evidence of association.
- The remaining two records are in `English_-_Common_Data_Files/Mountain_World/Intro_Level/Intro Level.txd`, SHA-256
  `79198853c73fe596c9ef1f0761b66e1a84834758cf13554427c772ce1fa54586`.
  Its sole qualified candidate is selector-`0x0030` index 1 with count zero.
  Texture index 69 is 64×64 and texture index 70 is 32×32; each visible byte
  in both records has value 255. All 5,120 bytes are therefore at or above
  the same-file candidate count, which is automatic when that count is zero.
- Across all 1,030 records, 241 contain at least one visible byte 0 and 25
  contain at least one visible byte 255. These values alone do not establish
  transparent pixels, visible colors or the palette used by the game.

## Inferred and unknown

The two zero-count cases do not provide a usable palette from their same-file
candidate. Whether the original game loads or displays either texture, uses a
shared runtime palette, performs a fallback, or follows another path remains
unknown. Row orientation, palette mutation, alpha and color-key behavior
remain unresolved. The scan does not assert that a byte value of 255 is
transparent or that source-row order is display order.

## Reproduction

```sh
python3 tools/research/indexed_texture_samples.py research/installed/us research/exports/indexed-texture-samples/us.json
python3 tools/research/indexed_texture_samples.py research/installed/us research/exports/indexed-texture-samples/us-repeat.json
cmp research/exports/indexed-texture-samples/us.json research/exports/indexed-texture-samples/us-repeat.json
python3 -m unittest discover -s tools/research -p 'test_*.py' -v
```

On 2026-10-17, the metadata outputs matched exactly and the full suite passed
20 tests. Four new synthetic tests cover raw and compressed rows, stride
padding, count boundaries, malformed input and caps, zero-width huge height,
and ambiguous or zero-count candidate selection. The ignored metadata output
contains statistics and provenance only, not texture rows or palette entries.

The inspector's explicit-pair results were compared against these independent
measurements on 2026-10-17:

```sh
python3 tools/research/verify_indexed_inspector.py build/debug/dragonrider_inspect research/installed/us research/exports/indexed-texture-samples/us.json
```

All 1,030 pairs matched on entry count, visible byte count, distinct count,
maximum and out-of-range count. This does not validate runtime selection.
