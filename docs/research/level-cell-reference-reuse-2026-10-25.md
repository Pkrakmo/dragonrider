# Level cell reference reuse across US levels — 2026-10-25

## Scope and provenance

This measurement asks whether the signed 32-bit values at serialized cell
offsets `+2` and `+6` recur across the 23 installed-US `.lvl` files. The
inventory snapshot is SHA-256
`e878d60f9bc3ffcee8c42ef302970d9f6676ca0ed6cb3e582cc01ddd1a543b64`.
The relevant retail executable is the pinned US `Drakan.exe`, SHA-256
`23630f48e20e8a9f42026501165ae1df407cfcee545a784ec930a4c25ee70648`; its
static keyed-lookup path is summarized in [the cell layout note](level-0001-cell-reference-layout-2026-10-25.md).
The new Python 3.14.7 tool reuses the bounded `measure_level_blocks.py`
decoder and verifies every selected input's inventory size and SHA-256 before
counting. Each file is capped at 256 MiB; its manifest and on-disk sizes are
checked before reading, and the read is limited to expected size plus one
byte. It prints aggregate counts only, with no keys or file paths.

## Observed measurement

Across the 23 levels, there are 2,510 distinct signed key values when values
are deduplicated separately within each level, and 1,622 distinct values in
the union across levels. Therefore 545 values occur in more than one level,
accounting for 888 additional per-level occurrences beyond the union. Of 253
possible level pairs, 249 share at least one value; one value occurs in 22 of
the 23 levels.

These are exact equality counts over the two decoded signed dwords. They show
that equal serialized values frequently recur across the sample. They do not
establish a global key namespace, successful runtime lookup, object identity,
or a semantic relationship between cells. The findings apply only to this
hash-pinned installed-US inventory and the traced decoder path.

## Reproduction

```sh
sha256sum research/exports/asset-inventory/us.json research/binaries/us/Drakan.exe
python3 tools/research/measure_level_cell_reference_reuse.py \
  research/installed/us research/exports/asset-inventory/us.json
PYTHONPATH=tools/research python3 -m unittest \
  test_measure_level_cell_reference_reuse -v
```

Seven synthetic tests cover cross-level count aggregation, aggregate-only
output, stale hashes, duplicate paths, symlink rejection, oversized inputs,
and the bounded snapshot read. See also the
[static cell layout and whole-sample counts](level-0001-cell-reference-layout-2026-10-25.md).
