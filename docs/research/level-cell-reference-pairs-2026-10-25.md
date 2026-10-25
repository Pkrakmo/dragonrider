# Level cell reference-pair reuse across US levels — 2026-10-25

## Scope and provenance

This measurement checks recurrence of the **ordered pair** of signed 32-bit
values decoded from serialized cell offsets `+2` and `+6` in the selected
`(1,0,0)` payloads. Inputs are the installed-US inventory
`research/exports/asset-inventory/us.json`, SHA-256
`e878d60f9bc3ffcee8c42ef302970d9f6676ca0ed6cb3e582cc01ddd1a543b64`, and
US-retail `Drakan.exe`, SHA-256
`23630f48e20e8a9f42026501165ae1df407cfcee545a784ec930a4c25ee70648`. The
executable hash supplies context for the statically traced two-lookup cell
path in the [cell layout note](level-0001-cell-reference-layout-2026-10-25.md);
this aggregate measurement itself does not analyze executable bytes.

The Python 3.14.7 tool reuses `measure_level_blocks.py` for bounded cell
stream decoding. It verifies safe inventory paths, file sizes, and SHA-256
from one capped snapshot per selected file (256 MiB maximum; read length at
most declared size plus one byte). It requires exactly one `(1,0,0)` table
entry per selected level, then emits counts only; no pair values or paths are
reported. Confidence is high for the counts over the pinned installed-US
inventory and decoder path.

## Observed measurement

Across 23 levels and 542,791 decoded cells:

- There are 4,870 distinct ordered pairs after deduplicating within each
  level, and 3,538 distinct pairs in their union.
- 854 pairs occur in more than one level, accounting for 1,332 extra
  per-level occurrences beyond the union.
- 249 of 253 level pairs share at least one ordered pair.
- One ordered pair occurs in 22 of the 23 levels.

For context, the companion scalar scan finds 2,510 distinct signed values
when values are deduplicated separately within each level and 1,622 in their
union; 545 scalar values occur in multiple levels. These scalar and tuple
counts use the same cell decoder and inventory. Equality recurrence describes
the bytes only. It does not establish a global namespace, successful lookup,
object identity, or semantic relationships between cells; it covers only
this US sample.

## Reproduction

```sh
sha256sum research/exports/asset-inventory/us.json research/binaries/us/Drakan.exe
python3 tools/research/measure_level_cell_reference_pairs.py \
  research/installed/us research/exports/asset-inventory/us.json
python3 tools/research/measure_level_cell_reference_reuse.py \
  research/installed/us research/exports/asset-inventory/us.json
PYTHONPATH=tools/research python3 -m unittest \
  test_measure_level_cell_reference_pairs -v
```

Seven synthetic tests cover ordered-pair distinctions, within-level
deduplication, aggregate-only output, stale hashes, duplicate and symlinked
paths, size limits, and capped snapshot reads. See the related
[scalar reuse measurement](level-cell-reference-reuse-2026-10-25.md) and
[serialized cell layout](level-0001-cell-reference-layout-2026-10-25.md).
