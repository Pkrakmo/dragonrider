# ADR 0006 — Bounded selector-0x0030 entry inspection

**Status:** Accepted, 2026-10-17.

## Context

The retail executable reads a little-endian 16-bit count and four bytes per
entry for selector `0x0030` on a palette-loading path. The path also filters
the third table word, has a version gate, and associates data using a runtime
namespace; see `docs/research/texture-palette-behavior.md`. Retail measurements
include zero-count records, including one in a file with depth-8 textures;
see `docs/research/texture-palette-samples.md`. Neither file co-occurrence nor
the entry layout proves which palette is actually selected for each texture.

## Decision

Provide a bounded structural reader that validates the complete count and
entry range before allocating, returns four-byte entries in file order, and
leaves following bytes opaque. Accept all 16-bit counts, including zero, and
make no global 256-entry, version-gate, or image interpretation assumption.
The inspector's `--palette` selects table word 0 `0x0030` and table word 2
zero, reads only the bounded entry prefix (at most 262,142 bytes), and reports
the count, CRC32 and unvalidated trailing length. This is structural inspection,
not a claim that the original runtime reached or displayed the record.

## Consequences

The reader is independent of the renderer and palette lookup policy, and its
output preserves all four bytes without interpreting alpha or flags. Palette
resolution, entry index bounds, rendered colors, transparency, orientation,
and alternate original-engine branches require separate evidence. CRC32 is a
comparison aid, not a cryptographic integrity check. Windows remains untested.
