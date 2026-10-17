# ADR 0007 — Explicit indexed-texture diagnostics

**Status:** Accepted, 2026-10-17.

## Context

The observed indexed conversion reads 8-bit row values as palette indices.
The runtime chooses a palette by source identifier and load order, not by an
established same-file rule. One measured file contains depth-8 textures and
only a zero-count same-file palette candidate. See
`docs/research/texture-palette-behavior.md` and
`docs/research/indexed-texture-samples.md`.

## Decision

Provide an opt-in diagnostic for a caller-selected 8-bit texture and palette
record in the same SRSC file. Check the selected record selectors and ranges,
decode texture rows under the existing 32 MiB input/output limits, validate
the palette entry prefix and require width no greater than row stride. Count
only the first width bytes of each row, excluding row padding. Report pixel
count, distinct values, maximum, and how many indices exceed the selected
palette's entry count. Zero-sized rows have no maximum index. Out-of-range
counts are reported, rather than claiming that the record is invalid or that
the selected palette is the runtime choice.

## Consequences

The API is independent of rendering and does not export images, assign color
or transparency, perform palette lookup, or define a global format rule. The
same-file constraint belongs to this diagnostic; it does not constrain the
game's runtime association. The existing inspector size-change check cannot
detect concurrent modifications that leave the file size unchanged. Windows
builds remain unverified.
