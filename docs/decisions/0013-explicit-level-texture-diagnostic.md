# ADR 0013 — Compare an explicit level source with a texture container

**Status:** Accepted, 2026-10-17.

## Context

The traced texture selector checks a source ID and then matches two SRSC
selector words, ignoring the third on this path. Sample files support the
association under an unverified installer-overlay hypothesis; see
[the research](../research/level-texture-candidates.md). Embedded names and
runtime source state do not establish a safe, universal file resolver.

## Decision

Provide `--level-texture-ids BLOCKS_INDEX SOURCE_ID LEVEL_FILE TEXTURE_FILE`.
Both physical files, the level record index, and a 16-bit source ID are
explicitly supplied by the caller. Validate both SRSC tables and all their
ranges, require the level record's `(1,0,0)` selector, apply the existing
block inspection limits, and compare nonnegative cell dwords whose high half
matches the supplied source ID against texture records with selector word 0
`0x0040` and word 1 equal to the low half. Report unique, multiple and missing
matches, plus negative and other-source occurrences. The third selector is not
tested, matching the traced search; multiple matches are reported rather than
silently assigning a runtime record. Counts represent file occurrences, not
calls or visible textures.

Do not read embedded directory names, resolve paths, open implicit files,
decode texture payloads, assert successful runtime loading, or require the
texture file to use a specific extension. No validation of selected texture
payload content is implied. Both inputs are checked for file-size changes;
unchanged-size concurrent modification is not detected.

## Consequences

This enables bounded, reproducible comparison without adding a path-resolution
policy or coupling Riot assets to rendering. A reported match depends on the
caller-supplied file and ID; zero IDs, cache state, source reuse and runtime
failures may produce different behavior. Other editions and Windows builds
remain unverified.
