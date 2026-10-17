# ADR 0005 — Bounded texture base-row decoding

**Status:** Accepted, 2026-10-17. Extends ADR 0004 for base rows; its
header and table policies remain in force.

## Context

Static executable analysis and measurements of private retail samples support
zlib-wrapped DEFLATE for the observed selector-`0x0040` storage word 1; see
`docs/research/texture-pipeline-behavior.md` and `texture-pixel-samples.md`.
They also support raw row data on the signed-nonpositive path. Pixel layout,
display orientation, additional blocks, and other positive values need more
evidence. The original loader's error handling is not a safety policy.

## Decision

Provide a bounded base-row API: calculate height × row bytes with overflow
checks, require a caller-specified output cap, and validate raw input ranges.
For storage word 1, read the little-endian length, require a complete zlib
stream that consumes exactly that range and produces exactly the expected
output. Reject other positive control words. Return the end offset and leave
subsequent bytes opaque. No pixel conversion or orientation is assumed.

Use CMake's required `ZLIB::ZLIB` system dependency, without bundling its code.
On the tested Fedora host, zlib-ng compatibility packages identify their RPM
license as Zlib; other platforms must supply a compatible development library.
Ghidra is never a build or runtime dependency. The inspector's opt-in
`--texture-rows` limits both input payload and decoded rows to 32 MiB and
reports length and CRC32 without writing asset data. CRC32 is a comparison aid,
not a cryptographic integrity check.

## Consequences

The engine now requires zlib headers and a library at build time. Validating
complete streams is intentionally stricter than observed unchecked loader
calls; results do not establish the validity of extra blocks, formats on
other branches, or displayed images. Windows dependency discovery and builds
remain unverified.
