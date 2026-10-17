# Reverse engineering research log

## Original US/UK Retail Disc Comparison

**Investigation date:** 2026-10-17

### Confirmed findings

- Both discs contain eight tracks.
- Track 1 uses MODE1/2352.
- Tracks 2–8 are marked AUDIO.
- Both data tracks contain ISO9660 filesystems with the volume label `DRAKAN`.
- Both extracted data-track ISO images are byte-identical, confirmed using SHA-256.
- Canonical data-track SHA-256: `256a4e51020b06c551cc310895e245f1df8790be0af230711a727ecbf29d079c`. Locally rechecked with `sha256sum research/discs/{us,uk}/drakan.iso` on 2026-10-17; this corrects the digest transcribed in the earlier handoff and TODO.
- The game installer contains a `Setup/data1.cab` InstallShield archive.
- The US and UK audio-track BIN files differ at the byte level.

### Decisions

1. Use the US data-track filesystem as the canonical retail asset baseline.
2. Retain both original BIN/CUE images for provenance.
3. Preserve the UK audio tracks as a separate reference.
4. Do not assume that audio differences correspond to different musical recordings.
5. Keep official patch 445 separate from original retail data.

### Outstanding work

- Identify Riot Engine resource files.
- Investigate CD audio-track differences.
- Import the original executable into Ghidra.





## Evidence states
- **Observed:** verified from an identified binary/hash, file header, tool output, or repeatable game behavior.
- **Inferred:** plausible explanation; not yet independently confirmed.
- **Unknown:** no reliable evidence.

## Current observations
- **Observed (2026-10-17):** the level loader's `(1,0,0)` record begins
  with a count and a variable-length first loop; a hash-verified scan measured
  the traced prefix in 23/23 selected US level files. Subsequent payload data
  includes one dimension-derived block per entry; all 4,445 scanned blocks are
  complete zlib streams. On one path the loader transforms one word per grid
  item and uses the resulting values in bounds; 628,856 such items were measured.
  World coordinates and geometry remain unresolved. See the
  [prefix trace](research/level-0001-prefix.md) and [block trace](research/level-0001-blocks.md).
- **Observed (2026-10-17):** one drawing path constructs grid point inputs
  from signed entry origins, 2048-unit steps, a float base and the transformed
  second word. Runtime offsets and clipping still matter. See the
  [coordinate trace](research/level-grid-coordinate-path.md).
- **Observed and inferred (2026-10-17):** a selected cell drawing branch orders neighboring grid points according to a flag and runtime mode. This gives candidate sequences, subject to clipping and other branches; see the [cell topology trace](research/level-cell-topology.md).
- **Observed (2026-10-17):** a traced drawing path consumes the `(1,0,0)`
  cells, branches on copied flag bits and submits groups of neighboring points.
  A conditional lookup reaches the traced selector-`0x0040` texture loader;
  field counts and limitations are in the [cell drawing trace](research/level-cell-draw-behavior.md).
  Runtime source resolution, orientation, winding and visual output remain unknown.
- **Observed (2026-10-17):** a retail level-loading path reads a version-gated
  `(0,0,0)` record containing two unnamed words and a database-reference list;
  an independent scan matched 23/23 selected US files. See the
  [level directory trace](research/level-directory-behavior.md). Name encoding,
  safe path resolution and geometry remain unknown.
- **Observed (2026-10-17):** on one retail texture-loading path, the game
  processes a length-prefixed stream into successive pitched surface rows;
  the stream checks zlib header properties. All 5,991 selected compressed
  US samples decode as complete zlib streams, and two selected samples use
  raw base rows. See [texture pipeline behavior](research/texture-pipeline-behavior.md)
  and [sample measurements](research/texture-pixel-samples.md). Requested
  surface masks are documented there; displayed appearance and orientation
  remain unverified.
- **Observed (2026-10-17):** the palette-loading path reads a count and
  four-byte entries from selected `0x0030` records and uses a runtime source
  identifier for association. Two indexed conversion paths use entry bytes
  0–2 as RGB; byte 3's role is unknown. A US sample scan found 36 records
  with 256 entries and three with zero; see [the trace](research/texture-palette-behavior.md)
  and [sample measurements](research/texture-palette-samples.md).
- **Observed (2026-10-17):** one palette-loading path constructs an object
  even for zero entries; the traced first-match lookup does not check count.
  A conditional indexed conversion compares the source index with a value
  obtained from the device before emitting one-bit-alpha output. No usable
  fallback or universal transparency rule is established. See the
  [fallback and color-key trace](research/texture-fallback-behavior.md) and
  [indexed sample measurements](research/indexed-texture-samples.md).
- **Observed (2026-10-17):** on the traced surface-creation path, a null
  palette handle skips attachment, while failed non-null attachment ends
  that texture load; see [device behavior](research/texture-device-behavior.md).
  The [offset-18 sample scan](research/texture-key-samples.md) compares file
  values with index bytes, not device-returned values or rendered pixels.
- **Observed (user-provided listing):** US and European releases are each named as a directory with one CUE and eight BIN track files.
- **Observed (user report):** European edition is English/UK.
- **Observed (user-provided listing):** an `drakan_patch445_eng` directory with InstallShield-related files exists.
- **Unknown:** actual installed game version and decoded audio differences. Track modes, executable identity, and data-track identity are recorded above and in TODO; other US/UK compatibility remains unverified.

## Research entry template
### Topic
- Status: Observed / Inferred / Unknown
- Source: edition + relative path + SHA-256 + tool/version
- Procedure: reproducible steps
- Finding: minimal factual statement
- Confidence: high / medium / low
- Counterexamples / limitations:
- Implications / tests:

## General warning
A matching filename or length is not proof of matching content. Same SHA-256 is evidence of byte identity. Track numbers alone do not tell us their mode. Treat external community format documentation as a hypothesis until validated against legal local copies.
