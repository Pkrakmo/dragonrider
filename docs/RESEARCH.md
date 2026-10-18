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
5. Defer further patch 445 analysis and compatibility work until base-game work is complete; keep patch inputs separate from original retail data.

### Outstanding work

- Identify Riot Engine resource files.
- Investigate CD audio-track differences.
- Import the original executable into Ghidra.





## Evidence states
- **Observed:** verified from an identified binary/hash, file header, tool output, or repeatable game behavior.
- **Inferred:** plausible explanation; not yet independently confirmed.
- **Unknown:** no reliable evidence.

## Current observations
- **Observed (2026-10-18):** a direct retail `0x0102` writer has a fixed-width
  136-byte initial sequence, while the sampled `.odb` reader uses a
  length-prefixed payload layout. Of 4,203 hash-verified US records, 136 are
  shorter than that sequence; all have a same-file `(0x0402,0,0)` gate whose
  dword is `0x0102`, whereas the enclosing writer emits `4` in its gate.
  Successful writes, stable record state and writer dispatch are conditional;
  no file production or runtime association is established. See [the writer
  comparison](research/srsc-writer-third-state.md#follow-up-the-0x0102-writer-is-a-separate-candidate).
- **Observed (2026-10-18):** all 4,185 nonempty `0x0102` tails have printable
  ASCII in the high half of their second dword; its low half fits as a
  candidate body length in 4,157, with 4,052 such bodies ending in NUL. The
  lengths cover only part of the tails and do not establish a structure or
  field meaning. See [the bounded byte summary](research/srsc-0102-runtime.md#candidate-second-dword).
- **Observed (2026-10-18):** the most common tail prefix/tag pairs are `(1, In)`,
  `(7, Wa)`, `(1, Da)`, `(7, Ty)`, `(10, Di)`, and `(0x1003, Sp)`; literal
  immediate searches did not locate those tag constants in retail code.
  Meanings and table-driven handling remain unknown; see [the tail
  comparison](research/srsc-0102-runtime.md#candidate-second-dword).
- **Observed (2026-10-18):** the retail `0x0102` consumer's traced success path
  clears the selected record without consuming its remaining read budget. A
  bounded disassembly scan found one direct caller and no immediate matches
  for the common two-byte tail pairs. This does not rule out generic or
  indirect handling; see [the caller boundary](research/srsc-0102-runtime.md#consumer-and-direct-caller-boundary).
- **Observed (2026-10-18):** sampled `0x0102` prefix bytes are unique by exact
  bytes within each file, but have five ASCII-case-folded repetitions. Their
  numeric `0x0101` associations form terminating candidate chains in this
  sample; runtime traversal remains unverified. See [the comparison](research/srsc-0102-runtime.md#0x0101-association-and-prefix-bytes-2026-10-18).
- **Observed (2026-10-18):** 271 sampled nonzero type-5 flagged-range high
  words match one ID in each same-path descriptor; all 129 strictly formatted
  type-10 tag occurrences match inventoried zero-third `0x0400` selectors.
  These are conditional numeric joins, not established runtime associations;
  see [the comparison](research/srsc-0102-runtime.md#range-values-and-type-10-selector-comparison-2026-10-18).
- **Observed (2026-10-18):** candidate metadata identifies flagged array-unit
  intervals and type-10 candidate spans. In 4,203 hash-checked US records,
  the nonempty spans cover all 6,486 units beyond the matched base counts,
  without overlap in this sample. Runtime processing and general validity
  remain unverified; see [the bounded comparison](research/srsc-0102-runtime.md#flagged-ranges-and-type-10-spans-2026-10-18).
- **Observed (2026-10-18):** a correction to the `0x0102` lookup trace:
  zero keys return the receiver rather than zero, preserving the low half
  on the traced consumer path. Array metadata also routes two conditional
  unit types through that lookup. The measured resource and same-path file
  comparisons do not establish runtime source pointers or dispatch; see
  [the trace and measurements](research/srsc-0102-runtime.md#array-processing-and-metadata-comparison-2026-10-18).
- **Observed (2026-10-18):** the conditional `0x0102` comparison table can come
  from a named module resource. All 4,203 sampled records match keys and
  comparison values in the corresponding resource of the pinned US retail
  `Dragon.rfl`; the runtime module path and execution remain unverified. See
  [resource provenance](research/srsc-0102-runtime.md#candidate-resource-table-provenance-2026-10-18).
- **Observed (2026-10-18):** after its known prefix, a conditional `0x0102`
  path compares one dword and requests a count of four-byte units from the
  next. All 4,203 measured US records contain the indicated units, while 4,185
  have additional opaque data; runtime matches and unit meanings remain open.
  See [the conditional trace](research/srsc-0102-runtime.md#conditional-dword-array-follow-up-2026-10-18).
- **Observed (2026-10-18):** a conditional runtime path passes a transformed
  `0x0102` payload dword to a model cache and, on a miss, to a `0x0200` search.
  A lexical inventory comparison found 416 selector matches among 418 unique
  candidate model occurrences, with two missing; this does not establish
  runtime path resolution. See [the trace](research/srsc-0102-runtime.md).
- **Observed (2026-10-18):** in 4,203 hash-verified US `0x0102` records, a
  word skipped by one traced consumer equals the third selector and matches
  one same-file `0x0101` second selector. The same comparison holds for only
  10 of 1,561 `0x0302` records. These sample observations do not establish a
  runtime link; see [the comparison](research/srsc-0102-runtime.md).
- **Observed (2026-10-18):** a descriptor-loading path passes its selected
  object through a helper to the `0x0102` consumer, which uses a payload high
  word to search the object's dependency pairs. In 39 hash-verified same-path
  `.odb`/`.db` pairs, six of 432 nonzero key occurrences lack a matching
  descriptor ID; all 39 `.odb` gate records carry the consumer's expected
  value. Runtime execution and file association remain conditional; see
  [the trace and measurement](research/srsc-0102-runtime.md).
- **Observed (2026-10-18):** the retail loader can stably reorder the in-memory
  record table by its second selector word. Two lookup paths select the first
  matching triple or pair, respectively, under their traced ordering
  assumptions. A hash-checked scan found three duplicate triples and changed
  table positions in 112/178 US samples. See [SRSC lookup order](research/srsc-lookup-order.md).
- **Observed (2026-10-18):** a separate texture selector path compares all
  three words with a zero third word. All 5,993 sampled selector-`0x0040`
  records have zero there, so modeled pair and zero-third lookups agree for
  those files; runtime source equivalence is unknown. See [selector 0x0040](research/selector-0040-behavior.md#selector-comparison-follow-up-2026-10-18).
- **Observed (2026-10-18):** a retail model-loading path reads point triples
  and variable-length groups from adjacent SRSC records. An independent scan
  matched the inspector for 3,221 model pairs in 29 hashed US `.mod` files;
  topology, materials and rendered appearance remain unresolved. See
  [model geometry records](research/model-geometry-records.md).
- **Observed (2026-10-18):** the selected level cell four-point and triangle
  paths use different word scale constants, 1/65536 and approximately 1/65535
  respectively. The previous draw note incorrectly described them as identical;
  see the corrected [cell drawing trace](research/level-cell-draw-behavior.md)
  and [corner associations](research/level-cell-topology.md).
- **Observed (2026-10-18):** a retail database-loading path reads a `.db`
  text descriptor with version and dependency fields. All 39 hash-verified US
  samples matched the restricted inspector; same-path level directory ID sets
  differed for all 20 paired levels. See [database descriptors](research/database-descriptors.md).
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
