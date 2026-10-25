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

## Coverage map

The [research coverage map](research/coverage-map.md) gives a bounded,
reproducible view of topic states and next questions. Its totals count tracked
topics by evidence and implementation category; they are deliberately not a
percentage of compatibility.

## Current observations
- **Observed, static; bounded implementation (2026-10-25):** one verified US-retail constructor path reads a 16-bit `0x0502` count, then a `52 × count` byte span and advances through 52-byte rows. The engine now exposes opaque, input-backed rows plus a caller-selected helper for the measured stable-order `0x0501`/`0x0503`/`0x0502` neighbor run. Synthetic tests cover missing neighbors, invalid order entries, truncation, maximum count, and opaque tails; no selector, row, ownership, or runtime semantics are claimed. See [SRSC record behavior](research/srsc-record-behavior.md) and [ADR 0027](decisions/0027-srsc-0501-trio-and-0502-rows.md).
- **Observed and measured, bounded (2026-10-24):** one hash-pinned retail path selects a `0x0501` record, skips its 16-bit-length-prefixed bytes, then reads seven raw dwords; the 1,722 installed-US samples retain an uninterpreted 16-byte remainder. The engine now has a caller-selected structural reader for exactly that prefix, with synthetic truncation checks. It neither validates a full grammar nor establishes runtime execution; see [SRSC record behavior](research/srsc-record-behavior.md) and [ADR 0026](decisions/0026-srsc-0501-observed-prefix.md).
- **Measured, bounded (2026-10-24):** all 4,445 installed-US `(1,0,0)` entries have nonzero measured width and height. The 509 raw-discriminator-2 entries account for 103,391 grid items and 91,299 cells, so they are not a zero-area/cell-free exceptional category in this sample. Field and runtime meanings remain unknown; see the [discriminator census](research/level-discriminator-shapes-2026-10-24.md).
- **Measured, bounded (2026-10-25):** in the same 23 hash-pinned US levels, the signed cell reference values at `+2` and `+6` have 1,622 distinct scalar values and 3,538 distinct ordered pairs across the sample. 545 scalar values and 854 ordered pairs occur in multiple levels; 249/253 level pairs share at least one of each. Seven synthetic tests for each aggregate tool passed, including capped snapshot reads. Repetition is an equality measurement only and does not establish namespace or runtime identity; see the [scalar reuse note](research/level-cell-reference-reuse-2026-10-25.md) and [ordered-pair note](research/level-cell-reference-pairs-2026-10-25.md).
- **Measured, bounded (2026-10-24):** within the previously aligned Europe track-8 tail, 174,867/175,054 channel samples are nonzero. Under conditional signed-little-endian decoding, all 20 non-overlapping 100 ms RMS windows are at or above -50 dBFS; this is not an audibility finding. See [the level-bounds note](research/audio-track8-level-bounds-2026-10-24.md).
- **Measured, static (2026-10-25):** an aggregate exact-byte search found none of the 353 complete frame tokens from 23 verified US levels in either the exact 1,724,416-byte US `Dragon.rfl` or the 552,960-byte retail `Drakan.exe` snapshots. This excludes literal storage in those two snapshots only, not runtime construction, transformation, another module, or other editions; see the [frame consumer follow-up](research/level-entry-caller-followup.md#exact-level-frame-token-search-in-us-code-and-module-snapshots-2026-10-25).
- **Observed, static (2026-10-22):** an independent Ubuntu REA/Ghidra
  investigation of the hash-matched US retail executable corroborated the
  existing loader report: `0x0047D900` contains `SRSC`, and the loader at
  `0x0045EDC0` reads 12 header bytes, checks version `0x0100`, and reads a
  count-derived 14-byte table. A bounded startup map records the entry,
  window/message loop, termination path and imports; subsystem labels remain
  interpretations. The loader result adds independent provenance, not new
  format semantics. Local `objdump` verification and reproduction gaps are
  recorded in the [research handoff](research/rea-windows/README.md).
- **Measured, bounded (2026-10-23):** a fresh US/Europe audio comparison from single CUE/BIN byte snapshots reproduces the +673-frame offset for tracks 2–8, with no differing aligned frames on tracks 2–7 and 87,527 differing frames in track 8. The exact byte/frame comparisons are independent of sample endianness. The hash-checked `tools/disc/measure_cdda_byte_order.py` centered-window spectral comparison favors little-endian decoding. A five-position-per-track check gives a similar median over 34/35 US and 35/35 Europe windows, though several windows favor big-endian; this supports a signal-shape inference, not independent decode or source provenance. RMS and amplitude metrics remain conditional because BIN extraction provenance and byte-swap setting are unknown. The later symlink-boundary hardening and exact-two-CUE validation pass 13/13 disc-tool tests; the repository's research suite passed 347/347 before the current SRSC additions and 361/361 after them. See the [audio comparison](research/cd-audio-comparison.md).
- **Measured, hash-pinned audio recheck (2026-10-24):** all 19 archival CUE/BIN/patch hashes passed; fresh full-track and adjacent-boundary reports exactly matched their stored measurements. Five-window byte-order medians again favored little-endian, lower in 30/34 usable US and 30/35 Europe windows, without proving BIN byte-order provenance. All 13 disc-tool tests passed. These measurements establish sample differences, not musical content or mastering intent; see the [audio comparison](research/cd-audio-comparison.md).
- **Observed, static (2026-10-23):** the pinned US executable has a bounded `(0x0022,0,0)` lookup consumer at `0x0040E3CA`, followed on success by a count read, length-prefixed strings, and two indirect calls. A hash/size-checked scan found no matching tuple in 178 examined US SRSC containers. This does not establish entry-point reachability, runtime use, or selector meaning; see the [consumer note](research/srsc-selector-0022-consumer-2026-10-23.md).
- **Observed, static (2026-10-23):** the hash-pinned bounded-read census finds 103 direct calls to `0x0045F2D0`. The conservative checker classifies 42 callsites with constant requested lengths and anchors the derived `0x0042499F` masked-count×10 request separately; 60 calls remain unknown to its constant-only analysis. Two manual, argument-to-store-traced batches add 14 mutation-checked variable-size expressions, including a conditional `16n`/`60n` request and a gated `4n` read; these fourteen still appear in the constant analyzer's unknown set. The checker rejects argument stack changes, aliasing memory writes, skipped definitions and register clobbers. Four candidate constants whose post-push ESI/EBP writes could not be proven disjoint were left unknown. These are static request-byte expressions, not field semantics, runtime outcomes, or a general payload grammar; see the [reader behavior note](research/srsc-record-behavior.md#additional-bounded-request-size-callsites-2026-10-23).
- **Observed, static (2026-10-24):** the extended hash-pinned census still finds 103 direct bounded-read calls. It classifies 42 local constants and anchors 34 additional request expressions plus the derived `masked_count * 10` call; 26 calls remain unresolved. Exact instruction anchors cover a first-match two-word `(0x0501, second word)` lookup and its I/O sequence, with six direct callers to the upstream key-lookup routine. Caller field meanings, runtime reachability and payload grammar remain unknown. See the [reader behavior note](research/srsc-record-behavior.md#two-word-selector-caller-path-2026-10-24) and [bounded-size follow-up](research/srsc-record-behavior.md#additional-bounded-read-size-formula-2026-10-24).
- **Observed, static (2026-10-24 recheck):** a separate bounded review added 11 exact request expressions or constants to the pinned direct-read census, including 2-, 4-, and 48-byte requests and counts copied from local/object fields. The verifier now covers 536 variable-size instruction addresses across 45 formula callsites; 42 requests remain classified as local constants, one as the derived `masked_count * 10`, and 15 direct calls remain unresolved. This does not establish field meaning, runtime reachability, or read success. See the [additional bounded-read expressions](research/srsc-record-behavior.md#additional-bounded-read-request-expressions-2026-10-24).
- **Observed, static (2026-10-24 caller-batch extension):** six more callsites were anchored in the same US retail executable. Three have stack-derived requests, and the string reader's conditional second read requests the lesser of its masked length prefix and capacity. Together with the prior batches, the verifier covers 598 variable-size instruction addresses across 51 formula callsites, with 9 calls still unresolved; meanings and runtime outcomes remain unknown. See the [bounded-read request note](research/srsc-record-behavior.md#additional-bounded-read-request-expressions-2026-10-24).
- **Observed, static (2026-10-24 register-preservation follow-up):** five further request sizes were traced across calls using full instruction anchors for the relevant bounded-read, skip, word-reader, and `0x00409DB0` helper bodies. A separate conditional branch computes `26*A*C + 4*(A+1)*(C+1)` into EBX and carries it across imported allocation calls under the Win32 x86 nonvolatile-register convention. Another call clamps EDI to a table length and carries it across the full `0x0045F270` helper body. A wider trace of `0x0042EEEF` found the table-derived request size is stored in a local distinct from an earlier pointer-valued local after an intervening persistent stack push. A further caller uses as its size value a local targeted as the destination buffer by the four-byte reader at `0x0040BDD9`; read success is not established. The hash-pinned verifier covers 895 variable-size instruction addresses across 60 formula callsites, with no unresolved calls in this direct-call inventory; source meanings and runtime results remain unknown. See the [bounded-read request note](research/srsc-record-behavior.md#additional-bounded-read-request-expressions-2026-10-24).
- **Measured, bounded SRSC payload sample (2026-10-24):** the hash-verified US inventory contains 1,722 `0x0501` records in 12 `.adb` files, with 1,293 second-word values; 242 second-word values occur with multiple payload lengths (up to four). An aggregate-only review measured 1,640 unique payloads and variable NUL-delimited prefixes plus repeated aligned values. Static code also contains a cache-miss path that queries `0x0501` using a caller key's low word, but no caller values have been joined to this asset distribution. These measurements support only a tentative byte-shape observation, not field meanings or runtime execution. Eight synthetic tests and a fresh inventory run passed, including duplicate-path rejection; see the [reader behavior note](research/srsc-record-behavior.md#us-asset-distribution-for-first-selector-0x0501-2026-10-24).
- **Measured, static indexed-record association (2026-10-24):** the verified constructor sorts the loaded table by its second selector, then after its `0x0501` match selects indices `i+1` and `i+2`. In all 1,722 hash-verified US `0x0501` records, those next entries under stable ordering are `0x0503` and `0x0502`, both with the same second selector. Each record is the first matching `(0x0501, second-selector)` key in its own file; selector values can recur across different files. The match supports this specific sample's three-entry association but does not establish a format invariant, field meanings, read success, or runtime execution. Eight synthetic measurement tests passed; see the [bounded reader note](research/srsc-record-behavior.md#two-word-selector-caller-path-2026-10-24).
- **Measured, static payload-count relationship (2026-10-24):** in all 1,722 hash-verified US selector trios, the `0x0503` two-byte prefix matches the `0x0501` post-field DWORD used by the observed `8 × count` read, and the `0x0502` prefix matches the DWORD used by the `52 × count` read. Both payload lengths match `2 + multiplier × prefix`. The current consumer verifier checks 104 instruction anchors tracing the selected data fields, reads, and next-index selection; ten synthetic aggregate-measurement tests passed. This does not establish runtime read success or general field semantics; see the [bounded reader note](research/srsc-record-behavior.md#follow-up-read-path-for-selector-0x0501-2026-10-24).
- **Observed and measured, static `0x0501` read boundary (2026-10-24):** 104 hash-pinned instruction anchors trace a null-output/zero-capacity length-prefixed skip, subsequent fixed-width reads, and selection of index `i+1`. In all 1,722 US sample payloads, 16 bytes remain beyond the `30 + prefix` bytes covered by those reads if they succeed; the constructor advances selection without consuming that suffix. The suffixes have 146 distinct byte sequences and seven constant positions, without field or consumer interpretation. Six instruction-verifier tests and ten layout-measurement tests passed. See the [bounded reader note](research/srsc-record-behavior.md#follow-up-read-path-for-selector-0x0501-2026-10-24).
- **Measured, static `0x0501` suffix cross-kind scan (2026-10-24):** for all 1,722 suffixes in the 12 US containers, no complete 16-byte sequence appears in a payload of another record kind. 1,628 source rows match another `0x0501` payload, representing 90 distinct suffix sequences counted per container; each repeated source suffix matches only other rows with different second selectors. Seven synthetic tests exercise same-kind, cross-kind, and selector-repeat cases; this repetition does not identify a consumer or field meaning. See the [suffix search](research/srsc-record-behavior.md#exact-suffix-searches-in-other-srsc-payloads-2026-10-24).
- **Measured, static SRSC payload extent association (2026-10-24):** in the 12 US `.adb` files with `0x0501`, 1,722 first-match `0x0501/0x0503/0x0502` trios have contiguous, bounded payload extents in selector order; the groups start at byte 12 and are gap-free. Each file then has a six-byte `(0x0500,0,0)` extent and four-byte `(0x0402,0,0)` extent filling the final ten bytes before the table. This sample-specific packing does not establish record meaning, shared ownership, a format invariant, or runtime use. Ten synthetic tests passed; see the [payload extent note](research/srsc-record-behavior.md#payload-extents-for-stable-order-selector-trios-2026-10-24).
- **Observed, static selector-`0x0501` follow-up (2026-10-24):** exact anchors in the hash-pinned US executable verify an `8 × count` read, a later `52 × count` read, and a following 52-byte repeated stride that scales three dwords per unit. The full-image verifier pins six callers to the upstream routine, one to its wrapper, and four to the pair-selector loader; 18 instruction anchors classify the six upstream DWORD sources as forwarded stack arguments or caller/table `+4` fields. This does not establish field meanings, read success, or runtime execution; see the [bounded read path note](research/srsc-record-behavior.md#two-word-selector-caller-path-2026-10-24).
- **Observed, Ghidra database recheck (2026-10-24):** a serialized read-only/no-analysis query returned 103 direct-call references to `0x0045F2D0`, and all 103 addresses matched the separate hash-pinned objdump census. The saved-log verifier's four synthetic tests cover provenance, duplicate/missing entries, reference type, count and truncation errors. This checks stored database references only and does not rule out indirect/computed calls; see the [read-helper recheck](research/srsc-record-behavior.md#ghidra-read-helper-reference-recheck-2026-10-24).
- **Measured, bundled PE resources (2026-10-24):** a size/SHA-verified scan of 21 Mplayer-group PEs counted 229 resource entries across 12 numeric IDs and `TYPELIB`, using the exact input snapshots with `wrestool` 0.32.3. Four synthetic tests passed. The aggregate reports resource types only and does not establish their meaning or runtime use; see the [retail asset inventory](research/retail-asset-inventory.md#mplayer-pe-resource-type-inventory-2026-10-24).
- **Observed, bounded level-frame cross-kind scan (2026-10-24):** 353 distinct complete serialized frame tokens from 13,418 level-frame occurrences were searched across 38,926 records in 178 hash-verified US SRSC files. Every token appeared in at least one `0x0102` record; exact matches occurred in 3,877/4,203 such records and no other record kinds beyond the source level records. This unordered match does not identify producer, source association, or semantics; five synthetic tests passed, including symlinked inventory-path rejection. See the [cross-kind search note](research/level-frame-cross-kind-search-2026-10-24.md).
- **Coordinator reproducibility pass (2026-10-24):** the retail inventory generator recreated 337 US installed-file entries and exactly matched the private JSON manifest; all 178 candidate SRSC tables again ended at EOF. The complete research, disc-tool, and Ghidra bridge Python suites passed 417, 13, and 6 tests; coverage-map verification validated 17 topics; current debug and release builds had no pending work and CTest passed 17/17 in each; both staged and worktree `git diff --check` passed. The fresh audio comparison and tail analysis matched stored measurements, with only the explicit sample-interpretation metadata differing in the full comparison report. These checks establish reproducibility for the recorded inputs, not runtime semantics or compatibility.
- **Coordinator installed-tree recheck (2026-10-25):** a fresh inventory generator pass recreated all 337 US installed-file entries and exactly matched the private JSON manifest; all 178 candidate SRSC tables ended at EOF. The comparison snapshot was kept in `/tmp`, outside Git.
- **Observed, bounded installed-text inventory (2026-10-24):** the hash-verified US Mplayer `mpurl.dat` is 2,500 ASCII bytes with 12 `http://` tokens, while three `.lfl` and one `.mpl` samples have CRLF path-like row shapes ending in `.lvl` or `.reo`. The scans emit aggregate structure only and do not establish file grammar, consumers, or network behavior; eight combined synthetic tests passed. See the [MPURL note](research/mplayer-mpurl-dat-2026-10-24.md), the [LFL/MPL note](research/retail-lfl-mpl-text-lists-2026-10-24.md), and the [retail inventory](research/retail-asset-inventory.md#bounded-text-shapes-in-lfl-mpl-and-mplayer-mpurldat-2026-10-24).
- **Measured, bounded list-to-inventory candidates (2026-10-25):** all ten path-shaped `.lvl` rows in the three hash-pinned `.lfl` files have unique basenames in the 337-file installed inventory, but no full-path match. The 16 `.reo` rows in the `.mpl` file have no basename matches. Five synthetic tests pass; this does not establish how the lists are resolved or whether they are used. See the [aggregate measurement](research/lfl-mpl-inventory-links-2026-10-25.md).
- **Observed, static Mplayer filename reference (2026-10-24):** among 21 hash-pinned Mplayer-group PE files, only `mIC.exe` contains the ASCII `mpurl.dat` literal (offset `0x2d850`), passed as an argument at `0x00402b6f`; ten instruction anchors include the following call at `0x00402b80`, whose thunk resolves through IAT RVA `0x42b58` to MFC42 ordinal 924; its identity and effect remain unknown. The hash-pinned retail executable has no ASCII or UTF-16LE literal. Eight synthetic tests passed; runtime file access and network behavior remain unknown. See the [MPURL note](research/mplayer-mpurl-dat-2026-10-24.md).
- **Observed, static Mplayer CSV filename references (2026-10-25):** hash-verified `mphisto.csv` and `mpusage.csv` files yielded inconsistent aggregate CSV row widths; exact filename literals appeared only in `gizmo.ocx` among 21 hash-pinned Mplayer PEs plus retail `Drakan.exe`. Forty-three anchored instructions show each name formatted into a `%s\\%s` path, passed to `fopen` with mode `wb`, and followed by `fwrite`/`fclose` on both non-null handle branches. Runtime execution, successful writes, output contents and purpose remain unknown. Classifier and static-verifier synthetic tests pass. See [CSV candidate note](research/mplayer-csv-candidates-2026-10-25.md).
- **Measured, static `0x0502` row float slots (2026-10-25):** three 52-byte-row dwords at offsets 40, 44, and 48 feed a multiply by 2048.0; the pinned scalar bytes are verified from the retail executable snapshot. A hash/size-verified census found all 1,722 `0x0502` records in the 178-file US inventory belonged to the selected trios; each of the three slots has 1,350,554 finite float32 interpretations. Raw ranges are recorded without naming fields. Five measurement tests and eight consumer-verifier tests pass. See [the bounded note](research/srsc-0502-float-slots-2026-10-25.md).
- **Measured, bounded SRSC table correlations (2026-10-23):** a new hash/size-verified scan found unique same-file matches from all 3,122 `0x0207`, 99 `0x0208`, and 3,122 `0x0209` third words to `0x0201` second words. Target table entries precede sources in 3,101, 99, and 3,101 cases, respectively. The inspected model consumer does not anchor these words, so this does not establish runtime association or selector meaning; see the [SRSC lookup note](research/srsc-lookup-order.md#additional-selected-third-to-second-correlations-2026-10-23).
- **Measured, bundled PE metadata (2026-10-23):** all 21 Mplayer-group PE files match the private US inventory; 12 have VERSION resources and none has RT_MANIFEST. Embedded description/product strings are distinct per file; a Sound.ocx file/product version mismatch is observed but does not establish a packaging problem. Static imports show internal Mplayer dependencies but none named by `Drakan.exe`, and its printable bytes contain no Mplayer PE basenames; constructed names or dynamic loading remain possible. See the [retail asset inventory](research/retail-asset-inventory.md).
- **Observed, extraction provenance (2026-10-23):** the existing US and UK disc trees each have all 2,033 ISO files and 85 non-root directories; fresh xorriso 1.5.8.pl02 extracts matched every node and file SHA-256. Unshield 1.6.2 extracted the US cabinet's `English - Mplayer Files` group, and all 21 PE members matched the installed copies and inventory hashes. These checks establish disc-tree fidelity and cabinet membership for those PE files; they do not establish installer behavior outside the listed group or runtime use. See the [retail asset inventory](research/retail-asset-inventory.md#disc-extraction-tree-coverage-2026-10-23).
- **Observed, bounded palette bytes (2026-10-23):** the inventory-hash-verified `mic.pal` contains 256 distinct four-byte rows with zero fourth bytes and a four-byte trailer whose second byte is nonzero. Its row layout matches the documented simple Windows RIFF PAL `LOGPALETTE` structure; the extra bytes remain unexplained. Hash-verified disassembly follows the Mplayer `mIC.exe` `%s\mic.pal` path template through `fopen`/`fread` and a fixed 256-entry loop that skips the fourth byte and the trailer. Its `>1,024`-byte gate is shorter than the 1,048 bytes processed; behavior on malformed shorter files is unknown. A single direct caller exists at `0x00416979`, but runtime execution and game linkage remain unverified. See the [retail asset inventory](research/retail-asset-inventory.md#mplayer-palette-loading-path-static-review-2026-10-23).
- **Measured, bounded resource container (2026-10-23):** the hash-verified common-data `LevelFileList.ico` has two in-bounds BI_RGB DIB images at 32×32 and 16×16, both 4 bpp; no trailing bytes were found. Consumer and visual role remain unknown. See the [retail asset inventory](research/retail-asset-inventory.md#common-data-ico-container-check-2026-10-23).
- **Local CI evidence (2026-10-24):** a reviewed 400-file helper-generated source snapshot, including the selector-path, payload-extent, and resource-inventory tools, passed fresh GCC 15.3.1 debug/release builds and 17/17 CTests each; its Python suites passed 393 research, 13 disc, and 6 Ghidra tests. The snapshot excluded private top-level `research/`, Git metadata, media and executable binaries. This does not verify hosted Linux CI; `actionlint`, `act`, and a container API socket are unavailable in this checkout. See [CI notes](CI.md).
- **Observed and inferred (2026-10-19):** a `0x0302` new-object path builds a
  candidate waveform-format structure and passes it through a conditional
  buffer-creation interface. All 1,561 sampled records have values consistent
  with mono 8- or 16-bit waveform data at three sample rates, and their sizes
  align to the derived frame size. Actual runtime dispatch and playback are
  unverified; see [the trace](research/srsc-0302-selector-followup.md#candidate-waveform-format-and-buffer-path-2026-10-19).
- **Measured (2026-10-19):** the candidate level-object/`0x0102` joins that
  yield matching frame text do not yield generally equal neighboring array
  units. Under the overlay hypothesis, 1,754 of 13,418 compared pairs match,
  including 944 zero pairs. Conditional ranges and runtime selection remain
  unresolved; see [the bounded comparison](research/level-entry-caller-followup.md#candidate-array-value-comparison-2026-10-19).
- **Observed, static (2026-10-19):** the candidate RFL raw-write forwarder
  can receive the same writer pointer used by an executable `0x0102` writer,
  under the documented interface-table and unchanged-state assumptions.
  The resulting file and actual dispatch remain unknown; see [the writer
  context](research/srsc-0102-runtime.md#module-write-context-2026-10-19).
- **Measured (2026-10-19):** within the 87,527 Europe track-8 frames aligned
  to the US zero tail, 100 ms stereo RMS windows decrease in 18 of 19
  transitions, with one increase; first/last window RMS is 1,599.635/200.996.
  This indicates a broad decline in the measured envelope, not a conclusion
  about audibility, music or mastering; see the [track-8 note](research/audio-track8-tail.md#short-window-rms-envelope-2026-10-19).
- **Measured (2026-10-19):** a fresh hash inventory exactly matches the
  private 337-file US installed-tree manifest, including 178 SRSC candidates
  with tables ending at EOF. `file` identifies the three `.lfl` files and one
  `.mpl` as ASCII, one `.pal` as RIFF `PAL `, and 21 PE32 executables/DLLs/
  OCXs in the separate Mplayer extraction group. The palette has unexplained
  chunk bytes under a four-byte-entry calculation; runtime use, software
  provenance and other editions remain unknown; see the
  [retail inventory](research/retail-asset-inventory.md).
- **Observed, static (2026-10-21):** bounded byte inspection of the hash-verified
  `.mpi` and `.tln` files found NUL-padded printable fields in the 1,620-byte
  `.mpi` and no recognizable signature in the 32-byte `.tln`; their formats
  and runtime roles remain unknown. A GNU `strings` scan of the hash-matched
  US retail executable found no literal filename/suffix matches for those
  files, and its generic `CreateFileA` import does not identify them as inputs.
  A 2026-10-23 hash-verified scan found generic `.mpi` strings in four of the
  21 Mplayer PE files, but no exact `mpdrakan.mpi` or `.tln` reference there;
  runtime use and format remain unknown. The scan is reproducible with
  `tools/research/scan_mplayer_pe_references.py`; see the
  [retail inventory note](research/retail-asset-inventory.md).
- **Measured (2026-10-19):** 13,418 level frames match indexed candidate
  `0x0102` frames byte-for-byte under an installer-overlay hypothesis, and
  match descriptor flags and descriptor-relative text in the pinned RFL.
  Separately, all 4,203 sampled `0x0102` tails fit a descriptor-count frame
  model and all 77,772 frame flags and text match the candidate descriptors.
  Producer, text meaning and runtime source association remain unknown; see
  [level frames](research/level-entry-caller-followup.md#frame-text-and-candidate-0x0102-comparison-2026-10-19)
  and [0x0102 tails](research/srsc-0102-runtime.md#metadata-frame-tail-comparison-2026-10-19).
- **Observed, static (2026-10-19):** the retail executable exposes an
  RFL-filtered file dialog and resolves `GetRFLInterface`; the pinned
  `Dragon.rfl` has a matching slot-`0x9c` raw-write forwarder. Its candidate
  writer selects a descriptor from the input object's word at `+2`, then
  writes a descriptor-derived 16-bit value and a byte span pointed to by
  object `+0xa0`; its static process-attach path walks an initializer table
  containing the interface-table installer, and its only found direct caller
  is the slot-`0x9c` forwarder. No runtime module selection, selected record
  or relationship to selector-`0x20` frames is established;
  see the [bounded interface and
  writer trace](research/srsc-0102-runtime.md#rfl-module-selection-path-2026-10-19).
- **Observed (2026-10-19):** one conditional level-object helper searches a
  word array by value and uses its first matching position to address a
  separate dword array on a selected path. In 5,384 sampled objects the word
  count never exceeds the dword count, but 5,684 word values exceed or equal
  that count. Runtime dispatch and semantics remain unknown; see [the trace](research/level-entry-caller-followup.md#conditional-word-array-lookup-2026-10-19).
- **Measured (2026-10-19):** with an installer-overlay assumption, each of
  5,384 array-bearing level objects has a unique candidate `0x0102` and RFL
  metadata entry; all 13,418 word indices fit and the skipped frame prefixes
  equal their candidate descriptor flags. Candidate flagged and type-10
  spans cover all 1,145 extra array units without overlap. Runtime joins and
  frame semantics remain unknown; see [the comparison](research/level-entry-caller-followup.md#metadata-and-conditional-array-candidates-2026-10-19).
- **Observed (2026-10-19):** conditional selector `(0x20,0,0)` framing fits
  all 16,312 declared objects in 23 hashed US levels. Of their third dwords,
  834 match a same-file level entry and 16 nonzero values do not; all 16 occur
  in other sampled levels. The 5,909 candidate object-index words are in
  range, but most directed relations have no reverse. Runtime associations
  remain unverified; see [the object trace](research/level-entry-caller-followup.md#conditional-full-object-framing-2026-10-19).
- **Measured (2026-10-19):** hypothetical cached-object `0x0302` offsets
  yield nonzero modes and zero- or one-byte stored inputs for all 1,561 sampled
  records. The branch's actual cache state and processing remain unknown; see
  [the cached-path comparison](research/srsc-0302-selector-followup.md#cached-object-offset-comparison-2026-10-19).
- **Observed (2026-10-19):** one `0x0302` consumer has different new-object and cached-object read offsets; 1,561 sampled records fit the hypothetical new-object framing, and all 390 nonzero spans decoded as complete zlib streams to the indicated size. Runtime state and decoded meaning remain open; see [the selector follow-up](research/srsc-0302-selector-followup.md).
- **Observed (2026-10-19):** a selector `(0x20,0,0)` object value is looked up against level entry first dwords, with conditional later use of the index; sampled first objects do not establish full framing. See [the caller trace](research/level-entry-caller-followup.md).
- **Measured (2026-10-19):** 35 of 41 type-12 candidate ranges match a unique level under both numeric and direct lexical-source comparisons; six do not. The overlay hypothesis yields 35 unique, one multiple and five none. Runtime associations remain unverified; see [the comparison](research/level-0001-prefix.md#directory-name-comparison-for-type-12-candidate-ranges-2026-10-19).
- **Observed (2026-10-19):** a retail helper finds the first level entry whose first dword matches its argument. Across 41 sampled type-12 candidate ranges, all values have a common matching level, but 20 ranges have multiple common levels. Runtime association remains unknown; see [first-dword lookup](research/level-0001-prefix.md#first-dword-lookup-and-type-12-candidates-2026-10-19).
- **Observed (2026-10-19):** each of 4,445 US level entries contains its own index once among 207,353 raw inner values. Static code records the self position and first and last strictly overlapping candidates; sampled overlapping positions are not always contiguous. Runtime meaning remains unresolved; see [level inner-value relations](research/level-0001-prefix.md#inner-value-consumer-and-sample-relations-2026-10-19).
- **Observed (2026-10-19):** six static loader stages select `(0x0402,0,0)` and compare stage-specific dwords; all 153 US inventory files in their corresponding suffix groups have one gate with the matching value. Runtime source paths and pointer aliasing remain unknown; see [the stage trace](research/srsc-0102-runtime.md#remaining-source-object-loader-stages-2026-10-19).
- **Observed (2026-10-19):** in 4,185 nonempty sampled `0x0102` tails, a candidate 16-bit length including the following two bytes fits in every record, but two simple count models explain only one complete tail each. The actual grammar remains unknown; see [tail framing hypotheses](research/srsc-0102-runtime.md#tail-framing-hypotheses-2026-10-19).
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
- **Observed and measured (2026-10-25):** one level-cell path consumes 26-byte
  serialized rows with a 22-byte runtime stride, resolves two keyed dwords,
  and complements all four trailing words into the runtime row. In 23
  hash-verified US levels, 521,441
  of 542,791 measured reference pairs are equal and 21,350 differ. Of the
  1,085,582 references, 335,828 have their high bit set and none are zero. No field
  meaning is established; see the [cell reference layout](research/level-0001-cell-reference-layout-2026-10-25.md).
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
- **Observed (2026-10-25):** a hash-checked remeasurement of all 5,993 US
  texture headers found offset-14 values 0, 1, 4 and 8, with no example of
  the value-2 descriptor branch. Seven records set flag `0x100000` and 1,802
  set `0x200`. Static code has a separate device-state gate that can bypass
  standard surface creation, so header counts do not prove runtime reachability.
  See [texture header branch coverage](research/texture-header-branch-coverage-2026-10-25.md).
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
