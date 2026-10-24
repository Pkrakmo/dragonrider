# US and Europe retail CD audio comparison

**Investigation:** 2026-10-17. Inputs are the original, user-owned US and
Europe CUE/BIN sets at the paths in the README. They were read only. The
private report `research/exports/audio-comparison/us-uk.json` records the CUE
and all eight BIN filenames, lengths, SHA-256 digests, CUE indexes, per-track
program-region hashes, and comparisons. It does not contain audio samples.
The Europe edition is identified as English/UK from the prior user report;
this comparison establishes properties of these two physical image sets, not
all pressings of either edition.

## Method and scope

Both CUEs describe one binary file per track. Tracks 2–8 are AUDIO; each has
INDEX 00 at `00:00:00` and INDEX 01 at `00:02:00` (150 sectors, 352,800
bytes). Comparing the program region therefore starts after the first two
seconds in **each** BIN, rather than assuming the whole BIN is program audio.
Each CD sector is 2,352 bytes, or 588 four-byte interleaved stereo frames.
The numerical sample calculations interpret each frame as two signed 16-bit
little-endian samples at 44,100 frames per second. This byte order is an
analysis assumption: the CUE files do not identify how the BIN data was
extracted. Raw-audio tools differ by output path: cdrdao documents raw output
as big-endian, while bchunk exposes an optional byte-swap operation. These
documents do not establish the byte order of these particular BINs. Byte
equality and discovered frame offsets do not depend on sample endianness;
signed amplitude, RMS, and sample-step figures do. Until source-rip provenance
or an independent decode confirms byte order, those numeric observations are
conditional on the little-endian interpretation. No resampling, gain matching,
lossy encoding, channel swapping, or audio fingerprinting was applied.

The script searches 64-byte exact anchors at three widely separated positions
in the US program region. It intersects their UK frame offsets, and only
reports an offset if at least two usable anchors agree on a unique result.
It then compares every overlapping stereo frame, not just the anchors. If the
anchors cannot establish a unique shift, it reports no aligned comparison:
this is **not** evidence of different recordings. Direct same-INDEX comparisons
are also recorded. The analysis does not compare INDEX 00 pregap audio, the
non-overlapping boundaries, or beyond the track file. It cannot determine why
an offset exists, whether the difference is audible, or whether other image
sources agree. Its CUE parser intentionally rejects unsupported layouts and
synthetic PREGAP directives rather than guessing their meaning.

## Observed

All seven audio BIN pairs have equal file lengths but different SHA-256 hashes.
For each of tracks 2–8, the three anchors agree that the matching UK frame is
673 frames later than the US frame measured from INDEX 01. This is 2,692 bytes,
or approximately 15.26 ms. The single offset cannot establish whether the
difference originated in a disc master, image extraction, or another source.

After this alignment, the US overlap starts at its program frame 0 and the UK
overlap at program frame 673. Tracks 2–7 are byte-identical over their entire
aligned overlaps; 673 US frames at the end and 673 UK frames at the start are
outside each comparison. This does **not** establish the boundaries match.

| Track | Overlap frames | Differing frames |
| --- | ---: | ---: |
| 2 | 9,907,715 | 0 |
| 3 | 10,733,855 | 0 |
| 4 | 11,527,067 | 0 |
| 5 | 10,422,803 | 0 |
| 6 | 10,712,099 | 0 |
| 7 | 12,754,223 | 0 |
| 8 | 9,477,887 | 87,527 |

For track 8, the aligned comparison has identical frames through frame
9,390,359; each frame from 9,390,360 through 9,477,886 differs. That final
87,527-frame interval is about 1.985 seconds. An independent NumPy check found
all 175,054 US channel samples in that interval are zero, while 174,867 of the
UK channel samples are nonzero. The two images thus contain a real sample
content difference there, beyond the common shift; its cause and perceptual or
musical significance are unknown. The following hashes were independently
checked with `sha256sum` against the private report:

| Input | SHA-256 |
| --- | --- |
| US CUE | `11c6ab929bba1143a6e39e0661773fa79268ca19292225819208be73c9931ad7` |
| Europe CUE | `a15303d32a4b0e5ccae6dc29a5efbeda2476d2775d5933f1ebfbf4c0e6c210c2` |
| US track 8 BIN | `26972b82a995d7a0bff99445ea88681be525635bc086ec6dbc369bccf490b7df` |
| Europe track 8 BIN | `ac2fb5635365c786b17fc6568b277f15a4ec58c38b60c2d3997fcd5ea2bf2d95` |

On 2026-10-19, the full anchor-and-overlap comparison was rerun with Python
3.14.7 and NumPy 2.3.5 after all 19 archival manifest entries verified. All
three usable anchors on each AUDIO track again supported the +673-frame
alignment. The aligned program overlaps for tracks 2–7 had zero differing
frames; track 8 again had 87,527 differing frames in its 9,477,887-frame
overlap, beginning at overlap frame 9,390,360. The fresh aggregate report is
private under ignored `research/exports/audio-comparison/`; it contains paths
and hashes, not audio samples.

## Reproduction

Python 3 with NumPy is required; the investigation used NumPy 2.3.5. Run from
the repository root with the original paths available. These commands only
read the CUE/BIN files and create a private report beneath ignored `research/`:

```sh
python3 -m unittest discover -s tools/disc -p 'test_*.py' -v
python3 tools/disc/compare_audio.py \
  'Drakan - Order of the Flame (USA)/Drakan - Order of the Flame (USA).cue' \
  'Drakan - Order of the Flame (Europe)/Drakan - Order of the Flame (Europe).cue' \
  research/exports/audio-comparison/us-uk.json
```

The synthetic tests cover positive and negative frame shifts, a changed frame,
silent and nonmatching anchors, different INDEX 01 positions, out-of-range
indexes, path traversal, unsupported CUE directives, and output aliases of
inputs. They passed 4/4 on
2026-10-17. The script records the NumPy version and the assumed, unverified raw sample byte order in its private report. It is a
research tool, not an engine or build dependency.

The original two CUEs, sixteen BINs and separate patch ZIP also have a private
SHA-256 archival manifest. On 2026-10-17 all 19 entries passed verification:

```sh
sha256sum 'Drakan - Order of the Flame (USA)'/* 'Drakan - Order of the Flame (Europe)'/* drakan_patch445_eng.zip > research/exports/audio-comparison/archival.sha256
sha256sum -c research/exports/audio-comparison/archival.sha256
```

This identifies the supplied patch archive; it does not establish the version
of any extracted or installed patch executable.

## Single-snapshot recheck, 2026-10-23

`compare_audio.py` now reads each CUE and track BIN once per comparison and
uses those in-memory byte snapshots for parsing, sizes, SHA-256 values, anchor
search, and PCM comparisons. The CLI also uses the same CUE snapshots for its
output/input collision check and the comparison, so both steps resolve the same
BIN paths. This ensures the reported digests identify the bytes actually
measured. Six synthetic tests passed, including read-count checks for both the
comparison API and CLI. A fresh Python 3.14.7/NumPy CLI run on the
same US and Europe CUE/BIN inputs produced measurements identical to the prior
private JSON after removing input path fields and the new byte-order-assumption
metadata field: each of tracks 2–8 retained
the +673-frame offset; tracks 2–7 had zero differing aligned frames, while
track 8 retained 87,527 differing frames in 9,477,887 aligned frames. The
19-entry private archival SHA-256 manifest also passed. This recheck confirms
the same measured content and improves byte-to-digest provenance; it does not
identify why track 8 differs or establish audibility or musical significance.

An input-boundary review on 2026-10-23 found that the comparator rejected
absolute and parent-traversal names but would follow a symlinked BIN member.
The resolver now rejects symlink components and requires the resolved regular
file to remain within the resolved CUE directory. Temporary tests reproduce
both a symlinked file and a symlinked directory escape. The byte-order
measurement API also now requires exactly two CUE paths; previously one path
raised `IndexError` and extra paths were silently ignored by `zip`. The focused
disc-tool suite passes 13/13 tests after these changes.

## PCM byte-order limitation

The sample-domain metrics above currently interpret each pair of bytes as a
little-endian signed 16-bit value. The exact frame-match counts, alignment, and
zero-byte spans are unchanged if the interpretation is big-endian, but numeric
sample amplitudes, RMS envelopes, and step sizes would change. The original
CUEs do not record which extraction tool or byte-swap setting produced their
BIN files. For example, [cdrdao documents its raw audio output as big-endian](https://github.com/cdrdao/cdrdao),
while [bchunk exposes an explicit optional audio-byte swap](https://github.com/hessu/bchunk/blob/master/bchunk.c).
Neither source identifies the provenance of the files examined here. Treat the
sample-domain numeric conclusions as conditional until rip provenance or an
independent decode resolves this.

A bounded signal-shape cross-check favors the current little-endian
interpretation. `tools/disc/measure_cdda_byte_order.py` verifies the CUE and
AUDIO BIN snapshots against the private archival SHA-256 manifest, then measures
a centered 44,100-frame window after INDEX 01 in each track 2–8 BIN. For each
candidate byte order, it removes the channel mean, applies a Hann window, and
compares summed two-channel FFT power above 20 kHz with power from 20 Hz through
20 kHz. The median ratio was `3.94e-9` (US) and `3.91e-9` (Europe) for the
little-endian interpretation, versus `0.0977` for both editions interpreted
big-endian. The output contains only aggregate ratios; it emits no paths, hashes
or audio bytes. This signal-shape result supports, but does not prove, the
little-endian interpretation: it is not an independent decode, extraction
provenance, or confirmation from the retail disc. The amplitude and RMS
conclusions therefore remain conditional.

A five-position robustness check samples one-second windows at 0%, 25%, 50%,
75%, and 100% of each track's legal program-region start range. Across 34 usable
US windows (one was unusable for lacking finite audible-band power) and 35 Europe
windows, the median high/audible ratio was `5.81e-9` and `6.22e-9` for
little-endian, compared with `0.0986` and `0.0980` for big-endian. The
little-endian ratio was lower than the big-endian ratio in 30/34 US and 30/35
Europe windows; maxima near `0.11` show that this is not true of every window.
This distributed check makes a single centered sample less likely to explain
the aggregate preference, while preserving the same caveat about source byte
order.

Reproduce the bounded check with:

```sh
python3 -m unittest discover -s tools/disc -p 'test_measure_cdda_byte_order.py' -v
python3 tools/disc/measure_cdda_byte_order.py \
  'Drakan - Order of the Flame (USA)/Drakan - Order of the Flame (USA).cue' \
  'Drakan - Order of the Flame (Europe)/Drakan - Order of the Flame (Europe).cue' \
  research/exports/audio-comparison/archival.sha256
python3 tools/disc/measure_cdda_byte_order.py \
  'Drakan - Order of the Flame (USA)/Drakan - Order of the Flame (USA).cue' \
  'Drakan - Order of the Flame (Europe)/Drakan - Order of the Flame (Europe).cue' \
  research/exports/audio-comparison/archival.sha256 --windows-per-track 5
```
