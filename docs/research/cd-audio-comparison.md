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
little-endian samples at 44,100 frames per second. Byte equality and discovered
frame offsets do not depend on sample endianness. No resampling, gain matching,
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
2026-10-17. The script records the NumPy version in its private report. It is a
research tool, not an engine or build dependency.

The original two CUEs, sixteen BINs and separate patch ZIP also have a private
SHA-256 archival manifest. On 2026-10-17 all 19 entries passed verification:

```sh
sha256sum 'Drakan - Order of the Flame (USA)'/* 'Drakan - Order of the Flame (Europe)'/* drakan_patch445_eng.zip > research/exports/audio-comparison/archival.sha256
sha256sum -c research/exports/audio-comparison/archival.sha256
```

This identifies the supplied patch archive; it does not establish the version
of any extracted or installed patch executable.
