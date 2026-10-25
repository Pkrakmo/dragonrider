# Track 8 aligned-tail level bounds

**Investigation:** 2026-10-24. This narrowly measures aggregate signal levels
in the Europe portion aligned to the previously observed trailing US zero run.
It is not a listening test, loudness measurement, or claim of audibility.

## Method

`tools/disc/measure_track8_tail_levels.py` requires the two original CUEs and
the existing archival SHA-256 manifest. It rejects unlisted, changed, symlinked
or incompatible CUE/BIN inputs, reads snapshots only, and emits hashes plus
aggregate values—never sample bytes. It assumes the established
Europe-minus-US alignment of 673 frames and divides the 87,527-frame aligned
Europe tail into non-overlapping 4,410-frame (100 ms) windows. Per-window RMS
and peak values are compressed into first/last/minimum/maximum dBFS bounds and
counts above fixed signal-level thresholds.

The numeric conversion assumes signed 16-bit little-endian stereo. CUE metadata
does not prove that byte order, so dBFS values remain conditional. The exact
US all-zero boundary and the number of raw zero frames are byte-order
independent. No normalization, resampling, weighting, or hearing model is
applied.

## Observed

The fresh private JSON report retained the known 88,200-frame US zero tail and
87,527 aligned Europe frames. Of 175,054 Europe channel samples in that aligned
region, 174,867 are nonzero. At 100 ms resolution, first/last Europe RMS bounds
are -26.229/-44.245 dBFS and first/last peak bounds are -18.049/-37.782 dBFS.
All 20 windows are at or above -50 dBFS RMS, 13 are at or above -40 dBFS, and
two are at or above -30 dBFS. These are unweighted signal-level aggregates,
not audibility thresholds. They corroborate that this aligned region contains
signal under the stated numeric interpretation, but do not determine whether
that signal is audible on any playback chain or what it represents.

## Unknown

The cause of the difference, source-rip provenance, true sample byte order,
musical content, masking, playback gain, listener threshold, and perceptual
significance remain unknown. Establishing audibility would require controlled
listening or an appropriately scoped psychoacoustic analysis, neither performed
here.

## Reproduction

```sh
python3 -m unittest tools/disc/test_measure_track8_tail_levels.py -v
python3 tools/disc/measure_track8_tail_levels.py \
  'Drakan - Order of the Flame (USA)/Drakan - Order of the Flame (USA).cue' \
  'Drakan - Order of the Flame (Europe)/Drakan - Order of the Flame (Europe).cue' \
  research/exports/audio-comparison/archival.sha256 \
  > research/exports/audio-comparison/track8-level-bounds-20261024.json
```

The output path is private and must not name an input. The command must be run
from the repository root because the archival manifest uses repository-relative
paths.
