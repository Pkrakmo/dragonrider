# Track 8 tail and adjacent audio boundaries

**Investigation:** 2026-10-17, using the same original US and Europe CUE/BIN
images identified by SHA-256 in [the prior comparison](cd-audio-comparison.md).
Inputs were read only. The private report
`research/exports/audio-comparison/audio-tail.json` records the CUE and audio
BIN hashes and aggregate measurements; it contains no audio samples. These
results describe these supplied images, not every pressing or extraction.

## Method

The previous investigation established a +673-frame Europe-minus-US alignment
from exact anchors and compared each program-region overlap. This follow-up
**assumes that alignment**; it does not estimate it again. It compares the
INDEX 00 region, program region, and where available the US file's final 673
frames with the first 673 frames of the following Europe AUDIO file. For these
particular CUEs INDEX 01 is frame 88,200 in each file. The script requires
consecutive AUDIO tracks with matching CUE indexes and track lengths, and
rejects incompatible layouts. It interprets four-byte frames as signed 16-bit
little-endian interleaved stereo at 44,100 frames/second; equality itself is
independent of sample endianness. No normalization or resampling was used.

## Observed

- At the assumed +673-frame alignment, each track 2–8's entire 88,200-frame
  INDEX 00 region matches its Europe counterpart, with the last 673 frames of
  each such comparison extending into the Europe program region.
- The six US-to-next-Europe boundaries (tracks 2→3 through 7→8) each match
  for all 673 frames. This covers the US program-region ends previously left
  outside the within-track comparisons for tracks 2–7. The Europe initial
  673 frames of track 2 have no preceding AUDIO file in this analysis; the US
  final 673 frames of track 8 have no next Europe AUDIO file to pair.
- A follow-up on 2026-10-18 measured the leading zero stereo frames in the
  track 2 files: 88,203 for the US image and 88,876 for Europe, a difference
  of 673 frames. Both runs include the entire 88,200-frame INDEX 00 region.
  Thus all 673 otherwise unpaired initial Europe frames are zero; the first
  frame after each respective run is nonzero. This characterizes the image
  boundaries without identifying any preceding disc audio. Together with the
  final US zero run, both unpaired outer segments are known to be zero, but
  their absent counterparts cannot be compared.
- The US track 8 file ends with **exactly 88,200 consecutive zero stereo
  frames**, or 2.000 seconds. The preceding frame is nonzero. Silence begins
  at file frame 9,478,560, or program frame 9,390,360. The Europe track 8
  file's final frame is nonzero, so it has no trailing all-zero stereo frame.
- Of the US zero tail, 87,527 frames have an aligned Europe counterpart in
  track 8; all 87,527 differ, and 174,867 of 175,054 Europe channel samples
  are nonzero. The last 673 US frames are known to be zero but have no
  counterpart in these images. The Europe overlapping tail has peak absolute
  sample value 4,102 and RMS 704.735 on the signed-16-bit scale, computed
  across both channels. Four successive windows of 22,050, 22,050, 22,050,
  and 21,377 frames have Europe RMS values 1,169.140, 654.760, 358.962, and
  220.165 respectively. These decreasing aggregate levels characterize these
  samples; they do not establish a particular mastering process.

**Inferred:** the images contain materially different sample data at the US
track 8 end; it is more specific than an ordinary constant alignment shift.
The decreasing Europe RMS is consistent with a declining tail but does not
independently establish musical content or intention.

**Unknown:** why the US tail is zero, whether either image faithfully represents
its original pressing, whether a particular listener would hear the difference,
and whether it reflects musical, mastering, disc-authoring, or extraction
choices. Listening, another verified rip, or independent disc access would be
needed to investigate those questions. This comparison does not determine
whether there are gain or mastering differences that do not preserve exact
sample equality outside the tested alignment.

## Reproduction

Python 3 and NumPy are research-tool dependencies, not engine dependencies.
The run used NumPy 2.3.5. The report is aggregate metadata and remains under
ignored `research/`:

```sh
python3 tools/research/test_audio_tail.py -v
python3 tools/research/audio_tail_analysis.py \
  'Drakan - Order of the Flame (USA)/Drakan - Order of the Flame (USA).cue' \
  'Drakan - Order of the Flame (Europe)/Drakan - Order of the Flame (Europe).cue' \
  > research/exports/audio-comparison/audio-tail-leading.json
sha256sum -c research/exports/audio-comparison/archival.sha256
```

On 2026-10-18 the 19 archival hashes passed; the updated report agrees with
the earlier report after excluding the added leading-zero measurement.
Two synthetic tests passed on 2026-10-18, covering a cross-file aligned
boundary, a zeroed final region, aggregate metrics, negative sample extrema,
long silent suffixes, different leading-zero runs and invalid offsets. The
script processes comparisons in bounded chunks and memory-maps inputs read-only. Redirect only to a private
output path; shell redirection is not protected by the script against an
operator choosing an input as output.


## Cutoff transition, 2026-10-19

**Observed:** the same two CUE/BIN sets were read with Python 3.14.7 and
NumPy 2.3.5, using the previously measured +673-frame alignment and the
verified track 8 hashes in [the comparison](cd-audio-comparison.md). At the
first US zero-tail frame, the absolute change from the previous sample is
491 and 1,089 in the two signed-16-bit channels. The corresponding Europe
changes are 12 and 2. In the preceding 44,100 within-channel steps, US changes
at least as large as its cutoff change occur 575 and six times respectively;
the aligned Europe counts relative to its own cutoff changes are 36,893 and
43,133. All 44,101 aligned frames used to calculate those preceding steps
match between images. These rankings compare sample differences, not perceived
loudness or click audibility. Endianness and channel interpretation follow the
prior analysis; input hashes and the alignment do not establish rip fidelity,
cause, mastering choices, or music content. The analysis reads files through
read-only mappings, hashes them separately, and does not rule out concurrent
modification between hashing and measurement. Confidence is high for the
specified aligned sample snapshots, limited for acoustic interpretation.

```sh
python3 tools/research/test_audio_tail.py -v
python3 tools/research/audio_tail_analysis.py \
  'Drakan - Order of the Flame (USA)/Drakan - Order of the Flame (USA).cue' \
  'Drakan - Order of the Flame (Europe)/Drakan - Order of the Flame (Europe).cue' \
  > research/exports/audio-comparison/audio-tail-cutoff.json
```

The new report reproduced the earlier report’s CUE and track hashes, all
track and boundary comparisons, and prior terminal metrics. The output contains
private input paths and hashes, and is kept under ignored `research/`. The cutoff measurements are omitted if the zero-tail start is
outside the available aligned overlap.

## Short-window RMS envelope, 2026-10-19

**Measured:** a separate read-only analysis of the same hash-verified US and
Europe track 8 BINs used the assumed 673-frame alignment and began at the
US's measured zero-tail start, file frame 9,478,560. It divided the 87,527
aligned Europe frames into twenty non-overlapping windows of 4,410 frames
(100 ms at 44,100 frames/s), with a 3,737-frame final window, then computed
stereo RMS without normalization. The first window RMS is 1,599.635 and the
last is 200.996; of the 19 adjacent-window transitions, 18 decrease and one
increases. Thus the bounded result has a broadly lower short-window envelope
toward the end, but it is not strictly monotonic and does not establish
musical content, mastering intent, audible level or causal relationship to
the US zero tail. The report contains paths and hashes but no samples; input
files are memory-mapped read-only. Confidence is high for these supplied
snapshots and this alignment assumption, not other pressings or rips. Window
size is capped at 441,000 frames (ten seconds) to bound temporary arrays;
hashing followed by mapping does not exclude concurrent file modification.
The JSON output retains all twenty aggregate window RMS values, but no samples.

The independent Python 3.14.7 / NumPy 2.3.5 measurement can be reproduced
with:

```sh
python3 -m unittest discover -s tools/research -p 'test_measure_audio_tail_envelope.py' -v
python3 tools/research/measure_audio_tail_envelope.py \
  'Drakan - Order of the Flame (USA)/Drakan - Order of the Flame (USA).cue' \
  'Drakan - Order of the Flame (Europe)/Drakan - Order of the Flame (Europe).cue'
```

The tool's three synthetic tests pass on 2026-10-19, including a temporary
two-CUE/two-BIN fixture that checks the selected program tail and the output
hash metadata. No original media are written.
