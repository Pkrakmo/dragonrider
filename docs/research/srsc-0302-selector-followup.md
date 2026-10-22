# `0x0302` pair-lookup payload framing follow-up

**Date and input:** 2026-10-19, unpatched US retail `Drakan.exe`, SHA-256
`23630f48e20e8a9f42026501165ae1df407cfcee545a784ec930a4c25ee70648`;
178 hash-checked installed US SRSC files inventoried at
`research/exports/srsc-records/us.json`. No executable was run, and no
Ghidra project was accessed. **Method:** GNU objdump 2.45.1-5.fc43 and a
bounded independent aggregate measurement. **Confidence:** high for the
identified static instruction paths and sampled counts, conditional for any
relationship to an actual invocation. See the earlier
[pair-lookup analysis](srsc-lookup-order.md#follow-up-two-word-0x0302-lookup).

## Observed: selection and control flow

`0x00432f70` receives a 32-bit value and asks `0x00431010` for a previously
stored object with that value. The helper searches a remainder-89 bucket and
compares the complete 32-bit key with object offset `+0x62`. If an object is
found and its `+0x5a` field is nonzero, the caller branches away before the
record-selection code. Otherwise, the shown path compares the input's high
half with a source object's `+0x114`, opens its `+0x15c` loader if needed,
and requests a two-word `(0x0302, low 16 bits)` lookup. `0x0045fa10` returns
the first matching index or `-1`; it does not compare the third selector.
Selection and loader-read failures can cause early return or affect later
behavior. The source object's actual file and runtime execution remain unknown.

After successful record selection, the branch at `0x0043305e` distinguishes
a null object returned by the earlier key lookup from a nonnull object. Both
branches request a length-prefixed skip using `0x0045f430`, with its return
value unchecked. Assuming successful reads and skip, and counting byte
offsets from the end of that prefix:

- For a null object, the code allocates one and reads a dword at offset `+0`,
  words at `+4` and `+6`, and dwords at `+8`, `+12`, `+16`, `+20` and `+24`
  (`0x0043309c`–`0x0043313e`). The last dword is stored at object `+0x22`.
  A subsequent shared dword read at `0x00433259` therefore reads offset `+28`.
- For a nonnull object with zero `+0x5a`, the other branch requests a 24-byte
  skip after the prefix (`0x00433179`–`0x00433188`). Under the same successful
  skip/read assumption, the shared dword read at `0x00433259` is from offset
  `+24`, not `+28`. On the way to that read, an argument bit can cause an
  earlier return, and virtual/helper calls can fail. Whether this branch is
  reached for any measured record and how its existing object was initialized
  are unknown; no conclusion about intended or actual results follows.

The shared dword is tested for zero (`0x0043325e`–`0x00433264`). On zero,
the caller requests a read of the object `+0x22` count into a destination
(`0x00433266`–`0x00433279`). On nonzero, it first requests a further dword,
uses it as a buffer size and input read count, then calls further processing
helpers (`0x00433283`–`0x0043331b`). The shown record reads and processing
calls do not check their returns. These are requested counts, not proof of
successful reads, decoding, or a semantic name for the fields.

On the new-object branch the code also computes, with 16-bit truncation after
the first multiplication, `(word_at_4 * (word_at_6 >> 3) mod 65536) *
dword_at_8 mod 2^32` (`0x004330e4`–`0x004330ff`). This arithmetic is separate
from the dword at `+24`; the sample comparison below does not establish its
meaning.

## Observed: bounded sample comparison

The measurement rechecks each file against the existing inventory, validates
selected payload ranges against the pre-table region, compares the reread
selector table with the hash-checked table, and reads at most 65,573 bytes
per selected record. It emits aggregate counts only. Of 1,561 `0x0302`
records in 19 files, all contain at least 32 bytes after the length-prefixed
head. On a **hypothetical new-object path**:

| Measurement | Records |
| --- | ---: |
| `+28` dword is zero | 1,171 |
| `+28` dword is one | 390 |
| `+28` dword has another value | 0 |
| Zero `+28`: `+24` equals remaining bytes after `+32` | 1,171 |
| Nonzero `+28`: dword at `+32` equals remaining bytes after `+36` | 390 |
| `+24` is nonzero | 1,561 |
| Arithmetic result above equals `+24` | 0 |

All nonzero-mode records have the additional `+32` dword. These comparisons
are byte framing only: they do not decompress payloads or validate requested
read or processing success. Existing-object behavior may depend on a previous
object's `+0x22` value, rather than the selected record's `+24`; no cache
state was reconstructed. The inventory hash precedes a later table and payload
read, so concurrent modification between those operations is not excluded.
The measured outcomes are not format validation requirements or evidence
that the third selector identifies these fields.

## Reproduction

```sh
sha256sum research/binaries/us/Drakan.exe
objdump --version
objdump -d -Mintel --start-address=0x431010 --stop-address=0x43103a research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x432f70 --stop-address=0x43318d research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x43318d --stop-address=0x43334d research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x45f2d0 --stop-address=0x45f430 research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x45fa10 --stop-address=0x45fa70 research/binaries/us/Drakan.exe
python3 tools/research/measure_0302_followup.py research/installed/us research/exports/srsc-records/us.json
python3 -m unittest discover -s tools/research -p 'test_measure_0302_followup.py' -v
```

## Bounded inspector comparison

`--record-0302-new` implements the hypothetical new-object framing described
above, including the nonzero-mode stored span without decoding it. Its limits
and scope are recorded in [ADR 0024](../decisions/0024-srsc-0302-new-object-diagnostic.md).
The independent Python decoder below matched every field, span length, CRC32
and trailing-byte count for all 1,561 selected records in 19 of 178 hash-checked
US files with both GCC debug and release inspectors on 2026-10-19. The Python
comparison reads a verified snapshot; the inspector reopens each file, so a
concurrent modification between those reads cannot be excluded.
The same two comparisons were rerun on 2026-10-19 after the waveform-field
follow-up, with 1,561/1,561 records matching in each build again.

```sh
python3 tools/research/verify_srsc_0302_new.py research/installed/us research/exports/srsc-records/us.json build/debug/dragonrider_inspect
python3 tools/research/verify_srsc_0302_new.py research/installed/us research/exports/srsc-records/us.json build/release/dragonrider_inspect
```

## Nonzero stored-span follow-up

The nonzero branch at `0x004332c7`–`0x0043331b` supplies the stored input,
the object's `+0x22` output size, and version string `1.0.2` to the same
`0x004629e0` / `0x00462a00` routines previously traced on the level
[compressed block path](level-0001-blocks.md). The helper results are not
checked in the shown caller. This static sequence does not show that any
particular sampled record reaches the branch.

A separate bounded Python zlib experiment (runtime `1.3.1.zlib-ng`) tested
all 390 sampled nonzero-mode stored spans from the hash-checked snapshot.
All reached stream end, produced exactly the new-object `+24` size, and had
no unused or unconsumed input; none had trailing record bytes. The 1,171 zero
mode records were counted but not decompressed. Both stored and decoded
sizes are capped at 32 MiB by the experiment; no sampled stream exceeded that
limit. This supports a zlib interpretation for these samples, but does not
establish cached-object behavior, original runtime return values, the decoded
bytes' meaning or applicability to other editions. No decoded bytes are
exported.

```sh
objdump -d -Mintel --start-address=0x4332c7 --stop-address=0x43331b research/binaries/us/Drakan.exe
objdump -s --start-address=0x47b778 --stop-address=0x47b780 research/binaries/us/Drakan.exe
python3 -c 'import zlib; print(zlib.ZLIB_VERSION, zlib.ZLIB_RUNTIME_VERSION)'
python3 tools/research/measure_0302_streams.py research/installed/us research/exports/srsc-records/us.json
python3 -m unittest discover -s tools/research -p 'test_measure_0302_streams.py' -v
```

## Cached-object offset comparison, 2026-10-19

Applying the cached-object offsets hypothetically to the same 1,561 records,
the `+24` mode is nonzero in every record, and the following input length at
`+28` is zero in 1,171 and one in 390. All requested spans fit, but none ends
at the record boundary. Under those assumptions these lengths cannot provide
a complete zlib stream. This observation concerns record bytes, not actual
cached-object execution or the preexisting output size at object `+0x22`.
The calls' return values and actual cache state are not reconstructed, so it
does not establish what the original game does with those inputs.

The common path calls `0x00430710` before the mode read; that helper returns
early when object `+0x5a` is zero. The cached candidate was initially selected
with `+0x5a` zero, but a virtual call occurs between those checks and could
change state. The state of that object at the later check remains unknown.

```sh
objdump -d -Mintel --start-address=0x433179 --stop-address=0x43329c research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x430710 --stop-address=0x430779 research/binaries/us/Drakan.exe
python3 tools/research/measure_0302_followup.py research/installed/us research/exports/srsc-records/us.json
python3 -m unittest discover -s tools/research -p 'test_measure_0302_followup.py' -v
```

The four synthetic tests include cached zero/nonzero modes and bounded input
lengths. The earlier reread/concurrent-modification qualification applies.

## Candidate waveform-format and buffer path, 2026-10-19

**Observed, static:** in the same hash-pinned US executable, the new-object
branch at `0x004330bd`–`0x004330ff` writes constant word `1` at object
`+0x10`, reads the two post-prefix words at `+4` and `+6` into object `+0x12`
and `+0x1e`, reads the dword at `+8` into `+0x14`, and derives object words
`+0x1c` and dword `+0x18` from those values. The object constructor installs
table `0x004758c4`, whose `+0x18` entry is `0x0042f850`. Assuming that table
remains installed, the virtual call at `0x00433215` reaches that routine.
It builds a 20-byte descriptor containing the object `+0x22` size and a
pointer to object `+0x10`, then passes it, an output pointer at object
`+0x5a`, and zero to slot `+0x0c` of the supplied interface. On another
conditional path the containing manager's `+0x2e4` interface is obtained
through ordinal 1 of `DSOUND.dll` at `0x00430c7d`; the branch can also use a
different helper. The loader supplies that manager field to the virtual call.

**Inference:** the field order and arithmetic match a 32-bit
[WAVEFORMATEX](https://learn.microsoft.com/en-us/windows/win32/api/mmreg/ns-mmreg-waveformatex)
PCM layout: the two words are candidate channel count and bits per sample,
the dword is a candidate sample rate, and the computed fields correspond to
block alignment and average bytes per second. The descriptor and call match
the leading fields and argument pattern documented for
[DirectSound buffer creation](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/ee416820%28v%3Dvs.85%29).
This is an inference from static structure and call shape; the ordinal import,
runtime interface identity, device operation and buffer contents were not
observed. The constructor and virtual table do not prove that no mutation or
alternate dispatch occurs.

**Measured:** a separate scan of the same 178 individually hash-checked US
snapshots finds all 1,561 candidate new-object records have word `+4` equal
to 1; word `+6` is 16 for 1,558 and 8 for three. The dword at `+8` is
11,025 for 116 records, 22,050 for 1,433, and 44,100 for 12. The candidate
size at `+24` is nonzero and divisible by the derived nonzero block size in
every case; all average-rate products fit 32 bits. These are structural
measurements consistent with mono waveform data, not playback, audible
content, a universal format constraint, or proof that the sampled files reach
the new-object path. Earlier bounded zlib measurements establish complete
streams only for the 390 selected nonzero-mode spans; neither mode's decoded
content has been rendered or validated as sound.

```sh
sha256sum research/binaries/us/Drakan.exe
objdump -p research/binaries/us/Drakan.exe | rg -A 3 'DSOUND.dll'
objdump -d -Mintel --start-address=0x430c30 --stop-address=0x430ca1 research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x430f20 --stop-address=0x430f61 research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x4307f0 --stop-address=0x430810 research/binaries/us/Drakan.exe
objdump -s --start-address=0x4758c4 --stop-address=0x4758e0 research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x4330ad --stop-address=0x433102 research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x43320a --stop-address=0x43321c research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x42f850 --stop-address=0x42f8e4 research/binaries/us/Drakan.exe
python3 tools/research/measure_0302_audio_fields.py research/installed/us research/exports/srsc-records/us.json
python3 -m unittest discover -s tools/research -p 'test_measure_0302_audio_fields.py' -v
```

The measurement uses the same input snapshot for hashing and parsing, checks
selected record bounds, and emits aggregate counts only. Three synthetic tests
cover truncation, zero alignment, odd bit widths and 32-bit product overflow.
Confidence is high for the stated instructions and sample counts; runtime
association, interface identity, actual playback and other editions remain
unknown.

## Candidate body duplication, 2026-10-19

**Measured:** a separate scan of the 178 verified snapshots reads the 1,171
zero-mode bodies directly and uses bounded zlib decompression for the 390
nonzero-mode bodies under the hypothetical new-object framing. It requires
stream end, exact indicated output size and no unused or unconsumed input;
both stored and decoded spans are limited to 32 MiB. All 1,561 records fit
those checks and have no trailing record bytes. It groups output by byte
length, SHA-256 and the three candidate waveform fields above; it emits no
body or digest. SHA-256 identity is strong evidence of byte identity, not a
direct byte-by-byte comparison or proof of semantic identity.

There are 1,526 distinct candidate format/body groups, with 35 occurrences
beyond the first in 34 repeated groups. Eighteen groups occur in multiple
inventoried files and eleven groups include both zero and nonzero modes. No
body digest/length group spans different candidate formats. These counts are
specific to the sampled US inventory and do not prove actual audio playback,
runtime file selection, or identity of a decoded sound. The data are not
exported and no sample-based uniqueness rule is imposed on the reader.

```sh
python3 tools/research/measure_0302_body_duplicates.py research/installed/us research/exports/srsc-records/us.json
python3 -m unittest discover -s tools/research -p 'test_measure_0302_body_duplicates.py' -v
```

Four synthetic tests cover raw and compressed equality, file and format
groups, decompression limits, output-size mismatch, truncation, damaged streams
and unused input.
The hash and parser use the same in-memory file snapshot; the data remain
private.

## Candidate PCM value statistics, 2026-10-19

As a separate numeric experiment, the same bounded bodies were interpreted as
mono unsigned 8-bit or signed little-endian 16-bit PCM according to their
candidate field values. This is consistent with Microsoft's documented
[PCM packing](https://learn.microsoft.com/en-us/windows/win32/multimedia/devices-and-data-types),
but it is conditional on the unverified runtime association above. No samples
or derived audio files were exported.

Across 1,561 record occurrences, including duplicate bodies, this interpretation
produces 88,793,442 candidate samples; 947,080 equal the respective midpoint
and 6,421 equal a minimum or maximum representable value. Every record has at
least one change between adjacent values; none consists entirely of midpoint
values. The endpoint count does not establish clipping or audible properties.
This aggregate is not an audibility assessment, proof of playback, or an
independent decoding of the original game's output.

```sh
python3 tools/research/measure_0302_pcm_candidates.py research/installed/us research/exports/srsc-records/us.json
python3 -m unittest discover -s tools/research -p 'test_measure_0302_pcm_candidates.py' -v
```

The three synthetic tests exercise both sample widths and their endpoints,
midpoint-only and empty bodies, unsupported candidate formats and truncated
16-bit input. The script reuses the bounded raw/zlib validation and verifies
the source snapshots, but does not model the original audio device or cached
object branch.

## Reproducibility check, 2026-10-20

The documented US-retail hash was rechecked before a fresh GNU objdump 2.45.1
inspection of `0x00432f70`–`0x0043334d`. The observed pair lookup, branch
split and field reads agree with the static offsets recorded above. The
aggregate measurements reproduced the stated 1,561-record counts: 1,171
zero-mode and 390 nonzero-mode records; candidate mono fields of 1 channel,
8 or 16 bits, and rates 11,025, 22,050 or 44,100; 1,526 distinct candidate
format/body groups; and 88,793,442 conditionally interpreted PCM samples.

`verify_srsc_0302_new.py` again matched all 1,561 selected records in both
GCC debug and release inspector builds. The focused `0x0302` Python tests
passed 16/16 and the complete research-tool suite passed 207/207. This is a
repeatability check of the bounded static and aggregate observations. It does
not establish runtime path selection, DirectSound execution, decoded-content
meaning, cached-object behavior, or playback.

```sh
sha256sum research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x432f70 --stop-address=0x43334d research/binaries/us/Drakan.exe
python3 tools/research/measure_0302_audio_fields.py research/installed/us research/exports/srsc-records/us.json
python3 tools/research/measure_0302_streams.py research/installed/us research/exports/srsc-records/us.json
python3 tools/research/measure_0302_body_duplicates.py research/installed/us research/exports/srsc-records/us.json
python3 tools/research/measure_0302_pcm_candidates.py research/installed/us research/exports/srsc-records/us.json
python3 tools/research/verify_srsc_0302_new.py research/installed/us research/exports/srsc-records/us.json build/debug/dragonrider_inspect
python3 tools/research/verify_srsc_0302_new.py research/installed/us research/exports/srsc-records/us.json build/release/dragonrider_inspect
python3 -m unittest discover -s tools/research -p 'test_*.py' -v
```

## Bounded decoded-body diagnostic, 2026-10-21

**Observed implementation check:** the independent engine reader now exposes a
separate caller-selected decode of the already selected hypothetical
new-object framing. In zero mode it copies the bounded raw body. In nonzero
mode it requires exactly one zlib stream, with no unused input and output
equal to the earlier fifth-dword size. The inspector reports only the decoded
byte count and CRC32. It does not print decoded bytes, name them as audio, or
model a cache, device, or playback.

On the same 178 individually hash-checked US snapshots, the independent
Python verifier and both GCC builds agreed on all 1,561 metadata summaries in
the 19 files containing selected records. This includes 1,171 zero-mode and
390 nonzero-mode observations. The verifier hashes and parses its in-memory
snapshot before the inspector reopens the input path, so concurrent mutation
between those reads remains possible. This repeatability check does not turn
the static waveform-shaped inference into an established runtime format.

```sh
cmake --build --preset debug
ctest --test-dir build/debug --output-on-failure
cmake --build --preset release
ctest --test-dir build/release --output-on-failure
python3 tools/research/verify_srsc_0302_new.py \
  research/installed/us research/exports/srsc-records/us.json \
  build/debug/dragonrider_inspect --decoded
python3 tools/research/verify_srsc_0302_new.py \
  research/installed/us research/exports/srsc-records/us.json \
  build/release/dragonrider_inspect --decoded
```

The synthetic C++ cases cover raw mode, exact zlib decoding, declared output
limits, damaged streams, and unused compressed input. All output and source
snapshots remain private.
