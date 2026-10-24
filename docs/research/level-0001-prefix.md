# Level selector `(1,0,0)` prefix

**Date:** 2026-10-17. **Input:** unpatched US retail `Drakan.exe`,
SHA-256 `23630f48e20e8a9f42026501165ae1df407cfcee545a784ec930a4c25ee70648`;
installed-US level files are checked against their individual hashes in the
private asset inventory. **Method:** GNU objdump 2.45.1 bounded disassembly,
and Python 3.14.7 measurement of bytes. No Ghidra project was accessed for
this investigation. **Confidence:** high for the stated instructions and
sample measurements, limited to this path and the inventoried files.

## Observed

- The level-loading path calls `0x00421c30` with the resource object after
  processing the database list; see [the earlier trace](level-directory-behavior.md).
  At `0x00421c43`–`0x00421c5b`, this function selects `(1,0,0)` and reads
  a four-byte outer count. The loop at `0x00421d34`–`0x004220cc` uses a
  signed positive comparison, and each iteration populates a 168-byte runtime
  object. This size is an in-memory stride, not a file record size.
- On its successful path each iteration reads seven four-byte values, a
  two-byte-length-prefixed byte sequence via `0x0045f430`, six more four-byte
  values, then a four-byte inner count and `count * 4` bytes via `0x0045f2d0`.
  The four-byte helper `0x0045f370` requests exactly four bytes. The reader
  skips the length-prefixed bytes with a null buffer; their meaning and encoding
  are unknown. The call at `0x00421d9e` allocates based on two of the first
  values and may take an error path before the rest is read.
- On this path the inner dwords are copied into 16-bit runtime entries
  (`0x00422088`–`0x004220a6`); a subsequent loop uses these entries as indices
  into the runtime object array (`0x00422145`–`0x0042215d`). This does not
  establish valid indices for arbitrary files, or their broader meaning.
- After the first loop the function reads another dword at `0x004221f7` and
  enters further per-object processing. The prefix scan leaves that data opaque;
  subsequent investigation is recorded in [the block trace](level-0001-blocks.md).

## Measured samples

The script below verifies the inventory hash and SRSC table bounds and selects
exactly one `(1,0,0)` record in each candidate `.lvl`. It parses the successful
path prefix only, with measurement limits of 4,096 for either count. All
**23/23** files passed: 4,445 outer entries, 1–941 per file, and 207,353 inner
dwords, 1–162 per entry. None of these dwords was at least its file's outer
count or exceeded 65,535. Skipped byte-sequence lengths ranged from 2 to 32;
opaque trailing data ranged from 59 to 389,404 bytes per record. These are
sample observations, not format constraints, and the script does not verify
the trailing data or simulate allocations, errors, or runtime behavior.

## Unknown and reproduction

The names and meanings of the fields, their coordinate or rendering role,
other versions, and actual level geometry remain unresolved. Later findings
and bounded block inspection are documented in [the block trace](level-0001-blocks.md).
Original read return values on this path are not
uniformly checked; the measurement script independently checks bounds.

```sh
sha256sum research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x421c30 --stop-address=0x422350 research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x4226c0 --stop-address=0x422756 research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x45f2d0 --stop-address=0x45f4c3 research/binaries/us/Drakan.exe
python3 tools/research/measure_level_0001.py research/installed/us research/exports/asset-inventory/us.json
python3 -m unittest discover -s tools/research -p test_measure_level_0001.py -v
```

## Inner-value consumer and sample relations, 2026-10-19

**Observed, static:** on the successful first-loop path at
`0x00422088`–`0x004220a6`, the retail executable compares each entire raw
32-bit inner value against the current zero-based outer-entry index. On a
match it writes the current inner-list position to runtime entry offset `+0x44`;
it separately copies the value's low 16 bits into the runtime list. If there
are repeated full-dword matches, the later assignment overwrites the earlier
one on this path. No range check appears in this bounded copy loop.

The later loop at `0x00422108`–`0x004221c6` initializes runtime entry word
`+0x4a` to `0xffff`, uses each copied low word as an index into the 168-byte
runtime entry array, and compares signed origin and dimension-derived
intervals. For a candidate whose intervals strictly overlap on both axes, it
writes the list position to `+0x48` and, for the first matching position, to
`+0x4a`. A first/last position is not a filtered list: nonmatching candidates
may lie between them. A later query path uses the saved positions as described below; malformed-input
handling is not established. Allocation success, read success,
unchanged memory, and the absence of untraced mutations are assumptions for
correlating serialized fields with these runtime instructions.

**Sample measurement:** Python 3.14.7 and the pinned US SRSC inventory checked
sizes and SHA-256 of all 23 selected level files. Their 4,445 entries contain
207,353 inner dwords. Each entry contains its own full index exactly once;
1,582 have it first and 129 last. No low-half values repeat within a list,
no high halves are nonzero, and every low half is in range. Of the 207,353
directed occurrences, 199,055 have a reverse occurrence, including self-links;
8,298 do not. These counts describe static numbers, not object associations.
The first serialized dword is nonzero and unique within its level in all
4,445 entries; it equals the zero-based entry index in seven cases. Across
levels there are 1,867 distinct numeric values, including 1,295 found in more
than one file; one value occurs in eight files. These numeric repetitions do
not establish a shared logical identity, the first dword's meaning, or
uniqueness as a format rule.

A separate model applies the stated strict comparisons to the sampled raw
origins and dimensions, using signed 32-bit comparisons and wrapping additions
as in the inspected x86 instructions. It finds 22,779 overlapping occurrences,
including 194 without a reciprocal occurrence. Every entry's self occurrence
overlaps. In 1,748 entries the overlapping positions are contiguous; in the
other 2,697 they are not. Across the sample, 54,159 nonoverlapping occurrences
lie between the first and last overlapping positions. These sample-specific findings do not show that any entry was processed in a
running game.
No original bytes or names are emitted; no Ghidra project or game was opened.
Confidence is high for the specified static instructions and hash-checked
snapshots, conditional for runtime state and other editions.

**Observed, bounded query trace:** in the nonnegative selected-entry branch,
`0x00420f0c`–`0x00420f25` derives the same 168-byte runtime entry and retains
its pointer. `0x00420fac` saves its `+0x44` dword as a starting position.
On the list-iteration branch, `0x00420feb`–`0x0042103f` adds a signed step
to that position, checks the list count and nonnegative bounds, and, when a
separately computed query condition is true, also compares against words
`+0x48` and `+0x4a` before loading a low-word list value. On an exhausted
forward branch, `0x00421372`–`0x0042138d` can reverse the step under its
query flag and prior-result conditions. Thus the first/last overlap positions
are conditional bounds in this query, not proof that every candidate between
them overlaps. The candidate path applies additional discriminator and
coordinate checks (`0x0042106a`–`0x0042109a`). A second bounded window at
`0x00421598`–`0x00421624` shows analogous starting-position and bounds checks;
its complete behavior was not traced. These findings assume the original
entry/list state is unchanged between loading and query, and do not establish
which user action, objects, or visible outcome exercises either path.

The C++ diagnostic exposes raw inner dwords without validating these sample
relationships; [ADR 0022](../decisions/0022-level-inner-value-diagnostic.md)
records its bounds. An independent decoder matched `--level-links` for all
23 levels with both debug and release inspectors. Because the inspector
reopens each path after the verifier checks its input buffer, concurrent file
changes are not excluded.

```sh
sha256sum research/binaries/us/Drakan.exe
objdump --version
objdump -d -Mintel --start-address=0x420e10 --stop-address=0x4210a0 research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x421350 --stop-address=0x4213e0 research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x421598 --stop-address=0x421646 research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x422080 --stop-address=0x4220af research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x422108 --stop-address=0x4221cc research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x4226c0 --stop-address=0x422754 research/binaries/us/Drakan.exe
python3 tools/research/measure_level_inner_graph.py research/installed/us research/exports/srsc-records/us.json
python3 tools/research/verify_level_links.py research/installed/us research/exports/srsc-records/us.json build/debug/dragonrider_inspect
python3 tools/research/verify_level_links.py research/installed/us research/exports/srsc-records/us.json build/release/dragonrider_inspect
python3 -m unittest discover -s tools/research -p 'test_measure_level_inner_graph.py' -v
python3 -m unittest discover -s tools/research -p 'test_verify_level_links.py' -v
```

## Verified level-link inspector snapshot recheck, 2026-10-23

`verify_level_links.py` now sends a temporary copy of the exact verified bytes
used for independent decoding to the inspector. Debug and release builds
matched the same 23 levels and aggregate counts: 4,445 entries and 207,353
inner values, with every measured inner value equal to its entry index. These
remain bounded observations of this inventory, not a general rule for other
levels or executable paths.

## First-dword lookup and type-12 candidates, 2026-10-19

**Observed, static:** with the same pinned US executable and GNU objdump
2.45.1-5.fc43, `0x00421d69`–`0x00421d75` passes the address of each 168-byte
entry directly to the four-byte reader. `0x0041f1c0`–`0x0041f1e4` starts
at the level object's `+0x0c` entry array, compares the first dword of each
entry with its argument in increasing index order, returns the first matching
index, and returns `0xffffffff` for no match or a nonpositive count. This
relies on the receiver being the level object and unchanged entry state; it
does not establish the first dword's broader meaning or uniqueness.

There are direct calls at `0x0042a28b`, `0x0042acb3`, and `0x004373c8`.
In the first, the jump table at `0x0042a298` selects that branch for type 12;
the argument is read from the provided unit and replaced by the return value.
The resource-driven array path and its conditional assumptions are documented
in [the `0x0102` trace](srsc-0102-runtime.md#array-processing-and-metadata-comparison-2026-10-18).
The second call is behind a separate type-12 dispatch: the byte table at
`0x0042ad04` selects the target at `0x0042aca3` through the pointer table at
`0x0042acec`. That branch returns early for input zero or `0xffffffff`; those
sentinel checks are not part of the lookup helper.
The third reads a dword through `0x0045f370`, calls the helper, and replaces
that field with the returned index. Caller context, active level identity,
indirect callers, mutations and actual runtime execution remain unknown.

**Sample measurement:** a bounded Python 3.14.7 scan checks the pinned RFL
SHA-256 and each of 178 US SRSC files against its private inventory. Using
candidate resource descriptors matched by the earlier `0x0102` investigation,
it finds no unflagged type-12 base entries and 136 flagged type-12 entries
among 4,203 records. Under the raw range interpretation, 95 have a zero
endpoint or length and 41 are in bounds; none is negative or out of bounds.
The 41 candidate ranges contain 82 occurrences of 80 distinct raw values.
Each occurrence matches at least one first dword among all 23 sampled levels:
14 match one file and 68 match multiple files. All values in each of the 41
ranges share at least one candidate level: 21 ranges have exactly one common
level, while 20 have multiple. The comparison uses sets of first dwords per
file, not runtime selection; it cannot show that the game loaded a matching
level or processed those unmutated values. A common numeric match is not an
identity or cross-file association rule. No names or original bytes are
emitted and no game execution or Ghidra project access was performed.

[ADR 0023](../decisions/0023-level-entry-prefix-diagnostic.md) defines raw
prefix and first-match diagnostics. An independent Python decoder matched all
4,445 prefixes against a test-only callback probe and compared 67 selected
prefix summaries and 90 selected first-word lookups against each of the debug
and release inspectors. The
inspector reopens each path after the verifier checks it, so concurrent changes
are not excluded. Confidence is high for the specified static instructions and
hash-checked snapshots, conditional for runtime state and other editions.

```sh
sha256sum research/binaries/us/Drakan.exe
objdump --version
objdump -d -Mintel --start-address=0x41f1c0 --stop-address=0x41f1e7 research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x421d69 --stop-address=0x421d81 research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x42a180 --stop-address=0x42a298 research/binaries/us/Drakan.exe
objdump -s --start-address=0x42a298 --stop-address=0x42a2c8 research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x42ac50 --stop-address=0x42ace9 research/binaries/us/Drakan.exe
objdump -s --start-address=0x42acec --stop-address=0x42ad10 research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x43736f --stop-address=0x4373d3 research/binaries/us/Drakan.exe
python3 tools/research/measure_0102_level_keys.py research/installed/us research/exports/srsc-records/us.json research/installed/us/English_-_Program_Files/Dragon.rfl
python3 tools/research/verify_level_entry.py research/installed/us research/exports/srsc-records/us.json build/debug/dragonrider_inspect --probe build/debug/level_entry_probe
python3 tools/research/verify_level_entry.py research/installed/us research/exports/srsc-records/us.json build/release/dragonrider_inspect --probe build/release/level_entry_probe
python3 -m unittest discover -s tools/research -p 'test_measure_0102_level_keys.py' -v
python3 -m unittest discover -s tools/research -p 'test_verify_level_entry.py' -v
```

## Verified entry-inspector snapshot recheck, 2026-10-23

`verify_level_entry.py` now passes the same verified byte snapshot used by its
independent decoder to the inspector's selected-entry and first-word lookup
commands. Debug and release builds each matched all 4,445 decoded entries,
67 selected-entry comparisons, and 90 lookup comparisons across 23 levels;
the probe also matched all 4,445 entry prefixes. This confirms consistency for
the measured inventory, not the meaning or runtime use of every field.

## Directory-name comparison for type-12 candidate ranges (2026-10-19)

The earlier 41 numeric candidate ranges were compared with lexical level
source names using `tools/research/measure_level_0102_sources.py`. Inputs are
178 inventory-hash-checked US SRSC files, including 23 levels, and the pinned
`Dragon.rfl` resource hash used by the prior analysis. Directory strings are
normalized as relative Windows-style paths; a missing extension is assigned
`.odb` as a hypothesis. Names are compared only to inventory keys, never
opened as paths. An optional second hypothesis removes the extracted installer
group and converts underscores to spaces; see the prior source-candidate
analysis for its limitations.

| Comparison | Direct layout | Installer overlay hypothesis |
| --- | ---: | ---: |
| Directory entries with one inventory key | 62 / 164 | 164 / 164 |
| Ranges with one level matching both the numeric values and source name | 35 / 41 | 35 / 41 |
| Ranges with multiple such levels | 0 / 41 | 1 / 41 |
| Ranges with no such level | 6 / 41 | 5 / 41 |

Each range contains two candidate values, 82 total, across nine source files.
In the direct layout, two unmatched ranges have only a partial value match in
the named level and four have no value match there. Under the overlay
hypothesis those counts are two and three. All 41 source inventory keys are
unique in both comparisons. These results narrow candidate associations but
cannot establish which file the runtime loads, a reference's meaning, or
whether the compared ranges are actually used together.

```sh
python3 tools/research/measure_level_0102_sources.py research/installed/us research/exports/srsc-records/us.json research/installed/us/English_-_Program_Files/Dragon.rfl
python3 tools/research/measure_level_0102_sources.py research/installed/us research/exports/srsc-records/us.json research/installed/us/English_-_Program_Files/Dragon.rfl --overlay-hypothesis
python3 -m unittest discover -s tools/research -p 'test_measure_level_0102_sources.py' -v
```

A separate static trace follows a selector `(0x20,0,0)` object's third dword
to the same first-match helper and a conditional later use of the returned
index; see [the caller follow-up](level-entry-caller-followup.md). Its sample
initially covered the first object in each level. The later conditional framing
scan covers all declared objects in the same sampled levels; runtime loading
and association remain unverified.
