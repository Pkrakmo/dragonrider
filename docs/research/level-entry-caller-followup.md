# Level entry lookup from selector `(0x20,0,0)`

## Provenance and scope

**Input:** US retail `Drakan.exe`, SHA-256
`23630f48e20e8a9f42026501165ae1df407cfcee545a784ec930a4c25ee70648`.
**Method:** static x86 disassembly with GNU objdump 2.45.1-5.fc43; no Ghidra
project access or game execution. **Confidence:** high for the described
instructions and conditional data flow; medium for the association between
the loader and the later manager traversal, which depends on runtime object
lifetime and state. File bytes below refer only to 23 hash-checked, inventoried
US levels, not other editions or all selector-0x20 objects.

## Observed: loading and lookup

On a successful path through the level loader, `0x00437179` passes the global
level object at `0x00480230` and its open source object to `0x00421c30`, which
selects `(1,0,0)` and builds the level entry array. Subsequently, the loader
may pass the same open source to `0x00437290` at `0x00437233`; this call is
skipped on branches involving loader flags. That routine selects
`(0x20,0,0)` at `0x004372b3`–`0x004372bb`, returns if selection fails, reads a
two-byte count, allocates an eight-byte-per-item table, and obtains a runtime
object for each declared item from the manager at `0x00482f78`.

For each object, `0x00437380`–`0x004373ba` reads three four-byte values: the
first goes into its table entry, the second is passed to another lookup whose
result becomes a word at object `+0x02`, and the third goes to object `+0xb0`.
`0x004373bf`–`0x004373d0` then looks up the third value in the global level
object using `0x0041f1c0` and replaces object `+0xb0` with the returned first
matching entry index, or `0xffffffff` if no match. The helper itself neither
skips zero nor guarantees uniqueness; see [the earlier lookup trace](level-0001-prefix.md#first-dword-lookup-and-type-12-candidates-2026-10-19).
Read failures and intervening state changes can invalidate an interpretation of
the raw bytes as a completed runtime object.

The manager's allocation routine `0x004291a0` takes an object from its pool,
initializes it through `0x00428000`, and returns it. The initializer sets
`+0xb0` to `0xffffffff` before the selector reader writes it. The pool's
objects are spaced `0xea` bytes apart and the manager also tracks free
objects. These offsets describe this observed runtime structure, not a new
on-disk fixed object size.

## Observed: conditional later use

The separate manager routine `0x004294d0` traverses the manager's object
storage in 64-object blocks and skips objects in its free list. Its branch at
`0x00429514`–`0x00429553` additionally requires object `+0x74` nonzero,
`+0x78` zero, bit `0x2000` of `+0x04` clear, `+0x8c` nonzero, and `+0xac`
not equal to `0xffffffff`. Under those conditions, if `+0xb0` is not
`0xffffffff`, `0x0042958c` takes it as the selected index. Otherwise the
routine uses `+0xac`, potentially replacing it with a conditional call to
`0x004213f0`; a `0xffffffff` query result falls back to `+0xac`.

For a nonnegative selected index, `0x00429592`–`0x004295a4` computes
`[0x0048023c] + index * 168`, where `0x0048023c` is `+0x0c` of the same
global level object. It then passes addresses at entry `+0x38` and `+0x68`
to one of two routines chosen by object flags. A negative value instead
produces a zero base before those offsets are formed. No upper-bound check is
visible in that local sequence, and the effects of the called routines are
not established here. A direct call to this manager routine occurs at
`0x0040cb4b`; its actual timing relative to a particular object load is not
established. Values may be changed or objects released or reused between the
two paths.

**Inference:** on a path where the loaded object remains allocated and its
fields satisfy the later gates, a successful lookup can select the matching
level entry for this subsequent operation. This does not establish the
semantic type of the object, the first dword's general meaning, or the
resulting visual or gameplay effect.

## Measured first-object prefixes, 2026-10-19

The bounded script below checks each `.lvl` file against the private SRSC
inventory hash, requires exactly one `(0x20,0,0)` record, validates its
payload range and reads only its two-byte count and first three dwords. It
independently compares the first object's third dword against the same file's
`(1,0,0)` first-dword values. All 23 levels contain one matching selector and
have a nonzero declared count, with 16,312 objects declared in total. Of the
23 first-object values, 21 are zero and do not match a same-file level entry;
two are nonzero and each matches one same-file entry. None is `0xffffffff`.

These are observations of **23 first objects only**. The declared total is
not a count of parsed or validated objects, and later object framing is not
measured. The comparison assumes the level reader and selector reader use
those files without mutations; it does not demonstrate a runtime lookup,
loaded level identity, complete record validity, or whether zero represents a
sentinel. The matching object and level input remain private.

## Reproduction

```sh
sha256sum research/binaries/us/Drakan.exe
objdump --version | head -1
objdump -d -Mintel --start-address=0x437144 --stop-address=0x437245 research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x421c30 --stop-address=0x421c60 research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x437290 --stop-address=0x4373d3 research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x4294d0 --stop-address=0x429601 research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x4291a0 --stop-address=0x4292c6 research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x428000 --stop-address=0x42807f research/binaries/us/Drakan.exe
python3 tools/research/measure_level_entry_caller.py research/installed/us research/exports/srsc-records/us.json
python3 -m unittest discover -s tools/research -p 'test_measure_level_entry_caller.py' -v
```

Five synthetic tests passed on 2026-10-19, covering empty lists, unsigned
values, truncated prefixes, missing or duplicate selectors, and an invalid
record range. At that point the full object framing had not been measured.
The manager's actual execution sequence, selector aliases and mutations,
runtime loading of the sampled levels, indirect calls, and behavior in other
editions remain unknown.

## Direct record-initializer scan, 2026-10-20

**Observed:** a fresh GNU objdump 2.45.1 scan of the hash-checked US retail
executable found exactly ten direct relative calls to record initializer
`0x0045f600`. The nearest preceding immediate selector at those callsites is,
once each: `0x0021`, `0x0022`, `0x0023`, `0x0051`, `0x0102`, `0x0302`,
`0x0311`, `0x0320`, `0x0400`, and `0x0402`. No scanned direct call has an
immediate `0x0020` selector. The matching calls are at `0x0040b55b`,
`0x0040b59b`, `0x0040b611`, `0x0040b74b`, `0x0040dd4c`, `0x0040e166`,
`0x00427671`, `0x0042c8e6`, `0x004315f4`, and `0x00441e38`.

`measure_direct_record_writers.py` parses only objdump instruction lines and
looks back at most eight preceding instructions for up to three immediate
`push` values at a direct call, restoring x86 push order for its reported
pair/triple keys. It cannot find a producer that calls indirectly, supplies a
selector from a register or memory, is absent from this executable image, or
reaches a different initializer. Therefore this is a bounded negative result,
not evidence that the `0x0020` frames have no producer.

```sh
sha256sum research/binaries/us/Drakan.exe
python3 tools/research/measure_direct_record_writers.py research/binaries/us/Drakan.exe
python3 -m unittest discover -s tools/research -p 'test_measure_direct_record_writers.py' -v
```

The two synthetic tests cover a direct immediate selector, an unrelated call,
and a direct target call with no immediate selector. The scan emits addresses
and aggregate selector values only; it does not export proprietary code.

## Module direct-initializer scan, 2026-10-20

**Observed:** applying the same bounded scanner to the hash-pinned US
`Dragon.rfl` finds two direct relative calls to module initializer
`0x101562f0`. Their immediate selector pairs are `(0x0401, 0x037b)` at
`0x10016120` and `(0x0401, 0x037d)` at `0x10016247`. A separate scan of all
178 individually hash-checked US SRSC tables found neither first/second pair,
with any third selector. This excludes those two direct module callsites as a
source of a matching entry in the selected snapshot under the static-call and
inventory assumptions.

The scanner records at most two immediate pushes in the eight instructions
before a direct call. It does not cover module paths that call indirectly,
select values through registers or memory, use another initializer, write a
different file, or run only in a different edition. Therefore the absence is
not evidence that `Dragon.rfl`, its raw writer, or other modules cannot
produce selector-`0x0020` frames at runtime.

```sh
sha256sum research/installed/us/English_-_Program_Files/Dragon.rfl
python3 tools/research/measure_direct_record_writers.py \
  research/installed/us/English_-_Program_Files/Dragon.rfl --target 0x101562f0
python3 -m unittest discover -s tools/research -p 'test_measure_direct_record_writers.py' -v
```

## Direct selector-consumer scan, 2026-10-20

**Observed:** the hash-checked US executable contains 26 direct relative calls
to full-record selector `0x0045f0d0`. The scanner finds one immediate pair
`(0x0020, 0x0000)`, at `0x004372bb`, which is the level-object reader already
traced above. Its third selector is the preceding immediate zero at
`0x004372b3`. No other direct call has an immediate first selector `0x0020`.
The other recovered immediate first selectors are `0x0000` (two calls),
`0x0001`, `0x0021`, `0x0022`, `0x0023`, `0x0051`, `0x0100`, `0x0102`,
`0x0302`, `0x0311`, `0x0320`, `0x0400` (two calls), and `0x0402` (eleven
calls). Several direct calls have a non-immediate second or third selector,
so the scan records only pairs formed by two nearby immediate pushes.

The scanner now records a three-immediate key as well: this call is
`(0x0020,0x0000,0x0000)`. This makes the zero third selector a bounded,
reproducible property of the direct callsite rather than a manual reading of
the nearby instructions. The result corroborates the documented reader rather
than proving that it is the sole runtime consumer. It excludes neither indirect
calls, lookup wrappers, selectors supplied through registers or memory, code
in optional modules, nor other editions. It also does not establish the
reader's execution or frame meaning.

```sh
sha256sum research/binaries/us/Drakan.exe
python3 tools/research/measure_direct_record_writers.py \
  research/binaries/us/Drakan.exe --target 0x45f0d0
python3 -m unittest discover -s tools/research -p 'test_measure_direct_record_writers.py' -v
```

## RFL forwarder call-boundary follow-up, 2026-10-20

**Observed, static:** the sole executable call through the global loaded-RFL
interface pointer at `0x00483bf4` and its `+0x9c` slot is at `0x0040e113`.
Immediately before it, the
surrounding writer conditionally emits scalar fields from its current runtime
object (`esi`): it writes values derived from `+0x8c`, then `+0x8c` itself,
and then `+0x90` for a computed four-byte-unit span.  It clears the object's
`+0xac` sentinel before passing that same object as the sole stack argument
to the interface call.  There is no call to the investigated record
initializer or selector function in that immediate call boundary.

For the hash-pinned US `Dragon.rfl`, the installed `+0x9c` table entry is
`0x10015610`, a forwarding routine which passes its one argument to
`0x10016a80`.  That routine uses the object's word at `+2` to choose a
descriptor, then writes a descriptor-derived word and a span from object
`+0xa0` through the module raw-write helper.  The helper only writes when its
writer is in mode 2 with a selected record.  This establishes an object
serialization boundary conditional on the loaded interface table and writer
state.  It does not establish the selected record, output file, execution,
or that the serialized fields are the selector-`0x0020` conditional frames.

A whole-image textual scan also finds a separate `+0x9c` virtual call at
`0x00431eeb`, but its receiver is the current object (`esi`) rather than the
loaded-RFL global and it takes no stack argument.  The surrounding method
collects four return values into its caller-provided output structure; it
does not reference `0x00483bf4` in the inspected range.  Thus this second
call does not expand the established RFL forwarding path.

```sh
sha256sum research/binaries/us/Drakan.exe \
  research/installed/us/English_-_Program_Files/Dragon.rfl
objdump -d -Mintel --start-address=0x40df40 --stop-address=0x40e148 \
  research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x10015610 --stop-address=0x10015620 \
  research/installed/us/English_-_Program_Files/Dragon.rfl
objdump -d -Mintel --start-address=0x10016a80 --stop-address=0x10016ad7 \
  research/installed/us/English_-_Program_Files/Dragon.rfl
objdump -d -Mintel research/binaries/us/Drakan.exe | \
  rg 'call[[:space:]]+DWORD PTR \[[a-z]{3}\+0x9c\]'
```

## RFL `+0xa0` object-call boundary, 2026-10-20

**Observed, static:** after its local state work, the executable calls the
loaded-RFL interface's `+0xa0` entry at `0x0040d819`, passing the current
runtime object and a second address derived from the caller.  In the
hash-pinned US `Dragon.rfl` table, this slot is `0x100155c0`, which sets `ecx`
to the module's stored writer global and jumps to `0x100161e0`.  That target
does not read either forwarded stack argument in the inspected range.  It
loads the stored writer pointer and invokes a different module interface
entry with global bounds selected by a module global.

Consequently, the static call boundary does not show the module serializing
the executable's supplied object.  The executable input object and the
direct `0x0102` writer both use a word at `+2`, but this shared offset alone
does not establish object identity, selected record, or a producer for the
level object's skipped frames.

```sh
sha256sum research/binaries/us/Drakan.exe \
  research/installed/us/English_-_Program_Files/Dragon.rfl
objdump -d -Mintel --start-address=0x40d6c9 --stop-address=0x40d847 \
  research/binaries/us/Drakan.exe
objdump -s --start-address=0x1016b830 --stop-address=0x1016b838 \
  research/installed/us/English_-_Program_Files/Dragon.rfl
objdump -d -Mintel --start-address=0x100155c0 --stop-address=0x100155ca \
  research/installed/us/English_-_Program_Files/Dragon.rfl
objdump -d -Mintel --start-address=0x100161e0 --stop-address=0x10016227 \
  research/installed/us/English_-_Program_Files/Dragon.rfl
```

## Conditional full-object framing, 2026-10-19

The continuation at `0x004373d3–0x0043781e` requests four additional dwords
after the three previously described: three are stored at object `+8`, `+c`,
and `+10`; the next supplies flags, including bit `0x100`. It then requests
one word, a word count, that many word indices into the allocated object
table, and three more words. If the flags contain `0x100`, it requests
another 12 bytes. It next reads two signed dwords. If both are positive, it
requests four times the first count, two times the second count, and then,
for each unit of the second count, skips four bytes and skips a 16-bit
length-prefixed byte sequence. The skip helper `0x0045f430` reads the word
length even when passed a null destination. The loop then proceeds to the
next object. These descriptions assume all reads and skips succeed; the
retail caller does not check each return. The destination operations and later
object lifecycle are not modeled by this framing.

An independent bounded Python parser applied this sequence to the same 23
hash-checked US level snapshots. It parsed all 16,312 declared objects and
ended at the record boundary in every file. There were 4,128 objects with
bit `0x100`, 5,384 with both signed counts positive, and 13,418 skipped
length-prefixed sequences. This boundary agreement is evidence for the
conditional framing in these samples, not a proof of field meanings, runtime
success, or a general format rule.

The first three dwords of every parsed object can now be compared with the
same-file level entries, rather than only the first object. Of the 16,312
third-dword values, 15,462 are zero and do not match; 834 match exactly one
entry; and 16 nonzero values have no same-file match. Those 16 occurrences
span four files and five distinct values; each occurs among the first dwords
of entries in multiple other sampled levels.
This is a numeric cross-file comparison, not evidence that another level is
loaded or that such a match is used at runtime.

All 5,909 sampled index words are within their file's declared object count;
13 refer to their own object, 2,639 to earlier objects, and 3,257 to later
objects. No object's list repeats a target. Treating those words as directed
edges, 279 distinct edges have their reverse present, including the 13 self
edges; 5,630 do not. This is a measured relationship, not a guarantee that
indices are valid in other inputs or that the runtime objects persist. The
sample does not establish the purpose of these relations or the conditional
arrays, strings, and flags.

On the observed loading path, each input index selects an already allocated
object pointer from the eight-byte-per-item table. The code then acquires or
reuses a slot in a separate global six-byte-per-item table containing a
pointer and a word counter, increments that counter, and stores a one-based
slot number in the current object's `+0xbc` array. On a later release path,
`0x004292d0` clears the object's own slot pointer if present and decrements
the counters for its stored handles; a counter reaching zero triggers slot
cleanup. These actions are conditional on execution and successful allocation;
the original file words are indices, while the stored runtime words are
converted handles. No general ownership or gameplay meaning follows.

```sh
objdump -d -Mintel --start-address=0x4373d3 --stop-address=0x43781e research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x45f3d0 --stop-address=0x45f4c3 research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x4292d0 --stop-address=0x4293cc research/binaries/us/Drakan.exe
python3 tools/research/measure_level_objects.py research/installed/us research/exports/srsc-records/us.json
python3 tools/research/measure_level_objects.py research/installed/us research/exports/srsc-records/us.json --probe build/debug/level_objects_probe --inspector build/debug/dragonrider_inspect
python3 tools/research/measure_level_objects.py research/installed/us research/exports/srsc-records/us.json --probe build/release/level_objects_probe --inspector build/release/dragonrider_inspect
python3 -m unittest discover -s tools/research -p 'test_measure_level_objects.py' -v
```

The seven synthetic tests cover conditional branches, every truncation of a
representative object, signed counts, oversized requested spans, and directed
edge and conditional-word accounting. The inventory hash and parser operate on the same in-memory
snapshot. Confidence is high for the stated instructions and these sample
counts; runtime association, effect, and other editions remain unknown.
The Python parser and the test-only C++ callback probe agreed on the raw
dwords and words, index-word and optional-byte CRC32s, count bits and each
object's end position for all 16,312 objects in both GCC debug and release
builds on 2026-10-19. The probe receives the same verified in-memory snapshot;
it produces per-object values only in a captured pipe, not public files.
The inspector summary also agreed for 23/23 levels in each build. It reopens
the source path after the Python hash check, so concurrent file changes between
the two reads cannot be excluded.
The production reader's scope and safety policy are in [ADR 0025](../decisions/0025-level-object-framing.md).
The targeted C++ test also passed with GCC's `_GLIBCXX_ASSERTIONS` enabled
in a fresh build. Attempts to configure AddressSanitizer and
UndefinedBehaviorSanitizer builds failed at the compiler link check because
the host lacks `/usr/lib64/libasan.so.8.0.0` and
`/usr/lib64/libubsan.so.1.0.0`; sanitizer coverage is unverified.

## Conditional word-array lookup, 2026-10-19

When both counts are positive, the loader constructs a 24-byte helper using
`0x0042a6e0`; its table at `0x0047579c` includes `0x0042a790` at slot `+4`.
Under successful allocation and reads, the first conditional array is stored
at helper `+8` as four-byte units, and the second at `+0x14` as words; their
counts are stored at `+4` and `+0x10`. In `0x0042a7f0`, a low 16-bit
argument is compared sequentially with the second array's words and the first
matching position is returned. The table's `+4` method uses that position
with `0x00429f50` to form an address in the four-byte array when its second
argument is `-1`; an absent match instead delegates through helper `+0x0c`.
Other arguments take another path. Runtime dispatch, helper lifetime, the
delegated object, and the semantic role of either array remain unknown.
After the reads, the loader retains the helper at object `+0xa4` only when
the object's `+2` word is nonnegative as a signed 16-bit value; otherwise it
calls the helper destructor and clears that pointer. This gate depends on the
earlier runtime lookup result, not solely on the sampled bytes.

Among the 5,384 sampled objects with both counts positive, the second count
is at most the first in all and equals it in 4,806; none has repeated words
in the second array. Of 13,418 second-array words, 5,684 are numerically at
least the first count, across 3,685 objects. This reinforces that these words
cannot simply be assumed to be indices into the first array. These are sample
comparisons, not new format validity rules or evidence of runtime lookup.

For the 13,418 positions corresponding to sampled second-array words, the
low half of the same-position dword is below the first count in 8,942 cases;
its high half is zero in 7,632. The other 4,476 low halves are not below that
count. This matters only to the distinct method branch that uses a returned
dword's low half plus an additional argument; the actual argument, call path,
runtime mutations and object state are unknown. It does not establish an
invalid runtime access or an interpretation of the high half.

```sh
objdump -s --start-address=0x47579c --stop-address=0x4757bc research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x42a6e0 --stop-address=0x42a730 research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x42a790 --stop-address=0x42a81e research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x429f50 --stop-address=0x429f8c research/binaries/us/Drakan.exe
python3 tools/research/measure_level_objects.py research/installed/us research/exports/srsc-records/us.json
```

## Metadata and conditional-array candidates, 2026-10-19

**Observed, static:** GNU objdump 2.45.1-5.fc43 on the US retail executable
(SHA-256 `23630f48e20e8a9f42026501165ae1df407cfcee545a784ec930a4c25ee70648`)
shows that the `0x0047579c` table's `+8` method is `0x0042a820`. Given a
metadata entry, it traverses its groups using entry-relative and
group-relative offsets, and uses each helper word as a flattened descriptor
index. If the descriptor has flag `0x1000`, the method looks up that word
through slot `+4`, using the *first matching word position* to read a dword.
Its low half is a start and its arithmetic-shifted high half contributes a
signed length to an end check. Zero start or high half clears that dword;
an end at or above the helper's first count clears it and returns an error.
Otherwise the method dispatches the range through `0x0042a180`. Without the
flag it dispatches the same-position dword using the descriptor's low 12
bits. A second loop invokes `0x0042a2d0` for low type 10.

The manager path at `0x00429640` selects an object by index, attaches its
`+8` pointer via `0x0042a620` and searches the resource table using the
object's word at `+6`. The attach helper stores that pointer at an existing
helper's `+0x0c`; `0x0042a540` then conditionally invokes the existing
helper's slot `+8` with the selected object and matching metadata entry.
The level loader retains its helper at the corresponding level-object
`+0xa4` only after a nonnegative manager lookup. Its later conditional call to
`0x0040f680` supplies that index and level-object pointer. The initialization
thunk for global `0x00483928` calls `0x0040a030`, which installs table
`0x004754ec`; its `+0x1c` slot contains `0x0040f940`. If that table is still
installed at the virtual call, `0x0040f680` forwards the index and pointer
to `0x0040f940`, which passes them to `0x00429640`; the latter uses the
supplied non-null level object. Thus the traced path can reach the helper
dispatch with the retained helper. Actual manager contents, resource
selection and successful execution remain unverified.
Earlier processing can mutate the units; the following comparisons use the
original on-disk bytes and do not simulate a running game.

**Sample comparison:** `measure_level_object_metadata.py` reads the same
hash-verified snapshots of 178 US SRSC files, including 23 levels, and pins
the `ROC`/`OBJECTS` resource in the US RFL (SHA-256
`9b6496b65e962cf35dd1e18f424f2c8af08ceade78331dcc0b6da332ce844ac3`).
For each of 5,384 level objects with both counts positive, it compares the
second object dword's high half with that level's directory IDs, forms a
lexical `.odb` inventory key, matches its low half with the candidate file's
`0x0102` second selector, and selects the resource entry by the candidate
record's post-prefix metadata word. It requires uniqueness at every join and
checks the declared metadata count. Names from level records are never opened.
Same-path `.db` files come only from the separate 337-file inventory and are
hash-checked before comparing their IDs.

With direct extracted paths, 3,396 objects have unique candidate joins and
1,988 have no source-file key match; all 8,977 words in the joined objects
fit their candidate flattened metadata, and each corresponding skipped
four-byte frame prefix equals its descriptor flags. Under the separately
documented installer-overlay hypothesis, all 5,384 objects have unique
candidate joins and all 13,418 words fit; all 13,418 frame prefixes equal the
candidate descriptor flags. Those frame bodies are nonempty and contain only
printable ASCII or NUL bytes; 8,177 end in NUL. The loader skips these frames,
so their runtime purpose and interpretation are unknown.

In the overlay comparison, 686 words select flagged descriptors: their
same-position dwords yield 570 positive in-bounds candidate intervals and
116 with zero start or zero length; no signed-negative length or out-of-range
end was seen. All sampled words are distinct per object, so first-match and
same-position selection coincide. Of 748 scalar type-5 units, 621 have zero
high halves and the other 127 each match exactly one ID in the same-path
candidate descriptor; all 95 scalar type-9 units have zero high halves. These
are numerical joins, not evidence that a source pointer was resolved.

The 42 type-10 positions yield 41 nonempty spans inside the raw four-byte
array under a low-half start / unsigned high-half unit-count hypothesis, and
one zero-length span. All 41 bounded spans contain NUL; only 31 have exclusively
printable bytes before their first NUL, including an empty prefix if present.
This deliberately bounded experiment does not emulate the format scan at
`0x0042a2d0`, prove string content or identify runtime behavior.

For a separate raw coverage experiment, the first `m` positions are the
candidate base positions, where `m` is the word count, and the remaining
positions are extra units. The 570 in-bounds positive flagged intervals
and 41 bounded nonempty type-10 spans cover all 1,145 extra units: 946 only
by flagged intervals and 199 only by type-10 spans. No extra unit is covered
twice or by both categories, and no base unit lies in either category. This
is an observation under the candidate metadata and pre-mutation layout; it is
not a requirement imposed by the reader and does not prove runtime use.

```sh
sha256sum research/binaries/us/Drakan.exe research/installed/us/English_-_Program_Files/Dragon.rfl
objdump -s --start-address=0x47579c --stop-address=0x4757bc research/binaries/us/Drakan.exe
objdump -s --start-address=0x4754ec --stop-address=0x475514 research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x4072a0 --stop-address=0x4072aa research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x40a19c --stop-address=0x40a1ad research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x43785e --stop-address=0x4378ae research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x40f680 --stop-address=0x40f6aa research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x40f940 --stop-address=0x40f9c5 research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x429640 --stop-address=0x4297ab research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x42a620 --stop-address=0x42a636 research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x42a820 --stop-address=0x42aa40 research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x42a2d0 --stop-address=0x42a3f0 research/binaries/us/Drakan.exe
python3 tools/research/measure_level_object_metadata.py research/installed/us research/exports/srsc-records/us.json research/installed/us/English_-_Program_Files/Dragon.rfl --descriptors research/exports/asset-inventory/us.json
python3 tools/research/measure_level_object_metadata.py research/installed/us research/exports/srsc-records/us.json research/installed/us/English_-_Program_Files/Dragon.rfl --overlay-hypothesis --descriptors research/exports/asset-inventory/us.json
python3 -m unittest discover -s tools/research -p 'test_measure_level_object_metadata.py' -v
```

Confidence is high for the quoted instructions and measured US snapshots;
the overlay, runtime associations and interpretation in other editions are
unverified. The production reader now exposes the already-validated arrays
and entire frame sequence as raw input-backed views. Python and C++ compared
their CRC32 values for all 16,312 objects in both GCC debug and release,
using the probe commands above. Each inspector also matched the 23 level
summaries, including the new raw array and frame counts. These checks do not establish semantic
validity or identify asset names.
The updated targeted C++ test also passed with `_GLIBCXX_ASSERTIONS` in the
existing `/tmp/dragonrider-object-assertions` build on 2026-10-19.

## Candidate array-value comparison, 2026-10-19

**Measured:** a separate bounded comparison uses the same 178 SHA-256
verified US SRSC snapshots and the lexical candidate joins described above.
For each array-bearing level object, it takes each word as a candidate base
index in the joined `0x0102` array and compares the level dword at the word's
*position* with the candidate dword at that index. It does not open embedded
names or execute the game. This is an experiment on original file bytes,
not a claim that either runtime object retains those bytes after loading.

Under the installer-overlay hypothesis, 5,384 objects join uniquely and all
13,418 words have a corresponding level unit and candidate base unit. Only
1,754 unit pairs are exactly equal: 944 are both zero and 810 are nonzero.
The low halves agree in 4,346 pairs and the high halves in 7,823; all base
units agree for 166 objects. The level and candidate full array counts are
equal for 42 objects. Of the 686 pairs whose level frame dword has bit
`0x1000`, 103 base units match exactly. The other 12,732 pairs have 1,651
exact matches. Thus the previously observed exact frame matches do not imply
equal neighboring arrays under this positional hypothesis.

For a second, explicitly hypothetical comparison on the 686 flagged pairs,
interpret each unit's low half as a start and its positive signed high half
as a count, requiring nonzero starts and full containment in its own raw
array. The level side has 570 bounded positive ranges, the candidate side
109, and both sides are bounded for 91 pairs. Of those 91, 63 have equal
lengths and seven contain identical dwords. The bounds here permit a range
ending at the array boundary; they do not emulate the retail helper's
additional end check, dispatch, or mutations. A nonmatching candidate range
is not evidence that runtime data are invalid.

Without the overlay assumption, 3,396 objects join and 1,988 lack a unique
inventory-file key; 1,480 of 8,977 compared units match, including 866
zero pairs. There are 546 flagged comparisons, with 56 pairs of bounded
ranges and six exact range matches. Numeric equality, lexical matching and
these conditional intervals do not establish actual runtime source
selection, a producer, array semantics, or behavior in other editions.

```sh
python3 tools/research/measure_level_0102_arrays.py research/installed/us research/exports/srsc-records/us.json
python3 tools/research/measure_level_0102_arrays.py research/installed/us research/exports/srsc-records/us.json --overlay-hypothesis
python3 -m unittest discover -s tools/research -p 'test_measure_level_0102_arrays.py' -v
```

The four synthetic tests cover reversed candidate indices, half-word
comparison, short and duplicate records, counts outside the candidate base,
frame-count mismatch, signed range and truncation boundaries. The inventory
and parser use the same verified snapshots. Confidence is high for these
aggregate comparisons and conditional for the candidate joins.

## Direct writer-call check, 2026-10-19

**Observed, static:** the previously documented `0x0045f600` record
initializer has ten direct relative call sites in GNU objdump's disassembly
of the hash-identified US executable. Inspecting the immediate first-selector
arguments at those sites gives `0x0402`, `0x0400`, `0x0023`, `0x0021`,
`0x0102`, `0x0022`, `0x0320`, `0x0311`, `0x0302`, and `0x0051`; none is
`0x0020`. This bounded negative result does not exclude indirect calls, a
different writer or another executable, and does not identify the producer
of the sampled level frames. The instructions were inspected without executing
the writer, which can create or replace files.

```sh
objdump -d -Mintel research/binaries/us/Drakan.exe | rg -B 7 'call\s+0x45f600'
```

## Direct conditional-consumer call boundaries, 2026-10-21

**Observed, static:** a bounded whole-image GNU objdump 2.45.1-5.fc43 scan
of the hash-checked US retail executable finds one direct relative call to
the manager traversal at `0x004294d0`, at `0x0040cb4b`. Its enclosing routine
first calls a virtual method through its object at `+0x194` after pushing two
zero values, then invokes the manager through global `0x00482f78`, followed
by a neighboring direct call to `0x00429470`. The local window does not itself
write or pass a selected level-object's `+0x74`, `+0x78`, `+0x8c`, `+0xac`, or
`+0xb0` fields. It therefore establishes a bounded call boundary, not the
event that initialized or selected any particular object.

The same scanner finds three direct relative calls to fallback resolver
`0x004213f0`: `0x00420dd6`, `0x0042957a`, and `0x00445eb6`. The latter two
are separate local sequences that test a candidate object's `+0x8c`, `+0xac`,
and `+0xb0` fields before conditionally calling the resolver with the global
level object at `0x00480230`; both use fallback `+0xac` when the resolver
returns `0xffffffff`. The `0x0042957a` sequence is within the already traced
manager traversal. The `0x00445eb6` sequence independently has the same
local field gates, so the manager is not the sole statically observed
downstream field consumer. The bounded `0x00420dd6` call occurs in a separate
routine and has a different nearby immediate selector (`0x11` on one local
branch); no object identity or semantic relationship is inferred from it.

`measure_level_object_consumers.py` reports only direct call addresses and up
to three nearby immediate pushes in x86 source order. It records no
decompilation or raw bytes. It does not discover indirect/virtual calls,
register- or memory-supplied arguments, other modules, or execution. Thus it
cannot establish a conditional-frame producer, field lifetime, frame meaning,
or runtime timing.

```sh
sha256sum research/binaries/us/Drakan.exe
objdump --version | head -1
python3 tools/research/measure_level_object_consumers.py research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x40ca80 --stop-address=0x40cc20 research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x420d80 --stop-address=0x420e00 research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x429540 --stop-address=0x4295a0 research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x445e70 --stop-address=0x445ee0 research/binaries/us/Drakan.exe
python3 -m unittest discover -s tools/research -p 'test_measure_level_object_consumers.py' -v
```

The scanner also records direct relative tail jumps separately from calls. On
the hash-checked executable it finds a tail jump at `0x00408685` to the
manager traversal, after loading the manager global into `ecx`; the one direct
`CALL` remains `0x0040cb4b`. This distinction matters because Ghidra's
reference database classifies the tail transfer as a call reference. It does
not show whether either path executes.

Four synthetic tests cover target separation, immediate source ordering,
non-immediate pushes, indirect-call exclusion, tail-jump separation, and the
eight-instruction lookback bound. Confidence is high for the reported direct
instructions and limited callsite counts, but not for complete xrefs or runtime
behavior.

## Ghidra ownership and xref follow-up, 2026-10-21

**Observed, database-dependent:** a serialized read-only, no-analysis Ghidra
12.1.4 run against the existing US retail project reported the expected
executable SHA-256 above. It assigns the manager traversal to function
`0x004294d0` (body `0x004294d0`–`0x00429631`), the fallback resolver to
`0x004213f0` (body `0x004213f0`–`0x004219fd`), and the independent local
gate at `0x00445eb6` to function `0x00445bd0` (body
`0x00445bd0`–`0x004463ee`). The report's direct call references corroborate
all three resolver calls and add a manager reference at `0x00408685`; Ghidra
has no containing function for that latter address in this database. Independent
raw-byte inspection shows that reference is an `E9` direct tail jump, not a
`CALL`, as recorded above.

The same bounded xref query reports direct calls to the independent gate's
function entry at `0x0044011e` (inside `0x0043fe40`) and `0x00408727`
(unowned in this database). It reports no direct call reference to
`0x0040bf30`, the Ghidra owner of the known manager call at `0x0040cb4b`.
These facts narrow static entry boundaries only. They do not show indirect or
virtual callers, recover missing function ownership, establish execution,
connect either gate to skipped frames, or identify object lifetime or field
semantics.

`TraceLevelObjectConsumers.java` caps each target's printed direct call xrefs
at 40 and its instruction windows at 80; this run did not reach a cap. It
uses Ghidra's existing analysis database and therefore supplements rather
than supersedes the raw-disassembly scan. It exports no game bytes or
decompilation.

```sh
sha256sum research/binaries/us/Drakan.exe
export GHIDRA_HOME=/home/qpotato/opt/ghidra_12.1.4_PUBLIC
"$GHIDRA_HOME/support/analyzeHeadless" research/ghidra-projects Drakan_US_Retail -process Drakan.exe -readOnly -noanalysis -scriptPath tools/ghidra/scripts -postScript TraceLevelObjectConsumers.java
```

The local coordinator run used `-process Drakan.exe -readOnly -noanalysis`,
a cooperative project lock, unique ignored logs, and per-run XDG cache/config
directories. Close any GUI instance of the project before reproducing it;
serialize access with the same protections, because a Ghidra database is not
safe for concurrent project access.

## Candidate indirect gate route, 2026-10-21

**Observed, static:** the unowned short wrapper containing the independent
gate call at `0x00408727` starts at `0x004086f0`. It conditionally prepares
two stack values, calls `0x0043c4f0` through global `0x00483908`, then passes
its original receiver in `ecx` and global `0x00483890` to `0x00445bd0`.
The bounded Ghidra reference query finds no direct call reference to the
wrapper entry, but finds one data reference at `0x00408b2c`. Raw disassembly
confirms that initializer `0x00408a70` writes the wrapper address to an
object's table slot `+0x5c`.

A bounded whole-image text scan finds several `call [register+0x5c]`
instructions, including one at `0x0040cc15`; such an indirect call could only
reach the wrapper if its receiver has the table initialized by `0x00408a70`.
The static windows do not establish that receiver identity, table lifetime,
dynamic target, execution, or a relationship to the skipped level-object
frames. This is therefore a candidate indirect route, not a recovered caller
or frame producer.

```sh
sha256sum research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x4086f0 --stop-address=0x408730 research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x408a70 --stop-address=0x408bc2 research/binaries/us/Drakan.exe
objdump -d -Mintel research/binaries/us/Drakan.exe | \
  rg -i 'call[[:space:]]+(DWORD PTR )?\[[a-z]{3}\+0x5c\]'
python3 tools/research/measure_level_object_consumers.py research/binaries/us/Drakan.exe
python3 -m unittest discover -s tools/research -p 'test_measure_level_object_consumers.py' -v
```

## Loaded-RFL `+0x5c` replacement boundary, 2026-10-21

**Observed, static:** the sole direct reference to initializer `0x00408a70`
is its call at `0x00437bf5` inside `0x00437ab0`. Immediately beforehand, that
function calls a `GetProcAddress` result, stores its return in global
`0x00483bf4`, invokes the returned table's first entry, and passes the same
returned table address to `0x00408a70`. This corroborates the earlier bounded
trace that obtains `GetRFLInterface` for the loaded module. Thus, on this
static success sequence, the initializer writes local wrapper `0x004086f0`
to the returned RFL table at `+0x5c`; it is not merely an unrelated compatible
object table.

For the separately hash-pinned US `Dragon.rfl` input, table `0x1016b794`
contains `0x10152410` at offset `+0x5c`. The executable has a global-table
slot-`+0x5c` call at `0x0045afc8`; if that module was selected, the interface
return succeeded, the initializer executed, and the table was not later
changed, the call dispatches to the local wrapper rather than the module's
original entry. The original module entry and local wrapper have different
bounded instruction sequences, so no semantic equivalence is inferred.

This establishes an executable-installed interception boundary on the loaded
RFL table. It does not establish the loaded module identity, the dynamic table
address, execution order, original entry's semantic role, the wrapper's
runtime receiver, or a producer/consumer relation for the skipped conditional
frames.

**Observed, bounded helper context:** the wrapper first calls `0x0043c4f0`.
That helper compares masked inputs against a field at its receiver `+0x164`
and conditionally dispatches smaller state-update helpers. The read-only
Ghidra database reports four direct calls to it: `0x00408719` in the wrapper,
`0x00436a41`, `0x00436e5b`, and `0x0043b724`. The latter three do not call
the independent gate in their inspected local windows; two also use global
`0x00483908` as receiver. Consequently the wrapper's preliminary helper call
is a shared state-management boundary, not evidence for conditional-frame
handling.

```sh
sha256sum research/binaries/us/Drakan.exe \
  research/installed/us/English_-_Program_Files/Dragon.rfl
objdump -d -Mintel --start-address=0x437b74 --stop-address=0x437c08 research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x45afb0 --stop-address=0x45afcb research/binaries/us/Drakan.exe
objdump -s --start-address=0x1016b7e8 --stop-address=0x1016b808 research/installed/us/English_-_Program_Files/Dragon.rfl
objdump -d -Mintel --start-address=0x10152410 --stop-address=0x10152475 research/installed/us/English_-_Program_Files/Dragon.rfl
objdump -d -Mintel --start-address=0x43c4f0 --stop-address=0x43c5f2 research/binaries/us/Drakan.exe
```

## Loaded-RFL `+0x5c` aggregation caller separation, 2026-10-21

**Observed, static:** the Ghidra 12.1.4 read-only/no-analysis report records
`0x0045afb0` as a function ending at `0x0045afef`, with one direct caller at
`0x0045ac72` in function `0x0045ab80`. Independent GNU objdump disassembly
shows that caller allocating or selecting a 2,052-byte aggregate slot,
then invokes `0x0045ad40`, `0x0045aee0`, `0x0045afb0`, `0x0045b050`,
`0x0045b100`, and `0x0045b170` in sequence. Each receives an address based on
the current aggregate offset, and each result advances that offset. The
`0x0045afb0` contribution is therefore one bounded stage in this aggregate
routine, not a direct call from the level-object manager.

Inside that stage, the installed table's `+0x5c` entry receives a stack-local
128-byte buffer and constant `0x80`. Its output is then passed, together with
the caller-supplied argument and static format address `0x0047d75c`, to
`0x0046810c`. The raw data at that address is an ASCII backslash-delimited
percent-format fragment. The pinned module's original entry at `0x10152410`
instead derives one of four constants from a module-global mode and forwards
the caller buffer and two stack arguments to `0x10157000`; that helper is a
bounded NUL-aware byte-copy routine in the inspected range. Neither bounded
executable caller window nor the original module entry reads the level global
at `0x00480230`, manager fields, SRSC selectors, or a conditional frame.

This rules out only the **inspected static aggregation boundary** as direct
evidence that the installed interception handles conditional frames. It does
not identify the aggregate's full protocol, prove a dynamic table target or
execution, establish the original slot's semantic name, or exclude relations
through uninspected callers and indirect state.

```sh
sha256sum research/binaries/us/Drakan.exe \
  research/installed/us/English_-_Program_Files/Dragon.rfl
objdump -d -Mintel --start-address=0x45ab80 --stop-address=0x45acd0 research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x45afb0 --stop-address=0x45afef research/binaries/us/Drakan.exe
objdump -s --start-address=0x47d570 --stop-address=0x47d7e0 research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x10152410 --stop-address=0x10152475 research/installed/us/English_-_Program_Files/Dragon.rfl
objdump -d -Mintel --start-address=0x10157000 --stop-address=0x101570fe research/installed/us/English_-_Program_Files/Dragon.rfl
```

The Ghidra check used the existing `Drakan_US_Retail` project after verifying
that no Ghidra GUI/headless process was active, a cooperative project lock,
unique ignored logs and temporary XDG state. Run `run-FhNtFBTd` completed on
2026-10-21 with the US executable hash above and Ghidra 12.1.4. The report
prints at most 40 direct xrefs and 80 instructions per window; neither cap
was reached. Database xrefs remain incomplete evidence for indirect calls.

## Resolver-query and object-field setup separation, 2026-10-21

**Observed, static:** the third direct call to fallback resolver `0x004213f0`,
at `0x00420dd6`, belongs to Ghidra function `0x00420960` (body
`0x00420960`–`0x00420e00`), rather than either of the two field-gated manager
sequences. In the bounded call window, that routine chooses a neighboring
query routine `0x00420e10` on three branches; otherwise it calls the fallback
resolver with an incoming integer and four incoming values, including literal
`0x11` on one branch. It then passes the result and the same incoming values
to `0x00420960` itself at `0x00420df3`. No `+0x74`, `+0x78`, `+0x8c`,
`+0xac`, or `+0xb0` object-field access occurs in that local call window.
Ghidra records six direct entries to `0x00420960`, including this recursive
call and two calls internal to `0x004213f0`; the existing database cannot
establish its complete indirect callers or execution.

Thus the third direct resolver call is a separately bounded recursive-query
route, not a fourth static instance of the level-object's field-gated
consumer. This classification does not give semantic names to its values,
prove that its receiver is the global level object on any execution, or rule
out a relation through state outside the inspected window.

**Observed, static object setup:** Ghidra assigns initializer `0x00428000`
to body `0x00428000`–`0x004280e2` and records its one direct call at
`0x004292bc` within allocator `0x004291a0`. The initializer writes zero to
`+0x8c`, and `-1` to both `+0xac` and `+0xb0`. Two separately bounded setter
windows subsequently write `+0x8c` from a selected object's `+0x24` while
also assigning that object to `+0x74`: `0x00428445` in function `0x00428340`
and `0x0042972d` in function `0x00429640`. Each then calls through the
selected object's first table entry. These instructions corroborate a static
setup path for three manager gate fields, but do not establish the selected
object's meaning, lifetime, which setter reaches an allocated object, or any
conditional-frame producer/body semantics.

**Observed, direct-boundary follow-up:** the Ghidra report records three
direct calls to allocator `0x004291a0`, including `0x0043731b` in the traced
level-object reader `0x00437290`. Raw disassembly shows that reader invokes
the allocator through manager global `0x00482f78` in a counted allocation
loop before it reads the object entries. The report records three direct calls
to first setter function `0x00428340`, including `0x00445da8` in the
independent gate `0x00445bd0`. Raw disassembly shows that call occurs before
that gate reads its receiver's `+0x74`, then reaches its later `+0x8c`,
`+0xac`, and `+0xb0` condition sequence. Therefore the static path can set
the `+0x8c` gate input before that gate reads it. It does not show whether the
branch takes this setter call, whether its target is a level-reader allocation,
whether any condition succeeds, or how a conditional frame body is used.

```sh
sha256sum research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x420d76 --stop-address=0x420dfe research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x428060 --stop-address=0x4280e2 research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x428436 --stop-address=0x428462 research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x42971a --stop-address=0x42977e research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x4372f6 --stop-address=0x437390 research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x445d60 --stop-address=0x445ec8 research/binaries/us/Drakan.exe
```

Serialized read-only/no-analysis Ghidra 12.1.4 run `run-Ee3r0Cyw` corroborated
the recursive-query ownership and its direct call entries; follow-up run
`run-reMapSp5` corroborated the initializer/setter ownership and the single
direct allocator call. Both used the existing hash-matched US retail project,
the cooperative lock, unique ignored logs, and temporary XDG state. The script
caps each call-xref list at 40 and instruction window at 80, with no cap
reached. These reports are database-dependent and do not prove complete xrefs.
Run `run-JS5ro3uF` additionally recorded the bounded direct calls to the
allocator and both setters; its lists also remained below the cap.

## Conditional-object serialization forwarder boundary, 2026-10-21

**Observed, static:** raw executable disassembly identifies a contiguous
callback-style range beginning at `0x0040dd30`. Its early error return at
`0x0040dd5c` is followed by the successful continuation at `0x0040dd5f`, so
the existing Ghidra database does not assign the latter instructions (and the
`+0x9c` dispatch at `0x0040e113`) to a containing function. Before that
dispatch, the range writes fields at `+0x8c`, `+0xac`, and `+0xb0` from its
`ESI` object to a writer, together with other fields of the same object.
**Inferred, cautiously:** the matching offsets to those initialized by
`0x00428000` and inspected by the field-gated consumers make this a candidate
object-serialization boundary in the same object family; offset coincidence
alone does not prove object identity.

On its path to `0x0040e113`, the range checks/updates `ESI+0xac`, loads the
loaded-RFL table global at `0x00483bf4`, pushes `ESI`, and calls its `+0x9c`
entry. The pinned module forwarder at `0x10156210` forwards its one object
argument to `0x10156a80`; the inspected module window reads that object's
`+2` and `+0xa0` fields. The executable pointer `0x0040dd30` occurs once in
the `.rdata` pointer array at `0x00475520`, while the serialized Ghidra
database records no direct relative call xrefs to it. This supports an
indirect/callback route rather than identifying an ordinary direct caller.

The bounded evidence does **not** prove that this range is invoked for a
level-reader allocation, that the loaded module is selected or executes, that
the forwarded object is a conditional frame, or that the module writes a
selector-`0x0020` record. It also does not assign semantic names to any
object field. Ghidra's missing ownership after the early return is a database
coverage limitation, not proof of a separate function.

```sh
sha256sum research/binaries/us/Drakan.exe \
  research/installed/us/English_-_Program_Files/Dragon.rfl
objdump -d -Mintel --start-address=0x40dd30 --stop-address=0x40e150 research/binaries/us/Drakan.exe
objdump -s --start-address=0x475500 --stop-address=0x475560 research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x10156210 --stop-address=0x10156270 research/installed/us/English_-_Program_Files/Dragon.rfl
objdump -d -Mintel --start-address=0x10156a60 --stop-address=0x10156b20 research/installed/us/English_-_Program_Files/Dragon.rfl
```

Serialized read-only/no-analysis Ghidra 12.1.4 runs `run-KjjqP29q`,
`run-lM81Bp9Y`, and `run-HNrT2HCb` used the hash-matched US retail project,
cooperative lock, unique ignored logs, and temporary XDG state. The first
reported no containing function for `0x0040df40` or `0x0040e113`; the second
reported zero direct call xrefs to `0x0040dd30`; and the third reported zero
database xrefs to its raw pointer location `0x00475520`. The script caps
each xref list at 40, and none of these zero-result queries reached the cap.
As with all database xrefs, indirect-table references and dynamic calls
remain outside that result.

## Frame text and candidate 0x0102 comparison, 2026-10-19

**Measured:** the candidate RFL descriptor's first dword, treated as an
offset relative to that 16-byte descriptor, points to a NUL-terminated byte
sequence within the pinned resource in every compared case. After removing
at most one terminal NUL from each level frame body, all 13,418 bodies equal
the corresponding descriptor sequence under the overlay-based join above.
There are 8,177 bodies with exactly one terminal NUL and 5,241 with no NUL;
none contains an embedded NUL. All are nonempty printable ASCII. None is a
standalone signed decimal integer, decimal fraction or `0x`-prefixed hex
integer under the explicitly tested byte patterns. This does not identify
the strings' semantic role or prove that the offset is interpreted by retail
code as a string pointer.

Within each joined resource entry, compare the frame's flag and normalized
text with *all* candidate descriptors, rather than only its indexed one.
Every descriptor in the joined entries has a bounded candidate text under
the same 512-byte limit. 13,411 frames have exactly one matching pair,
while seven match multiple descriptors. Therefore even this pair cannot be
treated as a unique key in the sample; the observed equality uses the
separate word index.

A separate comparison parses a candidate sequence of `(dword, u16 length,
body)` frames after the array in each `0x0102` record and joins each level
object to its lexical source candidate without using RFL metadata. Every one
of the 13,418 level frames equals its indexed candidate `0x0102` frame
byte-for-byte, including the raw length and body, across all 5,384 joined
objects under the overlay hypothesis. With direct extracted paths, all 8,977
frames across 3,396 joined objects match; 1,988 objects have no unique file
candidate. Index words are used only as an experimental comparison, not
enforced as a reader validity rule.

These comparisons use hash-checked in-memory US snapshots and emit aggregate
counts only. They do not establish that the original runtime selected these
sources, that the data was produced by the retail executable, or that the
level loader consumes the skipped text. The frame producer and runtime
meaning remain unknown. Confidence is high for these measured relations,
conditional on the stated joins; other editions and input sets are untested.
The related complete `0x0102` sample-tail measurement is in
[the 0x0102 investigation](srsc-0102-runtime.md#metadata-frame-tail-comparison-2026-10-19).

```sh
python3 tools/research/measure_level_object_metadata.py research/installed/us research/exports/srsc-records/us.json research/installed/us/English_-_Program_Files/Dragon.rfl --overlay-hypothesis --descriptors research/exports/asset-inventory/us.json
python3 tools/research/measure_level_object_metadata.py research/installed/us research/exports/srsc-records/us.json research/installed/us/English_-_Program_Files/Dragon.rfl --descriptors research/exports/asset-inventory/us.json
python3 tools/research/measure_level_0102_frames.py research/installed/us research/exports/srsc-records/us.json --overlay-hypothesis
python3 tools/research/measure_level_0102_frames.py research/installed/us research/exports/srsc-records/us.json
python3 -m unittest discover -s tools/research -p 'test_measure_level_object_metadata.py' -v
python3 -m unittest discover -s tools/research -p 'test_measure_level_0102_frames.py' -v
```

On 2026-10-19 the targeted metadata and direct-comparison suites passed 13
and 2 tests respectively; the full research suite passed 190 tests. Debug
and release builds each passed 17 CTests, and both independent probe runs
compared all 16,312 objects and 23 inspector summaries. These checks cover
the current GCC/Linux environment, not other platforms.
