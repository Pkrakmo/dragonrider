# SRSC `0x0102` indexed payload consumer

**Input and method:** unpatched US retail `research/binaries/us/Drakan.exe`,
SHA-256 `23630f48e20e8a9f42026501165ae1df407cfcee545a784ec930a4c25ee70648`;
GNU objdump 2.45.1-5.fc43, Intel syntax, static disassembly on 2026-10-18.
The [lookup-order note](srsc-lookup-order.md) supplies previous Ghidra 12.1.4
corroboration of the loader accessors and the source-qualified value. This
follow-up did not access a Ghidra project. **Confidence:** high for the
specified instructions and their successful branches, limited for runtime
associations and untraced callers.

## Observed

- In `0x00429b00`, after an optional open of the input object's loader, the
  code requests `(0x0402, 0, 0)` and conditionally reads a dword into a
  temporary value. It continues only when that value equals `0x0102` at
  `0x00429ba2`. This is a payload value checked by the function, separate
  from the later `0x0102` **record selector**. If the lookup fails, the
  temporary was initialized to `0x0100`; read errors are not checked there.
- The loop at `0x00429c17` reads each table entry's second and first selector
  words using `0x0045faa0` and `0x0045fa70`, respectively. For a first word
  of `0x0102`, it selects that same index with `0x0045f270`, then calls
  `0x0045f430` with a buffer capacity of 256. On a successful helper path,
  `0x0045f430` reads a 16-bit byte count, reads up to the capacity, terminates
  the buffer, and skips any excess. It then requests a two-byte skip via
  `0x0045f3d0` and a four-byte read via `0x0045f370`
  (`0x00429c42`–`0x00429c67`). The caller does not check the returns of these
  operations, so this sequence describes successful reads, not malformed input
  behavior.
- The high 16 bits of that payload dword are passed to `0x0041e3e0`. That
  function, for a nonzero argument, searches the input object's array of
  eight-byte entries for a matching first dword and returns the second dword;
  it returns its receiver unchanged when the key is zero, and zero if a
  nonzero key has no matching entry. If a
  non-null object is returned, the caller replaces the payload dword's high
  half with that object's `+0x114` value shifted left 16, preserving its low
  half; otherwise it clears the whole dword (`0x00429c6c`–`0x00429c94`).
- The next successful two-byte read is stored at runtime object `+6`; after
  another two-byte skip, the code compares the read word against first dwords
  in an unrelated in-memory table with 32-byte entries. A match supplies a
  word and a dword stored in the runtime object; a missing match exits the
  function with an error (`0x00429c9a`–`0x00429d08`, `0x00429de8`–`0x00429e1f`).
  This comparison uses payload bytes, not the third selector word.
- On a subsequent successful branch, `0x00429db9`–`0x00429dd1` constructs a
  second source-qualified dword from the input object's `+0x114` shifted left
  16 and the current record's second selector in the low half. The two
  source-qualified dwords therefore have distinct inputs and are stored at
  different runtime-object offsets (`+0xc` and `+0`).

## Inferred and unknown

The payload dword's high half is a key for a runtime lookup on this path; its
low half is preserved on a successful match. The runtime target object's role,
which source files take this path, and the relationship to the same-file
`0x0102` third-word / `0x0101` second-word matches remain unknown. No third
selector accessor appears in the traced loop; this does not exclude indirect
use by called functions or another path. No game execution was performed.

## Sample measurement

On 2026-10-18 a bounded aggregate scan of the hash-checked US inventory found
4,203 `0x0102` records in 39 of 178 examined files. All 4,203 begin with a
fitting nonempty length-prefixed sequence containing only ASCII printable or
NUL bytes, and have at least ten bytes after it; 2,182 end the sequence in
NUL. At the payload position read as the dword above, its high half is zero
in 3,771 records. All 4,203 table third words are nonzero; only one equals
that payload high half. These are byte comparisons, not evidence that every
sample reaches this consumer or that either value has a general semantic name.
The initial 2026-10-18 script reopened validated files after the hash check,
so concurrent changes between reads were not excluded in that run. The
2026-10-23 snapshot recheck below removes that limitation from the current
measurement script. It outputs aggregate counts only.

## Prefix-measurement snapshot recheck, 2026-10-23

`measure_srsc_0102_prefix.py` now receives the table selectors and full file
bytes from the same hash-verified `read_snapshot` call. It no longer reopens
the source file between table parsing and payload measurement. A fresh scan
reproduced 178 examined files, 39 files with `0x0102`, all 4,203 fitting
prefixes and ten-byte following regions, and the prior aggregate selector
comparisons. The six focused tests passed, including stale-hash, unexamined,
truncation, and out-of-range cases. This changes measurement consistency only;
it does not establish runtime consumption or selector meaning.

## Post-prefix word and selector comparison, 2026-10-18

On the consumer's successful read path, the helper at `0x0045f430` consumes
the two-byte prefix length and its specified bytes; the following call at
`0x00429c58`–`0x00429c5c` requests a two-byte skip. It then requests the dword
read described above. The skip helper checks its remaining read budget before
advancing, but the caller does not check the helper's return. The two bytes
are therefore not used as a key by this specific successfully traced path.

An independent Python 3.14.7 aggregate scan read the 178 installed US SRSC
files once each and checked their sizes and SHA-256 values against the private
inventory before parsing. In all 4,203 `0x0102` records from 39 files, the
little-endian word immediately following the length-prefixed bytes equals the
third selector word. The word is nonzero in every case and equals exactly one
`0x0101` second selector in the same file; it equals the `0x0102` second
selector in 14 cases. No selected prefix or post-prefix word was truncated.
The `0x0101` match is a numeric join, not evidence that the traced consumer
performs a `0x0101` lookup or that a runtime association occurs.

As a counterexample to generalizing the byte position, the same measurement
found that only 10 of 1,561 `0x0302` post-prefix words in 19 files equal their
third selector; 954 post-prefix words are zero, while all 1,561 third selectors
are nonzero. All selected prefixes and words fit. The `0x0302` comparison does
not establish that its consumer interprets that location as a word. These
counts are observations of this retail extraction, not validation rules or
evidence of the producer's intent. No game execution was performed.

## Descriptor key connection, 2026-10-18

The descriptor-loading loop described in [database descriptors](database-descriptors.md)
selects an object from its caller's array into `ebp` at `0x0041e98e`–`0x0041e991`.
After reading a dependency integer into a stack temporary and obtaining a non-null
object through an indirect call, it appends that integer and object pointer to
the selected object's eight-byte array at `+0x108`, incrementing the count at
`+0x110` (`0x0041eb2f`–`0x0041ec82`). The `0x0041e3e0` lookup called by the
`0x0102` consumer searches those same offsets and returns the pointer from the
first matching pair. After the descriptor loop, `0x0041ecc9` passes that same
selected object to `0x0041e5a0`, which in turn passes it to `0x00429b00` at
`0x0041e5bb`–`0x0041e5c1`; that consumer passes it to the lookup at
`0x00429c6c`–`0x00429c74`. On this traced path the payload high word therefore
selects an integer/object pair populated by the descriptor loop, provided the
loop and intervening calls succeed and the array is not changed by an alias.
A zero key bypasses the search and returns the receiver. This does not establish that the path executes,
that an arbitrary sample is its input, successful path resolution, or a general
third-selector meaning.

The descriptor loader copies a string from the selected object and calls the
suffix helper with `.db` at `0x0041e9e1`–`0x0041ea19`. The consumer opens its
loader using index zero on the same object if necessary (`0x00429b3d`–`0x00429b57`);
the index-zero path supplies `.odb`. The common helper appends the suffix only
when it does not find an existing extension. This supports the same-base pairing
for extensionless object paths, but neither proves actual filenames nor requires
the optional open if a loader is already present.

An independently bounded comparison paired `.odb` and `.db` files by relative
path in the hash-verified installed US inventory. All 39 `.odb` files had a
descriptor and contained `0x0102` records. Of their 4,203 records, 3,771 payload
keys were zero. Of 432 nonzero keys, 426 matched exactly one descriptor ID,
six matched none, and none matched multiple IDs. These six occurrences belong
to three pairs, with four distinct missing-key values summed per file (a value
repeated in different files is counted once in each). All 39 `.odb` files have
exactly one `(0x0402, 0, 0)` record, at least four bytes long, whose first
little-endian dword is `0x0102`, the value tested by this consumer. This checks
the bytes and tuple, not the outcome of its runtime seek or read.

All six unmatched nonzero-key occurrences have nonzero low halves. Among the
3,771 zero-key occurrences, 2,942 also have nonzero low halves. A correction
to the earlier interpretation: `0x0041e3e6` tests the key, `0x0041e3e8`
copies the receiver into `eax` without changing flags, and `0x0041e3ea`
branches directly to the return for zero. On this consumer's successful path
the receiver was already dereferenced, so the zero-key case uses that receiver's
`+0x114` for the high half and preserves the low half. A nonzero key with no
match, or a matching entry whose pointer is null, instead clears the whole
dword. For the six unmatched keys this outcome additionally assumes the runtime
array corresponds to the paired descriptor and has no other matching entries.
The scan does not prove that the sampled records are consumed or used later.

Twenty pairs also have a same-path `.lvl` file; none of the three pairs with
missing keys is among them. For those 20 files, the optional comparison uses
the independently decoded `(0,0,0)` level directory values, with all three
files hash-checked. It cannot explain the six missing keys. These are record
occurrences, not distinct keys; pathname pairing and numeric equality do not
prove runtime associations. The comparison does not resolve descriptor paths.
Each file is read once and its bytes are checked against the manifest before
measurement. The script emits aggregates, not asset names or payloads.
Confidence is high for the stated static branches and measured sample,
conditional for runtime behavior.

## Model lookup and candidate comparison, 2026-10-18

**Observed, static:** the object created by `0x00429a70` is inserted in the
manager's pointer array at `+8`. The `0x0102` reader stores the transformed
payload dword in that object's `+0xc` and its source-qualified own selector at
`+0`. A later manager path indexes that pointer array at `0x00429661`–`0x00429664`
and passes the selected object to `0x00428bd0` at `0x0042971a`–`0x0042971c`.
That helper returns zero for a zero `+0xc`; otherwise it passes the dword to
`0x00424690` (`0x00428bd0`–`0x00428be0`). The latter searches a cache by the
full dword and, on a miss, invokes `0x004246d0`.

The cache-miss path looks for an object whose `+0x114` equals the dword's high
half. If found, it opens that object's index-1 loader if needed, and calls the
two-word SRSC search with kind `0x0200` and the same dword; the search compares
the low 16 bits as its second selector (`0x004246ea`–`0x0042476e`). Index 1
conditionally appends `.mod`; see [model records](model-geometry-records.md)
and [loader callers](loader-callers.md). Thus, on these conditional paths, the
`0x0102` dword can select a model source and a `0x0200` record. A cache hit,
earlier failure, existing loader, later record validation, and actual execution
can change the observed outcome; no game was run.

**Sample comparison, not runtime resolution:** using the 337-file private US
inventory from [retail inventory](retail-asset-inventory.md), Python 3.14.7
verified the size and SHA-256 of every examined `.odb`, its same-path `.db`,
and each inventoried `.mod`. It matched each nonzero payload high word to a
unique descriptor ID, then formed an overlay-relative Windows-style string by
combining the descriptor directory and dependency name, normalizing `..`, and
appending `.mod`. It compared that string case-insensitively with inventoried
`.mod` paths after dropping their top-level extraction group. Names were never
used to open files; only inventory paths were opened, and unsupported or
escaping names were counted separately. This assumed overlay and lexical path
model is not proof of the retail installation layout or Windows path behavior.

Across 39 `.odb`/`.db` pairs and 4,203 `0x0102` records, 3,771 have zero high
words and six have no matching descriptor ID. Of the remaining 426, eight have
no model candidate under this string comparison and 418 have exactly one; none
has multiple candidates. Of those 418 occurrences, 416 have exactly one
`0x0200` record with a matching second selector in that candidate model, and
two have none; none has multiple matches and all 418 low words are nonzero.
Counts are record occurrences, not unique models or runtime calls. The two
missing records and eight missing candidate files do not establish broken game
data: extraction completeness, overlay, actual path values, cache state, and
runtime resolution remain unknown. The script tests selector membership only;
it does not validate model payloads or reproduce the manager's cache.

The original nonzero-key comparison excludes the 3,771 zero-key occurrences.
Applying the same overlay assumption to a same-base `.mod` candidate for the
receiver, 3,747 occurrences have one candidate and 24 have none; none has
multiple candidates. Of the 3,747, 2,884 low words match exactly one `0x0200`
second selector and 863 match none. Of those 863, 805 have a zero low word;
the remaining 24 zero-low occurrences have no candidate model. The scan checks
membership even for zero low words: whether the transformed full dword is zero
depends on the receiver's runtime `+0x114`, and the earlier helper skips a
zero full dword. These are lexical and numeric comparisons, not evidence of
which model actually loads or whether the cache-miss search executes.

### Exception follow-up

The same hash-checked inventory scan groups the exceptions by source file and
compares their low words with `0x0200` selectors in every inventoried `.mod`.
The six missing-descriptor-ID occurrences come from three source files and
comprise five distinct `(high, low)` pairs summed per file. Four of these six
low-word occurrences appear in exactly one inventoried model, and two appear
in multiple models. This is numeric membership, not an alternative resolution.

The eight missing lexical model-candidate occurrences come from four source
files and represent eight distinct `(candidate string, low word)` pairs summed
per file. The inventory lists both same-base `.db` and `.odb` paths for four
of those occurrences and neither for the other four; this is a manifest path
comparison, not a check that the game opened those files. Two low-word
occurrences appear in exactly one inventoried model, and six in multiple
models. The two low words missing from their uniquely selected candidate models
come from two source files and each appears in multiple other inventoried model
tables. The 29 inventoried model files were hash-checked before their table
keys were counted. Model counts here are per file containing the low word,
not the number of matching entries within a file; values are not globally
unique and these comparisons cannot identify a target.

On the traced cache-miss path, `0x00424775`–`0x00424786` returns zero if the
`0x0200` pair search returns `-1`. That zero propagates through `0x00428bd0`,
and `0x00429721`–`0x00429726` stores it at the destination object's `+0x74`
and skips the following model-dependent block. The enclosing routine continues
after that block; the later effects are untraced. This is conditional static
behavior, not proof that any particular sampled exception reaches it.

## Reproduction

From the repository root:

```sh
sha256sum research/binaries/us/Drakan.exe
objdump --version
objdump -d -Mintel --start-address=0x429b00 --stop-address=0x429e84 research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x41e3e0 --stop-address=0x41e41c research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x45f2d0 --stop-address=0x45f4c3 research/binaries/us/Drakan.exe
python3 tools/research/measure_srsc_0102_prefix.py research/installed/us research/exports/srsc-records/us.json
python3 -m unittest discover -s tools/research -p 'test_measure_srsc_0102_prefix.py' -v
python3 tools/research/measure_srsc_prefix_selector.py research/installed/us research/exports/srsc-records/us.json
python3 -m unittest discover -s tools/research -p 'test_measure_srsc_prefix_selector.py' -v
objdump -d -Mintel --start-address=0x41e940 --stop-address=0x41ed1f research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x41e5a0 --stop-address=0x41e646 research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x41e420 --stop-address=0x41e510 research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x409020 --stop-address=0x409082 research/binaries/us/Drakan.exe
python3 tools/research/measure_0102_descriptor_keys.py research/installed/us research/exports/asset-inventory/us.json
python3 -m unittest discover -s tools/research -p 'test_measure_0102_descriptor_keys.py' -v
objdump -d -Mintel --start-address=0x429640 --stop-address=0x42972b research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x428bd0 --stop-address=0x428c50 research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x424690 --stop-address=0x424789 research/binaries/us/Drakan.exe
python3 tools/research/measure_0102_model_candidates.py research/installed/us research/exports/asset-inventory/us.json
python3 -m unittest discover -s tools/research -p 'test_measure_0102_model_candidates.py' -v
```

## Conditional dword-array follow-up, 2026-10-18

**Observed, static:** after the earlier ten post-prefix bytes and successful
32-byte-table match, the consumer requests a dword at `0x00429d4d`–`0x00429d57`
and compares it with the matching runtime entry's dword at `+0x14`. A mismatch
exits with an error at `0x00429e22`. If it matches, the consumer requests a
second dword at `0x00429d6b`–`0x00429d72`, passes it to `0x0042a5d0`, and,
if that helper returns zero, requests a bulk read of four times that dword at
`0x00429d8a`–`0x00429da6`. The helper creates a container and forwards the
count to `0x00429ee0`; its allocation size is also calculated with 32-bit
multiplication by four. The reader's fixed and bulk read return values are not
checked by this caller, and overflow, allocation failure and truncated input
must not be assumed to behave like the mathematical framing below. On the
success branch the caller invokes `0x0045f7a0`; in read mode that function
clears the current-record selection without consuming the remaining budget.
A different routine at `0x00429f50` can address entries of the resulting buffer
as four-byte units, but their general meaning remains unproven.

**Sample measurement:** an independent Python 3.14.7 scan checks the exact
size and SHA-256 of each of 178 inventoried US SRSC files before parsing its
single in-memory snapshot. For each `0x0102` record it measures the two dwords
at the above conditional positions and checks `count <= remaining_bytes / 4`
using integer arithmetic, without assuming a runtime table match. All 4,203
selected records in 39 files contain both dwords and the mathematical count of
four-byte units; counts range from 0 to 271, totaling 84,258 units, of which
41,015 are zero. In 3,127 records the two dwords are numerically equal. Both
are zero in 18 records; the other 4,185 have both nonzero. The 18 zero-count
records have no bytes after the measured units; all 4,185 nonzero-count
records have additional bytes, with a maximum of 4,602. No count reaches the
32-bit multiplication-overflow threshold. These observations do not establish
that the condition succeeds for any sample, that the two dwords must agree,
or that extra bytes are invalid. The conditional consumer does not establish
what other readers or writers do with those bytes.

**Unknown:** the dwords' semantic names, the units' general meaning, the extra
bytes' structure, and actual runtime behavior remain unverified. The subsequent
sections investigate a candidate resource and selected unit-processing paths.
Confidence is high for the specific instructions and measured US snapshot,
conditional for execution. No game or Ghidra project was run.

```sh
sha256sum research/binaries/us/Drakan.exe
objdump --version
objdump -d -Mintel --start-address=0x429c9a --stop-address=0x429dd7 research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x42a5d0 --stop-address=0x42a615 research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x429ee0 --stop-address=0x429f47 research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x45f2d0 --stop-address=0x45f36e research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x45f7a0 --stop-address=0x45f804 research/binaries/us/Drakan.exe
python3 tools/research/measure_0102_tail.py research/installed/us research/exports/srsc-records/us.json
python3 -m unittest discover -s tools/research -p 'test_measure_0102_tail.py' -v
```

## Opaque tail byte summary, 2026-10-18

A hash-checked aggregate scan of the same 178 US files located the bytes after
the conditional dword array without saving or printing their contents. All
4,185 nonempty tails contain at least four bytes; together they contain
1,835,088 bytes, of which 334,257 are zero. None of the tails is entirely zero.
The most common first dword values are `1` (1,828 records), `7` (963), `2`
(400), `0x1003` (255), and `10` (254). The first-byte histogram matches the
low byte of these values for all 4,185 records. This suggests a repeated
little-endian dword prefix in the sample, but does not identify its field or
meaning, prove that every tail begins with a dword, or connect it to a runtime
reader/writer. The remaining tail layout stays unknown.

Reproduction and synthetic boundary checks:

```sh
python3 tools/research/measure_0102_tail_bytes.py research/installed/us research/exports/srsc-records/us.json
python3 -m unittest discover -s tools/research -p 'test_measure_0102_tail_bytes.py' -v
```

### Candidate second dword

The same scan splits the second tail dword into its low and high 16-bit halves.
In all 4,185 nonempty tails, the high half's two little-endian bytes are
printable ASCII. The low half fits within the bytes after the first eight tail
bytes in 4,157 records; at that candidate length, 4,052 bodies end in NUL.
The 28 values that exceed the available bytes show this is not a universal
length rule. Even where it fits, the candidate bodies account for only part of
each tail: 1,747,956 bytes remain after taking those lengths. The frequent
pairs include `In`, `Wa`, `Da`, `Ty`, `Sp`, and `Mo`; the most common candidate
lengths are 14, 12, 6, 18, and 4. No string or field-name meaning is
established. The pairs, low-word sizes, NUL endings, and first dword are
measured byte patterns, not confirmed record fields.

The most frequent first-dword/tag pairs are `(1, In)` (1,254), `(7, Wa)`
(332), `(1, Da)` (304), `(7, Ty)` (260), `(10, Di)` (230), and `(0x1003, Sp)`
(206). This shows the two candidate components are associated in the sample;
it does not establish an enum, a property name, or a semantic relationship.
A bounded disassembly search for the corresponding immediate constants in
the retail executable found no matches. Generic table-driven or resource-based
handling is still possible, and no runtime path has been linked to these bytes.

```sh
objdump -d -Mintel research/binaries/us/Drakan.exe | rg -i '0x(6e49|6157|6144|7954|7053|6f4d|6944)([^[:xdigit:]]|$)'
python3 tools/research/measure_0102_tail_bytes.py research/installed/us research/exports/srsc-records/us.json
```

### Consumer and direct-caller boundary

A bounded whole-image disassembly scan found one direct relative call to
`0x00429b00`, at `0x0041e5c1`. Its caller then invokes other readers with the
same source-object argument but different global objects at `0x0041e5d5`,
`0x0041e5e9`, `0x0041e5fd`, `0x0041e611`, and `0x0041e625`. This shows the
consumer is one stage in a larger load routine; it does not establish what
those other methods do with the current record or rule out indirect callers.
The source object contains several loader pointers; the argument is not itself
the selected loader. See the subsequent loader-stage follow-up below.

In the traced success path, `0x00429b00` reads its length-prefixed field,
performs the conditional resource-table comparison, reads the dword array,
clears the selected record through `0x0045f7a0`, and returns. That clear does
not consume the remaining record budget. The common two-byte tail pairs were
also searched as immediate constants in this executable's disassembly with no
matches. Together, these checks found no direct code explanation for the
measured tail patterns. They do not rule out a generic or indirect parser,
another caller, or interpretation by a later subsystem. The tail bytes remain
unassigned.

```sh
objdump -d -Mintel research/binaries/us/Drakan.exe | rg 'call[[:space:]]+0x429b00'
objdump -d -Mintel --start-address=0x41e5a0 --stop-address=0x41e648 research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x429b00 --stop-address=0x429e83 research/binaries/us/Drakan.exe
```

Together these observations suggest the tail may contain tagged or
length-prefixed substructures, but a single candidate body length does not
explain the entire tail, and the runtime reader/writer traces examined so far
do not account for it. Keep the remainder opaque pending a matching code path.

## Candidate resource-table provenance, 2026-10-18

**Observed, static:** if the manager's `+0x2c` pointer is null,
`0x00429b26`–`0x00429b3a` asks `0x00411cc0` for the resource named `OBJECTS`
of type `ROC`, then stores its returned pointer there. The helper calls
`FindResourceA`, `LoadResource`, and `LockResource` on the module handle in
global object `0x004800f0`. The consumer subsequently treats the returned
pointer as a dword count followed by 32-byte entries: it searches each entry's
first dword for the zero-extended post-prefix word, and compares the first
post-prefix tail dword against the matched entry's dword at `+0x14`
(`0x00429cb8`–`0x00429d65`). The executable's nearby mismatch diagnostic
mentions parameters and an RFL; this text is corroborating context, not a full
semantic specification.

The module-loading helper at `0x00411c00` calls `LoadLibraryA` on its supplied
path, checks an exported version result, and stores the module handle in that
same global object on its successful path. Its caller at `0x00437ab0` copies
its own nonempty path argument before calling the helper at `0x00437b67`.
This static trace does **not** identify the path supplied at runtime or show
that the manager's pointer was initially null. It does not establish that an
arbitrary sample reaches the consumer or that resource bytes remain unchanged.

**Candidate and measurement:** the separately inventoried US retail
`English_-_Program_Files/Dragon.rfl` has SHA-256
`9b6496b65e962cf35dd1e18f424f2c8af08ceade78331dcc0b6da332ce844ac3`.
GNU objdump 2.45.1-5.fc43 lists a `ROC` / `OBJECTS` resource, language `0x0409`,
RVA `0x183fd8`, size `0x1198b`; its `.rsrc` maps that RVA to file offset
`0x180fd8`. A separate Python 3.14.7 scanner pins the whole RFL hash before
reading that bounded range. It verifies that the resource's count and
32-byte entries fit, and hash-checks each SRSC input before comparing a
single in-memory snapshot. The scanner uses this version-specific offset; it
is not a general PE resource parser. It emits aggregates only.

The candidate resource has 145 entries with 145 distinct first-dword keys.
All 4,203 selected `0x0102` records across 39 of 178 files have exactly one
matching key for the word at the traced position. In every case the next
conditionally compared dword equals that entry's `+0x14` dword. This is a
numeric comparison against the named resource in one pinned module, not proof
of module selection, successful resource lookup, actual dispatch, or execution.
The bulk array's later count differs from that compared dword in 1,076 samples,
so matching the resource's `+0x14` does not imply those two payload dwords are
equal. The resource's other fields and the array-unit meanings remain unknown.
Confidence is high for these static instructions and the measured snapshots;
runtime conclusions remain conditional. No game execution or Ghidra project
access was performed.

## Array processing and metadata comparison, 2026-10-18

**Observed, static:** the container constructed at `0x0042a5d0` installs the
table at `0x0047578c`; its slots `+4` and `+8` contain `0x00429f50` and
`0x00429f90`. On a later conditional manager path `0x0042a540` resolves two
source pointers by comparing high halves of the record object's `+0` and
`+0xc` with objects' `+0x114`, then invokes container slot `+8`. For each
base index up to the resource entry's `+0x14` count, `0x00429f90` uses the
entry-relative offsets at `+0x1c` to traverse groups, and the group-relative
offset at `+8` to locate a 16-byte descriptor. For descriptors without flag
`0x1000`, it passes the corresponding four-byte array unit and the low 12
flag bits to `0x0042a180`. Descriptors with that flag follow a separate
indirection path and are excluded from the comparison below.

The dispatch table at `0x0042a298` routes type 5 and type 9 to
`0x0042a1b6` and `0x0042a200`, respectively. Both leave a zero unit zero;
otherwise each calls `0x0041e3e0` with its high half, using the first or
second resolved source pointer respectively. A non-null result replaces the
high half with that object's `+0x114` shifted left 16 while preserving the
low half; a null result clears the unit. For a zero key the lookup returns
its receiver, including null if the receiver is null. Dispatch, pointer
identity, earlier mutations and all successful-branch assumptions remain
unverified at runtime; this is not a complete interpreter for the resource.

**Sample measurement:** the pinned RFL resource contains 145 entries, 528
groups and 3,046 grouped descriptors; every entry's summed group count equals
its declared base count. The bounded scanner matches each of the 4,203
hash-checked US records to a unique resource key, checks its declared count
and that the payload array has at least that many units, then compares only
unflagged base-index units to their candidate metadata. It finds 5,459 flagged
base entries and 65,223 unflagged entries of other types. For type 5 there
are 6,001 units: 4,855 zero, 598 nonzero with a zero high half, and 548 with
a nonzero high half. Each of those 548 high halves matches exactly one ID in
the same-path, hash-checked descriptor. For type 9 there are 1,089 units: 429
zero and 660 nonzero, all with zero high halves. The descriptor comparison is
a numeric join under the assumed same-path pairing; it does not prove that the
resolved first source pointer is that descriptor's object, that fields are
unmodified at dispatch, or that either dispatch executes. Extra array units,
flagged entries and other types are not interpreted. No game execution or
Ghidra project access was performed.

```sh
objdump -s --start-address=0x47578c --stop-address=0x475798 research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x429640 --stop-address=0x42972b research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x429f50 --stop-address=0x42a297 research/binaries/us/Drakan.exe
objdump -s --start-address=0x42a298 --stop-address=0x42a2c8 research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x42a540 --stop-address=0x42a615 research/binaries/us/Drakan.exe
python3 tools/research/measure_0102_array_types.py research/installed/us research/exports/srsc-records/us.json research/installed/us/English_-_Program_Files/Dragon.rfl --descriptors research/exports/asset-inventory/us.json
python3 -m unittest discover -s tools/research -p 'test_measure_0102_array_types.py' -v
```

Resource provenance reproduction:

```sh
sha256sum research/binaries/us/Drakan.exe research/installed/us/English_-_Program_Files/Dragon.rfl
objdump --version
objdump -d -Mintel --start-address=0x429b00 --stop-address=0x429d78 research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x411c00 --stop-address=0x411cfb research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x437ab0 --stop-address=0x437b90 research/binaries/us/Drakan.exe
objdump -s --start-address=0x47cf5c --stop-address=0x47cfd8 research/binaries/us/Drakan.exe
objdump -h research/installed/us/English_-_Program_Files/Dragon.rfl | rg '\.rsrc'
objdump -x research/installed/us/English_-_Program_Files/Dragon.rfl | rg -A 13 'The .rsrc Resource Directory section'
python3 tools/research/measure_0102_resource_table.py research/installed/us research/exports/srsc-records/us.json research/installed/us/English_-_Program_Files/Dragon.rfl
python3 -m unittest discover -s tools/research -p 'test_measure_0102_resource_table.py' -v
```

## Flagged ranges and type-10 spans, 2026-10-18

**Observed, static:** on the slot-`+8` path described above, if a descriptor
has flag `0x1000`, `0x00429ffe`–`0x0042a046` reads the corresponding base
unit, takes its low half as an index and sign-extends its high half. A zero
low or zero high takes the branch that clears that base unit. Otherwise it
computes `end = low + signed_high - 1` and compares `end` with the container
count using a signed comparison. If `end` is at least the count, the path
clears the base unit and returns an error. Otherwise the signed increasing
loop at `0x0042a074`–`0x0042a0a9` applies the descriptor's type to units from
`low` through `end` inclusive. A negative high can pass the upper check but
does not enter that increasing loop. This describes the inspected dispatch
path and is not a recommended input-validation algorithm.

After that loop completes, `0x0042a0bb`–`0x0042a159` separately visits each
base descriptor with low type bits equal to 10 and calls `0x0042a2d0`. That
helper forms a pointer from the low half of the base unit, passes it with a
format string and output pointer to `0x0046861d`, and returns early unless
the result is positive. Its later branch uses the high half multiplied by
four as a byte length while manipulating a buffer and array storage. The
format bytes at `0x0047d010` spell `<0x%x>`. The format string and pointer
use motivate the bounded raw-byte comparison below; they do not prove all
type-10 bytes have a particular encoding or that this branch runs. The helper
can modify array storage and base descriptors, so a raw scan is not a replay.

**Sample measurement:** Python 3.14.7 checked the pinned US retail RFL and
the 178 SRSC inventory snapshots as in the preceding section. Using the
matched candidate metadata and original payload units, 3,729 of 5,459 flagged
base units have both halves zero. The other 1,730 have positive signed high
halves and form in-bounds intervals entirely after the base units. Within
each record these intervals do not overlap and cover 4,426 extra units. No
negative high, out-of-bounds end or base overlap was found in this sample.

The scan also finds 366 type-10 base entries: 143 have both halves zero and
223 have nonzero high halves. Treating the latter's low half as a starting
index and unsigned high half as a unit count gives in-bounds, non-overlapping
candidate spans entirely after the base units, covering 2,060 extra units.
All 223 contain a NUL within that span and have only ASCII printable bytes
before the first NUL; 129 start with the stricter byte pattern
`<0x` followed by one or more ASCII hex digits and `>`. This pattern test is
not an emulation of the helper's parser. The type-10 spans do not overlap the
flagged intervals, and their union covers all 6,486 extra array units in the
sample. Counts refer to raw record occurrences; the samples do not establish
mandatory partitioning, character encoding, successful parsing, or runtime
behavior. No game execution or Ghidra project access was performed.

Confidence is high for the listed instructions and the measured snapshots,
conditional for runtime execution and resource identity. The retail helper's
pointer-derived input is not shown to be bounded by the candidate span, and
earlier dispatch or aliases may change array contents.

```sh
sha256sum research/binaries/us/Drakan.exe research/installed/us/English_-_Program_Files/Dragon.rfl
objdump --version
objdump -d -Mintel --start-address=0x429f50 --stop-address=0x42a16d research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x42a2d0 --stop-address=0x42a46f research/binaries/us/Drakan.exe
objdump -s --start-address=0x47d010 --stop-address=0x47d020 research/binaries/us/Drakan.exe
python3 tools/research/measure_0102_indirect_ranges.py research/installed/us research/exports/srsc-records/us.json research/installed/us/English_-_Program_Files/Dragon.rfl
python3 -m unittest discover -s tools/research -p 'test_measure_0102_indirect_ranges.py' -v
```

## `0x0101` association and prefix bytes, 2026-10-18

**Observed, static:** a whole `.text` direct-call search in GNU objdump finds
two calls to the third-selector accessor `0x0045fad0`: `0x0042b0d9` copies
its result into the 26-byte cache entry at `+4`, and `0x00435601` tests it
for zero before checking for kind `0x0030`. The `0x0102` loop at
`0x00429c17`–`0x00429c30` reads the second and first selectors, while its
subsequent successful payload path skips the word which matches the third
selector in the sample. The previously bounded cache-consumer scan is in
[lookup order](srsc-lookup-order.md#follow-up-third-word-consumers). These
direct calls and inspected windows do not establish that any retail path
resolves the sampled `0x0102`/`0x0101` association, nor do they exclude
indirect calls, other memory accesses, or code outside the disassembly scan.

**Sample measurement:** Python 3.14.7 reads and SHA-256 checks each of 178
US SRSC files once, then compares raw prefix bytes within that snapshot. It
removes one trailing NUL, if present, from each `0x0102` prefix and `0x0101`
label. Each `0x0101` payload must fit its declared length exactly; each
`0x0102` prefix must fit within its record. Source byte strings are never
emitted or used as filesystem paths; chain traversal is limited to one million
steps per file. Of 4,203 `0x0102` records, all match
one `0x0101` second selector in the same file; none of their normalized prefix
strings is empty, contains NUL, or contains a byte outside ASCII `0x20`–`0x7e`.
Seven contain a slash or backslash, and 92 contain a colon. These are byte
counts, not proof of encoding or filesystem use.

Exact normalized `0x0102` prefix bytes are unique within each sampled file.
ASCII-only byte lowercasing yields five repeated occurrences within files,
but none within the same file and associated `0x0101` selector. A source
prefix equals its directly matched label in 124 cases, or 130 after ASCII
lowercasing. Under the purely numeric assumption that each nonzero label third
word points to another same-kind second selector and zero ends the chain,
all 4,203 source occurrences reach zero: 1,203 after one matched label,
1,282 after two, and 1,718 after three or more. Their prefix equals at least
one label along that candidate chain in 125 cases. The sample does not show
that the executable traverses this chain, that comparisons are case-insensitive,
or that any of these observed properties are format requirements. Confidence
is high for the specified static windows and aggregate measurements, limited
for runtime behavior and other editions. No game execution or Ghidra project
access was performed.

```sh
sha256sum research/binaries/us/Drakan.exe
objdump --version
objdump -d -Mintel research/binaries/us/Drakan.exe | rg 'call +0x45fad0'
objdump -d -Mintel --start-address=0x42b0b0 --stop-address=0x42b0ef research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x4355f0 --stop-address=0x435620 research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x429c17 --stop-address=0x429c60 research/binaries/us/Drakan.exe
python3 tools/research/measure_0102_label_names.py research/installed/us research/exports/srsc-records/us.json
python3 -m unittest discover -s tools/research -p 'test_measure_0102_label_names.py' -v
```

## Range values and type-10 selector comparison, 2026-10-18

The later [type-12 lookup investigation](level-0001-prefix.md#first-dword-lookup-and-type-12-candidates-2026-10-19)
traces another dispatch branch to a level entry's first dword and compares
candidate range values with hash-checked US levels. The active level and
runtime state remain unknown.

**Observed, static:** on the conditional flagged-range branch above,
`0x0042a085`–`0x0042a09d` passes each addressed unit to `0x0042a180` using
the descriptor's low 12 type bits. Thus, if the other assumptions in the
[array dispatch trace](#array-processing-and-metadata-comparison-2026-10-18)
hold, type-5 and type-9 range units use the same source-pointer lookup paths
as unflagged units. This does not prove that a sampled range is processed.

The type-10 helper passes the output slot used by `0x0046861d` as the first
argument to the global receiver's slot `+0x40`, with zero as the fourth
argument (`0x0042a2f5`–`0x0042a338`). If that receiver uses one of the tables
identified in [selector 0x0400 dispatch](srsc-selector-0400-dispatch.md),
the conditional path looks up `(0x0400, first argument low 16 bits, 0)`.
The helper has an early return when the first call's result is not positive;
runtime receiver identity, parser behavior and successful dispatch remain
unknown.

**Sample measurement:** using the pinned RFL, hash-checked US SRSC inventory
and same-path descriptor inventory, the bounded scanner inspected only the
raw in-bounds intervals from the preceding comparison. Of 1,319 type-5
range-unit occurrences, 63 are zero, 985 have a zero high half and nonzero
low half, and 271 have a nonzero high half. All 271 nonzero high halves match
exactly one ID in their same-path descriptor. The 304 type-9 range units all
have zero high halves, of which 15 are entirely zero. These are numeric joins
against the source file's descriptor, not proof that the resolved source
pointer identifies it or that the raw values persist until dispatch.

For the 129 type-10 candidate spans beginning with the stricter complete
`<0x` + hex digits + `>` pattern, the scanner converts the bounded digits
as an unsigned integer up to 32 bits and compares its low word to every
inventoried `0x0400` second selector whose third word is zero. All 129 values
fit in 16 bits; 128 occurrences have one matching table entry and one has two.
The comparison covers 426 records in one inventoried file. Its sole duplicate
selector key has two payloads with equal length and SHA-256. The other 94
nonempty type-10 spans do not match this stricter pattern; this comparison
does not emulate the retail parser or classify its acceptance. The selected
runtime receiver, source file, lookup order, mutations and call outcomes
remain unverified. Inputs are hash-checked independently on each of two
inventory passes; changes between passes are not excluded. No source bytes
or tag values are emitted, and no game execution or Ghidra access was used.

```sh
sha256sum research/binaries/us/Drakan.exe research/installed/us/English_-_Program_Files/Dragon.rfl
objdump --version
objdump -d -Mintel --start-address=0x42a074 --stop-address=0x42a0ab research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x42a2d0 --stop-address=0x42a34e research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x42c240 --stop-address=0x42c2c9 research/binaries/us/Drakan.exe
python3 tools/research/measure_0102_indirect_ranges.py research/installed/us research/exports/srsc-records/us.json research/installed/us/English_-_Program_Files/Dragon.rfl --descriptors research/exports/asset-inventory/us.json --compare-0400
python3 -m unittest discover -s tools/research -p 'test_measure_0102_indirect_ranges.py' -v
```

## Structural inspector verification, 2026-10-18

`--record-0102` exposes the traced prefix sequence without runtime resolution;
its policy and input bounds are in [ADR 0019](../decisions/0019-srsc-0102-prefix-inspection.md).
The following independent Python comparison checked all fields and prefix
CRC32 against both debug and release inspectors for 4,203 records in 39 of 178 hash-checked
US files; all 4,203 have opaque trailing bytes. The current script stages each
verified input snapshot to a temporary file before invoking the inspector. No
retail bytes are emitted.

```sh
python3 tools/research/verify_srsc_0102.py research/installed/us research/exports/srsc-records/us.json build/debug/dragonrider_inspect
python3 tools/research/verify_srsc_0102.py research/installed/us research/exports/srsc-records/us.json build/release/dragonrider_inspect
# Both: files=178 files_with_0102=39 comparisons=4203 records_with_tails=4203
```

## Array inspector verification, 2026-10-18

`--record-0102-array` reports the conditional array framing without applying
runtime resource checks; [ADR 0020](../decisions/0020-srsc-0102-array-inspection.md)
records the bounds and limits. An independent Python decoder compared the
selected dword, entry count, array CRC32 and opaque tail length for all 4,203
records and 84,258 entries across 178 hash-checked US SRSC files, using both
GCC debug and release inspectors. Each verified input snapshot is written to a
temporary file for the inspector, so its output is compared against the same
bytes as the independent decoder. No retail bytes are emitted.

```sh
python3 tools/research/verify_srsc_0102_array.py research/installed/us research/exports/srsc-records/us.json build/debug/dragonrider_inspect
python3 tools/research/verify_srsc_0102_array.py research/installed/us research/exports/srsc-records/us.json build/release/dragonrider_inspect
# Both: files=178 files_with_0102=39 comparisons=4203 entries=84258
```

## Temporary-snapshot verifier recheck, 2026-10-23

Both `verify_srsc_0102.py` and `verify_srsc_0102_array.py` now pass a temporary
file containing the exact hash-verified bytes to `dragonrider_inspect`, rather
than asking it to reopen the original path. The file is staged once per
source container and reused for that file's selected record comparisons. Two
synthetic integration tests confirm the verifier gives the inspector those
same bytes; a third confirms both scripts reject symlinked inventory paths.
Fresh runs against all 178 inventory entries matched 4,203
`0x0102` records in both GCC debug and release inspectors; the array variant
also matched 84,258 entries in both builds. This closes the inspector-side
reopen gap for these comparisons, without changing the compared fields or
their interpretation.

## Tail framing hypotheses, 2026-10-19

**Observed, sample measurement:** Python 3.14.7 re-read and SHA-256 checked
178 US retail SRSC inventory files, including 39 with 4,203 `0x0102` records.
After the conditional array framing, 18 records have no tail and 4,185 have a
nonempty tail. The independent scanner starts four bytes into each nonempty
tail, interprets the next two bytes as a little-endian length, and counts the
following *length* bytes as a candidate frame body. This body includes the two
printable bytes previously described as the high half of the second dword.
All 4,185 first candidate bodies fit; 1,389 end in NUL and 28 end exactly at
the record boundary. The difference from the earlier 4,157 fitting bodies is
that the earlier experiment started its candidate body **after** those two
printable bytes, rather than including them in the stated length.

Continuing at the first candidate body's end, a second candidate length and
body fit in 4,052 tails, of which 860 end in NUL; 105 declare a body longer
than the available bytes and 28 lack a complete next length. None of the
second bodies ends at the record boundary. Repeating this framing greedily
reaches the boundary for only 30 tails; 4,149 encounter an oversized body and
six a truncated length, after 11,319 fitting candidate bodies in total. The
loop permits zero lengths, advances at least two bytes per iteration, and has
a 65,536-frame limit; no sampled tail hit the limit.

Two further models treat the initial dword, or only its low 12 bits, as a
count of these consecutive frames. The full-dword model reaches the boundary
for one tail, leaves bytes for 2,228, and fails for 1,956; the low-12 model
reaches the boundary for one, leaves bytes for 2,275, and fails for 1,909.
Thus neither simple count model explains the sampled tails. These are bounded
byte experiments, not evidence that the game parses these candidate frames,
that the initial dword is a count or flag field, or that their bodies are
strings. The actual tail grammar and runtime consumers remain unknown. No game
execution, Ghidra project access, patch inputs, or source byte dumps were used.
Confidence is high for this hash-checked sample and the specified algorithms,
not for other editions or runtime interpretation. Concurrent modification
within a file read is not excluded; the inventory's recorded hashes verify the
read snapshots. A later [metadata-based frame comparison](#metadata-frame-tail-comparison-2026-10-19)
fits the complete sample using a different framing and count; runtime
consumption remains unknown.

```sh
python3 --version
python3 tools/research/measure_0102_tail_framing.py research/installed/us research/exports/srsc-records/us.json
python3 -m unittest discover -s tools/research -p 'test_measure_0102_tail_framing.py' -v
```


## Immediate subsequent loader stage, 2026-10-19

**Observed, static:** the larger load routine at `0x0041e5a0` passes the
same source-object pointer to the `0x0102` reader and its immediate successor
`0x00435540`. The `0x0102` reader uses the loader pointer in source-object
slot `+0x120`, optionally calling `0x0041e470` with index 0. Its successor
instead uses slot `+0x144`, optionally calling that helper with index 3
(`0x0043554d`–`0x00435573`). Thus the earlier phrase “same loader argument”
was imprecise: both receive the same source object, but load distinct pointer
slots. The suffix construction trace associates indices 0 and 3 with `.odb`
and `.txd` respectively when no extension already exists; actual runtime
paths, preexisting loader state and pointer aliasing are unverified.

The successor's next operation on its selected loader requests tuple
`(0x0402, 0, 0)` at `0x00435579`–`0x00435593`. On a successful selection it
reads a dword and clears that selection, then compares the dword with `0x0204`.
On the matching branch it iterates entries and, if a third selector is zero
and the first is `0x0030`, selects that indexed record (`0x004355ea`–
`0x00435622`). These instructions do not consume the previous reader's
unselected `0x0102` tail directly; if the slots alias, the new selection can
change loader position and state. This limited trace does not exclude aliases or indirect callbacks, or show
any runtime execution. The initial operations of the four later methods are
examined below. Confidence is high for the bounded instructions, limited
for file and runtime identity. No Ghidra project was accessed.

```sh
sha256sum research/binaries/us/Drakan.exe
objdump --version
objdump -d -Mintel --start-address=0x41e5a0 --stop-address=0x41e648 research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x429b3d --stop-address=0x429ba9 research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x435540 --stop-address=0x435630 research/binaries/us/Drakan.exe
```


## Remaining source-object loader stages, 2026-10-19

**Observed, static:** on successive permitted branches the load routine at
`0x0041e5a0` passes the same source object to four more stages. Each loads a
separate pointer slot and optionally opens it with the listed index. Each then
requests `(0x0402, 0, 0)`, conditionally reads a dword, clears the selection,
and compares the result to the listed value:

| Stage | Source slot | Open index | Conditional suffix | Compared value |
| --- | --- | --- | --- | --- |
| `0x004158b0` | `+0x150` | 4 | `.adb` | `0x0102` |
| `0x004245d0` | `+0x12c` | 1 | `.mod` | `0x010a` |
| `0x00431830` | `+0x15c` | 5 | `.sdb` | `0x0104` |
| `0x0042f2f0` | `+0x168` | 6 | `.ssd` | `0x0102` |

The first three initially use `0x0100` as the fallback comparison value;
the last uses `0x0101`. The `.txd` and `.odb` stages are described above.
Suffixes are conditional on an extensionless source path; preexisting loader
pointers, runtime execution, file identity and pointer aliasing remain
unknown. Different source-object slots are not proof of distinct pointers.
No Ghidra project or game execution was involved.

**Sample measurement:** Python 3.14.7 checked the sizes and SHA-256 hashes of
all 178 US SRSC inventory files, then classified the six suffix groups above
and in the preceding trace. Each of the 153 matching-extension files contains
exactly one `(0x0402, 0, 0)` entry of at least four bytes, whose initial dword
matches the respective static comparison: 39 `.odb`, 38 `.txd`, 12 `.adb`,
29 `.mod`, 19 `.sdb`, and 16 `.ssd`. The other 25 files have different
extensions and are not classified. This lexical comparison does not establish
actual runtime filenames, selection success or format invariants. Confidence
is high for the bounded instruction paths and checked snapshots, limited for
runtime associations and other editions. Concurrent file modification during
reading is not excluded; each read buffer is checked against its hash.

```sh
sha256sum research/binaries/us/Drakan.exe
objdump --version
objdump -d -Mintel --start-address=0x4158b0 --stop-address=0x415947 research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x4245d0 --stop-address=0x424684 research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x431830 --stop-address=0x4318dd research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x42f2f0 --stop-address=0x42f381 research/binaries/us/Drakan.exe
python3 tools/research/measure_srsc_stage_gates.py research/installed/us research/exports/srsc-records/us.json
python3 -m unittest discover -s tools/research -p 'test_measure_srsc_stage_gates.py' -v
```

## Metadata frame tail comparison, 2026-10-19

**Measured:** an independent bounded scan of the 178 hash-verified US SRSC
snapshots interprets each `0x0102` tail after the previously measured array
as a candidate sequence of its declared metadata-count frames. Each frame is
a little-endian dword, a little-endian 16-bit byte length, and that many
bytes. The script pins the same US `Dragon.rfl` SHA-256
`9b6496b65e962cf35dd1e18f424f2c8af08ceade78331dcc0b6da332ce844ac3`
and uses the previously documented unique resource-key comparison.

All 4,203 sampled records contain exactly the declared number of frames and
end at the record boundary, including records with zero declared frames. All
77,772 frame dwords equal their corresponding candidate metadata descriptor
flags. All 77,772 frame bodies, after removing at most one terminal NUL,
equal the bounded NUL-terminated bytes at the descriptor-relative offset in
the descriptor's first dword. Offsets are tested against the resource bounds
and a 512-byte terminator limit; neither a general string encoding nor a
runtime pointer interpretation is established by this comparison. The
previous [tail framing hypotheses](#tail-framing-hypotheses-2026-10-19)
tested different count and framing models; this one uses the separate
declared metadata count and includes a dword for *each* frame.

Of the 77,772 bodies, 35,200 have one terminal NUL and 42,572 have none;
none has an embedded NUL. Grouped by candidate resource key and descriptor
index, all occurrences of each of the 2,947 represented descriptors have
identical raw bodies, including their NUL treatment. This is a sample
property, not an additional format constraint.

**Observed, static:** the retail helper `0x0045f750` scans a NUL-terminated
input, masks the scan count with `0xfffe`, writes its low 16 bits, then, if
that write succeeds, writes that many bytes from the input. For short input
strings this gives an even byte count: a terminal NUL is included when the
text length is odd, and omitted when it is even. All 77,772 measured bodies
follow that rule; the same holds for all 13,418 joined level frames. The
input executable is US retail `Drakan.exe`, SHA-256
`23630f48e20e8a9f42026501165ae1df407cfcee545a784ec930a4c25ee70648`;
the method is GNU objdump 2.45.1-5.fc43, without game execution. Two direct
calls to this helper appear in the disassembly, at `0x0040b5ed` and
`0x0040e2d5`; these are in the documented `0x0400` and `0x0022` writer
paths, respectively. Neither identifies a writer for the sampled `0x0102` or
level frames. Indirect calls, other implementations and external tools
remain possible. Matching output does not identify the producer or prove the
helper was called for these records.

**Observed, static, module follow-up:** in the hash-pinned US `Dragon.rfl`,
GNU objdump 2.45.1-5.fc43 shows a second helper at `0x10156440` with the
same scan-and-mask rule. Its lower-level write helper checks mode 2 and a
selected record, then uses the module's `WriteFile` import. A whole-image
disassembly search finds one direct call to the string helper, at
`0x1001613b`. The enclosing `0x10016110` first calls record initializer
`0x101562f0` with immediate first two selector values `0x0401` and `0x037b`,
then passes a pointer at object `+4` to the string helper and closes the
record. The caller does not check those return values in this sequence.
The initializer stores the two arguments in the first two words of a
14-byte entry and copies existing writer state into its third word. No
execution, actual output file, indirect calls or alternate writers were
established. This does not identify the sampled frame producer; the scan
only covers direct relative calls in this one module. The same scan finds
two direct calls to this initializer: both have immediate first selector
`0x0401`, with second selector `0x037b` or `0x037d` respectively. The latter
does not call the string helper in the inspected sequence. This bounded
negative result does not rule out a different writer or indirect call.

In the 178 hash-checked US SRSC snapshots, neither `(0x0401, 0x037b)` nor
`(0x0401, 0x037d)` occurs as a first/second selector pair, regardless of
third selector. This does not establish the module writer's target file,
execution, complete installation or behavior in another edition.

**Observed, static, RFL follow-up:** for US retail
`English_-_Program_Files/Dragon.rfl` (SHA-256
`9b6496b65e962cf35dd1e18f424f2c8af08ceade78331dcc0b6da332ce844ac3`), GNU
objdump 2.45.1-5.fc43 shows that the initializer scan has a concrete
limitation: another module routine, `0x10016a80`, invokes the raw write helper
`0x101563e0` with a
two-byte value followed by a byte span. Before these calls it uses the input
object's word at `+2` to index a table reached through module global
`0x1017ae98`; from the selected descriptor it reads the two-byte value at
`+6` and a dword size at `+0x14`. The span pointer comes from the input object
at `+0xa0`. It then dispatches on the two-byte value and may issue further
writes. This is an observed descriptor-driven write sequence, not evidence
that its output is a selector-`0x20` frame: no selected-record context,
runtime dispatch or output was observed. The only direct call to this routine
found in a module-wide disassembly is from forwarding routine `0x10015610`;
it does not itself select a record before the shown writes. Indirect calls
and other writers remain unexamined.
In the module's static data, the forwarding routine's address is
at `0x1016b830`, offset `0x9c` from table `0x1016b794`. The code at
`0x10015520` writes that table pointer to global `0x1017aeb8`, and the
exported `GetRFLInterface` at `0x10015650` returns that global's address.
The module's process-attach path at `0x101592b0` calls `0x1015a6eb`;
that routine walks the constructor-pointer range beginning at `0x10174000`,
which contains pointer `0x10015510` at `0x10174028`. The latter jumps to
`0x10015520`, installing the interface-table pointer on this static startup
path. This supports the table setup as a registered initializer rather than
an unreferenced function, but does not prove a runtime load occurred. The
actual caller, selected record and file remain unknown. In the executable,
`0x0040e113` makes an
indirect slot-`0x9c` call using the pointer loaded from global `0x00483bf4`
and passes the current `esi` value. At `0x00437b74–0x00437be9`, a separate
path passes the loaded module handle and the string `GetRFLInterface` to
`GetProcAddress`, calls the returned pointer if non-null, and stores its
return in that global. If the handle identifies the hash-pinned module and
its table initialization is in effect, this connects the indirect call to
the raw-write forwarding entry. Module selection, execution order, mutations,
selected record and actual dispatch remain unverified.

Reproduction:

```sh
sha256sum research/installed/us/English_-_Program_Files/Dragon.rfl
objdump -d -Mintel --start-address=0x10016a80 --stop-address=0x10016c10 research/installed/us/English_-_Program_Files/Dragon.rfl
objdump -d -Mintel research/installed/us/English_-_Program_Files/Dragon.rfl | rg 'call[[:space:]]+0x10016a80'
objdump -d -Mintel --start-address=0x10015520 --stop-address=0x10015660 research/installed/us/English_-_Program_Files/Dragon.rfl
objdump -d -Mintel --start-address=0x101592b0 --stop-address=0x10159405 research/installed/us/English_-_Program_Files/Dragon.rfl
objdump -d -Mintel --start-address=0x1015a6eb --stop-address=0x1015a7eb research/installed/us/English_-_Program_Files/Dragon.rfl
objdump -s --start-address=0x10174000 --stop-address=0x10174030 research/installed/us/English_-_Program_Files/Dragon.rfl
objdump -d -Mintel --start-address=0x40e0f0 --stop-address=0x40e145 research/binaries/us/Drakan.exe
```

## RFL module-selection path, 2026-10-19

The interface lookup is part of a generic loader, not a hard-coded
`Dragon.rfl` load. In the hash-pinned executable, `0x00437ab0` accepts a
caller-provided string buffer; an empty string branches to its dialog path,
while the nonempty path reaches helper `0x00411c00`. That helper calls
`LoadLibraryA` through IAT slot `0x00475098`, resolves `GetRFLInterface`
through `GetProcAddress` at `0x00437b74`–`0x00437b80`, invokes the export if
found, and accepts only return values `0x101` or `0x80000101`; otherwise it
frees the module. This is consistent with a versioned plugin/interface
loader, but does not identify which module was loaded in any particular run.

One observed caller at `0x00407906` passes the address `0x00483bf8`. Earlier
in the same initialization path, `0x004078e8`–`0x004078fb` calls
`LoadStringA` (IAT slot `0x00475218`) with resource ID 5 and that destination
buffer. The raw string-table block shows resource ID 3 is the filter
`Riot Function Libraries (*.rfl)|*.rfl|All Files|*.*|`; ID 4 is
`Riot Engine Options\nDragon.rfl`; ID 5 is empty. In the observed flow, an
empty input branches to the dialog path, whose helper at `0x00437c10` loads
ID 3 and passes a `0x100`-byte filename buffer through the common-dialog
path; its open branch at `0x004654ae` jumps to imported `GetOpenFileNameA`.
The dialog writes a selected path to the caller-provided filename buffer,
which is then used in the loader retry path. This establishes a user-selected
module path through an RFL-filtered dialog in this UI branch, but not which
file was selected in any particular run. Because the filter also offers
`All Files`, it does not enforce the extension. `Dragon.rfl` is present in
an adjacent UI string, not proven to be the selected filename. The separate
call at `0x0040e113` only proves that another routine dispatches slot `0x9c` through
the global interface pointer; static evidence does not connect that call's
runtime state to this particular load or selected filename. Therefore the
`Dragon.rfl` raw-write entry remains a plausible, structurally matching
candidate, not an established producer of the sampled selector-`0x20`
frames. The subsequent writer-context trace below narrows this candidate to
a conditional `0x0102` writer path.

Reproduction against the same pinned executable:

```sh
objdump -d -Mintel --start-address=0x437ab0 --stop-address=0x437bf5 research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x411c00 --stop-address=0x411c65 research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x407780 --stop-address=0x407935 research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x437c10 --stop-address=0x437d97 research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x4654ae --stop-address=0x4654b4 research/binaries/us/Drakan.exe
objdump -p research/binaries/us/Drakan.exe
wrestool -l research/binaries/us/Drakan.exe
wrestool -x -t 6 -n 1 -L 1033 -R research/binaries/us/Drakan.exe | od -Ax -tx1z
```

## Module write context, 2026-10-19

**Observed, static:** on the same hash-pinned US executable and RFL, the
enclosing executable writer `0x0040b4d0` passes its local writer address to
interface slot `+0x90` at `0x0040b9ff`. The pinned RFL's table at
`0x1016b794` has `0x100155b0` at that slot; this function stores the argument
at `0x1017af70`. Its `+0x9c` entry `0x10015610` passes that same global's
address to `0x10016a80`, whose first field is used as the writer pointer by
the raw-write helper. The executable later passes the same local writer to
slot `+0x34` at `0x0040ba8e`. Its candidate implementation `0x0040dd30`
initializes first selector `0x0102` and a dynamic second selector, then calls
interface slot `+0x9c` at `0x0040e113` before calling the record-finalization
helper at `0x0040e134`.

**Inference:** if the pinned module and candidate executable table are both
active, the stored pointer is unchanged, the initializer succeeds, and
intervening calls do not change the writer's selected record or position,
the module's writes target that `0x0102` record. The module's initial
descriptor-derived word and byte span therefore have a concrete alternative
context to the level frame hypothesis. The observed two write requests alone
do not establish the level frame's four-byte prefix and length-prefixed body.
Neither successful writes nor output bytes were observed; the executable's
fixed-width `0x0102` writer also differs from the sampled length-prefixed
reader, as described in [the writer comparison](srsc-writer-third-state.md#follow-up-the-0x0102-writer-is-a-separate-candidate).
Module selection, indirect dispatch, intervening mutations, producer identity,
and any other writer paths remain unknown. Confidence is high for the static
instructions, conditional for their association, and limited to these inputs.

```sh
sha256sum research/binaries/us/Drakan.exe research/installed/us/English_-_Program_Files/Dragon.rfl
objdump --version | head -1
objdump -d -Mintel --start-address=0x40b9f2 --stop-address=0x40baab research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x40dd30 --stop-address=0x40dd72 research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x40e0f0 --stop-address=0x40e139 research/binaries/us/Drakan.exe
objdump -s --start-address=0x1016b820 --stop-address=0x1016b838 research/installed/us/English_-_Program_Files/Dragon.rfl
objdump -d -Mintel --start-address=0x100155b0 --stop-address=0x100155bc research/installed/us/English_-_Program_Files/Dragon.rfl
objdump -d -Mintel --start-address=0x10015610 --stop-address=0x10015622 research/installed/us/English_-_Program_Files/Dragon.rfl
objdump -d -Mintel --start-address=0x10016a80 --stop-address=0x10016ad7 research/installed/us/English_-_Program_Files/Dragon.rfl
```

The corresponding level frames also match a subset of these `0x0102` frames
byte-for-byte under candidate file joins; see
[the level comparison](level-entry-caller-followup.md#frame-text-and-candidate-0x0102-comparison-2026-10-19).
Confidence is high for the measured US snapshots, not for runtime use,
producer identity, other editions or a universal grammar. The traced retail
consumer does not consume this tail on its success path. This sample result
does not change the production reader's opaque-tail policy.

```sh
python3 tools/research/measure_0102_metadata_frames.py research/installed/us research/exports/srsc-records/us.json research/installed/us/English_-_Program_Files/Dragon.rfl
python3 -m unittest discover -s tools/research -p 'test_measure_0102_metadata_frames.py' -v
sha256sum research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x45f750 --stop-address=0x45f799 research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x40b591 --stop-address=0x40b5fb research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x40e150 --stop-address=0x40e2f3 research/binaries/us/Drakan.exe
objdump -d -Mintel research/binaries/us/Drakan.exe | rg 'call[[:space:]]+0x45f750'
objdump -d -Mintel --start-address=0x10016110 --stop-address=0x1001614a research/installed/us/English_-_Program_Files/Dragon.rfl
objdump -d -Mintel --start-address=0x101562f0 --stop-address=0x10156489 research/installed/us/English_-_Program_Files/Dragon.rfl
objdump -d -Mintel research/installed/us/English_-_Program_Files/Dragon.rfl | rg 'call[[:space:]]+0x10156440'
objdump -d -Mintel research/installed/us/English_-_Program_Files/Dragon.rfl | rg -B 3 'call[[:space:]]+0x101562f0'
objdump -d -Mintel --start-address=0x10015610 --stop-address=0x10015622 research/installed/us/English_-_Program_Files/Dragon.rfl
objdump -d -Mintel --start-address=0x10016a80 --stop-address=0x10016ad7 research/installed/us/English_-_Program_Files/Dragon.rfl
objdump -d -Mintel --start-address=0x10015520 --stop-address=0x1001552b research/installed/us/English_-_Program_Files/Dragon.rfl
objdump -d -Mintel --start-address=0x10015650 --stop-address=0x10015656 research/installed/us/English_-_Program_Files/Dragon.rfl
objdump -s --start-address=0x1016b7f0 --stop-address=0x1016b850 research/installed/us/English_-_Program_Files/Dragon.rfl
objdump -p research/installed/us/English_-_Program_Files/Dragon.rfl | rg -A 5 'Ordinal/Name Pointer'
objdump -d -Mintel --start-address=0x40e0ff --stop-address=0x40e119 research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x437b33 --stop-address=0x437bf4 research/binaries/us/Drakan.exe
objdump -s --start-address=0x47d3cc --stop-address=0x47d3e0 research/binaries/us/Drakan.exe
objdump -p research/binaries/us/Drakan.exe | rg -B 1 -A 1 'GetProcAddress|LoadLibraryA'
PYTHONPATH=tools/research python3 -c 'import json; from pathlib import Path; from collections import Counter; from measure_0102_model_candidates import table; from measure_srsc_prefix_selector import read_verified; root=Path("research/installed/us").resolve(strict=True); items=json.loads(Path("research/exports/srsc-records/us.json").read_text())["files"]; totals=Counter(); files=Counter();
for item in items:
 data=read_verified(root,item); _, records=table(data); matches=[(a,b) for a,b,c,d,e in records if a==0x401 and b in (0x37b,0x37d)]; totals.update(matches); files.update(set(matches))
print("files checked:",len(items)); print("selector counts:",dict(totals)); print("files containing:",dict(files))'
```

The five targeted synthetic tail tests and all 190 research tests passed on
2026-10-19. Synthetic tests exercise exact and trailing data, truncation,
metadata selection, raw-body variants and the even-byte comparison rule.
