# SRSC selector lookup and record order

**Date and input:** 2026-10-18, unpatched US retail `Drakan.exe`, SHA-256
`23630f48e20e8a9f42026501165ae1df407cfcee545a784ec930a4c25ee70648`.
The installed-US SRSC files were checked against their previously recorded
per-file SHA-256 values in `research/exports/srsc-records/us.json` before
measurement. **Method:** Ghidra 12.1.4 on a fresh disposable import, followed by
`-process Drakan.exe -readOnly -noanalysis` with bounded instruction windows
from `TraceSrscLookup.java`; independent GNU objdump 2.45.1 disassembly and
bounded direct-call windows from `TraceSrscSelectorCalls.java`, as well as
Python 3.14.7 measurements. Private disposable output is under
`/tmp/dragonrider-r1-jxQGslJF/`. **Confidence:** high for the specified
instructions and measured files, with limitations below. The Ghidra import
reported analysis success, which does not prove complete references or runtime
coverage. No persistent Ghidra project was opened.

## Observed: ordering and selection

- The successful file-open path at `0x0045eef9` sets object offset `+4` to
  zero. A separate method at `0x0045ef70` allocates a second table and copies
  complete 14-byte entries into ascending order of the unsigned word at record
  offset 2 (`0x0045f022`–`0x0045f088`). Within each equal-word group it
  traverses the original array in increasing index order. On successful
  completion it replaces the table pointer and sets object offset `+4` to one
  (`0x0045f0ae`–`0x0045f0b1`). This is a stable ordering by the second word;
  it is an in-memory transformation, not evidence that the file is rewritten.
- In the disposable database, direct calls to that method occur at
  `0x0041e50f` and `0x0042afe8`, after successful calls to the file opener.
  Neither shown caller checks the ordering method's return before continuing.
  Allocation failure returns an error before the table is replaced. These two
  call sites do not establish that every loader caller orders its table, or
  that ordering always succeeds.
- The three-word lookup `0x0045f0d0` uses a forward linear scan of all three
  16-bit words when object `+4` is zero; it selects the first matching entry.
  When `+4` is nonzero it passes the second input word to a binary-search
  routine at `0x00468f71`, using the unsigned second-word comparator at
  `0x0045ed40`. If a match is found, the code moves backward over equal
  second-word values and scans forward for all three words. For a correctly
  ordered table it selects the first matching triple in the current table.
  If no triple matches it returns an error. This describes the traced code,
  not malformed-memory behavior.
- The distinct two-word routine `0x0045fa10` searches forward for the first
  matching values at offsets 0 and 2 and does not compare the third word.
  `0x0045f230` uses its returned index for the index selection at
  `0x0045f270`; see [selector 0x0040](selector-0040-behavior.md). With
  correctly ordered data, stable ordering preserves the original relative
  order of entries sharing the second word, so the first matching pair or
  full triple corresponds to the first such entry in the original table.
  The selected *index* can nevertheless change when ordering changes the table.
- `0x0045f910` is a distinct three-word first-match lookup returning the
  current table index rather than selecting and seeking the payload. One
  caller supplies `(0x0040, value, 0)`; its comparison with the two-word
  texture path and sample limitations are in [selector 0x0040](selector-0040-behavior.md#selector-comparison-follow-up-2026-10-18).
- Another caller opens a file and requests the in-memory ordering step at
  `0x0042afb0`–`0x0042afe8`. Its loop constructs a 26-byte runtime entry for
  each current table index. The accessors at `0x0045faa0`, `0x0045fa70`,
  `0x0045fad0`, and `0x0045fb00` provide respectively the second, first and
  third selector words and the record read budget; the caller stores these at
  runtime entry offsets 0, 2, 4 and 6 (`0x0042b0ba`–`0x0042b0ee`). A later
  indexed read routine at `0x0042b1d0` uses the runtime `+6` value to cap a
  requested length and either copies from cached data or selects the same
  index in the loader before reading. The runtime entry layout is distinct
  from the 14-byte on-disk table and does not establish a semantic name for
  its stored third selector word. These observations follow the successful
  open/allocation and selected branches; indirect callers and errors are not
  fully characterized.
- A different consumer at `0x00429b00` iterates a loader table, reads each
  record's second word, and tests its first word for `0x0102`
  (`0x00429c17`–`0x00429c30`). On the traced successful branch it combines
  the source object's `+0x114` value shifted left by 16 with that second
  word and stores the resulting dword in the constructed runtime object at
  `0x00429db9`–`0x00429dd1`. This is another observed use of the second word
  in a source-qualified runtime value. It does not explain the third word.

## Observed: record construction in the retail executable

These are static observations of writer code, not a request to run it or a
claim that the installed files were produced by this executable:

- On the successful initialization path, `0x0045f4d0` sets writer state
  `+8` to zero, state `+0` to 2, and the active index `+0xc` to -1. Its
  `CreateFileA` call uses write access and creation disposition 2; it can
  replace a file. This investigation did not execute it.
- `0x0045f5d0` changes writer state `+8` to the low 16 bits of its argument
  only when mode is 2 and no record is active. In the disposable Ghidra
  database the one direct call found, at `0x00441e2d`, supplies zero. The
  caller does not check this setter's return before requesting a `(0x0051,
  0)` record. Direct references are database-dependent and do not rule out
  indirect calls or direct state writes.
- The mode-2 record initializer at `0x0045f600` takes two arguments, placing
  their low words at record offsets 0 and 2. It copies the current writer
  state `+8` into the word at offset 4 (`0x0045f6b2`–`0x0045f6b6`), obtains
  the current file position via `SetFilePointer`, and stores that position at
  record offset 6. It marks this record active. The separate setter therefore
  permits a value to persist across record initializations until the state is
  changed; this does not establish its meaning or all possible producers.
- When ending an active record in mode 2, `0x0045f7a0` subtracts the saved
  starting position from the then-current file position and stores the result
  at offset 10 before incrementing the count. The closing path at `0x0045f810`
  writes `count * 14` table bytes, records the table position and low 16 bits
  of the count in the 12-byte header, and rewrites that header. This
  corroborates offset 10 as the written payload length on that successful
  path, in addition to the reader's use of it as a read budget. Errors,
  overflow, incomplete writes and untraced writer paths are not characterized.

## Observed: installed-US measurements

The following counts describe only the 178 examined `SRSC` files in the
previously generated private inventory, with all 178 SHA-256 values rechecked.
They are structural measurements, not game execution:

- The tables contain 38,926 entries. There are three repeated first-two-word
  occurrences across two files; all three also repeat the entire triple.
  No sampled first-two-word pair has more than one third-word value.
- In 112 files a stable sort by the second word changes at least one position;
  30,083 entry positions differ, and 1,060 original adjacent pairs decrease in
  that word. The simulation records original indexes to compare first full
  tuple and pair matches and found zero changes to those identities. The raw
  measurements do not execute or independently emulate the retail
  binary-search helper.

A later byte-for-byte comparison rechecked the inventory hashes for all 178
files and examined each repeated full tuple relative to its first occurrence.
The three repeated occurrences form two groups in two files. All three have
the same payload length and bytes as the first member of their group, but
start at different offsets. This is a direct bounded byte comparison, not
execution of the original lookup. It explains that choosing another member of
these particular duplicate groups would yield the same bytes, but does not
establish a general duplicate policy or runtime equivalence for other files.
The comparison limits each equal-length comparison to 64 MiB, validates the
selected file ranges against the pre-table region, and prints only aggregate
counts. It rereads table and payload bytes after hashing, so concurrent
modification remains a limitation.

For a model-loader consumer that selects records by relative index, the sampled
raw-table and simulated reordered-table relationships were checked explicitly;
see [model geometry records](model-geometry-records.md#ordering-and-selector-cross-check-2026-10-18).

### Candidate cross-kind relationships

For each record of the first kind below, an exploratory comparison counted
records of the second kind in the **same file** whose second selector word
equals the first record's third word. After inspecting the sample, these
three pairs were selected for a reproducible aggregate check:

| First kind | Second kind | First-kind records | Exactly one match | No match | Multiple matches |
| --- | --- | ---: | ---: | ---: | ---: |
| `0x0102` | `0x0101` | 4,203 | 4,203 | 0 | 0 |
| `0x0200` | `0x0201` | 3,221 | 3,221 | 0 | 0 |
| `0x0302` | `0x0301` | 1,561 | 1,561 | 0 | 0 |

For each of those second kinds, the same check against its **own** kind gives:

| Kind | Records | Third word zero | Nonzero with one match | Nonzero with no match | Nonzero with multiple matches |
| --- | ---: | ---: | ---: | ---: | ---: |
| `0x0101` | 808 | 285 | 523 | 0 | 0 |
| `0x0201` | 640 | 187 | 451 | 2 | 0 |
| `0x0301` | 221 | 105 | 116 | 0 | 0 |

Each of these 1,669 records has a payload consisting of a little-endian
16-bit length followed by exactly that many bytes. All measured lengths are
even and nonzero; the bytes are printable ASCII or NUL, with no embedded NUL.
The last byte is NUL in 418, 345, and 122 records respectively. This framing
is consistent with the executable's string helper at `0x0045f750`, which
writes the low 16 bits of `(C-string length + 1) & 0xfffe`, followed by that
many bytes; `0x0045f430` reads a 16-bit length, copies up to a caller-supplied
capacity, and terminates the destination. Static helper behavior and matching
sample bytes do not prove that this helper wrote these records or establish
that the strings are directory names. The measurement caps individual payloads
at 65,537 bytes and prints aggregate counts rather than payload contents.

None of these nonzero words equals the same record's second word. Zero is
reported separately; this check does not interpret zero as a link or prove a
root convention. The two unmatched `0x0201` values are retained as observed
exceptions rather than silently treated as valid links.

Treating each nonzero third word as a lookup key and repeatedly following the
unique same-kind match terminates at zero for 808/808 `0x0101` records,
636/640 `0x0201` records, and 221/221 `0x0301` records. The remaining four
`0x0201` traversals encounter a missing key, including traversals that reach
one of the two direct exceptions indirectly. No sampled traversal encounters
a cycle or ambiguous key. The simulation stops at zero, missing, ambiguous,
or repeated keys; it does not execute the original code.

A follow-up hash-checked scan found that the two directly missing `0x0201`
references occur in one file and share one missing key. That key is not a
second word of another kind in that file, or a `0x0201` second word in any
other sampled file. Of the four `0x0201` paths ending at a missing key, two
have zero matched hops and two have one. Of the 44 `0x0200` paths ending at
a missing key, 22 have one matched hop and 22 have two. These are structural
comparisons within the sampled inventory, not evidence of runtime search
across files or a validation rule; matching keys could still be resolved in
other ways. The scan counts unique file-local missing keys and does not print
the key, file name, or payload.

Starting from the first-kind records in the preceding table and then following
the same-kind matches under the same zero-termination assumption reaches zero
for 4,203/4,203 `0x0102`, 3,177/3,221 `0x0200`, and 1,561/1,561 `0x0302`
records. The other 44 `0x0200` traversals reach a missing key. There are no
cycle or ambiguous endings in this sample. These are record counts: multiple
records can lead to the same missing key.

This is consistent with a same-file association, but the comparison does not
establish that the retail executable resolves such an association or reveal
its meaning. The same-kind pattern suggests a possible hierarchy, but other
samples, cross-file relationships and runtime resolution remain unverified.
It is neither a general uniqueness rule nor a validation
requirement: the synthetic tests include missing and multiple matches. The
selected pairs and sample files do not cover all kinds or editions, and the
result counts records, not distinct selector values or runtime accesses.

### Candidate label fanout and repetitions

A further hash-checked scan compared the same selected source/label kind pairs
within each sampled file. For each label record it counted source records
whose third word equals the label's second word:

| Source → label kinds | Labels with no sources | One source | Multiple sources | Maximum source count |
| --- | ---: | ---: | ---: | ---: |
| `0x0102` → `0x0101` | 78 | 117 | 613 | 35 |
| `0x0200` → `0x0201` | 77 | 113 | 450 | 39 |
| `0x0302` → `0x0301` | 36 | 18 | 167 | 55 |

After removing one trailing NUL when present, repeated label byte strings in
the same file occur 4, 5, and 19 times beyond their first occurrences for the
three label kinds respectively. Grouping additionally by the label's third
word gives 0, 1, and 0 repeated occurrences. This is a counterexample to a
proposed uniqueness rule for the selected comparison, not proof that the
third word denotes a parent or that the game performs this association. The
script emits only aggregate counts, not label text or filenames; it rereads
the table and payloads after hashing, so concurrent modification remains a
limitation. The kind pairs were selected after inspecting the sample.

## Follow-up: third-word consumers

On 2026-10-18, a further review of the disposable Ghidra 12.1.4 report and
GNU objdump 2.45.1 did not establish that the executable resolves the sampled
same-kind candidate links. The disposable database reports direct calls to the
third-word accessor `0x0045fad0` at `0x00435601` and `0x0042b0d9`. At the
first, the subsequent instructions test for zero and then test the first
selector for `0x0030` (`0x00435606`–`0x00435619`); this branch concerns a
different kind from the candidate link kinds. The second call copies the word
into the runtime record as described above; the copy alone does not resolve it.
Direct references are not necessarily complete.

The disposable database reports no direct call references to the three-word
lookup wrapper at `0x0042b1a0`. A subsequent bounded read-only Ghidra run
(`TraceSrscIndirectLookup.java`, private run `dragonrider-indirect-cryApjdz`)
and independent raw PE disassembly support a conditional indirect dispatch:

- The table pointers installed at `0x004265e7` and `0x0042ae16` are
  `0x004756ec` and `0x004757ac`. Each table contains `0x0042b1a0` at offset
  `+8`; the pointer bytes are at `0x004756f4` and `0x004757b4`, respectively.
- The instructions at `0x0042b650` and `0x0042b710` load the receiver's
  table pointer and call its `+8` slot with a variable argument, `0x0030`,
  and zero. If the receiver has either of the two observed tables and its
  loader pointer at `+0x11c` is non-null, the wrapper rearranges those
  arguments before calling `0x0045f910`. The latter compares the tuple
  `(0x0030, variable low word, 0)` and returns an index on a match.
  The first caller passes the result to another `+0x10` dispatch; the second
  passes it to a `+0x14` dispatch. These are static conditional paths, not
  observed executions or proof of the receiver's table at either call.
- The shown zero third argument and kind `0x0030` do not explain the sampled
  same-kind candidate links. The wrapper accepts other arguments, but their
  actual runtime use, the runtime entry's word at `+4`, and the association
  between the sampled records remain open.

A further conditional `0x0400` dispatch accepts a variable third selector;
two identified indirect calls supply zero, with their receiver identity
unverified. See [selector 0x0400 dispatch](srsc-selector-0400-dispatch.md).

## Follow-up: copied selector in the 26-byte runtime cache

Bounded GNU objdump 2.45.1-5.fc43 disassembly of the same hash-identified US
retail executable follows the 26-byte entries populated at `0x0042b0ba`–
`0x0042b0ee`. The loader accessors store the second, first and third selector
words at runtime offsets `+0`, `+2` and `+4`; the record read budget is stored
at `+6`.

The read routine at `0x0042b1d0` computes an entry address using 26-byte
strides. On its shown branches it reads the `+6` read budget, `+0xa` data
offset, `+0xe` flags and `+0x12` use counter; it does not read runtime `+4`.
The update routine at `0x0042b2b0` uses `+0xe` and `+0x12`, also without a
read from `+4`. The adjacent helpers at `0x0042b640` and `0x0042b700` perform
a conditional `(0x0030, variable, 0)` selector lookup using their argument;
they do not obtain that key from the cached `+4` field in the shown code.

This establishes that the third selector is copied into this runtime cache,
but not that these particular read/update helpers consume it. The inspection
does not cover every method, indirect dispatch, or other runtime cache user
and therefore does not disprove a consumer elsewhere.

A textual scan of memory operands in the containing `0x42b000`–`0x42b720`
disassembly found the single word store to `[edi+4]` at `0x42b0de` and no
word load from an entry-relative `+4` offset in this range. The byte store to
`[esi+4]` at `0x42b192` belongs to the reset routine, and the other `+4`
matches are stack argument accesses. This is a bounded operand scan, not a
whole-image data-flow or indirect-use analysis.

Reproduce these bounded windows with:

```sh
objdump -d -Mintel --start-address=0x42b0ba --stop-address=0x42b115 research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x42b1d0 --stop-address=0x42b2ae research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x42b2b0 --stop-address=0x42b308 research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x42b640 --stop-address=0x42b71c research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x42b000 --stop-address=0x42b720 research/binaries/us/Drakan.exe | rg '\\[[^]]+\\+0x0?4\\]'
```

## Follow-up: two-word `0x0302` lookup

In a read-only Ghidra 12.1.4 run (`dragonrider-0302-m5aD3qb7`) and independent
GNU objdump 2.45.1 disassembly of the hash-verified US retail executable,
the path at `0x00432fc0` compares the high half of a supplied value to an
object's `+0x114`. It subsequently passes that value and kind `0x0302` to
`0x0045fa10` at `0x00433028`–`0x00433030`, then selects the returned index
at `0x00433049` if found. The helper masks the second input to 16 bits and
compares only record words 0 and 2; it does not compare the word at offset 4.
These observations describe a static path; runtime file selection and all
error paths are not established.

The separate hash-checked inventory comparison scanned 178 installed US files:
all 1,561 `0x0302` records in 19 files had a nonzero third word. There were
1,561 distinct file-local first-two-word pairs, with no duplicate occurrences.
For each pair, a hypothetical full-tuple lookup with third word zero would
find no match in that file. This hypothetical comparison is not the observed
lookup and does not imply a universal format rule, actual invocation of this
path, or a semantic name for the third word. The model handles duplicates and
missing matches in synthetic tests; it simulates stable ordering without
executing the retail helper.

A separate reader requests the full tuple `(0x0302, 0, 0)`, and a distinct
writer initializes the first two words to `(0x0302, 0)` while using existing
state for the third. None of the sampled `0x0302` records satisfies the read
tuple; this does not establish that this reader uses those files. See
[separate full-tuple consumer](srsc-third-selector-consumer.md).

On the earlier two-word selection path, both branches call the length-prefixed
helper `0x0045f430` with null destination and zero capacity at `0x0043309c`
and `0x0043317f`. After reading the 16-bit length, that helper requests a
forward skip of that many bytes via `0x0045f3d0`; the latter checks the
remaining read budget before issuing the seek. These are conditional static
observations; the path and skip return behavior are not a general validation
rule. On the second branch the caller then requests an additional 24-byte
skip. Ghidra 12.1.4 read-only run `dragonrider-r1-prefix-QH00PGGT` and GNU
objdump 2.45.1 corroborated the selected instruction windows.

The hash-checked 178-file inventory contains 1,561 `0x0302` records in 19
files. All have a nonzero little-endian 16-bit prefix length within their
record bounds; all prefix bytes are printable ASCII or NUL, with no embedded
NUL and 853 trailing NULs. All have at least 24 bytes after that prefix.
These counts describe only the measured files, not actual execution, text
encoding, or a universal rule. The scan reads at most 65,537 bytes per record,
checks the declared record against the pre-table range, and prints no payload
content. It rereads the table and payload after hashing, leaving concurrent
modification unexcluded.

The writer setter and the immediately subsequent `0x0051` initializer have
matching success preconditions; absent concurrent mutation, successful
initialization establishes a zero third word on that particular path. A
follow-up traces the same caller's intervening `0x0022` write: it reuses the
current state without an explicit setter, after which the caller invokes the
`0x0302` writer. No state change is visible in the shown instructions, though
indirect side effects or asynchronous mutation cannot be excluded. See
[writer third-word state](srsc-writer-third-state.md).
An independent whole-image disassembly found one direct call to the writer
constructor, one direct call to the setter (which supplies zero), and ten
direct calls to the record initializer. Indirect calls and direct stores
through aliases remain outside that count.

The input hash and method are as stated at the beginning of this note; no
original database was opened. Reproduce the narrow byte checks with:

```sh
objdump -d -Mintel --start-address=0x4355f0 --stop-address=0x435620 research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x42b0ba --stop-address=0x42b0f0 research/binaries/us/Drakan.exe
objdump -s --start-address=0x4756e0 --stop-address=0x4757c0 research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x4265e7 --stop-address=0x42660f research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x42ae00 --stop-address=0x42ae3c research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x42b1a0 --stop-address=0x42b1c7 research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x42b640 --stop-address=0x42b720 research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x45f910 --stop-address=0x45fa0d research/binaries/us/Drakan.exe
```

## Inferred and unknown

The second word acts as the ordering/search key on this path, but its semantic
name is still unknown, as are the individual meanings of the other two words.
Duplicate choice is established only for the specified lookup paths under the
stated ordering assumptions. Other selection routines, malformed inputs,
allocation failures, alternate executable versions, and indirect callers are
not covered. Reordering makes an index in a raw file table unsuitable as a
claim about a runtime table index unless the selected path and ordering state
are known. Do not impose uniqueness or sortedness as a file validation rule.
The measurement checks the input hash before reading its table, but cannot rule
out a same-size concurrent file modification between those operations.

The indexed `0x0102` consumer and its payload comparisons are documented in
[the `0x0102` runtime note](srsc-0102-runtime.md). In the sampled `0x0102`
records, a separate post-prefix payload word matches the third selector and
a unique same-file `0x0101` second selector; the traced consumer skips that
word. This does not establish a runtime association with `0x0101` records.

## Reproduction

Follow the disposable-import instructions in [Ghidra guidance](../GHIDRA.md),
including verifying the copied input hash. With `dr_workspace` set to the
fresh disposable project root and `GHIDRA_HOME` configured, run:

```sh
XDG_CONFIG_HOME="$dr_workspace/config" XDG_CACHE_HOME="$dr_workspace/cache" \
JAVA_TOOL_OPTIONS="-Duser.home=$dr_workspace" \
"$GHIDRA_HOME/support/analyzeHeadless" "$dr_workspace/project" Disposable_Drakan \
  -process Drakan.exe -readOnly -noanalysis -scriptPath "$PWD/tools/ghidra/scripts" \
  -postScript TraceSrscLookup.java -log "$dr_workspace/lookup.log" \
  -scriptlog "$dr_workspace/lookup-script.log" > "$dr_workspace/lookup-console.log" 2>&1
XDG_CONFIG_HOME="$dr_workspace/config" XDG_CACHE_HOME="$dr_workspace/cache" \
JAVA_TOOL_OPTIONS="-Duser.home=$dr_workspace" \
"$GHIDRA_HOME/support/analyzeHeadless" "$dr_workspace/project" Disposable_Drakan \
  -process Drakan.exe -readOnly -noanalysis -scriptPath "$PWD/tools/ghidra/scripts" \
  -postScript TraceSrscSelectorCalls.java -log "$dr_workspace/selectors.log" \
  -scriptlog "$dr_workspace/selectors-script.log" > "$dr_workspace/selectors-console.log" 2>&1
XDG_CONFIG_HOME="$dr_workspace/config" XDG_CACHE_HOME="$dr_workspace/cache" \
JAVA_TOOL_OPTIONS="-Duser.home=$dr_workspace" \
"$GHIDRA_HOME/support/analyzeHeadless" "$dr_workspace/project" Disposable_Drakan \
  -process Drakan.exe -readOnly -noanalysis -scriptPath "$PWD/tools/ghidra/scripts" \
  -postScript TraceSrscIndirectLookup.java -log "$dr_workspace/indirect.log" \
  -scriptlog "$dr_workspace/indirect-script.log" > "$dr_workspace/indirect-console.log" 2>&1
objdump -d -Mintel --start-address=0x45ed40 --stop-address=0x45ed64 research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x45eef3 --stop-address=0x45f226 research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x468f71 --stop-address=0x468ffc research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x45fa10 --stop-address=0x45facb research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x42afe2 --stop-address=0x42b101 research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x42b1d0 --stop-address=0x42b2ac research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x429b00 --stop-address=0x429de3 research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x45f4d0 --stop-address=0x45f8bb research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x45f430 --stop-address=0x45f4c3 research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x441e20 --stop-address=0x441e40 research/binaries/us/Drakan.exe
objdump -p research/binaries/us/Drakan.exe | rg 'CreateFileA|SetFilePointer|WriteFile'
python3 tools/research/measure_srsc_lookup.py research/installed/us research/exports/srsc-records/us.json
python3 -m unittest discover -s tools/research -p 'test_measure_srsc_lookup.py' -v
python3 tools/research/measure_srsc_selector_links.py research/installed/us research/exports/srsc-records/us.json
python3 -m unittest discover -s tools/research -p 'test_measure_srsc_selector_links.py' -v
python3 tools/research/measure_srsc_label_payloads.py research/installed/us research/exports/srsc-records/us.json
python3 -m unittest discover -s tools/research -p 'test_measure_srsc_label_payloads.py' -v
python3 tools/research/measure_srsc_0302_lookup.py research/installed/us research/exports/srsc-records/us.json
python3 tools/research/measure_srsc_0302_prefix.py research/installed/us research/exports/srsc-records/us.json
python3 tools/research/measure_srsc_link_exceptions.py research/installed/us research/exports/srsc-records/us.json
python3 tools/research/measure_srsc_label_relationships.py research/installed/us research/exports/srsc-records/us.json
python3 tools/research/measure_srsc_duplicate_payloads.py research/installed/us research/exports/srsc-records/us.json
python3 -m unittest discover -s tools/research -p 'test_measure_srsc*.py' -v
objdump -d -Mintel --start-address=0x432f70 --stop-address=0x43305e research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x43307d --stop-address=0x43318d research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x45f3d0 --stop-address=0x45f4c3 research/binaries/us/Drakan.exe
```

The measurement emits aggregate counts only. The source files, inventory,
disposable project and bounded Ghidra logs remain private.

## Aggregate third-selector relationships, 2026-10-23

`measure_srsc_third_selector_distribution.py` hash-checked all 178 private US
inventory entries, validated every table and payload range, and emitted only
kind labels plus aggregate counts. For selected cross-kind comparisons,
every nonzero third selector of `0x0102`, `0x0200`, and `0x0302` has exactly
one same-file second-selector match in `0x0101`, `0x0201`, and `0x0301`,
respectively: 4,203, 3,221, and 1,561 records. There were no zero, missing, or
multiple cases in those three selected cross-kind comparisons. Within the
same kind, the nonzero-third unique/missing counts were `523/0` (`0x0101`),
`274/3,929` (`0x0102`), `87/3,134` (`0x0200`), `451/2` (`0x0201`), `116/0`
(`0x0301`), and `571/990` (`0x0302`); none had multiple matches.

This is a same-file structural equality measurement, not a runtime lookup,
selector-semantics, or cross-file-resolution claim. The tool does not emit
paths, hashes, raw selector values, or payload bytes; its five synthetic tests
cover hash, path, header, table, and range rejection.

## Selected cross-kind table position, 2026-10-23

`measure_srsc_cross_kind_order.py` hash-checked all 178 private US inventory
entries and validates each header, table, and pre-table payload range before
measuring only aggregate table positions. Every selected same-file relation is
unique in every source-bearing file: 4,203 `0x0102` to `0x0101` relations in
39 files, 3,221 `0x0200` to `0x0201` relations in 29 files, and 1,561
`0x0302` to `0x0301` relations in 19 files. All `0x0101` targets precede their
`0x0102` sources. For the other two pairs, targets precede sources in
3,200/3,221 and 1,550/1,561 cases; sources precede targets in 21 and 11
cases, respectively. There are no missing, duplicate, or same-position
selected targets in this sample.

These are file-table position counts, not evidence of lookup order, runtime
loading sequence, selector semantics, or a format invariant. Four synthetic
tests cover unique/missing/duplicate ordering categories and malformed hash,
path, table, and payload ranges. The tool emits no individual paths, hashes,
selector values, record indexes, or payloads.

## Selected cross-kind table distance, 2026-10-23

`measure_srsc_cross_kind_distance.py` independently hash-checks the same 178
private US entries and validates safe paths, headers, tables, and every
pre-table payload range. It measures only absolute table-index distance for
the already-selected unique same-file relationships. For `0x0102` to
`0x0101`, the 4,203 relations have distance buckets 12 (1), 42 (2--4), 68
(5--16), and 4,081 (17+); all targets precede their sources. For `0x0200` to
`0x0201`, the 3,221 relations yield 34, 5, 79, and 3,103 in those buckets;
3,200 targets precede and 21 sources precede their targets. For `0x0302` to
`0x0301`, the 1,561 relations yield 13, 51, 176, and 1,321; 1,550 targets
precede and 11 sources precede targets. There are no zero-distance, missing,
or ambiguous selected relations in the measured files.

Distance is a serialized table-layout observation only. It does not establish
runtime traversal, lookup order, loading sequence, selector meaning, or a
format invariant. Four synthetic tests cover direction/distance buckets,
missing and ambiguous targets, malformed inputs, stale hashes, and unsafe
paths; output has no individual identifiers or payloads.

## Independent C++ lookup verification, 2026-10-19

The test-only C++ probe receives bounded table bytes from an independent Python
verifier and uses the explicit file and stable-second-selector order APIs in
[ADR 0021](../decisions/0021-srsc-record-lookup.md). Python reads each file
once, verifies its size and SHA-256 against the private inventory, and computes
first-match indices independently. For both debug and release builds, all
38,926 record occurrences in 178 US files matched in both orderings: 77,852
pair comparisons and 77,852 triple comparisons per build. This validates the
specified model against the sampled table bytes, not the original game's runtime
allocation, binary search or conditional choice of ordering. The probe emits
only record indices to its parent process; original tables remain private.

```sh
python3 tools/research/verify_srsc_lookup.py research/installed/us research/exports/srsc-records/us.json build/debug/srsc_lookup_probe
python3 tools/research/verify_srsc_lookup.py research/installed/us research/exports/srsc-records/us.json build/release/srsc_lookup_probe
python3 -m unittest discover -s tools/research -p 'test_verify_srsc_lookup.py' -v
```
