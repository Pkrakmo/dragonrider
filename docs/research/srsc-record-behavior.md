# SRSC record selection and reads

**Date:** 2026-10-17. **Input:** unpatched US retail
`research/binaries/us/Drakan.exe`, SHA-256
`23630f48e20e8a9f42026501165ae1df407cfcee545a784ec930a4c25ee70648`
(verified with `sha256sum` during this investigation). **Method:** Ghidra
12.1.4 headless, existing `Drakan_US_Retail` project, `-process Drakan.exe
-readOnly -noanalysis`, bounded instruction windows and call references via
`tools/ghidra/scripts/TraceSrscRecords.java`; independently checked with GNU
`objdump` disassembly and PE imports. Private log:
`research/ghidra-logs/srsc-record-behavior/run-9K4nbbcc/`. **Confidence:**
high for these specific instructions and the relationship between the two
fields and the file operations; extrapolation to other versions is unverified.
The initial analysis run reported success, but xref completeness remains unknown;
see [Ghidra guidance](../GHIDRA.md).

## Observed

- The loader at `0x0045EDC0` stores the raw `count * 14` table read at object
  offset `0x2c`, as detailed in `riot-file-loading.md`. On the index-based
  selection path at `0x0045F270`, the code computes `table + 14 * index`.
  It passes the 32-bit value at record offset 6 to `SetFilePointer` with a
  null high-order pointer and origin zero (`FILE_BEGIN`), and compares the
  return value with that record value. After success it copies the 32-bit
  value at record offset 10 into the object at offset `0x18` and saves the
  selected index at object offset `0x0c`. The PE import table identifies
  `0x004750C4` as `SetFilePointer`.
- The method at `0x0045F2D0` checks the object mode and selected index, then
  compares the requested read size against the value at object offset `0x18`.
  A request greater than that value calls `ReadFile` for the remaining value,
  sets the remaining value to zero and returns an error. Otherwise it calls
  `ReadFile` for the requested size and subtracts either the requested number
  on an exact successful read or the returned byte count on a short/error path.
  The PE import table identifies `0x004750C8` as `ReadFile`.
- Another selection path, `0x0045F0D0`, compares three 16-bit arguments with
  the words at record offsets 0, 2 and 4 (`0x0045F18A–0x0045F1A8` on its
  linear-search branch). On a match it selects that record; at
  `0x0045F1D5–0x0045F201` it seeks using record offset 6 and initializes the
  same remaining-byte state from record offset 10. The three values therefore
  act as a lookup tuple on this path. The routine also has an alternate branch;
  this observation does not establish uniqueness, ordering or all search
  behavior. The alternate branch, optional stable in-memory ordering and
  duplicate selection are traced in [SRSC lookup order](srsc-lookup-order.md).
- Retail PE32 i386 is little-endian. Consequently these instructions consume
  the four bytes at offset 6 as a little-endian 32-bit seek argument, the four
  at offset 10 as a little-endian 32-bit initial read budget, and the first six
  bytes as three little-endian 16-bit comparison values on the paths above.
  The measurements in `srsc-record-observations.md` independently found that
  offset/length interpretations partition the data region in 178 installed US
  examples; they do not establish a required layout.
- The 2026-10-17 Ghidra report listed 26 direct calls to `0x0045F0D0`, 19 to
  `0x0045F270`, and at least 40 to `0x0045F2D0` (that script capped output at
  40). A later bounded database recheck of the latter target is recorded below.
  These xrefs are not an execution trace.

## Whole-image read-helper reference recheck, 2026-10-23

GNU objdump 2.45.1-5.fc43 disassembly of the same hash-pinned US executable
contains 103 direct relative calls to the bounded-read helper at `0x0045F2D0`,
no direct unconditional jumps to it, and no exact raw little-endian absolute
address literal for it. `tools/research/verify_srsc_read_helper_callers.py`
pins the executable hash, reads one byte snapshot, and gives that snapshot to
objdump; it checks 24 helper, skip, and string-reader instructions, along with
the complete direct-call address set. This replaces the earlier Ghidra-xref lower
bound as a count of direct relative calls in the disassembled image; it does
not establish the containing functions, requested sizes, path feasibility, or
completeness of indirect, computed, or runtime-written references.

## Ghidra read-helper reference recheck, 2026-10-24

Ghidra 12.1.4 imported a byte-for-byte copy of the US retail executable into a
new disposable project under `/tmp`; a separate read-only, no-analysis query
then queried that analyzed disposable database. The input SHA-256 was
`23630f48e20e8a9f42026501165ae1df407cfcee545a784ec930a4c25ee70648`, and
headless analysis completed successfully. The bounded
`TraceBoundedReadHelperRefs.java` query then found 103 database references to
`0x0045F2D0`, all `UNCONDITIONAL_CALL`; the saved-log verifier found the
complete address set equal to the 103 direct relative callsites independently
found by the hash-pinned GNU objdump verifier. The query's 128-reference output
cap did not truncate this result. This corroborates direct-call references in
the disposable analyzed database only; it does not establish complete control
flow or exclude indirect, computed, or runtime-written references. The report
method and xref confidence are database-dependent. The disposable project and
logs were kept outside Git.

`tools/research/verify_srsc_read_helper_ghidra_refs.py` checks a saved script
log's pinned hash, Ghidra version, declared count, reference types, uniqueness,
truncation state and complete address-set equality. Four synthetic tests cover
missing and duplicate references, mismatched provenance, non-call entries,
truncation and declared-count errors.

Reproduce with `GHIDRA_HOME` set. Import into a new temporary project and use
unique private log and config paths for each run:

```sh
refcheck=$(mktemp -d /tmp/dragonrider-refcheck-XXXXXXXX)
mkdir -p "$refcheck/project" "$refcheck/input" "$refcheck/config" "$refcheck/cache"
cp research/binaries/us/Drakan.exe "$refcheck/input/Drakan.exe"
sha256sum "$refcheck/input/Drakan.exe"
env XDG_CONFIG_HOME="$refcheck/config" XDG_CACHE_HOME="$refcheck/cache" \
  "$GHIDRA_HOME/support/analyzeHeadless" "$refcheck/project" Drakan_US_Retail_Refs \
  -import "$refcheck/input/Drakan.exe" -log "$refcheck/import.log"
env XDG_CONFIG_HOME="$refcheck/config" XDG_CACHE_HOME="$refcheck/cache" \
  "$GHIDRA_HOME/support/analyzeHeadless" "$refcheck/project" Drakan_US_Retail_Refs \
  -process Drakan.exe -readOnly -noanalysis \
  -scriptPath tools/ghidra/scripts -postScript TraceBoundedReadHelperRefs.java \
  -log "$refcheck/query.log" -scriptlog "$refcheck/script.log"
python3 tools/research/verify_srsc_read_helper_ghidra_refs.py "$refcheck/script.log"
```

The bounded helper at `0x0045F2D0` reads the selected record's remaining
budget from loader object `+0x18`. If the caller's requested length exceeds
that budget, the shown branch requests only the remaining amount, clears the
budget and returns an error. Otherwise, it invokes `ReadFile` and subtracts
the requested amount on an exact successful read or the returned byte count
on a short/error path. The 103-call census identifies direct callsites only;
except for the two examples below, the scanner does not infer their stack
arguments or trace their control-flow feasibility.

The adjacent skip helper at `0x0045F3D0` also compares its requested skip
length against `+0x18`, calls `SetFilePointer` with `FILE_CURRENT`, and
subtracts the skipped length from that budget. The string reader at
`0x0045F430` reads a two-byte length prefix through the bounded helper,
limits the requested text bytes against its caller-provided capacity, then
uses the skip helper to advance over any unconsumed text. These are anchored
instruction paths, not a complete proof of all callers or runtime outcomes.

### Two bounded-read calls in one caller

A hash-pinned `objdump` check added 27 instruction anchors around direct calls
at `0x0042495d` and `0x0042499f` in this same US executable. At the first call,
the caller stores `6` in the local request-length value reached through the
first pushed pointer argument, then calls the helper with a local destination
buffer. Afterward it reads 16-bit values at destination offsets 0 and 4. It
also loads a dword at offset 2 and masks it to 16 bits, so the six-byte prefix
is accessed as three 16-bit words at offsets 0, 2, and 4.

That masked value is used as a loop count for the second call. The caller
computes `count * 10` (`count * 5`, then doubled), stores that as the request
length, and calls the helper with a second local destination. In the following
loop it loads a 16-bit word at the current pointer, a dword at offset 2, and a
second dword at offset 6; it advances the pointer by 10 bytes overall and
decrements the count once per iteration.
This is evidence for a six-byte prefix followed on this path by a count of
ten-byte units. It does not identify the enclosing function's caller, resource
kind, field meanings, or whether this path executes at runtime.

Neither bounded-read return value is tested before the shown caller continues
to consume the destination buffer. This is a static call-site observation; it
does not show whether those reads succeed for the sampled inputs or how the
program handles failures elsewhere.

No Ghidra project was opened for this follow-up; the additional caller anchors
use GNU objdump on the same hash-verified snapshot as the whole-image 103-call
census. The reproduction command below verifies both anchor groups and the
complete direct-call inventory.

### Bounded request-size classification, 2026-10-23

The verifier now classifies a request size only when it can trace the helper's
second stack argument through a register holding an ESP-relative local address
and match the latest DWORD store to that same stack slot inside a bounded
straight-line disassembly window. It consumes wide objdump output and requires
continuous instruction-byte coverage. Stack deltas from `push`, `pop`, and
immediate `add/sub esp` are accounted for, including operand-size overrides.
Register aliases, common implicit pointer-register writes, both `xchg`
operands, loop branches, direct branch targets that could skip the size-pointer
setup, and memory writes after the latest size store are checked. The scan is
capped at 40 instructions and reports unknown when the pointer, stack address,
stored value, instruction coverage, or direct control flow cannot be followed.
Indirect branches and runtime-written code are outside this static check. The
helper's size-pointer argument is independently anchored at `0x0045F2F3`.

The initial hash-pinned run found 37 direct callsites with locally
stored constant request lengths: 12 requests of 2 bytes, 8 of 4, 3 of 6, 3 of
8, 3 of 12, 3 of 16, one of 24, 3 of 48, and one of 108. This includes the
previously documented six-byte request at `0x0042495d`. The already anchored
request at `0x0042499f` is derived from a masked count times ten and remains
separate from the constant classification. The other 65 direct calls remain
unknown in that initial run; this label means the bounded local scan did not
establish a constant or the existing derived case. It does not mean the caller
necessarily supplies a variable size. The classifications concern requested
lengths only; they do not establish call feasibility, read success, payload
grammar or runtime use.

Ten additional synthetic tests cover matching stack slots with and without
ESP adjustment, operand-size stack changes, unknown register-computed lengths,
partial-register and `xchg` clobbers, loop/control-flow boundaries, direct
branch entries, discontinuous instruction bytes, writes after the size store,
unmodeled ESP writes, REP-prefixed string instructions, and missing bytes up to
the call instruction. Seventeen focused tests pass in total. The verifier prints all 37 classified
callsite addresses and byte counts so each can be compared with bounded raw
objdump windows; the committed expected map is a hash-specific regression
check, not 37 separate instruction anchors.

Reproduce with:

```sh
python3 tools/research/verify_srsc_read_helper_callers.py research/binaries/us/Drakan.exe
python3 -m unittest discover -s tools/research -p 'test_verify_srsc_read_helper_callers.py'
objdump -d -Mintel --start-address=0x00424949 --stop-address=0x004249a4 research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x004249a4 --stop-address=0x00424a02 research/binaries/us/Drakan.exe
```

The initial seventeen focused tests cover direct-reference parsing, helper and caller
instruction anchors, bounded request-size tracing, adversarial register and
control-flow cases, and the verified-byte snapshot passed to objdump.

### Additional bounded request-size callsites, 2026-10-23

The helper's `thiscall` entry at `0x0045F2F3` reads its second stack argument
as a pointer, dereferences that pointer at `0x0045F2FC` to obtain the requested
DWORD length, and returns with `ret 0x8`. Two bounded callsite batches traced
the stored value back through that size pointer. Fourteen calls now have
mutation-checked instruction anchors for these expressions:

Each product denotes the low 32-bit result of the retail instruction
sequence, not an unbounded mathematical product; signed 16-bit inputs can
produce negative intermediate values before they are interpreted as a DWORD.
An `esp+offset` source refers to the stack position at the specific load
instruction, before any subsequent pushes.

| Callsite | Requested byte expression |
|---|---|
| `0x0040C50A` | `2 × DWORD [esp+0x10]` |
| `0x0040CCCA` | `12 × DWORD [esp+0x3c]` |
| `0x0040CD09` | `44 × DWORD [esp+0x3c]` |
| `0x0040CD5F` | `4 × sign_extend_i16([esi+0x8e])` |
| `0x0040CDAA` | if `WORD [esi+0x8c] == bx`, `16 × sign_extend_i16([esi+0x8e])`; otherwise `60 × sign_extend_i16([esi+0x8e])` |
| `0x0040CEBA` | `6 × DWORD [[esi+0x78]+0x94]` |
| `0x0040CEE3` | `104 × DWORD [[esi+0x78]+0xa0]` |
| `0x0040D056` | `108 × DWORD [esp+0x34]` |
| `0x0040D0C9` | `12 × DWORD [esp+0x30]` |
| `0x0040D211` | `152 × DWORD [esp+0x30]` |
| `0x0040D47A` | `4 × DWORD [esp+0x20]` |
| `0x0040D495` | `2 × DWORD [esp+0x48]` |
| `0x0040D5F4` | `2 × DWORD [esp+0x1c]` |
| `0x0040D7F7` | `4 × DWORD [esp+0x1c]` |

At `0x0040D7F7`, the equality path performs the bounded read with the `4n`
value; the mismatch path skips the same byte count. These are requested-byte
expressions from local instructions, not semantic names for their source
fields. The verifier does not emulate arbitrary arithmetic, establish valid
input ranges, or show that the read succeeds. The formula sites remain in the
constant-only classifier's unknown set.

The size classifier was also extended to resolve a stored value from its most
recent same-block full-width `mov register, immediate`, while stopping at
intervening register writes and partial-register aliases. It recognizes the
four-byte request at `0x004156CC` and four additional newly classified
constant callsites, all covered by exact size-pointer, assignment, store, and
call instruction anchors. Four other immediate-register candidates were
returned to unknown because post-push writes through ESI/EBP could not be
proven disjoint from the live size-pointer argument. The checker also rejects
stack argument removal or width changes, writes overlapping the final
arguments, branch-skipped definitions, and untracked memory writes. The
pinned run classifies 42 constant callsites, anchors the derived
`0x0042499F` request separately, and leaves 60 direct calls unknown to the
constant-only classifier. Those 60 include the fourteen formula cases above;
they are not all wholly unexamined. Twenty-eight focused tests pass,
including the register and stack-clobber cases and mutation checks for the
instruction anchors.

### Two related size formulas and a repeated 52-byte stride, 2026-10-24

The same hash-pinned binary has two more locally traceable calls, added to the
address-specific request formula map in
`verify_srsc_read_helper_callers.py`. At `0x004157B6`, the caller loads the
DWORD at `[edi+0x20]`, shifts it left three bits, stores that value through the
helper's size pointer, and requests that many bytes: `8 * DWORD [edi+0x20]`.
At `0x0041580B`, it reads a DWORD through `[ebp]`, forms `13 * value` using
LEA instructions, shifts left two bits, allocates that amount, stores it as
the bounded-read request, and requests `52 * DWORD [ebp]` bytes. These are
machine-width arithmetic observations; input range and allocation success are
not established.

After the second request, a loop compares its iteration counter with the
same `[ebp]` value and advances the record pointer by `0x34` bytes per
iteration. The loop scales three DWORD values at offsets 40, 44, and 48 within
that stride by the same constant. This anchors the 52-byte request to the
loop's repeated byte stride on this path; it does not establish a general
record type, field meaning, selector association, or successful runtime read.
The current report verifies 895 instructions supporting variable request
formulas, classifies 42 local constant requests automatically, and separately
anchors the derived `masked_count * 10` case. The 61 calls outside the
constant-only classifier consist of 60 formula-anchored requests and that one
derived-size request; this fresh run leaves no direct calls unresolved in the
census. It remains limited to direct static callsites and does not establish
read success or source-field meaning. The focused verifier suite and a fresh
hash-pinned run passed on 2026-10-24.

### Two-word selector caller path, 2026-10-24

**Input:** the same US retail executable and SHA-256 recorded above.
**Method:** GNU objdump 2.45.1-5.fc43, using a fresh full-image disassembly
and the exact-instruction anchors in `verify_srsc_read_helper_callers.py`.
The verifier hashes one byte snapshot before passing it to objdump.

At `0x0041538D`, the sole direct caller passes a packed DWORD into the routine
that reaches `0x00415668`; its high word selects a module object by comparison
with the global table entry's `+0x114` field. The same value is later masked
to its low word and passed with `0x0501` to `0x0045FA10`. The callee reads the
two arguments, masks each to 16 bits, and
scans the loaded record table from index zero. For each index, calls to
`0x0045FA70` and `0x0045FAA0` return the words at record offsets 0 and 2;
both must match before the callee returns that index. If either differs, it
increments the index and repeats. The caller passes the returned index to
`0x0045F270`, the indexed selection path documented above.

The direct-call and instruction anchors also connect this to a cache-miss
constructor path: `0x00415360` calls `0x004155D0` when its key is absent;
`0x004155D0` resolves the packed key's high word to a module entry, obtains
that entry's object at `+0x150`, and calls the pair loader with `(0x0501,
low_word)`. In the same constructor, the selected index is passed to
`0x0045F270`, followed by the separately anchored bounded reads and repeated
stride at `0x004157B6` and `0x0041580B`. This is a static conditional path
from the cache lookup into a selected `0x0501` record and its later reads. It
does not show that any particular call or read executes, or that an observed
asset's second selector equals a caller's low word.

This establishes first-match pair lookup for this observed call path and
confirms that the table's first two selector words are read as a pair here.
It does not establish what `0x0501` denotes, how the packed argument's low
word is produced, or the selected payload's general grammar. The direct
caller, high/low-word split, lookup loop, comparisons, selector-word offsets,
module handoff, pair lookup, subsequent I/O sequence, and upstream argument
sources are guarded by 61 exact instruction anchors. These include the module
open/sort handoff and the two later indexed selections. The
focused verifier suite passes 31/31 tests, including
mutation of every selector-path anchor. Reproduction:

```sh
python3 tools/research/verify_srsc_read_helper_callers.py research/binaries/us/Drakan.exe
python3 -m unittest discover -s tools/research -p 'test_verify_srsc_read_helper_callers.py' -v
```

The selected-index call at `0x0041569C` is followed by `test eax,eax` and a
conditional branch, so this caller checks that operation's result before
entering the read sequence. In the fallthrough path, the bounded read at
`0x004156CC` proceeds directly to a skip call at `0x004156D4`; the skip
proceeds directly to a four-byte helper at `0x004156DF`; that helper proceeds
directly to another bounded read at `0x004156F3`. The latter read is followed
by three more four-byte helper calls at `0x004156FE`, `0x0041570A`, and
`0x00415715`, without testing the preceding helper result between those
calls. This is a static failure-check boundary for this caller only. It does
not establish that these operations fail for any retail input or how the
caller handles the resulting values.

The loader's direct caller at `0x0041538D` receives its packed DWORD as the
stack argument to the routine at `0x00415360`, which reads that value at
`0x00415363` and preserves it for the loader call. The full executable has six
direct call sites to `0x00415360` (`0x00415345`, `0x0041682E`, `0x00416BA8`,
`0x00417450`, `0x0041801F`, `0x00418B24`). Several pass a DWORD loaded from
their caller's data; this does not establish those fields' meaning or prove
that their values match the observed second-selector distribution.

The hash-pinned full-image verifier now checks the complete direct-call sets
for this path: six calls to `0x00415360`, one call from `0x0041538D` to
`0x004155D0`, and four calls to the pair selector loader `0x0045FA10` (from
`0x00415668`, `0x0042476E`, `0x00433030`, and `0x0045F24D`). Only the first
pair-loader callsite, `0x00415668`, is in the `0x0501` path described here;
the other three loader callers are not interpreted in this note. These are
direct relative calls in this executable; indirect calls and runtime dispatch
remain outside the census. One synthetic test checks the exact target/caller
sets and rejects missing or extra calls.

### Other direct callers of the pair-selector loader, 2026-10-24

The two-word lookup path has three direct callsites outside the traced
`0x0501` constructor. Bounded GNU objdump windows of the hash-pinned US retail
executable show that `0x0042476E` calls with first argument `0x0200` and a
second argument held in EDI; `0x00433030` uses first argument `0x0302` and a
second argument held in EBP. The loader masks both arguments to 16 bits,
compares the first with the word at record offset 0 and the second with the
word at offset 2, then searches the current table order from index zero.
These two callers test the returned index before continuing into indexed
selection, but the register values' meanings and their runtime values are
unknown.

The third callsite, `0x0045F24D`, is a mode-gated wrapper: when its object
mode equals 1, it forwards its two stack arguments to the same pair lookup
and, on a nonnegative result, passes that index to `0x0045F270`. This trace
does not classify the wrapper's callers or its runtime arguments.

`verify_srsc_0501_consumer.py` now checks 138 exact instruction anchors across
these callers, the pair lookup and the previously traced `0x0501` path. Its
six focused tests include mutation of every pinned instruction. The separate
whole-image `verify_srsc_read_helper_callers.py` pass confirms four direct
relative calls to `0x0045FA10`, matching the `0x00415668`, `0x0042476E`,
`0x00433030` and `0x0045F24D` callsites. This remains a direct-call census;
indirect callers, runtime dispatch and field semantics are unverified. The
findings refine observed use of the first two selector words for these paths,
not a universal selector grammar. Reproduce with:

```sh
python3 tools/research/verify_srsc_0501_consumer.py research/binaries/us/Drakan.exe
python3 -m unittest discover -s tools/research -p 'test_verify_srsc_0501_consumer.py' -v
python3 tools/research/verify_srsc_read_helper_callers.py research/binaries/us/Drakan.exe
python3 -m unittest discover -s tools/research -p 'test_verify_srsc_read_helper_callers.py' -v
```

### Packed-key routing into a 0x0302 pair lookup, 2026-10-24

**Input:** the same US retail executable and SHA-256 recorded above.
**Method:** GNU objdump 2.45.1-5.fc43; exact instruction anchors in
`tools/research/verify_srsc_selector_0302_key.py`, plus a full-image direct
call scan from the same verified byte snapshot.

At `0x00432F93`, a 32-bit first stack argument is copied to EBP. After a
preceding lookup at `0x00431010`, the branch at `0x00432FA5` checks object
offset `+0x5a`; on its zero fallthrough, the code shifts EBP right by 16 and
compares that value with the selected module entry's DWORD at `+0x114`
(`0x00432FC0`–`0x00432FCA`). Once the module's table at `+0x15c` is selected,
the callsite at `0x00433030` passes first selector `0x0302` and the original
EBP value to pair loader `0x0045FA10`. That loader masks both values to 16
bits; its first argument is compared with record offset 0, and its second
argument with record offset 2. On this conditional path, the same packed
DWORD therefore contributes its high half to module-entry matching and its
low half to the second selector comparison. The name and meaning of this
packed value remain unknown, and this trace does not establish runtime
execution or a successful lookup.

After a nonnegative pair lookup result, this function checks the result and
passes the index to `0x0045F270`. When that call returns zero and the local
object cache misses, it calls `0x00430F20` and, on a returned object, stores
the packed key at object offset `+0x62` (`0x00433086`). A separate direct
caller at `0x00432A6B` loads a DWORD from `+0x62` and forwards it to
`0x00432F70`. The shared offset and call route are observed, but do not prove
that the caller and constructor use the same object type or instance.

The full-image scan finds eight direct calls to function `0x00432F70`, at
`0x004310C6`, `0x00431106`, `0x00431146`, `0x00431186`, `0x004311AA`,
`0x00432A6B`, `0x00432B2F`, and `0x00432D1D`, with no direct unconditional
jumps to that address. Four thin wrappers forward their stack value through
EDI; one wrapper forwards its first stack argument unchanged; one call uses a
DWORD from object offset `+0x62`; two others use stack-local values loaded at
`[esp+0x38]`. These are source locations only. They do not identify the
fields' meanings or rule out indirect callers.

The verifier anchors 75 instructions and checks the exact eight-call set.
Six synthetic tests cover instruction mutation, missing/extra callers,
direct jumps, snapshot handoff, stale-hash rejection and symlink rejection.
Reproduce with:

```sh
python3 tools/research/verify_srsc_selector_0302_key.py research/binaries/us/Drakan.exe
python3 -m unittest discover -s tools/research -p 'test_verify_srsc_selector_0302_key.py' -v
```

The traced constructor calls `0x0041E470` for the selected module at
`0x00415645`. On its successful load path, that routine calls the stable
second-selector ordering method at `0x0041E50F` before returning the table.
After selecting a matching `0x0501` entry at index `i`, the constructor
selects indices `i+1` and `i+2` at `0x0041575A` and `0x004157CC`.

### Packed-key routing into a 0x0200 pair lookup, 2026-10-24

**Input:** the same hash-pinned US retail executable.
**Method:** GNU objdump bounded windows and a full-image direct-call scan,
guarded by 48 exact instructions in
`tools/research/verify_srsc_selector_0200_key.py`.

The cache helper at `0x00424690` retains its 32-bit key in ESI. It scans a
bucket selected by division by `0x59`, comparing the full key with the node
field at `+4`. On the missing-node path, it passes that key to
`0x004246D0` (`0x004246BA`). The latter shifts a copy right by 16 and compares
that high word against module-entry offset `+0x114`. After resolving the
module object's table at `+0x12c`, it calls the pair loader with first
selector `0x0200` and the original key. The pair loader masks both arguments
to 16 bits and compares them against record offsets 0 and 2, so this
conditional path uses the key's low word for the second-selector comparison.
The cache's upstream callers were not identified here; no field meaning,
runtime execution, successful match or selector-wide rule is established.

After a nonnegative match, the caller passes the index to the indexed selector
`0x0045F270`. It also reads the first selector of row `i+4` through
`0x0045FA70` and compares it with `0x0208`; the result chooses one of two
object-construction calls. It then stores the original packed key at object
offset `+4`, calls the indexed selector for row `i`, calls the bounded helper
`0x0045F430` with a buffer and capacity `0x40`, calls the read helper
`0x0045F370`, calls the indexed selector for row `i+1`, and calls
`0x0045F370` again. These are static follow-on operations; they do not
establish record meaning, runtime execution, or successful reads.

The full-image census found one direct call to `0x004246D0`, from
`0x004246BA`, and no direct unconditional jumps. It does not classify indirect
entries. The verifier anchors 49 instructions. Its five synthetic tests cover
all anchor mutations, exact caller-set behavior, same-snapshot disassembly,
stale-hash rejection and symlink rejection. Reproduce with:

```sh
python3 tools/research/verify_srsc_selector_0200_key.py research/binaries/us/Drakan.exe
python3 -m unittest discover -s tools/research -p 'test_verify_srsc_selector_0200_key.py' -v
```

The same executable path also gives a static testable relationship for the
sampled table rows. `measure_srsc_cross_kind_order.py` now measures the
first-match distinct `(0x0200, second_word)` rows in each hash-verified file
and reads the first selector four rows later. Across 178 US containers, all
3,221 `0x0200` rows have distinct pair keys and an in-bounds `i+4` row; 99 of
those successors have first selector `0x0208` and 3,122 have another value.
There are 99 `0x0208` rows total, so each such row has a one-to-one positional
match to a distinct `0x0200` row four positions earlier in this sample. This
co-occurrence does not establish why the caller checks that row, which key
values occur at runtime, or any grouping rule.
Seven synthetic tests cover this census's first-match de-duplication,
in-bounds, match, nonmatch, inventory-hash and malformed-input cases. The
measurement emits aggregate counts only; reproduce with:

```sh
python3 tools/research/measure_srsc_cross_kind_order.py research/installed/us research/exports/srsc-records/us.json
python3 -m unittest discover -s tools/research -p 'test_measure_srsc_cross_kind_order.py' -v
```
Accordingly, `measure_srsc_0501_payloads.py` now examines neighbors under
stable second-word ordering. In all 1,722 hash-verified US `0x0501` records,
the next two entries are `(0x0503, second_word)` and
`(0x0502, second_word)`. This exact sample pattern is consistent with the
traced indexed-selection sequence; it does not establish a universal file
rule, record meanings, successful reads, or runtime execution. Eight focused
measurement tests cover this aggregate neighbor check and malformed selectors.

Eighteen additional instruction anchors cover the six input sites to
`0x00415360`: two forward a DWORD already supplied on their own stack, three
load a DWORD from a caller object's `+4` field, and one loads a DWORD from a
table-entry `+4` field. The anchored sequence at `0x004173E3`/`0x004173EA`
shows the forwarded value is loaded and pushed before the later call at
`0x00417450`. These are argument-source locations only; they do not establish
the meaning of the fields or that the later low-word values match the sampled
`0x0501` second selectors. Mutation tests cover every added instruction
anchor.

### Additional bounded-read size formula, 2026-10-24

At `0x004248BF`, the caller loads the DWORD at `[edi+0x0c]`, forms three
times that value with `lea ecx,[eax+eax*2]`, and shifts the result left by two.
It stores that result in the bounded-read size argument slot, then calls
`0x0045F2D0`. The requested count is therefore `12 * DWORD [edi+0x0c]` modulo
32-bit arithmetic. The verifier anchors the input load, arithmetic, size-slot
store, buffer/position setup and call. This records only the requested byte
count; the field's semantic meaning, count validity and runtime outcome remain
unknown. At the nearby call `0x00425300`, the size pointer and buffer arguments
are set at `0x00425266`–`0x0042526F`. Intervening writes through ESI happen
before `0x004252F8` writes the value two using a four-byte store directly into
the live size slot; the helper call immediately follows at `0x00425300`.
This is an anchored two-byte
request despite those earlier writes.

Two additional callsites are anchored by the verifier. At `0x00421FDF`, the
size value is formed as `4 * DWORD [esp+0x28]`; at `0x004222E7`, the caller
loads `DWORD [esp+0x48]` and stores it through the established size pointer.
The latter call has intervening writes at higher stack offsets, disjoint from
that size-pointer target. These expressions describe the supplied byte count
at those callsites only; source-field meanings and runtime outcomes remain
unknown.

At `0x00429DA6`, the caller loads a stack-local DWORD from `[esp+0x10]`,
multiplies it by four, stores the result through the bounded-read size pointer,
and calls the helper. The associated buffer argument is set immediately
before the call. This is an anchored `4 * DWORD [esp+0x10]` request; it does
not assign a meaning to that local value.

At `0x00424C06`, the request is four times the sign-extended 16-bit value at
`[ebp+0x8e]`; the result is stored to a local size slot before the buffer and
size pointer are passed. At `0x00424C51`, the same signed 16-bit source is
multiplied by 16 and stored through the local size pointer before the call.
These are path-specific byte-count formulas; neither source field's meaning
nor its valid range is established.

At `0x00425259`, the size pointer is established before the intervening
floating-point writes, and the immediate store at `0x00425251` places `0x30`
(48) in its target directly before the helper call. The buffer pointer and
object argument are also anchored; no control transfer occurs between the
size-pointer setup and the request. This is a 48-byte request on this path,
without a claim about the buffer contents.

At `0x0042B388`, the stored request size is `DWORD [esi+0x6]`; the local size
slot, buffer argument and call are directly anchored. Calls at `0x0042B7FA`
and `0x0042B813` each request four bytes. Their size slots receive the value
from `EBP`, set to four earlier in the same sequence; the intervening helper
preserves the value because the bounded-read routine does not modify EBP.
These observations describe request sizes only and assign no meaning to the
source fields.

At `0x0042BDEC`, the request size is the DWORD loaded from `[esp+0x20]` into
the local size slot. The intervening multiply/add computes the buffer pointer
that is pushed for the helper, not the request length. At `0x0042CCAB`, the
caller computes `12 * DWORD [esp+0x20]`, stores it through the size pointer,
and passes the buffer immediately afterward. These formulas are specific to
the callsites and do not assign meanings to their stack-local sources.

At `0x0042CC25`, the request size is computed as 56 times the value in EDI at
`0x0042CC0B`; the calculation is `((EDI * 8) - EDI) << 3`, stored through the
size pointer before the buffer is pushed. EDI is reassigned afterward for the
helper object argument. This establishes the byte-count expression while
leaving the source value and its meaning unresolved.

The adjacent call at `0x00425D66` also has a four-byte request, with `EDI`
set to four at `0x00425D51`. Four subsequent calls at `0x00425D7A`,
`0x00425D8E`, `0x00425DA2`, and `0x00425DB6` reuse that value. The helper at
`0x0045F2D0` saves `EDI` on entry and restores it on each of its five return
paths; these entry, return and caller instructions are exact verifier anchors.
This establishes the request size at those callsites, while the values read
into their buffers remain uninterpreted.

### Additional bounded-read request expressions, 2026-10-24

The same hash-pinned US retail executable was inspected with GNU objdump
2.45.1-5.fc43. The verifier hashes one byte snapshot before giving it to
objdump, and now mutation-checks the following additional instruction paths.
At `0x00424ADF` and `0x00424B86`, immediate size-slot stores request 48 and 2
bytes. At `0x004254E1`, the request is 2 bytes: EDI is set to 2, then retained
through an earlier bounded read and skip helper whose observed return paths
restore EDI. At `0x00425618` and `0x0042562C`, ESI is set to 4 and retained
through the preceding bounded reads; both calls request 4 bytes. At
`0x00425C35`, EDI is set to `0x30`, retained through the preceding bounded
read, and stored as a 48-byte request.

Four other sites obtain the request from a local or object field. On the
fallthrough branch at `0x00433279`, the request is `DWORD [esi+0x22]`, copied
into the local size slot before the call. At `0x004332C2`, the request is
`DWORD [esp+0x10]`, also copied into the local slot. At `0x00435C13`, the
request is the local `DWORD [esp+0x1c]`; at `0x00435D1C`, it is
`DWORD [esp+0x30]`. The call at `0x00435737` requests
`4 * (DWORD [esp+0x18] & 0xffff)` with 32-bit register arithmetic. These are
byte-count observations only; the local fields' meanings, valid ranges,
runtime reachability, and read outcomes remain unknown.

A further three requests were traced in the same pinned image. At
`0x0042603C`, the caller loads `DWORD [esi+0x8]`, adds EBP, stores the sum
back to that field, shifts the sum left four, and stores it through the size
pointer: `16 * (DWORD [esi+0x8] + EBP)` using the value before the writeback.
At both `0x0042BBA1` and `0x0042BCB7`, the request is copied from
`DWORD [esp+0x28]` into the local size slot before the call. These stack and
object fields remain unnamed and their valid ranges are unknown.

Three more sites are anchored. At `0x00437782`, the request is
`4 * DWORD [esp+0x20]`; at `0x0043779D`, it is
`2 * DWORD [esp+0x18]`, both with 32-bit arithmetic. The string-reader helper's
conditional second read at `0x0045F47E` requests
`min(DWORD [esp+0x10] & 0xffff, DWORD [esp+0x1c])`. That call is reached only
after its initial two-byte length read succeeds and its destination pointer
is nonzero. The cap and length fields are not assigned broader meanings.

Five register-carried requests were also resolved by anchoring the complete
relevant helper bodies. At `0x004156F3`, EBX still contains 4 after the earlier
bounded read, skip, and four-byte reader calls; at `0x0043143F`, EBX still
contains 12 after the immediately preceding bounded read. At `0x00437035`,
the request is 4 on the fallthrough path where the prior read returned zero;
ESI is preserved by that helper. At `0x004376A9` and `0x004376D4`, EBP still
contains 4 after bounded reads and calls to `0x00409DB0`. The complete
`0x00409DB0` body uses EAX, ECX, and EDX plus floating-point operations, and
does not write EBP. These are path-specific request sizes and make no claims
about the values read or subsequent interpretation.

At `0x004223BA`, the request expression is conditional on the signed local
count at `[esp+0x38]` being nonpositive. With `A = DWORD [edi+0x18]` and
`C = DWORD [edi+0x1c]`, the code computes `26*A*C + 4*(A+1)*(C+1)` modulo
32 bits into EBX, passes it to imported `GlobalAlloc`, then follows a branch
that skips a later EBX overwrite before storing it in the read-size slot.
This trace relies on the Win32 x86 nonvolatile-register convention for EBX
across the imported `GlobalAlloc` and `GlobalLock` calls. The call's
reachability and both source fields' meanings remain unknown.

At `0x0042B293`, the request is the minimum of the caller's capacity argument
and a length value loaded from `base + 26*index + 6`, where `base` is loaded
from `[ebx+0x104]` and `index` is EBP. The code computes the table position
with 32-bit arithmetic, clamps EDI to the lesser value, and the read occurs
on the zero-return branch of `0x0045F270`; the complete helper anchors show it
saves and restores EDI on each return. This does not assign meaning to the
table, index, capacity, or length field, and does not establish input validity
or a successful read.

At `0x0042EEEF`, a wider caller trace resolves the table value used as the
request length: `DWORD [0x0047D050 + 4*(DWORD [esp+0x20] & 0xffff)]`. The
masked word indexes a dword table, and the selected value is stored into the
local size slot while two arguments are pushed for `GlobalAlloc`; after the
calls to `GlobalAlloc` and `GlobalLock`, that same slot is passed to the
bounded-read helper. The pointer-valued store at `0x0042EB60` targets a
different local: the persistent `push ebx` at `0x0042EBD8` shifts ESP by four
bytes before the later allocation sequence.
At `0x0042EED3`, `[esp+0x38]` after the two allocation-argument pushes aliases
the size slot later addressed as `[esp+0x30]` at `0x0042EEE4`. This identifies
the request expression only; table contents, selector/index meaning,
allocation outcome, and payload structure remain unknown.

At `0x0040BE48`, the bounded-read size pointer targets `[esp+0x14]`, the same
local targeted as the destination buffer by the four-byte reader at
`0x0040BDD9`. The reader body anchors show its request size is four; they do
not establish that this read succeeded. The preceding virtual call receives
immediate `0x20` with a separate output pointer; that output is later loaded
and passed as the read buffer, so `0x20` is not the request size. The verifier
includes the caller sequence and reader body anchors for this trace.

The exact caller anchors and helper/skip preservation instructions are in
`EXPECTED_VARIABLE_REQUEST_INSTRUCTIONS` and
`EXPECTED_VARIABLE_REQUEST_FORMULAS` in the verifier. The updated run checks
895 variable-size instruction addresses across 60 formula callsites; the
constant-only classifier still reports 42 locally traced requests, one
separately derived `masked_count * 10` request, and no unresolved calls.
Reproduction:

```sh
python3 tools/research/verify_srsc_read_helper_callers.py research/binaries/us/Drakan.exe
python3 -m unittest discover -s tools/research -p 'test_verify_srsc_read_helper_callers.py' -v
```

These anchors add no record or payload semantics and do not establish whether
any particular retail read succeeds.

### US asset distribution for first selector 0x0501, 2026-10-24

`tools/research/measure_srsc_0501_payloads.py` verifies each entry against the
private 178-file US SRSC inventory, then parses and measures the same
hash-checked byte snapshot. In this inventory, all 1,722 records whose first
selector is `0x0501` occur in the 12 `.adb` containers. Their third selector
is zero in all 1,722 records; they contain 1,293 distinct second-selector
values. Each of those 1,722 records is the first `(0x0501, second-selector)`
match in its own table; repeated second-selector values occur across files.
Their nonempty payload lengths range from 48 to 70 bytes, with 11
distinct lengths and 93,796 aggregate bytes. The measurement checks each
selected payload range against the complete file length and prints no paths or
payload bytes.

This is an edition- and inventory-specific distribution. It does not show
that the `0x00415668` caller's packed low word matches every observed second
selector, identify the records' contents, or establish runtime reachability.
Eight synthetic tests cover selector filtering, range bounds, selector/table
consistency, duplicate inventory paths, count mismatch and aggregate payload
shape. The aggregate output also reports 242 second selectors with multiple
lengths (maximum four lengths per selector). Reproduce with:

```sh
python3 tools/research/measure_srsc_0501_payloads.py research/installed/us research/exports/srsc-records/us.json
python3 -m unittest discover -s tools/research -p 'test_measure_srsc_0501_payloads.py' -v
```

A separate aggregate-only review of these same hash-checked payload snapshots
found 1,640 distinct exact payloads (82 duplicate occurrences, maximum
multiplicity seven). Payload lengths do not map one-to-one to second selector:
242 of 1,293 selectors occur with multiple lengths, up to four. In 1,487
records, bytes from offset 2 have a first NUL before offset 18; 1,030 of those
prefixes are entirely printable. Across all records with a NUL after offset 2,
1,047 prefixes are entirely printable, and the first-NUL offset varies across
22 positions. Some records contain nonprintable bytes before the NUL. At the
aligned two-byte slot at offset 44, 32 values occur and `0x3f80` occurs 400
times; at offset 38, 46 values occur and zero occurs 1,068 times. No consumer
reads have been located to anchor these slots' type or meaning. This supports
only a tentative string-plus-binary payload-shape hypothesis. The separate
static constructor trace selects records with first selector `0x0501`, but it
does not anchor these byte slots or connect their values to caller inputs.
Field meanings and a general grammar remain unknown. The aggregate-only
measurement is reproduced by
`measure_srsc_0501_payloads.py`; no payload bytes or paths are emitted.

### Follow-up read path for selector 0x0501, 2026-10-24

`tools/research/verify_srsc_0501_consumer.py` verifies the US retail executable
SHA-256 and 80 exact instruction anchors from `0x004156A9` through
`0x0041584A`, plus 24 anchors in the length-prefixed reader at
`0x0045F430` and its subsequent index selection. GNU objdump 2.45.1-5.fc43
confirms the caller's two `push eax`
arguments occur on the zero-result fallthrough of the selected-index check.
The helper reads a two-byte prefix, takes its low 16 bits, and, because this
caller supplied a null output pointer and zero capacity, skips the complete
length-prefixed span without copying its bytes. This identifies the first
variable span as skipped on this path; its contents remain unknown. The
constructor selects records at indices `i+1` and `i+2`
after the matched `0x0501` record at `i`, then reads a two-byte prefix from
each selected record. For the `0x0503` record, it requests eight times the
DWORD stored at runtime-object offset `+0x20`; for the `0x0502` record, it
requests 52 times the DWORD at `+0x18`. Those dwords were loaded from the
`0x0501` payload after the caller consumes an initial length-prefixed field:
they occur at byte offsets 8 and 16, respectively, after that field. The
following `0x0502` loop advances by `0x34` bytes and transforms three dwords
per unit.

The hash-verified US asset scan found that, in all 1,722 trios, the `0x0503`
two-byte prefix equals the `0x0501` dword at post-field offset 16, and its
payload length is exactly `2 + 8 × prefix`. Likewise, the `0x0502` prefix
equals the `0x0501` dword at post-field offset 8, and its payload length is
exactly `2 + 52 × prefix`. This supports the observed read arithmetic for
this sample; it does not name record fields, establish successful runtime
reads, or show that every `0x0501` record uses this path. Six synthetic
verifier tests pass, including mutation of every pinned instruction, a single
checked-snapshot handoff to objdump, and stale-hash rejection before
disassembly. The verifier now checks 104 instruction anchors across the
constructor, length-prefixed helper, and next-index selection, including both
zero arguments and the helper's skip branch. A bounded size comparison finds every sampled `0x0501`
payload is 16 bytes longer than the `30 + prefix` bytes covered by the traced
length-prefix/skip and fixed-width reads, assuming those operations succeed.
This leaves an unaccounted 16-byte suffix on this constructor path; whether
another consumer uses it and what it contains remain unknown. The anchored
caller next selects index `i+1`; its fixed-width read sequence does not consume
that suffix before the selection. Ten
aggregate-measurement tests cover valid ranges, gaps, both successor-prefix
mismatches, selector-snapshot mismatch, out-of-bounds extents, header overlap,
trailing bytes, and an unbounded prefix. Reproduce
the instruction and data checks with:

```sh
python3 tools/research/verify_srsc_0501_consumer.py research/binaries/us/Drakan.exe
python3 -m unittest discover -s tools/research -p 'test_verify_srsc_0501_consumer.py' -v
python3 tools/research/measure_srsc_0501_payload_layout.py research/installed/us research/exports/srsc-records/us.json
python3 -m unittest discover -s tools/research -p 'test_measure_srsc_0501_payload_layout.py' -v
```

### Payload extents for stable-order selector trios, 2026-10-24

`tools/research/measure_srsc_0501_payload_layout.py` rechecks the size and
SHA-256 of all 178 US SRSC inventory entries, then measures table and payload
ranges from each same byte snapshot. In the 12 `.adb` files containing
`0x0501`, it found 1,722 first-match `(0x0501, second-selector)` keys and
matching stable-order `0x0503`/`0x0502` followers. All three payload extents
are in bounds and contiguous in selector order in every trio. The 1,722 trio
groups also have zero gaps between them (1,710 inter-group boundaries), and
their first group starts at byte 12 in all 12 files.

In each file, the last trio ends ten bytes before the table. A separate
`(0x0500, 0, 0)` extent of six bytes followed by a `(0x0402, 0, 0)` extent of
four bytes fills that tail exactly in all 12 files. Payload lengths vary:
`0x0501` is
48–70 bytes, `0x0503` is 18–482 bytes, and `0x0502` is 106–612,510 bytes.
These are US-sample extent relationships; they do not establish shared
ownership, field meanings, a format invariant, or runtime use. The report
emits aggregate counts only. For all 1,722 `0x0501` payloads, the complete
length is `30 + prefix + 16`; the 16-byte remainder is not consumed by the
traced fixed-width read sequence if every operation succeeds, and its use is
unknown. In the 1,722 measured suffixes, 146 distinct 16-byte sequences occur;
1,576 occurrences are repeats beyond the first copy, and the most repeated
sequence occurs 578 times. Seven byte positions are constant across the
sample, but their values are not emitted. No suffix contents are included in
the report, and these repetitions do not identify a field or consumer. Ten
synthetic tests cover contiguous ranges, gaps, each
successor-prefix mismatch, snapshot mismatch, out-of-bounds extents, header
overlap, trailing bytes, and an unbounded prefix. Reproduce with:

```sh
python3 tools/research/measure_srsc_0501_payload_layout.py research/installed/us research/exports/srsc-records/us.json
python3 -m unittest discover -s tools/research -p 'test_measure_srsc_0501_payload_layout.py' -v
```

### Exact suffix searches in other SRSC payloads, 2026-10-24

`tools/research/measure_srsc_0501_suffix_reuse.py` takes each hash-verified
first-match `(0x0501, 0x0503, 0x0502)` trio under stable second-selector order
and searches the full candidate 16-byte `0x0501` remainder in the same
container's other SRSC payloads. It emits aggregate counts only. Across 1,722
trios in 12 of the 178 US containers, no complete suffix matched any payload
whose first selector differs from `0x0501`, including the aligned `0x0503` and
`0x0502` followers. The suffix bytes did match other `0x0501` payloads:
1,628 source records have at least one such match, and these repeats involve
90 distinct suffix byte sequences counted separately within each container.
For each of the 1,628 source records with a repeated suffix, the matching other
`0x0501` rows have a different second selector; no same-second-selector suffix
copies were found. This is consistent
with the previously measured repetition, but does not distinguish shared
values from common padding or identify fields. Exact absence from other kinds
in this sample does not establish that the suffix has no consumer or is not
decoded. Seven synthetic tests cover positive repeated matches within both
the same and other kinds, same/different second-selector cases, absent matches,
a non-16-byte remainder, and selector-snapshot mismatch. Reproduce with:

```sh
python3 tools/research/measure_srsc_0501_suffix_reuse.py research/installed/us research/exports/srsc-records/us.json
python3 -m unittest discover -s tools/research -p 'test_measure_srsc_0501_suffix_reuse.py' -v
```

### Bounded inspector cross-check for selector 0x0501, 2026-10-24

`dragonrider_inspect --record-0501-observed-prefix <index> <file>` exposes the
ADR 0026 structural reader for one explicitly selected `0x0501` record. It
reports the length-prefixed byte count and CRC32, seven raw little-endian
dwords, consumed byte count, and total opaque remainder length. Its remainder
CRC32 covers only bytes inside the bounded read window (at most 65,565 payload
bytes); it does not claim to checksum a larger suffix.

The independent `tools/research/verify_srsc_0501_inspector.py` verifies each
source file's inventory size and SHA-256, copies that exact snapshot to a
temporary path, and compares inspector output with an independent Python
decoder. On 2026-10-24 it matched 1,722 records in 12 of 178 inventoried US
containers. Five synthetic verifier tests cover opaque remainder reporting,
exact snapshot handoff, stale hashes, symlink paths and duplicate inventory
paths. CTest CLI fixtures also cover the bounded read window, truncation,
wrong selector, out-of-range index and invalid index syntax. This verifies
the bounded diagnostic against sampled bytes; it does not establish runtime
read success, field meaning, suffix semantics or compatibility with other
editions. Reproduce with:

```sh
python3 tools/research/verify_srsc_0501_inspector.py research/installed/us research/exports/srsc-records/us.json build/release/dragonrider_inspect
python3 -m unittest discover -s tools/research -p 'test_verify_srsc_0501_inspector.py' -v
ctest --preset debug --output-on-failure
ctest --preset release --output-on-failure
```

Reproduce the full hash-pinned census and formula summary with:

```sh
python3 tools/research/verify_srsc_read_helper_callers.py research/binaries/us/Drakan.exe
python3 -m unittest discover -s tools/research -p 'test_verify_srsc_read_helper_callers.py' -v
```

## Inferred and unknown

The evidence supports describing record offset 6 as a file-position field and
record offset 10 as the selected resource's byte length/read budget for these
paths. It is appropriate to validate the offset and length against file size
before exposing bytes in the independent engine; this is a safety policy, not
a claim that the original loader performs that validation. The semantic names
of the three lookup words, what the payload represents, zero-length entries,
alternate editions, and general ordering or uniqueness requirements remain
unknown. The retail measurements already include duplicate complete six-byte
tuples. Do not impose contiguity, nonzero payload length, ordering, uniqueness,
or table-at-EOF conditions solely from the scanned samples. `SetFilePointer`
has a signed low-order distance argument when its high-order pointer is null;
the sampled installed resources stay below that boundary, but this does not
establish practical support for unseen offsets at or above 2 GiB. See the
[hash-checked seek-width measurement](
srsc-record-observations.md#seek-width-boundary-recheck-2026-10-23).

The reader fields and bounded common-writer stores are jointly guarded by a
hash-pinned 14-anchor verifier; see [the record-field anchor
note](srsc-record-field-anchors-2026-10-23.md).
It confirms the documented offsets without adding a success-path or universal
format claim.

## Reproduction

Close any Ghidra GUI using this project and run in a dedicated shell. A process
listing cannot prove GUI closure; the lock below is cooperative among wrapper-based runs. List the
project and verify the input before invoking headless:

```bash
find research/ghidra-projects -maxdepth 1 -name '*.gpr' -print
sha256sum research/binaries/us/Drakan.exe
exec 9>research/ghidra-projects/.drakan-loader-probe.lock
flock -n 9 || exit 1
mkdir -p research/ghidra-logs/srsc-record-behavior
run=$(mktemp -d "$PWD/research/ghidra-logs/srsc-record-behavior/run-XXXXXXXX")
mkdir -p "$run/config" "$run/cache"
export XDG_CONFIG_HOME="$run/config" XDG_CACHE_HOME="$run/cache"
"$GHIDRA_HOME/support/analyzeHeadless" \
  "$PWD/research/ghidra-projects" Drakan_US_Retail -process Drakan.exe \
  -readOnly -noanalysis -scriptPath "$PWD/tools/ghidra/scripts" \
  -postScript TraceSrscRecords.java -log "$run/ghidra.log" \
  -scriptlog "$run/script.log" > "$run/console.log" 2>&1
exec 9>&-
```

The script limits each instruction window and caller list; its output and all
binary inputs remain private. The independent import and instruction checks
were run with:

```bash
objdump -p research/binaries/us/Drakan.exe | rg 'SetFilePointer|ReadFile|WriteFile'
objdump -d -Mintel --start-address=0x45eec2 --stop-address=0x45ef10 research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x45f0d0 --stop-address=0x45f228 research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x45f270 --stop-address=0x45f36e research/binaries/us/Drakan.exe
```

The follow-up aggregate measurement for the three observed `0x0502` row
float slots is recorded separately in
[`srsc-0502-float-slots-2026-10-25.md`](srsc-0502-float-slots-2026-10-25.md).
