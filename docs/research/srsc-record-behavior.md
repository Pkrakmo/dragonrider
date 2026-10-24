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
- Ghidra's current database has 26 direct calls to `0x0045F0D0`, 19 to
  `0x0045F270`, and at least 40 to `0x0045F2D0` (the script caps output at 40).
  Xrefs can be incomplete, and these counts are not a full execution trace.

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
