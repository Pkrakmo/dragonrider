# Writer state and the `0x0051` record

**Date and input:** 2026-10-18, unpatched US retail `Drakan.exe`, SHA-256
`23630f48e20e8a9f42026501165ae1df407cfcee545a784ec930a4c25ee70648`.
**Method:** GNU objdump 2.45.1-5.fc43 static disassembly of the PE, corroborated
for the setter and initializer checks by Ghidra 12.1.4 on a disposable project
using `TraceSrscIndirectLookup.java` with `-readOnly -noanalysis` (private run
`dragonrider-r1-prefix-QH00PGGT`); no game code was executed and no persistent
Ghidra project was opened. **Confidence:** high for
the instruction-level conditional result below; runtime reachability and
concurrent mutation are not established.

## Observed

The [writer analysis](srsc-lookup-order.md#observed-record-construction-in-the-retail-executable)
identifies state `+8` as the source of record word at offset 4. The helper at
`0x00441e20` calls the setter at `0x00441e2d` with zero and immediately calls
`0x0045f600` at `0x00441e38` with first two words `(0x0051, 0)`. It does not
check the setter's return. The setter writes zero exactly when the writer mode
is 2 and active index is -1; the initializer has the same two preconditions
and returns an error otherwise. No calls or stores occur between those calls
that could alter the writer. On a successful initializer return, absent
concurrent or asynchronous modification, the previous setter therefore
succeeded and this record's full tuple is `(0x0051, 0, 0)`. This is a
conditional consequence of the instructions, not an observed file write.

A larger routine at `0x0040b4d0` constructs a stack-local writer and invokes
its write-mode initialization at `0x0040b515`, testing for success. It passes
the same stack-local writer to `0x00441e20` at `0x0040ba27` and later to
`0x004315e0` at `0x0040bab6`. The latter requests `(0x0302, 0)` and takes its
third word from the writer state, as detailed in the
[separate consumer note](srsc-third-selector-consumer.md). The calls between
these points include indirect calls and paths receiving the writer pointer;
this inspection does not establish that state remains zero until the later
record initialization. It also does not establish that either call succeeds,
that this path ran, or which file it would write.

## Unknown

The `0x0051` result does not identify a general meaning for the third word.
Other writers, direct state writes, indirect dispatches, unusual error paths,
and alternate executable versions are outside this trace. A raw disassembly
search for direct calls cannot rule out indirect callers or aliases.

## Follow-up: caller-local state through the `0x0302` writer

On 2026-10-18 a bounded follow-up traced the stack-local writer in the caller
at `0x0040b4d0` using GNU objdump 2.45.1-5.fc43 against the same hash-checked
US retail executable. This follow-up did not open a Ghidra project or execute
the program. Confidence is high for the shown instructions and successful
branches, conditional for the full caller path.

- The caller initializes the local writer at `0x0040b515`, emits and closes
  preceding output, then calls `0x00441e20` with that same writer at
  `0x0040ba27`. The helper sets writer state `+8` to zero and successfully
  initializes `(0x0051, 0)` only if both operations succeed; as noted above,
  the setter's return is not checked, while initializer failure branches out.
- Before the later `(0x0302, 0)` writer call at `0x0040bab6`, the caller passes
  the same writer pointer to `0x0040e150` at `0x0040ba6a`. On its successful
  initializer branch, `0x0040e150` starts `(0x0022, 0)`, then writes a bounded
  sequence of fields and strings through `0x0045f6f0` and `0x0045f750`, and
  ends the record with `0x0045f7a0`. These operations do not call the state
  setter or explicitly store to writer `+8`; the `0x0022` record initializer
  therefore uses the current state as its third word.
- The same caller later passes that writer to `0x004315e0`. That routine
  initializes `(0x0302, 0)` and writes its payload without setting writer
  state. Because the common initializer copies state `+8` into record offset
  4, the `0x0302` record on this successful path has third word zero if state
  remained unchanged after the preceding `0x0051` setter.
- Between the `0x0022` and `0x0302` writes the caller invokes virtual methods
  on other objects. The disassembly shows no writer argument at those calls,
  but static inspection cannot exclude a hidden alias, global side effect, or
  asynchronous mutation of the writer. The code also does not establish that
  all initializers, writes, or enclosing branches succeed at runtime.

This narrows the state question for this one caller: no explicit writer-state
change is visible between the successful `0x0051` setup and the `0x0302`
initializer, and an intervening `0x0022` writer reuses that state. It still
does not identify the third word generally or prove which file this path
produces. All 1,561 sampled US `0x0302` records have nonzero third words, so
they are inconsistent with this conditional zero-state path as written; this
does not show that the routine ran or failed against those files.

## Direct setter call-site scan

A whole-image GNU objdump 2.45.1-5.fc43 scan of the documented US retail
executable found one direct call to the writer constructor `0x0045f4d0` (at
`0x0040b515`) and one direct call to the state setter `0x0045f5d0` (at
`0x00441e2d`); the setter's preceding instruction pushes zero. This matches
the one direct setter call in the earlier disposable Ghidra database. The
same disassembly has ten direct calls
to the record initializer `0x0045f600`, including the `(0x0302, 0)` call at
`0x004315f4`; on the successful mode-2 branch, each initializer copies the
writer's current `+8` state into the third selector word at record offset 4.
Another call at `0x0040dd4c` initializes an `0x0102` record with a dynamic
second selector and likewise uses the existing state. The scan is limited to
direct relative calls and does not find indirect calls or identify every
direct write through an aliased writer pointer. It therefore does not explain
the nonzero third words in installed files or show how those files were
produced.

## Follow-up: the `0x0102` writer is a separate candidate

On 2026-10-18, GNU objdump 2.45.1-5.fc43 was used to examine the same
hash-checked retail executable and compare its write calls with the sampled US
SRSC records. Confidence is high for the instruction-level sequence and the
measured sizes; file production and runtime dispatch are unverified.

The `0x0040dd30` routine initializes an `0x0102` record with a dynamic second
selector. After a successful initializer and a virtual call, it makes ten
consecutive `0x0045f6f0` calls at `0x0040dd7f` through `0x0040de4d`, with
requested sizes 4, 4, 108, 2, 2, 2, 4, 4, 4 and 2 bytes, respectively: 136
bytes in total. It does not check those write returns. If all writes complete
fully in the same active record, with no hidden alias, seek or concurrent
mutation changing the record, that record must contain at least 136 bytes.
The later calls can add more. These assumptions are necessary: this is not a
recorded execution or an unconditional minimum for a failed write.

The surrounding routine `0x0040b4d0` initializes an `0x0402` record with
second selector zero and writes the dword `4` at `0x0040b57b`, checking that
write's return. Later, at `0x0040ba8e`, it passes the same local writer to a
virtual slot `+0x34`. The table beginning at `0x004754ec` contains
`0x0040dd30` in that slot; this is a possible dispatch when the receiver uses
that table, not proof that it does so at runtime. The initializer takes its
third selector from current writer state; the gate's third selector and
unmodified file identity are not established here.

The [other `0x0102` reader](srsc-0102-runtime.md) checks a same-file
`(0x0402, 0, 0)` gate for `0x0102` and begins with a length-prefixed field,
unlike the fixed-width write sequence above. A hash-checked comparison of 178
inventoried US SRSC files found 4,203 `0x0102` records in 39 files: 136 are
shorter than 136 bytes, 13 equal it, and 4,054 are longer. Every one of those
records has exactly one same-file `(0x0402, 0, 0)` gate whose first dword is
`0x0102`. Under the stated successful-write and unchanged-record assumptions,
the 136 shorter records cannot be complete output of this writer sequence.
The others are not thereby shown compatible. The distinct gate values and
field sequences caution against using this writer as a description of the
reader's opaque tail; alternative versions, paths, aliases, and producer
identity remain open.

The measurement validates selected payload bounds and hashes each inventoried
file before reading; gate categories and size boundaries have synthetic tests.
It reports aggregate counts without copying sample payloads.

## Reproduction

```sh
sha256sum research/binaries/us/Drakan.exe
objdump --version | head -n 1
objdump -d -Mintel --start-address=0x441e20 --stop-address=0x441e45 research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x45f5d0 --stop-address=0x45f61f research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x45f66c --stop-address=0x45f6bb research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x40b4d0 --stop-address=0x40b53c research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x40b9f2 --stop-address=0x40bacb research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x40e150 --stop-address=0x40e2f3 research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x4315e0 --stop-address=0x431601 research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x45f5d0 --stop-address=0x45f5f8 research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x45f600 --stop-address=0x45f6bb research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x45f750 --stop-address=0x45f796 research/binaries/us/Drakan.exe
objdump -d -Mintel research/binaries/us/Drakan.exe | rg 'call[[:space:]]+0x45f5d0'
objdump -d -Mintel research/binaries/us/Drakan.exe | rg 'call[[:space:]]+0x45f4d0'
objdump -d -Mintel research/binaries/us/Drakan.exe | rg 'call[[:space:]]+0x45f600' | wc -l
objdump -d -Mintel --start-address=0x40dd30 --stop-address=0x40de52 research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x40b53c --stop-address=0x40b591 research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x40ba61 --stop-address=0x40ba9d research/binaries/us/Drakan.exe
objdump -s --start-address=0x47551c --stop-address=0x475524 research/binaries/us/Drakan.exe
python3 tools/research/measure_0102_writer_layout.py research/installed/us research/exports/srsc-records/us.json
python3 -m unittest discover -s tools/research -p 'test_measure_0102_writer_layout.py' -v
```

The executable remains a private user-owned input. The mode-2 writer can
create or replace files; the commands above only disassemble it.
The read-only Ghidra invocation is in the reproduction section of
[lookup order](srsc-lookup-order.md#reproduction).
