# Separate `0x0302` full-tuple consumer

**Date and input:** 2026-10-18, unpatched US retail `Drakan.exe`, SHA-256
`23630f48e20e8a9f42026501165ae1df407cfcee545a784ec930a4c25ee70648`.
**Method:** GNU objdump 2.45.1-5.fc43 static disassembly, corroborated by
Ghidra 12.1.4 read-only `-noanalysis` on a disposable project using
`TraceSrscIndirectLookup.java` (private run `dragonrider-r1-tuple-ydrkbGMf`),
plus the existing hash-checked installed-US measurement described below. No
retail executable was run and no persistent Ghidra project was opened.
**Confidence:** high for these instruction
paths and aggregate sample counts, conditional for any connection between them.

## Observed

- At `0x004312d0`, a routine accepts a loader as an argument. It clears `ebp`,
  pushes two zero arguments and `0x0302`, and calls the three-word selection
  routine `0x0045f0d0` at `0x004312fc`. The requested tuple is
  `(0x0302, 0, 0)`. On a nonzero return it branches to `0x004315bc`, where
  it returns zero without the selected-record processing.
- On the successful selection branch, `0x0043130a`–`0x00431323` request
  16 bytes into the receiving object's `+0x344` region, and
  `0x00431333`–`0x0043133a` request a further four bytes. Subsequent code
  uses the four-byte value as a loop bound. The routine does not check the
  shown read returns before proceeding; this description assumes successful
  reads and does not assert malformed-input behavior.
- The separate routine at `0x004315e0` calls the record initializer
  `0x0045f600` with first and second words `(0x0302, 0)` at `0x004315eb`–
  `0x004315f4`. After success it requests writing 16 bytes from its receiver's
  `+0x344` region and then four bytes from its `+0x17c` field. The initializer
  takes the third word from the writer's existing `+8` state, so the writer
  produces `(0x0302, 0, 0)` only if that state is zero. The read and write
  routines are statically consistent with a related payload layout; neither
  has been executed or proven to use the same runtime object or file.

## Sample comparison and limits

The prior [lookup-order analysis](srsc-lookup-order.md#follow-up-two-word-0x0302-lookup)
traces a distinct two-word `0x0302` selection path and explains the comparison
model. Re-running its measurement rechecked the hashes of 178 installed-US
files: 1,561 `0x0302` records occur in 19 files and all have nonzero third
words. Thus none of those observed records has the full tuple requested at
`0x004312fc`. A lookup against an unchanged, successfully loaded sampled
table cannot select one of those records with this tuple. This is a static
comparison, not evidence that the routine is invoked against these files, or
that it fails in an observed game run. Other editions, files and runtime table
states are outside the measurement. Neither this comparison nor the writer
path identifies what the third selector means.

The caller's first request is `(0x0402, 0, 0)`, before the later
`(0x0302, 0, 0)` request. A new hash-checked measurement of 178 installed-US
files found that all 19 files containing any `0x0302` record also contain the
first tuple; 157 other files contain the `0x0402` tuple without `0x0302`, and
two contain neither. None of the 178 files contains the exact
`(0x0302, 0, 0)` tuple. Thus those 19 files structurally satisfy the first
selection condition but cannot satisfy the later full-tuple selection on an
unchanged table. This does not establish that the caller is invoked for any
of those files or exclude table mutation, another edition, or an unmeasured
input.

## Caller context

A later Ghidra 12.1.4 read-only run (`dragonrider-r1-caller-UpoPKm75`) and
GNU objdump identify both direct calls at `0x0040bf6f` and `0x0040cb74` as
belonging to the function at `0x0040bf30`. Its entry constructs a stack-local
loader from a supplied path and opens it at `0x0040bf6f`. On the successful
open path it first requests `(0x0402, 0, 0)` and returns early on selection
failure. Later, at `0x0040cb74`, it passes the stack-local loader to the
`(0x0302, 0, 0)` reader; it does not inspect that reader's return before
continuing to another consumer and closing the loader. Numerous intervening
operations and branches are not fully characterized. In particular, this
static relationship does not identify the supplied path, prove the loader's
state at the later call, or connect this path to a specific installed file.

## Indirect dispatch context

A further bounded scan of the hash-identified executable found no direct
relative call to `0x0040bf30`. The word `0x0040bf30` occurs in `.rdata` at
`0x00475514`, as the entry at offset `+0x28` from `0x004754ec`. At
`0x0040a1a7`, an object-initialization path stores `0x004754ec` at the
object's first dword. This supports interpreting `0x0040bf30` as a method
reachable through that object's function table; it does not prove the
initialization path runs for the object used at `0x0040bf30`.

The initialization thunk at `0x004072a0` sets `ECX` to global storage
`0x00483928` and tail-jumps to the constructor at `0x0040a030`, which installs
that table. The teardown thunk at `0x004072c0` uses the same global and
tail-jumps to `0x0040a430`, which reinstalls the same table while releasing
fields. This identifies the table-bearing object as a global instance on
these paths. It does not establish that the reader at `0x0040bf30` was
invoked on that instance or which indirect callsite selects its `+0x28` slot.

The executable contains 30 disassembled indirect calls of the form
`call [register+0x28]`. The scan did not establish which receivers use the
table at `0x004754ec`, and the shown indirect callsites do not identify the
path argument supplied to `0x0040bf30`. Therefore the file path and any link
between the selected `(0x0302, 0, 0)` entry and an installed file remain
unknown. This table observation is static; the retail executable was not run.

A targeted Ghidra 12.1.4 `-readOnly -noanalysis` query of disposable project
`Disposable_Drakan` (run `dragonrider-r1-xref-scan-acNYFMGt`) corroborates the
existing database's reference records: `0x0040bf30` has one recorded
reference, a data reference from `0x00475514`; `0x004754ec` has two, from
`0x0040a1a7` and `0x0040a450`. The query found 28 recorded references to
global storage `0x00483928`; none of their containing functions includes a
decoded `CALL` instruction with a `+0x28` operand. This bounded cross-check
does not rule out a call through an alias, another object, an unanalyzed path,
or a function receiving the object indirectly. Ghidra's xrefs are from its
existing analysis database, not a fresh completeness guarantee.

One prominent `+0x28` dispatch site at `0x00412426` uses global object
`0x0048390c`, so it is possible to test this receiver's table directly.
Initialization at `0x004079a4`–`0x004079ed` allocates an object, calls
constructor `0x004387f0`, and stores its returned pointer at `0x0048390c`.
That constructor writes `0x00475aec` to the object's first dword
(`0x00438842`), whereas the table containing `0x0040bf30` begins at
`0x004754ec`. Thus this global's `+0x28` call at `0x00412426` uses a
different function table. This excludes that callsite as a direct dispatch
to `0x0040bf30`; it does not identify the reader's actual caller.

A bounded one-level direct-callee scan of those reference-owning functions
found apparent `+0x28`/`+0x30` dispatches in several callees, but their call
sites pass other receivers: `0x00407ee9` sets `ECX` to `0x0047fb20` before
calling `0x00405a60`; `0x0042d7c3` sets it to `0x00482c10` before calling
`0x00432af0`; and `0x00407ba4` loads `0x0048390c` before calling `0x00438c40`.
At `0x00440aac`, the call to `0x00447f40` receives a stack-local address in
`ECX`. These dispatches therefore do not establish use of the `0x004754ec`
table. The scan is shallow and does not trace aliases or deeper call chains.

A bounded two-edge direct-call reachability query against the same disposable
Ghidra project (`dragonrider-r1-depth-MDrwTZ6v`) found candidate indirect
calls deeper in functions associated with global-reference owners. Independent
disassembly resolves the notable candidates to other receivers: `0x004170b0`
calls `0x00432af0` with `ECX=0x00482c10`; `0x0043aea0` calls `0x0043c140`
with `ECX=[0x00483908]` and `0x0043c4b0` with the same global; and
`0x00410fd0` calls `0x00438d00` with `ECX=[0x0048390c]`. The latter object's
constructor installs `0x00475aec`, as described above. The helper
`0x0043c4b0` itself dispatches through the object at its `+4` field, whose
identity is unresolved. These paths do not establish a call through
`0x004754ec`. The Ghidra query relies on its existing function boundaries and
direct-call references, caps each root traversal at 250 functions and each
function at 2,000 instructions, and does not propagate object identity;
remaining indirect paths and aliases are unknown.

## Reproduction

With `GHIDRA_HOME` set, the GUI closed for this database, and a fresh
disposable project at `$dr_workspace/project/Disposable_Drakan` containing
the hash-verified US retail executable, run:

```sh
sha256sum research/binaries/us/Drakan.exe
objdump --version | head -n 1
objdump -d -Mintel --start-address=0x4312d0 --stop-address=0x431350 research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x431592 --stop-address=0x431630 research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x45f0d0 --stop-address=0x45f1c7 research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x45f66c --stop-address=0x45f6bb research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x40bf30 --stop-address=0x40bfd1 research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x40cb5a --stop-address=0x40cb92 research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x40a190 --stop-address=0x40a1b0 research/binaries/us/Drakan.exe
objdump -s --start-address=0x4754ec --stop-address=0x475520 research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x407290 --stop-address=0x4072ca research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x407edc --stop-address=0x407ef2 research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x42d7b6 --stop-address=0x42d7ce research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x407b98 --stop-address=0x407bab research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x440aa0 --stop-address=0x440ab3 research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x407976 --stop-address=0x4079ed research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x4387f0 --stop-address=0x438937 research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x412419 --stop-address=0x412429 research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x4170b0 --stop-address=0x41714d research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x43aea0 --stop-address=0x43af35 research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x410fd0 --stop-address=0x411041 research/binaries/us/Drakan.exe
objdump -d -Mintel research/binaries/us/Drakan.exe | rg 'call.*PTR \[[a-z]+\+0x28\]' | wc -l
XDG_CONFIG_HOME="$dr_workspace/config" XDG_CACHE_HOME="$dr_workspace/cache" JAVA_TOOL_OPTIONS="-Duser.home=$dr_workspace" \
  "$GHIDRA_HOME/support/analyzeHeadless" "$dr_workspace/project" Disposable_Drakan \
  -process Drakan.exe -readOnly -noanalysis -scriptPath "$PWD/tools/ghidra/scripts" \
  -postScript TraceR1TableRefs.java -log "$dr_workspace/r1-xrefs.log" \
  -scriptlog "$dr_workspace/r1-xrefs-script.log" > "$dr_workspace/r1-xrefs-console.log" 2>&1
python3 tools/research/measure_srsc_0302_lookup.py research/installed/us research/exports/srsc-records/us.json
python3 -m unittest discover -s tools/research -p 'test_measure_srsc_0302_lookup.py' -v
python3 tools/research/measure_srsc_0302_context.py research/installed/us research/exports/srsc-records/us.json
python3 -m unittest discover -s tools/research -p 'test_measure_srsc_0302_context.py' -v
```

The measurement emitted the counts above and both synthetic tests passed.
The input files and inventory remain private; the comparison cannot rule out
concurrent mutation between hash verification and reading.
The disposable Ghidra command is in the reproduction section of
[lookup order](srsc-lookup-order.md#reproduction); its script includes the
reader and writer windows above.
