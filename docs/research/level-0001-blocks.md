# Level selector `(1,0,0)` blocks

**Date:** 2026-10-17. **Input:** unpatched US retail `Drakan.exe`, SHA-256
`23630f48e20e8a9f42026501165ae1df407cfcee545a784ec930a4c25ee70648`;
US installed level files verified against private inventory hashes. **Method:**
GNU objdump 2.45.1, Python 3.14.7 with zlib, and the independent C++ inspector.
No Ghidra project was accessed in this investigation. **Confidence:** high
for the bounded instructions and measured streams; other paths and editions
remain unverified. No game was run.

## Observed

After the [first loop](level-0001-prefix.md), `0x004221f7` reads a dword.
At `0x00422260` the loader reads a dword for each entry and allocates
`4 * (a + 1) * (b + 1) + 26 * a * b` bytes, where `a` and `b` are the
second and third dwords of that entry's first loop. The allocation arithmetic
uses 32-bit operations; DragonRider checks overflow and imposes limits.

If the first dword is signed-positive, the loader reads the declared number
of bytes and calls the decompression routine at `0x00462a00`, then calls
`0x00462820` before the next entry. The initialization path passes 15 at
`0x004629ee`, and the decoder checks deflate header properties; related
stream evidence is in [texture pipeline behavior](texture-pipeline-behavior.md).
If the dword is nonpositive, `0x004223ae` requests the derived allocation size
directly; the per-entry dword read earlier is not used for that raw read.
The original code does not uniformly check return values in this path.

The decoded data is traversed at `0x004223c5`–`0x00422543` as
`(a + 1) * (b + 1)` four-byte items followed by `a * b` 26-byte items.
The first group's second little-endian word is transformed by `2 * word - 65536`
and used in runtime floating-point calculations, while fields in the second
group feed additional lookups and transformations. These operations suggest
spatial data but do not establish a complete geometry or rendering format.

## Follow-up: grid values and spatial bounds

On 2026-10-17 Ghidra 12.1.4 processed the existing `Drakan.exe` import in the
dedicated disposable `Disposable_Drakan` project with `-readOnly -noanalysis`.
Its reported import hash matched the executable hash above. The bounded
`TraceLevelBlockConsumers.java` report in private run `level-consumers-S01gvJc9`
found a direct call to `0x00422760` at `0x0044005b`, in function `0x0043fe40`.
The following observations were independently checked with objdump; the
database's analysis may have incomplete or indirect references.

- The first loop's second and third dwords are saved at runtime offsets `+0x18`
  and `+0x1c` (`0x00421d7a`–`0x00421d9e`, `0x00422749`–`0x0042274c`).
  The fifth and sixth dwords are saved at `+0x10` and `+0x14` and multiplied
  by the little-endian float 2048.0 at `0x00475600` for related floating-point
  values (`0x00421db6`–`0x00421e5b`).
- Function `0x00422760` subtracts those latter integers from an input rectangle,
  rejects non-overlap, and clamps the result to the two dimensions. Its caller
  at `0x0044005b` iterates the resulting ranges and indexes a four-byte pointer
  array using the first dimension as a row stride. This supports a spatial-grid
  interpretation on that path; it does not establish world axes or display
  orientation.
- In the decoded grid array, `0x004223fc`–`0x00422417` copies the first word
  and converts the second word by `2 * unsigned_word - 65536`; it stores the
  result as a float and updates per-object bounds. Later, at
  `0x00422454`–`0x00422476`, another value from the entry is added to those
  bounds. The full world-space interpretation of these values remains unknown.

An independently decoded, hash-verified scan and the C++ inspector agreed on
**628,856** grid items across the same 23 US levels, with a global transformed
range of **-65536 to 65534**. Both endpoints occur in this sample; this is not
proof of their meaning. The inspector reports each selected record's count and
range, excluding the following 26-byte cells. It does not resolve axes, units,
surface topology or world coordinates.

## Samples and limits

The reproducible script checks whole-file SHA-256 and table ranges, selects
exactly one `(1,0,0)` record per candidate file, and compares its independent
Python decode with the C++ inspector. All **23/23** records use storage word 1;
their **4,445/4,445** blocks are complete zlib streams with exactly the derived
decoded size and no unused input. The inspected structures end at the payload
boundary in these samples. The C++ and Python aggregate decoded-byte counts,
CRC32 values, entry counts, inner counts and trailing lengths match per record.
CRC32 comparisons do not prove visual correctness. This scan establishes no
raw-branch sample, other positive storage word, other edition, or extraction
completeness. The C++ inspection policy and explicit limits are in
[ADR 0011](../decisions/0011-level-block-inspection.md).

## Entry discriminator and draw-path routing, 2026-10-18

The first seven dwords read for each entry are stored at runtime offsets
`+0`, `+0x18`, `+0x1c`, `+0x28`, `+0x10`, `+0x14`, and `+8`, respectively
(`0x00421d69`–`0x00421e5b`). Thus the fourth dword becomes the value at
`entry + 0x28`. After the skipped length-prefixed bytes, the first of the next
six dwords contributes bit 1 to a runtime flag at `entry + 0x2c`
(`0x00421de9`–`0x00421dfd`).

In drawing function `0x0043fe40`, the code obtains an entry through the
level's 16-bit entry-index array and first calls `0x00422760` to test whether
the entry intersects the requested rectangle (`0x0044002d`–`0x00440060`).
For an intersecting entry, discriminator `entry + 0x28 == 2` selects one
list-building branch; values other than 2 select the other branch
(`0x00440068`–`0x00440084`). Both branches store the entry pointer and advance
their respective cursors. The code then checks a separate pointer at
`entry + 0x34` before continuing. This establishes conditional routing on
this drawing path, not the fields' broader names or purpose.

The two cursor chains are joined after the entry scan. At function entry, the
chain heads are zeroed; discriminator-2 entries are appended through their
`+0x30` link to the chain headed at local `-0x24`, while other values use the
chain headed at local `-0x2c` (`0x0043fff6`–`0x00440013` and
`0x00440068`–`0x00440084`). The final tail of the non-2 chain is linked to the
discriminator-2 head, and the other tail is terminated with null
(`0x004402db`–`0x004402f1`). Traversal then starts at the non-2 head and follows
each entry's `+0x30` pointer until null (`0x00440300`–`0x0044030e`,
`0x00440c8e`–`0x00440c99`). Thus the observed discriminator-2 entries are
placed after non-2 entries in this combined scan chain. This establishes
processing order on this path; it does not identify the discriminator's
meaning or prove a rendering effect.

The discriminator also participates in the level-query helper at
`0x00420e10`. After selecting an entry through the level's 16-bit index array
and computing entry-relative grid coordinates, query flag bit `0x10` causes
discriminator 2 to reject that candidate before the bounds and cell-value
checks (`0x0042103a`–`0x00421079`). In later branches, the helper reads the
same dword and applies distinct rejection conditions to value 1 versus other
values using query flag bits `0x08`, `0x04` and `0x20`
(`0x004212d8`–`0x00421355`). The helper also evaluates transformed grid
values and cell corners before returning; the broader caller intent and the
meanings of these query flags are not established. This is a second observed
consumer of the discriminator, and shows that it affects candidate acceptance
in at least one query mode in addition to draw-chain ordering. The call from
`0x0043fe40` supplies literal flag value 4 (`0x0043fe91`–`0x0043fef2`), so its
query call does not enable the bit-`0x10` rejection branch.

### Bounded direct-caller flag sweep, 2026-10-23

GNU objdump 2.45.1-5.fc43 against the pinned US executable found 23 direct
relative calls to `0x00420e10`: 17 supply literal flag `5`, five supply
literal `4`, and one forwards a caller-derived value at `0x00420d93`. The
apparent `[esp+0x2c]` source at `0x0044cb63` is its enclosing function's fifth
argument; its sole direct caller supplies literal `5`. The literal categories
set bit `0x04`, but neither sets `0x08`, `0x10`, or `0x20`. The bounded
windows, full call-address list, hash, and reproduction procedure are in
[the direct-caller report](level-0001-query-callers-2026-10-23.md).

This is static direct-call evidence only. It does not classify the remaining
dynamic flag, find indirect or virtual callers, establish reachability, assign
a meaning to the flags, or establish the discriminator's runtime role.

## Per-entry cell pointer grid, 2026-10-18

The pointer checked at `entry + 0x34` is used as a runtime cell-head array on
this path. Helper `0x00422a70` lazily allocates `4 * entry[0x18] * entry[0x1c]`
bytes when that field is null, stores the result back at `+0x34`, then selects
a four-byte slot using `entry[0x18] * third_argument + second_argument`
(`0x00422a7c`–`0x00422ab7`). The helper links a node into that slot: the node's
first dword receives the previous slot head, its second dword receives the
first argument, and the slot is replaced by the new node
(`0x00422adb`–`0x00422ae6`, with the expanded-pool path at
`0x00422c19`–`0x00422c38`). Several retail call sites reach this helper,
including `0x0041f69e`, `0x0041f6b1`, `0x0041f846`, `0x004206c0` and
`0x0042072b`; their distinct callers' selection rules are not established
here.

In `0x0043fe40`, after the clipped rectangle selects a starting slot from the
`+0x34` grid, the inner loops advance by four bytes across grid slots. Each
non-null slot is traversed as a linked chain: the code reads the node's second
dword as an object pointer and follows the node's first dword to the next node
(`0x004400d0`–`0x00440149`). It updates per-object state and conditionally
calls `0x00445bd0`. The cell grid therefore stores runtime object-list heads;
it is not the serialized `(1,0,0)` block itself. The `+0x34` pointer is
released and reset in cleanup paths (`0x0042260e`–`0x00422628`,
`0x00422d50`–`0x00422d82`). Exact object classes, membership rules and the
rendering consequences remain unknown.

## Runtime population callers, 2026-10-18

The callers show the grid is populated from runtime object pointers, rather
than decoded directly from the level block. In the routine around
`0x0041f550`, the code selects an entry from the level's `+0x0c` object array
using a runtime index at object `+0xac`, subtracts that entry's `+0x10` and
`+0x14` origin values, and calls `0x00422a70` with the object and the two
relative indices (`0x0041f654`–`0x0041f6b1`). A nearby branch can call
`0x00421a00` while preparing the membership update. Another path computes
indices from object coordinates and a selected entry origin, then calls the
same helper (`0x0041f7d6`–`0x0041f846`). These traces establish coordinate-like
arguments and an object pointer, not the object's class or why it belongs in
that cell.

A further cell walk around `0x00420620` obtains a runtime object through
`0x00403ad0`, computes two relative indices, and conditionally calls
`0x00422a70` to add the object or `0x00422c50` to remove it, based on a caller
flag (`0x0042065e`–`0x004206c7`, `0x00420700`–`0x00420732`). This supports a
mutable runtime cell-membership structure. It does not identify which object
families use each path, whether the lists are complete at draw time, or the
relationship between those runtime objects and serialized entry discriminator
values. No bounded static-file measurement can recover the runtime pointer
contents from these observations.

## Per-cell object update path, 2026-10-18

During the per-cell chain walk, function `0x0043fe40` reads each node's object
pointer and compares the object's dword at `+0xb8` with global
`0x00483ba0`. On a mismatch it calls `0x0040b010` and writes the current
global value back to `+0xb8`. It then checks bit 0 of the object's byte at
`+4` and requires a non-null pointer at `+0x74` before calling
`0x00445bd0` (`0x004400e0`–`0x00440123`). This is a conditional per-object
update path reached while walking the cell lists.

The routine at `0x00445bd0` clears object flag bits, calls helper
`0x004468c0` for an early status check, derives state from object and global
vectors, updates additional flags, and dispatches more routines according to
bits in the object field at `+0x8c` (`0x00445bd0`–`0x00445f4c`). Some selected
branches call additional object-processing routines, but this bounded trace
does not establish a graphics submission or tie the work to the serialized
`entry + 0x28` discriminator. The cell-list walk therefore proves that
membership gates an object update call; it does not yet prove why discriminator
2 entries are ordered last or what visual effect that ordering has.

A hash-checked measurement of the 23 US `.lvl` files found 4,445 entries:
2,523 have discriminator 0, 1,413 have 1, and 509 have 2. The low 16 bits of
the post-name dword are 0 in 4,304 entries and 2 in 141. All 141 entries with
bit 1 set have discriminator 0 or 1; all 509 discriminator-2 entries have
that bit clear. This is a sample correlation and does not show that the flag
controls routing or that any entry rendered at runtime.

The result extends the entry evidence without completing the `(1,0,0)` format:
first-dword semantics, the discriminator's general meaning, remaining entry
fields, runtime visibility, axes, units, geometry and other editions remain
unknown.

```sh
sha256sum research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x421d69 --stop-address=0x421e5d research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x421de9 --stop-address=0x421e00 research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x44002d --stop-address=0x4400b8 research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x420e10 --stop-address=0x4213ea research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x43fe91 --stop-address=0x43fef7 research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x43fff6 --stop-address=0x440013 research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x4402db --stop-address=0x4402f7 research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x440300 --stop-address=0x44030e research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x440c8e --stop-address=0x440c99 research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x422a70 --stop-address=0x422ae8 research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x422c19 --stop-address=0x422c3e research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x440086 --stop-address=0x440149 research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x42260e --stop-address=0x42262b research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x422d50 --stop-address=0x422d8b research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x41f550 --stop-address=0x41f6b9 research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x41f7d6 --stop-address=0x41f846 research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x42065e --stop-address=0x4206d2 research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x420700 --stop-address=0x420737 research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x4400e0 --stop-address=0x440137 research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x445bd0 --stop-address=0x445f4c research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x422760 --stop-address=0x4227fd research/binaries/us/Drakan.exe
python3 tools/research/measure_level_entry_modes.py research/installed/us research/exports/srsc-records/us.json
```

## Reproduction

```sh
sha256sum research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x4221f0 --stop-address=0x4225c0 research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x4629e0 --stop-address=0x462a98 research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x422760 --stop-address=0x4227fd research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x44002d --stop-address=0x44015f research/binaries/us/Drakan.exe
objdump -s --start-address=0x475600 --stop-address=0x475608 research/binaries/us/Drakan.exe
python3 tools/research/measure_level_blocks.py research/installed/us research/exports/asset-inventory/us.json --inspector build/debug/dragonrider_inspect
python3 -m unittest discover -s tools/research -p 'test_measure_level*.py' -v
```

For the Ghidra report, first create a separate disposable import as described in
[Ghidra guidance](../GHIDRA.md), close any GUI using it, and serialize access.
With `dr_workspace` still identifying that workspace and `GHIDRA_HOME` set:

```sh
env XDG_CONFIG_HOME="$dr_workspace/config" XDG_CACHE_HOME="$dr_workspace/cache" \
  JAVA_TOOL_OPTIONS="-Duser.home=$dr_workspace" \
  "$GHIDRA_HOME/support/analyzeHeadless" "$dr_workspace/project" Disposable_Drakan \
  -process Drakan.exe -readOnly -noanalysis -scriptPath "$PWD/tools/ghidra/scripts" \
  -postScript TraceLevelBlockConsumers.java \
  -log "$dr_workspace/level-consumers.log" -scriptlog "$dr_workspace/level-consumers-script.log"
```

Use fresh log names for repeated runs; the report contains derived private
research. `-noanalysis` means the direct-reference list reflects only the
existing analysis state and does not establish completeness.
