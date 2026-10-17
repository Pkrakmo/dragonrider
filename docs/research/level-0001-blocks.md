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
