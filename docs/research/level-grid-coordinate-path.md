# Level grid coordinate construction on a drawing path

**Date:** 2026-10-17. **Input:** unpatched US retail `Drakan.exe`, SHA-256
`23630f48e20e8a9f42026501165ae1df407cfcee545a784ec930a4c25ee70648`,
and 23 installed-US level files verified against their private inventory hashes.
**Method:** Ghidra 12.1.4, disposable `Disposable_Drakan` project, read-only
`-process -noanalysis`, `TraceLevelGridCoordinates.java`, private run
`level-grid-coordinates-jZ0EDgVp`; independently checked with GNU objdump
2.45.1, raw constant bytes, Python 3.14.7 and the C++ inspector. The Ghidra
import reports the same executable hash. No game was run. **Confidence:** high
for the specific instruction path and measured bytes; axes, units, runtime
adjustments, visibility, final geometry, other paths and editions are not
established.

## Observed

The `(1,0,0)` first loop reads seven dwords per entry. Its second and third
values become the grid dimensions; the fifth and sixth are loaded as signed
integers and multiplied by the float at `0x00475600`, whose bytes `00 00 00
45` encode 2048.0. The seventh dword is loaded as a float. The results are
stored at runtime offsets `+4`, `+0xc`, and `+8` respectively
(`0x00421d7a`–`0x00421e29`). This assumes the successful loader path; unusual
floating-point bit patterns and arithmetic remain subject to runtime behavior.

The following decoded block contains `(width + 1) * (height + 1)` four-byte
grid items in file order. The loader copies each first 16-bit word and stores
`2 * unsigned(second word) - 65536` as a float (`0x004223c5`–`0x00422417`).
In the selected draw routine, a grid pointer is computed with row stride
`width + 1` and the first coordinate varies along that row
(`0x00440459`–`0x004404a2`). The first coordinate begins from the fifth-dword
float and increases by 2048.0 for each grid point (`0x004407d9`–`0x004407ef`).
The second coordinate begins from the sixth-dword float and increases by
2048.0 per row (`0x004403a3`–`0x004403c7`, `0x00440c5e`–`0x00440c85`).
Thus, before subsequent operations and runtime float rounding, a candidate
for point `(column, row)` is:

```text
first  = (signed fifth dword + column) * 2048
middle = float represented by seventh dword + (2 * second grid word - 65536)
second = (signed sixth dword + row) * 2048
```

At `0x004404b4`–`0x004404ba`, bit `0x0100` of the first grid word skips
processing on this path. Otherwise the word's low byte selects a runtime entry;
if that entry's bit 0 is set, its float at `+4` is added to the middle value
(`0x004404c0`–`0x004404dd`). Further transforms, clipping, rendering state and
cell logic follow. These observations do not establish universal coordinates,
mesh topology, which points are visible, axes, physical units or pixel output.
The nominal integer extents printed by the inspector omit float rounding and
runtime offsets; they are not a promise of final world bounds.

## Measured US sample

The independent decoder scanned **23/23** hash-verified level files, comprising
**4,445** entries and **628,856** grid points. Bit `0x0100` is set in
**173,007** first grid words. None of the 4,445 seventh-dword bit patterns has
an IEEE-754 binary32 exponent of all ones (a sample property, not an input
requirement). The aggregated nominal integer extents are `0..1036288` for the
first component and `0..1032192` for the second. These global ranges combine
separate levels and have no claim to represent one scene.

The independent script compared first, middle and last entry summaries for
each file after deduplication: **67** entry comparisons matched the C++
inspector. Every entry and grid point was independently decoded for the
aggregate measurement; only these selected entries were compared with the
inspector. The inspector preserves raw base bits and reports bit counts and
nominal integer ranges without interpreting geometry or applying the float base.
See [ADR 0014](../decisions/0014-level-grid-diagnostic.md).

## Reproduction

```sh
sha256sum research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x421d69 --stop-address=0x421e5e research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x4223c5 --stop-address=0x422484 research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x4403a3 --stop-address=0x4404e0 research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x4407d9 --stop-address=0x4407f5 research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x440c5e --stop-address=0x440c8b research/binaries/us/Drakan.exe
objdump -s --start-address=0x475600 --stop-address=0x475604 research/binaries/us/Drakan.exe
python3 tools/research/verify_level_grid.py research/installed/us research/exports/asset-inventory/us.json --inspector build/debug/dragonrider_inspect
python3 -m unittest discover -s tools/research -p 'test_verify_level_grid.py' -v
```

For Ghidra, use the disposable-project procedure in
[the block trace](level-0001-blocks.md), substitute `TraceLevelGridCoordinates.java`
and use fresh logs. Close any GUI using the project and serialize access.
