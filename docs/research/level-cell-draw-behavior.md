# Level cell fields and drawing path

**Date:** 2026-10-17. **Input:** unpatched US retail `Drakan.exe`, SHA-256
`23630f48e20e8a9f42026501165ae1df407cfcee545a784ec930a4c25ee70648`,
and hash-verified installed-US levels. **Method:** Ghidra 12.1.4 disposable
project, read-only `-process -noanalysis`, bounded script
`TraceLevelCellDraw.java`, private run `level-cell-draw-gbd5GxRU`; independently
checked with GNU objdump 2.45.1 and Python 3.14.7 byte measurements. The Ghidra
import reports the same hash. **Confidence:** high for the selected static
path and the sampled field counts; runtime state, visual output, other paths
and editions remain unverified. No game was run.

## Observed

The [block trace](level-0001-blocks.md) establishes a decoded sequence of
four-byte grid items followed by `a * b` 26-byte cell items. At
`0x00422484`–`0x00422543`, the loader consumes each 26-byte cell and fills
a 22-byte runtime item. The offset map below describes this path only:

| Decoded cell offset | Observed use |
| --- | --- |
| `+0` | A 16-bit word copied to runtime `+0`. |
| `+2`, `+6` | Two signed 32-bit values. A negative value contributes its low 16 bits; a nonnegative value is passed to `0x004234c0` to obtain a runtime 16-bit value. Equal inputs reuse the first result. |
| `+10`, `+12`, `+14`, `+16` | Four 16-bit values copied to runtime `+6`, `+8`, `+10`, `+12`. |
| `+18`, `+20`, `+22`, `+24` | Four 16-bit values subtracted from `0xffff` modulo 16 bits and stored at runtime `+14`, `+16`, `+18`, `+20`. |

Function `0x004234c0` searches a runtime collection and, if necessary, passes
the dword to `0x00435800`. That function first checks a cache by full value;
on a miss, it calls `0x00435840`, the previously traced texture loader. The
loader compares the high 16 bits with a runtime source identifier, conditionally
opens the source using path-builder index 3, and searches for selector
`0x0040` using the low 16 bits. See the
[texture trace](selector-0040-behavior.md) and
[path-builder trace](loader-callers.md). Failure can yield a sentinel and
the drawing path includes further tests. This establishes a conditional
connection to texture records, not a safe file-path policy or a general
resolution of every cell: source selection depends on runtime state.

In function `0x0043fe40`, the drawing path calculates an address in the
runtime 22-byte array using the first dimension as row stride
(`0x00440805`–`0x00440828`). It prepares four neighboring transformed point
pointers (`0x0044087b`–`0x00440898`). Bit 0 of the copied cell word affects
selection/order of those pointers, with a separate branch for runtime mode 1
(`0x004408b0`–`0x00440940`). Bit 1 participates in a four-pointer path when
additional clipping/state conditions pass (`0x00440943`–`0x00440a29`).
Otherwise the path prepares groups of three pointers and calls a clipping
function before conditional submission (`0x00440a33`–`0x00440b24` and
`0x00440b29`–`0x00440c20`). Other gates, runtime modes, sentinel values and
alternate calls matter; these bits alone do not predict what is drawn.

On these paths, values from the two groups of four runtime words are multiplied
by a float and written to per-point fields. The three-point path uses the
constant at `0x00475b5c`, bytes `80 00 80 37` (approximately `1/65535`); the
four-point path uses `0x00475b9c`, bytes `00 00 80 37` (exactly `1/65536`).
The previous version of this note incorrectly reported those constants as
identical; the correction was checked against raw PE bytes on 2026-10-18.
The resulting values are consistent
with texture coordinates, but the complete texture association, coordinate
orientation, clipping, winding and output are not yet established. The
submission function copies 32 bytes per supplied point and calls a device
vtable entry with primitive argument 6 (`0x0043b15b`–`0x0043b1a6`).

## Measured US samples

The independent Python decoder and C++ inspector agreed per record for all
23 hash-verified level files. Across **542,791** decoded cells, bit 0 is set in
**374,452**, bit 1 in **85,546**, the signed dword at `+2` is negative in
**167,836**, and the signed dword at `+6` is negative in **167,992**. Counts
may overlap. These are properties of the selected file bytes, not frequencies
of visible triangles, texture assignments, or a format requirement. The scan
validates complete zlib streams and lengths; it does not simulate lookup or
rendering. The inspector reports the same measurements with bounded memory;
see [ADR 0011](../decisions/0011-level-block-inspection.md).

## Reproduction

```sh
sha256sum research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x422484 --stop-address=0x422549 research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x440805 --stop-address=0x440c49 research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x43b15b --stop-address=0x43b1aa research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x4234c0 --stop-address=0x423580 research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x435800 --stop-address=0x4358e4 research/binaries/us/Drakan.exe
objdump -s --start-address=0x475b58 --stop-address=0x475ba4 research/binaries/us/Drakan.exe
python3 tools/research/measure_level_blocks.py research/installed/us research/exports/asset-inventory/us.json --inspector build/debug/dragonrider_inspect
python3 -m unittest discover -s tools/research -p 'test_measure_level*.py' -v
```

For Ghidra, use the disposable-project procedure in
[the block trace](level-0001-blocks.md), substitute `TraceLevelCellDraw.java`,
and use fresh log names. Close the GUI and serialize access to that project.
The report reflects existing analysis and is not proof of complete references.
