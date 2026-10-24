# Level cell candidate point ordering

**Input and method:** US retail `Drakan.exe`, SHA-256
`23630f48e20e8a9f42026501165ae1df407cfcee545a784ec930a4c25ee70648`;
Ghidra 12.1.4, disposable imported project, read-only `-noanalysis` bounded
instruction trace `TraceLevelCellTopology.java`, private run
`level-cell-topology-vA4i18ab`; corroborated with bounded `objdump` disassembly.
Confidence is limited to the observed path and this executable. Naming the
points A–D and interpreting them as neighboring grid positions is an inference
from the pointer arithmetic, row-buffer rotation, and preceding grid trace.

## Observed and inferred

The loader at `0x00422484`–`0x00422543` reads the 26-byte cell: a flags word,
two dwords and eight more words. On the selected drawing path around
`0x00440805`–`0x00440c85`, each runtime cell uses a 22-byte stride and the
point pointer array is populated from two adjacent row buffers. For a cell at
column `x`, row `y`, define A `(x,y)`, B `(x+1,y)`, C `(x+1,y+1)`, and D
`(x,y+1)`; grid indices are row-major with stride `width+1`. The row-buffer
advance at `0x00440c4c` supports this interpretation. In the ordinary
triangle branch the instructions select these cyclic sequences before further
processing:

| Runtime selection | Flag bit 0 | Pointer array | First candidate | Second candidate |
| --- | --- | --- | --- | --- |
| Normal | 0 | A B C D | D A B | B C D |
| Normal | 1 | A B C D | C D A | A B C |
| Mode 1 | 0 | B A D C | B A D | D C B |
| Mode 1 | 1 | B A D C | A D C | C B A |

The two groups of four cell words are indexed by the selected pointer-array
position; on the traced path one group is transformed by `65535 - word`.
These observations support a diagonal-selection interpretation for bit 0 and
an ordering change in mode 1. The labels do not establish geographic axes,
world handedness or texture semantics.

**Unknown:** The candidate sequences do not prove that either triangle is
rendered. Clipping and visibility, sentinel values, texture lookups, culling,
flag bit 1 and its four-point path, and a separate mode-2 path can change or
bypass processing. Runtime mode is not derived from the file by this diagnostic.
There is no claim that these candidates form a complete or visually correct
mesh. Callback data are provisional until the entire parse succeeds.

## Four-point word association and mode 2

On 2026-10-18 the same executable was rechecked with GNU objdump 2.45.1,
without opening a Ghidra project. If bit 1 is set and the OR of the four
point-state dwords is zero, the code at `0x00440943`–`0x004409a9` copies the
four point pointers in point-array order and associates slot `i` with runtime
words at cell offsets `+6+2*i` and `+14+2*i`. The loader already copied the
first four source words and transformed the other four by `65535 - word`;
see the [cell draw trace](level-cell-draw-behavior.md). This association is
also used on the selected three-point branch, where the selected corner index
chooses the corresponding word slot. The code later applies additional
conditions before submission, so flag bit 1 alone cannot determine whether a
four-point primitive is submitted.

The four-point path uses `0x00475b9c` (`00 00 80 37`, exactly 1/65536),
while the ordinary three-point path uses `0x00475b5c` (`80 00 80 37`,
approximately 1/65535). An earlier note incorrectly stated both constants
were the latter; the draw trace has been corrected. The inspector reports
integer values only, without applying a float scale or asserting final UVs.

An independent Python decoder scanned the same 23 hash-verified levels and
542,791 cells, selecting the first cell for each observed combination of the
two low flag bits per file. Across both explicit orientations, 116 selected
comparisons matched each GCC debug and release inspector on 2026-10-18. This
verifies selected byte associations and calculations, not the runtime gates.

At `0x004408f5`–`0x0044093b`, mode 2 and a runtime flag can select the
separate `0x0043fbb0` routine. There the first and second groups use the
same cyclic slot selection, with extra floating-point calculations involving
runtime values and different field writes. When that runtime flag is absent,
the caller continues through the ordinary branch with a mode-dependent state.
This does not establish the mode's visual behavior, timing, texture mapping,
or that normal-mode candidate output represents mode 2. The explicit
inspector orientations remain normal and mode 1.

## Measurements and reproduction

The independent decoder scanned 23/23 SHA-256-verified US level files and
542,791 cells. Counts for flags bits `1:0` as values 0, 1, 2 and 3 were
162,821, 294,424, 5,518 and 80,028 respectively. In each file the first
observed cell of each bit-0 value was checked in both modes: 92 selected
comparisons matched each of the GCC debug and release inspectors. These checks
validate raw field extraction and the described calculations on samples; they
do not independently establish the runtime branch's interpretation. Other
editions and Windows are untested.

```sh
sha256sum research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x422484 --stop-address=0x422544 research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x440805 --stop-address=0x440c86 research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x43fbb0 --stop-address=0x43fe40 research/binaries/us/Drakan.exe
objdump -s --start-address=0x475b5c --stop-address=0x475b60 research/binaries/us/Drakan.exe
objdump -s --start-address=0x475b9c --stop-address=0x475ba0 research/binaries/us/Drakan.exe
python3 tools/research/verify_level_cells.py research/installed/us research/exports/asset-inventory/us.json --inspector build/debug/dragonrider_inspect
python3 tools/research/verify_level_cells.py research/installed/us research/exports/asset-inventory/us.json --inspector build/release/dragonrider_inspect
```

## Verified snapshot comparison recheck, 2026-10-23

The cell verifier now validates each inventory path, size, and SHA-256, parses
the selected cells from those bytes, then gives the inspector a temporary
snapshot of the same bytes. Debug and release builds each matched 116 selected
comparisons across all 23 US levels while reproducing 542,791 cells. The
selected normal and mode-1 outputs remain candidate topologies as described
above; this change only makes comparison inputs reproducible.

For Ghidra, follow the disposable-project procedure in [the block trace](level-0001-blocks.md),
substitute `TraceLevelCellTopology.java`, use fresh private logs, and serialize
project access. See [ADR 0015](../decisions/0015-level-cell-candidates.md).
