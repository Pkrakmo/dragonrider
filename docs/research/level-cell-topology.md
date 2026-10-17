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
python3 tools/research/verify_level_cells.py research/installed/us research/exports/asset-inventory/us.json --inspector build/debug/dragonrider_inspect
python3 tools/research/verify_level_cells.py research/installed/us research/exports/asset-inventory/us.json --inspector build/release/dragonrider_inspect
```

For Ghidra, follow the disposable-project procedure in [the block trace](level-0001-blocks.md),
substitute `TraceLevelCellTopology.java`, use fresh private logs, and serialize
project access. See [ADR 0015](../decisions/0015-level-cell-candidates.md).
