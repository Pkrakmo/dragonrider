# Level `(1,0,0)` discriminator and decoded-block shape census

**Date:** 2026-10-24. **Input:** the unpatched US retail executable, SHA-256
`23630f48e20e8a9f42026501165ae1df407cfcee545a784ec930a4c25ee70648`, and
the 23 installed-US `.lvl` files selected from the private, hash-checked SRSC
inventory. **Method:** Python 3.14.7 ran
`tools/research/measure_level_discriminator_shapes.py` over immutable,
size-and-SHA-256-verified file bytes. It selected exactly one `(1,0,0)` record
per `.lvl`, rejected table overlap, and decoded only the already traced prefix:
the second and third initial dwords and the fourth dword used as the draw/query
discriminator. It printed aggregates only. No Ghidra project was opened and no
game code ran.

## Observed

All 4,445 entries have nonzero measured dimensions. The aggregate shapes,
grouped by the raw fourth initial dword, were:

| Raw discriminator | Entries | Grid items | 26-byte cell items | Maximum width | Maximum height | Zero-area entries |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 0 | 2,523 | 396,527 | 345,364 | 200 | 173 | 0 |
| 1 | 1,413 | 128,938 | 106,128 | 38 | 40 | 0 |
| 2 | 509 | 103,391 | 91,299 | 51 | 42 | 0 |

The totals are consistent with the prior all-entry measurements: 628,856 grid
items and 542,791 cells. The prefix decoder left 2,019,088 bytes unparsed
after the measured prefix across the selected record payloads; that number is
not a format-level trailing-byte assertion.

## Inferred

Within this installed-US sample, discriminator `2` is not a zero-dimension or
cell-free exceptional-block category. Its largest measured dimensions are
smaller than the largest discriminator-0 dimensions, but this aggregate does
not establish a size limit, a semantic class, draw visibility, or the cause of
the static draw-chain ordering.

## Unknown

The units and signs of the dimensions, remaining entry fields, grid/cell
meaning, runtime reachability, discriminator semantics, other editions, and
unextracted or runtime-created files remain unknown.

## Reproduction and checks

```sh
sha256sum research/binaries/us/Drakan.exe
python3 -m unittest discover -s tools/research \
  -p 'test_measure_level_discriminator_shapes.py' -v
python3 tools/research/measure_level_discriminator_shapes.py \
  research/installed/us research/exports/srsc-records/us.json
```

The focused synthetic suite covers normal aggregation, every shorter structural
prefix, a dimension-limit rejection, and a selected payload overlapping its
SRSC table. In this run it passed 2/2 tests. The private files remain excluded
from version control.
