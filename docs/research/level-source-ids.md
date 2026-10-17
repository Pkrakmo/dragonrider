# Level directory values and cell source IDs

**Date:** 2026-10-17. **Input:** unpatched US retail `Drakan.exe`, SHA-256
`23630f48e20e8a9f42026501165ae1df407cfcee545a784ec930a4c25ee70648`,
and installed-US level files verified against their private inventory hashes.
**Method:** Ghidra 12.1.4, disposable project, read-only `-process -noanalysis`,
`TraceLevelSources.java`, private run `level-sources-tsIeCQQz`; corroborated
with GNU objdump 2.45.1 and Python 3.14.7. The imported executable reports the
same hash. **Confidence:** high for the traced branches and sample counts;
actual runtime state, other editions and path resolution are unverified. No
game was run.

## Observed

At `0x004370e8`–`0x00437136`, the level loader reads a directory entry's
32-bit value and its length-prefixed string, constructs a string, and passes
the constructed string and value to `0x0041e800`. That manager first invokes
a lookup with the string. If it finds an existing object, it increments an
object field and returns the existing object; the entry value does not replace
that object's ID on this branch. Otherwise, when the supplied value is zero,
the manager takes and advances its next-ID counter. With a nonzero value, it
uses that value, advancing the counter when the signed comparison warrants it.
It checks the chosen value against existing objects' `+0x114` fields and
returns null on a collision. On the new-object path it stores the chosen value
at `+0x114` (`0x0041e800`–`0x0041e904`). Other runtime state and earlier
sources can therefore affect this sequence.

On the selected cell path, a nonnegative dword can reach `0x00435840` through
intermediate collections and caches. At `0x0043586a`–`0x0043587e`, the loader
compares its high 16 bits to source objects' `+0x114` field. After a successful
source selection and conditional open, it requests selector `0x0040` with
the value passed for its other selector (`0x004358a7`–`0x004358d4`); see
[cell drawing](level-cell-draw-behavior.md) and
[texture behavior](selector-0040-behavior.md). Equal cell dwords can reuse a
result, and later caching and error paths affect actual calls.

## Measured and inferred

The independently decoded `(0,0,0)` directory and `(1,0,0)` blocks in all
23 hash-verified US levels contain **164** directory entries. No entry value
is zero, exceeds 16 bits, or duplicates another value in its own directory.
Across **1,085,582** dword occurrences in 542,791 cells, **335,828** are
negative and all **749,754** nonnegative occurrences have a nonzero high
half matching exactly one explicit directory value in the same level. Twenty-two
levels contain nonnegative occurrences; one has none. Counts include both cell
fields even when equal; they are not lookup or rendered-texture counts.

The static data and traced manager support interpreting these values as
candidate source-ID associations on this selected path. They do not prove
which file was opened, that any texture selector exists, or that the manager
accepted a new object: duplicate strings, pre-existing runtime objects, zero
allocation in other files, failed opens, caches and other control flow remain
relevant. The diagnostic intentionally does not resolve file names or open
additional assets. Directory strings remain untrusted bytes.

## Reproduction

```sh
sha256sum research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x4370d8 --stop-address=0x437144 research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x41e800 --stop-address=0x41e940 research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x435840 --stop-address=0x4358e4 research/binaries/us/Drakan.exe
python3 tools/research/measure_level_source_ids.py research/installed/us research/exports/asset-inventory/us.json --inspector build/debug/dragonrider_inspect
python3 -m unittest discover -s tools/research -p 'test_measure_level*.py' -v
```

For Ghidra, use the disposable-project procedure in
[the block trace](level-0001-blocks.md), substitute `TraceLevelSources.java`,
and use fresh logs. Serialize access and close any GUI using the project.
The scan's inventory is private and identifies the exact sampled file hashes;
its aggregate results do not establish complete media coverage.
