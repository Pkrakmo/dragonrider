# Level `(1,0,0)` cell reference layout — 2026-10-25

## Provenance and scope

**Input:** US retail `Drakan.exe`, SHA-256
`23630f48e20e8a9f42026501165ae1df407cfcee545a784ec930a4c25ee70648`, plus the
installed-US asset inventory at `research/exports/asset-inventory/us.json`,
SHA-256 `e878d60f9bc3ffcee8c42ef302970d9f6676ca0ed6cb3e582cc01ddd1a543b64`.
**Method:** GNU objdump 2.45.1-5.fc43 for bounded static disassembly; Python 3.14
measurement over file-size/hash-verified `.lvl` snapshots using the existing
bounded `measure_level_blocks.py` decoder. **Confidence:** high for the
instruction mapping and the measured aggregate counts. No game execution or
visual output was used.

## Observed static mapping

The existing block trace establishes `a * b` serialized 26-byte cells after
the `(a + 1) * (b + 1)` grid words. At `0x00422489–0x00422543`, the loader
walks those cells with a 26-byte input stride and advances the output pointer
by `0x16` (22) bytes each iteration. For each cell it:

* copies the 16-bit value at serialized offset `+0` to runtime offset `+0`;
* reads 32-bit values at serialized offsets `+2` and `+6` and writes two
  16-bit lookup results at runtime offsets `+2` and `+4`;
* copies serialized 16-bit values at `+10`, `+12`, `+14`, and `+16` to runtime
  offsets `+6`, `+8`, `+10`, and `+12`;
* writes `0xffff - value` for serialized 16-bit values at `+18`, `+20`, `+22`,
  and `+24` to runtime offsets `+14`, `+16`, `+18`, and `+20`.

The shown loop consumes all 26 serialized bytes and writes a 22-byte runtime
representation. The shorter runtime stride does not imply that a serialized
field is skipped; this statement applies to the traced loader path only.

For the two dwords, the loader tests signed negativity. A negative value is
copied as its low 16 bits. A nonnegative value is passed to `0x004234c0` with
the runtime table at object offset `+0x2838`. That helper compares the value
with a field at `+4` on existing table objects; on a miss, it calls manager
routine `0x00435800` with the value and appends the returned object to the
table. If the second serialized dword equals the first, the loader reuses the
first 16-bit result; otherwise it resolves the second independently. This
shows keyed table resolution in the selected code path, but does not name the
referenced object type or the meaning of the two references.

## Measured US sample

The new aggregate-only measurement rechecked 23 inventory-listed `.lvl`
files and 542,791 cells. Their 1,085,582 reference dwords contain 1,622
distinct signed values; none is zero, and 335,828 have their high bit set.
The two dwords are equal in 521,441 cells and differ in 21,350. The aggregate
counter treats negative values returned by the decoder as evidence that the
serialized dword's high bit is set. These 335,828 values fall on the signed
negative branch in the traced code if that code receives them; this does not
prove runtime execution. The high-bit total also equals the sum of the existing
block scanner's negative `+2` and `+6` aggregates. Separately, the existing
cell verifier matched all 542,791 cell counts with both inspectors, plus 116
selected raw-cell comparisons per build; that verifier does not cross-check
every reference pair. These counts describe only the installed-US sample.
They do not prove lookup success, table uniqueness, or semantic object
relationships.

The existing decoder already rejects malformed extents and incomplete zlib
streams. The new counter validates file hashes/sizes, uses safe inventory
paths, rejects duplicate level paths, requires exactly one `(1,0,0)` entry per
selected level, and emits only aggregate counts (no serialized identifiers).
Five synthetic tests passed, including an explicit signed high-bit case, stale
hash, duplicate inventory path, and symlink rejection.

## Reproduction

```sh
sha256sum research/binaries/us/Drakan.exe
objdump --version | head -1
objdump -d -Mintel --start-address=0x422489 --stop-address=0x422549 research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x4234c0 --stop-address=0x42357e research/binaries/us/Drakan.exe
python3 tools/research/measure_level_cell_references.py research/installed/us research/exports/asset-inventory/us.json
python3 tools/research/measure_level_blocks.py research/installed/us research/exports/asset-inventory/us.json
PYTHONPATH=tools/research python3 -m unittest test_measure_level_cell_references -v
python3 tools/research/verify_level_cells.py research/installed/us research/exports/asset-inventory/us.json --inspector build/debug/dragonrider_inspect
python3 tools/research/verify_level_cells.py research/installed/us research/exports/asset-inventory/us.json --inspector build/release/dragonrider_inspect
```

This trace extends the bounded `(1,0,0)` findings in
`level-0001-blocks.md`; it does not establish the format's complete grammar,
cell semantics, object classes, world geometry, rendering, runtime branch
success, or compatibility with other editions.
