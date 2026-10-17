# DragonRider

DragonRider is an independent, open-source C++20 engine reimplementation targeting Windows and Linux. Its initial compatibility target is *Drakan: Order of the Flame*. Users must provide their own game data. This is not an original-source recovery. Research inputs are private and excluded from Git.

A project license has not yet been added to this working directory.

## AI disclaimer

This project was developed with substantial AI assistance and human review.

## Project status
**Status: investigation phase.** DragonRider is far from playable: work so far focuses on bounded asset inspection and reverse-engineering research. There is no game runtime, renderer, playable level, or complete asset pipeline yet. Progress and open investigations are tracked in `TODO.md`.

See the [Git workflow](docs/GIT-WORKFLOW.md) for version control, private research, worktrees, and release preparation. Ignore rules do not replace staged-file review.

The core library contains checked SRSC, bounded level-block diagnostics, selector-`0x0040` texture base-row and selector-`0x0030` palette-entry readers. The inspector also reports selected level grid and cell observations; no playable runtime exists yet. Building requires CMake 3.20 or newer, a C++20 compiler, Ninja for the presets, and zlib development headers and library (CMake `find_package(ZLIB)`). On Fedora 43, the following commands were verified on 2026-10-17 with GCC 15.3.1, CMake 3.31.11, and Ninja 1.13.1:

```sh
cmake --preset debug
cmake --build --preset debug
ctest --preset debug
cmake --preset release
cmake --build --preset release
ctest --preset release
```

Both presets passed 12/12 synthetic tests. The debug inspector is at
`build/debug/dragonrider_inspect`; the release inspector is under
`build/release/`.

On Windows, the same preset commands are a starting point from a shell with a
C++20 compiler, CMake, Ninja, and zlib development files available. CMake must
be able to find the installed zlib headers and library. **These Windows
instructions and builds have not been tested**; dependency setup and compiler
environment may need platform-specific configuration.

The `dragonrider_inspect` executable prints a file's size and first 16 bytes;
for SRSC input it also validates and reports header metadata. With `--records`,
it validates every record's payload range and shows up to 50 records. With
`--texture INDEX`, it reports the observed texture fields for a selector-`0x0040`
record, including raw words at payload offsets 14, 18, and 34, and checks
raw-row bounds on the nonpositive storage branch. The interpretation of those
words depends on the runtime path. With
`--texture-rows INDEX`, it validates raw rows or storage-word-1 zlib rows and
reports their length and CRC32. The inspector limits the selected payload and
decoded rows to 32 MiB each; additional blocks remain opaque. Requested
surface masks are documented, but displayed color and orientation remain
unverified.

`--palette INDEX` checks an observed selector-`0x0030` entry structure and
reports its count and entry CRC32. It leaves any trailing bytes unvalidated
and does not resolve which palette a texture uses. Inspection uses bounded memory:

`--indexed-check TEXTURE_INDEX PALETTE_INDEX` compares an explicitly chosen
8-bit texture and palette record in the same file. It reports index coverage
and excludes row padding; it does not establish their runtime association.

`--manifest EDITION` lists every validated SRSC physical record range with the
caller-supplied edition and input path. It does not infer logical asset IDs or
calculate a hash; the output may contain private paths.

`--level-directory INDEX` structurally inspects a selected `(0,0,0)` record
using the observed level database-list layout. It reports raw-name lengths and
checksums without resolving paths, and does not apply the original version gate.

`--level-blocks INDEX` validates the observed `(1,0,0)` level record framing
and raw or storage-word-1 zlib blocks with bounded decoded sizes. It reports an
aggregate checksum; other storage words, geometry and the version gate remain
unverified. It also reports the
range of the loader's transformed second word across the four-byte grid items;
it counts selected flag bits and negative dwords in the following cells. These
diagnostics do not establish world coordinates or visual correctness.

`--level-grid RECORD_INDEX ENTRY_INDEX` reports one grid's raw metadata,
flag counts and nominal integer coordinate ranges. Runtime adjustments,
floating-point rounding, visibility and final geometry are not represented.

`--level-cell RECORD_INDEX ENTRY_INDEX COLUMN ROW normal|mode1` reports one
raw cell and the candidate grid point order for a traced branch. The caller
selects the orientation; these candidates do not establish rendered geometry.

`--level-source-ids DIRECTORY_INDEX BLOCKS_INDEX` compares the high halves of
nonnegative cell dwords with explicit values in a selected directory record.
It counts ambiguous and unmatched values and does not open or resolve sources;
matches do not guarantee a successful runtime texture load.

`--level-texture-ids BLOCKS_INDEX SOURCE_ID LEVEL_FILE TEXTURE_FILE` compares
cell selector values with an explicitly supplied texture container. It reports
unique, multiple and missing selector matches without resolving embedded paths
or guaranteeing a runtime load.

```sh
./build/debug/dragonrider_inspect --help
./build/debug/dragonrider_inspect path/to/user-owned-file
./build/debug/dragonrider_inspect --records path/to/user-owned-file
./build/debug/dragonrider_inspect --manifest us-retail path/to/user-owned-file
./build/debug/dragonrider_inspect --level-directory 0 path/to/user-owned-level
./build/debug/dragonrider_inspect --level-blocks 1 path/to/user-owned-level
./build/debug/dragonrider_inspect --level-grid 1 0 path/to/user-owned-level
./build/debug/dragonrider_inspect --level-cell 1 0 0 0 normal path/to/user-owned-level
./build/debug/dragonrider_inspect --level-source-ids 0 1 path/to/user-owned-level
./build/debug/dragonrider_inspect --level-texture-ids 1 42 path/to/user-owned-level path/to/user-owned-textures
./build/debug/dragonrider_inspect --texture 0 path/to/user-owned-file
./build/debug/dragonrider_inspect --texture-rows 0 path/to/user-owned-file
./build/debug/dragonrider_inspect --palette 0 path/to/user-owned-file
./build/debug/dragonrider_inspect --indexed-check 1 0 path/to/user-owned-file
```

## Naming

The project and repository are named `DragonRider`; C++ uses the `dragonrider` namespace and `dragonrider/` include paths. The engine library is `dragonrider_engine`; `dragonrider_inspect` is the asset inspector. The main executable `dragonrider` and level viewer `dragonrider_viewer` are planned. See [ADR 0002](docs/decisions/0002-project-naming.md).

Read in order: `AGENTS.md` → `TODO.md` → `docs/RESEARCH.md` → `docs/GHIDRA.md` → `docs/ARCHITECTURE.md`.

## Paths currently reported
- Ghidra installation: set `GHIDRA_HOME` to the local installation directory.
- Working directory: `$HOME/Projects/DragonRider`
- Ghidra program copy: `research/binaries/us/Drakan.exe`
- Original installed program: `research/installed/us/English_-_Program_Files/Drakan.exe`
- Data ISO images: `research/discs/us/drakan.iso`, `research/discs/uk/drakan.iso`
- Separate original CDs: `Drakan - Order of the Flame (USA)/`, `Drakan - Order of the Flame (Europe)/`

Never commit these private files. Actual location/state should be checked on each Codex session.
