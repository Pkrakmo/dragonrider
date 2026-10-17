# DragonRider session handoff

**Date:** 2026-10-17. Read `AGENTS.md`, `TODO.md`, and the linked research
before resuming. Windows builds and project licensing remain
unverified/unresolved. See `docs/GIT-WORKFLOW.md` for repository practices.

## Current state

The C++20 engine library and inspector can validate SRSC headers and record
ranges, decode bounded selector-`0x0040` base rows, inspect selector-`0x0030`
palette entries, and compare explicitly selected indexed textures and palette
counts. The inspector now reports raw texture-header dwords at offsets 14, 18
and 34; they do not establish universal color or transparency semantics.
The physical manifest API and `--manifest EDITION` report validated SRSC
locations with explicit source provenance, separate from future logical IDs;
ADR 0008 records the boundary and limitations. The private US inventory
matched all 38,926 ranges across 178 containers. No logical resolver exists.
The level database-list reader and `--level-directory INDEX` inspect the
observed `(0,0,0)` record without resolving raw names. The independent US scan
matched 23 level containers and 164 entries; see ADR 0009 and the level trace.
No playable runtime or visually validated image export exists.

On this session's Fedora GCC build, debug and release each passed 10/10 CTests;
the Python research suite passed 24/24 tests. The texture-header inspector
matched independent byte decoding for 5,993/5,993 selected private US records.
The latest sample and device findings are in
`docs/research/texture-key-samples.md` and
`docs/research/texture-device-behavior.md`. Research outputs, original game
data, and Ghidra databases remain local and excluded from Git.

## Next investigation

Trace the `(1,0,0)` record consumed by the same level loader, including the
count and subsequent data, before implementing geometry or object placement.
Establish actual device surface format, palette defaults and visual row
orientation before deciding how to export images. Investigate the conditional
alternate surface path, texture coordinates and/or a reproducible comparison
against a running original game; do not infer display results from sample
co-occurrence or file color-key values alone. The zero-count palette case and
non-null attachment failure are documented but do not establish a fallback.
See the open M2 item in `TODO.md` for the complete limitations.

## Reproduction

```sh
cmake --preset debug
cmake --build --preset debug
ctest --preset debug --output-on-failure
python3 -m unittest discover -s tools/research -p 'test_*.py' -v
python3 tools/research/verify_texture_inspector.py build/debug/dragonrider_inspect research/installed/us research/exports/selector-0040-samples/us.json
python3 tools/research/verify_srsc_manifest.py build/debug/dragonrider_inspect research/installed/us research/exports/asset-inventory/us.json
python3 tools/research/verify_level_directory.py build/debug/dragonrider_inspect research/installed/us research/exports/asset-inventory/us.json
```

For any new Ghidra work, verify project name and input hash, close GUI access,
and use the cooperative lock and unique read-only run described in the
research notes. Do not alter the persistent project or original media.
