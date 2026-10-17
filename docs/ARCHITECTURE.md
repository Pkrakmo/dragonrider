# Architecture — DragonRider

## Objective
DragonRider is an independent, open-source C++20 engine reimplementation for Windows and Linux, initially targeting compatibility with user-provided *Drakan: Order of the Flame* game data. No original executable or proprietary assets in releases.

## Naming and current implementation

The project/repository is `DragonRider`; C++ namespace and public include prefix are `dragonrider`. The engine library target is `dragonrider_engine`. `dragonrider_inspect` provides bounded file, SRSC record, texture base-row and palette-entry inspection; the `dragonrider` and `dragonrider_viewer` applications remain planned. These names do not rename original game data, the Riot Engine, or the retail Ghidra project. See [ADR 0002](decisions/0002-project-naming.md), [ADR 0003](decisions/0003-srsc-record-validation.md), [ADR 0004](decisions/0004-bounded-inspection-texture-header.md), [ADR 0005](decisions/0005-texture-base-rows.md), and [ADR 0006](decisions/0006-palette-entry-inspection.md).

## Dependency boundaries
- `core`: checked binary reads, diagnostics, identity, errors.
- `assets/riot`: importer of **validated** Drakan formats into neutral assets; depends on core, not rendering/gameplay.
- The texture base-row reader uses system zlib through CMake; no zlib source is bundled. Its API does not expose Ghidra, rendering, or pixel-layout assumptions.
- Indexed row diagnostics compare explicitly supplied rows and palette sizes without choosing a runtime association; see [ADR 0007](decisions/0007-indexed-texture-diagnostics.md).
- `assets`: source provenance, logical IDs, caches.
- Physical manifests preserve caller-supplied edition and container provenance separately from future logical IDs; see [ADR 0008](decisions/0008-physical-asset-manifests.md).
- The level database-list reader preserves untrusted raw names without resolving paths; see [ADR 0009](decisions/0009-level-directory-inspection.md).
- The `(1,0,0)` level block diagnostic validates bounded raw or zlib data without interpreting it as geometry; see [ADR 0011](decisions/0011-level-block-inspection.md).
- Grid callbacks expose raw level observations and nominal ranges without producing meshes; see [ADR 0014](decisions/0014-level-grid-diagnostic.md).
- Cell callbacks and explicitly selected candidate point ordering remain bounded diagnostics, not a renderer or mesh; see [ADR 0015](decisions/0015-level-cell-candidates.md).
- Level source-ID diagnostics compare explicitly selected records without opening or resolving paths; see [ADR 0012](decisions/0012-level-source-id-diagnostic.md).
- Level texture diagnostics compare caller-selected files without resolving embedded names; see [ADR 0013](decisions/0013-explicit-level-texture-diagnostic.md).
- `world`: entities, transforms, scene lifetime.
- `render`: rendering abstraction and backend; backend choice via ADR.
- `platform`: filesystem/input/window adapters (SDL3 is candidate).
- `physics`, `animation`, `audio`: independent runtime systems.
- `game`: Rynn, Arokh, AI, combat, scripts, quests, inventory.
- `apps`: inspector, level-viewer, player.
- `tools/ghidra`: research only, never linked into the engine.

## Design principles
- Asset provenance includes edition, container path, internal ID, offset, length, hash when known.
- Identical retail data-track bytes justify shared retail **data** baseline; CD audio tracks remain edition-specific pending PCM research.
- Prefer synthetic fixtures in public tests and opt-in private original-data integration checks.
- Render/world/game types must not expose packed original file layouts.
- Build vertical slices: inspect bytes → parse verified header → inspect model → inspect level → playable movement.
- Do not select engine dependencies blindly; validate portability and licensing via an ADR.

## Multi-agent boundaries
A Ghidra research worker owns `tools/ghidra/*` within assigned files; engine worker owns designated `src/`, `include/`, and tests. Coordinator owns shared plans/docs. No concurrent writers to a single Ghidra project or common file.
