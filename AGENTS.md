# AGENTS.md — DragonRider

## Mission and scope
**DragonRider** is the permanent project and repository name. Build an **independent, open-source C++20 engine reimplementation**, with *Drakan: Order of the Flame* as its initial compatibility target. Fedora 43 is the only active development and testing platform; Windows support may be considered later. Original game media are user-owned, read-only research inputs; the distributed engine must require users to supply their own assets. Do not claim this is an original-source recovery.

Use `dragonrider` for the C++ namespace and public include directory, `dragonrider_engine` for the engine library, and `dragonrider`, `dragonrider_inspect`, and `dragonrider_viewer` for the planned main executable, asset inspector, and level viewer respectively. Preserve names of the original game, its technology, and research artifacts; see `docs/decisions/0002-project-naming.md`.

## Read before acting
1. Read `TODO.md`, `README.md`, `docs/ARCHITECTURE.md`, `docs/RESEARCH.md`, and relevant `docs/research/*.md`.
2. Inspect the actual repository state before modifying it. This docs package does **not** certify that an engine skeleton exists.
3. Treat user-reported commands and hashes as observed evidence; do not upgrade hypotheses into facts.
4. For decisions that change boundaries or format policy, add an ADR under `docs/decisions/`.
5. Never mark TODO items complete based solely on instructions or assumptions. Record verification commands/results.

## Confirmed research baseline (2026-10-17)
- Fedora 43 on primary development host; Ghidra 12.1.4 GUI and `analyzeHeadless` work; OpenJDK/Javac 25.0.4.1.
- Ghidra 12.1.4 is available on the research host; set `GHIDRA_HOME` to the local installation directory before running Ghidra tools.
- US and English European/UK retail discs: track 1 `MODE1/2352`, tracks 2–8 `AUDIO` with cue INDEX 00/01 information.
- Extracted US/UK Mode 1 ISO images have identical SHA-256: `256a4e51020b06c551cc310895e245f1df8790be0af230711a727ecbf29d079c` (verified locally with `sha256sum` on 2026-10-17; an earlier handoff had an incorrect digest).
- Their original audio-track BIN files 2–8 are **byte-different**; actual decoded audio differences are not yet established.
- Retail `Drakan.exe` extracted at `research/installed/us/English_-_Program_Files/Drakan.exe`, copied to `research/binaries/us/Drakan.exe`; PE32 i386, 4 sections; SHA-256 `23630f48e20e8a9f42026501165ae1df407cfcee545a784ec930a4c25ee70648`.
- User has opened the executable in Ghidra GUI. Headless import completion and exact project name/path must be verified locally, not assumed.
- Candidate file-open function at `0x0045EDC0` reads a 12-byte header, compares four bytes with `0x0047D900`, checks `0x0100` version, seeks and reads `count * 14` bytes. **Format identity unverified.**
- English patch 445 exists separately. Defer further patch analysis and compatibility work until base-game work is complete; do not mix patched files with retail fixtures.

## Task allocation and model effort
Use the Codex runtime's **actual available** subagent/delegation features, only when they exist. Prompts cannot force model switching or thinking effort; use settings if exposed. For tiny mechanical tasks work directly. Delegate independent, bounded, measurable tasks when expected time savings exceed coordination overhead (usually 2–3 workers, not five by default).

| Task type | Suggested effort | Ownership |
|---|---|---|
| Listing, formatting, manifests, TODO transcription | Low | coordinator or lightweight worker |
| Small C++ implementation, CMake, tests, Ghidra script maintenance | Medium | isolated implementation worker |
| Binary parsing, Ghidra control-flow investigation, architecture conflicts | High | research specialist |
| Deep ambiguous reconstruction | Highest available, selectively | designated specialist |

### Parallel work contract
- Coordinator assigns **explicit input, expected artifact, verification, and file ownership** to each agent.
- Example independent workers: (A) Ghidra candidate-file-loader research; (B) disc/audio and asset-format inventory; (C) C++ bootstrap and synthetic tests.
- **Only coordinator edits `TODO.md`, `AGENTS.md`, and shared architecture docs** after integrating worker results. Workers give proposed checkboxes/notes, not competing writes.
- Never simultaneously mutate the same Ghidra project. Read-only headless sessions may still lock a project: **serialize all access to a shared project**. For parallel Ghidra work, use separate project copies if needed and feasible.
- Prefer narrow scripted exports under distinct ignored paths: `research/exports/<task-id>/`, `research/ghidra-logs/<task-id>/`.
- Do not spawn agents for blocked tasks or duplicate costly analyses. Limit search/analysis scope and reuse prior metadata exports.
- Integrate work only after reviewing evidence and running appropriate tests; resolve conflicting findings explicitly.
- If subagents are unavailable, proceed sequentially without pretending delegation occurred.

### Cross-host collaboration
- Give each contributor exclusive ownership of each changed file. The Fedora maintainer owns `TODO.md`, shared architecture documents, and integration into `main`.
- Each contributor uses an independently owned local Ghidra project. Never share, synchronize, or concurrently open a writable Ghidra database.
- Treat original executable output as evidence, not source to copy. Do not copy unreviewed decompilation or third-party implementation code into DragonRider.
- Do not push, merge, rewrite history, or change repository access automatically. The Fedora maintainer reviews research evidence and controls integration.

## Engineering rules
- Use C++20, CMake, Ninja, GCC and CTest on Fedora Linux; Clang is an optional secondary compiler. Do not add Windows CI, configure MSVC, or implement Windows-specific support unless explicitly requested. See `docs/CI.md`.
- Validate workflow changes with actionlint. For local `act` runs, review an isolated source snapshot and keep original media, private research and the container-engine socket out of job containers; follow `docs/CI.md`.
- Modules: `core`, `assets/riot`, `world`, `render`, `platform`, `physics`, `animation`, `audio`, `game`; apps: inspector, level viewer, player.
- `assets/riot` must not depend on renderer, Ghidra, platform UI or gameplay.
- Validate every binary read: bounds, endianness, overflow, relative offsets, file length, count limits; add malformed-input tests.
- Prefer RAII, `std::span`, `std::filesystem`, fixed-width types, clear errors and deterministic tests.
- Don't prematurely implement speculative Riot formats. Start with proven headers and synthetic fixtures.
- No proprietary game executable, assets, ISO/CUE/BIN, audio, Ghidra databases or derived bulk decompilation in Git.
- Use original code as evidence of behavior, not as implementation to copy. Inspect third-party project licenses before reuse.

## Ghidra rules
- Ghidra is research-only; never a runtime/build dependency. Ghidra scripts require `GHIDRA_HOME`; do not hard-code installation paths.
- Verify project naming/location (`Drakan_Retail` vs prior `Drakan_US_Retail`) by listing local `.gpr` files before invoking headless mode.
- If the program is already imported, use `-process Drakan.exe`, not `-import`; prefer `-readOnly -noanalysis` for narrow reporting if suitable.
- Close Ghidra GUI/project before running headless processing of the same database; do not delete/overwrite persistent projects.
- Prefer targeted Java scripts with bounded output, no huge pseudocode dumps. Include input SHA-256, address, edition, method, Ghidra version, and confidence in every report.
- Distinguish `Observed`, `Inferred`, `Unknown`. Decompiler types/names are provisional. Verify offsets with actual input bytes and callers.

## Git and integration
- `main` is the stable integration branch. Use `research/*`, `feat/*`, `fix/*`, `test/*`, `docs/*`, or `chore/*` for scoped work; assign a branch and exclusive file ownership to each independent agent.
- Use separate Git worktrees for worthwhile parallel tasks; keep private research outside those worktrees and never duplicate original data into them. Shared documentation has one owner. Serialize all access to each Ghidra database, including read-only access.
- Use Conventional Commit-style messages. Before committing, run tests appropriate to the change, `git diff --check`, and review staged names and contents (`git diff --cached --stat` and `git diff --cached`). Verify no original media, game assets, executables, DLLs, private exports or databases are staged. Ignore rules are not a substitute for review.
- Never use destructive resets, force-pushes, history rewrites, or remove private research data. Preserve user changes; resolve integration conflicts with care. The coordinator reviews and tests completed branches before integrating them, using a non-destructive merge or reviewable pull request.
- Verified local commits are permitted. Never push, create a remote repository, or change its visibility without explicit user approval. If protected material appears in history, stop before publishing and report it; do not rewrite history automatically. See [Git workflow](docs/GIT-WORKFLOW.md).

## Workflow and reporting
1. Review current files and mark blockers.
2. Pick the highest-impact unblocked vertical slice; delegate only separable work.
3. Make small changes; run targeted tests/scripts; log outputs outside Git.
4. Update research notes and ADRs based on evidence.
5. Coordinator updates TODO checkbox + proof, then reports changes, tests, failures, next investigation.
6. Never assert success of commands you have not executed.
