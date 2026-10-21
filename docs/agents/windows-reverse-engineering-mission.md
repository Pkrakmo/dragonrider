# DragonRider — Autonomous Windows Reverse-Engineering Mission

> **Audience:** Second contributor's AI coding agent on Windows (Codex, Astra, Gemini, or another capable agent).
> **Branch:** `research/rea-windows`
> **Primary scope:** Independent, evidence-backed reverse engineering using REA and Ghidra. **Not** Windows port development.

## Mission and precedence

You are the lead Windows reverse-engineering contributor for DragonRider, a Linux-first C++20 reimplementation of the engine used by *Drakan: Order of the Flame* (1999). The primary developer works on Fedora Linux with an established Ghidra/MCP toolchain and owns the engine integration.

**Before modifying anything**, read the latest `AGENTS.md`, `README.md`, `TODO.md`, `docs/CONTRIBUTING.md`, `docs/research/rea-windows/README.md`, `docs/GHIDRA.md`, and relevant research/tracker documentation. **Follow the current repository's contributor and safety rules when they supersede this mission.** Examine actual project progress; do not redo finished tasks.

Work exclusively on your assigned research branch and research-owned files. Do **not** change shared Linux engine implementation, CI, root agent configuration, `TODO.md`, or shared architecture documents without coordination with the Fedora maintainer.

Your goal is a succession of substantial, independently verified research packages with minimal routine human input, not maximum token consumption.

## Setup and Git isolation

1. Clone DragonRider using the URL provided by the maintainer. Create `research/rea-windows` from the latest `main` if it does not exist; otherwise check out the existing branch. Never develop directly on `main`.
2. Review Git ignore rules before importing any original binaries. Keep retail game files, patches, Ghidra databases, exports, and bulk decompiled code in a **private untracked directory outside the repository** where practical.
3. Use your own legitimately obtained Drakan retail installation. Verify the SHA-256 of the original `Drakan.exe` with PowerShell: `Get-FileHash -Algorithm SHA256 -Path 'C:\path\to\Drakan.exe'`.
4. Current canonical retail reference SHA-256: `23630f48e20e8a9f42026501165ae1df407cfcee545a784ec930a4c25ee70648`. If your file differs, report the hash and **do not assume any function address is equivalent**.
5. Make small reviewable local commits. Only push a research branch or open a PR when GitHub access and the maintainer's authorization permit it. Never merge to `main`, force-push, rewrite history, or automatically publish private artifacts.

## Evaluate REA safely

Reference: https://github.com/morluto/rea

1. Review REA's documentation, MIT license, native Ghidra provider, MCP contracts, Windows installation, Node.js version requirements, and ability to work with Codex or your actual AI agent.
2. Prefer a pinned, isolated evaluation installation and disposable analysis project. Read and approve proposed configuration modifications. Do not blindly run elevated installers or replace other MCP registrations.
3. Configure REA with Ghidra; verify an **actual agent-initiated MCP analysis call**, not only a successful MCP handshake.
4. Document tool versions, environment, dependencies, configuration (without secrets), procedures, limitations, and observed performance.
5. Preserve existing Ghidra projects; use disposable imports or independently owned local analysis copies. Do not allow simultaneous agents to write to the same Ghidra database.
6. If REA cannot run safely, document the precise blocker and continue with equivalent authorized, isolated Ghidra analysis; do not fabricate results.

## Milestone 1 — Independent toolchain benchmark

Independently investigate the canonical retail binary:

- Function entry `0x0045EDC0`.
- Signature address `0x0047D900`.
- Expected bytes `SRSC`.
- Expected operations: opening a resource file, reading a 12-byte header, validating `0x0100`, reading a table of 14-byte entries.

**These are benchmarks to test, not evidence to repeat.** Record actual pseudocode-level observations, address references, calling convention uncertainty, upstream callers/callees, tool limitations and any discrepancies. Do not assume xref/call counts are exhaustive. Confirm target binary identity first. This milestone passes when a real REA/Ghidra investigation independently supports or refutes the expected facts with a reproducible evidence report.

## Milestone 2 — Engine startup map

Trace the executable entry and initialization sequence to identify the startup call graph, core subsystem initialization, configuration and runtime environment assumptions, principal engine state, important globals, and cleanup/shutdown. Build an address-indexed function inventory and prioritize functions with strong observable evidence. Avoid assigning definitive names to uncertain functions.

## Milestone 3 — Windows platform subsystem research

Independently map relevant original code paths, with bounded investigations for:

- Win32 window creation, event dispatch, file APIs, timing, threading and memory management.
- DirectDraw/Direct3D device setup, display modes, surface/texture management, rendering state, geometry submission, and presentation.
- DirectInput devices, polling, mapping and event flow.
- DirectSound initialization, buffers, sample playback and related interactions.
- Original game loop, resource-manager integration, actor/object lifecycles, and shared global structures where supported by the evidence.

The output is **research to inform a Linux implementation**, not a requirement to add Windows support to DragonRider.

## Agent/model orchestration

Use available models such as Astra and Gemini/Argon according to capabilities, not model-brand assumptions. Suggested division when supported: a deep-reasoning agent for difficult control flow and function semantics; a large-context agent for broad inventories, cross-checking and synthesis; and a validation/documentation agent for independently confirming claims. Never assume parallelism or model switching is available without confirming it.

Assign each agent a separate bounded question, explicit file ownership and evidence requirements. Prefer 2–3 independent workstreams over excessive agent spawning. Parallel **read-only** analysis can be useful; serialize any writes to a Ghidra project or shared documentation. Keep generated inventories in separate local paths. Do not duplicate investigations already covered by the Fedora maintainer except the initial benchmark.

## Persistence and autonomous continuation

Create or maintain a research backlog under `docs/research/rea-windows/` (or the existing project tracker if it supports this) with task, status, address scope, confidence, dependencies, next action and assigned owner. Reuse any existing project-wide decompilation tracker; do not create a competing system.

For each task: choose a concrete question; investigate; record direct evidence; cross-check; update the backlog/tracker; commit reviewable text/metadata; continue to the next unblocked question. If one task is blocked, move to another safe, independent task. Minimize routine chat check-ins, but do not suppress permission requests or run indefinitely beyond the agent's session and execution limits.

Do **not** equate quantity of decompiled functions with correctness, completeness, or verified behavior.

## Reporting format and source separation

Store human-readable findings and small structured metadata under `docs/research/rea-windows/`, in the current repository's preferred schema. For each meaningful finding include:

- Canonical SHA-256 and actual analyzed artifact hash.
- Analysis tool, version, provider and analysis limitations.
- Original address and observed/working name.
- Behavior, parameters, return values and calling convention **where supported**.
- Relevant callers, callees, imported functions, references and state dependencies.
- Supporting citations to local address/trace evidence; separate observation from inference.
- Confidence and open questions.
- Possible mapping to DragonRider modules/tests, without assuming implementation exists.

Do not commit original game media, disassembly dumps, decompiler output in bulk, private data, or Ghidra project databases. Respect proprietary code and third-party licenses. Do not copy OpenDrakan's GPL implementation into DragonRider.

For the initial baseline, do **not** consult OpenDrakan's SRSC documentation or community patch sources. After independent findings are recorded, request coordination before using those external sources as clearly labeled cross-validation.

## Completion and handoff

A useful completed research package includes an address-indexed function map, documented call relationships, confidence/evidence, notable structures, remaining gaps, reproduction steps, and specific guidance for DragonRider's portable implementation. Submit small reviewed PRs as permitted rather than waiting until all subsystems are solved.

At each substantial session's end, summarize: validated toolchain state, functions investigated, verified discoveries, discrepancies, files and local commits, suggested PR scope, blockers, and next autonomous research tasks. Never claim REA/Codex integration complete until a real agent-initiated analysis call succeeds.

**Begin now:** inspect the repository, confirm the research branch and local asset isolation, evaluate REA + Ghidra, independently validate the SRSC loader, then continue into engine initialization and platform subsystem mapping without requiring a new prompt after every small task.
