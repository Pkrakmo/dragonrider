# DragonRider — Fedora Collaboration Preparation Mission

> **Audience:** Primary developer's Codex agent on Fedora Linux.
> **Scope:** Prepare the *existing* DragonRider repository for a second, Windows-based research contributor. Preserve the Linux-first engineering workflow.

## Mission

You are the coordinating agent for DragonRider, a C++20 Linux-first reimplementation of the original engine used in *Drakan: Order of the Flame*. A second contributor will investigate the original Windows executable using REA, Ghidra, and their available AI coding agents. Your mission is to prepare a safe, documented collaboration workflow **and commit both mission files to the repository when authorized by existing project policy**.

Begin by reading `AGENTS.md`, `README.md`, `TODO.md`, `docs/CONTRIBUTING.md` if present, `docs/GHIDRA.md`, relevant research notes, existing agent skills, any progress tracker, and Git/CMake/test configuration. The repository's current facts and rules take precedence over this mission; never assume older reported milestones are still pending.

## Phase 1 — Audit without destroying work

1. Inspect Git status, remotes, branches, tracked paths, uncommitted changes, `.gitignore`, and relevant history. Do not reset, discard, rewrite, or overwrite work.
2. Inspect working Linux CMake/CTest, Ghidra headless tooling, current MCP bridge, agent skills, and the progress tracker if present. Do not reinstall or replace functioning tools.
3. Check for proprietary retail executables, BIN/CUE/ISO, extracted assets, patch files, Ghidra databases, and bulk decompilation dumps in Git's index/history. If found in history, document and halt **publication**, not unrelated local preparation; never rewrite history automatically.
4. Verify the canonical executable identity from existing evidence when available. Current expected SHA-256: `23630f48e20e8a9f42026501165ae1df407cfcee545a784ec930a4c25ee70648`. Do not alter any original files.

## Phase 2 — Prepare two-contributor workflow

1. Keep `main` as the integration branch; follow existing branch conventions. Reserve `research/rea-windows` for the Windows contributor; use separate Fedora feature/research branches as needed.
2. Define ownership: Fedora maintains C++20 engine, Linux CI, current Ghidra/MCP tooling, SRSC parser work, shared architecture/TODO, and merges. Windows contributor owns REA evaluation, original engine startup, Win32/DirectX research, and evidence-backed findings under `docs/research/rea-windows/`.
3. Add or update `docs/CONTRIBUTING.md` covering cloning, working branches, pull requests, verification, private assets, cross-platform research notes, and conflict avoidance. Create `docs/research/rea-windows/README.md` as the contributor's onboarding and scoped deliverables guide.
4. Add a small link in `README.md`/contributing docs to the Windows mission at `docs/agents/windows-reverse-engineering-mission.md`.
5. Update `AGENTS.md` **minimally** with shared collaboration policies: single owner per file, local independent Ghidra projects, no sharing writable databases, no unreviewed code copying, no automatic push/merge/history rewrite, primary maintainer controls shared TODO and integration. Do not copy the whole Windows mission into `AGENTS.md`.
6. Add a reusable evidence template, or extend the existing tracker schema if one exists. Record binary hash, tool/version, address, observed behavior, calls/xrefs, evidence, confidence, uncertainty, and possible DragonRider mapping. Never maintain duplicate competing trackers.
7. Keep Fedora Linux as the only active build/CI target. Do **not** create Windows CI or attempt Windows engine-porting work.

## Phase 3 — Prepare the research handoff

1. Ensure `docs/agents/windows-reverse-engineering-mission.md` is present and usable as a standalone assignment; prefer preserving the supplied mission document rather than paraphrasing or replacing it.
2. Explain branch checkout in PowerShell, SHA-256 validation via `Get-FileHash`, local-only original assets, REA configuration review, and how to open a research pull request.
3. Define the initial independent benchmark: retail loader function `0x0045EDC0`, magic address `0x0047D900`, and the observed `SRSC` bytes. Treat these as expectations to independently verify, not conclusions to copy.
4. Define subsequent Windows-only research focus: original startup sequence, imports, DirectDraw/Direct3D, DirectInput, DirectSound, original engine state, and function maps.
5. Keep OpenDrakan's format research and community-patch reverse engineering out of the initial independent baseline. Those can be introduced later, explicitly labeled as outside validation.
6. If repo is private, check whether GitHub collaboration is configured; **do not** invite users, publish, push, change permissions, or change visibility without explicit authorization.

## Autonomous execution rules

Execute all safe, reversible, local tasks in sequence. After completing a task, validate, document, and continue to the next unblocked task without prompting for each step. Use subagents only when independent work and clear file ownership justify them. If blocked, switch to another authorized task. Stop for destructive commands, system installs, privilege elevation, sharing copyrighted files, publishing, or GitHub access changes. Do not bypass filesystem or sandbox restrictions.

## Acceptance and handoff

- Collaboration docs and both mission docs exist and have valid relative links.
- Original game assets and Ghidra databases remain untouched and untracked.
- Existing Linux build and tests still pass, or failures are documented as pre-existing or newly introduced.
- Ignore rules and staging are checked; no proprietary files staged.
- Git status, remote readiness, and any unmet permissions are reported precisely.
- Windows contributor has a complete first milestone and pull-request workflow.
- Only mark TODO items complete after verification.

Finish with a concise summary: files changed, branch/status, checks and test results, blockers, and exact actions the human maintainer must take before inviting the friend. **Do not automatically push.**
