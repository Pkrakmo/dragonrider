# Contributing to DragonRider

DragonRider is a Linux-first, independent C++20 engine reimplementation. The
active build and CI target is Fedora Linux. Windows reverse engineering supplies
evidence for the portable implementation; it does not authorize Windows engine
porting or Windows CI.

Read [AGENTS.md](../AGENTS.md), [the Git workflow](GIT-WORKFLOW.md), and
[research guidance](RESEARCH.md) before starting. Windows research contributors
also begin with the standalone [Windows mission](agents/windows-reverse-engineering-mission.md)
and [Windows research onboarding](research/rea-windows/README.md).

## Ownership and branches

`main` is the integration branch. Work on a focused branch using the existing
prefixes: `research/`, `feat/`, `fix/`, `test/`, `docs/`, or `chore/`.

- Fedora maintainer: portable C++20 engine, Fedora CI, existing Ghidra/MCP
  tooling, SRSC parser work, shared architecture and `TODO.md`, and merges.
- Windows contributor: REA evaluation, independently owned Ghidra projects,
  original startup and Win32/DirectX research, and evidence-backed files under
  `docs/research/rea-windows/`.

The Windows contributor reserves `research/rea-windows`. Do not modify a file
owned by another contributor without agreeing on the handoff first. Do not edit
`TODO.md`, shared architecture documents, Linux CI, or engine code from the
Windows research branch unless the Fedora maintainer explicitly assigns it.

## Getting started

Clone the URL supplied by the maintainer. Never add original game material to
the checkout. Keep retail executables, disc images, patches, extracted assets,
Ghidra projects, exports, logs, and bulk decompilation in a private directory
outside the repository where practical.

On Windows PowerShell, create or update the research branch from the latest
locally available `main`:

```powershell
git fetch origin
git switch main
git pull --ff-only
git switch --create research/rea-windows
```

If the branch already exists locally, use `git switch research/rea-windows`
instead. If the remote branch exists but not the local branch, use
`git switch --track origin/research/rea-windows`. These commands require the
maintainer-provided remote and only the access already granted to the
contributor; do not change remote URLs or repository settings.

Before using a retail executable, validate its identity locally:

```powershell
Get-FileHash -Algorithm SHA256 -Path 'C:\private\Drakan.exe'
```

The current canonical US retail reference is
`23630f48e20e8a9f42026501165ae1df407cfcee545a784ec930a4c25ee70648`.
If it differs, record the actual hash and do not assume the documented
addresses apply.

## Research and evidence

Use a separate, locally owned Ghidra project for each contributor. Do not share
writable project databases, and serialize access even when a tool claims to be
read-only. Review REA or MCP configuration changes before applying them; do
not replace existing registrations or use elevated installers without approval.

The initial independent benchmark is the retail loader at `0x0045EDC0`, the
data address `0x0047D900`, and expected bytes `SRSC`. These are hypotheses to
verify independently, not conclusions to copy. Keep OpenDrakan format material
and community-patch reverse engineering out of that baseline. Subsequent
Windows research covers startup/imports, Win32, DirectDraw/Direct3D,
DirectInput, DirectSound, original engine state, and function maps.

Use [the evidence template](research/rea-windows/evidence-template.md) for
every meaningful finding and update the scoped backlog in the same directory.
Commit concise, independently written conclusions and small metadata only—never
bulk disassembly, pseudocode dumps, original binary data, or proprietary assets.

## Verification and review

Keep changes small and reviewable. Before requesting review, run the checks
relevant to your changes, inspect `git status --short`, run `git diff --check`,
and review the staged paths and content. Fedora engine changes use the CMake and
CTest workflow in [CI documentation](CI.md); Windows research documentation
does not add a Windows build requirement.

Open a research pull request only after the maintainer has granted the needed
GitHub access and authorized a push. State the binary hash, tool versions,
method, evidence, confidence, open questions, and exact commands run. The
Fedora maintainer reviews and merges into `main`. Do not force-push, merge,
rewrite history, publish artifacts, invite users, or change repository access
or visibility.
