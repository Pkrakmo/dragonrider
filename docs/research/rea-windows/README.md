# Windows REA research handoff

This directory is owned by the Windows research contributor on
`research/rea-windows`. It holds concise, evidence-backed findings and the
backlog for Windows-only analysis. It must never contain original media,
executables, patches, Ghidra databases, exported disassembly, bulk decompiler
output, credentials, or local machine paths.

Start with [the Windows mission](../../agents/windows-reverse-engineering-mission.md)
and [contributor workflow](../../CONTRIBUTING.md). The Fedora maintainer owns
shared `TODO.md`, architecture documents, engine implementation, Linux CI, and
integration into `main`.

## First milestone

Independently test the following retail-binary expectations after validating
the input hash:

- loader function `0x0045EDC0`;
- data address `0x0047D900`;
- bytes expected to be ASCII `SRSC`;
- a resource-file open, 12-byte header read, `0x0100` version check, and a
  14-byte-entry table read.

They are benchmark hypotheses, not established results for the Windows
contributor to repeat. Record supporting or contradictory observations with
[the evidence template](evidence-template.md). The canonical US retail
reference hash is
`23630f48e20e8a9f42026501165ae1df407cfcee545a784ec930a4c25ee70648`.
If the analyzed executable differs, report its actual hash and do not reuse
these addresses as equivalent.

Do not use OpenDrakan format research or community-patch reverse engineering
until this independent baseline is complete and the Fedora maintainer agrees
to explicitly labeled cross-validation.

## Scoped backlog

| Status | Task | Scope | Dependency / next action | Owner |
| --- | --- | --- | --- | --- |
| Done | Evaluate REA with a disposable local project and actual agent-initiated MCP call | Ubuntu VM toolchain; Windows-native integration unverified | [Observed synthetic analysis and limitations](ubuntu-toolchain-validation.md), 2026-10-22 | Windows contributor |
| Blocked | Independently benchmark the SRSC loader | `0x0045EDC0`, `0x0047D900` | Retail executable absent; obtain legitimate input privately, validate hash, then write evidence report | Windows contributor |
| Blocked by milestone 1 | Map executable startup and imports | Entry point and initialization | Begin only after the benchmark report exists | Windows contributor |
| Blocked by startup map | Map platform subsystems | Win32, DirectDraw/Direct3D, DirectInput, DirectSound | Use bounded questions and evidence reports | Windows contributor |

Update this single table rather than creating competing trackers. Use `Ready`,
`In progress`, `Blocked`, or `Done`; a `Done` row must link to an evidence
report and its reproducible verification.
