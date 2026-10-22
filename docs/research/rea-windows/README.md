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
| Done | Evaluate REA through actual MCP calls | Ubuntu Ghidra; Windows-native providers not evaluated | [Validation](ubuntu-toolchain-validation.md) | Research contributor |
| Done | Independently benchmark SRSC loader | Canonical retail binary | [Evidence and reproduction](retail-loader-benchmark.md) | Research contributor |
| Done | Map executable startup and imports | Bounded static entry/window/loop/exit map | [Map, limits and reproduction](startup-map.md) | Research contributor |
| Ready | Map platform subsystems | Window lifetime and input first | Inspect 0x412350 and 0x4058d0; resolve graphics vtables | Research contributor |

Update this single table rather than creating competing trackers. Use `Ready`,
`In progress`, `Blocked`, or `Done`; a `Done` row must link to an evidence
report and its reproducible verification.
