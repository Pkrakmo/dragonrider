# Retail executable REA research handoff

This branch and directory name are historical. The analysis target is the
original Windows PE executable, but the contributor's research environment is
Ubuntu/Linux. No Windows host, Windows runtime, Windows engine port, or Windows
CI is required. Findings inform DragonRider's portable C++20 implementation;
they do not claim original-source recovery.

The local branch `research/rea-windows` now includes the current `main` via a
non-destructive merge. Keep original game files, Ghidra databases, exports,
logs, and bulk decompilation outside Git. Never modify shared `TODO.md`, engine
code, CI, or architecture documents from this research branch without the
maintainer's assignment.

Start with [the current autonomous research prompt](../../agents/ubuntu-retail-binary-research-prompt.md),
[contributor workflow](../../CONTRIBUTING.md), and the root
[AGENTS.md](../../../AGENTS.md). The older
[Windows mission](../../agents/windows-reverse-engineering-mission.md) is
superseded.

## Completed baseline

| Status | Task | Evidence |
| --- | --- | --- |
| Done | Validate Ubuntu REA/Ghidra toolchain on a synthetic input | [Toolchain report](ubuntu-toolchain-validation.md) |
| Done | Independently benchmark the retail SRSC loader | [Loader benchmark](retail-loader-benchmark.md) |
| Done | Map executable entry, startup, message loop, termination, and imports | [Startup map](startup-map.md) |

The toolchain report records the earlier session when no retail executable was
available. The later loader report documents obtaining and hash-verifying the
retail input, so the earlier blocker is historical and closed for the current
baseline.

## Audit against project notes, 2026-10-22

On 2026-10-22, the available US retail executable hashed to
`23630f48e20e8a9f42026501165ae1df407cfcee545a784ec930a4c25ee70648`, matching
the project baseline. Local `sha256sum` and `objdump` checks independently
confirmed the `SRSC` bytes at `0x0047D900`, the loader's 12-byte read,
`0x0100` comparison, and `count * 14` table-read arithmetic. These findings
agree with [the established loader note](../riot-file-loading.md); the report
does not claim new format semantics. Bounded disassembly also supports the
startup entry, window setup, and message-loop calls in the new map. Subsystem
labels and indirect call targets remain interpretations, as the report says.

The independent check used GNU `objdump` 2.45.1-5.fc43:

```sh
sha256sum research/binaries/us/Drakan.exe
objdump -s --start-address=0x47d900 --stop-address=0x47d904 research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x45edc0 --stop-address=0x45ef62 research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x468e20 --stop-address=0x468f20 research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x412010 --stop-address=0x4122c0 research/binaries/us/Drakan.exe
```

The reports still need stronger reproduction detail before their findings are
treated as fully reproducible by another maintainer: record the GNU `objdump`
and PE-parser versions used by the contributor, the exact command/procedure for
the startup/import inventory, and the method used for the contributor's
separate cross-check. Those details are not present in the committed reports.
Keep raw outputs private. Do not repeat completed baseline work while these
documentation gaps are being filled.

## Next bounded work

Inspect window-procedure lifetime at `0x00412350` and the input-initialization
candidate at `0x004058D0`, separately. For each, pin the executable hash, use
REA/Ghidra with a separately owned project, corroborate important facts with
bounded `objdump` or raw-byte inspection, and preserve uncertainty in the
report. If the retail input or Ghidra tool is unavailable, record that blocker
and continue another independent, non-sensitive task.

Update this single backlog after each completed task. Use `Ready`, `In progress`,
`Blocked`, or `Done`; a `Done` row must link to a report with reproducible
verification. See the [evidence template](evidence-template.md). Never commit
original media, executables, assets, private paths, databases, or raw exports.
