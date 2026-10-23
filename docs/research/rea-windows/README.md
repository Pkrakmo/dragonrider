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

The contributor's 2026-10-23 [reproduction audit](reproduction-audit-2026-10-23.md)
records Ubuntu objdump 2.42, Python 3.12.3, the original inline-parser method,
and a versioned hash-gated metadata probe. A fresh metadata check agrees with
13 import descriptors and 207 entries. Historical and repeated checks are
explicitly separated; raw outputs remain private.

## Next bounded work

| Status | Task | Evidence / next action |
| --- | --- | --- |
| Done | Close baseline reproduction gaps | [Audit and commands](reproduction-audit-2026-10-23.md) |
| Done | Map bounded window lifetime at 0x412350 | [Report](window-lifetime-2026-10-23.md); explicit callback recovery and raw cross-check |
| Done | Map input setup at 0x4058d0 and selected ownership paths | [Report](input-initialization-2026-10-23.md); full runtime recovery remains unknown |
| Done | Connect activation field and selected input vtable slots | [Bounded follow-up](input-activation-poll-boundary-2026-10-23.md); conditional static dispatch |
| Done | Resolve normal-return destructor registration/invocation | [Registration and exit walk](input-exit-registration-2026-10-23.md); failure and exceptional exits remain conditional |
| Done | Map input event-consumer contracts | [Three consumer boundaries](input-event-consumers-2026-10-23.md); raw event uncertainty preserved |
| Done | Resolve input callback ownership across EXE/RFL | [Conditional module bridge and temporary capture](input-callback-binding-2026-10-23.md); selected runtime module unobserved |
| Done | Map small RFL pointer callback | [Kinds, masks and downstream boundary](input-pointer-callback-2026-10-23.md); jump table independently checked |
| Done | Map downstream pointer-routing boundaries | [Hit tests, state and forwarding](pointer-routing-2026-10-23.md); pointee lifetime and concrete widget targets remain unknown |
| Ready | Bound one action-code family in the large module callback | Select a narrow case in 0x1000c6c0; correlate its mapping producer before assigning gameplay labels |
| Done | Establish normal-exit input/module release order | [Shutdown and handle boundary](module-shutdown-boundary-2026-10-23.md); release attempts ordered, unconditional callback clearing not proven |
| Ready | Trace explicit callback-clear reachability | Recover containing function at 0x10150f3c; separately trace early-init failure into host shutdown |

All new investigation commands and tool limitations are in the
[lifecycle reproduction procedure](lifecycle-reproduction-2026-10-23.md).
The later RFL investigations extend that procedure with a separately imported,
hash-pinned module project and [bounded script](support/InspectPinnedRetailFunctions.java).
This is a completed static platform/input research package, not completion of
the engine or proof of original runtime compatibility. No original code was run.

Update this single backlog after each completed task. Use `Ready`, `In progress`,
`Blocked`, or `Done`; a `Done` row must link to a report with reproducible
verification. See the [evidence template](evidence-template.md). Never commit
original media, executables, assets, private paths, databases, or raw exports.
