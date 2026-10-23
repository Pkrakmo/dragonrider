# Reproducing the window/input static investigation

Date: 2026-10-23. US retail input only, SHA-256
`23630f48e20e8a9f42026501165ae1df407cfcee545a784ec930a4c25ee70648`.
Versions: Ubuntu 24.04.5, Python 3.12.3, GNU objdump 2.42,
Ghidra 12.1.4, OpenJDK 25.0.4.1, REA 6.7.0, Node 24.22.1.
Reports: [window lifetime](window-lifetime-2026-10-23.md) and
[input initialization](input-initialization-2026-10-23.md).

## Preconditions and private outputs

Work inside the analysis VM. Set `DR_EXE` to the private original and
`GHIDRA_HOME` to the pinned installation. Set `DR_PRIVATE` to an existing
private directory outside Git. Do not put literal personal paths in reports.
Run one Ghidra operation at a time and close any GUI using the project.
The scripts parse/decompile; they never execute the original program.

From the repository root, first run the hash-gated metadata check:

```sh
python3 docs/research/rea-windows/support/pe_metadata_probe.py "$DR_EXE" \
  > "$DR_PRIVATE/lifecycle-metadata.json"
```

Stop on nonzero exit. The probe rejects noncanonical input before PE parsing.

## REA observations

The original stdio client used protocol `2024-11-05`: initialize, initialized
notification, tools/list, then tools/call. Provider settings were
`REA_ANALYSIS_PROVIDER=ghidra`, `GHIDRA_INSTALL_DIR=$GHIDRA_HOME`, and the JDK
path described in the toolchain report. It used a 450-second request allowance.
The first sequence was:

1. `open_binary`: `{"path":"<private absolute executable>","provider_id":"ghidra"}`.
2. `analyze_function`: `{"procedure":"0x412350"}`.
3. `close_binary` after the returned error (no procedure at that address).

A second fresh sequence substituted `0x4058d0` and succeeded, recovering
`0x4058d0..0x4059c0`. The function was checked against raw disassembly.
The first failure was not silently counted as successful REA recovery.

## Explicit Ghidra callback recovery

The following reproduces the fallback, using the included self-authored
[Java script](support/InspectWindowLifecycle.java). It verifies Ghidra's stored
input hash, reports whether a function already exists, rejects an address inside
another function, and explicitly creates a missing candidate before decompiling.
It emits private pseudocode and call sites; never commit its output.

```sh
dr_project=$(mktemp -d "$DR_PRIVATE/lifecycle-project-XXXXXX")
dr_scripts="$PWD/docs/research/rea-windows/support"
"$GHIDRA_HOME/support/analyzeHeadless" "$dr_project" WindowLifecycle \
  -import "$DR_EXE" -scriptPath "$dr_scripts" \
  -postScript InspectWindowLifecycle.java 0x412350 0x406930 0x406a50 \
  -log "$dr_project/import.log" -scriptlog "$dr_project/import-script.log"
```

Observed exit 0, post-analysis/save/import success. Ghidra's default PE analysis
was used, without manually supplied Windows DLLs or function signatures.
`0x412350` was initially undefined, then recovered as `0x412350..0x41275d`.
The two input helpers were already defined. Their decompiler output had stack/
prototype artifacts; raw instructions determine argument values and tests.

Keep that exact project and serialize these read-only follow-ups:

```sh
"$GHIDRA_HOME/support/analyzeHeadless" "$dr_project" WindowLifecycle \
  -process Drakan.exe -readOnly -noanalysis -scriptPath "$dr_scripts" \
  -postScript InspectWindowLifecycle.java 0x412320 0x406d80
"$GHIDRA_HOME/support/analyzeHeadless" "$dr_project" WindowLifecycle \
  -process Drakan.exe -readOnly -noanalysis -scriptPath "$dr_scripts" \
  -postScript InspectWindowLifecycle.java 0x407b70 0x408050 0x406bf0
"$GHIDRA_HOME/support/analyzeHeadless" "$dr_project" WindowLifecycle \
  -process Drakan.exe -readOnly -noanalysis -scriptPath "$dr_scripts" \
  -postScript InspectWindowLifecycle.java 0x4059f0 0x406c10
```

Each follow-up exited 0. Callback `0x406bf0` was initially undefined;
its transient definition was discarded with the read-only session. The
scratch project was retained privately, not deleted or synchronized.

## Independent raw control-flow check

A separate agent used Python standard-library PE header/import/GUID decoding
and GNU objdump, without Ghidra. The following windows reproduce the checked
regions; output stays private. Stop addresses are exclusive, and windows may
include boundary context rather than exact function bodies.

```sh
objdump -d -Mintel --start-address=0x412350 --stop-address=0x412760 "$DR_EXE"
objdump -d -Mintel --start-address=0x412320 --stop-address=0x412350 "$DR_EXE"
objdump -d -Mintel --start-address=0x4058d0 --stop-address=0x4059d0 "$DR_EXE"
objdump -d -Mintel --start-address=0x4059f0 --stop-address=0x405aa0 "$DR_EXE"
objdump -d -Mintel --start-address=0x406930 --stop-address=0x406d80 "$DR_EXE"
objdump -d -Mintel --start-address=0x406d80 --stop-address=0x406dc0 "$DR_EXE"
```

For each indirect imported call, map its IAT VA through PE sections, pair the
FirstThunk slot with the corresponding OriginalFirstThunk entry, and read the
name or preserve the ordinal. This is the same mapping method documented in
the [reproduction audit](reproduction-audit-2026-10-23.md); the companion probe
provides aggregate imports, not a bulk disassembly export. Object virtual
calls are retained as slot offsets unless separately identified.

For the three GUID observations, after the probe has accepted the input, map
VAs `0x476c30`, `0x476c20` and `0x476b40` by subtracting the image base,
finding the unique section containing all 16 raw-backed bytes, and computing
`section.raw_offset + RVA - section.rva`. Read exactly 16 bytes at that offset
and format them with Python `uuid.UUID(bytes_le=raw_guid_bytes)`. This accounts
for the mixed-endian GUID fields; do not decode all 16 bytes as a big-endian UUID.

Compare branch conditions and call positions, not decompiler variable names.
No runtime testing, third-party engine code, community patch research or
claim of complete cross-references is part of this procedure.
