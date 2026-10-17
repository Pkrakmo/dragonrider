# Loader caller and extension construction

- **Input:** US retail `research/binaries/us/Drakan.exe`, SHA-256 `23630f48e20e8a9f42026501165ae1df407cfcee545a784ec930a4c25ee70648` (verified with `sha256sum` on 2026-10-17).
- **Addresses:** loader `0x0045EDC0`, selected caller `0x0041E470`, path helper `0x0041E420`, suffix helper `0x00409020`, suffix table `0x0047B6BC`.
- **Method:** Ghidra 12.1.4 headless, existing `Drakan_US_Retail` project, `-process Drakan.exe -readOnly -noanalysis`; `TraceLoaderCallers.java` lists bounded instruction windows for direct references to the seven already identified loader callers. The selected path was independently checked using GNU `objdump` disassembly and raw section bytes. Private Ghidra run: `research/ghidra-logs/loader-callers/run-MNnv7Dat/`.
- **Confidence:** high for the specified instructions and table bytes; Ghidra xrefs describe the existing database only. Prior analysis completeness and indirect calls remain unknown.

## Observed

- At `0x0041E49F–0x0041E4A5`, the caller passes its integer argument and a stack buffer to `0x0041E420` with the original object in `ECX`. That helper copies a zero-terminated string from the object into the supplied buffer, selects an address `0x0047B6BC + 5 * index`, and passes the buffer and selected string to `0x00409020`. The latter searches backward for a period or backslash and appends the selected suffix if no extension is found. Existing extensions are retained.
- The result buffer is passed at `0x0041E4CA–0x0041E4D1` to `0x0045ED70`, which copies its argument into the loader object's path field; the caller invokes `0x0045EDC0` at `0x0041E4E9`.
- The seven consecutive five-byte entries, read directly from the executable's `.data` section, are:

  | Index | Bytes | ASCII suffix |
  | --- | --- | --- |
  | 0 | `2e 6f 64 62 00` | `.odb` |
  | 1 | `2e 6d 6f 64 00` | `.mod` |
  | 2 | `2e 6d 6f 64 00` | `.mod` |
  | 3 | `2e 74 78 64 00` | `.txd` |
  | 4 | `2e 61 64 62 00` | `.adb` |
  | 5 | `2e 73 64 62 00` | `.sdb` |
  | 6 | `2e 73 73 64 00` | `.ssd` |

- The Ghidra database reports eleven direct calls to `0x0041E470`. Bounded windows show arguments 0, 1, 3, 4, 5, and 6 at ten of those sites; the remaining site (`0x0042EB75`) has no containing function in this database and its argument was not established. There may be additional calls absent from the database.
- This produces a direct code path from selected caller indices to the above suffixes and then to the `SRSC` loader, conditional on the input path lacking an extension. The separately inventoried retail files include `SRSC` files with each of these six distinct suffixes. No exact filename was recovered by this trace.

## Inferred and unknown

These paths support the use of the same loader across several resource types, but do not prove that every file bearing one of the suffixes is an SRSC container. The duplicate `.mod` entries do not establish a semantic distinction. The loader's other callers, actual runtime input strings, individual 14-byte table fields, and prior Ghidra analysis completeness remain unresolved. Avoid claiming that the helper replaces an existing extension or that its input values are limited to the observed table indices.

## Reproduction

Close all Ghidra GUI sessions using this project. List the `.gpr` and verify the executable hash. Use the same cooperative lock as `tools/ghidra/analyze.sh` and unique private logs; run the existing imported program without analysis or saving:

```bash
find research/ghidra-projects -maxdepth 1 -name '*.gpr' -print
sha256sum research/binaries/us/Drakan.exe
exec 9>research/ghidra-projects/.drakan-loader-probe.lock
flock -n 9
mkdir -p research/ghidra-logs/loader-callers
run=$(mktemp -d "$PWD/research/ghidra-logs/loader-callers/run-XXXXXXXX")
mkdir -p "$run/config" "$run/cache"
export XDG_CONFIG_HOME="$run/config" XDG_CACHE_HOME="$run/cache"
"$GHIDRA_HOME/support/analyzeHeadless" \
  "$PWD/research/ghidra-projects" Drakan_US_Retail -process Drakan.exe \
  -readOnly -noanalysis -scriptPath "$PWD/tools/ghidra/scripts" \
  -postScript TraceLoaderCallers.java -log "$run/ghidra.log" \
  -scriptlog "$run/script.log" > "$run/console.log" 2>&1
```

The script prints at most 40 direct call sites per target and 10 previous instructions per site; it does not export decompiled bodies. Cross-check the path flow and suffix table with:

```bash
objdump -d -Mintel --start-address=0x41e420 --stop-address=0x41e510 research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x409020 --stop-address=0x409082 research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x45ed70 --stop-address=0x45edb0 research/binaries/us/Drakan.exe
objdump -s --start-address=0x47b6bc --stop-address=0x47b6df research/binaries/us/Drakan.exe
```

The cooperative lock does not detect a GUI session. Use a shell dedicated to this run, or close file descriptor 9 afterwards (`exec 9>&-`), to release it.
