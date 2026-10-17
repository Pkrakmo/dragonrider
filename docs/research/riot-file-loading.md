# Retail file-loader probe

- **Source:** US retail `research/binaries/us/Drakan.exe`, SHA-256 `23630f48e20e8a9f42026501165ae1df407cfcee545a784ec930a4c25ee70648`.
- **Method:** Ghidra 12.1.4 read-only `-process` with `-noanalysis`, using `tools/ghidra/analyze.sh`; corroborated with GNU `objdump` and raw PE bytes. The generated JSON and logs are private under `research/`.
- **Confidence:** high for the identified instructions and bytes; caller completeness depends on existing Ghidra analysis. The status of the prior auto-analysis is not established.

## Observed

- The imported program's stored SHA-256 matches the binary above. Its function at `0x0045EDC0` spans `0x0045EDC0–0x0045EF61` in the existing Ghidra database.
- `0x0047D900` is `.data` bytes `53 52 53 43`, ASCII `SRSC`. Independent PE section mapping places these bytes at file offset `0x7D900`.
- The function opens a path held by its object, reads exactly 12 bytes, calls `_strncmp` for four bytes against that constant, and checks a little-endian 16-bit value at header offset 4 for `0x0100`. It seeks from the beginning using the little-endian 32-bit value at offset 6, then uses the unsigned little-endian 16-bit value at offset 10 as a nonzero count, allocating and reading `count * 14` bytes. The instruction checks both read success and exact bytes read. Subsequent research identifies the record seek and read-budget fields; see `srsc-record-behavior.md`.
- The current database lists seven direct call references at `0x0040BB7E`, `0x0040BD2C`, `0x0040BF6F`, `0x0041E4E9`, `0x0042AFB0`, `0x00436F21`, and `0x004379A2`. The bounded JSON records these, containing functions and direct callees. This is not proof that indirect references do not exist.
- A scan of `research/installed/us` found 178 files beginning `SRSC`: `.rrc` 2, `.txd` 38, `.adb` 12, `.lvl` 23, `.mod` 29, `.odb` 39, `.sdb` 19, `.ssd` 16. Each of these 178 has version `0x0100` and `offset + count * 14 == file size`. This describes the scanned files, not a requirement established for all files or editions. Files are private and remain unchanged.

## Inferred and unknown

The loader likely processes an indexed container shared across multiple asset types. Later evidence of specific caller-to-extension mappings and record field use appears in `loader-callers.md` and `srsc-record-behavior.md`. Selector meanings and payload formats remain unknown. Test offsets and counts independently instead of assuming that every valid table ends at EOF.

## Reproduction and validation

On 2026-10-17 a separate fresh import into a disposable `/tmp` project was
processed with `-readOnly -noanalysis`, including a stdio MCP tool call. It
reported the same executable hash, function span and `SRSC` bytes, with seven
direct references and 14 calls. Its import log warned about unresolved Windows
DLLs, so the observed cross-reference counts are not proof of completeness.
The primary project was not opened for this verification. See
[Ghidra guidance](../GHIDRA.md) for the experimental bridge and its limits.

Close any Ghidra GUI using the project first. List the projects, then execute:

```sh
find research/ghidra-projects -maxdepth 1 -name '*.gpr' -print
sha256sum research/binaries/us/Drakan.exe
./tools/ghidra/analyze.sh
```

The wrapper uses a cooperative `flock` for its own invocations, Ghidra's project locking, a unique log directory, isolated per-run preferences/cache, and never imports or saves analysis. It does not detect GUI sessions reliably; closing them remains a prerequisite. It produces one JSON per run. `python3 -m json.tool research/exports/loader-probe/run-EJNY4qji.json` successfully validated the second run; the first successful run was `run-yu3b4kfz.json`. Their JSON data are identical. Independent disassembly used `objdump -d -Mintel --start-address=0x45edc0 --stop-address=0x45ef62 research/binaries/us/Drakan.exe`.

The first wrapper execution failed because Ghidra attempted to save its Java selection outside the sandbox. Isolating XDG config/cache resolved that problem; both subsequent executions completed. Missing system DLLs in an earlier import log and unresolved prior analysis completeness do not imply complete xrefs.
