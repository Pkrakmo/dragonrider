# `(1,0,0)` query-wrapper non-`.rdata` pointer scan — 2026-10-23

**Input:** unpatched US `Drakan.exe`, SHA-256 `23630f48e20e8a9f42026501165ae1df407cfcee545a784ec930a4c25ee70648`.
**Method:** GNU objdump 2.45.1-5.fc43 bounded section dumps; no Ghidra, execution, media inspection, or private export.

## Observed

The PE has `.text`, `.rdata`, `.data`, and `.rsrc` sections. Searches of initialized non-`.rdata` section dumps for the little-endian wrapper address `0x0044c9f0` (`f0 c9 44 00`) found no occurrence in `.text`, `.data`, or `.rsrc`. This extends the earlier `.rdata` absence result, but does not prove the wrapper has no pointer reference.

## Unknown

The scan does not cover computed targets, relocations, imports, register or stack construction, pointer transforms, dynamically written tables, indirect calls, or unrecovered code. It does not establish reachability or the wrapper fourth argument's value.

## Reproduction

```sh
sha256sum research/binaries/us/Drakan.exe
objdump --version | head -n 1
objdump -h research/binaries/us/Drakan.exe
objdump -s -j .text research/binaries/us/Drakan.exe | rg -n -i 'f0c94400'
objdump -s -j .data research/binaries/us/Drakan.exe | rg -n -i 'f0c94400'
objdump -s -j .rsrc research/binaries/us/Drakan.exe | rg -n -i 'f0c94400'
```
