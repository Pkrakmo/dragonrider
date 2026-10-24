# `(1,0,0)` query wrapper table scan — 2026-10-23

**Input:** unpatched US `Drakan.exe`, SHA-256
`23630f48e20e8a9f42026501165ae1df407cfcee545a784ec930a4c25ee70648`.
**Method:** GNU objdump 2.45.1-5.fc43 bounded static inspection; no Ghidra,
game execution, or private export.

## Observed

The wrapper begins at `0x0044c9f0` and directly calls `0x00420960` at
`0x0044ca10`. A scan of the executable `.rdata` dump found no little-endian
`0x0044c9f0` pointer, so this scan supplies no static vtable/table slot for
the wrapper. The nearby indirect call at `0x0040cc15` is through an unrelated
receiver's `+0x5c` slot; this instruction alone does not identify its dynamic
target as the wrapper.

## Unknown

The wrapper may still be entered through an indirect, virtual, tail-jump,
unrecovered, or non-`.rdata` route. No caller identity, forwarded value, or
runtime reachability follows from the absent `.rdata` pointer.

## Reproduction

```sh
sha256sum research/binaries/us/Drakan.exe
objdump --version | head -n 1
objdump -s -j .rdata research/binaries/us/Drakan.exe | rg 'f0c94400'
objdump -d -Mintel --start-address=0x44c9d0 --stop-address=0x44ca30 research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x40cc00 --stop-address=0x40cc35 research/binaries/us/Drakan.exe
```
