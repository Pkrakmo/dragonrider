# Level `(1,0,0)` wrapper address-reference check — 2026-10-23

**Input:** unpatched US `Drakan.exe`, SHA-256
`23630f48e20e8a9f42026501165ae1df407cfcee545a784ec930a4c25ee70648`.
**Method:** bounded GNU objdump 2.45.1-5.fc43 disassembly; no Ghidra, game
execution, media inspection, or private export.

## Observed

The wrapper at `0x0044c9f0` has a direct relative CALL at `0x0044c940`.
The bounded caller window pushes zero, a stack-local address, and `esi` before
the call. It is adjacent to a literal-4 call to `0x00420e10` at `0x0044c95f`.
This corrects the earlier text-scan claim that no direct relative CALL reached
the wrapper.

The shown wrapper forwards its fourth stack argument as the seventh argument
to `0x00420960`; the bounded caller establishes that fourth argument as zero
on this direct edge. Therefore this edge cannot reach the wrapper's nonzero
seventh-argument branch as written.

No pointer occurrence was established by a bounded `.rdata` byte scan. That
is not evidence of no data, indirect, virtual, tail-jump, or unrecovered
references.

## Reproduction

```sh
sha256sum research/binaries/us/Drakan.exe
objdump --version | head -n 1
objdump -d -Mintel --start-address=0x0044c900 --stop-address=0x0044ca18 \
  research/binaries/us/Drakan.exe
objdump -s --start-address=0x00475000 --stop-address=0x00476000 \
  research/binaries/us/Drakan.exe
```
