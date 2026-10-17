# Texture surface creation and palette attachment

**Date:** 2026-10-17. **Input:** unpatched US retail
`research/binaries/us/Drakan.exe`, SHA-256
`23630f48e20e8a9f42026501165ae1df407cfcee545a784ec930a4c25ee70648`.
**Method:** Ghidra 12.1.4, existing `Drakan_US_Retail` project, read-only
`-process Drakan.exe -noanalysis`, bounded instruction windows in
`tools/ghidra/scripts/TraceTextureDevice.java`, independently checked with
GNU `objdump`; private log `research/ghidra-logs/texture-device/run-Rom3g6VZ/`.
**Confidence:** high for the stated static control flow, medium for the
interpretation of device interface operations. No game or graphics driver was
run; other code paths and editions are not covered. This extends the
[palette fallback trace](texture-fallback-behavior.md).

## Observed: palette handle and failure

On the standard surface path, `0x00435b08–0x00435b3c` passes a null handle
unless the depth is at most eight and the previously associated object is
non-null, in which case it passes the object's stored device handle. The
surface-creation helper `0x00433570` first calls a device virtual method with
its descriptor and an output pointer (`0x0043386a–0x0043387f`). A nonzero
return exits the helper without reaching the subsequent attachment call.

If surface creation returns zero, the helper tests for depth exactly 8 and
a non-null handle (`0x004338b0–0x004338be`). Only then does it call the
new surface's virtual slot at byte offset `0x7c`, passing that handle. If the
slot returns a nonzero value, another virtual slot is called on the surface,
the stored surface pointer is cleared, and the helper returns 1
(`0x004338c0–0x004338e6`). The caller tests this result and, on nonzero,
abandons the texture rather than continuing to row loading
(`0x00435b41–0x00435ba0`). A zero return from the slot continues to later
surface setup; later setup may itself fail.

Thus, on this path, a null handle **skips** the attachment call; it does not
cause a software palette to be populated here. A failed non-null attachment
does not trigger a retry with a different handle in this helper. The method
at slot `0x7c` is consistent with a DirectDraw surface palette-attachment
operation, and the subsequent slot with a release operation, but identifying
the device's concrete object and its defaults requires further evidence. The
effect of skipping attachment, the contents of a zero-count object's entry
buffer, and whether later rendering succeeds remain unknown. This does not
prove a universal fallback rule or behavior on the alternate branch at
`0x00435b27`.

## Observed: device-dependent surface dimensions

The helper also conditionally adjusts the dimensions supplied to the surface
descriptor. At `0x00433591–0x004335fc`, when its flags do not contain `0x40`
and a device-state field is nonzero, bit 0 of a second device-state field
causes each dimension to be rounded upward by repeated doubling from one;
bit 1 then makes both dimensions the larger of the two. At
`0x0043364d–0x0043366a`, the descriptor width is doubled again on a separate
8-bit/flag-`0x10` branch. These are conditional requested surface dimensions,
not restrictions on valid retail files, and do not establish the actual
accepted format, pitch, row orientation, or displayed UV coordinates.

## Reproduction

Close Ghidra GUI sessions using this project. Verify the project and executable,
then run the bounded trace in a unique private directory:

```sh
find research/ghidra-projects -maxdepth 1 -name '*.gpr' -print
sha256sum research/binaries/us/Drakan.exe
exec 9>research/ghidra-projects/.drakan-loader-probe.lock
flock -n 9 || exit 1
mkdir -p research/ghidra-logs/texture-device
run=$(mktemp -d "$PWD/research/ghidra-logs/texture-device/run-XXXXXXXX")
mkdir -p "$run/config" "$run/cache"
export XDG_CONFIG_HOME="$run/config" XDG_CACHE_HOME="$run/cache"
"$GHIDRA_HOME/support/analyzeHeadless" \
  "$PWD/research/ghidra-projects" Drakan_US_Retail -process Drakan.exe \
  -readOnly -noanalysis -scriptPath "$PWD/tools/ghidra/scripts" \
  -postScript TraceTextureDevice.java -log "$run/ghidra.log" \
  -scriptlog "$run/script.log" > "$run/console.log" 2>&1
exec 9>&-
```

The cooperative lock does not detect GUI sessions. Independently check
`0x00433591–0x0043366a`, `0x0043386a–0x004339d2`, and
`0x00435b08–0x00435ba0` with `objdump -d -Mintel`, starting at an instruction
boundary. No private executable bytes or Ghidra output are committed.
