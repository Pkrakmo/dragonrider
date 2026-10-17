# Palette absence and keyed indexed conversion

**Date:** 2026-10-17. **Input:** unpatched US retail
`research/binaries/us/Drakan.exe`, SHA-256
`23630f48e20e8a9f42026501165ae1df407cfcee545a784ec930a4c25ee70648`.
**Method:** Ghidra 12.1.4, existing `Drakan_US_Retail` project, read-only
`-process Drakan.exe -noanalysis`, bounded instruction windows in
`tools/ghidra/scripts/TraceTextureFallback.java`, independently checked using
GNU `objdump`; private log
`research/ghidra-logs/texture-fallback/run-HKlpXlM5/`. **Confidence:** high
for the stated static instructions on these paths, medium for their runtime
meaning. No game was run; device behavior, alternate paths, and editions may
vary. This extends [the palette trace](texture-palette-behavior.md).

## Observed: zero count and absent matching object

In the selected palette-loading loop, there is no count-zero branch between
the two-byte count read and object construction at `0x0043562e–0x00435746`.
The loader requests a `0x410`-byte object and, on successful allocation, records the count and source tag,
requests `count * 4` entry bytes, and calls `0x00433480`, including when the
count is zero. At `0x0043349d–0x004334b0`, that helper passes the entry area
at object offset 4 to a device method and saves its returned handle. The
specific entry-buffer contents after a zero-byte read, device behavior, and
eventual rendering are not established. These instructions do not show a
replacement palette being populated from another resource.

The first-match lookup at `0x00435780–0x004357bb` compares the stored tag
and does not test entry count or device handle. When there is no matching
object it returns null. On the standard depth-at-most-8 surface creation
path at `0x00435b08–0x00435b3c`, a missing object results in a null handle
argument; a present object contributes its stored device handle, which may
itself be null. That observation does not establish whether the surface
device provides a fallback or fails.

Two subsequent indexed conversion call sites pass the associated object
directly to `0x00433af0`; the byte-indexing code at `0x00433bf2–0x00433c3b`
does not check the object pointer or entry count before reading entry bytes
for a non-key index. Reachability and error handling at runtime are not
established. An independent implementation should not treat a zero-count
record or absent association as a usable palette based on this trace.

## Observed: a keyed indexed-to-16-bit path

On this loader path the dword at texture payload offset 18 is passed to a
virtual method at `0x00435ba5–0x00435bb3`, unless it is `0xffffffff`. The
texture object receives vtable `0x004757f0` at `0x004353ac`; raw `.rdata`
shows its slot at offset `0x0c` points to `0x004339e0`. The latter marks a
flag on the object for a non-sentinel value and passes that value twice to a
surface method. Getter `0x00433a30` checks that flag, calls a surface method
and returns its first value on success, or `0xffffffff` when the flag is
absent or the surface call fails. This traces the value through the virtual
dispatch; it does not prove the device returns the original value unchanged.

When the device-state field tested at `0x00435d75` is nonzero, the getter
does not return `0xffffffff`, and the source depth is 8, the loader requests
a 16-bit surface and calls `0x00433af0` (`0x00435d86–0x00435e10`). In its
one-bit-alpha indexed branch, the 8-bit source index is compared with the
getter's full 32-bit result: equality yields a zero output word; otherwise
RGB comes from the palette and the top bit is set. The branch is conditional
on runtime device state and surface behavior. It does not establish a
file-wide transparency rule, palette byte 3 semantics, visible compositing,
or orientation.

## Reproduction

Close Ghidra GUI sessions using this project; the cooperative lock does not
detect them. Verify the project and executable and run:

```sh
find research/ghidra-projects -maxdepth 1 -name '*.gpr' -print
sha256sum research/binaries/us/Drakan.exe
exec 9>research/ghidra-projects/.drakan-loader-probe.lock
flock -n 9 || exit 1
mkdir -p research/ghidra-logs/texture-fallback
run=$(mktemp -d "$PWD/research/ghidra-logs/texture-fallback/run-XXXXXXXX")
mkdir -p "$run/config" "$run/cache"
export XDG_CONFIG_HOME="$run/config" XDG_CACHE_HOME="$run/cache"
"$GHIDRA_HOME/support/analyzeHeadless" \
  "$PWD/research/ghidra-projects" Drakan_US_Retail -process Drakan.exe \
  -readOnly -noanalysis -scriptPath "$PWD/tools/ghidra/scripts" \
  -postScript TraceTextureFallback.java -log "$run/ghidra.log" \
  -scriptlog "$run/script.log" > "$run/console.log" 2>&1
exec 9>&-
```

Independently check instructions at `0x0043561f–0x0043574d`,
`0x00435780–0x004357bb`, `0x00433480–0x004334be`,
`0x0043539c–0x004353c5`, `0x0043597c–0x004359c7`,
`0x00435b08–0x00435b3c`, `0x00435ba5–0x00435bb6`,
`0x004339e0–0x00433a5c`, `0x00433ba1–0x00433c3b`, and
`0x00435d75–0x00435e10` with `objdump -d -Mintel`. Check the vtable with
`objdump -s --start-address=0x4757f0 --stop-address=0x475800`.
