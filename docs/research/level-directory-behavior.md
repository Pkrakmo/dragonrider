# Level database-list record

**Date:** 2026-10-17. **Input:** unpatched US retail
`research/binaries/us/Drakan.exe`, SHA-256
`23630f48e20e8a9f42026501165ae1df407cfcee545a784ec930a4c25ee70648`,
verified using `sha256sum`; private retail files and their individual hashes are
listed in the existing `research/exports/asset-inventory/us.json`.
**Method:** GNU `objdump` bounded instruction windows and PE imports; Python
3 independently decodes the retail bytes and checks each inventory hash.
No Ghidra project was accessed; Ghidra version 12.1.4 is not part of this
method. **Confidence:** high for the stated static instructions and measured
samples, limited for other paths and editions. No game was executed.

## Observed in the executable

- At `0x00436f21`, the function beginning at `0x00436eb0` opens a supplied
  path with the SRSC loader. Its diagnostics at `0x0047d344`–`0x0047d390`
  refer to a level file and databases. The open path is supplied by the caller;
  this trace does not establish a filename extension requirement.
- It looks up `(0x0402, 0, 0)` and, if found, reads a dword. The initially
  set value is `0x100`; the continuation examined here requires `0x10c`
  (`0x00436f81`–`0x00436fc0`). It then selects `(0, 0, 0)` at
  `0x00436fdf`–`0x00436fee`.
- The reader at `0x0045f430` reads a little-endian `u16` byte count and
  then consumes that many bytes. If a buffer is supplied, it copies at most
  its capacity, inserts a terminator, and skips excess. With a null buffer and
  zero capacity it skips the full byte sequence. The level path makes that
  null-buffer call at `0x00436ff4`–`0x00436ff8`.
- Next it reads two four-byte values and one four-byte count
  (`0x00436ffd`–`0x00437054`); a zero count takes a diagnostic path. For
  each positive signed count it reads one four-byte value and one length-prefixed
  byte sequence via the same helper (`0x004370d8`–`0x00437142`). It then
  passes the copied string and value to `0x0041e800`, after constructing a
  path relative to the selected level's directory. The nearby messages say
  databases are being loaded. The two earlier words are passed to
  `0x0041f1f0`, which accepts values up to 1024 on this path; their full
  meanings are not established.
- At `0x00437192` the same resource object is passed to `0x00421c30`, which
  selects `(1, 0, 0)` and reads another four-byte count. Its further content
  requires investigation; it is not decoded here.

These are path-specific observations. In particular, copying into a 256-byte
runtime buffer does not establish the raw byte sequence's encoding or a safe
filesystem path policy. Some read return values are unchecked in the original
path; DragonRider checks them.

## Observed in the selected retail files

The reproducible verification script selects `.lvl` entries with candidate
SRSC tables from the private installed-US inventory, verifies each whole-file
SHA-256 against that inventory, finds exactly one `(0,0,0)` record per file,
independently decodes the prefix, and compares all values and name CRC32s with
the C++ inspector. All **23/23** files matched, with **164** entries in total,
four to ten entries per file, no bytes left after the parsed prefix, and one
matching `(0x0402,0,0)` gate containing `0x10c` in each file. The scan does
not prove extraction completeness or behavior of other versions.

## Unknown and implications

The leading sequence's meaning, the two dwords' meaning, byte encoding,
database identifiers, path semantics, runtime associations, other record types,
and geometry are unresolved. Raw path bytes are untrusted and must not be
opened or joined automatically. The structural reader accepts zero entries
and opaque trailing data; this is an input inspection policy, not a claim that
the original loader accepts them. It rejects negative signed counts and
enforces bounds and a caller-supplied count limit; the inspector limits each
payload to 32 MiB and the count to 4,096. It does not enforce the version gate
or prove that an arbitrary `(0,0,0)` record is a level directory.

## Reproduction

```sh
sha256sum research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x436eb0 --stop-address=0x4371e3 research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x45f430 --stop-address=0x45f4c3 research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x41e800 --stop-address=0x41e870 research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x41f1f0 --stop-address=0x41f21a research/binaries/us/Drakan.exe
objdump -s --start-address=0x47d318 --stop-address=0x47d3c8 research/binaries/us/Drakan.exe
python3 tools/research/verify_level_directory.py build/debug/dragonrider_inspect research/installed/us research/exports/asset-inventory/us.json
```
