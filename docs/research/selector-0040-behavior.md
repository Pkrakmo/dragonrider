# Selector 0x0040 texture-loading path

**Date:** 2026-10-17. **Input:** unpatched US retail
`research/binaries/us/Drakan.exe`, SHA-256
`23630f48e20e8a9f42026501165ae1df407cfcee545a784ec930a4c25ee70648`
(rechecked with `sha256sum`). **Method:** Ghidra 12.1.4, existing
`Drakan_US_Retail` project, `-process Drakan.exe -readOnly -noanalysis`,
`tools/ghidra/scripts/TraceSelector0040.java`, bounded instruction windows;
GNU `objdump` independently checked the instructions and diagnostic strings.
Private Ghidra log: `research/ghidra-logs/selector-0040/run-3C8vXiLg/`.
**Confidence:** high for the specific selected path and field reads; medium
for extending the labels to all selector-0x0040 entries. Static database xrefs
and prior analysis may be incomplete. The program was not executed.

## Observed

- At `0x004358b1`, function `0x00435840` passes index 3 to the path builder
  `0x0041e470` if its resource object is not already open. The path builder's
  index 3 conditionally appends `.txd` (see `loader-callers.md`). At
  `0x004358cb–0x004358d4` it passes selector `0x0040` and an ID to
  `0x0045f230`. The latter calls `0x0045fa10`, then selects the returned index
  using `0x0045f270`. The search at `0x0045fa10` compares the selector to the
  16-bit word at record offset 0 and the low 16 bits of the ID to the word at
  record offset 2, stopping on the first match; it does not compare the word at
  offset 4 on this path.
- At `0x00435902`, `0x0043590e` and `0x0043591a`, the selected resource's
  stream is read in three consecutive four-byte units. The helper at
  `0x0045f370` invokes the bounded resource read for four bytes. At
  `0x0043597c`, another helper `0x0045f3a0` reads two bytes. Diagnostic
  strings at `0x0047d2e0` and `0x0047d2ac`, together with the argument order
  at `0x0043595e–0x00435970` and `0x004359f8–0x00435a10`, identify the first
  two units as texture width and height, and the 16-bit value at offset 12 as
  texture bit depth. The third four-byte unit at offset 8 is used as a read
  size per row on the branch described below. Values are little-endian on this
  PE32 i386 path.
- After those 14 bytes, the path reads five four-byte units, two more four-byte
  units, skips four bytes, then reads another four-byte unit; the cursor is
  then at payload offset 50. Return codes of these individual header reads are
  not checked in this sequence. A safe independent implementation must check
  them. The roles of these intervening fields are not yet established.
- At `0x00435bc4–0x00435bca`, the last value read, a dword at payload offset
  46, is compared as a signed value with zero. When it is nonpositive, the
  branch at `0x00435cf6–0x00435d28` loops over the height and calls the bounded
  resource read once per row with the offset-8 value as requested byte count;
  destination addresses advance by a surface pitch. This is direct evidence
  of a row-based, uncompressed read branch, not a complete pixel format. When
  the offset-46 value is positive, the other branch reads a four-byte length,
  then that many bytes into a buffer, and invokes `0x00462a00` once per row
  with the offset-8 value as output budget. The current trace does not fully
  establish what every positive offset-46 value means.
- After the row data, if bit `0x100` in the dword at payload offset 34 is
  set, the positive branch reads another four-byte length and skips that many
  bytes (`0x00435c99–0x00435cc6`); the nonpositive branch skips
  `height * row-byte count` bytes (`0x00435d2a–0x00435d3d`). The identity and
  use of the skipped data are unknown. A minimal decoded base-row result does
  not describe or validate that additional data.
- This particular path accepts width values 4, 8, 16, 32, 64, 128 and 256;
  otherwise it follows a diagnostic path. It separately accepts depth 8 or 16
  at `0x004359df–0x004359e7`. These are runtime-path observations, not global
  file validation rules. Among inventoried `0x0040` examples there are other
  widths and depths; reachability, other consuming paths, and why these values
  occur remain unknown.
- The private `Dragon.rrc` sample described in `srsc-payload-observations.md`,
  SHA-256 `fb1e403bd33b370cc64fe1ac296b3cf889e524ff2279eca2a27b65911f0ca72a`,
  record 67 at offset 2,950,439 and length 2,098, begins with width 32, height
  32, row byte count 64 and depth 16; its dword at offset 46 is zero. Its
  record length equals `50 + 32 * 64`. This is consistent with the nonpositive
  branch. It does not establish its pixel channel layout. In the same file,
  record 474 has width 192, depth 16 and offset-46 dword 1: the selected path
  would take its unsupported-width diagnostic rather than the row path.
- An independent Python 3.14.7 `zlib.decompressobj` test scanned the same
  installed US selection of 5,993 bounded selector-0x0040 ranges described in
  `srsc-payload-observations.md`. The 5,991 entries with dword 1 at offset 46
  all have an in-range length at offset 50; the bytes at offset 54 decode as
  complete zlib streams, with no unused or unconsumed input and output length
  exactly `height * row-byte count`. Each output was limited to the expected
  length plus one and the expected size was limited to 128 MiB. The other two
  entries have dword 0 at offset 46. This is a measurement of this extraction,
  not a proof for other versions or values. Exact pixel packing remains unknown.

## Inferred and unknown

### Selector comparison follow-up (2026-10-18)

A read-only Ghidra 12.1.4 trace on a fresh disposable US retail import and
independent `objdump` disassembly identify a separate path at `0x0042c140`.
It passes `(0x0040, supplied value, 0)` to `0x0045f910`, which returns the
first matching three-word table index or `-1`. The latter uses the same
second-word ordering flag and first-triple search pattern described in
[SRSC lookup order](srsc-lookup-order.md); unlike `0x0045f0d0`, this traced
function returns an index without seeking the record. This path and the
two-word path above do not have identical comparison rules. Static evidence
alone does not establish that both are used for the same runtime file.

An independent scan rechecked all 178 SRSC input hashes against the private
inventory and modeled the two lookups on each file's stable second-word
ordering. Across 39 files, all 5,993 `0x0040` records had third word zero and
distinct `(first, second)` pairs within their file. For those sampled pairs,
the two modeled lookups select the same record. This observation is not a
universal requirement: synthetic tests include nonzero third words and show
that the two comparisons can select different records or that the zero-third
lookup can find none. No game execution, runtime source equivalence or other
editions were checked. The scan and tests can be repeated with:

```sh
python3 tools/research/measure_texture_selector_lookup.py research/installed/us research/exports/srsc-records/us.json
python3 -m unittest discover -s tools/research -p 'test_measure_texture_selector_lookup.py' -v
objdump -d -Mintel --start-address=0x42c140 --stop-address=0x42c15f research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x45f910 --stop-address=0x45fa6d research/binaries/us/Drakan.exe
```

For the bounded Ghidra callsites and windows, first create a disposable project
as described in [Ghidra guidance](../GHIDRA.md), then run with `dr_workspace`
set to its root and `GHIDRA_HOME` configured:

```sh
XDG_CONFIG_HOME="$dr_workspace/config" XDG_CACHE_HOME="$dr_workspace/cache" \
JAVA_TOOL_OPTIONS="-Duser.home=$dr_workspace" \
"$GHIDRA_HOME/support/analyzeHeadless" "$dr_workspace/project" Disposable_Drakan \
  -process Drakan.exe -readOnly -noanalysis -scriptPath "$PWD/tools/ghidra/scripts" \
  -postScript TraceSrscSelectorCalls.java -log "$dr_workspace/selectors.log" \
  -scriptlog "$dr_workspace/selectors-script.log" > "$dr_workspace/selectors-console.log" 2>&1
```

Its output and the original inputs remain private.

The observations support a texture-header interpretation for the traced path,
with `u32 width`, `u32 height`, `u32 row-byte count`, and `u16 bit depth` at
payload offsets 0, 4, 8 and 12. The earlier measurement's fourth `u32` spans
both this `u16` and two bytes of the next field; its upper half should not be
interpreted as part of bit depth. The row path supports developing a limited
header or row inspector, with bounds and overflow checks and no assumptions
about raw pixel packing. It does not justify a general texture decoder,
renderer, or rejecting entries by the runtime's width/depth checks. Color
masks, palettes, row orientation, fields after offset 14, positive-branch
values other than 1, the selector's other consumers and editions remain unknown.

## Reproduction

Close Ghidra GUI sessions using this project. A process listing cannot prove
GUI closure. Verify project name and hash, acquire the cooperative wrapper
lock, and use unique private output:

```sh
find research/ghidra-projects -maxdepth 1 -name '*.gpr' -print
sha256sum research/binaries/us/Drakan.exe
exec 9>research/ghidra-projects/.drakan-loader-probe.lock
flock -n 9 || exit 1
mkdir -p research/ghidra-logs/selector-0040
run=$(mktemp -d "$PWD/research/ghidra-logs/selector-0040/run-XXXXXXXX")
mkdir -p "$run/config" "$run/cache"
export XDG_CONFIG_HOME="$run/config" XDG_CACHE_HOME="$run/cache"
"$GHIDRA_HOME/support/analyzeHeadless" \
  "$PWD/research/ghidra-projects" Drakan_US_Retail -process Drakan.exe \
  -readOnly -noanalysis -scriptPath "$PWD/tools/ghidra/scripts" \
  -postScript TraceSelector0040.java -log "$run/ghidra.log" \
  -scriptlog "$run/script.log" > "$run/console.log" 2>&1
exec 9>&-
```

The cooperative lock does not detect a GUI session. Independent checks:

```sh
objdump -d -Mintel --start-address=0x4358a7 --stop-address=0x435a6d research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x435bc4 --stop-address=0x435d29 research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x45f230 --stop-address=0x45f26b research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x45f370 --stop-address=0x45f3cd research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x45fa10 --stop-address=0x45facd research/binaries/us/Drakan.exe
objdump -s --start-address=0x47d270 --stop-address=0x47d318 research/binaries/us/Drakan.exe
```

The selected sample's fields can be independently read with Python's
`struct.unpack('<IIIH9I', data)` on exactly 50 bytes starting at the stated
record offset. Neither sample contents nor Ghidra output are committed.

The bounded zlib measurement can be repeated without writing game data:

```sh
python3 - <<'PY'
from pathlib import Path
from collections import Counter
import struct, zlib
c = Counter()
for p in Path('research/installed/us').rglob('*'):
    if not p.is_file():
        continue
    data = p.read_bytes()
    if len(data) < 12 or data[:4] != b'SRSC':
        continue
    version, table, count = struct.unpack_from('<HIH', data, 4)
    if version != 256 or table < 12 or table + 14 * count > len(data):
        continue
    for i in range(count):
        key, _, _, pos, size = struct.unpack_from('<HHHII', data, table + 14 * i)
        if key != 64 or pos < 12 or size < 50 or pos + size > table:
            continue
        width, height, row, depth, *fields = struct.unpack_from('<IIIH9I', data, pos)
        flag = fields[8]
        c[f'flag_{flag}'] += 1
        if flag != 1:
            continue
        if size < 54:
            c['short'] += 1
            continue
        length = struct.unpack_from('<I', data, pos + 50)[0]
        expected = height * row
        if length > size - 54 or expected > 128 * 1024 * 1024:
            c['bounds'] += 1
            continue
        stream = zlib.decompressobj()
        try:
            decoded = stream.decompress(data[pos + 54:pos + 54 + length], expected + 1)
        except zlib.error:
            c['error'] += 1
            continue
        c['equal' if len(decoded) == expected else 'different'] += 1
        c['eof' if stream.eof else 'no_eof'] += 1
        c['unused' if stream.unused_data else 'no_unused'] += 1
        c['unconsumed' if stream.unconsumed_tail else 'no_unconsumed'] += 1
print(dict(c))
PY
```

Observed counts: `flag_1=5991`, `flag_0=2`, `equal=5991`, `eof=5991`,
`no_unused=5991`, `no_unconsumed=5991`; no error counters occurred.
