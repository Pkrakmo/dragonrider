# Indexed texture palette loading and conversion

**Date:** 2026-10-17. **Input:** unpatched US retail
`research/binaries/us/Drakan.exe`, SHA-256
`23630f48e20e8a9f42026501165ae1df407cfcee545a784ec930a4c25ee70648`.
**Method:** Ghidra 12.1.4, existing `Drakan_US_Retail` project, read-only
`-process Drakan.exe -noanalysis`, bounded instruction windows in
`tools/ghidra/scripts/TraceTexturePalette.java`, independently checked using
GNU `objdump`; private log
`research/ghidra-logs/texture-palette/run-uUZCMf1a/`. Private installed US
SRSC files were also scanned as described below. **Confidence:** high for the
specific instructions and the shape of the measured records; medium for
generalizing these paths to other editions or runtime conditions. No game was
run and Ghidra's existing xrefs may be incomplete.

## Observed: palette records and association

The function at `0x00435540` opens the resource source through the same path
builder index 3 used by the texture loader, which conditionally appends
`.txd`. It first searches for the exact record selector tuple
`(0x0402, 0, 0)`, reads a little-endian dword if found, and proceeds only
when the resulting value is `0x204`; the initial value is `0x100`. The exact
meaning of this gate and other possible versions are not established.

The loop at `0x004355fe–0x0043562e` scans table entries in order and selects
those whose record word at offset 0 equals `0x0030` and word at offset 4 is
zero; it does not compare the word at offset 2. It selects each record and
reads a two-byte value. The helper at `0x0045f3a0` reads two bytes. At
`0x004356d3–0x00435737`, this value is stored as the count in an object and
then multiplied by four to obtain the byte count read from the current
record into the object's entry area. Thus, on this path the selected payload
begins with a little-endian `u16` count followed by `count` four-byte
entries. The original code allocates storage for 256 entries, but this is not
an argument for trusting a malformed input's count or ignoring short reads.

At `0x004356d3–0x004356f8` each allocated object is tagged with a dword from
the source object at offset `0x114`. The texture path for depth at most 8
passes the same source-object field to `0x00435780`; this helper scans the
loaded object array from the beginning and returns the **first** object whose
tag matches, or null. At `0x00435b08–0x00435b3c`, its device handle is passed
to the standard surface-creation path if present. This is a runtime source
association, not a lookup of a palette ID in the 50-byte texture header. The
tag is not the SRSC record's offset-2 word. Loading order, alternate paths,
multiple matching palettes, and missing or null handles affect reachability.

## Observed: indexed conversion

After reading base rows, two conditional branches of the texture path call
`0x00433af0` with the 8-bit surface and the associated palette object at
`0x00435e09–0x00435e10` and `0x00435f7f–0x00435f86`. In that conversion
function's 8-to-16-bit branches, each source byte indexes the object at
`object + 4 + 4 * index`. The first three entry bytes are used as the high,
middle and low color components respectively in the resulting 16-bit words:

- `0x00433dcf–0x00433e0b` packs byte 0 to bits 11–15, byte 1 to bits
  5–10, and byte 2 to bits 0–4 (RGB565).
- `0x00433cd7–0x00433d13` packs byte 0 to bits 10–14, byte 1 to bits
  5–9, and byte 2 to bits 0–4 (RGB555).
- `0x00433bf2–0x00433c3b` takes a separate one-bit-alpha branch: a
  source index matching a value obtained from `0x00433a30` becomes zero;
  other indices are packed to RGB555 with the top bit set. The conditions
  establishing and using that value require separate analysis.

These branches do not use the fourth entry byte. This supports red, green,
blue, unknown-byte ordering for the record entries on these paths; it does
not establish the fourth byte's purpose or a universal alpha rule. The
conversion processes rows using source and destination pitches, but does not
establish whether the first row is visually top or bottom, whether the
branches execute for a particular asset, or how the resulting surfaces are
composited. Surface negotiation and visual correctness remain unverified.

## Observed: bounded private US sample scan

On 2026-10-17, a scan of the installed US tree selected valid SRSC tables and
in-range records with offset-0 selector `0x0030` and offset-4 word zero. It
found 39 records in 39 files. Of these, 36 had entry count 256 and three had
count zero. Every selected payload length was exactly `2 + 4 * count`. This
measurement did not apply the runtime version gate or establish that any
individual resource was loaded, and does not prescribe a format-wide
requirement. It writes no retail bytes.

## Third-selector comparison with the bounded loader branch, 2026-10-23

The hash-pinned US retail executable's selector loop checks the third word for
zero before checking whether the first selector is `0x0030`; see the bounded
caller evidence in [the SRSC field-anchor note](srsc-record-field-anchors-2026-10-23.md).
To compare that branch with installed data, the aggregate third-selector tool
was extended to include kind `0x0030`. It verified all 178 US inventory hashes
and reported 39 `0x0030` records, with all 39 third words zero. The palette
reader's prior bounded payload measurements were unchanged. An independent
`palette_measure.py` scan also reported 39 candidate records with offset-4
word zero; its 178 examined paths and SHA-256 values exactly matched the SRSC
inventory.

This matches the observed zero-predicate branch in the inventoried US sample;
it does not establish why the third word is zero, whether other `0x0030`
records exist in other editions or unextracted files, or a format-wide rule.
Reproduce with:

```sh
python3 tools/research/measure_srsc_third_selector_distribution.py \
  research/installed/us research/exports/srsc-records/us.json
python3 -m unittest discover -s tools/research \
  -p 'test_measure_srsc_third_selector_distribution.py' -v
```

## Reproduction

Close Ghidra GUI sessions using the project. The cooperative lock does not
detect a GUI session. Verify the project and executable, then run:

```sh
find research/ghidra-projects -maxdepth 1 -name '*.gpr' -print
sha256sum research/binaries/us/Drakan.exe
exec 9>research/ghidra-projects/.drakan-loader-probe.lock
flock -n 9 || exit 1
mkdir -p research/ghidra-logs/texture-palette
run=$(mktemp -d "$PWD/research/ghidra-logs/texture-palette/run-XXXXXXXX")
mkdir -p "$run/config" "$run/cache"
export XDG_CONFIG_HOME="$run/config" XDG_CACHE_HOME="$run/cache"
"$GHIDRA_HOME/support/analyzeHeadless" \
  "$PWD/research/ghidra-projects" Drakan_US_Retail -process Drakan.exe \
  -readOnly -noanalysis -scriptPath "$PWD/tools/ghidra/scripts" \
  -postScript TraceTexturePalette.java -log "$run/ghidra.log" \
  -scriptlog "$run/script.log" > "$run/console.log" 2>&1
exec 9>&-
```

Independently check `0x00435540–0x004357bb`,
`0x0043597c–0x004359a0`, `0x00435b08–0x00435b3c`,
`0x00435d75–0x00435e10`, `0x00435f4f–0x00435f86`,
`0x00433ba1–0x00433e0b`, `0x0045fa70–0x0045faf4`,
and `0x0045f2d0–0x0045f3cd` with `objdump -d -Mintel`. Repeat the sample
measurement, without displaying or writing game data:

```sh
python3 - <<'PY'
from pathlib import Path
from collections import Counter
import struct
counts = Counter()
files = 0
for path in Path('research/installed/us').rglob('*'):
    if not path.is_file():
        continue
    with path.open('rb') as f:
        header = f.read(12)
        if len(header) != 12 or header[:4] != b'SRSC':
            continue
        version, table, total = struct.unpack_from('<HIH', header, 4)
        if version != 256 or table < 12 or table + 14 * total > path.stat().st_size:
            continue
        f.seek(table)
        entries = f.read(14 * total)
        matches = 0
        for i in range(total):
            selector, _, auxiliary, start, length = struct.unpack_from('<HHHII', entries, 14 * i)
            if selector != 48 or auxiliary != 0 or start < 12 or start + length > table or length < 2:
                continue
            f.seek(start)
            count = struct.unpack('<H', f.read(2))[0]
            counts['records'] += 1
            counts['count_' + str(count)] += 1
            counts['length_delta_' + str(length - (2 + count * 4))] += 1
            matches += 1
        if matches:
            files += 1
print('files', files, dict(counts))
PY
```

## Inspector snapshot recheck, 2026-10-23

`verify_palette_inspector.py` now validates each candidate file's recorded size
and SHA-256, parses the selected table and entry bytes from that same snapshot,
and passes a per-file temporary copy to `dragonrider_inspect`. Three synthetic
tests cover a successful comparison, a stale hash and a symlinked inventory
path. Debug and release inspectors each matched 39/39 palette entry summaries
again. This confirms the selected byte comparisons against the hash-verified
inputs; it does not establish universal palette resolution or visual output.

```sh
python3 tools/research/verify_palette_inspector.py build/debug/dragonrider_inspect research/installed/us research/exports/asset-inventory/us.json
python3 tools/research/verify_palette_inspector.py build/release/dragonrider_inspect research/installed/us research/exports/asset-inventory/us.json
```
