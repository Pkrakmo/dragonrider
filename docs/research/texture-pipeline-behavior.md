# Texture stream and requested surface format

**Date:** 2026-10-17. **Input:** unpatched US retail
`research/binaries/us/Drakan.exe`, SHA-256
`23630f48e20e8a9f42026501165ae1df407cfcee545a784ec930a4c25ee70648`.
**Method:** Ghidra 12.1.4 on the existing `Drakan_US_Retail` project using
`-process Drakan.exe -readOnly -noanalysis`, bounded instruction windows in
`tools/ghidra/scripts/TraceTexturePipeline.java`, independently checked with
GNU `objdump`; plus private retail sample measurements in
`selector-0040-samples.md`. Private log:
`research/ghidra-logs/texture-pipeline/run-dukZdKgX/`. **Confidence:** high
for instruction behavior on the selected path; medium for interpreting the
descriptor as the ultimate displayed image format. Static analysis only; the
game was not run and other paths and editions may differ.

## Observed: stream and rows

The selected `0x0040` path and offsets are described in
`selector-0040-behavior.md`. In the signed-positive branch at `0x00435bd0`, a
32-bit length is read after the 50-byte header, followed by that many input
bytes. At `0x00435c18–0x00435c70` the loader configures one state object with
that input buffer, then calls `0x00462a00` once per row, passing 4 as its
second argument. It updates the output buffer to `surface_base + row * pitch`
and the available output to the row-byte field for each call, reusing the
same state. It does not check the calls' return values. The nonpositive branch
likewise writes each sequentially read row to `surface_base + row * pitch`.

The code at `0x00462a48–0x00462af7` checks the first input byte's low nibble
for 8, checks the implied window size against a limit, and checks that the
two-byte big-endian header is divisible by 31. Error strings in the executable
at `0x0047db50`, `0x0047db68` and `0x0047db7c` refer respectively to header
check, window size and compression method. This behavior, together with the
independent complete zlib streams in 5,991/5,991 measured positive samples,
supports zlib-wrapped DEFLATE for those examples. It does not establish all
positive storage-word values or justify ignoring decompression errors, input
limits, end-of-stream or trailing bytes in an independent implementation.

When offset-34 bit `0x100` is set, this path skips a second block rather than
decoding it. Its purpose is unknown. The two measured trailing-block samples
both have this bit set. The code establishes the order in memory, not whether
the first row is visually top or bottom. Pitch and display orientation are
properties of the destination surface and rendering path, not established
file-wide invariants.

## Observed: requested 16-bit surface masks

At `0x00435a6d–0x00435b41`, values read from payload offset 34 (a 32-bit
flags word) and offset 14 (a 32-bit word) form arguments to `0x00433570` on
the standard branch. That function builds a surface descriptor including a
pixel depth and four masks. The later call at `0x00435bb6–0x00435bc1` obtains
the destination buffer, and the above row paths write into it. For depth 16,
the following masks are requested in the descriptor, in the R, G, B, alpha
field order. Tests are ordered: the first applicable row controls the result.

| Conditions on offset 34 and offset 14 | R | G | B | Alpha |
| --- | ---: | ---: | ---: | ---: |
| `flags & 0x200`, offset-14 word = 1 | `0x7c00` | `0x03e0` | `0x001f` | `0x8000` |
| `flags & 0x200`, offset-14 word = 4 | `0x0f00` | `0x00f0` | `0x000f` | `0xf000` |
| `flags & 0x200`, offset-14 word = 8 | `0x00e0` | `0x001c` | `0x0003` | `0xff00` |
| `!(flags & 0x200)`, `!(flags & 0x100000)`, `flags & 0x2000` | `0x7c00` | `0x03e0` | `0x001f` | `0` |
| `!(flags & 0x200)`, `!(flags & 0x100000)`, `!(flags & 0x2000)` | `0xf800` | `0x07e0` | `0x001f` | `0` |

Other cases are intentionally not specified by this table. In particular,
the offset-14 value 2 takes a different descriptor branch; other values and
flag combinations require separate analysis. A branch at `0x00435b27` also
bypasses this standard surface-creation call. The 16-bit masks are strong
evidence about the packed words on this particular path because rows are
copied into the requested surface without an intervening pixel conversion;
they are not independent visual confirmation of every sample, actual surface
negotiation, color-key behavior, alpha blending, or orientation.

For depths up to 8, the loader calls `0x00435780` with a resource identifier,
then passes a pointer from the matching object into surface creation. That is
consistent with an external palette association but does not establish the
palette record format, channel order, or lookup behavior on every path.

The two measured records with trailing blocks have offset-14 word 8 and
offset-34 bit `0x100` set. A quick independent enumeration over the 5,993
private measured records also found 2,996 with depth 16, offset-14 word 0 and
flags `0x0000000a`; 915 with depth 16, offset-14 word 4 and flags `0x0000220a`;
and 783 with depth 16, offset-14 word 4 and flags `0x0000020a`. This is an
inventory of header combinations, not proof that each was reached or displayed.

## Reproduction

Close every Ghidra GUI session using this project; the cooperative lock does
not detect a GUI. Confirm project path and executable hash. Then run:

```sh
find research/ghidra-projects -maxdepth 1 -name '*.gpr' -print
sha256sum research/binaries/us/Drakan.exe
exec 9>research/ghidra-projects/.drakan-loader-probe.lock
flock -n 9 || exit 1
mkdir -p research/ghidra-logs/texture-pipeline
run=$(mktemp -d "$PWD/research/ghidra-logs/texture-pipeline/run-XXXXXXXX")
mkdir -p "$run/config" "$run/cache"
export XDG_CONFIG_HOME="$run/config" XDG_CACHE_HOME="$run/cache"
"$GHIDRA_HOME/support/analyzeHeadless" \
  "$PWD/research/ghidra-projects" Drakan_US_Retail -process Drakan.exe \
  -readOnly -noanalysis -scriptPath "$PWD/tools/ghidra/scripts" \
  -postScript TraceTexturePipeline.java -log "$run/ghidra.log" \
  -scriptlog "$run/script.log" > "$run/console.log" 2>&1
exec 9>&-
```

Cross-check `0x00435840–0x00435d75`, `0x00433570–0x00433880`,
`0x004629e0–0x00462af7`, and the jump table at `0x00436320` with
`objdump -d -Mintel` (use `objdump -s` for the jump table). The stream scan
and source hashes are reproducible using `selector-0040-samples.md`. The
inventory above can be repeated by reading 50 bytes at each sample's recorded
offset and unpacking `<IIIH9I`; the first and sixth dwords after depth are
the offset-14 word and offset-34 flags respectively. No retail bytes or
private Ghidra output are committed.
