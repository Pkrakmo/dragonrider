# Texture header branch coverage — 2026-10-25

## Evidence

The existing 5,993-record US `0x0040` texture measurement was regenerated on
2026-10-25 with `tools/research/measure_texture_layout.py`. It examined 39
files with zero invalid ranges; all 5,993 headers satisfy the recorded row
relation. Debug and release inspector comparisons are separately recorded in
`TODO.md`.

Aggregating the measured header words gives these `(depth, word at payload
offset 14)` counts:

| Depth | Offset-14 value | Records |
| ---: | ---: | ---: |
| 8 | 0 | 1,030 |
| 16 | 0 | 3,158 |
| 16 | 1 | 13 |
| 16 | 4 | 1,788 |
| 16 | 8 | 2 |
| 24 | 0 | 2 |

No measured record has offset-14 value `2`, so this inventory does not sample
the distinct descriptor branch documented in
`texture-pipeline-behavior.md`. Seven records set flag `0x100000`; 1,802 set
flag `0x200`. At `0x00435a40–0x00435b41`, the static path maps selected header
bits and offset-14 values into descriptor arguments, then checks a separate
device-state field at `0x00435b25–0x00435b27`. A nonzero device-state value
jumps to `0x00436226`, bypassing the standard surface-creation call at
`0x00433570`. The header census alone cannot establish whether those seven
records reach that branch, since the branch condition is device state.

## Reproduction

Run the existing aggregate measurement, then summarize the emitted private
JSON without printing any asset values:

```sh
python3 tools/research/measure_texture_layout.py research/installed/us /tmp/texture-layout.json
python3 - <<'PY'
import collections, json
d = json.load(open('/tmp/texture-layout.json', encoding='utf-8'))
r = [row for f in d['files'] for row in f['records']]
print(sorted(collections.Counter((x['depth'], x['words'][0]) for x in r).items()))
print('offset-14 value 2:', sum(x['words'][0] == 2 for x in r))
print('flag 0x100000:', sum(bool(x['words'][5] & 0x100000) for x in r))
print('flag 0x200:', sum(bool(x['words'][5] & 0x200) for x in r))
PY
objdump -d -Mintel --start-address=0x00435a40 --stop-address=0x00435b45 research/binaries/us/Drakan.exe
```

The file hashes in the measurement output identify its scanned inputs. The
disassembly is static evidence from the hash-pinned US retail executable; no
game execution or visual output was used. Descriptor negotiation, runtime
branch reachability, device behavior and displayed pixels remain unresolved.
