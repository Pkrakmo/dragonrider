# Retail installed-file inventory

**Investigation:** 2026-10-17, unpatched US retail extraction under
`research/installed/us`. The inventory and original files stay private.

## Observed

- `python3 tools/research/inventory_retail.py research/installed/us research/exports/asset-inventory/us.json`
  enumerated 337 files, recording each relative path, size, SHA-256 and first
  12 bytes in the private JSON output. This is an inventory of this extracted
  tree, not proof that extraction was complete or files were never modified.
- 178 files begin with bytes `53 52 53 43` (`SRSC`): `.adb` 12, `.lvl` 23,
  `.mod` 29, `.odb` 39, `.rrc` 2, `.sdb` 19, `.ssd` 16 and `.txd` 38.
  The remaining files have varied signatures and include executables, images,
  text and support files; extension alone is not a type guarantee.
- In all 178 matching files, interpreting bytes 4–5 as little-endian gives
  `0x0100`; interpreting bytes 6–9 as a little-endian offset and bytes 10–11
  as a little-endian count yields `offset + count * 14 == file size`.
- Example: `English_-_Common_Data_Files/Dragon.rrc` is 3,697,121 bytes,
  SHA-256 `fb1e403bd33b370cc64fe1ac296b3cf889e524ff2279eca2a27b65911f0ca72a`.
  Its 12-byte header is `53 52 53 43 00 01 4f 4b 38 00 2f 02`; the
  candidate offset is 3,689,295 and count is 559. Independent `sha256sum`
  confirmed its digest.
- The retail executable `research/binaries/us/Drakan.exe` has SHA-256
  `23630f48e20e8a9f42026501165ae1df407cfcee545a784ec930a4c25ee70648`.
  A Python PE-header calculation mapped VA `0x0047D900` (image base
  `0x00400000`) to `.data` file offset `0x0007D900`; the four bytes there
  are also `53 52 53 43`. This is an independent raw-file check, without
  accessing the Ghidra project.

## Inferred and unknown

The shared signature, version and exact end-of-file table calculation strongly
corroborate that the candidate loader's header pattern applies to these retail
files. The meanings of the 14-byte records, the relationship between file
extensions and content, and which specific paths are passed by callers remain
unknown. A matching header alone does not establish that a file is valid.

## Verification and limits

The inventory script was also run against three temporary synthetic files: an
empty file, a complete one-record table, and a truncated one-record table. It
classified the table bounds as expected. This checks inventory arithmetic, not
the game loader's error handling. It scans installed files rather than data
embedded in installer archives or separately supplied patch files.

## Non-SRSC files in the extracted installed tree

On 2026-10-18, Python 3.14.7 regenerated the inventory and `cmp` found it
byte-identical to the 2026-10-17 private manifest. The regenerated JSON has
SHA-256 `e878d60f9bc3ffcee8c42ef302970d9f6676ca0ed6cb3e582cc01ddd1a543b64`;
it includes the supplied root path, so that hash is specific to this invocation.
Of 337 files, 159 do not have a complete 12-byte SRSC header. Their top-level
extraction groups and counts are: Mplayer 110, common data 14, multiplayer data
17, program files 2, and single-player data 16. These are extraction group
names, not proof of runtime use or origin.

**Observed:** All 57 `.bmp` files start with `BM`, three `.gif` files with
`GIF8`, two `.jpg` files with `ff d8 ff`, and 14 `.wav` files with `RIFF`;
the 14 WAV headers also contain `WAVE` at offset 8. The nine `.dll`, six
`.exe`, seven `.ocx`, and one `.rfl` files start with `MZ`. All 39 `.db` files
start with `version `; their contents and relationship to the 39 `.odb` files
are not established by this observation. The Mplayer group contains all
57 BMPs and 14 WAVs, as well as five of the six EXEs, all DLLs and OCXs.
The remaining non-SRSC extensions are `.csv` (2), `.dat` (1), `.htm` (4),
`.ico` (2), `.ini` (2), `.lfl` (3), `.log` (1), `.mpi` (1), `.mpl` (1),
`.pal` (1), `.rfl` (1), `.tln` (1), `.txt` (1), and `.url` (1).

`file` 5.46 identified program file `Dragon.rfl` as a PE32 i386 DLL; its
SHA-256 is `9b6496b65e962cf35dd1e18f424f2c8af08ceade78331dcc0b6da332ce844ac3`.
It identified `mpdrakan.mpi` and `drakan.tln` only as data. These are tool
classifications, not evidence of execution or format semantics. Header matches
do not validate entire files. **Unknown:** which supporting files are needed
by the game, whether extraction included every installed component, and the
semantics of the unidentified formats. Confidence is high for the counted
bytes in this manifest, limited to the extracted US retail tree.

To reproduce the inventory and aggregate checks without publishing it:

```sh
python3 tools/research/inventory_retail.py research/installed/us /tmp/dragonrider-installed-inventory.json
cmp research/exports/asset-inventory/us.json /tmp/dragonrider-installed-inventory.json
python3 - <<'PY'
import collections, json, pathlib
m = json.loads(pathlib.Path('/tmp/dragonrider-installed-inventory.json').read_text())
files = [f for f in m['files'] if 'candidate_table' not in f]
print('non-SRSC:', len(files))
print('groups:', dict(sorted(collections.Counter(f['path'].split('/')[0] for f in files).items())))
print('extensions:', dict(sorted(collections.Counter(pathlib.PurePosixPath(f['path']).suffix.lower() for f in files).items())))
for ext, signature in [('.bmp', '424d'), ('.gif', '47494638'), ('.jpg', 'ffd8ff'),
                       ('.wav', '52494646'), ('.db', '76657273696f6e20')]:
    matching = [f for f in files if f['path'].lower().endswith(ext)]
    print(ext, len(matching), sum(f['header_hex'].startswith(signature) for f in matching))
print('WAVE markers:', sum(f['header_hex'][16:24] == '57415645' for f in files if f['path'].lower().endswith('.wav')))
PY
file research/installed/us/English_-_Program_Files/Dragon.rfl research/installed/us/English_-_Multi-Player_Data_Files/System/mpdrakan.mpi research/installed/us/English_-_Common_Data_Files/System/drakan.tln
```

On 2026-10-17 the GCC-built `dragonrider_inspect` validated all 178 SRSC
headers in the US installed-file manifest and reported the same table offsets
and counts as the independent Python inventory. This checks the header and
table bounds only, not record meanings or data contents. To repeat using the
build described in the README:

```sh
python3 - <<'PY'
import json, pathlib, subprocess
root = pathlib.Path('research/installed/us')
manifest = json.loads(pathlib.Path('research/exports/asset-inventory/us.json').read_text())
entries = [f for f in manifest['files'] if 'candidate_table' in f]
failures = []
for entry in entries:
    result = subprocess.run(['build/dragonrider_inspect', str(root / entry['path'])], capture_output=True, text=True)
    table = entry['candidate_table']
    expected = f"Table offset: {table['offset']}\nRecord count: {table['count']}\n"
    if result.returncode != 0 or expected not in result.stdout:
        failures.append(entry['path'])
print(f'{len(entries) - len(failures)}/{len(entries)} matched')
if failures:
    print(*failures, sep='\n')
    raise SystemExit(1)
PY
```

## US and UK extracted disc inventories

On 2026-10-17, the same script inventoried `research/extracted/us` and
`research/extracted/uk` into private files
`research/exports/asset-inventory/disc-us.json` and `disc-uk.json`. Each
contained 2,033 regular files; a comparison by relative path, length and
SHA-256 found no missing paths or differing files. Both copies of
`Setup/data1.cab` were 280,876,551 bytes with SHA-256
`d6b78b161eb5ed494ae76dae6c157b29c10822dc50b087708ec0de4bd6e08fc8`.
This verifies the extracted copies, not the completeness of extraction or
identity of the separately extracted installed tree. The 2,033 file count
excludes directories and therefore is not comparable directly to the prior
2,118 filesystem-node count.

Reproduce and compare the private manifests:

```sh
python3 tools/research/inventory_retail.py research/extracted/us research/exports/asset-inventory/disc-us.json
python3 tools/research/inventory_retail.py research/extracted/uk research/exports/asset-inventory/disc-uk.json
python3 - <<'PY'
import json
from pathlib import Path
root = Path('research/exports/asset-inventory')
def files(edition):
    manifest = json.loads((root / f'disc-{edition}.json').read_text())
    return {f['path']: (f['size'], f['sha256']) for f in manifest['files']}
us, uk = files('us'), files('uk')
print(f'US files: {len(us)}; UK files: {len(uk)}; identical: {us == uk}')
assert us == uk
PY
```
