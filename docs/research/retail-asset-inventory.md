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
