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
On 2026-10-19, a fresh run into a new `/tmp` directory again compared byte for
byte equal to the private manifest; the command reported 337 files, 178
`SRSC` signatures, and all 178 candidate tables ending at EOF.
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
On 2026-10-19, `file` 5.46 classified all 5 EXEs, 9 DLLs and 7 OCXs in the
extracted `English_-_Mplayer_Files` group as PE32 i386 images; the EXEs are
GUI applications and the remaining files are DLL images. This directory
grouping and binary inventory distinguish those files from the SRSC resource
containers, but do not establish who supplied the software, its license,
whether it is required or executed by the game, or whether every file is
actually used. No executable was run.
The remaining non-SRSC extensions are `.csv` (2), `.dat` (1), `.htm` (4),
`.ico` (2), `.ini` (2), `.lfl` (3), `.log` (1), `.mpi` (1), `.mpl` (1),
`.pal` (1), `.rfl` (1), `.tln` (1), `.txt` (1), and `.url` (1).
The `.db` descriptor trace and its bounded inspector comparison are recorded
in [database descriptor observations](database-descriptors.md).

`file` 5.46 identified program file `Dragon.rfl` as a PE32 i386 DLL; its
SHA-256 is `9b6496b65e962cf35dd1e18f424f2c8af08ceade78331dcc0b6da332ce844ac3`.
It identified `mpdrakan.mpi` and `drakan.tln` only as data. These are tool
classifications, not evidence of execution or format semantics. Header matches
do not validate entire files. **Unknown:** which supporting files are needed
by the game, whether extraction included every installed component, and the
semantics of the unidentified formats. Confidence is high for the counted
bytes in this manifest, limited to the extracted US retail tree.

On 2026-10-19, `file` 5.46 further classified all three installed `.lfl`
files and the one `.mpl` file as ASCII text; the single `.dat` file as ASCII
text; and the single `.pal` file as a RIFF `PAL ` resource. Hash-checked
byte counts for the three `.lfl` files are 202, 134 and 161 bytes with
5, 4 and 4 CRLF-separated lines respectively; the `.mpl` is 1,172 bytes and
has 16 CRLF-separated lines. All four are ASCII without NUL or bare-LF bytes.
A bounded-header check of that 1,052-byte `.pal` file observed a matching
RIFF length, one `data` chunk of 1,032 bytes, version word `0x0300`, and an
entry count of 256.
The documented four-byte entry layout accounts for 1,028 of the declared
1,032 `data` bytes; the remaining four bytes are unexplained. The tool
classified the one `.mpi` and one
`.tln` file only as generic data. The following selected input sizes and
SHA-256 values were checked against the private US inventory and live files:

On 2026-10-23, a follow-up against the same manifest-hash-verified `.pal`
confirmed 256 distinct four-byte candidate entries, each with a zero fourth
byte. The four unexplained trailing bytes contain one nonzero byte at trailer
position 1 and do not equal any candidate entry. The documented simple Windows
RIFF PAL layout is a `data` chunk containing a `LOGPALETTE` header followed by
four-byte `PALETTEENTRY` records, so the 256-row interpretation is consistent
with that specification. This file has four additional bytes inside the
declared `data` chunk; their role remains unknown, so the structural match
does not establish how the game consumes it. The bounded reproduction below
verifies the manifest hash and reports aggregate measurements without printing
entry data. See IBM and Microsoft's [Multimedia Programming Interface and Data
Specifications 1.0, “Palette File Format”](https://www.mmsp.ece.mcgill.ca/Documents/AudioFormats/WAVE/Docs/riffmci.pdf).

| Relative path | Bytes | SHA-256 | `file` classification |
| --- | ---: | --- | --- |
| `English_-_Multi-Player_Data_Files/Multiplayer/Air Only.lfl` | 202 | `46d11e81899360f7f482a925c08248e6a51f407752faf8641db29574b6c0a2ed` | ASCII text |
| `English_-_Multi-Player_Data_Files/Multiplayer/Ground Only.lfl` | 134 | `d8fac28723afb7db00583f59489294273b8deb1958cfe967f2200a838b2bba02` | ASCII text |
| `English_-_Multi-Player_Data_Files/Multiplayer/Master of the Dragon.lfl` | 161 | `c511a1fcb6f73b7c7213bd3a412a524a563cf1b4984702a9b7ef4b480ce4fe63` | ASCII text |
| `English_-_Single-Player_Data_Files/Islands_World/Islands_Night/Islands Night.mpl` | 1,172 | `411d1bb52dea950d0944534600c630b40379d293d2d07a5a800ddfc719bb630b` | ASCII text |
| `English_-_Mplayer_Files/System/mic.pal` | 1,052 | `8646438041042bd9b79effe001c96d808829603fcc83bc7bab8b3a8511c2d59c` | RIFF `PAL ` |
| `English_-_Mplayer_Files/Assets/mpurl.dat` | 2,500 | `d9dfd403a2ff8a1a4b60aa115e45a8cea4fe5b60e3769e92185071ccb552c0c8` | ASCII text |
| `English_-_Multi-Player_Data_Files/System/mpdrakan.mpi` | 1,620 | `40f742ef8c8968f63a2326c812c4ddd66a86f943f9f55493b59e370b86f2ae5b` | generic data |
| `English_-_Common_Data_Files/System/drakan.tln` | 32 | `19d261e827d92b0c58d2c606e9edc124b7373d58675ba56d5f996efafc051166` | generic data |

## Mplayer palette loading path, static review, 2026-10-23

The inventory-hash-verified `English_-_Mplayer_Files/System/mIC.exe`
(271,872 bytes, SHA-256
`074398d985605edb5d88117ff47c1c4e17936f630ba998d15a7bfdc1f21f1e00`)
contains the literal format string `%s\mic.pal` at file offset `0x2dedc`.
GNU `strings` 2.45.1-5.fc43 found it, and GNU `objdump` 2.45.1-5.fc43
disassembled a code reference at `0x00405D7B` that pushes its mapped virtual
address `0x0042FCDC`. In the same function, instructions call imported
`sprintf` at `0x00405D87`, `fopen` at `0x00405D9C`, `fread` at `0x00405DBE`,
and `fclose` at `0x00405DD8`. The `fopen` mode string is `rb`. The function
has one direct caller in the full disassembly, at `0x00416979`, and reads at
most `0xBB8` bytes; if the returned byte count exceeds `0x400`, it
uses a buffer starting at byte offset 24 to process 256 records at four-byte
strides. It constructs a `LOGPALETTE` header with version `0x0300` and count
256, copies the first three bytes of each input record into a new palette
entry, sets each entry's fourth byte to zero, and passes the structure to
imported `CreatePalette`. It also calls `GetNearestPaletteIndex` for each
source color. This path therefore does not consume the four trailer
bytes as palette entries, though it does not establish their intended role.
The branch threshold is 1,025 bytes, while the 24-byte prefix plus 256 rows
requires 1,048 bytes. An input between those lengths would enter the loop with
fewer bytes reported by `fread` than the loop consumes; malformed-input
behavior is not established. The measured retail file is 1,052 bytes.
The import table also names `SetPaletteEntries`, `RealizePalette`, and
`UpdateColors`; nearby text includes `MIC::SetMasterPalette invalidating
mainframe`. The disassembly establishes a static code path that formats and
opens a `mic.pal` path and processes the palette records. It does not establish
that this function executes at runtime or that the game executable loads this
Mplayer component. The executable was not run.

Recheck the source hash and relevant disassembly/imports with:

```sh
python3 - <<'PY'
import hashlib, json, pathlib
root = pathlib.Path('research/installed/us')
manifest = json.loads(pathlib.Path('research/exports/asset-inventory/us.json').read_text())
entry = next(e for e in manifest['files'] if e['path'] ==
             'English_-_Mplayer_Files/System/mIC.exe')
data = (root / entry['path']).read_bytes()
assert len(data) == entry['size'] == 271872
assert hashlib.sha256(data).hexdigest() == entry['sha256'] == \
       '074398d985605edb5d88117ff47c1c4e17936f630ba998d15a7bfdc1f21f1e00'
print({'size': len(data), 'sha256_matches_inventory': True})
PY
strings -a -t x research/installed/us/English_-_Mplayer_Files/System/mIC.exe \
  | rg 'mic\.pal'
objdump -d -Mintel --start-address=0x405d49 --stop-address=0x405e40 \
  research/installed/us/English_-_Mplayer_Files/System/mIC.exe
objdump -p research/installed/us/English_-_Mplayer_Files/System/mIC.exe \
  | rg 'fopen|fread|fclose|CreatePalette|GetNearestPaletteIndex'
```

The original files were not modified.
These observations classify bytes and file contents only: they do not show
which files the game loads or the purpose of the text documents. The Mplayer
palette reference is static only. Other editions and installed-tree
completeness remain open.

## Disc extraction tree coverage, 2026-10-23

Compared the logical paths, node types and file sizes listed by `xorriso`
against each existing extracted tree. Both US and UK images list 2,033 files
and 86 directories including the ISO root; each extracted tree contains all
2,033 files and all 85 non-root directories, with matching file sizes, no
extra paths, and no missing or mismatched non-root entries. The sole set
difference when retaining the ISO root is the expected root directory, which
has no corresponding entry inside the extraction directory. This establishes
path/type/size coverage for the extraction trees. As a content-integrity check,
each image was also freshly extracted by xorriso into a new `/tmp` directory;
all 2,033 regular files per edition matched the existing extraction byte for
byte by SHA-256, with no missing, extra, type-mismatched, size-mismatched, or
hash-mismatched nodes. This confirms the existing trees against a fresh
extraction of the same ISO using xorriso; it does not independently verify
xorriso itself or establish install completeness for files outside the disc
filesystem. The US and UK ISO inputs have the same SHA-256 recorded above
(`256a4e51020b06c551cc310895e245f1df8790be0af230711a727ecbf29d079c`). The
fresh extracts used xorriso 1.5.8.pl02.

The bounded listing comparison can be repeated with:

```sh
iso_tmp=$(mktemp -d /tmp/dragonrider-iso-check.XXXXXX)
printf '%s  %s\n' \
  '256a4e51020b06c551cc310895e245f1df8790be0af230711a727ecbf29d079c' research/discs/us/drakan.iso \
  '256a4e51020b06c551cc310895e245f1df8790be0af230711a727ecbf29d079c' research/discs/uk/drakan.iso \
  | sha256sum -c -
for edition in us uk; do
  xorriso -indev "research/discs/$edition/drakan.iso" -find / -exec lsdl \
    > "$iso_tmp/$edition-iso-list.txt" 2> "$iso_tmp/$edition-xorriso.log"
  find "research/extracted/$edition" -mindepth 1 \
    \( -type d -printf 'd 0 %P\n' -o -type f -printf 'f %s %P\n' \) \
    > "$iso_tmp/$edition-extracted-list.txt"
done
mkdir "$iso_tmp/us-reextract" "$iso_tmp/uk-reextract"
xorriso -osirrox on -indev research/discs/us/drakan.iso -extract / "$iso_tmp/us-reextract"
xorriso -osirrox on -indev research/discs/uk/drakan.iso -extract / "$iso_tmp/uk-reextract"
diff -qr research/extracted/us "$iso_tmp/us-reextract"
diff -qr research/extracted/uk "$iso_tmp/uk-reextract"
```

For the comparison, parse each xorriso `lsdl` row's node type, regular-file
byte size and single-quoted path; remove the leading slash and exclude the root
entry. Normalize directory sizes to zero and compare the records to `find`
output relative to the extraction root. Paths
with quoting characters should be reviewed explicitly before relying on a
text parser. The measured counts above came from a Python comparison of those
records; the complete paths remain in the private local research tree. The
fresh-extraction `diff -qr` commands above emit no output when the existing and
new trees match byte-for-byte.

## InstallShield Mplayer PE group, 2026-10-23

`unshield c` lists the InstallShield component `Mplayer.com Files`, and
`unshield g` lists the file group `English - Mplayer Files`. The `unshield l`
listing contains 21 EXE, DLL and OCX entries under that group. The group was
extracted into `/tmp` (110 files in all); each of the 21 extracted PE members
matched its installed counterpart in size and SHA-256, and each installed
counterpart matched the private inventory. This directly confirms that these
installed PE files are byte-identical to the contents extracted from the
InstallShield cabinet. `unshield t` also completed successfully for all 110
group members. This verifies decoder success, not a cabinet-authenticated
checksum for every file. It does not establish authorship, license, or runtime
necessity.
The US input cabinet `Setup/data1.cab` is 280,876,551 bytes with SHA-256
`d6b78b161eb5ed494ae76dae6c157b29c10822dc50b087708ec0de4bd6e08fc8`, checked
against the private US disc inventory. Extraction used unshield 1.6.2.

Reproduce the group enumeration with:

```sh
cab_tmp=$(mktemp -d /tmp/dragonrider-mplayer-check.XXXXXX)
printf '%s  %s\n' 'd6b78b161eb5ed494ae76dae6c157b29c10822dc50b087708ec0de4bd6e08fc8' \
  research/extracted/us/Setup/data1.cab | sha256sum -c -
unshield c research/extracted/us/Setup/data1.cab
unshield g research/extracted/us/Setup/data1.cab
unshield -g 'English - Mplayer Files' t research/extracted/us/Setup/data1.cab
unshield l research/extracted/us/Setup/data1.cab \
  | rg -i 'English - Mplayer Files\\.*\.(exe|dll|ocx)$' \
  | rg 'English - Mplayer Files'
unshield -g 'English - Mplayer Files' \
  -d "$cab_tmp" x research/extracted/us/Setup/data1.cab
```

Run the next block in the same shell session so it can use `cab_tmp`, then
verify the 21 PE members against the installed inventory:

```sh
CAB_TMP="$cab_tmp" python3 - <<'PY'
import hashlib, json, pathlib
import os
manifest = json.loads(pathlib.Path('research/exports/asset-inventory/us.json').read_text())
installed = pathlib.Path('research/installed/us')
extracted = pathlib.Path(os.environ['CAB_TMP']) / 'English_-_Mplayer_Files'
checked = 0
for entry in manifest['files']:
    relative = pathlib.Path(entry['path'])
    if relative.parts[0] != 'English_-_Mplayer_Files' or relative.suffix.lower() not in {'.exe', '.dll', '.ocx'}:
        continue
    member = extracted.joinpath(*relative.parts[1:]).read_bytes()
    current = (installed / relative).read_bytes()
    assert len(member) == len(current) == entry['size']
    assert hashlib.sha256(member).hexdigest() == hashlib.sha256(current).hexdigest() == entry['sha256']
    checked += 1
assert checked == 21
print({'cabinet_PE_members_verified': checked, 'size_and_hash_matches': checked})
PY
```

The corresponding UK cabinet listing also contains 21 PE entries in this
group. Temporary extracted files were kept outside the repository; original
media and installed files were read only.

## Common-data ICO container check, 2026-10-23

The inventory entry for
`English_-_Common_Data_Files/System/LevelFileList.ico` matches the installed
file at 1,078 bytes and SHA-256
`cf5d11796e7bc3281c2b73b610b180ee433ca69cfdc8fa8474053686291b6dfe`. A
standard-library bounds check observes an ICO directory with two images. Their
headers describe 32×32 and 16×16, one plane, 4 bits per pixel, 40-byte DIB
headers, and BI_RGB compression. The embedded image ranges fit the file and
leave no trailing bytes. This identifies container structure only; it does not
establish the ICO's consumer, visual contents, or runtime use.

Reproduce from the repository root. The command verifies size and SHA-256
against the private manifest, checks directory and DIB bounds, and prints only
aggregate header fields:

```sh
python3 - <<'PY'
import hashlib, json, pathlib, struct
root = pathlib.Path('research/installed/us')
manifest = json.loads(pathlib.Path('research/exports/asset-inventory/us.json').read_text())
entry = next(e for e in manifest['files'] if e['path'] == 'English_-_Common_Data_Files/System/LevelFileList.ico')
data = (root / entry['path']).read_bytes()
assert len(data) == entry['size'] and hashlib.sha256(data).hexdigest() == entry['sha256']
reserved, kind, count = struct.unpack_from('<HHH', data)
assert reserved == 0 and kind == 1 and count == 2 and 6 + 16 * count <= len(data)
images, ends = [], []
for i in range(count):
    w, h, colors, zero, planes, bpp, size, offset = struct.unpack_from('<BBBBHHII', data, 6 + 16 * i)
    w, h = w or 256, h or 256
    assert zero == 0 and offset <= len(data) and size <= len(data) - offset and size >= 40
    dib_size = struct.unpack_from('<I', data, offset)[0]
    assert dib_size == 40 and dib_size <= size
    dib_w, dib_h, dib_planes, dib_bpp, compression, image_size = struct.unpack_from('<iiHHII', data, offset + 4)
    assert dib_w == w and dib_h == 2 * h and dib_planes == 1 and compression == 0
    images.append({'width': w, 'height': h, 'planes': dib_planes, 'bits_per_pixel': dib_bpp, 'dib_bytes': size, 'compression': 'BI_RGB'})
    ends.append(offset + size)
assert max(ends) == len(data)
print({'file_bytes': len(data), 'sha256_matches_manifest': True, 'image_count': count, 'images': images, 'trailing_bytes': len(data) - max(ends)})
PY
```

## Mplayer PE version-resource metadata, 2026-10-23

The 21 PE files under the extracted `English_-_Mplayer_Files` group were
rechecked against size and SHA-256 values in the private 337-file US inventory;
all 21 matched. `wrestool` 0.32.3 listed resource types for every file without
error: 12 files have one numeric type-16 (VERSION) resource each, while none
has a numeric type-24 (manifest) resource. Raw VERSION resources from those
12 files were extracted with `wrestool -x -R -t 16`; GNU `strings` 2.45.1
found file-description and file-version strings in each. Three resources have
a nonempty `CompanyName` string: two say `Mpath Interactive, Inc.` and one
says `Pocket Soft, Inc.`. The other 18 files have no nonempty company-name
string in their VERSION resource or no VERSION resource. These are embedded
metadata claims, not proof of software authorship, license, runtime use, or
installation. In particular, the absence of an embedded manifest resource
does not show that a component needs no external manifest. No binary was run.

A second pass paired the UTF-16LE strings in each extracted VERSION resource
with their preceding field labels. All 12 resources contain `FileDescription`
and `ProductName`, each with 12 distinct values; `FileVersion` and
`ProductVersion` each have five distinct values. Eleven contain an
`OriginalFilename` field. In `Sound.ocx`, the embedded `FileVersion` is
`0, 6, 0, 2` while `ProductVersion` is `0, 6, 0, 1`; the discrepancy is
recorded as metadata only and does not establish a build or packaging issue.
The per-file resources were extracted only to a temporary directory, and all
21 PE inputs were checked against the private inventory before inspection.

The inventory membership and hashes can be rechecked with
`tools/research/inventory_retail.py` and the private manifest comparison above.
To recount VERSION-resource-bearing files and inspect their embedded strings,
run this bounded read-only shell procedure from the repository root:

```sh
find research/installed/us/English_-_Mplayer_Files -type f \
  \( -iname '*.exe' -o -iname '*.dll' -o -iname '*.ocx' \) -print0 |
while IFS= read -r -d '' pe; do
  listing=$(wrestool -l "$pe") || exit 1
  if printf '%s\n' "$listing" | rg -q '^--type=16\b'; then
    printf '%s\n' "$listing" | rg '^--type=16\b'
  fi
done

resource_dir=$(mktemp -d /tmp/dragonrider-mplayer-version-XXXXXXXX)
wrestool -x -R -t 16 -o "$resource_dir" \
  research/installed/us/English_-_Mplayer_Files/System/Mplayer.dll
find "$resource_dir" -type f -print0 | xargs -0 strings -el
```

This procedure reports embedded strings for one example DLL; the recorded
12-file aggregate was produced by applying the same extraction to each
type-16-bearing file. It remains an inventory of bundled PE metadata, not a
runtime or licensing determination.

On 2026-10-21, bounded inspection of the two remaining generic-data files
confirmed their manifest sizes and SHA-256 values above. `mpdrakan.mpi` has a
zero-heavy prefix and NUL-padded printable fields beginning at offset `0x10`;
one field is endpoint-shaped and another is key/value-shaped. `drakan.tln` is
32 bytes and has no recognized signature in the checked bytes; `strings` finds
only a short printable run. These byte observations are consistent with the
existing `file` classifications but do not establish either format, prove
that the `.mpi` fields are read or used as network settings, or show that the
game contacts any endpoint. No file was executed and no network operation was
attempted. The files remain unidentified at the format and runtime levels.

A printable-string scan of the hash-identified US retail executable found no
literal `.mpi`, `mpdrakan`, `.tln`, `drakan.tln`, or `.db` string. Its import
table does include `CreateFileA`, but that generic API does not identify which
files are opened. This bounded non-match cannot rule out constructed names,
indirect file access, optional modules, or use by another executable.
GNU `strings` and `objdump` 2.45.1-5.fc43 were used; the executable SHA-256
is recorded in the research baseline and was rechecked for this scan.

A separate 2026-10-23 printable-byte scan of all 21 size/SHA-256-verified PE
files in the Mplayer extraction group found `.mpi` substrings in `mIC.exe`,
`mpfaux.dll`, `mpics.dll`, and `mpreal.dll`. `mIC.exe` contains generic text
about fetching an MPI file and a temporary `.mpi` name; DLL matches include
`extra.mpi` and `default.mpi` strings. The scan found neither the exact
`mpdrakan.mpi` name nor `.tln`/`drakan.tln` in those 21 files, in ASCII or
UTF-16LE form. These generic extension references do not show that any listed
component reads the installed `mpdrakan.mpi`, identify its format, or establish
network behavior. No binary was executed. The new
`tools/research/scan_mplayer_pe_references.py` verifies all 21 candidate PE
files against the private inventory, rejects unsafe or stale paths/hashes and
files above its 16 MiB per-file limit, and prints only target-substring match
filenames; its three synthetic tests cover matching, completeness, stale,
oversized and symlink cases.

## Static PE import relationships, 2026-10-23

GNU `objdump` 2.45.1-5.fc43 reported import tables for all 22 installed PE
files (the 21 Mplayer-group files and `Drakan.exe`), after each file's size and
SHA-256 matched the private 337-file inventory. `Drakan.exe` statically imports
DirectDraw, DirectInput, DirectSound, WinSock 2, and Windows system libraries;
it has no static import naming an Mplayer-group PE such as `Mplayer.dll`,
`Mcp.dll`, or an OCX. Within the Mplayer group, nine PE import tables name
`Mplayer.dll`, four name `Mcp.dll`, and two name `Dialogs.dll`. This supports
an internal dependency structure in that extraction group, but the absence of
these names from `Drakan.exe`'s static imports does not rule out dynamic loading
or indirect use. A hash-verified case-insensitive scan of the retail executable
also found none of the 21 Mplayer PE basenames in ASCII or UTF-16LE printable
form. This bounded non-match cannot rule out constructed names or indirect
loading. No PE was executed.

The aggregate can be reproduced from the hash inventory with this read-only
check; it prints only file basenames and imported DLL names:

```sh
python3 - <<'PY'
import hashlib, json, pathlib, re, subprocess
root = pathlib.Path('research/installed/us')
entries = json.loads(pathlib.Path('research/exports/asset-inventory/us.json').read_text())['files']
images = [e for e in entries if pathlib.Path(e['path']).suffix.lower() in {'.exe', '.dll', '.ocx'}]
assert len(images) == 22
snapshots = {}
for e in images:
    path = root / e['path']
    data = path.read_bytes()
    assert len(data) == e['size'] and hashlib.sha256(data).hexdigest() == e['sha256']
    snapshots[e['path']] = data
    report = subprocess.run(['objdump', '-p', str(path)], check=True, capture_output=True, text=True).stdout
    imports = sorted(set(re.findall(r'^\s*DLL Name:\s*(.+?)\s*$', report, re.M | re.I)), key=str.casefold)
    print(path.name, ', '.join(imports) if imports else '(none reported)')
mplayer = [e for e in images if e['path'].startswith('English_-_Mplayer_Files/')]
game = next(e for e in images if e['path'] == 'English_-_Program_Files/Drakan.exe')
game_bytes = snapshots[game['path']]
names = {pathlib.Path(e['path']).name for e in mplayer}
for encoding in ('ascii', 'utf16le'):
    hits = []
    for name in names:
        raw = name.lower().encode()
        needle = raw if encoding == 'ascii' else b''.join(bytes((b, 0)) for b in raw)
        if needle in game_bytes.lower():
            hits.append(name)
    print('Drakan.exe', encoding, sorted(hits, key=str.casefold))
PY
```

Reproduce the bounded observations without printing the full `.mpi` strings:

```sh
sha256sum research/installed/us/English_-_Multi-Player_Data_Files/System/mpdrakan.mpi \
  research/installed/us/English_-_Common_Data_Files/System/drakan.tln
od -Ax -tx1z -N64 research/installed/us/English_-_Multi-Player_Data_Files/System/mpdrakan.mpi
od -Ax -tx1z research/installed/us/English_-_Common_Data_Files/System/drakan.tln
strings -a -t x -n 4 research/installed/us/English_-_Multi-Player_Data_Files/System/mpdrakan.mpi | awk '{ offset = $1; $1 = ""; value = substr($0, 2); kind = value ~ /tcp\// ? "endpoint-shaped" : value ~ /=/ ? "key-value-shaped" : "other"; print offset, kind }'
strings -a -t x -n 3 research/installed/us/English_-_Common_Data_Files/System/drakan.tln | awk '{ print $1, length($0) - length($1) - 1, "printable-bytes" }'
if strings -a -t x research/binaries/us/Drakan.exe | rg -i '\.mpi|mpdrakan|\.tln|drakan\.tln|\.db'; then
  :
else
  echo 'No matching literal in printable strings'
fi
python3 tools/research/scan_mplayer_pe_references.py research/installed/us \
  research/exports/asset-inventory/us.json
python3 -m unittest discover -s tools/research \
  -p 'test_scan_mplayer_pe_references.py' -v
objdump -p research/binaries/us/Drakan.exe | rg 'CreateFileA'
```

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
file research/installed/us/English_-_Multi-Player_Data_Files/Multiplayer/*.lfl research/installed/us/English_-_Single-Player_Data_Files/Islands_World/Islands_Night/*.mpl research/installed/us/English_-_Mplayer_Files/System/mic.pal research/installed/us/English_-_Mplayer_Files/Assets/mpurl.dat
python3 - <<'PY'
import hashlib, json
from pathlib import Path, PurePosixPath
root = Path('research/installed/us')
manifest = json.loads(Path('research/exports/asset-inventory/us.json').read_text())
for entry in manifest['files']:
    path = PurePosixPath(entry['path'])
    if path.suffix.lower() not in {'.lfl', '.mpl'}:
        continue
    data = (root / entry['path']).read_bytes()
    assert len(data) == entry['size']
    assert hashlib.sha256(data).hexdigest() == entry['sha256']
    print(entry['path'], len(data), 'CRLF', data.count(b'\\r\\n'),
          'bare-LF', data.count(b'\\n') - data.count(b'\\r\\n'),
          'NUL', data.count(b'\\0'), 'non-ASCII', sum(c >= 128 for c in data))
PY
```

The `.pal` measurements can be reproduced without printing palette entries:

```sh
python3 - <<'PY'
import hashlib, json, pathlib, struct
root = pathlib.Path('research/installed/us')
manifest = json.loads(pathlib.Path('research/exports/asset-inventory/us.json').read_text())
entry = next(e for e in manifest['files'] if e['path'] ==
             'English_-_Mplayer_Files/System/mic.pal')
data = (root / entry['path']).read_bytes()
assert len(data) == entry['size']
assert hashlib.sha256(data).hexdigest() == entry['sha256']
assert data[:4] == b'RIFF' and data[8:12] == b'PAL '
assert data[12:16] == b'data'
riff_size, chunk_size = struct.unpack_from('<II', data, 4)[0], struct.unpack_from('<I', data, 16)[0]
version, count = struct.unpack_from('<HH', data, 20)
assert riff_size + 8 == len(data) and chunk_size == len(data) - 20
assert version == 0x0300 and count == 256
end = 24 + count * 4
entries, trailer = [data[24 + 4*i:28 + 4*i] for i in range(count)], data[end:]
assert len(trailer) == 4
print({'file_bytes': len(data), 'sha256_matches_inventory': True,
       'candidate_entry_count': len(entries), 'distinct_candidate_entries': len(set(entries)),
       'entries_with_nonzero_fourth_byte': sum(row[3] != 0 for row in entries),
       'trailing_bytes': len(trailer),
       'trailing_nonzero_positions': [i for i, byte in enumerate(trailer) if byte],
       'trailer_matches_candidate_entry': trailer in entries})
PY
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
    result = subprocess.run(['build/debug/dragonrider_inspect', str(root / entry['path'])], capture_output=True, text=True)
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
