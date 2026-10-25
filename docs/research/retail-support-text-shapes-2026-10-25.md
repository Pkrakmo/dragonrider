# US retail support-text shapes and static basename literals — 2026-10-25

## Provenance and method

The source is the installed US retail tree and private inventory
`research/exports/asset-inventory/us.json` (337 entries, SHA-256
`e878d60f9bc3ffcee8c42ef302970d9f6676ca0ed6cb3e582cc01ddd1a543b64`). Three
bounded tools use Python 3.14.7 and the same private inventory. The first
checks size and SHA-256 before classifying eight selected `.htm`, `.ini`,
`.url`, and `.txt` files. It emits line endings, aggregate HTML
tag/reference categories, INI section/assignment counts, and README line
categories; it does not emit text, HTML attributes, URLs, or configuration
values. The second scan checks ASCII and UTF-16LE basename literals in the 21
inventory-selected Mplayer PE files and retail `Drakan.exe` (SHA-256
`23630f48e20e8a9f42026501165ae1df407cfcee545a784ec930a4c25ee70648`). The
21 Mplayer program inputs are selected from the same hash-pinned inventory.
The third tool checks selected PE section mappings and bounded instruction
anchors with GNU objdump 2.45.1-5.fc43, using the exact hash-verified byte
snapshots. None executes a binary.

## Observed support-file shapes

All eight files are NUL-free, valid UTF-8 and match the inventory hashes.
Their identities are:

| Relative path | Bytes | SHA-256 |
| --- | ---: | --- |
| `English_-_Common_Data_Files/ReadMe.txt` | 42,622 | `96c7034b84d22b31ed039479801a58be9527cb95f6cc8b4b417fcfbe3a181255` |
| `English_-_Mplayer_Files/Assets/Blank.htm` | 49 | `da5b6da9c9ca37e4805bbac982f16a0c25223a69d88120de0144a019e090f5e4` |
| `English_-_Mplayer_Files/Assets/Magazine01/Dismiss.htm` | 139 | `ddf6b0af27156f3d298b0f7199eedffa8b44c1879549be9d8cceb08ad4e03dae` |
| `English_-_Mplayer_Files/Assets/Magazine01/layout.htm` | 230 | `0f2f1c5628a707f2037ddadcdc847615f50cb8a94f00781f328f35852f71c074` |
| `English_-_Mplayer_Files/System/MplayerLocal.ini` | 562 | `10e8bfc6f46a2d0d7f3dbf9999fbcfa15b56d0635405cdaeded0931e7086622e` |
| `English_-_Mplayer_Files/System/MplayerWeb.ini` | 3,945 | `a9503b250b1765afa3da1b9a64389a0dfcf45a8f19a5732304a8ad714aba3ef9` |
| `English_-_Mplayer_Files/System/install.url` | 67 | `c40f171f174f900b16a1ae1b4ddb1c770189cebf3aab7dd909db57772d138c4c` |
| `English_-_Mplayer_Files/System/mic-help.htm` | 1,938 | `1bd3f443fde0508ef153b46766522db856ebea3e97d316d0d0ddca7b645519b2` |

An independent `file` 5.46 MIME pass classified the four `.htm` files as
`text/html`, `install.url` as `application/x-mswinurl`, `MplayerLocal.ini` as
`application/x-wine-extension-ini`, and the remaining two as `text/plain`.
These utility classifications corroborate the broad file roles only.

Python's lenient `HTMLParser` recognized tags in all four HTML files.
`layout.htm` contains one
HTTP reference and one relative reference; `mic-help.htm` contains six HTTP
references and one mail reference. The other two contain no counted `href`,
`src`, or `action` references. These are counts only; the referenced values
are intentionally not recorded.

The two INI files have 11 sections and 143 assignments combined. The URL
shortcut has one section and one assignment. None of these three files has a
duplicate section, duplicate key, or unclassified nonblank line under the
bounded line parser. The README contains 905 lines, including 270 blank lines,
85 indented lines, 11 list-shaped lines, and 20 equals-sign heading markers.
These measurements classify text structure, not application-specific grammar.

## Static literal scan

Among the 22 hash-verified program snapshots, ASCII literals for `Blank.htm`
and `mic-help.htm` occur in `mIC.exe`; literals for `MplayerLocal.ini` and
`MplayerWeb.ini` occur in `mpfaux.dll`, `mpics.dll`, and `mpreal.dll`. The
other four selected basenames were not found. No selected basename was found
in UTF-16LE, and no selected basename literal was found in retail
`Drakan.exe`. This is a case-insensitive byte-substring search over each
verified snapshot. It identifies static literal candidates only; it does not
prove a file is opened or used, and it does not exclude constructed names,
indirect references, other encodings, or other program components.

An instruction-level follow-up hash-pins `mpfaux.dll` (120,320 bytes,
SHA-256 `32c24c813194a98a0220202f4fa71f918fc3f8bbd5b4c989a03dbc2e5bc234c6`)
and `mpics.dll` (279,552 bytes, SHA-256
`8a68e01d823905961212ae48c2ce0b17da8dd1a0f4180ef9e4c3862d9e9f963f`).
`mpreal.dll` has the same size and SHA-256 as `mpics.dll`, so those two are
byte-identical in this inventory. In `mpics.dll`, two anchored instruction
sequences push the `MplayerWeb.ini` and `MplayerLocal.ini` literal addresses
alongside a register argument, then call a thunk whose address maps through
the import table to `strcat`. This supports static filename concatenation in
that routine; it does not show that the resulting strings are opened. In
`mpfaux.dll`, the two literal addresses are passed to an internal helper at
`0x10004ae0`; that helper's effect and any later use were not traced.

The anchored instruction check covers six instructions in `mpfaux.dll` and 21
in `mpics.dll`; it also verifies the `.data` file-offset/VA mappings and the
`strcat` and `GetPrivateProfileStringA` imports. A full disassembly finds
three direct callers each of the two profile-string helper routines at
`0x10002ab7` and `0x10002b09`. Their addresses are `0x100026d7`, `0x10002d3e`,
and `0x10004bea` for the first, and `0x100026bb`, `0x10002751`, and
`0x10004be3` for the second. The code constructs filename strings and passes
them to the profile-string API on these paths, but successful reads, runtime
execution, the queried keys, and the data's meaning remain unknown. The
`mpics.dll`/`mpreal.dll` byte-identity result means this finding applies to
their shared byte snapshot; it does not establish that either module loads.

The containing InstallShield group and 21 PE inventory are described in the
[retail inventory](retail-asset-inventory.md). The scan does not establish
authorship, licensing, runtime necessity, or network behavior.

## Reproduction

```sh
python3 tools/research/classify_retail_support_text.py \
  research/installed/us research/exports/asset-inventory/us.json
find research/installed/us/English_-_Mplayer_Files \
  research/installed/us/English_-_Common_Data_Files -type f \
  \( -iname '*.htm' -o -iname '*.ini' -o -iname '*.url' \
  -o -iname 'ReadMe.txt' \) -print0 | xargs -0 file --mime-type
python3 tools/research/verify_mplayer_support_text_refs.py \
  research/installed/us research/exports/asset-inventory/us.json
python3 tools/research/verify_mplayer_ini_path_anchors.py \
  research/installed/us research/exports/asset-inventory/us.json
PYTHONPATH=tools/research python3 -m unittest \
  test_classify_retail_support_text \
  test_verify_mplayer_support_text_refs \
  test_verify_mplayer_ini_path_anchors -v
```

The synthetic suites cover bounded metadata, missing/duplicate inventory
entries, stale hashes, NUL/encoding errors, symlink rejection, output
redaction, ASCII/UTF-16LE matching, section mappings, instruction anchors,
import names, direct-call parsing, and snapshot count. Reports contain no
retail text values or binary payloads.
