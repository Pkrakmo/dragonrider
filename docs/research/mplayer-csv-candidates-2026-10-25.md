# Mplayer CSV candidates and static filename references, 2026-10-25

## Evidence

- Status: measured byte and static instruction observations; grammar and use
  remain unknown.
- Edition/input: US retail installed tree. `mphisto.csv` is 10,735 bytes,
  SHA-256 `c8ab1fc5d9656c380142e6a263c08306f43292e119d300f0b40c0ddc902f3f4c`;
  `mpusage.csv` is 173 bytes, SHA-256
  `63694c9114f6f6abec96f3dbf5560e32012bb2fce776fe8798730755bb6c66e1`.
  Both match the private US installed-file inventory.
- Static reference binary: `gizmo.ocx`, 260,608 bytes, SHA-256
  `79b054b4407cca7cdf52bed2ad63790d6dad13d90069250baa9e30502857b5d2`.
- Tools: project-owned aggregate classifier with Python 3.14; GNU objdump
  2.45.1-5.fc43; SHA-256 checked before analysis.
- Confidence: high for the recorded input bytes and instruction encodings;
  low for any semantic interpretation.

## Measured text shapes

`tools/research/classify_mplayer_csvs.py` hash-checks both manifest entries,
parses bounded ASCII with Python's strict CSV reader, and emits only aggregate
row and line-ending counts. `mphisto.csv` produced 174 parsed rows with field
count distribution `{0: 10, 1: 6, 2: 58, 34: 98, 35: 2}`, 172 CRLF and two bare
LF separators, and 158 source lines containing quote bytes. `mpusage.csv`
produced six rows with field count distribution
`{0: 3, 1: 2, 9: 1}`, five CRLF and one bare LF separators, and one quoted
source line. These inconsistent widths and blank rows describe parser output;
they do not establish headers, columns, or a complete file grammar.

## Static filename references

A bounded byte scan of 21 hash-pinned Mplayer PE files and hash-pinned retail
`Drakan.exe`, in ASCII and UTF-16LE, found both exact NUL-terminated CSV names
only in `gizmo.ocx`. In that file, `mpusage.csv` is at file offset `0x2e61c`
and `mphisto.csv` at `0x2e7b4`. They map to VAs `0x1002fe1c` and `0x1002ffb4`
in `.data`. GNU objdump disassembly shows each VA pushed at `0x10016f76` for
`mpusage.csv` and `0x10017368` for `mphisto.csv`. Both sequences pass a
`%s\\%s` format and the filename to `sprintf` at IAT VA `0x1004e15c`, then
pass the resulting stack buffer and mode `wb` to `fopen` at IAT VA
`0x1004e134`. The import table identifies these IAT entries as `sprintf` and
`fopen`. On each non-null `FILE*` branch, the corresponding pinned function
reaches a `fwrite` call and later `fclose` on the saved handle. Forty-three exact
instruction anchors cover both path setups, the mode, the open-result branch,
and the write/close calls. This is static evidence of constructing a path,
requesting a write-mode open, and calling a write routine conditionally. It
does not establish the path prefix, runtime branch execution, successful
write, output contents, or purpose.

## Reproduction

From the repository root with the private US inventory and installed tree:

```sh
python3 tools/research/scan_mplayer_pe_references.py \
  research/installed/us research/exports/asset-inventory/us.json
python3 tools/research/classify_mplayer_csvs.py \
  research/installed/us research/exports/asset-inventory/us.json
PYTHONPATH=tools/research python3 -m unittest test_classify_mplayer_csvs -v
python3 tools/research/verify_mic_mpurl_reference.py \
  research/installed/us/English_-_Mplayer_Files/System/mIC.exe \
  research/binaries/us/Drakan.exe
python3 tools/research/verify_gizmo_csv_references.py \
  research/installed/us/English_-_Mplayer_Files/System/gizmo.ocx
PYTHONPATH=tools/research python3 -m unittest test_verify_gizmo_csv_references -v
objdump -d -Mintel -w --start-address=0x10016f70 \
  --stop-address=0x10016fa2 \
  research/installed/us/English_-_Mplayer_Files/System/gizmo.ocx
objdump -d -Mintel -w --start-address=0x10017360 \
  --stop-address=0x10017394 \
  research/installed/us/English_-_Mplayer_Files/System/gizmo.ocx
objdump -p research/installed/us/English_-_Mplayer_Files/System/gizmo.ocx
```

The classifier verifies both CSV sizes and SHA-256 values and does not emit
content values. Seven synthetic tests cover aggregate-only output, missing
or duplicate inventory entries, stale hashes, non-ASCII and malformed CSV,
symlink rejection, and the input-size ceiling. The static verifier checks the
`.data` section mapping and passes only a verified snapshot to objdump. No
original binary was executed and no network operation was attempted.
