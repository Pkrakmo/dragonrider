# Mplayer `mpurl.dat` bounded byte classification, 2026-10-24

## Evidence

- Status: Observed byte properties; format and runtime role unknown.
- Source: US retail installed tree,
  `English_-_Mplayer_Files/Assets/mpurl.dat`, 2,500 bytes,
  SHA-256 `d9dfd403a2ff8a1a4b60aa115e45a8cea4fe5b60e3769e92185071ccb552c0c8`.
  The size and digest matched the private asset inventory before measurement.
- Tool: project script `tools/research/classify_mplayer_url_catalog.py`, Python
  3.14. It reads only this path from the manifest and reports aggregate
  structure; it never emits line contents or URL values.
- Confidence: high for these measured bytes, low for semantic interpretation.

## Observation

The file is 7-bit ASCII with no NUL bytes and no control characters other than
CR, LF, and tab. It contains 82 LF-delimited lines after treating CRLF as a
single newline: 54 nonempty and 28 blank. The longest line is 116 bytes. A
bounded URI-scheme scan found 12 `http://` tokens, each on a separate nonempty
line; it found no `https://` or `ftp://` tokens. The report deliberately omits
all line values.

The filename and URI-shaped rows are consistent with a text file containing
URL entries, but do not establish a record grammar, whether the URLs are
active, or any network behavior. No executable was run and no network
operation was attempted. This result classifies only the one hash-pinned US
file; other editions and files are outside the sample.

## Reproduction

From the project root, using the private US inventory and installed tree:

```sh
python3 tools/research/classify_mplayer_url_catalog.py \
  research/installed/us research/exports/asset-inventory/us.json
PYTHONPATH=tools/research python3 -m unittest \
  test_classify_mplayer_url_catalog
```

The four synthetic tests cover aggregate-only output, missing/duplicate
inventory entries, stale hashes, and non-ASCII input. The live report verified
the inventory size and SHA-256 before counting; it returned 2,500 bytes,
82 lines, 54 nonempty lines, 28 blank lines, 12 HTTP scheme tokens, and zero
HTTPS or FTP scheme tokens.

## Static filename reference in the bundled Mplayer executable

The inventory-hash-verified `mIC.exe` (271,872 bytes, SHA-256
`074398d985605edb5d88117ff47c1c4e17936f630ba998d15a7bfdc1f21f1e00`)
contains `mpurl.dat` at file offset `0x2d850` and the printable log text
`ICSEngine:: Done waiting for mpurl.dat (%s)` at offset `0x34a68`. GNU objdump
2.45.1-5.fc43 shows the mapped filename address `0x0042f650` pushed at
`0x00402b6f`; the following call at `0x00402b80` receives that pointer among
its arguments. The called thunk at `0x00424248` jumps through IAT RVA
`0x42b58`, which the hash-verified PE import table identifies as MFC42 ordinal
924. The ordinal's function identity and call effect remain unknown. The US
retail `Drakan.exe` (SHA-256
`23630f48e20e8a9f42026501165ae1df407cfcee545a784ec930a4c25ee70648`) contains
no ASCII or UTF-16LE `mpurl.dat` literal in the verified byte snapshot. Of the
21 hash-verified Mplayer-group PE files, the exact filename appears only in
`mIC.exe` and only as ASCII; the targeted scan found no UTF-16LE occurrence.
The Mplayer executable also contains URL-shaped strings, but these static
bytes do not establish that the code runs, that it reads the inventory, or
that any URL is used.

`tools/research/verify_mic_mpurl_reference.py` verifies both hashes, both
`mIC.exe` file-offset strings, ten exact instructions, including the import thunk, and the MFC42 ordinal
at the anchored IAT RVA using the same verified executable snapshot passed to
objdump. Eight synthetic tests cover
anchor mutation, stale hashes, filename rejection, symlink rejection,
wrong-DLL rejection, and snapshot handoff. No binary is run.
`scan_mplayer_pe_references.py` reproduces the 21-file ASCII/UTF-16LE filename
census.

```sh
python3 tools/research/verify_mic_mpurl_reference.py \
  research/installed/us/English_-_Mplayer_Files/System/mIC.exe \
  research/binaries/us/Drakan.exe
python3 -m unittest discover -s tools/research \
  -p 'test_verify_mic_mpurl_reference.py' -v
```
