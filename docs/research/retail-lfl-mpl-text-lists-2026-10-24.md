# Retail LFL/MPL text-list byte shapes, 2026-10-24

## Evidence

- Status: Observed byte structure; record meaning and consumer unknown.
- Source: Four US retail installed files. Their sizes and SHA-256 values match
  the private inventory and are listed in the [retail asset inventory](retail-asset-inventory.md).
- Tool: `tools/research/classify_retail_text_lists.py`, Python 3.14.7.
- Confidence: high for the measured bytes; low for semantic interpretation.

## Observation

All four inputs are NUL-free 7-bit ASCII with CRLF line endings. The three
`.lfl` files contain 5, 4, and 4 nonempty lines. Each has one line without a
path separator and the remaining lines have a path separator and end in
`.lvl`. The `.mpl` file contains 16 nonempty lines; all have a path separator
and end in `.reo`. No blank lines occur in these samples.

These shapes are consistent with small text files containing a header-like
line followed by level paths (`.lfl`) and a list of resource paths (`.mpl`).
That description is a byte-shape hypothesis: it does not establish the
header's meaning, whether the path-like rows are opened, which component reads
them, or the purpose of `.reo` files. The report contains no row values and
covers only these four US files.

## Reproduction

```sh
python3 tools/research/classify_retail_text_lists.py \
  research/installed/us research/exports/asset-inventory/us.json
PYTHONPATH=tools/research python3 -m unittest \
  test_classify_retail_text_lists
```

The script requires exactly the four expected inventory paths, verifies each
size and digest before parsing, bounds each input to 64 KiB, and emits only
line counts, path-separator counts, and suffix totals. Four synthetic tests
cover aggregate-only output, missing/duplicate paths, stale hashes, and
non-ASCII input.
