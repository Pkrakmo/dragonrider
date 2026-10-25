# LFL/MPL path-shaped rows against the installed inventory — 2026-10-25

## Evidence

The four hash-pinned US files measured in
`retail-lfl-mpl-text-lists-2026-10-24.md` were compared with a fresh
337-file installed-tree inventory. The inventory SHA-256 is
`e878d60f9bc3ffcee8c42ef302970d9f6676ca0ed6cb3e582cc01ddd1a543b64`.
The source SHA-256 values are listed in
[`retail-asset-inventory.md`](retail-asset-inventory.md) for the four named
files. All ten path-shaped `.lfl` rows end in `.lvl`; each has one exact
basename match in the inventory. Their extension-free basename stems each
match multiple inventory paths, so they are ambiguous under that looser check.
After converting backslashes and normalizing relative separators, none
resolves as an exact or case-insensitive path relative to either the
inventory root or the list's directory. The `.mpl` file has sixteen `.reo`
rows, none with a matching basename or stem in the inventory. No row values
are emitted by the tool.

**Observed:** these are candidate filename matches in the bounded installed-US
snapshot. **Unknown:** whether the paths are opened, what base directory or
normalization the consumer uses, and whether `.reo` resources are generated,
external, or absent from this installation. The suffixes and basename matches
do not establish list semantics or runtime use.

## Reproduction

```sh
python3 tools/research/inventory_retail.py research/installed/us /tmp/dragonrider-inventory.json
cmp research/exports/asset-inventory/us.json /tmp/dragonrider-inventory.json
PYTHONPATH=tools/research python3 tools/research/measure_text_list_inventory_links.py \
  research/installed/us /tmp/dragonrider-inventory.json
PYTHONPATH=tools/research python3 -m unittest test_measure_text_list_inventory_links -v
```

The Python 3.14.7 measurement rechecks the four source-file sizes and SHA-256
values, rejects unsafe or duplicate inventory paths, emits aggregate counts
only, and does not resolve paths or infer their meaning. Five synthetic tests cover aggregate
output, missing and duplicate entries, stale hashes, unsafe paths and rejected
row traversal.
