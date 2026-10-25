# Exact level-frame token search across SRSC record kinds — 2026-10-24

**Status:** Observed byte-distribution result; frame producer and meaning remain unknown.

## Inputs and method

The source scope is the hash/size-verified US retail installed-tree SRSC
inventory at `research/exports/srsc-records/us.json`: 178 containers and
38,926 records. The level subset is 23 `.lvl` containers. The executable
provenance anchor is US retail `Drakan.exe`, SHA-256
`23630f48e20e8a9f42026501165ae1df407cfcee545a784ec930a4c25ee70648`.
The inventory itself pins each measured container by file size and SHA-256.

`tools/research/measure_level_frame_payload_matches.py` decoded selector
`(0x0020,0,0)` level objects with both conditional arrays, then built each
complete six-byte `(tag, byte length)` header plus frame body observed in
those objects. A bounded byte automaton searched each hash-verified SRSC
record payload independently and reported counts by record kind. It emits no
payload bytes, tags, filenames, or digests. Python 3.14.7 was used; no Ghidra
project or game executable execution was involved.

## Result

Across 16,312 declared objects, 13,418 frame occurrences yielded 353 distinct
serialized frame tokens. Scanning 38,926 records found complete frame tokens
in 23/23 selector-`0x0020` level records and 3,877/4,203 selector-`0x0102`
records. All 353 distinct observed tokens appeared in at least one
`0x0102` record. No other selector kind had an exact complete-frame-token
match in this 178-container US sample.

This is a broader, unordered cross-kind byte search; it does not identify
which matching `0x0102` belongs to which level object. It is consistent with
the prior indexed, candidate-source comparisons in
[the frame comparison note](level-entry-caller-followup.md#frame-text-and-candidate-0x0102-comparison-2026-10-19),
but does not independently establish runtime source selection, a producer,
writer continuity, record grammar, semantic text meaning, execution, or
behavior in other editions. The 326 `0x0102` records without a match are
outside the implication of the observed level-frame token set.

## Reproduction

```sh
sha256sum research/binaries/us/Drakan.exe
python3 --version
python3 tools/research/measure_level_frame_payload_matches.py \
  research/installed/us research/exports/srsc-records/us.json
python3 -m unittest discover -s tools/research \
  -p 'test_measure_level_frame_payload_matches.py' -v
```

The five synthetic tests cover overlapping token detection, per-kind aggregate
counts, payload extent rejection, stale inventory hashes, and symlinked
inventory-path rejection. The measurement validates inventory status, safe
unique non-symlink paths, regular-file link count, file size, SHA-256, SRSC
table bounds, and record payload bounds before counting.
