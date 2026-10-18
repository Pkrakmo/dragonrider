# Retail database descriptor observations

**Date and inputs:** 2026-10-18, unpatched US retail `Drakan.exe`, SHA-256
`23630f48e20e8a9f42026501165ae1df407cfcee545a784ec930a4c25ee70648`, and
the 337-file installed-US inventory from `retail-asset-inventory.md`. Each
descriptor and each paired level used below was SHA-256 verified against that
private manifest. Example: `Common/FX/FX.db`, SHA-256
`61cfc96e7fa81c9ffd664489d4116adf7787da4a2258f2f3c69be16065438b65`.
**Method:** GNU objdump 2.45.1, raw PE data and import table, Python 3.14.7,
and independently implemented C++ inspector. No Ghidra project or game was
opened or run. **Confidence:** high for these instructions and sample bytes;
stream helper internals, full grammar, other editions and actual runtime
resolution remain unverified.

## Observed

On the selected database-loading path `0x0041e940`–`0x0041ed1e`, a helper
receives the suffix `.db` at `0x0041ea0c`–`0x0041ea19`. The path is opened
and the code calls stream helpers to read a token and double; it compares the
token with `version` and the double with 1.0 (`0x0041ea4a`–`0x0041eab9`).
Next it reads a token and integer, compares the token with `dependencies`,
and if the count is positive loops over it (`0x0041eabf`–`0x0041eb2f`).
The loop reads an integer and a line into a buffer, invokes
`SetCurrentDirectoryA` and `GetFullPathNameA`, and stores the integer and
returned object in a pair (`0x0041eb2f`–`0x0041ec88`). Static imports identify
the Windows calls. Their success, error handling, exact stream extraction
semantics and path safety are not established here. The executable's existing
extension handling is described in [loader callers](loader-callers.md).

The 39 `.db` files in this extracted tree each have a same-relative-name
`.odb` file. All 39 use CRLF-terminated `version 1` and `dependencies N`
lines followed by N lines consisting of a decimal integer, one space and a
nonempty name. Their 132 entries have IDs 1–8 and names 7–60 bytes long;
all sampled bytes are ASCII. Counts range from 0 to 6. These are sample
properties, not format invariants or proof of the runtime association.

For 20 of the 23 hash-verified `.lvl` files a same-path `.db` exists in this
extracted layout; three lack one. Among those 20 pairs, descriptor entries
contain 85 IDs and selector-`(0,0,0)` level directories contain 146 values.
59 descriptor ID occurrences have the same numeric value somewhere in their
paired directory, and 59 directory value occurrences appear somewhere in
their paired descriptor. None of the 20 pairs has identical ID sets. This
checks numeric membership only: names, runtime association, ordering and
installation overlay are not verified. Do not equate the two lists or infer a
missing required asset from these counts.

## Inspection and reproduction

The C++ parser accepts a restricted form with explicit limits and retains raw
names; the inspector prints only lengths and CRC32, not the names. These rules
are a safety policy, not a reconstruction of every retail stream parsing case;
see [ADR 0016](../decisions/0016-database-descriptor-inspection.md).
The independent Python decoder matched all **39 descriptors and 132 entries**
against both GCC debug and release inspectors. Synthetic tests cover truncated
and malformed lines, numeric overflow, zero count, duplicate IDs, raw names,
limits, and CLI output. Windows is untested.

```sh
sha256sum research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x41e940 --stop-address=0x41ed1f research/binaries/us/Drakan.exe
objdump -s --start-address=0x47b75c --stop-address=0x47b778 research/binaries/us/Drakan.exe
objdump -s --start-address=0x475650 --stop-address=0x475658 research/binaries/us/Drakan.exe
objdump -p research/binaries/us/Drakan.exe | rg 'GetFullPathNameA|SetCurrentDirectoryA'
python3 tools/research/verify_database_descriptors.py research/installed/us research/exports/asset-inventory/us.json --inspector build/debug/dragonrider_inspect --compare-level-ids
python3 tools/research/verify_database_descriptors.py research/installed/us research/exports/asset-inventory/us.json --inspector build/release/dragonrider_inspect
python3 -m unittest discover -s tools/research -p 'test_verify_database_descriptors.py'
```
