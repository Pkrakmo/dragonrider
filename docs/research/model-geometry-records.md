# Retail model point and group records

**Date and source:** 2026-10-18, unpatched US retail `Drakan.exe`, SHA-256
`23630f48e20e8a9f42026501165ae1df407cfcee545a784ec930a4c25ee70648`,
and 29 `.mod` files verified against the private installed-US SHA-256
inventory. The inventory and original assets remain private. **Method:**
bounded GNU objdump 2.45.1 disassembly and raw PE constants; independent
Python 3.14.7 byte decoder and C++ inspector. No Ghidra project or game was
opened. **Confidence:** high for these instruction windows and measured
bytes; names, topology and runtime behavior remain provisional.

## Observed

At `0x004245d0` the code uses path-builder index 1, which conditionally appends
`.mod` as documented in [loader callers](loader-callers.md). The version
check at `0x004245f5`–`0x00424680` selects `(0x0402,0,0)`, initializes a
default value of `0x0100`, reads a dword if selection succeeds, and accepts
`0x010a` on the observed success path. Our structural reader does not apply
this version gate.

The function at `0x004246d0` searches `0x0200` with a runtime-provided ID at
`0x00424760`–`0x00424773`. It selects table index `i+2` and reads a 16-bit
count followed by `count * 12` bytes at `0x0042487f`–`0x004248c4`. It
subsequently treats each successive 12-byte item as three float values and
multiplies each by the float at `0x00475600`, previously measured as 2048.0
(`0x004248c4`–`0x004248fd`). This is behavior on that path; our reader retains
the raw bit patterns and does not impose floating-point or coordinate policy.

At table index `i+3`, `0x00424906`–`0x00424a1e` reads a 16-bit group count.
For each group it reads three 16-bit words, then reads `word 2 * 10` bytes.
Each 10-byte entry is copied as one 16-bit word and two 32-bit words into
runtime storage. The 16-bit word is a **candidate** point index: its measured
range supports this interpretation, but the final draw consumer and topology
have not been fully traced. The other two words and the group header's first
and third words are retained without semantic names. The parser accepts other
group sizes, zero counts, opaque tails and out-of-range candidate indices where
structurally safe; that is not a claim about game behavior.

The helpers at `0x0045f270`, `0x0045f2d0`, `0x0045f370`, and `0x0045f3a0`
show index-based record seeking, a bounded read budget and four- and two-byte
reads. Actual errors and malformed-file acceptance were not reproduced. The
index lookup and adjacency on this path do not justify assuming all editions
or all SRSC files have this sequence.

### Ordering and selector cross-check (2026-10-18)

A follow-up Ghidra 12.1.4 trace on a fresh disposable US retail import,
corroborated by `objdump`, gives more detail for the same function. At
`0x004246f1`–`0x00424720` the high 16 bits of its supplied 32-bit value are
compared with a runtime object's dword at `+0x114`; the chosen object supplies
the file loader. The same value is passed to `0x0045fa10` at
`0x00424766`–`0x0042476e` alongside `0x0200`. That helper compares its low
16 bits to record offset 2 and does not compare offset 4. This establishes
how the two parts are consumed on this path, not a universal ID format or
the meaning of record offset 4. At `0x00424789`–`0x004247b6` the caller
checks the first word at index `i+4` for `0x0208` and chooses between two
object-construction calls; it does not prove their resulting visual behavior.

The opener used here invokes the optional in-memory ordering step described in
[SRSC lookup order](srsc-lookup-order.md), although its return is not checked.
If ordering succeeds, `i` is an index in the reordered table. A fresh
hash-checked scan modeled that stable ordering and first-pair search for all
29 sampled `.mod` files: all 3,221 selected `0x0200` entries had different
runtime-order and raw-table positions, but the four entries following each
selection retained their original record identities. The first four records
retained matching second and third words in all 3,221 sequences. The `i+4`
first word was `0x0208` for 99 sequences and `0x0209` for 3,122. Both the
second and third words on the `0x0200` entries were nonzero in this sample;
they were equal in seven instances. These are sample measurements, not
runtime execution or format requirements. If ordering fails, or for different
files, index-relative behavior may differ; the inspector's explicit indices
are always raw file-table positions.

## Measured sample

All 29 hash-verified US `.mod` files contained **3,221** selector-`0x0200`
entries with consecutive first selectors `0x0200, 0x0206, 0x0203, 0x0204`
and matching other selector words. The selected `0x0203` and `0x0204` records
contain **198,743** triples, **265,121** groups and **825,714** group entries.
All selected record payloads ended exactly after the traced data. The groups
contained either three entries (234,770 groups) or four (30,351 groups), and
all candidate point indices were below their paired point count. These are
sample properties, not universal validation rules. No game was run and no
model or texture was visually verified.

The C++ reader accepts an explicit record pair; it neither applies the model
version gate nor determines a runtime lookup or source association. See
[ADR 0018](../decisions/0018-model-geometry-inspection.md). The independent
Python script verifies each inventory hash, sequences and ranges, then can
compare all pairs with an inspector; it does not require private fixtures in
the source tree. Tests use synthetic data, including malformed and hostile
counts, an out-of-range candidate index, zero groups and opaque tails.

## Reproduction

```sh
sha256sum research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x4245d0 --stop-address=0x424682 research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x424760 --stop-address=0x424a25 research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x45f270 --stop-address=0x45f3cb research/binaries/us/Drakan.exe
objdump -s --start-address=0x475600 --stop-address=0x475604 research/binaries/us/Drakan.exe
python3 tools/research/verify_model_geometry.py research/installed/us research/exports/asset-inventory/us.json --inspector build/debug/dragonrider_inspect
python3 tools/research/verify_model_geometry.py research/installed/us research/exports/asset-inventory/us.json --inspector build/release/dragonrider_inspect
python3 -m unittest discover -s tools/research -p 'test_verify_model_geometry.py'
python3 tools/research/measure_model_record_order.py research/installed/us research/exports/srsc-records/us.json
python3 -m unittest discover -s tools/research -p 'test_measure_model_record_order.py' -v
```
