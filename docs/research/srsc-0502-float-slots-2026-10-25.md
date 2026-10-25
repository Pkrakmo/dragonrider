# SRSC `0x0502` row float slots, 2026-10-25

## Evidence

- Status: observed static conversion path and measured raw float32
  representations; meanings are unknown.
- Input: the 552,960-byte US retail `Drakan.exe`, SHA-256
  `23630f48e20e8a9f42026501165ae1df407cfcee545a784ec930a4c25ee70648`, and
  the 178-entry private US SRSC inventory whose snapshots are size/hash
  checked by the measurement tool.
- Method: GNU objdump instruction anchors verified by
  `verify_srsc_0501_consumer.py`; aggregate-only Python 3.14 scan using
  `measure_srsc_0501_float_slots.py`.
- Confidence: high for the pinned instruction bytes and measured sample;
  low for semantic interpretation.

## Static path

The hash-pinned consumer selects the first `(0x0501, second selector)` pair
match in table order, then selects the following `0x0503` and `0x0502` rows.
Its `0x0502` loop advances in 52-byte units. The verified instructions at
`0x0041581f`, `0x00415822`, and `0x0041582c` load, multiply, and store the
first candidate 32-bit value at row offset `+40`; corresponding load/store
anchors at `0x0041582f`/`0x00415838` and
`0x0041583b`/`0x00415844` process offsets `+44` and `+48`. The multiplier at
`0x00475600` maps to file offset `0x75600`, where the hash-pinned executable
contains bytes `00 00 00 45`, interpreted as binary32 `2048.0` by the
consumer verifier. This is a static conversion path, not evidence the
routine ran successfully.

## Bounded US sample measurement

The scan used the stable second-selector ordering and accepted only first
pair matches whose next two rows were `(0x0503, same selector)` and
`(0x0502, same selector)`. It examined all 178 hash/size-verified inventory
files and found 1,722 trios in 12 files. The scan counted 1,722 `0x0502` table
records total in the 178-entry inventory; all were selected by one of those
trios, with no unselected `0x0502` rows in this sample. For each selected
payload, the little-endian 16-bit row count fit exactly in the available row
bytes; there were zero payload trailing bytes. The selected records contained
1,350,554 52-byte rows.

At each of the three offsets, all 1,350,554 row values were finite when
interpreted as little-endian float32. Raw pre-multiply ranges were:

| Row byte offset | Minimum | Maximum | Non-finite |
|---:|---:|---:|---:|
| 40 | -5.67889404296875 | 6.659355163574219 | 0 |
| 44 | -9.927200317382812 | 10.797979354858398 | 0 |
| 48 | -7.29737663269043 | 1.9556465148925781 | 0 |

These are raw float interpretations before the observed multiplication. They
do not name axes or fields, establish coordinate units, establish runtime
success, or generalize beyond this US inventory.

## Reproduction

```sh
python3 tools/research/verify_srsc_0501_consumer.py \
  research/binaries/us/Drakan.exe
python3 tools/research/measure_srsc_0501_float_slots.py \
  research/installed/us research/exports/srsc-records/us.json
PYTHONPATH=tools/research python3 -m unittest \
  test_measure_srsc_0501_float_slots -v
```

The five measurement tests cover finite ranges, non-finite values, truncated
prefixes/rows, invalid payload extents, and selected/unselected trio rows; the
consumer verifier's eight tests also check the scalar bytes and instruction
anchors. No game binary was executed and no private byte values are emitted.
