# SRSC 14-byte record reader/writer anchors — 2026-10-23

## Scope and provenance

**Input:** unpatched US retail `Drakan.exe`, SHA-256
`23630f48e20e8a9f42026501165ae1df407cfcee545a784ec930a4c25ee70648`.
**Method:** bounded GNU objdump 2.45.1-5.fc43 static disassembly, checked by
the committed verifier. No Ghidra project was opened, no program code was
executed, and no private export was written. **Confidence:** high for the
listed instruction operands; limited for control-flow feasibility and all
untraced writer/reader paths.

## Observed

The common writer's documented state and table stores have these anchors:

| Record offset | Static writer observation |
| --- | --- |
| `0` and `2` | caller-provided 16-bit inputs are stored by the common initializer (prior bounded trace) |
| `4` | the setter masks its input to 16 bits, stores writer `+8`, then the initializer loads that word and writes it at table-record `+4` |
| `6` | the initializer writes the current file-position result at table-record `+6` |
| `10` | the closer subtracts record `+6` from a later file position and stores the result at record `+10` |

The tuple reader independently compares words at `0`, `2`, and `4`, seeks
with the dword at `+6`, compares the returned position to it, and copies the
dword at `+10` into its selected-record remaining-byte state. This corroborates
the on-disk interpretation of the 14-byte layout as three 16-bit lookup values
followed by a 32-bit file position and a 32-bit payload/read-budget value.

The writer evidence is static and conditional: it does not prove its mode-2
paths execute successfully, that all writes complete, or that an output file
matches an installed resource. The stored third word is sourced from mutable
writer state, so this result does not assign a universal semantic label to it.
Likewise, the reader evidence does not establish uniqueness, table order, or
the meaning of payload bytes.

## Reproduction

```sh
python3 tools/research/verify_srsc_record_field_anchors.py research/binaries/us/Drakan.exe
python3 -m unittest discover -s tools/research -p 'test_verify_srsc_record_field_anchors.py'
objdump -d -Mintel --start-address=0x0045f0d0 --stop-address=0x0045f805 \
  research/binaries/us/Drakan.exe
```

The verifier asserts only the executable hash and 14 bounded instruction
anchors. It does not analyze dynamic dispatch, file contents, or alternative
editions.
