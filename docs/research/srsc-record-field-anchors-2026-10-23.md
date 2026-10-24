# SRSC 14-byte record reader/writer anchors — 2026-10-23

## Scope and provenance

**Input:** unpatched US retail `Drakan.exe`, SHA-256
`23630f48e20e8a9f42026501165ae1df407cfcee545a784ec930a4c25ee70648`.
**Method:** whole-`.text` GNU objdump 2.45.1-5.fc43 disassembly with bounded
instruction anchors, checked by the committed verifier. No Ghidra project was
opened, no program code was executed, and no private export was written.
**Confidence:** high for the listed instruction operands and direct call set;
limited for control-flow feasibility and all untraced writer/reader paths.

## Observed

The common writer's documented state and table stores have these anchors:

| Record offset | Static writer observation |
| --- | --- |
| `0` and `2` | caller-provided 16-bit inputs are stored by the common initializer (prior bounded trace) |
| `4` | the setter masks its input to 16 bits, stores writer `+8`, then the initializer loads that word and writes it at table-record `+4` |
| `6` | the initializer writes the current file-position result at table-record `+6` |
| `10` | the closer subtracts record `+6` from a later file position and stores the result at record `+10` |

The full executable `.text` disassembly also contains exactly two direct
calls to the third-selector accessor `0x0045FAD0`, at `0x0042B0D9` and
`0x00435601`, and no direct unconditional jump to that accessor. At
`0x0042B0D9`, the returned word is stored at runtime cache-entry `+4`. At
`0x00435601`, the next instructions test the returned word for zero; only on
zero does that path read the record's first selector and require `0x0030`
before selecting it. This is a branch-specific use of the third word as a
zero predicate, not a general semantic name or format-wide constraint.

A byte scan of the pinned executable also found no exact little-endian
absolute-address literal for `0x0045FAD0`. This excludes that raw byte pattern
only; it does not rule out computed, relocated, runtime-written pointers, or
indirect dispatch.

An independent aggregate scan rechecked all 178 US SRSC inventory hashes and
found 39 `0x0030` records; all 39 have a zero third word. This matches the
branch filter in this sample but does not establish why the word is zero or
whether other editions contain nonzero values. The bounded palette trace and
reproduction command are in [the palette note](texture-palette-behavior.md#third-selector-comparison-with-the-bounded-loader-branch-2026-10-23).

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
objdump -d -Mintel --start-address=0x0042B0D0 --stop-address=0x0042B0E5 research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x004355F8 --stop-address=0x00435620 research/binaries/us/Drakan.exe
objdump -d -Mintel --start-address=0x0045f0d0 --stop-address=0x0045f805 \
  research/binaries/us/Drakan.exe
```

The verifier asserts the executable hash, 17 bounded instruction anchors,
the complete direct call/jump reference set, and absence of a raw absolute
address literal for the accessor. It does not analyze computed or indirect
dispatch, file contents, or alternative editions.
