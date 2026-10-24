# Level `(1,0,0)` query-helper flag branch anchors — 2026-10-23

## Scope and provenance

**Input:** unpatched US retail `Drakan.exe`, SHA-256
`23630f48e20e8a9f42026501165ae1df407cfcee545a784ec930a4c25ee70648`.
**Method:** bounded GNU objdump 2.45.1-5.fc43 static disassembly, checked by
the committed verifier. No Ghidra project was opened, no code was executed,
and no private export was written. **Confidence:** high for the listed
instruction bytes and operands; runtime reachability and meanings are unknown.

## Observed

In the query helper beginning at `0x00420e10`, the documented flag tests are
at the following instruction addresses:

| Address | Observed instruction | Local condition described by the existing trace |
| --- | --- | --- |
| `0x0042106a` | `test bl,0x10` | before comparison of entry `+0x28` with `2` |
| `0x004212e3` | `test bl,0x8` | after reading entry `+0x28` on the later candidate path |
| `0x004212f1` | `test bl,0x20` | only after the same dword compares equal to `1` |
| `0x00421346` | `test bl,0x4` then `jne 0x00421392` | only after the same dword is nonzero on the alternate path |
| `0x00421350` | `test bl,0x20` | only after that dword compares equal to `1` on the alternate path |

The direct-caller inventory establishes literal flags `4` and `5` on all
resolved direct paths. Those values can set the observed bit-`0x04` test, but
do not set the observed `0x08`, `0x10`, or `0x20` tests. This is a static
bit-use observation, not a statement that any branch is feasible or what a
bit or discriminator value means.

The `0x00421349` branch targets the helper's per-candidate continuation at
`0x00421392`, which advances the candidate loop. Thus, only under the shown
alternate path and nonzero `+0x28` condition, an active `0x04` bit bypasses
the remaining acceptance work for that candidate. It does not prove that an
entry is rejected in any executed game query, or identify why either value is
used.

## Reproduction

```sh
python3 tools/research/verify_level_query_flag_branches.py research/binaries/us/Drakan.exe
python3 -m unittest discover -s tools/research -p 'test_verify_level_query_flag_branches.py'
objdump -d -Mintel --start-address=0x00420e10 --stop-address=0x004213ea \
  research/binaries/us/Drakan.exe
```

The verifier asserts only the executable hash and seven instruction anchors. It
does not find callers, infer values from registers, evaluate data-dependent
conditions, or exclude indirect/virtual paths.
