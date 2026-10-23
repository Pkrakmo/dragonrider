# Level `(1,0,0)` query-helper direct callers — 2026-10-23

## Scope and provenance

**Input:** unpatched US retail `Drakan.exe`, SHA-256
`23630f48e20e8a9f42026501165ae1df407cfcee545a784ec930a4c25ee70648`.
**Method:** GNU objdump 2.45.1-5.fc43 static disassembly. This report did not
open Ghidra, execute the program, inspect media, or write a private export.
It follows the bounded direct-caller procedure in the
[static-review handoff](level-0001-static-review-2026-10-23.md) and the query
branches already recorded in [the level-block trace](level-0001-blocks.md).
**Confidence:** high for the shown direct relative call instructions and their
immediately preceding flag push; no claim is made about reachability or caller
semantics.

## Observed

A whole-image text disassembly has 23 direct relative `CALL` instructions to
`0x00420e10`. The list is below the 32-call procedure cap. For each call, the
listed half-open inspection window begins 96 bytes before the call and ends
five bytes after it. The helper reads its flag byte from its fifth stack
argument (`[ebp+0x18]`); on these call sequences that is the first shown push
for the helper.

| Direct call | Inspected window | Flag provenance in the window |
| --- | --- | --- |
| `0x00403623` | `0x004035c3–0x00403628` | literal `4` |
| `0x0040374e` | `0x004036ee–0x00403753` | literal `5` |
| `0x00403820` | `0x004037c0–0x00403825` | literal `5` |
| `0x004038d2` | `0x00403872–0x004038d7` | literal `5` |
| `0x004039a9` | `0x00403949–0x004039ae` | literal `5` |
| `0x00403a23` | `0x004039c3–0x00403a28` | literal `5` |
| `0x0040489c` | `0x0040483c–0x004048a1` | literal `5` |
| `0x0041f62e` | `0x0041f5ce–0x0041f633` | literal `5` |
| `0x0041f7c3` | `0x0041f763–0x0041f7c8` | literal `5` |
| `0x004205df` | `0x0042057f–0x004205e4` | literal `5` |
| `0x00420694` | `0x00420634–0x00420699` | literal `5` |
| `0x004207f0` | `0x00420790–0x004207f5` | literal `5` |
| `0x00420d93` | `0x00420d33–0x00420d98` | value loaded from caller `[ebp+0x20]` |
| `0x00420dab` | `0x00420d4b–0x00420db0` | literal `5` |
| `0x0043fef2` | `0x0043fe92–0x0043fef7` | literal `4` |
| `0x00441444` | `0x004413e4–0x00441449` | literal `5` |
| `0x00441734` | `0x004416d4–0x00441739` | literal `5` |
| `0x0044c49f` | `0x0044c43f–0x0044c4a4` | literal `4` |
| `0x0044c5d2` | `0x0044c572–0x0044c5d7` | literal `5` |
| `0x0044c742` | `0x0044c6e2–0x0044c747` | literal `4` |
| `0x0044c8a0` | `0x0044c840–0x0044c8a5` | literal `5` |
| `0x0044c95f` | `0x0044c8ff–0x0044c964` | literal `4` |
| `0x0044cb63` | `0x0044cb03–0x0044cb68` | callee fifth argument; sole direct caller supplies literal `5` |

Thus 17 listed direct calls supply literal `5`, five supply literal `4`, and
one passes a value derived from a caller input. Literal `5` has bit `0x04`
set; literal `4` has bit `0x04` set and bit `0x01` clear. Neither literal
category sets `0x08`, `0x10`, or `0x20`, which are among the documented
discriminator branches in the helper. The sole nonliteral case at `0x00420d93`
requires further bounded caller tracing; `0x0044cb63` was resolved in the
[follow-up trace](level-0001-query-flag-44cb63-2026-10-23.md).

## Limits and unknowns

The direct-call list omits indirect, virtual, tail-jump, data-driven, or
unrecovered calls. It does not establish that any listed path executes, that
the remaining dynamic flag takes a particular value, what the flags mean, or
what effect the discriminator has on gameplay or rendering. In particular,
the result does not make literal `4` or `5` a format invariant.

## Reproduction

```sh
sha256sum research/binaries/us/Drakan.exe
objdump --version | head -n 1
objdump -d -Mintel research/binaries/us/Drakan.exe \
  | rg -n 'call[[:space:]].*(420e10|<.*420e10>)' | head -n 32
objdump -d -Mintel --start-address=0x0043fe60 --stop-address=0x0043ff10 \
  research/binaries/us/Drakan.exe
```

For every reported call, subtract `0x60` from its address and use the call
address plus five as the `objdump` window bounds. Record only the call address,
window and argument provenance; do not publish the private executable or bulk
disassembly.

The committed bounded verifier checks the executable's pinned SHA-256 and the
23 direct relative call addresses before this report's per-window provenance
classification is reused:

```sh
python3 tools/research/verify_level_query_callers.py research/binaries/us/Drakan.exe
python3 -m unittest discover -s tools/research -p 'test_verify_level_query_callers.py'
```

It deliberately does not classify stack arguments or make any inference about
the absent indirect-call population.
