# Retail RFL pointer callback boundary

## Evidence

Date: 2026-10-23. Observed static behavior at `0x10014d50..0x10014e04`
in US retail Dragon.rfl, SHA-256
`9b6496b65e962cf35dd1e18f424f2c8af08ceade78331dcc0b6da332ce844ac3`.
The [binding report](input-callback-binding-2026-10-23.md) establishes its
conditional connection to the EXE callback field +0x5c8. No original program
was executed. Ghidra 12.1.4/OpenJDK 25.0.4.1 findings were independently
checked with GNU objdump 2.42, including the raw jump table. Confidence is high
for this boundary, not for downstream UI semantics.

## Observed contract

Four stack arguments correspond to `(kind, code, x, y)` from the EXE event
consumer. These are descriptive labels, not recovered source types. At
`0x10014d50`, the callback loads a receiver from global `0x1017ae08`; a null
receiver returns 0. Code `0x100` selects mask 3, code `0x101` mask 5, all other
codes mask 0. An unsigned kind comparison at `0x10014d85` accepts only 0..3;
other bit patterns, including negative signed interpretations, return 0.

Call notation below lists the receiver separately from the three stack
arguments `(mask,x,y)`; the receiver is supplied in ECX.

| Kind | Calls and masks | Sites |
| --- | --- | --- |
| 0 | `0x10128850` with initial receiver and mask 0; then `0x10128710` with mask `selected & ~1` | `0x10014db1`, `0x10014dc2` |
| 1 | `0x10128850`, then `0x10128710`, each with selected mask | `0x10014d9c`, `0x10014dc2` |
| 2 | Only `0x10128850` with selected mask | `0x10014df1` |
| 3 | Add bit 0x08 for code 0x114, or bit 0x10 for code 0x115; call only `0x10128850` | `0x10014dd7`/`0x10014de3`, `0x10014df1` |

For kinds 0/1 the second helper's receiver is **reloaded from global
0x1017ae08 at 0x10014dbb**. The initial null guard does not prove that this
second receiver remains nonnull or unchanged after the first helper.
Both helpers receive the original x/y arguments. Valid kinds return 1 at
`0x10014dc9` or `0x10014df8`, independently of helper return values.

The raw jump table `0x10014e08..0x10014e17` contains targets
`0x10014da5`, `0x10014d91`, `0x10014de6`, `0x10014dd0` in kind order.
This independently resolves the decompiler's switch rather than assuming
its recovered cases are complete.

## Inference and remaining boundary

The EXE emits kinds 0/1 for button status, 2 for coordinate motion, and 3 for
the selected third-axis path. The module transforms those into masks and
two downstream call families. Exact coordinate representation, receiver
ownership, helper effects, and whether events are consumed by a particular
widget remain unknown. The EXE caller ignores this callback's return value;
return 1 here therefore does not prove propagation stops.

This supports separating normalized pointer events from module/UI routing.
It does not establish a complete portable UI contract or justify importing
unreviewed gameplay dispatch code.

## Reproduction

Verify the hash above before using these VAs, then:

```sh
sha256sum "$DR_RFL"
objdump -d -Mintel --start-address=0x10014d50 --stop-address=0x10014e05 "$DR_RFL"
objdump -s --start-address=0x10014e08 --stop-address=0x10014e18 "$DR_RFL"
```

Process the already imported private RFL project sequentially with
`-process Dragon.rfl -readOnly -noanalysis -postScript
InspectPinnedRetailFunctions.java 0x10014d50`, using the environment and
script in the binding report. This function was initially undefined; the
script explicitly recovered it and completed successfully. Raw data,
decompilation and logs remain outside Git.
