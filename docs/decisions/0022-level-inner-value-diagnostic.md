# ADR 0022 — Bounded level inner-value diagnostic

**Status:** Accepted, 2026-10-19.

## Context

The `(1,0,0)` level reader consumes per-entry 32-bit values, compares each
raw value with the current entry index, and copies the low 16 bits into runtime
storage. A later loop uses the low half as an index into the same runtime
entry array. See [the level prefix trace](../research/level-0001-prefix.md).
The general purpose of the relationship and runtime validity are unresolved.

## Decision

Extend the existing bounded reader with an optional callback for each raw
inner dword and its containing entry index. Check the entire entry's inner
byte span before invoking its callbacks. As with other callbacks, later errors
can occur and clients must discard partial results after any failure. The
existing entry, inner-count, block and total decoded limits remain in force.
Do not reject high bits, out-of-range indices, repeats, missing self-values,
or nonreciprocal relationships based on retail sample observations.

Add `--level-links RECORD_INDEX FILE` to report totals of raw high halves,
raw and low-half values outside the entry count, and low-half self-equality.
The result is a byte-level diagnostic, not runtime traversal, identity
resolution or a validity guarantee. The diagnostic summary is emitted after full block
inspection and the existing file-size recheck. Do not expose names or load
paths.

## Consequences

Callers can inspect the evidenced list without committing to a scene or graph
model. Reported low-half comparisons do not apply the game’s full-dword
self-comparison, emulate mutable runtime state, or prove that arbitrary index
values are safe in the original. Other editions and Windows remain untested.
