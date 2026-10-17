# ADR 0014 — Bounded level grid observations

**Status:** Accepted, 2026-10-17.

## Context

A selected drawing path constructs point components from grid dimensions,
two signed entry dwords, a floating-point base, and the transformed second
word of each grid item. Further runtime offsets and rendering state matter;
see [the trace](../research/level-grid-coordinate-path.md).

## Decision

Extend the existing bounded level block reader with an optional streaming grid
callback. It exposes entry index, dimensions, row and column, signed raw
origins, raw base bits, and both raw grid words. It does not allocate a mesh or
apply floating-point, visibility, or rendering assumptions. As with the cell
callback, callers must discard partial results on any later validation error.
Existing input, count, block and total decoded limits still apply.

Add `--level-grid RECORD_INDEX ENTRY_INDEX FILE` for a selected `(1,0,0)`
record and entry. Report dimensions, raw origins and base bits, grid point
count, first-word bit-8 count, transformed second-word extrema, and nominal
integer horizontal ranges computed with signed 64-bit arithmetic and 2048-unit
steps. These nominal ranges omit float rounding and dynamic adjustments and do
not describe final world bounds. Do not reject nonfinite base bit patterns or
claim semantic meaning for individual axes.

## Consequences

The reader provides evidence-backed ingredients for further level work without
introducing renderer dependencies or treating incomplete runtime state as a
mesh. Decoded block validity does not establish visual correctness or level
compatibility. Windows and other editions are untested.
