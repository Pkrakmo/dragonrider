# ADR 0015 — Bounded level cell candidates

**Status:** Accepted, 2026-10-17.

## Context

A selected executable drawing branch associates neighboring row-buffer points
with cell flags and constructs candidate point sequences. Other runtime
branches, clipping and source resolution remain incompletely understood; see
[the trace](../research/level-cell-topology.md).

## Decision

Extend the bounded streaming level reader with an optional callback for the
raw 26-byte cell fields, entry dimensions and row-major coordinates. Preserve
the existing callbacks and limits. Callbacks can run before a later failure;
callers must discard partial results if validation fails.

Expose a separate checked candidate calculation requiring explicit dimensions,
cell position, flags and normal or mode-1 orientation. Reject invalid
coordinates, arithmetic overflow and unsupported orientations. Add
`--level-cell RECORD ENTRY COLUMN ROW normal|mode1 FILE` to print the selected
raw cell and these point indices only after successful validation. This is a
branch diagnostic, not a mesh or a guarantee of rendered triangles. The caller
must choose the orientation; do not infer runtime state from the cell.

## Consequences

The asset module stays independent of rendering and remains bounded. No
clipping, runtime texture association, dynamic point adjustment or actual
rendering is implemented. Other executable editions and Windows remain untested.
