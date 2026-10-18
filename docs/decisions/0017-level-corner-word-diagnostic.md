# ADR 0017 — Level corner word diagnostics

**Status:** Accepted, 2026-10-18.

## Context

The observed level draw path associates each point-array slot with two words
from a decoded cell. Four-point and three-point paths use different scale
constants, and runtime conditions determine which path proceeds. See the
[trace](../research/level-cell-topology.md).

## Decision

Extend the explicit normal and mode-1 candidate diagnostics with four
point-array slots, each reporting the grid index, first raw word, and
`65535 -` the corresponding second raw word. Preserve word-slot order when
the chosen orientation changes point order. The inspector reports integer
values after the whole record is validated; it does not apply a branch's float
scale, model mode 2, decide visibility, resolve textures or output a mesh.
Existing candidate triangles continue to describe the selected three-point
branch even when the input's flags could permit the four-point branch.

## Consequences

The asset layer remains independent of rendering and runtime state. A slot
association or flag is not proof of submission or visual correctness. Synthetic
tests and the private retail comparison validate data extraction and the
calculation, not the original device output or other executable editions.
