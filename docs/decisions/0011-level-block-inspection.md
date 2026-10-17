# ADR 0011 — Bounded level block inspection

**Status:** Accepted, 2026-10-17.

## Context

The retail level loader reads a `(1,0,0)` record with a variable-length first
loop followed by one dimension-derived block per entry. A scan of the US
inventory found complete zlib streams on storage word 1; see
[the trace](../research/level-0001-blocks.md). The content's complete semantics,
other storage values, other editions and runtime behavior are not established.

## Decision

Provide a structural diagnostic with explicit caller-supplied entry, per-entry
count, per-block decoded byte and aggregate decoded byte limits. Validate all
reads and arithmetic, reject negative counts and dimensions, and support only
storage words 0 and 1. For 0, use the traced raw read size and ignore the
preceding word, as that path does; no sample of this branch has been verified.
For 1, require exactly one complete zlib stream per length-delimited block,
with exactly the derived output size and no unused compressed bytes. These
strict checks and limits are DragonRider inspection policy, not a claim that
the original loader performs them. Other storage values are rejected pending
evidence, even though the original branches on signed positivity.

The inspector requires an explicitly selected `(1,0,0)` record, limits payload
and individual decoded blocks to 32 MiB, aggregate decoded bytes to 256 MiB,
and both counts to 4,096. It reports aggregate counts, length, CRC32 and the
range of the loader's `2 * word - 65536` transformation for the second word
of each four-byte grid item. It excludes the following cell data and reports
remaining bytes as opaque from that range. It also reports counts for cell
flag bits 0 and 1 and negative signed dwords at cell offsets 2 and 6, without
resolving those values or predicting rendering. See the
[cell trace](../research/level-cell-draw-behavior.md). No names, indices,
paths or geometry are resolved or exported. The version gate is not applied.

## Consequences

The diagnostic validates a larger evidence-backed part of a level without
introducing rendering assumptions. Complete stream checks are stricter than
the observed call sequence and may reject files the original loader attempted
to process. The scan covers only inventoried US retail files, and no result
establishes visual correctness, completeness of extraction, or Windows support.
