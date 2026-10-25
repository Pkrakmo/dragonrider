# ADR 0027 — Keep the observed `0x0501` trio and `0x0502` rows structural

**Status:** Accepted, 2026-10-25.

## Context

The hash-pinned US-retail constructor path documented in [SRSC record
behavior](../research/srsc-record-behavior.md) first-pair-selects `0x0501` in
a stable-second-selector ordering. In all measured US examples its two next
rows are `0x0503` and `0x0502` with the same second selector. The same static
path reads a 16-bit count from the selected `0x0502` payload, requests `52 ×
count` bytes, and iterates in 52-byte strides while transforming three
dwords. The ordering, count relationship, and stride are evidence for one
path, not a complete SRSC grammar or runtime success.

## Decision

Expose two caller-selected diagnostics in `assets/riot`:

- a helper that reports the first observed `(0x0501, key)`, `(0x0503, key)`,
  `(0x0502, key)` ordered run, returning no result when the relationship is
  absent and retaining the third selector words uninterpreted;
- a `0x0502` payload reader that validates the count and complete 52-byte
  rows, preserves every row and tail as input-backed opaque spans, and does
  not expose or name interior fields.

Both readers reject invalid traversal/range input. They do not require the
measured neighboring relationship, exact payload extent, contiguous storage,
or an empty trailing span.

## Consequences

Synthetic tests can exercise row truncation, maximum count, opaque tails,
missing neighbor sequences, and malformed order maps without distributing
retail files. The engine does not gain a model, ownership rule, runtime
dispatch, field meaning, or general format invariant from these helpers.
