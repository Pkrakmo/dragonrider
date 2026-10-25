# ADR 0026 — Inspect the observed SRSC `0x0501` consumer prefix

**Status:** Accepted, 2026-10-24.

## Context

One hash-pinned US-retail consumer path selects a first-match `0x0501`
record, skips a 16-bit-length-prefixed byte span, and subsequently performs
seven fixed-width reads. The sample has a further 16-byte suffix, but neither
the consumer's read success nor the suffix's meaning is established. The
static anchors and private aggregate measurements are documented in
[SRSC record behavior](../research/srsc-record-behavior.md).

## Decision

Expose a caller-supplied, bounded structural reader in `assets/riot` for only
this observed prefix. It returns input-backed views of the skipped bytes and
unconsumed remainder plus seven little-endian raw dwords. It rejects a
truncated prefix or fixed read through the checked binary reader.

The reader does not select a record, assign field names or meanings, require a
16-byte suffix, join neighbouring `0x0503`/`0x0502` records, or model runtime
execution. All returned views require the caller to retain the payload.

## Consequences

Synthetic malformed inputs can be tested without distributing game data, and
private sample measurements can compare the observed prefix without promoting
the complete `0x0501` payload to a format grammar or runtime object.
