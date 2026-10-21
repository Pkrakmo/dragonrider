# ADR 0023 — Bounded level entry-prefix diagnostics

**Status:** Accepted, 2026-10-19.

## Context

The retail `(1,0,0)` reader fills the first dword of each runtime entry from
its serialized prefix. A retail helper compares that dword in entry order and
returns the first matching index, or `-1`; a `0x0102` descriptor dispatch
can use the helper. The identity and lifecycle of the selected runtime level,
and the wider meaning of this value, remain unverified. See
[the trace and measurements](../research/level-0001-prefix.md#first-dword-lookup-and-type-12-candidates-2026-10-19).

## Decision

The bounded level inspector may report seven raw dwords, the intervening
length-prefixed byte sequence, six following raw dwords and the inner count,
in serialized order. The optional callback receives a byte view into its
caller-owned payload; it is valid only while that input remains alive. The
reader checks the entire inner array before the entry callback. Later errors
can occur, so callers must discard partial callback results on failure.
Existing input, count and decompression limits apply.

`--level-entry RECORD ENTRY FILE` reports the raw dwords, byte-sequence
length and CRC32, and inner count without displaying the sequence itself.
`--level-entry-find RECORD DECIMAL_DWORD FILE` counts matches of the first
raw dword and reports the first index, or `none`. Both commands finish bounded
block validation and the existing file-size recheck before their summaries.
Lookup accepts every 32-bit value, including zero and `0xffffffff`; individual
retail callers may apply different sentinel checks. No sample-derived
uniqueness rule is enforced and no runtime object or path is resolved.

## Consequences

The diagnostic exposes enough evidence to investigate a traced lookup without
requiring a scene model or treating sampled values as globally unique IDs. It
compares a caller-selected record in file order; runtime mutations, selected
level, other callers, other editions and visual behavior remain unknown.
