# ADR 0019 — Bounded SRSC 0x0102 prefix inspection

**Status:** Accepted, 2026-10-18.

## Context

The successful path of a US retail consumer reads a 16-bit length, the
specified bytes, a skipped word, a dword, a word, and another skipped word.
A private sample confirms this sequence fits the selected records. See
[the research trace](../research/srsc-0102-runtime.md). The meanings of the
prefix, skipped words, trailing data and general third selector remain open.

## Decision

Provide a structural parser that preserves the prefix as a caller-owned byte
view and exposes the four raw little-endian values and consumed length. It
rejects truncation; it does not require printable text, a terminating NUL, or
selector equality. Empty prefixes and opaque tails are accepted as input
policy, not as claims about retail behavior.

The inspector's `--record-0102 INDEX FILE` requires an explicitly selected
first selector `0x0102` and validates all table ranges. It reads at most
65,547 payload bytes, the maximum needed for the 16-bit length and fixed
fields, and reports raw fields, third selector, prefix length and CRC32, and
unvalidated tail length. It does not print or resolve embedded names, follow
references, reproduce the runtime lookup or apply the consumer's gate.

## Consequences

The diagnostic supports byte-level comparisons without treating correlations
as format invariants. A successful parse does not establish runtime use or
semantic identity. CRC32 is a summary rather than an integrity guarantee.
The inspector detects changes in file size but not all same-size concurrent
changes; other editions and Windows remain untested.
