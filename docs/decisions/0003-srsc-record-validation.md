# ADR 0003 — SRSC record bounds and interpretation

**Status:** Accepted, 2026-10-17.

The inspector's original 128 MiB limit described below was superseded by
[ADR 0004](0004-bounded-inspection-texture-header.md); the other record
validation decisions remain in effect.

## Context

The retail loader reads 14-byte SRSC entries. Evidence in
`docs/research/srsc-record-behavior.md` shows that one path compares the first
three little-endian 16-bit values, while two selection paths use the following
32-bit values as a file seek position and a remaining read budget. Retail
measurements show particular layout patterns, but they do not establish general
requirements for all versions or files.

## Decision

Expose these fields as three unnamed selector values, a file offset, and a
length, preserving record order and duplicate selectors. Reject a record when
its payload range exceeds the supplied file bytes, using checked arithmetic.
This is DragonRider's input-safety policy, not a claim about validation in the
original executable. Validate the header and entire table before returning
records. Inspector output is explicitly limited to 50 entries; it checks all
record ranges before printing any entries. Its existing 128 MiB file limit
continues to apply.

Do not require unique selectors, contiguous payloads, a nonzero payload size,
or the table ending at EOF. Do not assign a resource type, decode payloads, or
interpret selector meanings until corroborated.

## Consequences

The reader can safely expose established table information and help direct
further research. Bounds validation alone does not establish that payloads are
well-formed or compatible with the original game. Alternate versions and
support for offsets at or above 2 GiB require further evidence.
