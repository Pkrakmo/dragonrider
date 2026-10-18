# ADR 0020 — Bounded SRSC 0x0102 array inspection

**Status:** Accepted, 2026-10-18.

## Context

After the prefix in [ADR 0019](0019-srsc-0102-prefix-inspection.md), a
conditional US retail path reads a dword, compares it against a runtime
resource entry, and reads a second dword followed by that many four-byte units.
The sampled files contain the indicated units, usually with further opaque
data. See [the research trace](../research/srsc-0102-runtime.md).

## Decision

Add a structural reader for the two dwords and the indicated raw bytes after
an existing `0x0102` prefix. It requires a caller-supplied entry limit, checks
multiplication and payload bounds, preserves byte views and consumed length,
and leaves the remaining data opaque. Zero counts are accepted. Do not require
that the two dwords match or validate the first against a resource: the retail
comparison depends on runtime state and is not established for all inputs.

The inspector's `--record-0102-array INDEX FILE` validates the SRSC table,
requires a selected first selector `0x0102`, limits the count to one million
and reads at most 4,065,555 payload bytes. It reports the compared dword,
count, array CRC32 and unvalidated tail length. It does not load or inspect an
RFL, resolve references, or simulate the consumer's conditional branches.
These bounds are project input-safety policy, not claims about retail errors.

## Consequences

This exposes the evidenced framing without naming array values or requiring
proprietary runtime libraries. Successful structural parsing does not prove
that the game reaches the array read or interprets the units in any particular
way. CRC32 is a summary, not an integrity guarantee. Same-size concurrent
changes may go undetected; other retail editions and Windows remain untested.
