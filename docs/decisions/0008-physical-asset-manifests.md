# ADR 0008 — Physical provenance and logical asset identity

**Status:** Accepted, 2026-10-17.

## Context

SRSC records have validated physical ranges and three selector words, but the
selectors' individual meanings and lookup behavior are not established.
Duplicate tuples occur, so selectors alone cannot safely identify a logical
asset. A game-facing identity must not depend on a packed format or on a
particular edition's offsets.

## Decision

Represent a physical manifest as source provenance (caller-supplied edition,
container path, file size and optional SHA-256) plus an ordered list of record
indices, offsets and lengths. The SRSC adapter validates each range and
preserves order, duplicates, overlaps and zero-length ranges. A record index
identifies a location only within this source snapshot, not across revisions.
The reader's SRSC selector values remain available separately and are not
assigned meanings or promoted to logical IDs.

Define a distinct opaque logical ID value type, without creating a mapping,
namespace, uniqueness policy or asset resolver until evidence supports one.
No hash is computed or verified by the manifest API; the caller is responsible
for its correctness and for associating parsed records with the supplied source.
The inspector accepts an explicit edition label, reports the supplied path and
size, and lists all validated physical records; it reports that a hash was not
provided. Output can contain private paths and should remain local.

## Consequences

The neutral manifest has no renderer, gameplay or Ghidra dependency, and it
does not claim that bounded payloads are valid or that two locations represent
the same logical asset. Equal file sizes do not detect concurrent same-size
changes. The format-specific parser remains responsible for validating the
container header and table before supplying records. Future identity and
content-hash policies require separate decisions and evidence.
