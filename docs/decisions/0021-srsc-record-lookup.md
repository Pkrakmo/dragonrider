# ADR 0021 — Explicit SRSC record ordering and lookup

**Status:** Accepted, 2026-10-19.

## Context

The [lookup trace](../research/srsc-lookup-order.md) describes a conditional
stable in-memory sort by the unsigned second selector and first-match pair and
triple searches. Stable ordering preserves the relative order of equal second
selectors but can change table indices. Not all callers necessarily sort, and
sorting can fail. Duplicate selectors occur in the measured files.

## Decision

Provide an explicit index mapping for file order or stable second-selector
order, leaving parsed records untouched. Pair and triple lookup scan a
caller-supplied mapping and return both the position in that mapping and the
original record index of the first match. They return no result on a miss.
Out-of-range mapping entries encountered during a search are rejected; a
caller-supplied mapping is otherwise used as supplied and is not required to
be a permutation. The generated mappings are permutations. Callers must retain
the records and their order for the lifetime of the mapping and select the
ordering based on their own evidence. These helpers neither seek nor parse
payloads and do not reproduce loader allocation failures or binary search.

## Consequences

The helper models first-match results for the traced paths with a correctly
ordered table while retaining original physical positions and duplicates.
It does not establish universal runtime ordering, matching policies for other
paths, selector semantics, or behavior for other editions. Synthetic tests
cover duplicate pairs and triples, both orderings, misses and invalid indexes.
