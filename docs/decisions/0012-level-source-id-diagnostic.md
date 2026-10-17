# ADR 0012 — Compare explicit level source ID candidates

**Status:** Accepted, 2026-10-17.

## Context

On a selected retail loading path, directory values can become runtime source
IDs and high halves of nonnegative cell dwords can select those sources. Object
reuse, allocation, collisions, caches and errors affect the outcome. The US
sample supports a file-level association; see
[the trace and measurements](../research/level-source-ids.md).

## Decision

Provide `--level-source-ids DIRECTORY_INDEX BLOCKS_INDEX FILE`, requiring
explicitly selected `(0,0,0)` and `(1,0,0)` records in the same SRSC container.
Use the existing bounded directory and block parsers. Classify each of the two
cell dword occurrences as negative, zero high half, matching one nonzero
16-bit directory value, matching multiple such entries, or unmatched. Report
only aggregate counts. Values greater than 65535 and zero cannot be explicit
high-half matches. Counts include repeated cell fields, even when runtime code
could reuse a result. Do not resolve names, follow paths, simulate loading or
claim successful texture resolution.

The block parser offers an optional streaming callback for raw cell dwords;
callbacks can occur before a later error, so callers must discard any partial
results on failure. Existing decoded-size and count limits continue to apply.
These checks are DragonRider diagnostic policy, not a claim about retail input
validation.

## Consequences

The diagnostic identifies a useful association without expanding the asset
trust boundary or prescribing path policy. Results do not determine which files
or selectors exist, and the same sample may behave differently with runtime
state or another edition. Windows remains untested.
