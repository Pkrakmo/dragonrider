# ADR 0024 — Inspect the selected 0x0302 new-object framing

**Status:** Accepted, 2026-10-19.

## Context

Retail disassembly shows that one selector-`0x0302` consumer follows different
read sequences for a newly allocated object and a previously cached object.
The sampled bytes fit the new-object sequence, but actual cache state, read
success and processing are not established. See the
[static trace and measurement](../research/srsc-0302-selector-followup.md).

## Decision

Expose a caller-selected, bounded structural reader for the hypothetical
new-object path. It preserves the prefix and body as input-backed byte spans,
reports the unassigned scalar fields and mode, and leaves trailing bytes
unvalidated. In zero mode the fifth dword supplies the body size; otherwise
an additional dword supplies the stored span size. The caller supplies a body
limit; the inspector additionally caps each selected record at 32 MiB. These
are safety limits, not claims about the original format.

The reader does not select runtime sources, model cache state, infer meaning
from selectors, decode or decompress the stored span, or assert that the game
would reach this branch. The existing-object path has a different offset and
is outside this diagnostic. All returned spans require the original payload
to remain alive.

## Consequences

Synthetic malformed inputs can be rejected deterministically and sampled
framing can be compared independently without publishing assets. Successful
inspection establishes only that the selected bytes fit this framing; it is
not validation of a runtime object or other editions.
