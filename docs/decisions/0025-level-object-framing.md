# ADR 0025 — Bounded level-object framing

**Status:** Accepted, 2026-10-19.

## Context

One retail level loader selects `(0x20,0,0)` and conditionally reads
variable-sized object records. Static tracing and a hash-checked US sample
comparison are documented in [the object investigation](../research/level-entry-caller-followup.md#conditional-full-object-framing-2026-10-19).
Objects' meanings, runtime associations, success of the retail reads and
other editions are not established.

## Decision

Provide a caller-supplied payload structural reader in `assets/riot`. It
retains unassigned dwords and words, input-backed index and optional byte
views, the two raw count bit patterns, and each object's end position. When
both counts are positive, it also returns input-backed raw views of the two
conditional arrays and the contiguous length-framed bytes, after validating
their full extent. It
checks every skipped region, multiplication and length-prefixed sequence,
limits declared objects and indices, and limits both counts when both are
signed-positive. These safety limits are not claims about retail validity.
The returned end position allows callers to report or inspect an opaque tail.

The reader does not select an SRSC record, interpret references, require
index values to be in range, construct runtime objects, access embedded
paths, or parse the conditional arrays' meanings. Callbacks may have occurred
before a later failure; consumers must discard partial results. Byte views
depend on the caller retaining the payload.

The inspector's `--level-objects` selects an explicit `(0x20,0,0)` record,
caps its input at 32 MiB and counts at one million, and reports aggregate
object, index-word, flag, conditional-array and opaque trailing-byte counts
only after successful validation. These are diagnostic limits, not original
format restrictions.

## Consequences

Independent tools can compare bounded framing across private samples without
publishing assets or asserting that the runtime chose this path. Implementing
this structural view does not establish a complete level format or renderer.
