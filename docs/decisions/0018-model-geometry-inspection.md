# ADR 0018 — Bounded model geometry records

**Status:** Accepted, 2026-10-18.

## Context

The US retail model-loading path reads 12-byte triples and variable-length
groups from consecutive records. The selected US samples corroborate the
layout and contain three- and four-corner groups; see
[model geometry research](../research/model-geometry-records.md). Coordinate
system, material semantics, and final rendering are not yet established.

## Decision

Implement a bounded structural reader for two explicitly supplied payloads.
Retain each triple as three raw 32-bit words and each group as two raw header
words plus its ordered entries, each comprising a 16-bit candidate point index
and two raw 32-bit words. Record consumed lengths and count indices outside the
point array; preserve such indices rather than rejecting them because retail
behavior for malformed or other-edition inputs is not established. Do not
restrict groups to three or four entries solely because these were observed
in the US sample. Leave trailing data opaque.

Require caller-supplied point, group and total-entry limits. Inspector mode
`--model-geometry POINT_RECORD GROUP_RECORD FILE` requires first selectors
`0x0203` and `0x0204`, respectively, validates the entire SRSC table, limits
each input payload to 32 MiB and the total number of entries to one million,
and reports whether the other selector words match. It does not resolve the
pair automatically, apply version gates, convert raw floats, follow embedded
references, or produce a mesh. CRC32 summarizes consumed bytes only.

## Consequences

The reader provides evidence-backed data for later model work while keeping
original packed layouts inside the asset layer. An in-range candidate index,
matching selectors or structurally valid group does not prove visual
correctness, material association or runtime use. Input limits are project
safety policy rather than claims about retail acceptance. Windows and other
retail editions remain untested; same-size concurrent changes may go unnoticed.
