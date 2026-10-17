# ADR 0009 — Bounded level database-list inspection

**Status:** Accepted, 2026-10-17.

## Context

The traced retail level loader reads a selector `(0,0,0)` prefix containing a
length-prefixed byte sequence, two dwords, a count and count repetitions of a
dword and length-prefixed bytes. See [the evidence](../research/level-directory-behavior.md).
The lookup has a version gate and the source strings are used in a path-related
operation, but their general encoding, meaning and safe resolution are unknown.

## Decision

Provide a structural parser that preserves file-order raw bytes, both unnamed
dwords, ordered entry values and names, and the end of the parsed prefix. It
checks all reads and requires an explicit count limit, rejects negative signed
counts, and leaves trailing bytes opaque. It accepts empty counts and names,
duplicate values and embedded zeroes without claiming runtime equivalence.
The inspector requires an explicitly selected `(0,0,0)` record, bounds its
payload and entry count, and reports byte lengths and CRC32 values rather than
interpreting or opening referenced names. It does not apply the original gate.

## Consequences

This adds an evidence-backed level inspection step without imposing sampled
file layouts, resolving untrusted paths, or assigning unproven logical asset
IDs. These checks do not establish playable levels, geometry, other editions,
or correctness of every `(0,0,0)` record in every container. Any future path
resolution and version policy need independent evidence and a separate decision.
