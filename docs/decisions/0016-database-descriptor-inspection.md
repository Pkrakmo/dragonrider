# ADR 0016 — Restricted database descriptor inspection

**Status:** Accepted, 2026-10-18.

## Context

The US retail executable reads a `.db` text file on a database loading path.
The 39 hash-verified US descriptors sampled use a version line, a count line,
and numbered names; see [research](../research/database-descriptors.md). The
full accepted grammar and runtime path resolution are not established.

## Decision

Provide a parser for the deliberately restricted observed version-1 text
form: exact `version 1` and `dependencies ` labels, nonnegative decimal
signed-32-bit-range integers, a single separator space, and nonempty raw name
bytes followed by LF or CRLF. Require a terminator for each line and reject
trailing data, embedded NUL and embedded CR. Preserve duplicate IDs, byte order,
name bytes and spaces; do not infer an encoding or normalize paths. Require
caller-supplied entry and name-byte limits; the inspector also limits the
complete file to 1 MiB and each of the other limits to 4096. These are
DragonRider safety and subset policies, not retail-loader compatibility claims.

`--database FILE` reports counts, IDs, name lengths and CRC32 checksums after
the whole file has been validated. It neither prints nor opens embedded names.
CRC32 is a diagnostic checksum, not an identity or security hash. Compare
original inputs through an opt-in private inventory and synthetic tests.

## Consequences

The asset module has a useful bounded source of raw dependency candidates;
it does not resolve names, establish installation layout, emulate the loader's
full grammar, associate IDs across formats, or claim compatibility with other
editions. The inspector's input size and name limits are not universal format
limits. As with other inspection modes, same-size concurrent file changes may
escape detection.
