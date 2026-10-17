# ADR 0004 — Bounded file inspection and selector-0x0040 header

**Status:** Accepted, 2026-10-17. Supersedes only the 128 MiB inspector limit
in ADR 0003; its record safety policy remains in force.

## Context

SRSC has a 16-bit table count and 14-byte entries. The inspector can read the
12-byte header and bounded table without loading payload data. Ghidra and retail
samples also establish a texture path for selector `0x0040` with a 50-byte
header; see `docs/research/selector-0040-behavior.md`. Pixel packing and the
full positive-storage branch remain unknown.

## Decision

Read SRSC metadata using bounded memory and checked seeks, without a whole-file
size cap. The maximum table is 65,535 × 14 bytes; validate every record range
against the file size before showing entries. Share header and table validation
with the existing span reader. Detect size changes during inspection, without
claiming a snapshot if bytes change while the file remains the same size.

For a selected `0x0040` record, expose the observed width, height, row byte
count, 16-bit depth and storage-control word. Check the 50-byte header and,
on the observed signed-nonpositive branch, the `height × row bytes` range
against the record length. Preserve other widths, depths and selector values;
do not infer a pixel layout or claim whole-record validation. Report positive
storage as undecoded. Independent research found zlib in samples, but this
decision does not make decompression or its limits part of the runtime API.

## Consequences

Large sparse or ordinary files can be inspected with bounded allocations. The
results describe structure, not visual correctness or validity of texture
contents. Further work is needed for pixel packing, additional blocks,
positive storage behavior and Windows verification.
