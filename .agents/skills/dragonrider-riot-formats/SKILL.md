---
name: dragonrider-riot-formats
description: Research or implement evidenced Riot resource formats for DragonRider, including SRSC records and bounded asset inspection.
---

# Riot resource formats

Read `docs/ARCHITECTURE.md`, `docs/research/srsc-format-status.md`, relevant research notes and format ADRs before extending a reader. Treat external documentation as a hypothesis and distinguish measured sample properties from format invariants. Keep retail and patch 445 evidence separate.

Start with original-byte and loader evidence, then implement only supported interpretations independently. Preserve unknown fields and distinguish physical provenance from logical identity. Validate every read, little-endian conversion, offset, length, count, arithmetic overflow and resource limit. Keep `assets/riot` independent of renderer, platform UI, Ghidra and gameplay. Do not resolve untrusted embedded paths without a separately justified policy.

Use synthetic fixtures for deterministic valid and malformed cases, including truncation and boundary conditions; private retail comparisons are optional, locally run evidence and must not become public fixtures. Document confidence and counterexamples, and add an ADR for a changed format policy or boundary.
