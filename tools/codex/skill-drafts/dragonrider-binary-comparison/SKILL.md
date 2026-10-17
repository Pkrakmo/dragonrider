---
name: dragonrider-binary-comparison
description: Compare user-owned DragonRider research binaries or media with reproducible provenance and bounded private outputs.
---

# Binary comparison

Read relevant `docs/RESEARCH.md` and `docs/research/` notes; identify edition, exact inputs, sizes and SHA-256 before comparing. Treat original media, extracted files and executables as read-only. Keep retail and patch inputs separate, and keep outputs containing raw bytes, private paths or bulk derived data under ignored research storage.

Choose a comparison appropriate to the question: hashes establish byte identity; offsets and bounded differences locate changes; decoding or behavioral checks require their own evidence. Differing compressed, container or disc bytes alone do not establish different decoded content. Use existing `tools/disc/` and `tools/research/` scripts where applicable, recording commands, versions, counts and limitations. Verify on synthetic inputs where a new comparison tool changes behavior.

Summarize findings independently in research notes with observed, inferred and unknown conclusions, without copying proprietary content into Git. Preserve all inputs and never move or remove research data as part of a comparison.
