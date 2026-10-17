---
name: dragonrider-research-documentation
description: Document and review DragonRider reverse-engineering findings with provenance, evidence states and reproducible verification.
---

# Research documentation

Read `docs/RESEARCH.md`, relevant existing topic notes and `docs/GIT-WORKFLOW.md`. Write concise, independently authored findings in `docs/research/`, preserving existing evidence and disagreements. Record input edition and SHA-256, address where relevant, tool and version, procedure, confidence, limitations and reproducible verification. Explicitly distinguish observed facts, inferences and unknowns; label user reports as such and do not generalize beyond measured samples.

Exclude original media, private paths where sensitive, executables, game assets, databases, bulk decompilation and raw research exports from Git. Link the applicable evidence and ADRs. Add an ADR when an architecture boundary or format policy changes. The coordinator owns shared `TODO.md`, `AGENTS.md` and architecture documents; propose progress with proof rather than claiming an unexecuted check passed.
