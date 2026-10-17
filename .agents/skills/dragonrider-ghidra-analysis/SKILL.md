---
name: dragonrider-ghidra-analysis
description: Investigate DragonRider's retail executable using bounded, reproducible Ghidra analysis and corroborating binary evidence.
---

# Ghidra analysis

Read `AGENTS.md`, `docs/GHIDRA.md`, and the relevant `docs/research/` notes. Verify the input edition and SHA-256, Ghidra version, project location and imported program before making claims. Use `GHIDRA_HOME` and the existing wrapper when appropriate; `DRAGONRIDER_RESEARCH_ROOT` selects its private research root.

Serialize all access to a shared project, even read-only access. Close GUI sessions using that project before headless work. Use `-process` for an existing import, favor `-readOnly -noanalysis`, and never overwrite or delete a persistent project. Test unfamiliar integrations on a disposable project before using research databases. Keep logs and bounded exports in private ignored paths.

Trace the requested address and relevant callers, callees, constants and branches with bounded output; corroborate consequential offsets against raw bytes or independent disassembly. Decompiler names and types are provisional, and absent cross-references do not prove absent indirect callers. Report edition, input hash, addresses, method, tool version, confidence and limitations; separate observed facts, inferences and unknowns. Do not copy decompiled code into the engine or commit bulk exports.
