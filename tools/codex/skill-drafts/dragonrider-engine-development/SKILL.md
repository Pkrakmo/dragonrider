---
name: dragonrider-engine-development
description: Implement and test portable C++20 engine or inspector changes in the DragonRider repository.
---

# Engine development

Read `AGENTS.md`, `TODO.md`, `docs/ARCHITECTURE.md` and relevant ADRs; inspect existing code and tests before editing. The project independently reimplements behavior and requires user-owned assets. Use the `dragonrider` namespace and include prefix, `dragonrider_engine` library, and established app names.

Respect module boundaries and build for GCC/Clang and MSVC. Prefer C++20 RAII, spans, filesystem paths and fixed-width types. For untrusted binary input, bound reads and allocations, check arithmetic and endian conversions, and return clear errors. Implement only interpretations supported by research; keep raw on-disk layouts out of render and game APIs. Review third-party licenses and add an ADR when dependencies or architectural boundaries change.

Use synthetic tests for correctness, malformed data and meaningful boundary cases. Run relevant CMake builds and CTest suites; document commands and platform gaps, including Windows if untested. Never place original assets in tests, artifacts or version control.
