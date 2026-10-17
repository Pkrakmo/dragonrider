# ADR 0002 — DragonRider project naming

**Status:** Accepted, 2026-10-17.

## Context

The project began under the working name Drakan Reborn. It is an independent, open-source C++20 engine reimplementation, initially targeting compatibility with *Drakan: Order of the Flame* on Windows and Linux. A consistent identity avoids confusing the project with the original game or its source code.

## Decision

Use `DragonRider` permanently as the project and repository name. Use `dragonrider` as the C++ namespace and public include prefix, `dragonrider_engine` as the engine library, and `dragonrider`, `dragonrider_inspect`, and `dragonrider_viewer` for the planned main executable, asset inspector, and level viewer. Application names are reserved conventions, not claims that those applications have been implemented.

## Consequences

Update project-owned documentation, identifiers, and build targets. Preserve references to the original game, Psygnosis, Surreal Software, and Riot Engine when historically appropriate. Do not rename game files, extracted assets, or the existing `Drakan_US_Retail` Ghidra project. Preserve historical evidence paths and hashes. The existing Ghidra wrapper's cooperative lock filename also remains unchanged so older and newer wrapper instances cannot bypass one another's lock.
