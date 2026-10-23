# Research coverage map

**Status:** active tracker, 2026-10-23. **Scope:** public, bounded evidence and implementation tracking for the base retail investigation. This is not a compatibility percentage, a promise of format completeness, or an original-source recovery claim.

The machine-readable source is [`coverage-map.json`](coverage-map.json). It records one deliberately bounded topic at a time, links project-owned evidence, and separates byte/layout, loader, runtime, implementation, and validation states. Run this command to validate the schema and cited documents and calculate current totals:

```sh
python3 tools/research/verify_coverage_map.py docs/research/coverage-map.json
```

`bounded` means DragonRider has a checked diagnostic for an evidenced subset; it does not mean the whole format is known. `static_partial` is an observed disassembly path, not proof of runtime reachability. `private` validation means the check ran against user-owned, ignored inputs; it does not put those inputs in Git. States use the definitions in [the research log](../RESEARCH.md).

## Current map

| Topic | Layout | Loader | Runtime | Implementation | Validation | Next smallest question |
| --- | --- | --- | --- | --- | --- | --- |
| Retail data track | Measured | N/A | N/A | N/A | Private | Extraction completeness |
| CD audio | Measured | N/A | Unknown | None | Private | Audibility/cause of tail difference |
| Resource inventory | Measured | Unknown | Unknown | None | Private | Classify remaining generic files |
| SRSC table | Bounded | Observed | Unknown | Diagnostic | Private | Record-field semantics |
| SRSC `0x0102` | Bounded | Static partial | Unknown | Diagnostic | Private | Tail grammar or proven consumer |
| SRSC `0x0302` | Bounded | Static partial | Unknown | Diagnostic | Private | Playback-path dispatch |
| Database descriptors | Bounded | Static partial | Unknown | Diagnostic | Private | Full grammar/runtime association |
| Model geometry | Bounded | Static partial | Unknown | Diagnostic | Private | Topology/materials/transforms |
| Level `(1,0,0)` | Bounded | Static partial | Unknown | Diagnostic | Private | Fields and discriminator role |
| Level objects `(0x20,0,0)` | Bounded | Static partial | Unknown | Diagnostic | Private | Frame producer/consumer |
| Textures/palettes | Bounded | Static partial | Unknown | Diagnostic | Private | Visual correctness |
| Checked reader core | N/A | N/A | N/A | Partial | Synthetic | Add primitives only as needed |
| Renderer | Unknown | Unknown | Unknown | None | None | Backend ADR after display evidence |
| World/physics/animation | Unknown | Unknown | Unknown | None | None | Neutral world model from evidence |
| Audio runtime | Unknown | Unknown | Unknown | None | None | Prove candidate playback path |
| Gameplay/UI/save | Unknown | Unknown | Unknown | None | None | Defer until navigable level slice |
| Linux CI/portability | N/A | N/A | N/A | Partial | Synthetic | Verify hosted Linux CI |

The JSON is authoritative when this table and its totals diverge. Its intentional granularity avoids declaring a subsystem complete merely because a specific diagnostic is well-tested. A topic should advance only with a linked, reproducible observation; an inference belongs in a topic's next question or research note, not in a stronger state.
