# ADR 0001 — Canonical retail data baseline

**Status:** Accepted for current research; revisit if new evidence emerges.

## Context
US and English/UK Mode 1 data ISO payloads have the exact same SHA-256. Their audio-track BIN files 2–8 differ byte-for-byte.

## Decision
Use a single canonical **unpatched retail data** baseline derived from the user-owned US copy, while retaining provenance for both source discs. Preserve US/UK CD-audio variants separately until decoded PCM and CUE offsets are studied. Treat English patch 445 as a separate future reference.

## Consequences
One Ghidra project is sufficient for the byte-identical retail executable; no need to re-import the same binary as a separate UK version. Do not assume audio identity or patch identity.
