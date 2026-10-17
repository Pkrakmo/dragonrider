# 0010: A narrow disposable-project Ghidra MCP bridge

**Status:** experimental, 2026-10-17.

## Context

The external MCP candidates offer broad scripting or modification facilities,
have dependencies and licensing that require further review, and have not been
verified with our Ghidra installation. Research databases and original media
must remain private and protected from concurrent access.

## Decision

Evaluate a local, dependency-free stdio bridge exposing only the existing
bounded loader report against explicitly selected disposable projects below
`/tmp`. Require the US retail executable's Ghidra-reported import hash. Invoke Ghidra in
read-only, no-analysis mode and serialize cooperating bridge calls. Do not
connect the primary project or install a third-party server on this evidence.
No socket, runtime engine dependency, or general-purpose script tool is added.

## Consequences

This is a small research tool, not an operating-system security sandbox. A
path under `/tmp` does not prove isolation; the operator must create a fresh
project, avoid links to the original database and prevent GUI or other headless
access. The lock only coordinates this bridge. Its output derives from private
retail data and needs review before sharing. Codex registration and an actual
Codex tool call remain unverified in the restricted environment. The server
uses Linux-specific `fcntl`; Windows compatibility is not established. See
[Ghidra guidance](../GHIDRA.md) and the
[third-party evaluation](../research/external-tools-evaluation.md).
