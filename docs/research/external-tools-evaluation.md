# External research and MCP tools

**Reviewed:** 2026-10-17 using the projects' GitHub pages and linked files.
GitHub pages may be cached; commit dates and default branches can change. No
third-party code, dependencies or prebuilt binaries were installed or copied.
DragonRider's project code and documentation use the MIT License; that does
not grant rights to third-party projects or original game materials. This is
technical research, not a legal opinion; check exact revisions and licenses
before reuse.

## Ghidra MCP candidates

### [mrphrazer/ghidra-headless-mcp](https://github.com/mrphrazer/ghidra-headless-mcp)

- Headless PyGhidra, stdio or TCP; [project metadata](https://github.com/mrphrazer/ghidra-headless-mcp/blob/main/pyproject.toml) requires Python 3.11+ and `pyghidra>=3.0.2`. The project lists GPL-2.0 in its [license](https://github.com/mrphrazer/ghidra-headless-mcp/blob/main/LICENSE); the README also contains a conflicting license-selection statement, so verify the exact revision before use.
- Its [security model](https://github.com/mrphrazer/ghidra-headless-mcp#security-model) describes unauthenticated transports and arbitrary scripting and API calls. Its default read-only session setting is explicitly not a process or filesystem sandbox. Never expose TCP, credentials or private research paths to an unisolated instance, or assume an allowlist makes an untrusted server safe.
- A cached [commit history](https://github.com/mrphrazer/ghidra-headless-mcp/commits/main/) showed activity through 2026-08-06; the actual current HEAD and sustained maintenance are unverified. Ghidra 12.1.4, Fedora 43 and Python 3.14 compatibility have not been tested here.

This is the more direct candidate for a future isolated headless evaluation.
Review and pin an exact commit and its transitive dependencies; build an
isolated environment with no access to the primary project, credentials or
network; test a synthetic input and then a disposable copy of the retail
program. Confirm the actual exposed tool list and mutation behavior. Do not
register it globally or use it against the primary database merely because a
read-only mode is available.

### [ColdSlither/ghidra-mcp](https://github.com/ColdSlither/ghidra-mcp)

- The fork's README declares Apache-2.0 and lists Java 21, Maven 3.9+, Python 3.10+, and Ghidra 12.0.4 or compatible. Exact license and dependency sources should be checked at a pinned revision. Compatibility with the installed 12.1.4/Java 25 is unverified.
- Its setup describes deploying an extension and patching the Ghidra user profile; it can affect a running GUI. The described local HTTP service is unauthenticated by default and exposes broad operations; optional filesystem restrictions are not a security boundary by default. Do not run its deploy step against the normal profile or open its service to a network.
- Fork-specific maintenance is unknown. Its README clone example points at a different repository; do not mistake that upstream for the requested fork. Prefer a fully isolated profile and disposable project if evaluating it later.

Neither external MCP candidate is installed or approved for the primary
project. A narrow first-party experimental bridge was tested separately; see
[Ghidra guidance](../GHIDRA.md) for current verification and restrictions.

## Other repositories

### [Zalasus/opendrakan](https://github.com/Zalasus/opendrakan)

An early Riot Engine recreation, with SRSC-related documentation and tools
that could suggest testable hypotheses. Its [license](https://github.com/Zalasus/opendrakan/blob/master/LICENSE) is GPL-3.0; the project lists zlib, GLM, Bullet, OpenSceneGraph and OpenAL among dependencies. Its own documented status is old and Windows compatibility and current maintenance were not established. Do not copy code or integrate its dependencies without an explicit license and architecture decision; independently verify any format claims against original bytes and executable behavior.

### [UCyborg/DrakanAiOPatch](https://github.com/UCyborg/DrakanAiOPatch)

The repository describes source for the DLL portion of a Windows patch and
contains Visual Studio projects and prebuilt artifacts. No license was
identified in the inspected root listing; permission to reuse code is not
established. Treat it only as a potential lead for version-specific behavior,
not proof of retail behavior. Do not execute bundled binaries or conflate
patched and retail evidence. Maintenance and Linux compatibility are unknown.

### [openai/plugins](https://github.com/openai/plugins)

The [README](https://github.com/openai/plugins/blob/main/README.md) describes a
catalog of Codex plugin examples and their manifests, skills and optional MCP
components. It is not itself a Ghidra server. The inspected root listing did
not establish a repository-wide license; inspect each candidate plugin's
license, endpoints, permissions and dependencies before adoption. Cached
[history](https://github.com/openai/plugins/commits/main/) showed activity in
September 2026, but no Ghidra integration was established. No marketplace or
plugin was installed.

## Local environment and blockers

The host exposes Ghidra 12.1.4 and Java 25.0.4.1. Python 3.14.7 has no
importable `pyghidra`, `jpype` or `mcp` in the default environment. An attempted
`git ls-remote https://github.com/mrphrazer/ghidra-headless-mcp.git HEAD`
failed DNS resolution in this session; no revision was downloaded or pinned.
The `.agents` and `.codex` paths are read-only in this sandbox, so requested
repository skill discovery and persistent project-specific Codex configuration
cannot be set up here. The skill drafts remain under `tools/codex/skill-drafts/`.
