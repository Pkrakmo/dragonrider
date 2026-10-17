# Ghidra Headless — project-specific workflow

## Environment verified by user
- Fedora 43, Ghidra 12.1.4. Set `GHIDRA_HOME` to the local installation directory before running the commands below.
- Java and `javac` 25.0.4.1; `analyzeHeadless` prints usage.
- Drakan.exe hash: `23630f48e20e8a9f42026501165ae1df407cfcee545a784ec930a4c25ee70648`.
- The local project is `research/ghidra-projects/Drakan_US_Retail.gpr`; the imported `Drakan.exe` reports the same SHA-256. Prior auto-analysis completeness remains unknown.

## Safe repeatable invocation
First list the project files (do not assume name):
```bash
find research/ghidra-projects -maxdepth 1 -name '*.gpr' -print
```
Close all GUI sessions using the project before headless access. The tested wrapper processes the existing import without analysis or saving, creates unique logs and JSON under ignored `research/`, and serializes its own invocations using `flock`:
```bash
./tools/ghidra/analyze.sh
```
Set `GHIDRA_HOME` to the installation directory before running the wrapper. The wrapper cannot reliably detect GUI sessions and its cooperative lock only covers other wrapper invocations. Do not use `-overwrite` or `-deleteProject`. See `docs/research/riot-file-loading.md` for the tested probe and its limits.

The wrapper defaults to the checkout's `research/` directory. Set
`DRAGONRIDER_RESEARCH_ROOT` to an absolute path to an existing private research
root to select its `ghidra-projects`, `ghidra-logs`, and `exports` directories.
Other scripts and historical commands may still use explicit paths; check their
arguments before relocating anything. Do not move a live Ghidra project.

## Research sequence
1. Export bytes at `0x0047D900` precisely.
2. Find function containing `0x0045EDC0`, caller/callee cross-references and relevant strings/imports.
3. Look for caller-provided path or file extension.
4. Compare sample original-file bytes to hypothesized 12-byte header and 14-byte record table.
5. Export compact structured metadata (no bulk pseudocode); record every address in executable context.
6. Implement behavior independently in C++, after tests establish semantics.

## Avoid contention
Only one agent operates on a Ghidra project at a time, including nominally read-only sessions when locks are uncertain. If parallel analysis is essential, make separate copied projects with independent output locations. Original binary is immutable.

## Experimental disposable-project MCP bridge

The first-party `tools/ghidra/mcp_loader_server.py` speaks stdio MCP and
exposes only `investigate_file_loader`, with no arguments. It runs the existing
bounded loader report with `-process Drakan.exe -readOnly -noanalysis`. It
requires a dedicated project directory under `/tmp` and refuses reports whose
Ghidra-reported import SHA-256 differs from the documented US retail hash;
this is metadata from Ghidra, not an independent hash of the imported bytes.
It requires Linux, Python 3 and an existing Ghidra installation; no Python MCP
package or third-party server is required. The current single-tool bridge is
an experiment, not a general Ghidra interface or an OS sandbox. See
[ADR 0010](decisions/0010-disposable-ghidra-mcp.md) and the
[external tools evaluation](research/external-tools-evaluation.md).

Create a fresh disposable project from a copy of the retail executable. This
example runs from the repository root on Linux with `GHIDRA_HOME` pointing to
the installation. It creates a new temporary directory and never imports into
the primary project:

```sh
dr_workspace=$(mktemp -d /tmp/dragonrider-ghidra-XXXXXXXX)
mkdir -p "$dr_workspace/project" "$dr_workspace/input" "$dr_workspace/config" "$dr_workspace/cache"
cp research/binaries/us/Drakan.exe "$dr_workspace/input/Drakan.exe"
sha256sum "$dr_workspace/input/Drakan.exe"
env XDG_CONFIG_HOME="$dr_workspace/config" XDG_CACHE_HOME="$dr_workspace/cache" \
  JAVA_TOOL_OPTIONS="-Duser.home=$dr_workspace" \
  "$GHIDRA_HOME/support/analyzeHeadless" "$dr_workspace/project" Disposable_Drakan \
  -import "$dr_workspace/input/Drakan.exe" \
  -log "$dr_workspace/import.log" -scriptlog "$dr_workspace/import-script.log"
printf 'Disposable project directory: %s\n' "$dr_workspace/project"
```

Confirm the hash is `23630f48e20e8a9f42026501165ae1df407cfcee545a784ec930a4c25ee70648`
and inspect the import log before continuing. The import's analysis can take
time and may report unresolved Windows DLLs; cross-references may be incomplete.
Keep the temporary project private and remove it only after all processes have
closed and you no longer need it. Never use symlinks or hardlinks to the
primary project as a disposable project. `/tmp` placement alone does not
guarantee isolation. The bridge rejects project symlinks but cannot prove
there are no hardlinks or prevent another program from opening the project.
Its lock coordinates only other bridge calls, not the GUI, wrapper or unrelated
headless sessions. Avoid concurrent access, including read-only access.

To configure a trusted project after checking its existing `.codex/config.toml`,
add the following table, substituting real absolute paths. Do not overwrite
existing settings. The sample directory is temporary and must be replaced if
the system clears it. See the official [Codex MCP configuration](https://developers.openai.com/codex/mcp/)
and [configuration reference](https://developers.openai.com/codex/config-reference/).

```toml
[mcp_servers.dragonrider_loader]
command = "python3"
args = ["/absolute/path/to/DragonRider/tools/ghidra/mcp_loader_server.py", "--project-dir", "/tmp/dragonrider-ghidra-REPLACE/project", "--project", "Disposable_Drakan", "--ghidra-home", "/absolute/path/to/ghidra_12.1.4_PUBLIC"]
tool_timeout_sec = 240
```

Restart Codex, check `codex mcp list`, then request the
`investigate_file_loader` tool and compare its bounded report and import hash
with the local evidence. Review output before sharing it: it is derived from a
private executable. On 2026-10-17 a subsequent Codex session discovered and
invoked the registered tool against the disposable `Disposable_Drakan` project.
The reported import hash, function range, magic bytes, seven direct references
and 14 calls matched existing evidence. The user also reported that
`codex mcp list` showed `dragonrider_loader` enabled. The configured project is under
`/tmp` and may need recreation after cleanup. The bridge's cooperative lock,
read-only Ghidra flag, and temporary preferences are safeguards, not a security
boundary. The report excludes bulk pseudocode, but is still private research.

## Project-specific skill drafts

Five validated drafts live in [tools/codex/skill-drafts](../tools/codex/skill-drafts/):
Ghidra analysis, Riot formats, binary comparison, C++ development and research
documentation. Codex discovers project skills in `.agents/skills/`, as described
in the [Codex skills documentation](https://developers.openai.com/blog/skills-agents-sdk).
All five project skills appeared in the available-skills catalog of a later
Codex session on 2026-10-17. To install them in a new checkout, use an
environment where `.agents` is writable, inspect existing skill directories
first, then copy each draft into a
new matching directory under `.agents/skills/` without overwriting existing
skills. For example, from the project root:

```sh
ls -la .agents/skills 2>/dev/null || true
mkdir -p .agents/skills
for draft in tools/codex/skill-drafts/dragonrider-*; do
  skill_name=${draft##*/}
  if mkdir ".agents/skills/$skill_name"; then
    cp -n "$draft/SKILL.md" ".agents/skills/$skill_name/SKILL.md"
  else
    printf 'Skipped existing or unavailable skill directory: %s\n' "$skill_name"
  fi
done
```

Restart Codex and verify discovery. Validate changes with the skill-creator
validator before use.
