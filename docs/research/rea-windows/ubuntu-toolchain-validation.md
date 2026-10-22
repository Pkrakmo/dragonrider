# Isolated Ubuntu REA/Ghidra toolchain validation

## Scope

- Date: 2026-10-22.
- Status: **Observed toolchain success; retail benchmark blocked by missing input.**
- Repository baseline: `3765bdbf8af698ed815430c45553e0facc7180ba`.
- Research branch: `research/rea-windows`.
- The contributor chose an Ubuntu VM on a Windows Hyper-V host. This is a
  Linux toolchain evaluation supporting the assigned Windows-binary research,
  **not** validation of REA on Windows or a change to Fedora project support.
- No original game executable, media, assets, or prior Ghidra project was available.
- Canonical retail SHA-256, not analyzed in this session:
  `23630f48e20e8a9f42026501165ae1df407cfcee545a784ec930a4c25ee70648`.

## Observed environment

| Component | Version / configuration |
| --- | --- |
| Guest | Ubuntu 24.04.5 LTS, x86-64, kernel 7.0.0-38-generic |
| VM | Hyper-V generation 2, 4 vCPU, 8 GiB RAM, 80 GiB dynamic virtual disk |
| Java | OpenJDK full JDK 25.0.4.1, Ubuntu package |
| Ghidra | 12.1.4 PUBLIC, official 2026-09-21 archive |
| Node.js | 24.22.1, official Linux x64 archive |
| REA | npm `rea-agents@6.7.0`, local version-pinned installation |
| Compiler | GCC 13.3.0 |
| Build | CMake 3.28.3, Ninja 1.11.1 |
| Python | 3.12.3 |

Ghidra archive SHA-256 verified against the official GitHub release asset digest:
`ddac49f903da9d5bac833e5cc79395098b9c33cfd3279be5f31bd00387d2d4db`.
Node archive verified against the official HTTPS `SHASUMS256.txt` before extraction.
The checksum files were not independently signature-verified.

REA package-lock integrity:
`sha512-yhIx2ioJYYT1C/tONfYeitC6LhnKmCh+ZwRUOgYuhSc733lGhkkt73zhug9WmLgxoMdKuqIYGCoBfD4fXkOhFw==`.

Installation used `--save-exact --ignore-scripts --omit=optional --no-audit
--no-fund`, avoiding npm lifecycle scripts and optional Frida installation.
`npm audit --omit=optional --json` subsequently exited 0 and reported zero
known vulnerabilities at the time checked. This is not a security guarantee.

## Isolation and configuration

Analysis tools run as the guest's ordinary user; administrator privileges were
used only for Ubuntu package installation and updates. Original input storage,
Ghidra projects, exports, and logs have a private parent outside the checkout.
No host disk or personal folder was attached to the guest. No GitHub credentials
were copied: the checkout was transferred as a local Git bundle. The guest has
temporary network access through the existing Hyper-V Default Switch for setup
and SSH. That network is **not** a security boundary against the host or LAN.

REA uses stdio, not an HTTP listener. No global agent/MCP registration was changed,
and `rea setup` was not run. Explicit environment values select Ghidra and its JDK:

```sh
export GHIDRA_HOME="$HOME/tools/ghidra_12.1.4_PUBLIC"
export GHIDRA_INSTALL_DIR="$GHIDRA_HOME"
export JAVA_HOME=/usr/lib/jvm/java-25-openjdk-amd64
export PATH="$HOME/tools/node-v24.22.1-linux-x64/bin:$PATH"
export REA_ANALYSIS_PROVIDER=ghidra
node "$HOME/tools/rea-6.7.0/node_modules/rea-agents/scripts/rea.mjs" doctor --provider ghidra --json
```

Doctor exited 0, with `healthy: true` for the explicitly selected Ghidra scope.
The broader `environment_healthy: false` reflects absent unrelated providers and
the intentionally unregistered REA skill; those were not installed to silence it.

## Actual agent-initiated MCP analysis

The agent launched a Python stdio MCP client over SSH inside the VM. This was a
real `initialize` / `tools/list` / `tools/call` exchange with REA, not just CLI
startup or a successful handshake. It does not establish native desktop MCP
registration or access to the absent retail executable.

An original, synthetic ELF fixture was compiled with
`gcc -O0 -g -fno-inline -o fixture fixture.c`:

```c
__attribute__((noinline)) int add_values(int a, int b) { return a + b + 7; }
int main(void) { return add_values(3, 4) != 14; }
```

Observed fixture SHA-256:
`ecc8ef22e3f8507337ebe9bbc17cbecbf8c816557c91c30df9446b8402cfe8c3`.
Debug builds embed build paths, so recompilation elsewhere need not have this hash.

The client inspected the installed tool input schemas and used these calls on one
persistent connection (substitute the fixture's absolute path):

| Tool | Arguments | Observed elapsed seconds |
| --- | --- | --- |
| `open_binary` | `{"path":"<absolute fixture path>","provider_id":"ghidra"}` | 0.21 |
| `binary_overview` | `{}` | 6.99 |
| `list_procedures` | `{}` | 0.01 |
| `procedure_pseudo_code` | `{"procedure":"add_values"}` | 0.02 |
| `close_binary` | `{}` | 0.36 |

All calls returned without MCP errors. `binary_overview` triggered actual lazy
Ghidra analysis, reported image base `0x100000`, and `list_procedures` returned
21 entries including external functions and thunks. The synthetic `add_values`
function was reported at `0x101129`; its decompilation computed `b + a + 7`.
Independent `objdump --disassemble=add_values` showed symbol value `0x1129`,
addition of the two arguments, and addition of immediate 7. The image-base
difference accounts for the address difference. Running this **self-authored**
fixture exited 0. No original-game executable was run.

The client used a 450-second per-request allowance, closed the target and server,
and a subsequent process check found no remaining Ghidra/REA processes. REA's
temporary-project cleanup is provider behavior, not an OS sandbox. No persistent
user Ghidra database was touched. The synthetic ELF test does not validate PE32
imports, original-game calling conventions, or any SRSC hypothesis.

## Repository validation

The unmodified baseline was built in this Ubuntu guest:

```sh
cmake --preset debug
cmake --build --preset debug --parallel 4
ctest --preset debug --output-on-failure
cmake --preset release
cmake --build --preset release --parallel 4
ctest --preset release
python3 -m unittest discover -s tools/research -p 'test_*.py'
python3 -m unittest discover -s tools/disc -p 'test_*.py'
python3 -m unittest discover -s tools/ghidra -p 'test_*.py'
```

- Debug: **17/17 CTests passed**.
- Release: **17/17 CTests passed**.
- Python research: **210 tests passed**.
- Python disc: **4 tests passed**.
- Python Ghidra bridge: **6 tests passed**.

These are independent Ubuntu observations, not Fedora CI or Windows validation.
No engine, CI, root agent configuration, or shared TODO/architecture file changed.

## Blocker and next bounded action

The independent retail SRSC benchmark is **not done**. Obtain a legitimate,
unpatched retail `Drakan.exe` privately, outside Git. Record its SHA-256 before
import; only use the canonical addresses if its hash matches the reference.
Then independently inspect `0x0045EDC0`, the bytes at `0x0047D900`, header reads,
version checks, record-table stride, and callers/callees. Record observations
separately from hypotheses. Startup and subsystem mapping remain dependent on
that benchmark. Asset-level cross-checks additionally require the retail data.

No OpenDrakan format material or community-patch source was consulted. No push,
PR, merge, access change, or proprietary-data publication was performed.

## Official sources

- [Ghidra release](https://github.com/NationalSecurityAgency/ghidra/releases/tag/Ghidra_12.1.4_build)
- [Node.js archive checksums](https://nodejs.org/dist/v24.22.1/SHASUMS256.txt)
- [REA published package metadata](https://registry.npmjs.org/rea-agents/6.7.0)
- [REA installation](https://github.com/morluto/rea/blob/main/docs/installation.md)
- [REA MCP contracts](https://github.com/morluto/rea/blob/main/docs/mcp-contracts.md)
- [REA security policy](https://github.com/morluto/rea/blob/main/SECURITY.md)

Mutable upstream documentation is explanatory; installed schemas, package-lock,
hashes, and local observations above identify what was actually tested.
