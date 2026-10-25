# Development and CI

Fedora 43 is the active development and test platform. The primary toolchain is
GCC with C++20, CMake 3.20+, Ninja, CTest, Python 3, and zlib development headers
and library. The Python research tests also require NumPy. The presets enable
tests and select Ninja; use a fresh build folder when changing compilers.
Windows development and CI are on hold until a host is available.

```sh
CC=gcc CXX=g++ cmake --preset debug
cmake --build --preset debug --parallel 2
ctest --preset debug
CC=gcc CXX=g++ cmake --preset release
cmake --build --preset release --parallel 2
ctest --preset release
python3 -m unittest discover -s tools/research -p 'test_*.py'
python3 -m unittest discover -s tools/disc -p 'test_*.py'
python3 -m unittest discover -s tools/ghidra -p 'test_*.py'
```

If CMake cannot find zlib, check that the Fedora zlib development package is
available. To try Clang separately, if already installed, use a separate build
folder: `CC=clang CXX=clang++ cmake -S . -B build/clang -G Ninja
-DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTING=ON`, then `cmake --build build/clang`
and `ctest --test-dir build/clang --output-on-failure`. Clang has not been
verified here.

`.github/workflows/ci.yml` runs GCC debug and release on Ubuntu 24.04 and the
three Python suites in the debug matrix job. These tests generate synthetic
inputs; they do not require original game assets, network access to research
material, or Ghidra databases. Hosted runs have not been verified. Check the
workflow with [actionlint](https://github.com/rhysd/actionlint):

```sh
actionlint .github/workflows/ci.yml
```

On 2026-10-18, actionlint 1.7.12 passed and an isolated Fedora 43 source
snapshot passed all 14 CTests in both GCC 15.3.1 configurations and all 50
Python tests. `act` 0.2.89 with rootless Podman 5.8.8 and
`catthehacker/ubuntu:act-24.04` successfully ran both matrix configurations,
including those test suites. Its checkout step copied the local snapshot;
this does not verify the hosted checkout or hosted runner.

A subsequent fresh Fedora GCC build of the current tree passed 14/14 CTests in
both debug and release, and the Python suites passed 55 research, 4 disc and
6 Ghidra tests. Actionlint passed on the workflow, but the container socket was
unavailable for a new local execution. A separate GCC build with
`_GLIBCXX_DEBUG` and `_GLIBCXX_ASSERTIONS` passed all
14 CTests. AddressSanitizer could not link because the local libasan runtime was
missing; no package was installed.

On 2026-10-24, a fresh GCC 15.3.1 build using the same checked-iterator and
assertion flags passed all 18 CTests, including the bounded SRSC `0x0501`
reader and its input-view lifetime contract. An UndefinedBehaviorSanitizer
build could not link because `/usr/lib64/libubsan.so.1.0.0` is unavailable; no
system package was installed.

In a later 2026-10-18 restricted session, a newly prepared source snapshot
again passed 14/14 CTests for each GCC configuration, plus 55 research,
4 disc, and 6 Ghidra Python tests; actionlint 1.7.12 passed. The snapshot
contained the project source and synthetic tests without the private research
directory, media, Ghidra databases or original Git metadata. `act` 0.2.89
listed the Linux job but could not execute it in that session: the normal
rootless Podman configuration failed on the read-only `/run/user/1000/libpod`,
and a probe using temporary Podman storage and runtime directories failed
because `newuidmap` could not write the UID map (`Operation not permitted`).
No Docker or Podman API socket was available. An attempted `act push` with a
nonexistent temporary socket exited with `listen tcp: lookup <nil>: no such
host`; no job ran. These results do not invalidate the earlier successful
rootless Podman run, but do not verify the current snapshot with act.

On 2026-10-21, the configured current-tree debug and release build directories
reported no pending build work, and CTest passed 17/17 tests in each. The
Python suites passed 215 research, 4 disc, and 6 Ghidra tests. The same day,
`tools/ci/prepare_act_workspace.py` produced a 221-file isolated source
snapshot without `research/`, `.git`, or `.env`; fresh debug and release builds
and CTest passed 17/17 each, followed by the same 215/4/6 Python results. This
checks the reviewed source allowlist and synthetic test inputs locally. It
does not verify hosted CI; `actionlint`, `act`, Docker, and a container API
socket were unavailable in that session.

On 2026-10-23, running all CI suites from a fresh helper snapshot exposed that
the coverage-map tests require public Markdown evidence omitted by the original
allowlist. The helper now copies tracked `docs/` Markdown and JSON plus the
top-level `TODO.md`; it still excludes the private top-level `research/`
directory, Git metadata, and build outputs. The corrected snapshot passed fresh
GCC debug and release builds with 17/17 CTests each, plus 268 research, 4 disc,
and 6 Ghidra Python tests. `actionlint`, `act`, and a container API socket were
unavailable, so hosted CI remains unverified.

On 2026-10-23, a second fresh snapshot after additional verifier and audio
comparison changes contained 355 allowlisted files. Review found no top-level
private `research/`, `.git`, `.env`, or build directory and no original media,
executable, archive, or Ghidra project files; public `docs/research/` notes
and synthetic research tests are intentionally included. Fresh GCC 15.3.1
debug and release builds each passed 17/17 CTests. The snapshot Python suites
passed 328 research, 5 disc, and 6 Ghidra tests. The current checkout also
passed both configured build/test suites and all three Python suites.
`actionlint` and `act` were not installed and no container API socket was
present, so these results remain local and do not verify hosted CI.

A third fresh snapshot on 2026-10-23 included the latest selector-verifier and
audio CLI snapshot-consistency changes. It contained 358 allowlisted files and
no top-level private `research/`, `.git`, `.env`, or build directory. Fresh GCC
15.3.1 debug and release builds each passed 17/17 CTests; the snapshot Python
suites passed 334 research, 6 disc, and 6 Ghidra tests. This is local snapshot
evidence only; hosted CI remains unverified.

A final fresh 358-file snapshot reran those checks after adding the report's
explicit little-endian-assumption field, its CLI assertion, and the selector
verifier's final zero-register instruction anchor. Debug/release CTest
again passed 17/17 each, and the Python suites again passed 334 research, 6
disc, and 6 Ghidra tests. The snapshot still excluded private top-level
research, `.git`, `.env`, and build outputs.

On 2026-10-23, a fresh 362-file allowlisted snapshot included the current
research verifiers, the Mplayer PE reference scanner, and the CD-DA sample
byte-order measurement tool. Review found no symlinks, top-level private
`research/`, `.git`, `.env`, or build directory, and no original media, PE
binaries, archives, or Ghidra project files. Fresh GCC debug and release builds
each passed 17/17 CTests; the snapshot Python suites passed 337 research, 11
disc, and 6 Ghidra tests. These local checks do not verify hosted CI;
`actionlint`, `act`, and a container API socket remain unavailable.

A fresh 362-file helper snapshot on 2026-10-23 includes the bounded-read
request-size classifier and its adversarial synthetic cases. Before building,
the reviewed source snapshot had no symlinks, private top-level `research/`,
`.git`, `.env`, original media, executable/library binaries, archives or
Ghidra project files. Fresh GCC 15.3.1 debug and release builds each passed
17/17 CTests; Python suites passed 347 research, 11 disc and 6 Ghidra tests.
This remains local evidence only; hosted Linux CI is unverified because
`actionlint`, `act` and a container API socket are unavailable.

On 2026-10-24, the current integrated tree passed GCC debug and release
builds with 18/18 CTests in each configuration, plus 419 research, 16 disc,
and 6 Ghidra Python tests. This current-tree pass includes the bounded SRSC
`0x0501` diagnostic and the new aggregate level/audio measurements. It does
not substitute for an isolated snapshot or hosted CI verification.

On 2026-10-24, the current helper produced a fresh 400-file snapshot
including the selector-path, payload-extent and resource-inventory changes,
plus the final extent-bound tests. Review found no symlinks, top-level private
`research/`, `.git`, `.env`, build output, original media,
PE binaries, archives or Ghidra project files. Fresh GCC 15.3.1 debug and
release builds each passed 17/17 CTests; the snapshot Python suites passed
393 research, 13 disc and 6 Ghidra tests. This verifies the allowlisted local
source snapshot, not hosted CI; `actionlint`, `act` and a container API socket
remain unavailable.

Later on 2026-10-24, a fresh 423-file snapshot included the bounded `0x0501`
reader, inspector command, private-sample verifier source, and boundary fixture
for an opaque tail beyond the inspector's bounded read window. Review found no
symlinks, top-level private `research/`, `.git`, `.env`, build outputs, original
media, PE binaries, archives or Ghidra project files. Fresh GCC 15.3.1 debug
and release builds each passed 18/18 CTests; Python suites passed 424 research,
16 disc and 6 Ghidra bridge tests. This validates the reviewed local source
snapshot; hosted CI remains unverified.

A fresh 427-file snapshot on 2026-10-24 included all current allowlisted
changes. Review found no symlinks, top-level private `research/`, `.git`,
`.env`, build outputs or binary/media inputs. Fresh GCC 15.3.1 debug and
release builds each passed 18/18 CTests; the snapshot Python suites passed
437 research, 16 disc and 6 Ghidra tests. The snapshot excluded original media,
PE binaries, archives and Ghidra project files. These checks validate the local
source snapshot only; hosted CI remains unverified.

After expanding the aggregate exact-suffix search to all other record payloads,
a fresh 429-file helper snapshot was reviewed. It contained no symlinks,
private top-level `research/`, `.git`, `.env`, build outputs, original media,
executable binaries, archives or Ghidra projects. Fresh GCC 15.3.1 debug and
release builds each passed 18/18 CTests; Python suites passed 444 research,
16 disc and 6 Ghidra tests. Hosted CI is still unverified.

Earlier, after the 362-file snapshot on 2026-10-23, the audio comparator
gained file and directory symlink escape regression tests, and the byte-order
measurement API gained exact input count validation. The source-tree Python
suites reran then: 347 research and 13 disc tests passed. This records that
separate earlier recheck, not the 2026-10-24 snapshot above.

On 2026-10-25, a fresh 431-file helper snapshot included the current source,
tests, research scripts, and public evidence docs. Review found no symlinks,
private top-level `research/`, `.git`, `.env`, build outputs, original media,
executables, archives, or Ghidra project files. Fresh GCC 15.3.1 debug and
release builds each passed 18/18 CTests; Python suites passed 452 research,
16 disc, and 6 Ghidra tests. The snapshot run was local; hosted CI remains
unverified.

Later on 2026-10-25, a fresh 458-file helper snapshot included the support-text
shape classifier, its static program-literal verifier, and synthetic tests.
Review found no symlinks, private top-level `research/`, `.git`, `.env`, build
outputs, original media, executables, archives, or Ghidra project files. Fresh
GCC 15.3.1 debug and release builds each passed 20/20 CTests; Python suites
passed 494 research, 16 disc, and 6 Ghidra tests. The snapshot remained local:
`actionlint`, `act`, and `gh` were unavailable, and Podman could not initialize
its rootless state on the read-only runtime filesystem. Hosted CI remains
unverified.

After adding the bounded cross-level cell scalar and ordered-pair measurements,
their synthetic tests, and the `0x0501` trio traversal-boundary check, a fresh
466-file helper snapshot was reviewed. It contained no symlinks, private
top-level `research/`, `.git`, build outputs, original media, executables,
archives, or Ghidra projects. Fresh GCC 15.3.1 debug and release builds each
passed 20/20 CTests; Python suites passed 512 research, 16 disc, and 6 Ghidra
tests. `actionlint`, `act`, `gh`, and Docker/Podman sockets were unavailable in
this environment, so the snapshot run remained local and hosted CI is
unverified.

On the current tree, a fresh GCC 15.3.1 debug build with `-Werror` passed
20/20 CTests. A separate build with `-D_GLIBCXX_DEBUG -D_GLIBCXX_ASSERTIONS`
also passed 20/20 CTests. These checks do not replace hosted CI.

## Running the workflow locally

[`act`](https://nektosact.com/) runs GitHub Actions locally through a Docker
API. Check for existing `act`, `actionlint`, Docker or Podman first. If tools
are missing, their upstream release binaries can be downloaded to a user-owned
location after checking the release checksums; no system installation is
required. The runner image and public actions may require network access. The
image is not the GitHub-hosted VM, and act does not implement all GitHub Actions
features. Review workflow steps and container image before running them.

Never point act at the research checkout: act copies its working directory to
containers. This helper creates a fresh `/tmp` snapshot of Git-listed and
nonignored source files from an explicit directory/extension allowlist, with no
`research/`, private media, build directories or original `.git` directory.
It includes current uncommitted source changes and fails on symlinks. Review
the resulting snapshot before using it, especially any new source files. If a
future test needs another file type, review and extend the allowlist first.

```sh
snapshot=$(python3 tools/ci/prepare_act_workspace.py)
# Give act local Git metadata without copying the original repository's .git.
git -C "$snapshot" init -q
git -C "$snapshot" add .
git -C "$snapshot" -c user.name='Local CI' -c user.email='local-ci@example.invalid' commit -qm 'Temporary local CI snapshot'
# Set DOCKER_HOST to an already available Docker-compatible API socket.
DOCKER_HOST=unix:///path/to/socket act push -C "$snapshot" \
  -W .github/workflows/ci.yml -j linux --container-daemon-socket - --rm \
  -P ubuntu-24.04=catthehacker/ubuntu:act-24.04
```

The socket flag prevents mounting the container engine socket into jobs; do
not add `--bind`, privileged mode, secrets, or original research paths. `act`
is given a snapshot containing only the reviewed source and synthetic test
inputs. The workflow installs dependencies inside the runner containers; it
does not install packages on the Fedora host. Delete the temporary snapshot
when finished. Docker uses its existing socket; for rootless Podman the socket
is often `unix://$XDG_RUNTIME_DIR/podman/podman.sock`. Alternatively, run
`podman system service --time=300 unix:///tmp/dragonrider-ci-podman.sock` as a
temporary foreground process in another terminal, and use that socket. This
does not enable a system service. Podman compatibility with act is not
guaranteed by act; see its [custom engine documentation](https://nektosact.com/usage/custom_engine.html).

If the socket is inactive or inaccessible, check `podman info`, the socket
path, and whether the runtime environment allows rootless containers. Do not
change or enable services without approval. A sandbox may prohibit access to
`/run/user` or the network even when the host supports both. Image pulls need
registry access and sufficient disk space. If a runner image lacks Node, sudo,
CMake, GCC or Python, use a compatible runner image; minimal images do not
match hosted runners. `act` does not establish that hosted CI will pass.
