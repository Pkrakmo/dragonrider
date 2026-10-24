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

After that snapshot, the audio comparator gained file and directory symlink
escape regression tests, and the byte-order measurement API gained exact input
count validation. The current source-tree Python suites reran on 2026-10-23:
347 research and 13 disc tests passed. This is not a new isolated snapshot or
C++ build/CTest result.

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
