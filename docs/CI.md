# Linux development and CI

Fedora 43 is the active development and test platform. The primary toolchain is
GCC with C++20, CMake 3.20+, Ninja, CTest, Python 3, and zlib development headers
and library. The Python research tests also require NumPy. The presets enable tests and select Ninja; use a fresh build
folder when changing compilers. Windows CI and Windows-specific work are not
currently in scope.

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
