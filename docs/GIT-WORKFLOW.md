# Git and research workflow

DragonRider is an independent engine implementation. Git holds project-owned
source, CMake files, portable tools, documentation, and synthetic test inputs.
The intended layout is `include/`, `src/`, `apps/`, `tests/`, `tools/`, and
`docs/`; see [architecture](ARCHITECTURE.md) and [research](RESEARCH.md).
Review the origin and license of any third-party material before adding it.
Project licensing itself remains to be decided; see the [README](../README.md).

## Private inputs

Never add original discs, archives, extracted game files, executables, DLLs,
patches, assets, Ghidra projects, bulk decompilation, or private analysis
exports and logs to Git or Git LFS. Keep user-owned inputs read-only and keep
retail and patch 445 evidence separate. The existing local `research/`, retail
disc directories and patch directory are private; ignore rules are a safety
net, not proof that the index or history is clean. Do not force-add private
files. Review new paths and their contents before staging.

For long-term separation, a sibling `~/Projects/DragonRider-Private/` can hold
research data outside all public worktrees. Do not move the current data until
the paths, Ghidra project dependencies, scripts, and integrity checks have been
reviewed. `tools/ghidra/analyze.sh` defaults to the checkout's `research/`;
it accepts `DRAGONRIDER_RESEARCH_ROOT` for an existing external root. Other
tools and historical commands can use explicit paths, so check each dependency
and verify integrity before migration. No private data needs to be copied into
agent worktrees.

Record concise, independently written findings in `docs/research/`, with
edition, input hash, address when applicable, tools and versions, method,
confidence, and limitations. Distinguish observed facts, inferences, and
unknowns. Keep private source material and bulk exports out of the notes. Add
an ADR in `docs/decisions/` when a format policy or architecture boundary
changes. See [Ghidra guidance](GHIDRA.md) for provenance and locking details.

## Branches and commits

Use `main` for stable integration and create focused branches:

- `research/*`: reverse-engineering investigations.
- `feat/*`: engine functionality.
- `fix/*`: corrections.
- `test/*`: automated tests.
- `docs/*`: documentation.
- `chore/*`: build and development tooling.

Use Conventional Commit-style subjects, such as `feat: add checked reader` or
`docs: describe research provenance`. Before a commit, run applicable builds
and tests, `git diff --check`, and review both `git status --short` and
`git diff --cached` including the staged file list. Assess every staged file
for proprietary content and unintended changes. Local commits may be made
after verification; pushing requires explicit user approval.

## Parallel worktrees and agents

Worktrees share Git history but have separate checkouts and branches. Create
them only for independent work with a clear owner and distinct files. From the
main checkout, after establishing a repository and an initial commit, examples
are:

```sh
git worktree add -b research/riot-file-loading ../DragonRider-riot main
git worktree add -b feat/binary-reader ../DragonRider-reader main
git worktree add -b test/binary-reader ../DragonRider-reader-tests main
git worktree list
```

These names are examples, not a mandate to create worktrees. Assign each agent
inputs, expected outputs, verification, and exclusive file ownership; one
coordinator owns shared documents such as `TODO.md`, `AGENTS.md`, and
architecture notes. Avoid concurrent edits of the same files. Serialize all
access to the same Ghidra database, including read-only sessions that can lock
it; close the GUI before headless use. Separate copies may be used when truly
necessary, with their own outputs, while keeping private data out of Git.
The coordinator reviews changes and evidence, resolves conflicts, runs relevant
checks, and integrates finished branches. Use parallel work only when it saves
more time than coordination costs.

Before removing a worktree, inspect its status and ensure its changes are
committed or otherwise preserved and integrated. From the main checkout:

```sh
git -C ../DragonRider-reader status --short
git worktree remove ../DragonRider-reader
git worktree list
```

Do not use forced removal to discard work. Integration should preserve history:
review `git diff main...branch`, merge a verified branch or use a reviewed pull
request, and resolve conflicts deliberately. Do not rewrite history, force-push,
perform destructive resets, or remove private research data.

## Recovering from mistakes

- If the wrong file is staged, inspect it with `git diff --cached` and unstage
  it with `git restore --staged -- path/to/file`; this keeps the working file.
  Before the first commit, use `git rm --cached -- path/to/file` for an added
  file instead, again preserving the working file.
- If a merge has conflicts, inspect `git status` and resolve each file; if the
  merge should not continue, `git merge --abort` is available while a merge is
  in progress. Preserve any uncommitted work before starting a merge.
- If private material was committed, stop before publishing or rewriting
  history. Record the affected paths and commits, preserve the local inputs,
  and agree on a remediation plan. Ignore rules do not remove existing tracked
  files or historical objects.
- If an incorrect commit is already shared, prefer a reviewed `git revert`
  over history rewriting; consider whether any sensitive material remains in
  history before doing so.

## Preparing for GitHub

Start with a private repository named `DragonRider` when explicitly approved.
Before any upload, review all tracked files and the complete reachable history
for copyrighted material, secrets, private paths, and accidental binary data;
also verify licensing and third-party dependencies. A private repository is not
a substitute for this review. Do not create a remote, change visibility, or
push without explicit approval. Make the repository public only after a separate
release review and approval.

When GitHub is configured, protect `main`, use pull requests and reviews for
integration, and require passing checks. Enable secret scanning where available.
Add GitHub Actions builds and CTest runs for Linux and Windows when the project
and repository are ready; require the checks once they are reliable. Do not
upload original assets through artifacts, releases, Git LFS, or CI fixtures.
