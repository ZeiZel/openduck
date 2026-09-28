# OpenDuck monorepo

OpenDuck has one root Git repository and one root Beads database (`.beads/`). Do not initialize
Git or Beads inside a package directory. Package directories are independently versionable release
units, not nested repositories.

## Layout

| Path | Responsibility |
| --- | --- |
| `cmd/`, `internal/`, `schemas/` | Go Controller and its contracts |
| `plugins/<name>/` | Locally owned DSH/Codex-facing plugin package |
| `profiles/dsh/` | Pinned synthetic DSH profile assembly |
| `third_party/deepseek-harness/` | Vendored DSH source and its self-contained workspace |
| `deploy/` | Deployment templates, synthetic probes, and disabled runtime integration assets |
| `projects/`, `docs/`, `memory/` | Specifications, decisions, evidence, and traceability |

The root Bun workspace (`package.json` `workspaces`) includes only `plugins/*`. Do not add `third_party/deepseek-harness`,
`profiles/dsh`, or `deploy/openclaw` to it: each has a deliberately pinned dependency boundary.

## Plugin release boundary

Each `plugins/<name>/package.json` owns its package name and semantic version. A plugin may be
released independently only after its Controller contract, tests, and security review are accepted.
Until then, placeholder packages remain `private` and publish no executable integration. Changes
to a plugin stay in the root Git history and are reviewed together with any Controller or schema
change that it requires.

## Local state and safety

`.openduck/`, `.openclaw-state/`, encrypted stores, credentials, logs, caches, binaries, and backup
files are local runtime artifacts. They must not be staged. The ignore rules intentionally preserve
source configuration and dependency lockfiles; use committed templates rather than real credentials.

Before a baseline or release commit, verify there is exactly one root `.git` directory and one root
`.beads` directory, inspect staged paths, and run the relevant Go and DSH checks. Beads issue lifecycle stays
in the existing root database; do not run destructive reinitialization or create per-plugin stores.

## Main-only checkout policy

OpenDuck is operated from the primary checkout on the local `main` branch. Do not create or use
linked worktrees or topic branches for this repository. Run `bun run install:git-hooks` once after
cloning or provisioning a checkout. The installer first validates that the repository is attached
to `main`, has one worktree, and contains no other local branches, then sets the repository-local
`core.hooksPath` to `.githooks`.

The hooks enforce the policy at three boundaries: commits require the primary `main` checkout;
pushes must be a non-forced `main`-to-`main` update and all tag/deletion/non-main pushes are
rejected; and the `reference-transaction` hook rejects creation or updates of every non-main local
branch while allowing remote-tracking and local tag ref updates from fetch. Tags can therefore be
present locally, but this workflow never pushes them. These hooks are guardrails, not an absolute
security boundary: detached worktrees can be created before a hook runs, so an external CI or
operator check may additionally enforce the single-worktree policy.
Deletion of legacy topic refs is deliberately allowed for cleanup. Run `bun run test:main-only`
to test the guardrails in a disposable temporary repository without changing this checkout.
