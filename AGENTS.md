# Repository workflow

OpenDuck is a single-user repository. Work only in the primary checkout on the `main` branch;
do not create linked worktrees or topic branches. Install the repository-local guardrails with
`bun run install:git-hooks`. Changes should be made directly on `main`, reviewed, validated, and
pushed directly from `main` to `main` without force pushes. Legacy topic refs may be deleted for
cleanup, but must not be created or updated.

Keep the root Beads database at `.beads/`; do not initialize nested Git or Beads repositories in
plugins or vendored directories. Preserve unrelated existing working-tree changes, and run the
canonical checks relevant to each change before pushing.
