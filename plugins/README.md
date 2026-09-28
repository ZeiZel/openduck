# OpenDuck plugins

Each child directory is an independently versionable package in the root Bun workspace. Packages
share the root Git history and root Beads database; they must not contain nested `.git` or `.beads`
directories.

`beads-memory-explorer` and `workspace-groups` are static, fail-closed UI state packages. Their
DSH manifests are explicitly disabled: the pinned profile has reviewed additive UI primitives, but
the required Controller routes/authenticated bridge and package registration are not yet composed
and reviewed. Each package includes a DOM-free synthetic harness until that boundary is available.

The packages contain no runtime access to Beads, Dolt, credentials, or filesystem state. They only
accept bounded projections through an injected Controller read client.

`multi-provider-mesh` follows the same disabled-by-default posture for the mesh directory,
switcher, graph, compare/synthesis/templates, policy and diagnostics surfaces. It requires a
separate authenticated Controller UI projection seam and has no DSH registration while the
no-model/no-session-log feasibility proof remains unresolved. Its switcher emits only
Controller proposals: `compatible` + `mesh_spawn=true` + current evidence is the sole
mesh-eligible combination; `ready` never enables mesh work.
