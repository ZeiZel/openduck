# Workspace Groups

Static, DOM-free header badge and picker state for `od-pwk.22.2`. It accepts bounded Controller
WorkspaceGroup projections through an injected read client, renders only safe display labels and
per-root `read`/`write` modes, and returns only opaque group ID, version, and digest for a selected
group. A stale projection is visible but cannot be selected; a failed read clears every group and
returns `CONTROLLER_DOWN`.

The package does not alter DSH's single-root sandbox or session header. It has no runtime network,
filesystem, subprocess, browser persistence, telemetry, message bridge, or model/session-event
dependency.

The pinned DSH profile has reviewed additive header/UI primitives, but the required Controller
routes, authenticated UI bridge, and package registration have not been composed and reviewed.
Therefore [dsh.disabled.json](dsh.disabled.json) explicitly prevents installation. The synthetic
harness is only a supplied in-memory client contract check.

Run `bun run --filter @openduck/workspace-groups test` and `typecheck` from the root.
