# Beads Memory Explorer

Static, DOM-free UI state for `od-pwk.21.2`. It accepts only bounded project graph and global
metadata projections from an injected Controller read client. The graph/list/search model exposes
safe node metadata only. Global records are opaque metadata and are always shown as
`LOCAL_PD_UNAVAILABLE`; no memory value or chat message exists in this package.

`openMemoryChat()` produces an isolated, submission-disabled shell. The global shell visibly stays
blocked with `LOCAL_PD_UNAVAILABLE`. There is no model, session event, browser persistence,
filesystem access, subprocess, telemetry, message bridge, or network implementation here.

The pinned DSH profile has reviewed additive UI primitives, but the required Controller routes,
authenticated UI bridge, and package registration have not been composed and reviewed. Accordingly,
[dsh.disabled.json](dsh.disabled.json) is an explicit non-install manifest.
`test/synthetic-harness.mjs` demonstrates the injected read-client contract; it performs no network
activity.

Run `bun run --filter @openduck/beads-memory-explorer test` and `typecheck` from the root.
