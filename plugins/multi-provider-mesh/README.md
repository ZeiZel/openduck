# Multi-provider Mesh UI

This is a static, disabled-by-default Controller UI state package for provider directory and
switching, session mesh, graph, compare, synthesis, templates, policy/approval inspection,
provider/deployment diagnostics, and plugin lifecycle proposals. It accepts a bounded projection
from a separately authenticated Controller UI client and sends all mutations as typed Controller
proposals.

It does not import DSH, AgentLoop, model prompts, session logs, browser storage, provider SDKs,
credentials, filesystem, subprocess, or network clients. The DSH manifest stays disabled while the
required proof that an authenticated UI projection cannot enter DSH model/session paths is absent.

`profileOptions(filter)` deterministically returns all six projected profiles (or an exact bounded
filter) with Controller status, locality, evidence freshness, and a derived `mesh_eligible` flag.
A profile can be selected only when it is exactly `compatible`, advertises `mesh_spawn=true`, and
has `current` evidence. `ready` is informational and never a v1 mesh grant. `select(...)` only
sends a Controller proposal; it never changes the cached revision or an active turn. `children`
is a convenience namespace for all eleven typed mesh proposal operations and never invokes a
provider, model, or child process. A lifecycle projection cannot claim an `enabled` package unless
at least one profile satisfies that same compatible/spawn/current eligibility rule.

Native package fixtures in `native/` are metadata only and not installed. Codex uses
`codex/openduck-mesh/.codex-plugin/plugin.json`, Claude uses `claude/.claude-plugin/plugin.json`, Qwen uses
`qwen/qwen-extension.json`, and Kimi uses `kimi/kimi.plugin.json`. Each has a separate
`disabled.json` policy sentinel with `installation_status=not_installed` and
`runtime_status=disabled`; manifests contain no MCP declaration, command, hook, agent, system
prompt, credential, installation, or enablement action. DeepSeek deliberately has no native
subscription package: it is represented only by the Controller/DSH API profile.

`src/native-packages.js` is the separate, disabled-by-default lifecycle gate. It accepts only a
bounded, canonically chained sequence of Controller-signed
enable/disable/revoke receipts. Every receipt binds the provider, profile and revision, immutable
package digest, UI and mesh association, Controller endpoint generation and expiry, and the exact
eleven child-operation capabilities. Codex, Claude, Qwen, and Kimi have verified registration
metadata, but remain unavailable until the production Controller actually calls the official-host
launcher and supplies signed end-to-end evidence. The static fixtures remain disabled and
uninstalled. JavaScript verifies receipts and projections but has no filesystem publication,
quarantine, or removal authority. Codex, Claude, and Qwen record the fixed no-argument
`/Library/Application Support/OpenDuck/.openduck-native-mcp` command; Kimi uses its officially
supported plugin-relative `./bin/openduck-native-mcp` command, whose exact helper bytes must be
copied by the trusted root-owned publisher. No package can materialize unless the
root-owned `/Library/Application Support/OpenDuck/.openduck-native-mcp` helper evidence,
root-owned `/private/var/run/openduck/native-mcp.sock` listener, and
server-side host catalog are all present and manifest-bound. The source pins are the official Codex plugin configuration, Claude plugin
reference, Qwen extension guide, and Kimi plugin guide recorded in
`NATIVE_PROVIDER_REGISTRATIONS`. DeepSeek is rejected.
The enable gate independently verifies the canonical
`openduck.native-mcp-lifecycle.v1` Ed25519 projection and binds its release,
ManifestV2, helper artifact, socket generation/identity, host catalog generation,
provider topology, official host artifact/team/image identity and expiry into the signed package
receipt and package digest. Publication is reserved for the trusted root-owned Go publisher.
The public lifecycle key is release-pinned and Ed25519 verification is not callback-injectable.
Existing targets are never overwritten; disable/revoke atomically quarantine a legacy package.
Revocation remains terminal within its receipt chain.
