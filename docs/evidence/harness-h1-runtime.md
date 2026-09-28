# H1 Controller runtime boundary

The H1 Controller is a separate native process listening only on `127.0.0.1:8788`.
It persists encrypted state at `.openduck/controller.enc`, using the independent macOS
Keychain item `service=openduck`, `account=controller-state`. The process creates its state
directory with mode `0700`, rejects non-loopback listen addresses, and shuts down through a
bounded graceful lifecycle. Server errors are delivered through an error channel; no goroutine
calls `log.Fatal`.

The public API is deliberately bounded to `GET /healthz`, `GET /readyz`,
`GET /v1/controller/status`, and `GET /v1/controller/tasks`. The task endpoint
is a strictly read-only projection containing only task ID, lifecycle state,
version and boolean evidence/review/decision presence; it excludes signal/spec
text, WorkOrder, previews, callback handles and proof references. Status is synthetic metadata only: delivery is
`UI_DELIVERY_BLOCKED`, external effects and owner decision callbacks are false, and task counts
are reported by lifecycle state. No operations, tasks, preview, decision, authentication, or
mutation endpoints are exposed in H1. The persisted controller snapshot is strictly decoded and
validated, including schema versions, legal transition history, artifact/digest relationships,
runtime attestations, and the persisted interaction-delivery binding. The encrypted repository
uses AES-GCM with atomic fsync/rename persistence and treats uncertain commits as poisoned until
an explicit reload succeeds.

The plugin uses a fixed GET to `http://127.0.0.1:8788/v1/controller/status`, disables proxies and
redirects, applies a short timeout and a 64 KiB response bound, and validates the exact schema.
Unavailable, malformed, oversized, redirected, or non-200 responses become the safe disconnected
synthetic/UI-blocked status. The immutable render probe remains static and never contacts the
Controller. The executable confines its state path beneath the configured local state directory,
uses a same-user process lock, and keeps the listener loopback-only; a narrow same-user TOCTOU
window remains around filesystem open/rename operations and is an explicit residual risk. No
callback, approval route, or external effect is enabled in H1.

## Separate Codex worker runtime probe (2026-08-13)

`internal/codexruntime` now starts a fresh `codex app-server --stdio` instance
under a newly created private `CODEX_HOME`; no global config, plugins, skills,
hooks, apps or credential files are copied into it. The child environment is an
explicit five-variable allowlist (`CODEX_HOME`, clean `HOME`, fixed system
`PATH`, `LANG`, `LC_ALL`); API keys, cloud credentials, proxy variables and
telemetry exporters are not inherited. Because this host packages Codex as a
Node entrypoint, the probe uses an explicitly pinned absolute Node interpreter
instead of reopening ambient `PATH` lookup. A live host probe completed
the JSON-RPC `initialize` handshake in this clean profile. It sent no turn and
used no account, task, external effect or owner-decision callback.

The runner's production sequence is explicit and tested with a scripted
app-server: `Prepare` observes process identity and constructs a profile-bound
`WorkerRuntimeAttestation`; Controller persists the matching dispatch binding,
then transitions to `WORK_RUNNING`; only then can the one-use session submit a
schema-constrained `worker-result.v1`, which Controller binds into evidence.
The actual model-turn gate remains separate: a clean profile has no copied OAuth
state, so it is intentionally blocked until a dedicated credential provisioning
and egress review is approved. This does not affect the local Qwen PD route.
The production Controller therefore does not instantiate the Runner or native
confirmation Coordinator yet: no authenticated WorkOrder command surface and no
approved native callback verifier have been provisioned. Controller status stays
`UI_DELIVERY_BLOCKED`, `owner_decision_callback=false`, and
`external_effects=false`; wiring either component without those authorities
would turn a tested library boundary into an unreviewed control surface.
