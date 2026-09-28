# 11. Roadmap и gates

## P0 — Decisions and freeze

Deliver: owner/security/operations roles; ADR root/fanout/DSH UI projection; provider modality matrix; frozen proposal/order/binding/endpoint-auth/limits/error/release/checkpoint schemas; pinned compatibility targets; `ProviderEvidenceRecord.v1` per provider with official URLs/retrieval/runtime/claim mapping/digests/freshness; isolated implementation worktree plan. The P0 ADR is recorded; unresolved owner decisions remain gates.

Exit: DR-001..DR-007 resolved; every profile defaults `mesh_spawn=false`; no real account or privilege used.

## P1 — Controller mesh core

Deliver: additive v2 repositories/migration, ProviderDirectory, Controller-only proposal→admission→seal, crash-safe proposal idempotency, caller→target authorization matrix, canonical `ExecutionLimits.v1`, MeshCoordinator, fake adapters, lifecycle/lineage/budgets/cycle enforcement, typed events.

Exit: contract/replay/property/crash tests; v1 remains readable; no DSH/provider process.

## P2 — Capability and privacy boundary

Deliver: WorkspaceGroup, audience/peer/session/attempt-bound endpoint auth with rotation/nonce/replay/revoke, prompt binding, disclosure/fanout reservations, PD rejection, OS-isolation test harness.

Exit: security/fault-injection suite; no ambient credential/tool access.

## P3 — DSH and thin-plugin UX

Deliver: separate authenticated Controller UI projection channel; provider directory/switcher, mesh tools, graph, compare/synthesis/templates, policy/diagnostics/lifecycle proposals; thin native package fixtures. DSH UI mounts only after DR-007 positive feasibility evidence.

Exit: negative proof that projection never reaches model/session log/AgentLoop; synthetic UI/browser tests, package digest/policy tests; plugins remain disabled by default.

## P4 — Pinned adapter compatibility

Deliver sequentially: Codex, Claude, Qwen general/local, Kimi, DeepSeek API compatibility adapters; current provider evidence is refreshed, signed/approved by pinned technical+security reviewers, verified against revocation registry, and each adapter gets a pinned `MeshToolTransport` mapping.

Exit per adapter: pinned handshake/stream/schema/cancel/teardown/health plus spawn/collect endpoint-auth fixtures; mapping/evidence digests current before `mesh_spawn=true`. Synthetic tables are not P4 evidence. Status remains `compatible`, not operational.

## P5 — Ansible hardening

Deliver: doctor, v2 errors/parser, locked journal + independently anchored signed/HMAC checkpoints, plan/manifest v2 + trusted release envelope, per-task become, true scoped verify, state/gates, compensation diagnostics.

Exit: lint/schema/simulator/fault suite and disposable privileged Apple Silicon VM fresh/idempotent/upgrade/failure/rollback/retry/concurrency matrix.

## P6 — Owner-approved real canaries

One provider/account modality at a time, synthetic public prompt only, no repository private data, no system effects. Owner separately authorizes login/account connection and canary.

Exit per adapter: canary, reconnect, quota/rate behavior, cancel/quiescence, injected failure/recovery; evidence dated and scoped.

## P7 — Controlled enablement

Enable one root/profile/workspace group. Codex remains default unless ADR supersedes. Exactly-one cloud destination remains enforced unless separately approved fanout ADR + grants. PD remains local only.

Exit: operational monitoring, revoke/kill-switch proof, rollback rehearsal, owner acceptance.

## Promotion rules

- Phase dependency is strict; one provider may be P6 while another stays P4.
- Any protocol/auth/policy/manifest drift returns affected profile to prior gate.
- Real login, subscription spend, API key, sudo/become, plugin enablement, deployment and canary are never implied by phase plan.
- Unresolved security or authority conflict blocks only affected route; safe Codex single-cloud/PD-local defaults remain.
