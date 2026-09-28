# 09. Observability, recovery и operations

## Event model

`MeshEvent.v1` JSONL содержит allowlisted fields: `ts`, `event`, `root_run_id`, `run_id`, `session_id`, `attempt_id`, `parent_run_id`, `provider`, `profile_id`, model/runtime/evidence/mapping/limits digests, `phase`, status, classification label, provenance digest, budget deltas, usage source, error codes, recovery state и bounded artifact refs.

Запрещены по умолчанию: prompt/answer bodies, reasoning, tool arguments/results, raw stdout/stderr, tokens, cookies, API keys, provider account IDs, absolute credential paths. Debug capture требует отдельного schema/class/TTL/grant и не включается production default.

## Correlation и metrics

- counters: admitted/denied/spawned/completed/failed/cancelled/uncertain per provider/profile;
- gauges: active sessions, queue depth, reserved tokens/cost, quota remaining only if official;
- histograms: admission/start/first-token/turn/cancel/quiescence latency;
- health: auth freshness, protocol compatibility, provider endpoint, broker/process, capability endpoint;
- deployment: candidate/activated/rolled-back, configuration/activation/operational/operator gates.

`usage_source=provider_reported|controller_counted|estimated|unknown`; values разных semantics не суммируются как exact. Cost cap блокирует, если policy требует exact, а provider даёт unknown.

## Artifacts и retention

Result/evidence artifacts encrypted at rest, addressed by digest, scoped to run/classification и имеют TTL. Delete lifecycle сохраняет tombstone/erasure receipts с `hard|logical|none`. DSH/UI получает sanitized projection. PD artifacts остаются в local PD store и не materialize в DSH graph.

## Recovery matrix

| Failure | Canonical response |
|---|---|
| Auth expires before start | release reservations; `auth_required`; no retry until readiness changes |
| Rate/quota limit | bounded provider-specific backoff; budget/lease revalidation before retry |
| Start ACK lost | reconcile by idempotency/provider evidence; no blind second session |
| Proposal response lost/restart | caller-generation+nonce scope rereads durable proposal/run; exact retry returns original, conflicting digest rejects |
| Stream disconnect | reconnect if official protocol proves identity/sequence; otherwise partial+uncertain |
| Cancel transport fails | terminate broker-owned process/endpoints; uncertain until quiescence proof |
| Tool/effect uncertain | no model retry; Controller reconciliation workflow |
| Primary + cleanup failure | preserve primary; attach compensation error and manual recovery state |
| Controller restart | replay journal, expire leases, reconcile reservations/sessions, quarantine malformed state |
| Controller restart with persisted provider `running` child | fail closed until the SessionController supplies explicit durable route-recovery proof for each exact opaque provider session; never hydrate from volatile maps or redispatch Start (P4 integration gate) |
| UI rotate/revoke/root close interrupted | retain exact prepared lifecycle effect across provider-revision and mesh journals; revalidate expiry before callback, retry same signed nonce, and consume one receipt only after durable revision CAS |
| Provider evidence stale | atomically set `mesh_spawn=false`; drain/cancel policy for active runs; require P4 refresh |
| Endpoint credential replay/revoke | reject before payload processing; close generation; audit safe binding refs |

## Operator surfaces

`provider doctor` и `deployment doctor` read-only: they report schema/version, pinned binaries/digests, config attestation, auth readiness alias, health/quota freshness, journal integrity, gates и recovery actions. Они не log in, refresh by scraping, change config, enable plugin, activate deployment или run a canary.

Kill switches separated for cloud egress, each provider/account, mesh spawning, workspace writes, browser/CUA, MCP/domain service, effects, plugin lifecycle и deployment activation.
