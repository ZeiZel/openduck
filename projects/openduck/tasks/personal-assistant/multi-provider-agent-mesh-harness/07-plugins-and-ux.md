# 07. Плагины и UX

## Controller-owned DSH packages

| Package | Surface | Mutation |
|---|---|---|
| `provider-directory` | profiles/readiness/quota/policy eligibility | refresh probe через exact operation |
| `session-mesh` | mesh tool schemas и Controller client | spawn/send/steer/cancel only via bound API |
| `ui-provider-switcher` | root/child provider+model picker | creates immutable selection/session revision |
| `ui-session-graph` | lineage, attempts, status, budgets | cancel/retry через exact action |
| `run-compare` | parallel result comparison | no effects |
| `run-synthesis` | schema-bound synthesis with source coverage | new bound run |
| `run-templates` | approved role/order templates | proposal; template versioning separate |
| `policy-approval-inspector` | envelopes, grants, destination, expiry | trusted Controller renderer for approval |
| `provider-diagnostics` | auth/health/quota/protocol | read-only probes by default |
| `deployment-diagnostics` | doctor/journal/gates | read-only; deploy/rollback separate |
| `plugin-lifecycle` | inventory, compatibility, enablement plan | exact signed/approved Controller operation |

`VERIFIED`: existing DSH plugin inventory is read-only и existing OpenDuck plugins disabled. Поэтому lifecycle package не записывает Cordis config напрямую из model turn; он формирует plan, Controller validates package digest/compatibility and performs a separately approved operation.

`DECISION REQUIRED / DR-007 / P0`: доказать, что pinned DSH UI может получать bounded authenticated Controller projection без AgentLoop delivery, model visibility, durable session-event append и turn wakeup. Default P3 surface — отдельный Controller UI client/channel. При отрицательном/неполном probe DSH UI packages не монтируются; DSH может открыть отдельный trusted UI, но не проксирует projection через model session.

## Thin native packages

- Codex plugin: skill/commands/UI metadata + per-session mesh MCP only.
- Claude plugin: namespaced skills/agents + `.mcp.json` pointing to the same mesh endpoint.
- Qwen plugin/extension: provider-switch and mesh commands backed by the same endpoint.
- Kimi plugin: manifest with mesh MCP; native hooks/tools disabled unless separately reviewed.
- DeepSeek: no native subscription package; DSH/API profile only.

Thin package не содержит provider credential, Controller service key или general executable. Broker-to-process bootstrap delivers short-lived `MeshEndpointBinding` credential outside argv/env/model-visible prompt/session log. UI credential имеет отдельную `audience=ui`, peer identity и nonce/revoke state; mesh credential нельзя replay в UI и наоборот.

## Provider switching

Switcher всегда показывает:

1. current root/provider/model/profile/account alias;
2. classification/destination eligibility;
3. auth state, quota/rate/health freshness;
4. capabilities gained/lost, workspace mode и cost semantics;
5. operation type: new root, new child, clean fork или model-only new session.

Switch during active turn не меняет transport in-place. Пользователь/модель создаёт new session revision; старый attempt завершается/cancels separately. «Auto» может только выбрать из allowlisted eligible profiles по deterministic policy и обязан показать resolved profile.

## Graph, compare, synthesis

Graph nodes — sessions/attempts; edges — spawn/send/steer/synthesis. UI различает queued/running/partial/completed/failed/cancelled/uncertain и primary/compensation errors. Compare не скрывает missing/failed provider. Synthesis получает bounded validated `RunResult` refs и coverage map, не raw transcripts и не credentials.

## Approval UX

DSH/native plugin может показать suggestion, но approval authority остаётся trusted Controller renderer с exact payload/destination/capabilities/budget/expiry. Provider/session switch, fanout grant, cloud disclosure, plugin lifecycle и deployment — разные decision types; один approval не покрывает другой.
