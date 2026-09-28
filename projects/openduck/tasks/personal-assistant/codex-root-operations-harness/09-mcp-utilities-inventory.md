# 09. MCP, utilities и installation plan

## Verified current inventory (2026-08-12)

Источник факта — tracked [OpenClaw config](../../../../../deploy/openclaw/config.json) и [runtime evidence](../../../../../docs/evidence/openclaw-runtime.md); наличие config не заменяет live capability probe перед real use.

| Surface | Текущее состояние | Предлагаемая harness role |
|---|---|---|
| OpenClaw 2026.7.1-2 | loopback/token auth | read-only sensor, session routing |
| Ollama qwen3:8b | loopback, pinned observed digest, no fallback | PD/local classification |
| OpenClaw `codex-safe` | Sol route, agent-scoped home, guardian sandbox, tools denied | current safe reasoning probe; не root control plane |
| Obsidian direct MCP | enabled, eight read-only tools | scoped evidence/tech-base read after data decision |
| Filesystem bridge | disabled | не включать; future writer отдельным effector |
| Kaiten MCP | eight read-only tools | tracker read/context capsule |
| Context7 MCP | docs resolution/query only | technical documentation evidence |
| CuaDriver proxy | allowed Telegram/enterprise-chat window read/status only | app-read sensor; no click/type |
| Public search proxy | unauthenticated public GET/HEAD/search, SSRF bounds | public evidence only, untrusted content |
| Codex app-server/SDK | official programmatic surfaces | root thread control and event stream |
| Codex custom agents | native local Codex capability with inherited posture | Luna/Terra read-only profiles only; not implementation dispatch |
| Codex hooks | lifecycle/tool guardrails | bounded attestation/audit, defense-in-depth |
| Codex MCP server | available integration surface | disabled in target harness; root uses app-server, implementer uses separate Controller-launched app-server/`codex exec`, and custom agents are limited to read-only Luna/Terra |
| MCP Apps custom UI | official optional UI standard documented for ChatGPT/compatible hosts; target Codex desktop support unproven | preferred Codex-facing delivery candidate only after pinned live render + authenticated callback probe |
| Custom local Codex client | app-server officially supports building rich clients; no harness client exists | fallback Codex-facing delivery candidate; new local client/UI with separate Controller channel |

`VERIFIED / current configuration gap` (SRC-OD-07, SRC-OD-08): default OpenClaw runtime exposes several read-only MCPs, so it is not the required chat sensor `tools deny all`. The future sensor is a separate agent/process; editing a deny list in place without negative discovery tests is insufficient.

## Future capability composition matrix

Матрица основана на tracked configuration, current session read-only capability inventory (SRC-ENV-01) и explicit product decisions. `observed` означает только видимость binary/plugin/skill/config, не auth, entitlement, safe scope или approval to install/enable.

| Domain / candidate | Audit status | Target composition | Initial mode | Decision / gate |
|---|---|---|---|---|
| Telegram | CUA can read allowlisted Telegram window; official channel adapter не выбран | prefer official OpenClaw/API adapter for events; CUA read is fallback evidence only | sensor tools none; read-only test account | `DECISION REQUIRED / Product+Security / H6`: official adapter, scopes, ToS, gap/edit semantics |
| enterprise-chat | CUA can read allowlisted window; official integration unverified | official export/API/transcript if available; UI read fallback only | read-only, no recording/upload | provider/admin/consent capability probe before real data |
| Obsidian / tech-base | direct read-only MCP observed; filesystem bridge disabled | narrow read MCP + separate symlink-safe `techbase.create` effector | read-only; writer mock root | writer H5 + exact Inbox/path/content approval |
| Kaiten | read-only MCP tool set observed | read MCP for capsule; separate typed task effector | read-only | write scopes/schema/idempotency/admin decision after H5 |
| Context7 | read-only docs MCP observed | Luna/Terra technical evidence only | read-only, no private content | pin/version/schema; optional per role |
| Codex in-app Browser | product capability observed | public/authenticated browser-read worker, separate submit effector | disabled in root; isolated profile read canary | domain/origin/session/data classification gate |
| Chrome control | skill/plugin surface observed; may use existing signed-in profile | exceptional user-driven read; avoid root inheritance | disabled | explicit owner choice between isolated browser and existing Chrome state |
| CUA / Computer Use | CuaDriver read proxy and Codex CUA capability observed | app-read evidence; deterministic app mutation effector later | existing proxy read-only | bundle/window/action sequence + UI drift acceptance |
| GitLab `glab` | CLI observed in machine workflow | read MR/pipeline adapter; typed comment/status effector later | read-only commands | exact host/project/auth-ref and mutation approval |
| GitHub | recommended remote plugin available but not installed | optional connector for repo/PR read and typed mutation | absent/disabled | choose GitLab-only vs GitHub need; install/auth only after decision |
| Email | Gmail and Outlook Email plugins available but not installed | choose exactly one provider/account first; read adapter + separate draft/send effects | absent/disabled | `DECISION REQUIRED / Product+Data+Security`: Google vs Outlook, scopes, retention/admin |
| Calendar | Google and Outlook Calendar plugins available but not installed | choose provider; free/busy/read separated from proposal/invite | absent/disabled | same-provider decision; invitation outside initial writer |
| Local STT + `ffmpeg` | capability/version not established | offline media normalizer + pinned local STT, network denied | absent/disabled | consent/source legality, binary/model pin, no-network benchmark, raw retention |
| Notifications | one Codex-facing surface is target; delivery binding unresolved | metadata-only Controller→selected AD-15 interface | disabled until H0 probe | screen privacy, urgency/rate/quiet hours and binding decision |
| Scheduler | Codex scheduled tasks/OpenClaw automation capabilities exist | Controller scheduler emits typed wake/event, never direct effect | disabled | workflow reliable manually, overlap/lease/gap/kill-switch tests |
| Native Codex Implementer | app-server/`codex exec` surfaces documented; effective isolation must be probed | separate Controller-launched native runtime, generated clean home/profile + isolated worktree + task sandbox | synthetic workspace-write only; network/effectors disabled | no root-child inheritance; strict WorkOrder/Evidence schemas, separate runtime attestation, no lazy install/credential read, fail-closed cancellation/recovery probe |

### Composition-first rule

`PROPOSAL`: immediate broad installation is unnecessary and prohibited. Сначала выбирается конкретный workflow и состав уже доступных read components; затем фиксируются missing capability, provider, data class, scopes and acceptance. Plugin install, OAuth/auth, account binding, binary/model download and mutation credential follow only an owner decision and phase gate. Harness не устанавливает одновременно Google+Outlook, Browser+Chrome или несколько overlapping chat adapters «на будущее».

Codex implementer hardening baseline `PROPOSAL / H4 probe`: Controller launches a **separate** native app-server or `codex exec` process, never a root-spawned child. It permits lifecycle `read`/`wait` and synthetic workspace writes only before H4 exit; inherited root posture, permission escalation, external messaging, browser/app mutation, package install or unregistered nested delegation is denied. Worker uses a dedicated isolated worktree, generated minimal Codex home/profile, task-scoped workspace-write sandbox, strict schemas, pinned/attested runtime, no lazy installs, no credential-file content and fail-closed unknown output/timeout. Later capability is added one verb/resource at a time. WorkOrder semantics stay independent of model slug and launcher.

## Required logical tools

Controller exposes no broad generic `do_anything`. Minimal typed surface:

- `signals.list/get/ack` (read/status only);
- `artifacts.get_excerpt/get_metadata`;
- `tasks.get_spec/get_state`;
- `work.claim/heartbeat/submit_evidence`;
- `actions.propose/get_preview/cancel`;
- `capabilities.introspect` (metadata only);
- approval and effects are host/UI operations, not freely model-callable tools.

## Codex placement

`PROPOSAL`: root app-server uses freshly generated clean Codex home/profile, stable stdio/Unix transport, `approvalPolicy=never`, network false, restricted explicit read roots and static required allowlists for MCP/skills/hooks/apps. At every `thread/start/resume`, Controller reads effective config, returned instruction sources, MCP/tool inventory and sandbox/read-root projection, compares `RootRuntimeAttestation` digests, then starts a turn with output schema and exact context. Unknown/additional global/user capability blocks. Dynamic tools experimental API не используется in production baseline.

## Installation/enablement plan

1. Inventory exact versions/digests, transport, auth, tool annotations and owner.
2. Generate/store app-server JSON Schema for pinned Codex version; contract-test on upgrade.
3. Generate clean home/profile definitions for root and separate implementer runtime plus explicit read-only Luna/Terra profiles; static MCP/skills/hooks/apps/read/write-root allowlists, network policy and approval policy never. Implementer root-child inheritance forbidden.
4. Implement local Controller MCP read surface and app-server client in synthetic mode.
5. Mark mandatory policy/evidence MCP `required`; attest effective config/instruction sources/inventory/read/write roots for every native agent start and resume; any mismatch blocks.
6. Capability-probe separate native Codex implementer over app-server and/or `codex exec`: structured input/output, separate process identity, generated home/profile, cwd/worktree isolation, workspace-write sandbox, cancellation, identity/auth isolation, no permission escalation, event/evidence support and `WorkerRuntimeAttestation`.
7. Compose one approved workflow from existing read capabilities; add one connector/app read only after provider/account scopes/admin/retention decision.
8. Add writers only as separate effectors after Phase H5 approval tests.
9. Pin packages/model digests; shadow upgrade, schema diff, rollback test.

Installation, OAuth, app authorization, secret creation, account connection and dependency downloads are external changes requiring explicit execution authority; они не следуют из принятия этой спецификации.

`USER DECISION`: один Codex-facing interface является единственной owner-facing surface. `DECISION REQUIRED / AD-15 / H0`: preferred personal plugin + Controller MCP/MCP Apps UI допускается только после pinned target Codex desktop render/authenticated-callback probe; fallback — новый custom local Codex client на app-server; иначе blocked. OpenClaw/Qwen/worker control ports remain internal. `OwnerDecisionEvent` создаётся отдельным Controller-authenticated callback: MCP elicitation, built-in tool approvals, `tool/requestUserInput`, tool call/result, transcript и suggestion click excluded.

## UI delivery feasibility gate

1. Pin exact target Codex desktop build, plugin manifest/bundle, Controller MCP schema and callback authentication design.
2. For preferred route, prove the target host discovers the personal plugin, renders exact MCP Apps UI bytes, returns a render receipt and can send a replay-protected authenticated callback directly to Controller without exposing decision material to the model/tool result. Official docs for ChatGPT/compatible hosts are not runtime proof.
3. Negative-test forged iframe/postMessage/tool result, CSP/origin drift, `mcpServer/elicitation/request`, built-in approvals, `tool/requestUserInput`, transcript approval and stale display instance.
4. If preferred route fails, build/probe a custom local Codex client on pinned app-server schema with a separate Controller channel; do not relabel it as existing desktop UI.
5. If neither route passes, record `UI_DELIVERY_BLOCKED`; no approval, declassification or mutation enablement.

## Tool metadata requirements

Каждый MCP/app tool inventory record содержит: stable tool/action name, server/plugin version, input/output schema digest, readOnly/destructive/idempotent annotations, auth profile ref, data classes, resource scopes, network destinations, approval mode, timeout/retry semantics, owner, last probe and kill switch.

`CONFLICT`: MCP tool descriptions consume root context. Resolution: root loads only role-required servers; skills progressive-disclose workflows; inventory metadata stays outside prompt, capsule включает только selected tool contracts.

## Browser/app caution

Authenticated browser/desktop UI state может давать широкий фактический доступ даже при read intent. Browser/app tools поэтому получают отдельный profile/bundle/window/origin scope. Webpage/UI text untrusted; read action не может автоматически перерасти в submit/click/type/upload. CUA screenshot or accessibility tree не сохраняется в cloud evidence без classification/egress decision.
