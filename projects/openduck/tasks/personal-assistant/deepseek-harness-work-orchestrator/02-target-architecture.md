# 02. Целевая архитектура

## Архитектурный выбор

`USER DECISION`: **Pinned DeepSeek Harness + внешний OpenDuck Controller + минимальный ingress fork**.

`PROPOSAL`: поставлять reviewed pinned **distribution/profile**, а не набор ambient plugins. Единственный upstream fork — lowest durable model-visible admission seam. Один Command Center/bridge UI bundle обслуживает projections. Minimal Codex adapter связывает Controller с внешним Codex runner. Optional safe-public tools изолированы; Controller владеет DAG/scheduler/memory policy, а Qwen/private MCP/readers остаются внешними sidecars/modules. Web-client fork и P1 feasibility gate обязательны, если DSH не даёт UI-only/non-context/non-persistent local channel (`DR-018`).

```text
Enterprise-chat/TG/Calls AX ─┐
Task-tracker/Graph readers ├─> external source modules ─> OpenDuck Controller / TCB
CuaDriver proxy ─────┘                                  │
                                                       ├─ authoritative gate/high-water
                                                       ├─ ledgers/DAG/scheduler/memory
                                                       ├─ capabilities/approvals/effects
                           ┌───────────────────────────┴──────────────────────────┐
                           │                                                      │
             LocalPDDispatch (never DSH)                       CloudAdmittedPrompt (≤L1)
             native Qwen sidecar + LocalPDView              DSH lowest append seam + receipt
                outside DSH/browser/session                              │
                                                                         ├─ separate UI channel
                                                                         └─ Controller final gate
                                                                            re-read + egress CAS
                                                                                     │
                                                                 external persistent Codex app-server
                                                                   dedicated isolated boundary
```

## Deployment units

| Unit | Назначение | Trust/capabilities |
|---|---|---|
| `openduck-controller` | canonical state machines, admission, privacy, ledgers, DAG, scheduler, memory policy, grants, approvals, recovery | TCB; no probabilistic authority |
| pinned `openduck-dsh-distribution/profile` | exact DSH fork/profile and Command Center/bridge UI bundle | UI/event host only; general DSH LLM/agent/subagent routes disabled |
| `openduck-ingress-fork` | gates every durable model-visible append and closes raw paths | single maintained upstream patch; current-config CAS |
| external `openduck-codex-runtime` | persistent app-server threads/events/schemas | P5 synthetic protocol/auth stub; real Codex-owned login/use only P7+DR-020+explicit authorization; isolated profile/OS boundary |
| native `openduck-qwen-sidecar` + `LocalPDView` | PD processing and local secure interaction | outside DSH/browser/session bus; no tools/network/fallback |
| source modules/sidecars | AX enterprise-chat/TG/calls, task-tracker, Graph, CuaDriver | read-only per-source scopes; never parented by DSH |
| optional safe-public reader/MCP | public web/Context7 only | GET/navigation; no private payload/credential/private-net/effect |
| effectors | exact external/local mutation | separate process/credential per effect type; disabled by default |
| encrypted stores | Controller ledgers, quarantine, local PD sessions | owner-only; per-store erasure capability; backups disabled |

`VERIFIED / bounded prototype, not DSH-integrated or production`: Controller MCP/UI proof, CuaDriver proxy and Codex runtime runner exist as bounded repository artifacts/evidence. Это не доказывает целевую integration, privilege separation, auth safety или enablement.

## Planes

1. **Ingress plane**: source-specific collection, source locator, coverage/cursor and authenticity signals.
2. **Policy plane**: Controller class high-water, DLP, provenance, replay, snapshot-bound cloud admission, local PD dispatch and declassification.
3. **Work plane**: Controller-owned TaskSpec, WorkGraph, WorkOrder/AgentRunOrder, timers, memory policy and review evidence.
4. **Model plane**: external native Qwen for PD; target external Codex app-server threads for safe primary turns. P5 uses non-model stub, P7 may enable real Codex after gate. Luna/Terra/implementer are Codex run profiles, not DSH providers.
5. **Presentation plane**: DSH fetches typed Controller read models over separate authenticated local UI channel. Inbox/calendar/memory/health rows не становятся session events/model context/DSH persistence/browser durable cache.
6. **Effect plane**: one effector per action family, exact payload, CAS/idempotency, receipt/reconcile.

## Critical routing

### Safe work

`SourceEvent → Controller Gate/snapshot → SafeContextCapsule ≤L1 → CloudAdmittedPrompt → crash-safe DSH append+receipt → Controller final authoritative re-read/egress CAS → persistent Codex turn → EvidenceBundle → ReviewVerdict → owner decision → optional effector`.

Один consumed `CloudAdmittedPrompt` с matching append receipt может создать максимум один Codex cloud request. Decision/prompt bind’ят conversation scope, immutable event/revision set, complete-through watermark, authoritative gate/coverage digest and class-high-water version. Final Controller boundary atomically re-reads them; new/edit/delete/backfill/hidden prior event, gap/revoke/class bump invalidates request. DSH не вызывает model adapter, не строит duplicate model context и не инициирует ordinary AgentLoop/subagent turn.

### PD

`SourceEvent/owner input → Controller Gate → monotonic PDSession → LocalPDDispatch → native Qwen sidecar → Controller-owned LocalPDView`.

`LocalPDDispatch` не содержит DSH/Codex target/attestation и никогда не проходит DSH seam. Raw prompt/answer не создаёт DSH event, postMessage, localStorage/IndexedDB/service-worker cache, search row, title or telemetry. Qwen suggestion не может стать approvable release. Для non-local release отдельный blank/non-prefilled editor без suggestion/import/paste/drop/autofill/AX/AppleScript/synthetic input принимает fresh-authenticated manual owner input; после consumed exact decision/post-scan Controller создаёт fresh clean session без history/handles/index lineage. Class high-water не снижается.

### Owner and internal input paths

Custom composer сначала отправляет bytes Controller. Lowest durable append gate независимо защищает prompt, steer, followup, subagent prompt, attachment, import, resume seed, fork seed, scheduled job, background job, tool-context injection, plugin call и internal inbox call; любой cloud path без этого seam hard-disabled. Он проверяет full `CloudAdmittedPrompt`, CAS-переводит lifecycle `pending→consuming`, append’ит idempotently, возвращает receipt; crash reconciliation завершает `consumed|uncertain`, причём uncertain блокирует retry/egress. `agent/pre-step` — defense-in-depth, не gate.

### UI projections

Command Center read models идут не через `session/event`. Baseline — separate authenticated local UI channel с ephemeral memory-only cache. Sentinel scans проверяют DSH JSONL/SQLite/context assembly и browser durable stores. Если upstream Web client нельзя использовать без persistence/session projection leakage, DR-018/P1 блокирует rollout и требует isolated fork/client bridge.

## Codex placement and auth

Официальный `dsh-subagent-codex` — только one-shot subagent bridge, который надо заменить/минимально расширить; это не normal LLM provider.

- P5 реализует только persistent-thread protocol against synthetic auth/app-server stub; stream progress/evidence; structured outputs;
- runner вне DSH supervisor/process tree;
- real owner-interactive login в Codex-owned surface разрешается только P7+ после DR-020 и отдельной explicit authorization; DSH не знает token/path и не управляет auth lifecycle;
- dedicated native Codex profile/home/workspace;
- отдельный OS principal/App Sandbox либо доказанный OS-enforced read-deny to auth store + Keychain ACL against malicious DSH before enablement;
- model-transport network policy отделена от tool/worker process network policy;
- runtime attestation включает parent/supervisor, OS principal, profile, model, tools/MCP, read/write roots and both network digests;
- malicious DSH plugin cannot read auth artifacts, inject duplicate turn or gain Codex tool network.

Если DSH не способен быть UI/event host без general root LLM, P1 остаётся `BLOCKED` до accepted bridge/fork evidence.

## DSH capability constraints

`VERIFIED`: default `workspace-write` не confines reads/network/process visibility; DSH MCP command runs outside agent sandbox. Поэтому DSH никогда не запускает/parent’ит private MCP. CuaDriver/enterprise-chat/TG/calls/Outlook/task-tracker/Obsidian readers существуют за Controller. Every credential/raw-store sidecar — Codex, Graph, task-tracker, AX/CuaDriver, Qwen/quarantine, Beads/private stores — требует DR-020 and OS-enforced isolation evidence against malicious same-UID DSH; process-parent/ref alone insufficient. Optional Context7/public web проходит safe-public policy; real network off до P7/DR-022, затем только explicit enablement, live bounded conformance and revoke proof.

## Источники истины

| Domain | Authoritative source |
|---|---|
| admission/classification/approval/effect | Controller ledgers and IngressGateState |
| coverage UI | redacted `CoverageState` projection only |
| work scope/acceptance | frozen TaskSpec + order hashes |
| external task status | Task-tracker snapshot + explicit TaskLink reconciliation |
| calendar | chosen authority after DR-007; otherwise conflict-preserving projection |
| time | Controller TimeLedger; provider export only receipt |
| issue lifecycle | scoped Beads task database |
| reusable public/project fact | accepted MemoryRecord; private value only behind `PrivateMemoryRef` |
| UI | ephemeral projection; never authority/model context |

## Compatibility boundary

Pinned baseline: `dsh-v0.1.0-rc.7`, commit `99f6f02fecdb7dff40c3fbc9470f5907c29f74ca`. Upgrade requires source/install-script review, lockfile/SBOM/digests, append-path diff, schema/session replay, privacy/injection/auth/network/UI suites, synthetic canary and explicit rollback/promote record.

## Минимальный POC

Synthetic only: pinned distribution, all-path CloudAdmittedPrompt admission, separate LocalPDDispatch/Qwen/LocalPDView, separate UI read-model channel, persistent Codex protocol against auth/network stub, one synthetic chat/call/task-tracker/Graph/public-doc feed, calendar/graph UI and tamper-evident audit. Pass: no real credential/account/login/non-loopback provider network/effect; crash/race fixtures yield no duplicate append/egress; input/output PD sentinels absent from DSH/browser/Codex; exactly one synthetic Codex transport for safe prompt; no private MCP child.
