# 19. Решения, риски и конфликты

## Зафиксированные решения

| ID | Attribution | Решение |
|---|---|---|
| D-001 | USER DECISION / 2026-08-19 | DSH — единая work surface; Codex — cognitive root; Controller — technical root/TCB. |
| D-002 | USER DECISION / 2026-08-19 | Целевая база: pinned DSH + внешний Controller + минимальный ingress fork. |
| D-003 | USER DECISION / inherited | `Это ПД` обрабатывается local Qwen; raw PD не переходит в внешний Codex. |
| D-004 | USER DECISION / inherited | Backup hooks проектируются, но backups сейчас не реализуются/не включаются. |
| D-005 | USER DECISION / inherited | Hermes не является частью целевой архитектуры. |

## Решения, необходимые до enablement

| ID | Вопрос | Owner / gate | Safe default |
|---|---|---|---|
| DR-001 | Product/data/technical/security owners и escalation | User / P0 | no P1 implementation promotion |
| DR-002 | Upstream mirror/fork ownership, patch budget and update cadence | Technical+Security / P0 | exact rc.7 commit, no update |
| DR-003 | enterprise-chat/TG acquisition: official API/export vs AXObserver/CuaDriver; approved apps/chats | Product+Security / before P7 real source | synthetic fixture only |
| DR-004 | TTL per source/class/store and legal/business retention basis | Data+Security / before real data | real ingest blocked |
| DR-005 | Outlook tenant/account, delegated scopes and calendar conflict: ReadBasic polling vs explicit Calendars.Read for delta | Product+Security+admin / before Graph auth | no OAuth; calendar delta off; no scope escalation |
| DR-006 | Kaiten company/spaces/cards/fields, webhook endpoint, token scopes | Product+Security / before Kaiten auth | no token/account |
| DR-007 | Calendar authority, conflict policy and provider-write intent | Product / before real calendar projection | conflict-preserving read model |
| DR-008 | Definition of demo, timezone/default reminder and confirmation roles | Product / before P4 acceptance | candidate only |
| DR-009 | Time-tracking signals, parallel timers, idle/sleep handling, retention/report purpose | Product+Privacy / before activity sensing | explicit owner timers only |
| DR-010 | Memory scopes/categories, auto-candidate and approval rules for Beads/tech-base | Product+Data / before memory writes | lookup metadata; writes disabled |
| DR-011 | Real-data allowlists and absolutely forbidden data/categories/projects | Data+Security / before P7 | no real source |
| DR-012 | Exact Codex subscription/org data controls and allowed classes | Product+Security / before cloud pilot | sanitized L0/L1 synthetic only |
| DR-013 | Owner authentication/render-receipt mechanism and pre-approved templates | Security+Product / before P6 exit | effects disabled |
| DR-014 | Always-on host vs Mac sleep, coverage/SLO expectations | Product+Technical / before SLO | best-effort with visible gaps |
| DR-015 | Whether/when to enable local encrypted backups, keys, RPO/RTO/restore | Owner+Security / after P9 proposal | no backup copies |
| DR-016 | Project-prep mutation scope: installs/services/network/git operations | Technical+Security / before real project prep | read-only proposal |
| DR-017 | Separate Outlook/Kaiten/chat/time writer app registrations and first effector | Product+Security / before P8 | no writer credentials |
| DR-018 | Can DSH act as no-general-LLM UI/event host with separate non-session/non-persistent read-model channel, or is isolated web-client fork/bridge required? | Product+Technical+Security / P1 | rollout blocked until proven |
| DR-019 | Meeting/call platforms, consent/participant notice, transcript/audio source, coverage and retention | Product+Privacy/Legal+Security / before real call data | no capture; synthetic transcript only |
| DR-020 | OS-enforced isolation topology for every credential/raw-store runtime: Codex, Graph, Kaiten, AX/CuaDriver, Qwen/quarantine and Beads/private stores; separate principal/App Sandbox/read-deny/Keychain ACL evidence against malicious DSH, plus Codex model/tool network separation | Technical+Security / before any real login/credential/raw data | synthetic stubs only; process parent/ref insufficient |
| DR-021 | Whether model/Qwen-derived PD release can ever be approvable after dedicated security acceptance | Owner+Security / future only | disabled; owner-authored exact release only |
| DR-022 | Real safe-public web/Context7 network profile, allowed public destinations, operational bounds, live conformance and revoke/kill-switch evidence | Owner+Security+Technical / before P7 public network | non-routable synthetic server only |

## Conflicts

| ID | Conflict | Resolution rule |
|---|---|---|
| C-001 | DSH durable inbox/session semantics vs requirement to intercept PD before any log | minimal pre-inbox fork/custom composer; no real input until AC-003/004 |
| C-002 | Single interface vs privilege separation | DSH projects Controller state; approval UI never owns grant/effect authority |
| C-003 | «Оркестрировать всю работу» vs least privilege | typed per-domain capabilities; unsupported operation remains proposal/deny |
| C-004 | Continuous monitoring vs sleeping/offline Mac | honest coverage gaps/backfill; separate always-on decision |
| C-005 | Codex by ChatGPT subscription vs standard DSH LLM adapter/API semantics | native authenticated `codex app-server`; never copy OAuth token or treat plan as API credit |
| C-006 | «Сохранять всё выполненное» vs minimization/retention | save verified reusable claims/evidence refs, not raw transcript/progress; owner-defined TTL |
| C-007 | Automatic time tracking vs privacy/legal timesheet | explicit timers baseline; derived activity candidate only after DR-009 |
| C-008 | DSH developer preview vs stable daily control plane | exact pin, minimal fork, contract/replay/security suite and rollback on every update |
| C-009 | DSH AgentLoop/model-centric session vs target UI-only host with Controller-direct Codex | DR-018/P1 feasibility; disable all ordinary model paths or block rollout |
| C-010 | DSH session-event UI projections vs root-context/privacy hygiene | separate authenticated local UI channel; no session-event projection; fork if unavailable |
| C-011 | Convenient Qwen-derived redaction vs safe PD release | baseline derived release disabled; owner types exact release in trusted editor |
| C-012 | UI «Delete» expectation vs upstream archive/registration semantics | archive labelled reversible; purge reports per-store `hard|logical|none` and residuals |
| C-013 | Broad public research vs new real network authority | separate DR-022/P7 capability; synthetic until live bounded conformance and revoke evidence |

## Risk register

| ID | Risk | Likelihood/impact | Mitigation |
|---|---|---|---|
| R-001 | Raw PD logged before routing | H/Critical | pre-inbox admission, closed raw APIs, sentinel AC-003–006 |
| R-002 | Prompt injection from chat/mail/card/tool result | H/Critical | provenance/carrier, Unicode normalization, no direct sinks, AC-007 |
| R-003 | Default DSH read/network/process visibility leaks data | M/Critical | OS isolation, private MCP proxy, clean profile, AC-033 |
| R-004 | MCP/plugin trusted executable compromise | M/Critical | pins, review, SBOM, build isolation, no ambient MCP |
| R-005 | Codex OAuth/token copied into DSH | M/Critical | P5 auth stub; P7 DR-020 principal/App Sandbox/read-deny/Keychain ACL attack evidence |
| R-006 | AX/CuaDriver captures wrong app/window/content | M/High | signed allowlists, bounded snapshot, revoke/gap, synthetic look-alike tests |
| R-007 | Outlook/Kaiten cursor loss misses changes | M/High | delta/checkpoint, full reconcile, explicit gap |
| R-008 | Wrong task/date mapping creates false plan | M/High | candidates, provenance/conflict, owner baseline freeze |
| R-009 | Memory preserves stale/wrong/private fact | M/High | evidence/freshness/scope/conflict/forget lifecycle |
| R-010 | Parallel workers collide or pollute root | M/High | DAG/workspace ownership, budgets, typed evidence |
| R-011 | Wrong recipient/provider mutation | L/Critical | exact destination/revision preview, separate effector, CAS/receipt |
| R-012 | Ambiguous external outcome duplicates action | M/High | `UNKNOWN`, reconcile-before-retry, idempotency |
| R-013 | Approval fatigue | M/High | risk-tiered concise previews, no heterogeneous batch, metrics |
| R-014 | Mac resource pressure from Qwen/Codex/DSH | H/Medium | benchmark, concurrency/context limits, backpressure |
| R-015 | DSH breaking update invalidates admission/UI/session assumptions | H/High | pinned fork boundary, update gate/rollback |
| R-016 | Over-retention across caches/indexes/evidence | M/High | inventory, TTL, purge sentinel, backups disabled |
| R-017 | Sleep/auth/rate limit creates false “all clear” | H/Medium | coverage/stale badges and health alerts |
| R-018 | Time/activity monitoring becomes surveillance | M/High | explicit timers default, no content capture, DR-009 |
| R-019 | Malicious DSH plugin reads Codex auth or injects duplicate model turn | M/Critical | P5 stub; P7 DR-020 OS boundary plus final-gate exactly-one egress trace |
| R-020 | UI read models leak into DSH session/context/browser stores | M/Critical | separate UI channel, memory-only cache, sentinels, blocking DR-018 |
| R-021 | Archive is mistaken for deletion or purge overclaims erase | H/High | explicit lifecycle records, erasure capabilities/receipts and residual disclosure |
| R-022 | Conversation changes after privacy scan but before Codex egress | M/Critical | snapshot-bound decision/prompt, final authoritative re-read and race fixtures |
| R-023 | Cross-store crash duplicates append or sends stale prompt | M/Critical | consuming/receipt/reconcile/uncertain state; no blind retry/egress |
| R-024 | Same-UID malicious DSH plugin reads sidecar token/raw store | M/Critical | DR-020 OS-enforced isolation and per-sidecar attack evidence before real enablement |

## Change protocol

Decision becomes normative only as dated ADR/decision record with owner, affected IDs, migration and rollback. Conflict is never removed by editing source history; it is resolved by a superseding record and traceability update.
