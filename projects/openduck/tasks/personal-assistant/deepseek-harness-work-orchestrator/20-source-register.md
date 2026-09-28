# 20. Реестр источников

Web/source claims проверены 2026-08-19. Возможность конкретного аккаунта, OS permission, installed plugin, auth entitlement или current runtime доказывается только отдельным live probe. Primary sources подтверждают capability/semantics, но не разрешают установку, consent, real-data access или effect.

## DeepSeek Harness

| ID | Source | Использование |
|---|---|---|
| SRC-DSH-01 | [Official repository / README](https://github.com/deepseek-ai/deepseek-harness) и [pinned tag `dsh-v0.1.0-rc.7`](https://github.com/deepseek-ai/deepseek-harness/tree/dsh-v0.1.0-rc.7) | official project, MIT, web entrypoint, plugin-first, developer preview/breaking warning |
| SRC-DSH-02 | [Architecture at pinned commit](https://github.com/deepseek-ai/deepseek-harness/blob/99f6f02fecdb7dff40c3fbc9470f5907c29f74ca/docs/architecture.md) | Cordis profiles/bundles/events/seams; session log/context; model-visible means logged; UI extension map |
| SRC-DSH-03 | [Extension cookbook](https://github.com/deepseek-ai/deepseek-harness/blob/99f6f02fecdb7dff40c3fbc9470f5907c29f74ca/docs/cookbook/extension-cookbook.md) | tool/hook/UI/protocol/preset/memory/schedule extension mechanisms |
| SRC-DSH-04 | [MCP client](https://github.com/deepseek-ai/deepseek-harness/blob/99f6f02fecdb7dff40c3fbc9470f5907c29f74ca/packages/mcp/mcp-client/README.md) | stdio/Streamable HTTP tool bridge; server runs outside agent sandbox; no resources/prompts bridge |
| SRC-DSH-05 | [Generic LLM adapter](https://github.com/deepseek-ai/deepseek-harness/blob/99f6f02fecdb7dff40c3fbc9470f5907c29f74ca/packages/llm/llm-pi-ai/README.md) | custom OpenAI-compatible/self-hosted route; provider capability declarations; OAuth limitation evidence |
| SRC-DSH-06 | [Official Codex subagent provider](https://github.com/deepseek-ai/deepseek-harness/blob/99f6f02fecdb7dff40c3fbc9470f5907c29f74ca/packages/subagent/subagent-codex/README.md) | native app-server/auth; one process/thread/turn/final-text and deferred capabilities |
| SRC-DSH-07 | [CLI behavior reference](https://github.com/deepseek-ai/deepseek-harness/blob/99f6f02fecdb7dff40c3fbc9470f5907c29f74ca/apps/cli/reference/README.md) | profile composition, plugin install scripts, local web, default read/network/process limits, telemetry, MCP trust |
| SRC-DSH-08 | [API proxy `session.prompt` implementation](https://github.com/deepseek-ai/deepseek-harness/blob/99f6f02fecdb7dff40c3fbc9470f5907c29f74ca/packages/host/apiproxy/src/api-proxy.ts) и [agent inbox](https://github.com/deepseek-ai/deepseek-harness/blob/99f6f02fecdb7dff40c3fbc9470f5907c29f74ca/packages/core/agent/src/inbox.ts) | evidence that pre-step hook is too late for strict pre-persistence PD admission |
| SRC-DSH-09 | [Session persistence packages](https://github.com/deepseek-ai/deepseek-harness/tree/99f6f02fecdb7dff40c3fbc9470f5907c29f74ca/packages/persistence) | JSONL/SQLite durability baseline; custom encryption/purge requirement |
| SRC-DSH-10 | [Tencent Zhuque Lab paper, arXiv:2608.16393](https://arxiv.org/abs/2608.16393) | bounded empirical prompt-injection evidence; provenance/normalization/source→sink controls and rerunnable eval rationale |
| SRC-DSH-11 | [Pinned API proxy contract](https://github.com/deepseek-ai/deepseek-harness/blob/99f6f02fecdb7dff40c3fbc9470f5907c29f74ca/packages/host/apiproxy/README.md) и [workspace API](https://github.com/deepseek-ai/deepseek-harness/blob/99f6f02fecdb7dff40c3fbc9470f5907c29f74ca/packages/host/apiproxy/src/api/workspace.ts) | prompt/subagent/fork/queue/job surfaces; archive hides but retains session log/accounting; workspace registration delete preserves sessions |

## OpenAI Codex

| ID | Source | Использование |
|---|---|---|
| SRC-OAI-01 | [Codex authentication](https://learn.chatgpt.com/docs/auth) | ChatGPT login vs API key; local auth posture |
| SRC-OAI-02 | [Codex App Server](https://learn.chatgpt.com/docs/app-server) | supported deep integration, threads/turns/events/approvals; local transport basis |
| SRC-OAI-03 | [Codex SDK](https://learn.chatgpt.com/docs/codex-sdk) | alternative programmatic thread integration |
| SRC-OAI-04 | [Codex MCP server](https://learn.chatgpt.com/docs/mcp-server) | external harness calling Codex via MCP alternative |
| SRC-OAI-05 | [Non-interactive mode](https://learn.chatgpt.com/docs/non-interactive-mode) | `codex exec`, structured output/JSONL and sandboxed automation alternative |
| SRC-OAI-06 | [Agent approvals and security](https://developers.openai.com/codex/agent-approvals-security) | sandbox/network/approval model; built-in approval is not domain authorization |

## Apple platform

| ID | Source | Использование |
|---|---|---|
| SRC-APL-01 | [UNUserNotificationCenter getDeliveredNotifications](https://developer.apple.com/documentation/usernotifications/unusernotificationcenter/getdeliverednotifications%28completionhandler%3A%29) | delivered notifications are scoped to the calling app; no universal supported inbox |
| SRC-APL-02 | [AXObserverCreate](https://developer.apple.com/documentation/applicationservices/1460133-axobservercreate) | per-application Accessibility observer basis |
| SRC-APL-03 | [Accessibility notification constants](https://developer.apple.com/documentation/applicationservices/axnotificationconstants_h) | observable UI/application changes and native sensor design |
| SRC-APL-04 | [Scheduling a local notification](https://developer.apple.com/documentation/usernotifications/scheduling-a-notification-locally-from-your-app) и [`UNUserNotificationCenter.add`](https://developer.apple.com/documentation/usernotifications/unusernotificationcenter/add%28_%3Awithcompletionhandler%3A%29) | own-app local `UNNotificationRequest` scheduling; delivery is not guaranteed |

## Microsoft Graph / Outlook

| ID | Source | Использование |
|---|---|---|
| SRC-MS-01 | [Microsoft Graph permissions reference](https://learn.microsoft.com/en-us/graph/permissions-reference) | exact `Mail.ReadBasic`, `Calendars.ReadBasic`, read/write/send scope separation |
| SRC-MS-02 | [Delta query overview](https://learn.microsoft.com/en-us/graph/delta-query-overview) | next/delta link and incremental sync model |
| SRC-MS-03 | [Message delta](https://learn.microsoft.com/en-us/graph/api/message-delta?view=graph-rest-1.0) | folder-scoped message changes, paging/state token semantics |
| SRC-MS-04 | [Calendar view delta](https://learn.microsoft.com/en-us/graph/delta-query-events) | bounded time-window event/occurrence incremental sync |
| SRC-MS-05 | [List messages](https://learn.microsoft.com/en-us/graph/api/user-list-messages?view=graph-rest-1.0) и [list events](https://learn.microsoft.com/en-us/graph/api/calendar-list-events?view=graph-rest-1.0) | initial bounded read, paging and resource shapes |
| SRC-MS-06 | [List calendarView v1.0](https://learn.microsoft.com/en-us/graph/api/user-list-calendarview?view=graph-rest-1.0), [event delta v1.0](https://learn.microsoft.com/en-us/graph/api/event-delta?view=graph-rest-1.0) и [event delta beta](https://learn.microsoft.com/en-us/graph/api/event-delta?view=graph-rest-beta) | v1.0 delta lists `Calendars.Read` while other/beta surfaces list ReadBasic; live-probe, delta-off default and no silent escalation |

## Ollama / Qwen

| ID | Source | Использование |
|---|---|---|
| SRC-OLL-01 | [Official Qwen3 registry/tags](https://ollama.com/library/qwen3/tags) | Qwen3 8B artifact family and published 40K-class context metadata; exact digest still requires local pin |
| SRC-OLL-02 | [Ollama thinking capability](https://docs.ollama.com/capabilities/thinking) | Qwen3 thinking support uses provider-supported `think` semantics; `medium` is not assumed unless exact route supports it |

## Kaiten

| ID | Source | Использование |
|---|---|---|
| SRC-KTN-01 | [Official Kaiten REST API](https://developers.kaiten.ru/) | bearer auth, rate limit and card/history/comment/blocker/time-log resources |
| SRC-KTN-02 | [External webhooks](https://developers.kaiten.ru/external-webhooks) | add/update/remove events for spaces/cards/comments/time logs and payload change shape |
| SRC-KTN-03 | [Retrieve card list](https://developers.kaiten.ru/cards/retrieve-card-list) и [retrieve card](https://developers.kaiten.ru/cards/retrieve-card) | bounded polling/reconciliation fields and version volatility |

## Existing OpenDuck normative/evidence sources

| ID | Source | Использование |
|---|---|---|
| SRC-OD-01 | [Private OpenClaw Assistant](../private-openclaw-assistant/README.md) | inherited privacy, source allowlist, approvals, retention, no-auto-effect and backup decisions |
| SRC-OD-02 | [Private architecture](../private-openclaw-assistant/02-system-architecture.md), [egress policy](../private-openclaw-assistant/04-data-classification-egress-policy.md), [approval workflow](../private-openclaw-assistant/06-workflows-and-approval-gates.md) | TCB, L0–L3, SafeEnvelope, exact approval and UNKNOWN semantics |
| SRC-OD-03 | [Codex-root Operations Harness](../codex-root-operations-harness/README.md) | cognitive vs technical root, context hygiene, WorkOrder/evidence/reviewer and clean runtime |
| SRC-OD-04 | [Codex-root memory/tasks](../codex-root-operations-harness/10-memory-techbase-and-tasks.md) | Beads issue vs verified memory vs tech-base separation and private global memory handling |
| SRC-OD-05 | [Local model benchmark](../../../../../docs/evidence/local-model-benchmark.md), [Controller deployment](../../../../../docs/evidence/controller-deployment.md), [sensor ingress](../../../../../docs/evidence/sensor-ingress.md) | existing bounded components and local evidence; not production enablement |
| SRC-OD-06 | [Core implementation](../../../../../internal/core/core.go), [encrypted queue](../../../../../internal/core/filequeue.go), [schemas](../../../../../schemas/harness/README.md) | current deterministic components/contracts available for reuse |

## User/session evidence

| ID | Source | Использование |
|---|---|---|
| SRC-USR-01 | `USER REQUIREMENT / 2026-08-19` + inherited explicit requirements | enterprise-chat/TG/call capture; demo/calendar; task-tracker; Beads memory; multi-task; Outlook; time/review/project prep; broad read-only public web/Context7; Qwen 40960/32768/thinking; chat archive/delete lifecycle |
| SRC-USR-02 | `USER DECISION / 2026-08-19` | pinned DSH + external Controller + small ingress fork; DSH single surface, Codex cognitive root, Controller TCB |
| SRC-USR-03 | `USER DECISION / inherited conversation` | `Это ПД` local Qwen; no backups now; Hermes unnecessary |
| SRC-ENV-01 | `SESSION INVENTORY / 2026-08-19` | Outlook Email/Calendar plugins appear in recommended catalog but are not installed; no DSH runtime entitlement implied |
| SRC-ENV-02 | `LOCAL RESEARCH CLONE / 2026-08-19` | pinned DSH commit `99f6f02...`; read-only source inspection, no install/config mutation |

## Evidence quality and change protocol

- `VERIFIED` capability is not `ENABLED` capability.
- Source claim uses the minimum supported semantics; account/tenant/admin/OS behavior requires live probe.
- Research security statistics are scoped to paper setup and do not become universal rates.
- Each volatile source is rechecked before its phase; changed semantics create risk/conflict and block promotion.
- External/source code is never copied into runtime solely because it is listed here.
