# 01. Текущее состояние и разрывы

Снимок evidence: 2026-08-25. Dirty working tree содержит чужие изменения; эта спецификация не интерпретирует их как завершённую поставку.

## OpenDuck Controller и runtimes

| ID | VERIFIED evidence | Разрыв |
|---|---|---|
| GAP-001 | Root README указывает synthetic-only posture. | Нет доказанного real multi-provider runtime. |
| GAP-002 | `harness.Repository` — sole durable authority; Controller state — линейный task lifecycle. | Нужны additive `Run`/`Session`/`Attempt` state machines и миграция v1→v2, а не cosmetic provider field. |
| GAP-003 | `WorkOrder`/binding hard-code implementer `codex`, transport `app_server|exec`, `approval=never`, `workspace-write`, `network=false`. | Нужны provider-neutral v2 contracts без ослабления v1 validation. |
| GAP-004 | Codex runtime умеет account login start для ChatGPT flows, использует clean profile/broker/isolation seams. | Нет общего `SessionStarter`/stream/control/usage abstraction и provider directory. |
| GAP-005 | Local Qwen protocol pinned и synthetic; production constructor fail-closed, Controller возвращает `ErrLocalPDUnavailable`. | PD route сохраняется; general local Qwen adapter должен быть отдельным profile и не ослаблять PD isolation. |

## DSH seams

| ID | VERIFIED evidence | Разрыв |
|---|---|---|
| GAP-006 | Cordis предоставляет services/events/reversible effects; model adapters, tools и subagents заменяемы конфигурацией. | DSH composition удобна для UI/adapters, но не authoritative policy boundary. |
| GAP-007 | Subagent contract имеет registry, cancel/result и optional depth/toolFilter/persona/output schema. | In-process `toolFilter` не OS/Controller authority; нет cross-provider opaque auth, budgets, cost, lineage/cycle ledger. |
| GAP-008 | Claude/Codex bridges запускают fresh one-shot child и возвращают final answer; native settings/auth authoritative. | Нет continuation, usage/progress, deterministic capability enforcement, runtime version probe и robust reconnect. |
| GAP-009 | ACP создаёт fresh session с `mcpServers: []`; tool/depth/persona/schema capabilities не enforceable. | ACP нельзя использовать как универсальный mesh authority без Controller per-session MCP и typed binding. |
| GAP-010 | `llm-pi-ai` сам получает только API-key route; stored OAuth не означает login support. | OAuth/subscription adapters должны использовать native official broker/CLI, не generic LLM adapter. |
| GAP-011 | UI умеет per-session model directory/selectModel; plugin inventory показывает enablement/fiber phase. | Directory advisory, inventory read-only; нужны policy-aware switch, lifecycle operations и diagnostics. |
| GAP-012 | Controller read bridge bounded/read-only; все local OpenDuck plugins disabled. | Нужен authenticated Controller mesh bridge и поэтапное enablement, без direct DSH filesystem/credential reads. |

## Provider modalities

- `VERIFIED`: Codex официально поддерживает ChatGPT subscription sign-in и API-key usage; app-server exposes browser/device login lifecycle.
- `VERIFIED`: Claude Code требует Pro/Max/Team/Enterprise/Console account либо supported third-party provider; CLI browser login официальный.
- `VERIFIED`: Qwen OAuth free route discontinued; официальный current subscription-like route — Alibaba Cloud Coding Plan с dedicated endpoint/key; API и local endpoints допустимы.
- `VERIFIED`: Kimi Code membership даёт shared subscription quota; CLI поддерживает Kimi Code OAuth device flow и platform API key.
- `VERIFIED`: проверенные DeepSeek docs описывают API key/top-up/API integration; официальная subscription automation для harness не подтверждена.

## Ansible deployment gaps

| ID | VERIFIED evidence | Требуемое исправление |
|---|---|---|
| GAP-013 | `site.yml` задаёт play-wide `become` и production path загружает `vars/example.yml`. | Per-task exact become; example vars исключить из production execution. |
| GAP-014 | Run ID строится из digest + second-resolution epoch. | Collision-resistant Controller/installer-generated run ID и exclusive per-run lock/journal. |
| GAP-015 | Plan execution проверяет helper hash, но plan JSON полностью не валидируется. | Closed schema, exact fields/types/digests/operations и cross-field validation до apply. |
| GAP-016 | `activation=false` выводит `scoped_verify_only`, но не запускает настоящий scoped verify. | Реальный non-activation scoped verification с evidence. |
| GAP-017 | `active.release` пишется раньше финального `activated` marker. | Явные candidate→activated transitions; external active pointer публикуется только после activation commit. |
| GAP-018 | Callback append’ит общий `run.jsonl`; события часто без phase/run binding. | Per-run locked journal, typed sanitized record и durable phase boundaries. |
| GAP-019 | Artifact role требует exact hard-coded list из 11 artifacts. | Manifest v2 с typed artifact groups/provider bundles и backward-compatible validator. |
| GAP-020 | Error extraction исторически зависит от stderr/string matching; compensation может маскировать primary. | Shared typed error schema/parser, primary+compensation preservation, malformed/empty fallback. |
| GAP-021 | Cleanup работает в `always` и может стать вторичной ошибкой. | Cleanup — compensation outcome; primary error неизменен, cleanup evidence отдельно. |
| GAP-022 | Статические тесты покрывают часть safety posture. | Добавить simulator, fault injection и disposable privileged macOS VM matrix. |

## Independent review P1/P2 gaps

| ID | Finding | Нормативное закрытие в этом пакете |
|---|---|---|
| GAP-023 | Caller мог интерпретироваться как creator готового WorkOrder/binding. | Proposal-only public spawn и Controller-only admission/sealing. |
| GAP-024 | Не было provider-neutral transport и five-provider mapping gate. | `MeshToolTransport`; per-provider mapping; `mesh_spawn=false` default. |
| GAP-025 | Endpoint binding не задавал peer/audience/replay security. | Non-model credential + peer identity, expiry/rotation/nonce/revoke. |
| GAP-026 | DSH UI projection мог попасть в AgentLoop/session log. | Separate Controller UI default; P0 feasibility decision и P3 negative gate. |
| GAP-027 | Budget fields не имели canonical mandatory finite units/currency schema. | `ExecutionLimits.v1`; missing/unbounded reject. |
| GAP-028 | Локальная hash chain ошибочно могла называться tamper-evident. | Protected HMAC/signature + independent checkpoint anchor. |
| GAP-029 | Manifest/release не имели trusted platform/arch/replay envelope. | Signed `ReleaseEnvelope.v1` consumed before mutation. |
| GAP-030 | Volatile provider docs/runtime claims не имели reproducible freshness artifact. | P0/P4 `ProviderEvidenceRecord.v1`; stale-disable. |
