# 00. Контекст, цели и границы

## Исходное состояние

`VERIFIED / 2026-08-12`: репозиторий содержит local-only synthetic core: strict `InboundEvent`/`SafeEnvelope` schemas, deterministic DLP, encrypted leased queue, durable pseudonym mapping и fail-closed commit-uncertainty behavior. Реальные интеграции и egress не включены. См. [существующую архитектуру](../private-openclaw-assistant/02-system-architecture.md) и [runtime evidence](../../../../../docs/evidence/openclaw-runtime.md).

`VERIFIED / 2026-08-12`: локальный OpenClaw `2026.7.1-2` использует loopback Ollama `qwen3:8b`, не имеет fallback; browser, exec, process, message/channel mutation и generic write/delete/mutate запрещены. Отдельный `codex-safe` route tool-less и sandboxed. PD plugin sticky-маршрутизирует canonical marker и near-miss quarantine локально.

`VERIFIED / Codex manual 2026-08-12`: Codex поддерживает subagent threads, custom agents, per-agent model/sandbox/MCP/skills, app-server threads/turns/events/approvals, SDK, non-interactive structured output, hooks и MCP. Подробные ссылки находятся в [source register](15-source-register.md).

## Проблема

Большая root-сессия деградирует, если в неё постоянно попадают chat transcript, tool output, тестовые логи и worker reasoning. Одновременно untrusted messages не должны получать возможность инициировать произвольное исполнение или cloud egress. Нужен слой, который превращает наблюдения в ограниченные typed signals, а intent — в проверяемые specs, work orders и evidence.

## Цели

- G-01: сохранить Codex root сфокусированным на требованиях, решениях, декомпозиции и acceptance.
- G-02: обеспечить low-latency bounded answers через Luna без загрязнения root history.
- G-03: обеспечить локальную обработку PD с доказуемым отсутствием cloud/tool route.
- G-04: выполнять frozen WorkOrder через native Codex implementer с минимально необходимыми execution capabilities и чистой task-scoped средой.
- G-05: поддержать read/write/browser/app workflows с единообразным capability/approval contract.
- G-06: сделать lifecycle возобновляемым после crash, compaction, restart и partial failure.
- G-07: дать owner точную provenance, preview, audit и kill switches.
- G-08: запускать root из reproducible clean Codex profile без неучтённых global MCP/skills/hooks/apps, network или broad file reads.
- G-09: дать owner один интерфейс Codex для goals, suggestions, status, approvals и action previews, не перенося authorization authority из Controller в model/UI transcript.

## Не-цели

- NG-01: OpenClaw не становится cognitive root или универсальным executor.
- NG-02: Qwen не становится privacy/security policy authority.
- NG-03: transcript, model memory или `AGENTS.md` не используются как task database.
- NG-04: broad access не означает standing permission на unattended effects.
- NG-05: harness не обходит ToS, OS permissions, admin policy или consent requirements.
- NG-06: exactly-once external delivery не обещается.

## Границы доверия

- TB-H0: внешние чаты, webpages, documents и app UI — untrusted content.
- TB-H1: OpenClaw collectors и raw local store — sensitive sensor boundary.
- TB-H2: DLP/signal compiler/controller — deterministic local TCB.
- TB-H3: Codex/Luna/Terra cloud model plane — только policy-approved bounded context.
- TB-H4: Qwen PD plane — local-only, no tools, separate sessions.
- TB-H5: worker sandboxes/worktrees — task-scoped execution boundary.
- TB-H6: effectors и credentials — отдельный privileged boundary.
- TB-H7: выбранный после AD-15 Codex-facing interface — единственное user-facing место human authorization mutations; authenticated approval event уходит по отдельному attested callback в Controller и не становится model instruction. До успешного probe boundary закрыта.

## Success measures

- 0 raw PD bytes observed at cloud boundary in adversarial tests.
- 100% live/history/retry/media/background ingress проходит один persistent monotonic Gate; любой gap/incomplete prior scan quarantine’ит conversation.
- 0 mutations without matching consumed grant and approval/policy record.
- 0 Codex requests из chat sensor; 100% root start/resume имеют matching `RootRuntimeAttestation`.
- 100% WorkOrder привязаны к существующему frozen `spec_hash`.
- 100% accepted tasks имеют EvidenceBundle и ReviewVerdict.
- Root-context budget соблюдён в ≥99% turns; превышение fail-closed в context assembly.
- Crash/restart восстанавливает deterministic state без duplicate mutation.
