# DeepSeek Harness Work Orchestrator — пакет спецификации

## Карточка

| Поле | Значение |
|---|---|
| Status | `DRAFT / specification-only` |
| Stable ID | `deepseek-harness-work-orchestrator` |
| Базовая версия | 2026-08-19, Europe/Moscow |
| Целевой substrate | `VERIFIED`: DeepSeek Harness `dsh-v0.1.0-rc.7`, commit `99f6f02fecdb7dff40c3fbc9470f5907c29f74ca` |
| Зрелость substrate | `VERIFIED`: developer preview; upstream предупреждает о compatibility-breaking changes |
| Продукт/данные/security owners | `DECISION REQUIRED / DR-001 / до P0 exit` |
| Реализация | отсутствует; пакет не устанавливает DSH/плагины, не подключает аккаунты, не читает реальные данные и не разрешает effects |

## Нормативное решение

`USER DECISION / 2026-08-19`: единым рабочим интерфейсом становится DeepSeek Harness (DSH). Codex остаётся cognitive root: формирует спецификации, планы и WorkOrder, принимает bounded evidence и проверяет результат. Внешний deterministic OpenDuck Controller остаётся technical root и частью TCB: он единолично владеет ingress admission, PD routing, capability/approval consumption, effect dispatch, audit и recovery. Один интерфейс не означает один privilege domain.

Эта спецификация **наследует и не ослабляет** privacy, provenance, immutable approval, destination binding, clean-runtime, purge и fail-closed инварианты:

- [Private OpenClaw Assistant](../private-openclaw-assistant/README.md);
- [Codex-root Operations Harness](../codex-root-operations-harness/README.md).

Она явно заменяет только прежние presentation assumptions: OpenClaw и Codex Desktop больше не считаются обязательной user-facing surface. При конфликте действует более строгий существующий инвариант до датированного ADR владельцев. OpenClaw/Hermes не являются runtime dependencies целевой архитектуры; текущие безопасные OpenDuck-компоненты переиспользуются.

## Целевой охват

Система должна в одной точке:

1. фиксировать разрешённые диалоги enterprise-chat и Telegram, показывать смысл, договорённости и кандидаты ответов;
2. фиксировать подтверждённые даты демо, отображать календарь и строить график работ;
3. отслеживать изменения выбранных задач Kaiten и расхождения плана с фактом;
4. читать изменения Outlook Mail/Calendar с минимальными scopes;
5. вести разделённые Beads tasks и durable memory, переиспользуя проверенные решения;
6. оркестрировать bounded multi-task work без загрязнения root-контекста;
7. планировать и учитывать время без молчаливого юридического timesheet;
8. проводить независимое review и готовить проекты к работе в изоляции;
9. делать любые записи, отправки и provider mutations только через точное разрешение владельца.
10. читать широкий public web/Context7 без форм/загрузок/credentials/private networks и private payload; real network включается отдельно в P7 после conformance/revoke gate;
11. фиксировать consented meetings/calls локально; Qwen suggestions не выходят наружу, а DSH/tech-base получает только strict manually owner-authored exact release;
12. архивировать DSH sessions обратимо и честно показывать возможности/остатки delete/purge.

## Легенда атрибуции

- `VERIFIED` — подтверждено первичным источником или локальным evidence из [реестра](20-source-register.md).
- `USER REQUIREMENT` — прямо задано пользователем.
- `USER DECISION` — прямо выбранный пользователем архитектурный вариант.
- `PROPOSAL` — предлагаемое нормативное решение; не разрешение на реализацию или effect.
- `ASSUMPTION` — проверяемое допущение; не основание для enablement.
- `DECISION REQUIRED` — развилка с владельцем и phase gate.
- `CONFLICT` — несовместимые требования; применяется fail-closed до ADR.

## Инварианты

1. Любой chat/mail/card/web content — данные, а не инструкция агенту.
2. Каждый cloud/model-visible append path проходит snapshot-bound `CloudAdmittedPrompt`, crash-safe append receipt и final authoritative revalidation; stale/uncertain path не достигает Codex.
3. Маркер `Это ПД` и policy detection необратимо повышают class high-water и ведут по отдельному `LocalPDDispatch` во внешний Qwen + LocalPDView; этот dispatch никогда не входит в DSH seam.
4. DSH является control/work surface, но не security boundary.
5. DSH не имеет general root LLM: safe cloud admission связан максимум с одним persistent Codex turn; P5 использует только auth/network stub, real owner login/use начинается не раньше P7 после DR-020 и explicit authorization.
6. Read, propose, approve и effect — разные capabilities и credentials.
7. Beads task state, Beads memory, tech-base, Kaiten, Outlook и chat reply — разные effect types.
8. Неизвестные schema/class/source/coverage/permission/outcome трактуются fail-closed.
9. Authoritative approval UI — Controller/native trusted renderer; DSH только suggestion/launcher.
10. Реальные данные, credentials/login, public network и effects остаются выключены, пока соответствующий phase gate не закрыт фактическим evidence; privileged sidecars требуют OS-enforced denial against malicious DSH.
11. Backup hooks проектируются, но `USER DECISION`: backup не реализуется и не включается до отдельного решения.

## Состав

1. [Контекст и цели](00-context-and-goals.md)
2. [Требования](01-requirements.md)
3. [Целевая архитектура](02-target-architecture.md)
4. [Контракты и ledgers](03-contracts-and-ledgers.md)
5. [Ingress и PD](04-ingress-and-pd.md)
6. [Фиксация чатов](05-chat-capture.md)
7. [Демо, календарь и планирование](06-demo-calendar-planning.md)
8. [Kaiten](07-kaiten.md)
9. [Outlook](08-outlook.md)
10. [Beads и память](09-beads-and-memory.md)
11. [Мультитаск-оркестрация](10-multitask-orchestration.md)
12. [Учёт времени](11-time-tracking.md)
13. [Review и подготовка проектов](12-review-and-project-preparation.md)
14. [Инвентарь плагинов и sidecar](13-plugin-and-sidecar-inventory.md)
15. [Permissions, approvals и effects](14-permissions-approvals-effects.md)
16. [Command Center UX](15-command-center-ux.md)
17. [Наблюдаемость, recovery и retention](16-observability-recovery-retention.md)
18. [Roadmap и phase gates](17-roadmap.md)
19. [Acceptance и security tests](18-acceptance-tests.md)
20. [Решения, риски и конфликты](19-decisions-risks-conflicts.md)
21. [Реестр источников](20-source-register.md)
22. [Трассируемость](21-traceability.md)

## Definition of Ready

P0 начинается как synthetic specification/spike only. P1 implementation разрешается только после DR-001, выбора изолированной ветки/worktree, фиксации exact upstream digests, schema set и rollback. Любой real source, credential/raw store, Codex login/use или safe-public network требует своего P7 owner/security approval, DR-020 isolation where applicable, allowlist/retention/scope/negative egress evidence; public network additionally DR-022/live revoke. Mutation enablement всегда отдельное решение по одному effector.
