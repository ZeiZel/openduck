# Codex-root Operations Harness — пакет спецификации

## Карточка

| Поле | Значение |
|---|---|
| Status | `DRAFT / specification-only` |
| Stable ID | `codex-root-operations-harness` |
| Дата базовой версии | 2026-08-12, Europe/Moscow |
| Владелец продукта и данных | `USER REQUIREMENT`: пользователь-владелец; делегирование роли оформляется отдельным решением |
| Технический владелец | `DECISION REQUIRED / Product owner / до Phase H0` |
| Security/privacy approver | `DECISION REQUIRED / Product owner / до реальных данных или mutations` |
| Реализация | пакет не включает установку, подключение аккаунтов, выдачу credentials или включение mutations |

## Нормативное назначение

`USER REQUIREMENT / USER DECISION 2026-08-12`: построить personal-operations harness с одним **Codex-facing interface**. Codex является cognitive root и единственной user-facing orchestration surface: через выбранный Codex-facing client owner получает suggestions, status, approval requests и exact action previews. OpenClaw только наблюдает разрешённые чаты и производит task-context signals; Luna быстро отвечает на частые ограниченные вопросы и выполняет bounded exploration; отдельный native Codex implementer выполняет утверждённые WorkOrder; Terra независимо проверяет результат; Qwen локально обрабатывает сессии, явно помеченные `Это ПД`. Пользователю не требуется отдельный sensor или worker UI. Root-контекст должен оставаться свободным от сырых переписок, логов и промежуточной работы.

`DECISION REQUIRED / Technical + Security / H0`: delivery mechanism для единого interface не считается доступным. Preferred `PROPOSAL` — personal Codex plugin с Controller MCP и MCP Apps custom UI, но только после pinned live probe, доказывающего, что **target Codex desktop build** действительно рендерит UI и поддерживает secure authenticated callback в Controller. Fallback — отдельный custom local Codex client на app-server; это новый client/UI, а не существующий desktop task UI. Если ни один вариант не проходит boundary tests, owner interaction и mutation enablement остаются `BLOCKED`.

`USER REQUIREMENT`: harness в перспективе получает широкий доступ к read/write/browser/app операциям, но никакая unattended mutation не следует из широты доступа. Каждая mutation проходит детерминированную capability-проверку и, если не покрыта заранее утверждённой узкой политикой, точное owner approval.

`USER DECISION 2026-08-12`: Codex является **когнитивным root**, а локальный deterministic Harness Controller — **техническим root и частью TCB**. Модель формулирует intent/specification и принимает evidence; Controller вне probabilistic model владеет очередями, lifecycle, capability enforcement, approval consumption, audit и process supervision. Один UI не означает ambient authority: UI доставляет решение owner, но не создаёт grant и не исполняет effect сам по себе.

Пакет расширяет, но не ослабляет [Private OpenClaw Assistant](../private-openclaw-assistant/README.md). При конфликте privacy, immutable approval, destination binding, purge или delivery semantics более строгий существующий инвариант сохраняется до явного ADR владельцев.

## Инварианты

1. Недоверенный чат является данными, а не инструкцией для Codex или worker.
2. Единственный ingress PD gate обрабатывает webhook, polling, history/backfill, retry, attachments, transcripts, parsers и background jobs до любого parse/model/tool/cloud/Codex route; gap или неполная prior scan означает quarantine.
3. Codex author/freeze/acceptance proposals не дают ему credential, canonical state-transition authority или право совершить effect.
4. Worker получает frozen `TaskSpec` через `WorkOrder`, не меняет scope и возвращает typed evidence.
5. Authority хранится в versioned records и hashes, а не в chat transcript или model memory.
6. Root получает bounded artifacts и summaries; raw logs остаются в evidence plane.
7. Unknown schema, class, destination, permission, delivery outcome или policy state трактуется fail-closed.
8. Chat-facing OpenClaw sensor имеет `tools deny all`; только authenticated Controller transport с nonforgeable request ID может создать Codex request.
9. Root Codex запускается из generated clean home/profile с explicit allowlists и attested effective configuration; global/user additions не наследуются.
10. Все owner-facing suggestions/status/approvals/action previews проходят через выбранный и attested Codex-facing interface; authorization остаётся exact-record operation Controller, а не полномочием root, UI transport или transcript.

## Состав

1. [Контекст, цели и границы](00-context-and-goals.md)
2. [Функциональные и нефункциональные требования](01-requirements.md)
3. [Архитектура и потоки](02-architecture.md)
4. [Версионированные контракты](03-contracts.md)
5. [Root context hygiene и subprompting](04-context-and-subprompting.md)
6. [Роли и маршрутизация](05-agent-roles-and-routing.md)
7. [Мониторинг чатов и быстрые ответы](06-chat-monitoring-and-fast-answers.md)
8. [PD sticky mode и declassification](07-pd-routing-and-declassification.md)
9. [Capabilities, approvals и effects](08-capabilities-approvals-and-effects.md)
10. [MCP, utilities и installation plan](09-mcp-utilities-inventory.md)
11. [Memory, tech-base и задачи](10-memory-techbase-and-tasks.md)
12. [Observability, recovery и lifecycle](11-observability-recovery-lifecycle.md)
13. [Roadmap](12-roadmap.md)
14. [Acceptance и security tests](13-acceptance-and-security-tests.md)
15. [Решения, конфликты и риски](14-decisions-risks-conflicts.md)
16. [Реестр источников](15-source-register.md)
17. [Трассируемость](16-traceability.md)

## Легенда атрибуции

- `VERIFIED` — подтверждено source register или локальным evidence с датой.
- `USER REQUIREMENT` — прямо задано пользователем.
- `PROPOSAL` — предлагаемое нормативное решение, требующее принятия.
- `ASSUMPTION` — проверяемое допущение; не основание для enablement.
- `DECISION REQUIRED` — развилка с владельцем и фазой.
- `CONFLICT` — требования несовместимы без явного решения.

## Definition of Ready

Implementation начинается после закрытия всех unresolved AD, включая AD-15 UI delivery feasibility, назначения owners, заморозки schemas, выбора первого synthetic workflow, capability matrix и rollback. Зафиксированные пользовательские решения AD-05 и AD-14 не переоткрываются без нового owner decision; они не предрешают механизм AD-15. Real chat enablement дополнительно требует выполнения gates исходного пакета; mutation enablement — отдельного Phase H5 exit.
