# Private OpenClaw Assistant — пакет спецификации

## Карточка

| Поле | Значение |
|---|---|
| Status | `DRAFT / specification-only` |
| Владелец продукта и данных | `DECISION REQUIRED` — назначает пользователь до Phase 0 exit; временно решения принимает пользователь-заказчик |
| Технический владелец | `DECISION REQUIRED` — назначает владелец продукта до Phase 1 |
| Security/privacy approver | `DECISION REQUIRED` — назначает владелец продукта до любого подключения реальных данных |
| Дата базовой версии | 2026-08-12, Europe/Moscow |
| Целевая машина | `USER REQUIREMENT`: MacBook Pro Mac17,2, Apple M5, 24 GB RAM |
| Реализация | отсутствует; этот каталог не устанавливает ПО и не подключает аккаунты |

## Назначение

`USER REQUIREMENT`: спроектировать персонального privacy-first ассистента на базе OpenClaw, локальной модели и Codex/OpenAI. Он наблюдает только разрешённые коммуникации, быстро сообщает кто и что написал, приоритизирует, предлагает ответ и запрашивает подтверждение владельца. Он также готовит отчёты по чатам и созвонам, извлекает кандидаты договорённостей и задач, предлагает события календаря и сохраняет утверждённые записи в tech-base.

Ключевой инвариант: ассистент **не отправляет сообщения и не совершает другие внешние или долговременные действия без точного, действующего подтверждения**. Локальная LLM помогает классифицировать и редактировать данные, но не является границей безопасности: авторитетны детерминированные правила, политики и approval registry.

## Scope

В scope входят: адаптеры разрешённых каналов и звонков; read-only ingest; очередь и дедупликация; локальная DLP/policy-проверка; локальная транскрипция; псевдонимизация; безопасный облачный envelope; создание черновиков; подтверждения; строго ограниченная отправка; кандидаты фактов/договорённостей/задач/событий; запись только в Inbox tech-base; наблюдаемость, восстановление и тесты.

Не входят: произвольная UI-автоматизация аккаунтов без API; скрытая запись звонков; автономные необратимые действия; чтение всех файлов Mac; гарантированное покрытие всех личных чатов; обход ToS, администраторских политик или системных разрешений; самостоятельное юридическое определение допустимости обработки.

## Навигация

Комплект спецификации: 16 Markdown-файлов (`README.md` и нумерованные документы `00`–`14`).

1. [Контекст и цели](00-context-and-goals.md)
2. [Продуктовые требования](01-product-requirements.md)
3. [Системная архитектура](02-system-architecture.md)
4. [Security, privacy и threat model](03-security-privacy-threat-model.md)
5. [Классификация данных и egress policy](04-data-classification-egress-policy.md)
6. [Интеграции каналов и звонков](05-channel-and-call-integrations.md)
7. [Workflow и approval gates](06-workflows-and-approval-gates.md)
8. [Контракты tech-base, календаря и сущностей](07-tech-base-calendar-data-contracts.md)
9. [Локальная модель и облачная маршрутизация](08-local-model-and-cloud-routing.md)
10. [Наблюдаемость, эксплуатация и восстановление](09-observability-operations-recovery.md)
11. [Roadmap и work breakdown](10-implementation-roadmap.md)
12. [Верификация и acceptance](11-verification-and-acceptance.md)
13. [Решения, риски и открытые вопросы](12-decisions-risks-open-questions.md)
14. [Реестр источников](13-source-register.md)
15. [Трассируемость требований](14-requirements-traceability.md)

## Легенда атрибуции

- `VERIFIED` — подтверждено первичным официальным источником из [реестра](13-source-register.md), с датой проверки.
- `USER REQUIREMENT` — прямо задано заказчиком в текущем диалоге.
- `PROPOSAL` — предлагаемое проектное решение, ещё не принятое владельцем.
- `ASSUMPTION` — рабочее допущение, которое надо проверить.
- `DECISION REQUIRED` — развилка с владельцем и сроком принятия.
- `CONFLICT` — несовместимые требования/источники; нельзя молча разрешать.

## Evidence, assumptions, decisions

- `VERIFIED`: OpenClaw документирует каналы, сессии, hooks/automation, Markdown-memory, локальный Ollama и OpenAI/Codex provider; конкретная пригодность и разрешения каждого канала проверяются отдельно перед подключением.
- `VERIFIED`: OpenClaw позиционирует gateway как personal-assistant trust boundary, не как hostile multi-tenant boundary. Поэтому один gateway обслуживает только одного доверенного владельца.
- `USER REQUIREMENT`: никакой автоотправки без неизменяемого approval gate.
- `ASSUMPTION`: tech-base имеет Markdown/Obsidian-compatible адаптер. До подтверждения допустима только тестовая директория Inbox с синтетическими данными.
- `ASSUMPTION`: модель класса 4–9B подходит для локальной классификации, извлечения и псевдонимизации на целевой машине; это подтверждается benchmark на Phase 1, а не названием модели.
- `USER DECISION (2026-08-12)`: на pre-pilot synthetic/local этапе backup отключён; backup-копии не создаются. Будущая реализация допускается только как local encrypted backup после отдельного owner approval, с retention, раздельностью ключей, RPO/RTO и outbound-disabled restore drill. Cloud backup не является default.
- `DECISION REQUIRED / Product owner / до Phase 1`: первый канал, tech-base, календарь, звонки, retention и облачный auth/data-control режим.
- `CONFLICT`: желание постоянного мониторинга конфликтует со sleep/offline режимом ноутбука. Система обязана честно показывать gap и не обещать 24/7 без always-on узла.

## Definition of Ready для реализации

Работа над реальными интеграциями начинается только после: назначения владельцев; утверждения первых платформ и их ToS; определения запрещённых типов данных; выбора облачного режима; утверждения retention; выбора изолированного runtime; получения evidence минимального host security baseline; фиксации rollback; успешного synthetic security test. Актуальная [матрица трассируемости](14-requirements-traceability.md) является обязательным phase-exit artifact. Подробные gates — в [roadmap](10-implementation-roadmap.md).
