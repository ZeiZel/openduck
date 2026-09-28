# 01. Продуктовые требования

## Функциональные требования

### Наблюдение и уведомления

| ID | Требование | Приоритет |
|---|---|---|
| FR-001 | Владелец явно добавляет channel/account/conversation в allowlist; всё остальное не читается | Must |
| FR-002 | Collector сохраняет source event ID, channel, conversation, sender, timestamp и доступный locator | Must |
| FR-003 | Повторно полученное событие дедуплицируется без потери обновлённой версии | Must |
| FR-004 | Watcher присваивает приоритет с объяснимыми сигналами и показывает `uncertain`, если уверенности мало | Must |
| FR-005 | Уведомление содержит кто, где, когда, краткий смысл, приоритет, режим обработки и gap/staleness | Must |
| FR-006 | Владелец может mute/snooze отдельный peer/thread без отключения аудита | Should |

### Черновики и ответы

| ID | Требование | Приоритет |
|---|---|---|
| FR-010 | Черновик строится только из разрешённого окна текущей per-channel-peer session | Must |
| FR-011 | В облако передаётся только safe envelope, прошедший policy gate | Must |
| FR-012 | Владелец может запросить переписать, ответить иначе, сохранить без отправки или отклонить | Must |
| FR-013 | Preview показывает exact channel/account/conversation/recipient/body/attachments | Must |
| FR-014 | Любое изменение preview инвалидирует ранее выданное подтверждение | Must |
| FR-015 | Dispatcher не имеет доступа к генерации и принимает только approved immutable action | Must |
| FR-016 | Перед повторной отправкой сверяются idempotency key и delivery receipt | Must |

### Отчёты и долговременная память

| ID | Требование | Приоритет |
|---|---|---|
| FR-020 | По завершению диалога/созвона система создаёт draft summary с provenance и пометкой AI-generated | Must |
| FR-021 | Договорённости, обещания, решения, задачи и события сначала создаются как candidates | Must |
| FR-022 | Candidate содержит source locator, bounded excerpt, автора, source timestamp, confidence и status | Must |
| FR-023 | Дедлайн создаётся только при явной дате/времени в источнике или явном вводе владельца | Must |
| FR-024 | Принятие agreement, task, calendar event и reply требует отдельных approval records | Must |
| FR-025 | Tech-base writer пишет только в выделенный Inbox и не редактирует существующие страницы | Must |
| FR-026 | Calendar writer создаёт только proposal/draft до подтверждения; update/delete вне MVP | Must |

### Созвоны

| ID | Требование | Приоритет |
|---|---|---|
| FR-030 | Запись/импорт начинается только после consent gate и выбора разрешённого источника | Must |
| FR-031 | Транскрипция по умолчанию локальна; исходное аудио не уходит в облако | Must |
| FR-032 | Неуверенные speaker labels и timestamps явно помечаются | Must |
| FR-033 | Raw audio и transcript имеют отдельные retention/classification | Must |

## Нефункциональные требования

- **NFR-001 Security:** fail-closed при недоступном DLP, policy store, approval registry или неоднозначном destination.
- **NFR-002 Privacy:** raw L2/L3 не покидают local trust boundary по умолчанию.
- **NFR-003 Availability:** очередь переживает restart; sleep/offline gap отображается и восстанавливается в пределах возможностей API.
- **NFR-004 Integrity:** event/action records версионируются, хешируются и защищаются от частичной записи.
- **NFR-005 Auditability:** каждое внешнее действие трассируется approval→payload hash→attempt→receipt без raw body в operational log.
- **NFR-006 Performance:** Phase 1 измеряет p50/p95 на целевой машине; лимиты моделей и очередей конфигурируются по результатам.
- **NFR-007 Maintainability:** адаптеры реализуют общие versioned contracts, conformance tests и независимые capability scopes.
- **NFR-008 Accessibility:** approval preview пригоден для чтения, копирования и однозначной проверки адресата.
- **NFR-009 Localization:** русский — основной язык UX; исходный язык сообщения сохраняется как метаданные.

## Product modes

1. **Stopped:** ingest и actions выключены.
2. **Shadow/manual copy:** пользователь вручную подаёт текст; внешние аккаунты не подключены.
3. **Read-only:** collector читает allowlisted source, уведомляет, но dispatcher/writers отключены.
4. **Draft-only:** формируются drafts/candidates, но внешние mutations выключены.
5. **Approval-enabled:** разрешены только точно утверждённые action types.
6. **Degraded-local:** cloud выключен; допустимы локальные уведомления/локальные drafts с маркировкой.

Переход режима — audited configuration change. Более разрешительный режим требует прохождения phase exit; автоматическое повышение режима запрещено.

## UX-инварианты

- На каждом preview видны источник и классификация.
- `Approve` и `Edit` — разные действия; после edit требуется новое approve.
- «Ответить ему» без однозначного resolved recipient не исполняется.
- Истёкший approval нельзя «продлить» без нового показа payload.
- Облачный draft помечен как обработанный облаком; local-only/denied причины видны владельцу.
- Отсутствие сообщений во время offline не отображается как «новых сообщений нет».

## Success criteria MVP

MVP завершён, когда один одобренный канал работает в read-only shadow/draft режиме, egress по умолчанию запрещён, synthetic L2/L3 не утекают, уведомления и кандидаты имеют provenance, а ни один тест не может вызвать dispatcher/tech-base/calendar mutation без валидного approval. Полный список — [11-verification-and-acceptance.md](11-verification-and-acceptance.md).
