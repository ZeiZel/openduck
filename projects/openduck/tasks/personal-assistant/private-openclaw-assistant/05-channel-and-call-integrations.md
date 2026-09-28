# 05. Интеграции каналов и звонков

## Стратегия адаптеров

Точный набор платформ — `DECISION REQUIRED / Product owner / Phase 0`. Никакая поддержка не считается гарантированной только потому, что платформа названа в документации OpenClaw. Перед реализацией каждого адаптера выполняется capability probe и проверка официального API, ToS, scopes, webhook/polling, history access, edits/deletes, threads, attachments, receipts и admin consent.

Общий интерфейс:

```text
discover_capabilities(account_ref) -> CapabilityManifest
start(cursor) -> stream<InboundEvent>
backfill(cursor, bounded_window) -> stream<InboundEvent>
resolve_destination(canonical_id) -> ExactDestination | Ambiguous | Missing
send(ApprovedReply, idempotency_key) -> Delivered | Rejected | Unknown
health() -> Healthy | Degraded | Offline
revoke() -> result
```

Read credential и write credential разделяются, если платформа позволяет. Collector не импортирует dispatcher module/credential.

## CapabilityManifest и семантика доставки

Manifest versioned и содержит минимум:

```json
{
  "schema_version": "capability-manifest.v1",
  "provider_idempotency": "native",
  "delivery_reconciliation": "supported",
  "receipt_strength": "definitive"
}
```

- `provider_idempotency`: `native` — provider документирует серверную дедупликацию по ключу; `client_only` — ключ известен только OpenDuck и не гарантирует дедупликацию provider; `none` — ключ неприменим.
- `delivery_reconciliation`: `supported` — есть read-only запрос по provider message/correlation ID, позволяющий после timeout установить результат; `unsupported` — доказательно сверить доставку нельзя.
- `receipt_strength`: `definitive` — provider подтверждает окончательную доставку/отказ; `correlated` — результат связан с request, но может не означать доставку конечному пользователю; `best_effort` — transport acknowledgement; `none` — receipt отсутствует.

Action-enabled adapter разрешён только если его delivery policy прошла review: либо `native` idempotency или `supported` reconciliation позволяют контролируемую сверку, либо применяется строгий **one-attempt** режим. Для `client_only|none` вместе с `unsupported` timeout всегда даёт `UNKNOWN`, автоматический retry запрещён. Система не обещает exactly-once delivery: локальный CAS ограничивает исполнителей, но внешняя сеть/provider могут оставить outcome неоднозначным.

## Требования inbound

- Проверять webhook signature, timestamp/nonce и допустимое clock skew до parsing body.
- Отклонять replay и событие из не-allowlisted account/conversation.
- Сохранять platform event ID/version; edit/delete оформлять отдельными версиями.
- Не доверять display name, avatar, quoted metadata и embedded links.
- Ограничивать MIME, размер, число вложений; опасные типы помещать в quarantine и не рендерить автоматически.
- Polling cursor сохранять атомарно после durable enqueue, чтобы избежать потери.
- Backfill ограничен окном и rate limit; gap остаётся видимым, если API не даёт восстановить историю.

## Candidate matrix

| Платформа | VERIFIED capability basis | Проектная позиция | Gate |
|---|---|---|---|
| Telegram bot | OpenClaw имеет channel documentation; фактический bot access зависит от Bot API и chat membership | кандидат для первого MVP, только после capability probe | Bot token, allowlist, group privacy/admin policy |
| Slack | OpenClaw документирует channel ecosystem; workspace app требует scopes/admin policy | кандидат для корпоративного pilot | admin approval, scopes, retention/export policy |
| Microsoft Teams | не считать поддержанным без текущей официальной проверки конкретного adapter/provider | deferred | Microsoft app/admin/tenant policy |
| WhatsApp | интеграция может требовать linked account/provider-specific режим | **не MVP** из-за широкой trust surface и platform risk | отдельный threat review и ToS |
| iMessage | macOS-доступ может требовать UI/Full Disk Access/Automation и не даёт стабильного официального server API | **не MVP**; UI automation out of scope | отдельное явное исключение пользователем, security/legal review |
| Email | не заявлен пользователем как первый канал | deferred adapter | provider, folders/labels, OAuth scopes |

Таблица не утверждает, что каждая строка уже реализована OpenClaw или доступна текущему аккаунту.

## Выбор первого канала

`PROPOSAL`: выбрать один канал с официальным API, отдельным bot/app identity, узким read scope, стабильным event ID и test workspace. При равных условиях Telegram bot или Slack sandbox проще верифицировать, чем личный WhatsApp/iMessage. Решение фиксируется в DR-01 с владельцем и ссылкой на permission evidence.

## Режимы channel rollout

1. Synthetic/manual copy без account.
2. Read-only test account/conversation.
3. Read-only production allowlist + visible notifications.
4. Draft-only.
5. Dispatcher на одного canary peer после acceptance.
6. Расширение allowlist по одному scope с rollback.

## Звонки и транскрипция

Точные платформы звонков — `DECISION REQUIRED / Product + Legal/privacy owner / Phase 0–7`. MVP не записывает звонки.

Допустимый pipeline:

1. Пользователь выбирает **официальный transcript/recording export** платформы или локальный файл, полученный законно.
2. Consent record связывает meeting ID, участников/политику уведомления, purpose и retention.
3. Importer проверяет тип, размер, malware policy и source locator.
4. Local speech-to-text работает без network egress; network deny тестируется.
5. Speaker diarization/labels имеют confidence и не выдаются за факт при низкой уверенности.
6. Candidate summary/action items проходят human review.
7. Raw audio удаляется по отдельной retention policy; transcript не наследует автоматически более долгий срок.

Скрытая запись, обход индикаторов платформы и автоматическое включение микрофона — запрещены.

## Calendar integration

Провайдер неизвестен. Adapter должен поддерживать минимум draft/proposal representation и free/busy только если владелец разрешил. MVP не рассылает invitations и не добавляет attendees. Перед реальным create проверяются timezone, DST, recurrence, organizer, exact calendar ID и конфликт времени. Update/delete — отдельные будущие action types с отдельным threat review.

## Revocation и offboarding

Для каждого adapter документируются: кнопка/команда disable, revoke token у провайдера, удаление local token reference, остановка webhook/polling, purge queue/DLQ/index/cache по scope, сохранение минимального audit proof, проверка отсутствия новых событий. Отключение read не должно случайно оставить write credential активным.

## Conformance checklist адаптера

- canonical IDs не строятся из display names;
- allowlist действует до enqueue;
- signature/replay test проходит;
- edit/delete/version semantics известны;
- cursor recovery и rate-limit handling проверены;
- ambiguous destination fail-closed;
- idempotency/receipt semantics задокументированы;
- CapabilityManifest содержит валидные `provider_idempotency`, `delivery_reconciliation`, `receipt_strength`; action policy соответствует их комбинации;
- секреты только в Keychain/secret store, не в `.env`, docs, logs или backups;
- degraded/offline виден владельцу;
- ToS/admin/legal gate имеет evidence и owner.
