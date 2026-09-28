# 09. Наблюдаемость, эксплуатация и восстановление

## Health model

Каждый компонент публикует `healthy | degraded | offline | blocked` и `last_success_at`, queue lag, cursor age, policy/model version. Общий статус не может быть `healthy`, если источник offline, backlog превышает threshold или есть unreconciled `UNKNOWN` action.

Dashboard/notification показывает:

- channel connection и allowlist scope;
- last inbound event/poll/webhook verify;
- queue depth/oldest age/DLQ count;
- DLP/policy availability и deny/ask counts;
- local model loaded/latency/OOM;
- cloud availability, errors, cost/token counts без content;
- pending/expired/UNKNOWN approvals/actions;
- tech-base/calendar writer health;
- disk usage, backup age, restore-test age; when backups are disabled, expose explicit `disabled`
  status instead of a misleading age;
- sleep/offline gap и backfill status.

## SLO proposals

`PROPOSAL`, уточняется после baseline:

- Ingest при доступном API: 99% accepted source events durable enqueue ≤30 с.
- Notification: p95 enqueue→owner notification ≤60 с.
- Approval dispatch: p95 approve→attempt ≤10 с при healthy provider.
- No unauthorized mutation: 100%.
- Recovery: RPO ≤15 мин для config/approval/audit metadata; RTO ≤2 ч. Raw content RPO определяется retention/backup decision.

## Логи и метрики

Логи структурированы и redacted by construction. Payload body не передаётся logger API. Используются pseudonymous refs, digest, byte counts, class, decision/rule IDs, timings и category errors. Stack trace проходит redaction. Metrics labels не содержат recipient/conversation names и не допускают unbounded cardinality.

Audit transitions append-only: config change, allowlist change, egress decision, preview hash, approval, CAS, provider attempt/result, writer outcome, purge/restore. Отдельный integrity mechanism (hash chain или signed checkpoints) — `DECISION REQUIRED / Security owner / Phase 8`.

## Очереди, DLQ и retention

- At-least-once ingest + deterministic dedup.
- Lease/visibility timeout, bounded exponential backoff + jitter.
- Permanent validation/policy errors не ретраятся; уходят в redacted DLQ metadata.
- DLQ raw payload не хранится по умолчанию; если нужен encrypted payload для recovery, он наследует класс/retention.
- Queue/DLQ/index/cache purge входит в deletion workflow.
- Backpressure останавливает attachment processing раньше core text ingest и сигнализирует владельцу.

## Sleep/offline behavior

На sleep/shutdown service записывает cursor/checkpoint best-effort. После wake:

1. помечает интервал `coverage_gap`;
2. проверяет clock/timezone changes;
3. восстанавливает leases;
4. выполняет bounded backfill по platform cursor;
5. дедуплицирует;
6. закрывает gap только если API доказал полноту, иначе сохраняет `unrecoverable/unknown`.

Нельзя сообщать «всё просмотрено», если platform API не позволил backfill. Для настоящего 24/7 нужен `DECISION REQUIRED / Product owner / Pilot`: always-on отдельный узел с новой threat model.

## Outage behavior

| Сбой | Поведение |
|---|---|
| Channel API down | queue не получает события; health degraded, gap marker, backoff |
| Local model down | deterministic-only + manual drafts; no raw cloud fallback |
| DLP/policy down | cloud/actions blocked; encrypted local queue bounded |
| Cloud down/denied | inbound и local processing продолжаются; no provider switch |
| Approval DB down | все mutations blocked |
| Tech-base/calendar down | approved action остаётся pending/failed по semantics; не писать в другой destination |
| Send timeout | `UNKNOWN`, reconcile before any retry |
| Disk nearly full | stop attachments/transcription, alert; не удалять audit молча |

## Backup и restore

**USER DECISION (2026-08-12):** на текущем synthetic/local этапе резервное копирование не
выполняется. `backups.enabled=false`; backup-копии не создаются, не отправляются в cloud и не
подключаются к runtime. Потеря synthetic/local state в pre-pilot режиме принята как допустимое
ограничение. Это решение не является доказательством наличия шифрования диска или backup-
восстановления.

Будущая capability резервного копирования зарезервирована как **local encrypted backup only**;
её реализация отложена до отдельного owner approval и Phase 8. Никаких cloud-backup defaults не
добавляется.

**FUTURE PROPOSAL (Phase 8):** backup scope минимален: config без secrets, encrypted state DB,
approval/audit metadata, policy versions, tech-base Inbox согласно его собственной стратегии.
Credentials, plaintext secrets, model caches и raw L3 не включаются. Pseudonym map backup —
отдельный encrypted decision.

До реализации backup scope/retention/RPO/RTO остаются proposal. Перед включением owner обязан
утвердить retention, шифрование, раздельность ключей от live state, outbound-disabled restore
drill и evidence результата. Restore drill не должен отправлять сообщения, исполнять actions или
подключать cloud; восстановленные `CONSUMING` становятся `UNKNOWN`, а `APPROVED` требуют ручной
повторной проверки.

Restore runbook:

1. Запустить в isolated **outbound-disabled** mode.
2. Проверить integrity/schema/migrations и policy versions.
3. Все `CONSUMING` восстановить как `UNKNOWN`, все unexpired `APPROVED` не исполнять до ручного revalidation.
4. Сверить receipts/cursors read-only.
5. Проверить allowlist и credential references; секреты подключить отдельно.
6. Прогнать synthetic smoke/security tests.
7. Только затем вручную включить inbound; mutations — отдельным gate.

Restore никогда сам не отправляет queued messages.

## Purge

Purge job перечисляет primary records и derived copies: queue, draft store, transcript/audio, full-text/vector indexes, embeddings, prompt/model caches, quarantine, DLQ и backup expiry ledger. Он выдаёт signed/hashed manifest с counts, не raw content. Immutable/offline backups помечаются pending expiry. Provider-side deletion вызывается только при наличии официального API/receipt; иначе limitation сообщается владельцу.

## Runbooks

Обязательны до Pilot: start/stop/status; revoke one/all adapters; rotate credential reference; egress/mutations kill switch; drain queue; reconcile UNKNOWN; recover cursor; handle disk pressure; restore; purge subject/source; rollback dependency/model; lost/stolen Mac; suspected exfiltration. Каждый runbook тестируется на synthetic environment и имеет owner/escalation.
