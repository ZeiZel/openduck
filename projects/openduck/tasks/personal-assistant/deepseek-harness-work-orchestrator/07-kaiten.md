# 07. Kaiten

## Capability status

`USER REQUIREMENT`: отслеживать изменения выбранных задач Kaiten и строить график работ.

`VERIFIED / official docs`: Kaiten REST API предоставляет чтение карточек, location history, comments, blockers, time logs and audit-related resources; external webhooks документируют add/update/remove для ряда entities. Это не гарантирует все events/fields/ordering конкретного account: фактическое coverage задаёт versioned live-probed `CapabilityManifest`. API uses bearer auth/rate limits. Local MCP/config/account не считается доступным до probe.

## Reader design

`openduck-kaiten-reader` — отдельный process/credential:

- allowlist company/space/board/card IDs и fields;
- initial bounded snapshot;
- webhook ingest, если approved endpoint возможен;
- polling reconciliation по `updated_after`/resource revisions как recovery;
- normalized `TaskChange` с old/new digests;
- cursor/checkpoint, 429/backoff и gap state;
- no POST/PATCH/DELETE credential or generic request tool.

Ни webhook docs, ни polling filter не дают автоматическое `complete`: manifest перечисляет supported event kinds/fields/history, reconciliation interval and known gaps. Неподдержанный kind/field получает `unknown`; webhook + bounded snapshot доказывают только заявленную область.

Если используется внешний task-tracker MCP, Controller оборачивает только утверждённые read methods и проверяет schemas; DSH/Codex не получает raw MCP/credential. Real token/cache запрещены до DR-020 evidence, что isolated reader principal/container and Keychain/path ACL deny malicious DSH reads; отдельный process/ref этого не доказывает.

## Watched task model

`WatchRule` задаёт space/board/card/filter, allowed fields, polling interval, freshness SLO и destinations. Watched fields baseline: title, status/column/lane, owner/responsible, due date, blockers, checklist progress, estimate/size, update timestamp и approved custom properties. Comments/files остаются отдельным sensitivity decision.

## Reconciliation

`TaskLink` связывает Kaiten card с `WorkItem`, Beads issue и WorkOrder. Field ownership фиксируется явно:

- provider-owned: Kaiten external revision/status, author and location history;
- Controller-owned: spec hash, dispatch state, evidence, forecast;
- owner-decided: mapping, plan baseline, intended Kaiten mutation.

UI не скрывает:

- unlinked cards/work items;
- external move/due-date/owner change;
- stale/missing webhook and polling gaps;
- conflict between frozen WorkOrder and changed card;
- blocked/overdue/critical-path impact.

## Writer boundary

Create/update/move/comment/time-log/delete — отдельные effect types и, при включении, разные allowlists. Baseline P0–P7 — read-only. Writer использует отдельный token/process и exact provider revision precondition, показывает JSON-level diff and card destination, никогда не принимает свободный URL/HTTP method от модели.

## Rate/replay behavior

Webhook payload не считается полным authoritative snapshot; он триггерит normalized event и при необходимости bounded GET. Duplicate webhooks дедуплицируются; out-of-order сравнивается с revision/timestamp и reconcile snapshot. Rate-limit reset/backoff видим в health, а потерянный cursor переводит scope в gap до full rescan.
