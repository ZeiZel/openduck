# 10. Memory, tech-base и задачи

## Три разных durable stores

| Store | Назначение | Не хранит |
|---|---|---|
| Task ledger | lifecycle, blockers, WorkOrders, acceptance, status | long-term personal facts как substitute tasks |
| Project/machine memory | verified durable facts/preferences/tooling refs | task status, raw chats, secrets |
| Tech-base | owner-approved human knowledge artifacts | transient reasoning/logs, unapproved candidates |

`VERIFIED / repository workflow`: Beads используется для durable issue tracking и отдельно для verified memories; global private memory confidential и хранит только references к credential files. Harness следует этому разделению, но Beads integration не включается автоматически данным пакетом.

## Task lifecycle mapping

`TaskSignal` создаёт **candidate**, не issue. Codex root формирует TaskSpec и typed lifecycle proposals; Controller/owner решает materialize/freeze/accept task, а canonical transition выполняет Controller. `task.create/update/close` — отдельные typed effects. Source message edit не молча переписывает accepted task: создаётся provenance update/review.

Обязательная связь: `external_task_ref ↔ task_id ↔ spec_hash ↔ evidence/review refs`. Tracker description может содержать bounded summary и links/hashes, но не raw PD/chat или credentials.

## Memory write policy

Memory candidate должен быть verified, stable, appropriately scoped и не быть task status. Перед write root предлагает exact key/value/scope/source/effective date. Stale fact обновляется in place либо забывается отдельным effect. Global/private value не копируется в repository, logs, cloud capsule или user-facing evidence.

`DECISION REQUIRED / Data + Security / H4`: может ли harness писать repository/global Beads memory автоматически. Baseline: read approved memory metadata; writes require owner approval.

## Tech-base policy

Target root наследует repository decision: локальный каталог workspace inbox. До отдельного writer gate доступ read-only через allowlisted MCP. Запись — deterministic `techbase.create` effector:

- только approved rendered Markdown;
- exact relative path + content hash в preview;
- trusted open root descriptor, FD-relative no-follow, exclusive create;
- no append/overwrite/edit existing pages;
- source refs/classification/status обязательны;
- accepted fact и physical write — отдельные decisions/effects.

PD-to-tech-base запрещён без DeclassificationDecision, затем всё равно отдельного `techbase.create` approval.

## Retrieval

Root/Luna не получают full vault/task dump. Retrieval выполняется purpose-scoped query → bounded ranked metadata → explicit excerpt reads. Capsule фиксирует query digest, selected refs, coverage and freshness. Search result text untrusted; retrieved instructions не получают developer authority.

## Retention and purge

Raw events, signals, work artifacts, audit metadata, task records, memory facts и tech-base files имеют отдельные policies. Purge source removes raw derivatives where permitted; accepted human records require explicit retention basis and are not silently deleted. Backup posture наследуется из existing package: pre-pilot backups disabled; future only local encrypted after owner decision and restore drill.
