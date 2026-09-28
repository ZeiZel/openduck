# 09. Beads и долговременная память

## Разделение понятий

`USER REQUIREMENT`: вести Beads memory и сохранять выполненные решения, чтобы не искать их заново.

| Store | Что хранит | Что не хранит |
|---|---|---|
| Beads issues | durable work lifecycle, dependency, owner, status/blocker | reusable machine/project fact вместо задачи; raw transcript |
| Beads repository memory | проверенные архитектурные/project workflow facts | private machine connectivity/credential facts; transient progress |
| Beads global memory | private machine-local facts и credential-file references внутри Controller/helper boundary | private claim/value/path contents в DSH/UI/model/repo/cloud |
| Evidence store | immutable artifacts/check results/source refs | current task state или conversational summary |
| tech-base/Obsidian | owner-approved human-readable reports/decisions | canonical capability/approval/effect state |

Существующая machine policy Beads имеет приоритет: tasks принадлежат issue tracker, memory — только долговременным проверенным facts; private global values никогда не выходят в user-facing/model/repo artifacts.

## Memory lifecycle

`OBSERVED → CANDIDATE → VERIFIED → ACTIVE → STALE | SUPERSEDED | FORGOTTEN`.

Memory candidate создаётся из accepted EvidenceBundle/ReviewVerdict/owner decision, а не из одного model assertion. Stable key детерминирован по scope/domain/subject. Новое подтверждение обновляет record in place или создаёт conflict/supersedes relation; дубликаты не накапливаются.

## Write policy

Controller формирует `MemoryOperation` (`remember|update|forget`) с exact scope/key/claim/provenance/sensitivity. Для private global store наружу возвращается только `PrivateMemoryRef`: stable-key hash/kind/freshness/sensitivity/conflict metadata без claim/value/path/credential-ref content. До real private access DR-020 требует isolated helper principal/path/DB ACL that denies malicious DSH reads; process/ref alone insufficient. Scoped Beads helper:

- не принимает произвольный shell command;
- не читает/выводит private value в DSH;
- запрещает literal credential material;
- проверяет target repo/global store;
- возвращает metadata-only receipt/digest;
- выполняется только по matching policy/approval.

## Reuse workflow

Перед существенным исследованием или реализацией orchestrator:

1. определяет target repository/domain и search keys;
2. получает Controller-sanitized memory index/results;
3. проверяет freshness, source/evidence и conflict;
4. помечает result `reused`, `needs_revalidation` или `not_applicable`;
5. передаёт Codex bounded `MemoryCapsule` только для отдельно разрешённого sanitized non-private fact; `PrivateMemoryRef` не разворачивается в DSH/model;
6. после работы предлагает new/update/forget candidates.

Memory никогда не отменяет live capability probe для volatile version/auth/network/provider behavior.

## Tech-base integration

Первый `openduck-techbase-writer` делает только exclusive create-new (`O_CREAT|O_EXCL` equivalent) approved note/report в configured Inbox/path root, с frontmatter provenance, source links, AI-generated marker and retention. Для PD/meeting source он принимает только strict manually owner-authored exact bytes, matching consumed `DeclassificationDecision`/post-scan и отдельный create-effect approval; Qwen/MeetingDigest-derived candidate отвергается. Любая collision требует нового filename/owner decision; update, overwrite, purge and bulk delete deferred до отдельного ADR/implementation. Directory traversal и symlink escape запрещены. Obsidian MCP может быть read-only helper, но DSH не parent’ит private MCP, а write остаётся отдельным effector.

## Retention and search

- sensitive claims индексируются локально; embeddings/cloud search запрещены без решения;
- search results соблюдают caller scope/classification;
- `review_after` создаёт stale queue;
- forget purges materialized indexes/caches and writes tombstone/audit, не скрывая факт authorized deletion;
- future backup inventory учитывает memory, но backup сейчас disabled.

## UX

Memory panel показывает non-private stable key, scope, claim, provenance, last verified, review date, sensitivity, conflicts and consumers. Для private global record видны только поля `PrivateMemoryRef`; claim/value отсутствуют даже в DOM/network response. Owner может accept/edit/reject/stale/forget через trusted Controller operation; default auto-write отсутствует.
