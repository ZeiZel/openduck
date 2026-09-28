# 07. Контракты tech-base, календаря и сущностей

## Общий provenance contract

```json
{
  "schema_version": "provenance.v1",
  "source": {
    "adapter_id": "string",
    "account_ref": "pseudonymous-string",
    "conversation_ref": "pseudonymous-string",
    "source_event_id": "string",
    "source_version": "string",
    "locator": "provider-specific-local-safe-locator",
    "author_ref": "pseudonymous-string",
    "authored_at": "RFC3339 timestamp"
  },
  "excerpt": {
    "text": "bounded local excerpt",
    "start_offset": 0,
    "end_offset": 120,
    "content_digest": "sha256:..."
  }
}
```

`excerpt` локален и наследует класс source. Operational audit хранит digest/offset, а не text. Locator не должен содержать token или raw query.

## Candidate contract

```json
{
  "schema_version": "candidate.v1",
  "candidate_id": "cand_...",
  "type": "agreement",
  "subject": "Псевдонимизированное или локальное описание",
  "responsible_party_ref": "P-4F91AC",
  "due_at": null,
  "due_source_expression": "на следующей неделе",
  "confidence": 0.74,
  "status": "needs_clarification",
  "provenance_ref": "prov_...",
  "extractor": {"kind": "local_model", "model_ref": "recorded-version"},
  "created_at": "RFC3339 timestamp"
}
```

Допустимые transitions: `proposed → accepted|rejected|needs_clarification`; `needs_clarification → proposed|rejected`; `accepted → superseded` только новой attributed записью. Изменение смысловых полей создаёт новую version и требует повторного acceptance.

### Правило дат

`due_at` допускается только если:

1. источник содержит явную дату/время, которые однозначно нормализованы вместе с timezone и сохранённой source expression; или
2. владелец явно ввёл/подтвердил exact дату в preview.

День недели без даты, «завтра» при неизвестном source timezone, «к концу недели», «как можно скорее» — `due_at: null` и clarification. Даже высокая model confidence не отменяет правило.

## Tech-base adapter

`ASSUMPTION`: первая tech-base — Markdown/Obsidian-compatible filesystem. Это не подтверждено. Adapter interface обязан позволять Notion/другой backend после decision gate.

Минимальный filesystem contract:

- configured root выбирается владельцем и не равен всему домашнему каталогу;
- write root жёстко ограничен `<tech-base>/Inbox/OpenDuck/`;
- trusted Inbox root открывается один раз после configuration/ownership/permission verification; все последующие операции FD-relative к этому descriptor;
- каждый path component открывается с no-follow semantics и проверкой типа/owner/mode; разрешены только generated relative names без `..`, absolute path и control chars;
- запрещён check-then-open по строковому path: предварительный `stat/realpath` не является authorization;
- target создаётся exclusive atomic create-new (`O_CREAT|O_EXCL` или безопасный platform equivalent) через trusted root descriptor; existing target никогда не открывается для записи;
- после create writer сверяет inode/device и canonical containment открытого handle с trusted root, затем пишет, `fsync`-ит и атомарно завершает; mismatch/rename/symlink race удаляет только собственный незавершённый inode и fail-closed;
- writer не имеет recursive read vault; overwrite, append, rename existing и следование symlink запрещены в MVP;
- имя: `YYYY-MM-DD-HHMMSS-<candidate-id>.md`, timezone фиксируется config;
- content содержит YAML frontmatter + human-readable body + provenance locator/digest;
- attachments не копируются по умолчанию.

Пример preview (не фактическая запись):

```markdown
---
schema: openduck-inbox-v1
id: cand_example
status: accepted
captured_at: 2026-08-12T12:00:00+03:00
source_locator: local-safe-reference
source_digest: sha256:example
---

# Договорённость: краткое описание

- Ответственный: P-4F91AC (локально отображается реальное имя)
- Срок: требует уточнения
- Источник: сообщение, 2026-08-12 11:42 MSK
```

Реальное имя может отображаться только в local preview/render согласно классификации; cloud draft не rehydrate его.

## Calendar proposal contract

```json
{
  "schema_version": "calendar-proposal.v1",
  "proposal_id": "calp_...",
  "calendar_id": "canonical-calendar-id",
  "title": "string",
  "description": "string",
  "start": "RFC3339",
  "end": "RFC3339",
  "timezone": "IANA timezone",
  "location": null,
  "attendee_ids": [],
  "reminders": [],
  "source_refs": ["prov_..."],
  "status": "draft"
}
```

Требования: `end > start`; timezone обязательна; recurrence запрещена в MVP; attendee list пуст до отдельного future approval; description не содержит raw transcript; exact calendar ID виден в preview. Calendar writer proposal-only. Если provider не имеет draft semantics, local proposal остаётся local и в календарь не пишется до отдельного согласованного action design.

## Summary/report contract

Отчёт хранит: scope и временной диапазон; участников (local references); темы; подтверждённые решения; принятые и отклонённые candidates; открытые вопросы; source coverage и gaps; generated-by/model/policy versions; human reviewer/status. Неутверждённая model inference маркируется как inference. Summary не повышает provenance level и не удаляет необходимость source access.

## Schema evolution

- Semantic version для contracts; неизвестная major version отклоняется.
- Migration работает на копии, делает backup и dry-run report.
- Hash/approval всегда привязаны к schema version.
- Удалённое поле не интерпретируется новым смыслом.
- Golden fixtures и backward-compat tests обязательны до rollout.

## Deletion/purge contract

Purge по source/subject охватывает primary store, derived drafts, search indexes, embedding/vector caches, local model prompt cache, attachment quarantine, DLQ и backup expiry manifest. Невозможность немедленно удалить immutable backup явно отражается сроком expiry и owner-approved policy. Pseudonym mapping удаляется после удаления всех зависимостей либо tombstone удерживает только необратимый digest.
