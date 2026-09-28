# 04. Классификация данных и egress policy

## Классы

| Класс | Смысл | Примеры | Обработка по умолчанию |
|---|---|---|---|
| L0 Public | явно публичные, неидентифицирующие | публичная документация, общие шаблоны | cloud допустим по purpose allowlist |
| L1 Internal | низкочувствительный рабочий контекст | обезличенный статус, стабильные псевдонимы, общая тема | cloud только через safe envelope |
| L2 Confidential | персональные/коммерческие данные | raw сообщения, имена+контакты, договоры, непубличные планы, transcript | local-only по умолчанию; cloud `ask` только после явного исключения |
| L3 Restricted | секреты/особые категории/высокий риск | credentials, ключи, финансы, здоровье, HR, legal privilege, security incidents | local-only; cloud deny |

Класс применяется к полю и всему payload; итоговый класс — максимальный, пока field-level sanitizer не создал новый производный артефакт. Неопределённый класс трактуется как L2.

## Authoritative decision pipeline

1. Validate source and schema.
2. Apply deterministic exact/regex/dictionary/entropy detectors and platform labels.
3. Apply user/project/channel deny rules.
4. Optional local model предлагает labels и spans; оно не может снизить класс, назначенный правилами.
5. Sanitizer создаёт производный envelope по allowlisted fields.
6. Deterministic post-scan и size/budget check.
7. Policy engine выдаёт `allow`, `ask` или `deny` с versioned reason codes.

Local LLM **не гарантирует privacy** и не является security control в одиночку. False negatives ожидаемы, поэтому L2/L3 raw запрещены независимо от model score.

## Egress matrix

| Route | L0 | L1 sanitized | Raw L2 | L3 | Failure |
|---|---|---|---|---|---|
| Local deterministic | allow | allow | allow within purpose | metadata-only unless explicitly needed | fail closed |
| Local model, loopback | allow | allow | allow by local purpose policy | deny or explicit narrow local-only rule | degrade to rules/manual |
| Codex/OpenAI cloud | allow | allow after scan | deny by default; `ask` exception is separately approved and logged | deny | no silent fallback |
| Notification UI on owner device | allow | allow | allow with screen privacy setting | masked by default | queue locally |
| Operational logs | metadata | pseudonymous metadata | no raw | no raw | drop/redact content |

## Safe envelope contract

Нормативный JSON Schema (концептуальный; реализация должна положить machine-readable копию рядом с кодом):

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "openduck.safe-envelope.v1",
  "type": "object",
  "additionalProperties": false,
  "required": ["schema_version", "purpose", "session_ref", "messages", "constraints", "egress_attestation"],
  "properties": {
    "schema_version": {"const": "1.0"},
    "purpose": {"enum": ["draft_reply", "summarize", "extract_candidates"]},
    "session_ref": {"type": "string", "pattern": "^psn_[A-Za-z0-9_-]+$"},
    "messages": {
      "type": "array", "maxItems": 20,
      "items": {
        "type": "object", "additionalProperties": false,
        "required": ["speaker", "text"],
        "properties": {
          "speaker": {"type": "string", "pattern": "^P-[A-Z0-9]{6,16}$"},
          "text": {"type": "string", "maxLength": 4000},
          "relative_time": {"type": "string", "maxLength": 80}
        }
      }
    },
    "constraints": {
      "type": "object", "additionalProperties": false,
      "required": ["language", "tone", "forbidden_actions"],
      "properties": {
        "language": {"type": "string", "maxLength": 16},
        "tone": {"type": "string", "maxLength": 80},
        "forbidden_actions": {"type": "array", "items": {"type": "string"}}
      }
    },
    "egress_attestation": {
      "type": "object", "additionalProperties": false,
      "required": ["policy_version", "max_class", "decision", "digest"],
      "properties": {
        "policy_version": {"type": "string"},
        "max_class": {"enum": ["L0", "L1"]},
        "decision": {"const": "allow"},
        "digest": {"type": "string", "pattern": "^sha256:[a-f0-9]{64}$"}
      }
    }
  }
}
```

Пример допустимого envelope:

```json
{
  "schema_version": "1.0",
  "purpose": "draft_reply",
  "session_ref": "psn_7ETR2K",
  "messages": [
    {"speaker": "P-4F91AC", "text": "Предлагает обсудить обезличенный макет в четверг", "relative_time": "последнее сообщение"}
  ],
  "constraints": {"language": "ru", "tone": "деловой, короткий", "forbidden_actions": ["send", "create_calendar_event"]},
  "egress_attestation": {"policy_version": "egress-1", "max_class": "L1", "decision": "allow", "digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
}
```

Пример недопустимого envelope: реальное имя вместе с телефоном, raw договор, credential-like string, вложение или `max_class: L2`. Он отклоняется до network call.

## Stable pseudonyms и rehydration

- Псевдоним стабилен только внутри `(owner, channel, conversation/purpose namespace)` и создаётся keyed deterministic mapping.
- Mapping содержит real↔pseudo и хранится encrypted local-only отдельно от queue/logs.
- Cloud никогда не видит mapping key, real identifiers или функцию rehydration.
- Cloud output локально rehydrate только в preview; dispatcher получает уже точный approved payload, а не право lookup произвольных контактов.
- Merge identity между каналами запрещён без ручного подтверждения.

## `allow / ask / deny`

- `allow`: все поля allowlisted, max L1, purpose и endpoint разрешены, post-scan чист.
- `ask`: только заранее определённый L2 exception, точный excerpt/purpose/provider/retention показаны владельцу; одноразовое согласие не меняет policy.
- `deny`: L3, secret hit, неизвестный класс/schema, запрещённый endpoint, oversized context, missing provenance, policy/DLP failure.
- При `deny` предлагаются локальная обработка, ручное сокращение или безопасный шаблон. Причина сообщается без раскрытия найденного секрета.

## Data lifecycle

Derived artifact хранит parent IDs и policy version. Удаление raw source инициирует удаление локальных производных raw copies; принятые durable facts требуют отдельного retention basis. Cloud deletion не заявляется успешным без provider-supported receipt. Retention и legal hold имеют явный приоритет, владельца и audit event.
