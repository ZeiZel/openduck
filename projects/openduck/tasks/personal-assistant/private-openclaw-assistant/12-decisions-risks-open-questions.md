# 12. Решения, риски и открытые вопросы

## Decision register

| ID | Решение | Варианты | Владелец | Нужен к | Default до решения |
|---|---|---|---|---|---|
| DR-01 | Первый channel | Telegram test bot / Slack sandbox / иной официальный API | Product + Security | Phase 0 exit | manual copy only |
| DR-02 | Deployment isolation | native sandboxed services / containers | Technical + Security | Phase 1 | no daemon |
| DR-03 | Tech-base | Markdown/Obsidian adapter / Notion / иной | Product/Data | Phase 5 | synthetic Inbox only |
| DR-04 | Calendar | Google / Outlook / local/иной | Product + Security | Phase 6 | local proposal only |
| DR-05 | Cloud auth/privacy posture | strict API / explicit Codex OAuth / local-only | Data + Security | Phase 3 | local-only |
| DR-06 | OpenAI data controls | default API / eligible MAM/ZDR / no cloud | Data + Security | Phase 3 | no egress |
| DR-07 | Retention/backup | per-class periods, RPO/RTO, legal hold | Data + Security | Phase 1 / Phase 8 | **USER DECISION (2026-08-12): backups disabled now; future design is local encrypted only, implementation deferred; no cloud backups** |
| DR-08 | Approval auth/TTL | device auth/session controls and TTL values | Security + Product | Phase 4 | mutations off |
| DR-09 | Calls/consent | official transcript sources and consent policy | Legal/privacy + Product | Phase 7 | no import/recording |
| DR-10 | Always-on | Mac best-effort / isolated always-on node | Product + Security | Pilot | Mac gaps accepted/displayed |
| DR-11 | Local model | evaluated 4–9B artifact/version | Technical + Security | Phase 1 | deterministic-only |
| DR-12 | Owners/on-call | named people and escalation | Product | Phase 0 | no production data |
| DR-13 | Approval canonicalization | RFC 8785 or equivalent exact spec | Technical + Security | Phase 4 | dispatcher absent |
| DR-14 | Audit integrity | hash chain / signed checkpoints / OS audit | Security | Phase 8 | append-only local metadata |

## Явные конфликты

### C-01: ChatGPT/Codex OAuth vs strict API privacy

`USER REQUIREMENT` хочет использовать ChatGPT/Codex. `VERIFIED` OpenClaw имеет subscription OAuth route. Однако официальные data controls различаются между consumer/business ChatGPT/Codex и API, а API retention тоже зависит от endpoint/настроек. Нельзя считать OAuth эквивалентом отдельного API project/ZDR. До DR-05 strict class запрещает OAuth.

### C-02: постоянный мониторинг vs ноутбук

Mac sleep/offline делает 24/7 невозможным без платформенного backfill или always-on узла. Система сообщает coverage gaps; DR-10 решает, нужен ли отдельный host.

### C-03: широкий personal assistant vs least privilege

Желание «всё остальное» не может быть универсальным capability grant. Каждая новая mutation/platform/data category проходит отдельный adapter, threat review и approval type.

## Risk register

| ID | Риск | Вероятность/влияние | Mitigation | Owner |
|---|---|---|---|---|
| R-01 | DLP false negative | M/Critical | raw L2/L3 deny, deterministic rules, post-scan, tests | Security |
| R-02 | Local model poor Russian extraction | M/Medium | benchmark corpus, manual clarification, model swap | Technical/Product |
| R-03 | Prompt injection через чат/вложение | H/High | no tools, typed output, approval, sandbox | Security |
| R-04 | Platform API/ToS changes | M/High | capability probe, pinned adapter, kill switch | Technical/Product |
| R-05 | Wrong recipient | L/Critical | canonical ID, preview/hash, ambiguity reject | Technical |
| R-06 | Duplicate/unknown delivery | M/High | idempotency, CAS, UNKNOWN reconciliation | Technical |
| R-07 | Secret in logs/backups | M/Critical | redacted APIs, secret scan, backup exclusions | Security |
| R-08 | Supply-chain compromise | M/High | allowlist, pins/SBOM, staged upgrades | Security/Technical |
| R-09 | Data lost/corrupted | M/High | accepted pre-pilot synthetic state loss; future local encrypted backup, integrity and outbound-disabled restore drill gated by owner approval | Technical/Data |
| R-10 | Sleep causes missed messages | H/Medium | gaps/backfill; always-on gate | Product |
| R-11 | Non-consensual call processing | L/Critical | no recording, consent record, official transcript only | Legal/privacy |
| R-12 | Over-retention/index copies | M/High | lifecycle inventory, purge tests, expiry ledger | Data |
| R-13 | Tech-base writer damages notes | L/High | Inbox-only, create-new, path confinement | Technical/Product |
| R-14 | Cost/rate runaway | M/Medium | budgets, bounded context, no silent fallback | Product/Technical |
| R-15 | Owner habituates to approvals | M/High | concise exact previews, high-risk distinctions, metrics | Product/Security |

## Открытые вопросы

1. Какие конкретно 1–2 канала дают наибольшую ценность, и есть ли test workspace/account?
2. Какие типы данных абсолютно запрещены даже для локальной модели или долговременного хранения?
3. Где находится tech-base, кто её владелец, допустим ли filesystem Inbox и как она резервируется?
4. Какой календарь и нужна ли запись в provider либо достаточно local proposal?
5. Какие платформы звонков дают официальный transcript/export и как фиксируется consent?
6. Нужен ли облачный Codex для каждого черновика или только для low-risk сложных случаев?
7. Какой тип ChatGPT/API организации и data controls реально доступен владельцу?
8. Как владелец подтверждает действие: локальный UI, отдельный bot chat, device biometric?
9. Какой приемлемый TTL, retention, RPO/RTO и бюджет?
10. Нужно ли 24/7 вне Mac; если да, где разместить отдельный single-owner gateway?

Ответы фиксируются как dated ADR/decision records с источником и approver; отсутствие ответа не превращается в молчаливое разрешение.
