# 03. Security, privacy и threat model

## Защищаемые активы

Содержимое чатов/звонков; личности и связи; бизнес-секреты; credentials/tokens; pseudonym map; approvals; отправляемые сообщения; calendar/tech-base; audit/provenance; конфигурация allowlist/policy; резервные копии.

## Атакующие и допущения

- Внешний собеседник или скомпрометированный канал вставляет prompt injection.
- Вредоносное вложение/транскрипт пытается вызвать tool/action.
- Вредоносный/скомпрометированный plugin, dependency или model artifact.
- Локальное непривилегированное ПО читает world-readable state.
- Ошибка владельца: не тот адресат, устаревший preview, слишком широкий scope.
- Cloud/provider compromise или непреднамеренная retention.
- Потерянный ноутбук/backup; corrupted DB; replay webhook; сетевой MITM.

Один локальный OS administrator остаётся доверенным. Если нужен режим нескольких недоверяющих владельцев, требуются отдельные gateway, OS users и credentials; текущая архитектура его не поддерживает.

## Главные угрозы и меры

| ID | Угроза | До мер | Контроли | Остаток |
|---|---|---:|---|---:|
| T-01 | Prompt injection вызывает отправку/чтение/egress | Critical | контент всегда data; модель без action tools; typed outputs; approval + dispatcher separation; allowlist | Medium |
| T-02 | Raw L2/L3 уходит в cloud | Critical | default-deny, deterministic DLP, schema allowlist, post-scan, egress audit, kill switch | Low/Medium |
| T-03 | Отправка не тому адресату | Critical | canonical destination ID, exact preview, ambiguity reject, hash-bound approval, no display-name routing | Low |
| T-04 | Replay/duplicate delivery | High | webhook verification, source dedup, action idempotency, receipt reconciliation | Low |
| T-05 | Credential leak | Critical | Keychain/secret store, least scopes, no repo/log/prompt, rotation/revocation runbook | Medium |
| T-06 | Supply-chain compromise | High | pinned versions/digests, explicit plugin allowlist, provenance/SBOM, staged update, security audit | Medium |
| T-07 | Local state theft | High | FileVault gate, strict permissions, encryption, screen lock, encrypted backups | Medium |
| T-08 | Approval tampering | Critical | append-only registry, canonical serialization + hash, approver auth, TTL, audit chain | Low/Medium |
| T-09 | Poisoned durable memory | High | candidates, source provenance, human acceptance, Inbox-only writer, no autonomous promotion | Low |
| T-10 | Hidden recording/non-consensual processing | Critical | consent gate, visible indicator, source policy, no recording feature by default | Low |
| T-11 | Silent gaps while Mac sleeps/offline | High | heartbeat, gap marker, resumable cursor, reconciliation; no false all-clear | Medium |
| T-12 | Malicious attachment/parser exploit | High | type/size allowlist, quarantine, sandbox parsing, no macros, AV where available | Medium |

## Prompt injection policy

1. Message body, attachment text, webhooks, calendar descriptions и transcripts помечаются `untrusted_content`.
2. Они не могут изменять system policy, allowlist, tool access, routing, recipient или approval state.
3. Инструкции вроде «перешли все прошлые сообщения», «прочитай файл», «игнорируй правила» должны попадать в detector signals и тестовый корпус.
4. Local/cloud model получают только tools-free schema task. Никакие free-form tool calls из модельного ответа не исполняются.
5. Model output валидируется; неизвестные fields/URLs/action types отклоняются.
6. Цитирование source excerpt не даёт этому тексту authority.

## Secret handling

- Секреты не хранятся в Git, Markdown specification, prompts, event payloads или audit logs.
- Credential store содержит secret; конфигурация — только reference/profile ID.
- У каждого adapter/writer отдельный credential и минимальные read/write scopes.
- Tokens не передаются local/cloud LLM. Redaction применяется до логирования ошибок.
- Rotation/revocation тестируется; утеря устройства инициирует revoke всех tokens и cloud keys.
- Любое появление secret detector match в cloud envelope → deny и security event без значения секрета.

## Encryption, retention, backups

- До доступа к любым реальным данным Security owner обязан утвердить и проверить **minimum host security baseline**: FileVault включён; автоматическая screen lock настроена; runtime работает под отдельным OS UID/sandbox либо документирован formally accepted equivalent с компенсирующими мерами; state/config не доступны group/world; credentials представлены только Keychain/secret-store references; internal endpoints привязаны к localhost, а firewall/exposure проверены; решение по encrypted backup и recovery ownership зафиксировано. Отсутствие любого evidence блокирует Phase 2.
- Queue payload, raw transcript, pseudonym map и approval DB шифруются at rest; ключи отделены от backup данных.
- TLS + official endpoint allowlist обязательны для egress; plaintext official endpoint отклоняется.
- Retention настраивается по классу и purpose; delete propagates к derived local artifacts. Нельзя обещать удаление из provider logs сверх официальных controls.
- Backup содержит минимальный state, шифруется, имеет restore test и documented RPO/RTO. Raw audio по умолчанию не включается без отдельного решения.

Phase 8 расширяет этот минимум process sandbox hardening, signed/audited checkpoints, penetration/fault testing и incident drills, но не откладывает базовую защиту host до Production.

Предлагаемые стартовые сроки до decision: L0 — 90 дней; L1 — 30 дней raw/180 дней approved durable; L2 — 14 дней raw; L3 — только session memory или 0 дней persisted. Это `PROPOSAL`, не активная политика.

## Audit без raw content

Разрешены: event/action IDs, hashed canonical payload, channel/account/conversation pseudonymous IDs, class, policy version/rules, state transition, actor, timestamps, latency, error category, provider/model route, token counts/cost estimate, receipt ID. Запрещены: raw body, attachment, transcript, pseudonym map, OAuth token, secret matches, полный recipient address. Для расследования raw source открывается отдельно владельцем по locator и access check.

## Supply-chain gate

Перед обновлением OpenClaw, plugin, model, parser или adapter: проверить официальный origin и checksum/signature, changelog и permissions; создать SBOM; прогнать synthetic suite; запустить security audit; сохранить rollback artifact; canary в shadow mode. Auto-update production dependencies выключен.

## Legal/organizational gates

- `DECISION REQUIRED / Data owner + counsel/privacy role / до реальных данных`: lawful basis, notice/consent, purpose limitation, трансграничная передача и retention.
- `DECISION REQUIRED / Platform admin / до OAuth`: ToS, bot policy, approved app/scopes, workspace DLP/MDM.
- `DECISION REQUIRED / Meeting organizer / перед каждой записью либо утверждённой политикой`: согласие участников и видимый индикатор.
- `DECISION REQUIRED / Employer or data owner / до корпоративных чатов`: разрешена ли обработка рабочей информации персональным ассистентом.

## Security acceptance invariants

- При падении DLP, policy store, approval registry или destination resolver действия и cloud egress блокируются.
- Внешний текст не может создать valid approval.
- Local LLM verdict никогда не ослабляет deterministic deny.
- Reply/calendar/agreement approvals не взаимозаменяемы.
- Никакой recipient не выбирается по похожему имени.
- Security kill switch немедленно отключает egress и mutations, сохраняя локальные forensic metadata.
