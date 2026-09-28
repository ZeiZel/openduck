# 07. PD sticky mode и declassification

## Marker semantics

`USER REQUIREMENT`: сообщение, начинающееся canonical строкой `Это ПД`, обрабатывается локально. `VERIFIED / repository`: текущий plugin принимает optional BOM, horizontal spaces после marker и newline/end, но не leading ordinary space; похожее confusable написание попадает в quarantine. После marker session mode становится sticky и persist’ится.

## Authoritative route

1. Marker/near-miss проверяется единым persistent ingress Gate для каждого live/historical/replayed/background record до OpenClaw/model/parser/tool resolution; hook является defense-in-depth.
2. Canonical marker → `pd`; near miss → `quarantine`; corrupt/missing session identity → deny.
3. Model принудительно `ollama/qwen3:8b`; mismatch blocks run.
4. Любой tool call blocks; fallback list empty; local runtime outbound denied.
5. Следующие сообщения той же session остаются PD независимо от отсутствия marker.
6. Выход из PD создаёт **новую non-PD session**; unlatch существующей session запрещён.

Gate sequencing is monotonic per conversation. Если marker с sequence `n` обнаружен после уже полученного `n+1`, prior scan был incomplete, replay digest конфликтует или существует gap, вся conversation quarantine’ится; ни ранее созданный derivative, ни новое сообщение не получает cloud eligibility до local rescan/reconciliation. Marker in attachment/transcript metadata or locally parsed content также latch’ит parent conversation; attachment/transcript до declassification остаётся minimum L2.

## PD data rules

- PD content не попадает в TaskSignal, root thread, Luna, Terra, Codex Implementer, MCP, tech-base, tracker, logs или analytics.
- Operational audit содержит только pseudonymous session ref, mode transition, model digest, status, timing и `content_exported=false`.
- Qwen output считается sensitive derivative и наследует max class input.
- Выбранный после AD-15 Codex-facing client `PROPOSAL` локально отображает Qwen result в изолированной `LOCAL / ПД` панели без добавления body в model/root thread; screenshot/clipboard/export являются отдельными user actions. Пользователю не требуется OpenClaw или Qwen UI. До доказанного local-only rendering route blocked.
- Memory search and cross-session recall off.

## Minimal result

`PDHandled.v1` по умолчанию содержит `session_ref`, `handled_at`, `status=handled_local|needs_owner|failed_local`, `urgency`, `content_exported=false`, `policy_version`. Даже summary/topic отсутствует.

## Declassification

`USER REQUIREMENT` о «минимально необходимых данных» реализуется не автоматическим summary, а explicit local workflow:

1. Qwen либо owner создаёт immutable candidate payload; Controller canonicalizes exact released bytes and binds `candidate_payload_hash` plus released-byte hash.
2. Deterministic postscan/classification создаёт signed/digested attestation; L3/secret/unknown → deny.
3. Выбранный attested Codex-facing interface через Controller-owned local panel показывает exact released bytes/fields, purpose, exact provider, auth profile, retention profile, classification/postscan, source and expiry; model не получает эти bytes. Delivery binding обязан отдельно доказать local-only rendering.
4. Recently authenticated owner принимает nonce-bound `DeclassificationDecision` с TTL, `max_uses=1` и status `pending`.
5. Controller atomic CAS проверяет весь decision tuple и переводит `pending→consuming→consumed`; concurrent consumer проигрывает. Byte/field/class splice, candidate/class change, provider/auth/retention swap, source/policy mutation or expiry invalidates.
6. Signal compiler создаёт новый non-PD artifact только из exact consumed canonical bytes.
7. Решение не открывает original PD session и не разрешает future exports.

`PROPOSAL`: до отдельного security acceptance разрешить declassification только вручную написанного owner текста; model-derived PD release оставить disabled.

## Failure behavior

- Ollama down/OOM: local/manual only; no Codex fallback.
- Malformed output: один bounded local retry, затем error.
- State corruption/persist uncertainty: quarantine/deny until repair and owner-visible audit.
- Marker detected после ошибочного earlier route: immediate egress kill, incident record, purge where possible; отсутствие provider deletion receipt указывается явно.
- Cross-session paste из PD: новая content classification всё равно L2/L3; marker absence не является declassification.

## Required tests

Canonical/BOM/CRLF, leading-space rejection, confusables, bidi/zero-width, restart persistence, all-ingress tool denial, model mismatch, corrupt state, concurrent first message, session-key collision, no-network capture, log/telemetry scan, marker-old-after-new, replay/backfill gap, attachment/transcript marker/local L2, explicit new-session exit, declassification replay/expiry/concurrent consume, field/byte/class splice and provider/auth/retention swap.
