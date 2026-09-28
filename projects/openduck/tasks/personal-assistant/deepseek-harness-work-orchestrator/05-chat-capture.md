# 05. Фиксация диалогов enterprise-chat и Telegram

## Capability status

`USER REQUIREMENT`: фиксировать диалоги enterprise-chat и Telegram.

`VERIFIED / bounded prototype, not integrated/production`: локальный CuaDriver proxy существует, но его DSH integration, coverage, OS permission, ToS и isolation не доказаны. Наличие configured MCP не является enablement. Официальный API/export предпочтительнее UI sensing.

`VERIFIED`: macOS UserNotifications API возвращает delivered notifications собственного приложения, а не универсально чужих приложений. Поэтому baseline sensor — подписанный native Swift sidecar с Accessibility/AXObserver для allowlisted apps/windows; CuaDriver применяется для bounded snapshot/recovery, не как cloud tool.

## Adapter contract

Каждый adapter объявляет `CapabilityManifest`:

- platform/account/identity и supported read scopes;
- room/chat/topic/thread allowlists;
- create/edit/delete/reaction/thread semantics;
- stable IDs/locators и timestamp/timezone fidelity;
- history/backfill limits, cursor/gap behavior, rate limits;
- attachment/media support и class floor;
- ToS/admin/consent/OS permission evidence;
- revoke/disable procedure и health probe.

## Acquisition priority

1. Supported official read-only API/webhook/export.
2. Signed local Accessibility sidecar observing explicit apps/windows.
3. CuaDriver bounded snapshot by Controller request for recovery/clarification.
4. OCR only in quarantine with L2 floor and explicit uncertainty.

Full-screen continuous capture, clipboard scraping and arbitrary app exploration are excluded.

## Conversation processing

1. Sensor emits minimal metadata and encrypted payload ref.
2. Controller resolves dedup/edit/delete and updates `CoverageState`.
3. Privacy gate selects local/safe/quarantine route.
4. Local extractor creates `ChatDigest`, reply/agreement/task/demo candidates.
5. Command Center shows author, channel, time, digest, urgency, classification and coverage.
6. Owner can acknowledge, snooze, open bounded source view, ask local/Codex clarification or approve a candidate.

## Coverage and history

- per account/chat/topic monotonic sequence/cursor where provider permits;
- periodic reconciliation/backfill within approved window;
- sleep/offline/auth expiry/rate limit produce explicit gap;
- edit/delete never erases audit: new revision/tombstone is linked to prior digest;
- incomplete prior scan keeps conversation quarantined from cloud;
- revocation stops sensor and invalidates queued admissions.

AX/CuaDriver observation без authoritative provider cursor/sequence всегда получает coverage максимум `best_effort`, а при невозможности доказать видимое окно — `unknown`. UI не может преобразовать это в `complete`; `CoverageState` лишь projection authoritative Controller `IngressGateState`.

## Reply boundary

Reply generation has no send credential. The exact preview includes platform/account/chat/topic/thread/recipient/body/attachments/reply-to revision. Editing invalidates approval. Sender effector verifies current recipient/thread state, policy/kill switch/idempotency and returns receipt; ambiguous provider response becomes `UNKNOWN`.

## UI views

- unified Inbox grouped by conversation and urgency;
- coverage/gap/stale badge;
- local-only/PD badge;
- candidates panel with provenance;
- unread/acknowledged/snoozed state (local projection, не provider mutation);
- source link/open action guarded by current app/window allowlist.

## Decisions before real data

DR-003 chooses official vs AX/CuaDriver acquisition separately for enterprise-chat and Telegram. DR-011 fixes accounts/chats, forbidden categories and history window. DR-020 must prove the signed AX/CuaDriver principal/TCC/capture store is OS-isolated from malicious DSH; DSH cannot inherit Accessibility or read/control sensor IPC. Security approver validates permissions and a synthetic look-alike application before production apps.

## Созвоны и встречи

Call/meeting capture — отдельный adapter manifest. До capture требуется explicit consent record, purpose, source/platform, participant notification basis, allowed audio/transcript and retention. Preferred source — official transcript/export; live audio recording/OCR требует отдельного privacy/legal decision. Source coverage, missing segments, diarization/speaker and timestamp uncertainty сохраняются и не исправляются моделью молча.

Audio/transcript проходит pre-DSH PD gate через `LocalPDDispatch` и остаётся local quarantine. Native Qwen sidecar может создать `MeetingDigest` с attributed agreement/action/demo/report **suggestions**, но raw transcript, digest, Qwen answer и derived suggestions остаются только в Qwen/`LocalPDView`: они не входят в DSH, не становятся approvable candidate и не могут быть release payload.

Любой выход meeting content в DSH либо tech-base начинается заново: Controller открывает blank/non-prefilled trusted editor без Qwen suggestion/import; owner после fresh authentication вручную набирает exact release text, причём paste/drop/autofill/AX/AppleScript/synthetic input запрещены. Только matching consumed `DeclassificationDecision` и post-scan разрешают **любые** outward bytes; DSH route дополнительно требует fresh `CloudAdmittedPrompt`, tech-base — exact create-effect approval и exclusive create-new writer. Qwen-derived report напрямую writer’ом не принимается, update/purge не входят в первый writer. Эта input-policy evidence не называется cryptographic authorship proof.
