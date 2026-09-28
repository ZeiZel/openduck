# 04. Ingress и PD

## Нормативный choke point

Все source paths — UI composer, webhook, polling, delta, history/backfill, retry, attachment/OCR, CuaDriver, parser — создают `SourceEvent.v1`. Каждый **cloud/model-visible** append path — prompt, steer, followup, subagent prompt, attachment, import, resume seed, fork seed, scheduled job, background job, tool-context injection, plugin call и internal inbox call — независимо проходит один persistent Controller Gate на **lowest durable append seam** до DSH session/event/index, model, MCP, tool или memory. Каждый path hard-disabled, если он не умеет предъявить exact `CloudAdmittedPrompt`. Local PD не использует этот seam: Controller выдаёт `LocalPDDispatch` напрямую Qwen/native view, и raw/local result никогда не входит в DSH.

`VERIFIED`: DSH `agent/pre-step` может rewrite/reject model input, но session/inbox фиксирует попытку, а архитектура требует логировать всё model-visible. Поэтому hook остаётся defense-in-depth; privacy admission реализуется перед DSH ingress.

## Gate sequence

1. Проверить adapter identity/signature, allowlist и current credential scope digest.
2. Проверить conversation scope, source/revision/sequence/cursor, replay и coverage; зафиксировать immutable event/revision-set digest, complete-through watermark, authoritative IngressGateState/coverage digest и class-high-water version.
3. Сохранить encrypted raw payload в quarantine по opaque ref с class floor.
4. Нормализовать Unicode/hidden characters и отметить carrier type.
5. Выполнить deterministic detectors: canonical/near-miss `Это ПД`, identifiers, secrets, restricted projects/peers, attachments/OCR, policy labels.
6. Монотонно повысить conversation/session privacy high-water до любого model call; downgrade/unlatch отсутствует.
7. Выдать snapshot-bound `PrivacyDecision`: local, safe capsule, quarantine или deny.
8. Для local route выдать `LocalPDDispatch` только Controller↔Qwen IPC без DSH/Codex target/attestation. Для safe route построить field-allowlisted ≤L1 capsule, post-scan и полный signed one-use `CloudAdmittedPrompt`.
9. Cloud append выполнить как `pending→consuming→consumed|uncertain`: CAS reservation, idempotent DSH append, signed `CloudAppendReceipt`, Controller reconciliation. Crash/timeout без matching receipt блокирует retry и egress.
10. Непосредственно перед Codex socket write Controller атомарно re-read/revalidate conversation scope, full event/revision set, complete-through, authoritative gate/coverage, high-water version, current runtime/profile/model/tool/network/policy and consumed append receipt. New/edit/delete/backfill/hidden-prior event, gap, revoke, class bump or config drift invalidates egress.
11. Записать только digests/metadata в Admission Ledger; raw body не входит в DSH.

## Sticky PD mode

Binding key: owner + source/account + conversation/session. Он переживает restart; class high-water **никогда не снижается и не снимается**. Cloud возможен только в fresh session identity без copied history, attachment handles, indexes or lineage, либо для exact already-declassified object. В PD mode:

- provider — exact pinned Ollama/Qwen artifact во внешнем Controller-owned native sidecar, не DSH plugin/process;
- `num_ctx=40960`, route `contextWindow=40960`, working budget `32768`, semantic thinking profile `medium`; если Qwen API даёт только boolean `think`, adapter фиксирует explicit benchmarked mapping (`think=true` + bounded budget) либо возвращает unsupported, не подменяет профиль молча;
- endpoint — loopback-only;
- network namespace/firewall — deny;
- tools/MCP/subagents/browser/files — none;
- cloud fallback — none;
- prompt/history/persistence — отдельный encrypted local store;
- UI — Controller-owned native/separate-origin `LocalPDView`; raw prompt/answer не попадает в DSH event bus/postMessage/search/localStorage/IndexedDB/service worker/title/telemetry;
- output — local answer или неавторитетная локальная подсказка owner.

Qwen помогает анализировать, но не решает class, export или effect policy. `LocalPDDispatch` не является `CloudAdmittedPrompt`, не содержит DSH/Codex target fields и не может быть предъявлен DSH ingress или cloud runner. Real PD payload запрещён до DR-020 evidence for isolated Qwen/LocalPDView/quarantine principal, native IPC, encrypted hard-erasable store read-deny and network deny against malicious DSH.

## Declassification

Baseline model/Qwen-derived PD release **disabled**. Qwen может показывать локальный анализ только вне release flow. Для release Controller открывает новый blank/non-prefilled trusted editor без suggestion/import; paste, drop, autofill, AX injection, AppleScript и synthetic keyboard input denied. Owner вручную вводит exact bytes, проходит fresh owner authentication, а editor сохраняет native input provenance; это operational evidence, не cryptographic proof of authorship. Решение связывает exact bytes, source/input refs, purpose, destination/model, TTL, nonce and max uses. После approval Controller повторно DLP-сканирует text и создаёт fresh-session capsule. Любая правка, новая source revision, policy/config change или gap инвалидирует решение. Model-derived release возможен только после отдельного ADR/security acceptance.

## Prompt-injection containment

- carrier type и trust tier сохраняются до sink;
- instructions/code/tool-looking text внутри source всегда quoted data;
- hidden Unicode нормализуется и детектируется;
- source content не может повысить tool set, изменить system prompt, открыть MCP или выбрать effector;
- sensitive sink повторно авторизуется Controller независимо от model decision;
- skills/MCP/plugins pinned/reviewed; tool results получают тот же provenance/class floor;
- source→sink adversarial matrix обязательна при каждом DSH/plugin/model upgrade.

## Quarantine cases

`unknown schema`, invalid signature, missing prior scan, cursor gap, out-of-order ambiguity, unknown attachment parser, OCR uncertainty, unclassified destination, DLP detector failure, local model unavailable, network isolation not attested или retention policy absent. Quarantine отображается владельцу без raw content в общей UI.

## POC evidence

Synthetic corpus включает exact marker, typo/spacing/case variants, hidden Unicode, PD в attachment/OCR, marker после queued messages и все перечисленные append paths. Race fixtures вставляют new/edit/delete/backfill/hidden prior event, gap, revoke и class bump между decision, append и final egress; каждый случай даёт zero Codex write. Crash fixtures останавливают процесс до reservation, между `consuming` и append, после append до receipt persistence и до final egress: reconciliation доказывает ровно один append либо terminal `uncertain`, без blind retry/model call. Разные input и Qwen-derived output sentinels ищутся в DSH JSONL/SQLite/context assembly/event bus, postMessage, browser stores/service-worker/title, telemetry, Codex inputs/network and dumps. Ожидается ноль raw sentinel bytes вне quarantine/Qwen/LocalPDView. Отдельные negative cases доказывают, что `LocalPDDispatch` не принимается cloud/DSH seam, а Qwen suggestion/paste/drop/autofill/AX/AppleScript/synthetic input невозможно превратить в approvable release.
