# 06. Мониторинг чатов и быстрые ответы

## Sensor contract

OpenClaw adapter работает только с явно выбранными account/channel/conversation scopes. Для каждого source до enablement создаётся CapabilityManifest: official access mode, read scopes, history/backfill, edits/deletes, threads, attachments, webhook/polling security, rate limits, gap semantics, revocation и ToS/admin evidence.

`USER REQUIREMENT`: OpenClaw «следит за чатами» означает bounded authorized monitoring, а не запись всего desktop screen или всех аккаунтов. macOS sleep/offline и revoked access отражаются coverage gap.

## Pipeline

1. Все webhook, polling, history/backfill, replay/retry, attachments/transcripts, parser и background records поступают только в единый ingress Gate; прямой downstream ingest запрещён.
2. Gate проверяет source identity, signature/timestamp/nonce/cursor, persistent per-conversation monotonic sequence, digest chain и полноту prior scan.
3. PD marker проверяется над каждым source byte record до parse/summarization/routing; gap/out-of-order/conflicting replay/непроверенный более ранний диапазон latch’ит conversation quarantine.
4. Attachment/transcript child parts local-parse’ятся только после Gate registration, имеют floor L2 и cloud-ineligible.
5. Только Gate-attested normal event нормализуется в существующий `InboundEvent`, шифруется и deduplicates по source/version.
6. Deterministic DLP задаёт class floor; local model может предложить urgency/topic/spans.
7. Signal compiler создаёт `TaskSignal` из allowlisted fields и evidence refs.
8. Correlator группирует burst только в рамках одного conversation/session namespace.
9. Notification/fast answer создаётся локально; root turn появляется только по route policy.

## Sensor-to-Controller boundary

OpenClaw chat-facing agent baseline — `tools deny all`; запрет включает `codex_delegate`, MCP discovery/calls, browser/web, exec/process, message/channels, filesystem, apps и subagents. Sensor может только передать Gate-attested encrypted record в authenticated local Controller transport. Transport использует separate process identity, peer authentication, per-request nonforgeable random ID, nonce/replay cache, bounded schema and rate; sender/chat fields не могут влиять на request identity или Codex prompt method.

`VERIFIED / current tracked config gap`: текущий `deploy/openclaw/config.json` deny-list не является deny-all и одновременно включает read-only Obsidian, Context7, Kaiten, CUA и public-search MCP для default runtime; PD hook блокирует tools только после PD latch и отдельно валидирует `codex_delegate`, но не запрещает его для всех chat sessions. Поэтому текущая конфигурация **не соответствует** sensor baseline и не может быть real-chat ingress для harness. Implementation gate: отдельный sensor agent/process с empty tool surface; controller transport unavailable to model tool registry; negative discovery/delegation test до H2 exit.

## Fast-answer eligibility

Luna route разрешён, если одновременно: class ≤L1 после sanitization; purpose allowlisted; один bounded question; capsule complete; no owner decision; no mutation; no identity merge; evidence refs доступны read-only; estimated token budget проходит лимит.

Примеры eligibility: «какой статус карточки?», «кто ждёт ответ?» по allowlisted metadata, «суммируй три уже обезличенных факта». Не подходят: обещать срок, отправить ответ, трактовать договорённость, раскрывать PD, менять tracker или собирать cross-chat dossier.

## Answer delivery

AnswerCard показывается owner как suggestion только через выбранный после AD-15 Codex-facing interface с source/coverage/confidence; отдельный OpenClaw UI не требуется. До успешного interface probe delivery blocked. Автоответ в исходный чат является `reply.send` mutation и не входит в fast-answer route. Даже шаблонный ответ проходит ActionProposal, immutable Controller preview and exact-bound `OwnerDecisionEvent`, пока narrow pre-approved policy не прошла Phase H5.

## Injection controls

- Quoted/replied/forwarded text остаётся untrusted data.
- Message, filename, link title или card description не может выбирать agent/tool/model.
- URLs не fetch’ятся из chat signal автоматически.
- Attachments quarantined; parsing — отдельный local pipeline.
- Signal summary запрещает imperative/tool syntax; original excerpt хранится локально по ref.
- Any instruction вроде «игнорируй правила» фиксируется как content, не control.

## Edits, deletes и gaps

Source edit invalidates derived signal/capsule and any unapproved action. Delete инициирует retention/purge flow; accepted durable fact не удаляется автоматически без policy basis, но provenance помечается unavailable. Gap создаёт `coverage.complete=false`; summaries не утверждают полноту.

Gap also latches conversation quarantine until bounded rescan proves contiguous scanned-through watermark. Newer event cannot clear an older unseen marker. Backfill/replay follows the same Gate transaction as live delivery; it cannot be labeled trusted merely because it is historical.

## Backpressure

Priority queue учитывает explicit owner rules и deterministic urgency; model score не может вытеснить security/control events. При overload low-priority signals coalesce по digest, raw events не теряются молча, UI показывает lag/coverage. Rate/cost limit не вызывает cloud fallback.
