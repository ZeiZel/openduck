# 03. Контракты и ledgers

## Общие правила

Все authoritative records имеют `schema`, `id`, `version`, `created_at`, `producer`, `correlation_id`, canonical serialization/hash и sensitivity metadata. Unknown field в security-critical tuple, unknown enum/version или invalid signature отклоняется. Идентификаторы source/provider хранятся как typed IDs; display names не используются для адресации effects.

Существующие `InboundEvent`, `SafeEnvelope`, `TaskSpec`, `WorkOrder`, `EvidenceBundle`, `ReviewVerdict`, `ActionProposal`, `CapabilityGrant`, approval и receipt contracts из родительских пакетов переиспользуются без ослабления. Ниже — новые/расширенные contracts; несовместимое изменение получает новую major schema.

## Ingress и privacy

### `SourceEvent.v1`

`source_kind`, `account_id`, `container_id`, `thread_id`, `event_id`, `revision`, `event_type`, `author_ref`, `source_time`, `observed_at`, `locator`, `content_digest`, `payload_ref`, `coverage_cursor`, `auth_context_digest`, `carrier_type`, `capture_quality`.

Raw body хранится только в encrypted local quarantine по opaque `payload_ref`; он не входит в DSH payload.

### `CoverageState.v1` — projection only

`scope`, `cursor`, `last_complete_at`, `sequence`, `known_gaps[]`, `backfill_status`, `revoked_at`, `freshness`, `state=complete|best_effort|partial|gap|revoked|unknown`. Это consumer-facing projection существующего authoritative `IngressGateState`; она не заменяет monotonic gate state, не может повысить coverage и для AX без provider cursor имеет максимум `best_effort`.

### `PrivacyDecision.v1`

`conversation_scope`, `event_digest`, immutable `event_revision_set_digest`, `complete_through_watermark`, `ingress_gate_state_digest`, `authoritative_coverage_digest`, `class_high_water`, `class_high_water_version`, `detectors`, `pd_latch_id`, `route=local_qwen|safe_capsule|quarantine|deny`, `allowed_fields`, `policy_version`, `decision_hash`. Любой новый/edit/delete/backfill event, gap/revoke либо high-water version bump делает cloud decision stale.

### `CloudAdmittedPrompt.v1`

Exact single-use **cloud-only** tuple для payload класса не выше L1; он никогда не представляет local Qwen route:

- identity: `admission_id`, `nonce`, `issued_at`, `expires_at`, `max_uses=1`, `target_session_id`, `target_codex_thread_id`;
- source snapshot: `conversation_scope`, immutable `event_revision_set_digest`, `complete_through_watermark`, `ingress_gate_state_digest`, `authoritative_coverage_digest`, `class_high_water`, `class_high_water_version`;
- bytes/policy: `content_digest`, `privacy_decision_digest`, `policy_digest`, `source_refs`, `classification<=L1`, `route=codex_cloud`;
- runtime: `target_runtime_attestation_digest`, `target_dsh_distribution/profile_attestation_digest`, `target_codex_profile_attestation_digest`;
- model/tools: `model_class=codex`, `model_transport_policy_digest`, `toolset_digest`, `tool_network_policy_digest`;
- destination: DSH append store/schema/idempotency key and expected Codex runner/thread binding;
- payload: canonical allowlisted safe capsule only; local PD handle запрещён;
- authenticity: `controller_signature`, schema/version/canonicalization digest.

### `LocalPDDispatch.v1`

Controller-only tuple: `dispatch_id`, `nonce`, `issued_at/expires_at`, `privacy_decision_digest`, `conversation_scope`, `event_revision_set_digest`, `class_high_water/version`, encrypted `payload_ref`, exact Qwen model/runtime/config attestations, `LocalPDViewBinding` digest, tools/network/fallback=`none`, Controller signature. Он не содержит DSH session/profile или Codex thread/runtime attestation, не проходит DSH append seam и передаётся только по authenticated native Controller↔Qwen IPC.

### `CloudAdmissionConsumption.v1` / `CloudAppendReceipt.v1`

Cross-store append не называется атомарным. Controller ledger CAS выполняет `pending → consuming` с `append_attempt_id`, destination/idempotency key and exact prompt digest. DSH lowest seam делает idempotent append by `admission_id` и возвращает signed receipt: destination store/record/schema, admission/prompt/content digests, observed append revision/time and signer attestation. Пока state=`consuming`, reconciler query по `admission_id` переводит его в `consumed` только при единственном matching append/receipt; отсутствие доказательства, contradictory records или bounded timeout переводит в terminal `uncertain`, блокирует model egress/blind retry. Late receipt у terminal `uncertain` quarantined for audit, не повышает state; новый attempt требует новый admission ID.

Непосредственно перед Codex network write Controller в одной ledger transaction повторно читает current `IngressGateState`, authoritative coverage/complete-through, class high-water/version, current event/revision set and runtime/profile/model/tool/network/policy attestations, сравнивает их с `CloudAdmittedPrompt` и matching consumed append receipt, затем резервирует единственный egress nonce. Любой new/edit/delete/backfill, hidden prior event, gap, revoke, class bump or config drift запрещает egress и требует нового decision/admission. DSH самостоятельно не отправляет prompt модели.

### `IngressGateState.v1`

Наследуется из existing Controller contract и остаётся authoritative monotonic per-source/conversation state: last accepted sequence/revision/cursor, full-scan watermark, gaps, replay set, privacy high-water, policy digest and quarantine. `CoverageState` только redacted projection.

### `PDSessionBinding.v1`

`pd_session_id`, source/owner scope, immutable `class_high_water`, Qwen sidecar/runtime/config attestations, encrypted local-store ref, created/last-used timestamps. High-water не снижается. Cloud continuation возможен только через новую identity без history/attachment/handle/index lineage либо exact consumed declassified object.

### `LocalPDViewBinding.v1`

Controller-owned native window/separate origin identity, CSP/origin/IPC channel digests, no-DSH-event/postMessage/browser-store flags, title/notification redaction policy and one-session opaque handle. Raw input и derived output доступны только этому view и Qwen sidecar.

### `DeclassificationDecision.v1`

Наследует строгий parent contract: owner-authored exact release bytes, input/output byte digests, exact fields, destination/model/purpose, policy version, approver/auth context, TTL/nonce/max uses, post-scan digest и atomic consumption. `authorship_mode=strict_manual`: trusted editor открывается blank/non-prefilled, не показывает/не импортирует Qwen suggestion, запрещает paste/drop/autofill/Accessibility injection/AppleScript/synthetic keyboard input, требует fresh owner auth и сохраняет native input provenance. Это тестируемая UI/input-policy гарантия, **не cryptographic proof of human authorship**. Model/Qwen-derived release не принимается; будущий иной режим требует отдельного ADR/security acceptance.

## Work и planning

### `WorkItem.v1`

`work_item_id`, `title`, `kind`, `status`, `owner`, `source_links[]`, `task_spec_hash`, `parent_id`, `dependencies[]`, `estimate`, `planned_window`, `deadline`, `demo_links[]`, `confidence`, `version`.

### `TaskLink.v1`

Связывает `work_item_id` с `kaiten_card_id`, `beads_issue_id`, repo/worktree и/или calendar item; хранит mapping version, direction, field ownership и last reconciled external revision. Link не означает право синхронной записи.

### `WorkGraphSnapshot.v1`

`graph_id`, `baseline_version`, nodes, typed edges, capacity calendar, critical path, unscheduled items, conflicts, assumptions, generated_from[], generated_at`.

### `PlanDelta.v1`

`from_graph_hash`, `to_graph_hash`, `trigger_refs[]`, `changed_nodes[]`, `milestone_impact`, `capacity_impact`, `risk_delta`, `recommended_actions[]`; это proposal, не baseline transition.

### `DemoCandidate.v1`

`title`, exact/interval datetime, timezone, task links, source quote digest/locator, ambiguity, confidence, attendees/resource candidates, status. Неявная дата запрещена.

### `CalendarItem.v1`

`calendar_item_id`, `authority`, `external_id`, `ical_uid`, `recurrence_ref`, `start/end/timezone`, `status`, `demo_binding`, `source_revision`, `conflicts[]`.

## Source change contracts

### `ChatDigest.v1`

`conversation_scope`, `event_refs[]`, `participants`, `summary`, `urgency`, `agreement/task/demo/reply candidates`, `coverage`, `classification`; raw messages не включаются в cloud-safe variant.

### `TaskChange.v1`

`provider=kaiten`, `resource_id`, `event_kind`, `old_digest`, `new_digest`, `changed_fields`, `actor_ref`, `provider_time`, `observed_at`, `cursor`, `coverage`.

### `MailChange.v1`

`message_id`, `conversation_id`, allowed basic fields, `change_kind`, `received_at`, `delta_cursor_ref`, `classification`, `body_scope=absent|separately_authorized`.

### `CalendarChange.v1`

`event_id`, `ical_uid`, `series_master_id`, occurrence bounds, change kind, allowed basic fields, delta window/cursor, source revision.

## Memory и time

### `MemoryCandidate.v1` / `MemoryRecord.v1`

`stable_key`, `scope=repo|machine-private|domain`, `claim`, `provenance_refs[]`, `evidence_refs[]`, `valid_from`, `review_after`, `sensitivity`, `conflicts[]`, `supersedes`, `approved_by`, `status=active|stale|superseded|forgotten`.

Task progress не записывается как MemoryRecord. Machine-private records не рендерятся в repository artifact и не пересекают scope.

### `TimeEvent.v1` / `TimeEntry.v1`

`event=start|pause|resume|stop|adjust`, `work_item_id`, `actor`, monotonic/wall timestamps, `source=explicit|derived_candidate|provider`, `reason`, `supersedes`; materialized entry содержит interval, duration, overlaps, confidence и approval state.

## Orchestration и review

### `DispatchRecord.v1`

`dispatch_id`, `order_kind=work_order|agent_run_order|read_order`, `order_hash`, `run_dispatch_binding_hash`, `runtime_attestation_hash`, `role`, `session/thread binding`, `input_capsule_hash`, `capability_set_hash`, `started_at`, `status`, `attempt`, `parent_dispatch_id`. Поле `work_order_hash` отсутствует: implementer получает `order_kind=work_order`; другие роли никогда не маскируются под него.

### `RunDispatchBinding.v1`

Exact tuple: `dispatch_id`, `order_kind`, `order_hash`, `task_spec_hash`, `role/profile`, `input_capsule_hash`, `input_schema_digest`, `output_schema_digest`, `expected_evidence_schema/digests`, `runtime_attestation_hash`, capability/toolset/read/write-root/model-network/tool-network digests, workspace/thread binding, dependency hashes, issued/expires/nonce/max_uses and Controller signature. Scheduler и result acceptor независимо reject’ят role/order/schema/evidence/runtime mismatch.

### `AgentRunOrder.v1`

Common tuple: `order_kind=agent_run_order`, `role_profile`, `objective`, `input_capsule_hash/schema`, `allowed_sources`, `read_roots`, explicitly empty/default-denied write roots, model/tool network policies, `toolset_digest`, `output_schema_digest`, budgets, dependencies, prohibited effects and expected evidence schema. Review profile additionally binds repository/project identity, resolved target/base commits, diff digest, TaskSpec/acceptance hashes, prior evidence digest, checks allowlist, finding schema, `ReviewVerdict` schema and independence constraints. Generic orchestration profile has its own explicit input/output/evidence schemas and cannot accept review or implementation-only fields.

### `ReadOrder.v1`

Strict writes/effects-disabled tuple with `order_kind=read_order`, `role_profile=lookup|project_preparation|status`, objective, input capsule/schema, allowed sources/read roots/probes, network policy, toolset, output/evidence schemas, budgets and dependency hashes. Project-preparation profile additionally binds repository identity, requested base, observed branch/HEAD/dirty-state digest, instruction/policy digest, workspace candidates, doctor/version probe allowlist, dependency/credential-reference/service inventory schemas and exact `ProjectPreparationEvidence` schema; it cannot carry install/start/write/git-effect verbs.

### `WorkerRuntimeAttestation.v2`

Strict superset существующей attestation: order kind/hash, OS principal, parent/supervisor identity, profile/home/workspace, model route, toolset, read/write roots, model-transport network policy digest, tool-process network policy digest, MCP process parents, credential-reference capabilities and startup probes. `v1` остаётся обязательным минимумом для implementation WorkOrder; v2 ничего не ослабляет.

### `ProgressCard.v1`

`dispatch_id`, `state`, `completed_steps`, `current_step`, `blockers`, `next_checkpoint`, `evidence_refs`, `resource_usage`; не содержит chain-of-thought/raw logs.

### `ReviewVerdict.v1`

Наследуется: immutable target/spec/evidence hashes, findings с severity/location/proof, checks run, residual risks, verdict и reviewer independence attestation.

## Authority/effect records

### Inherited owner interaction contracts и `DSHDecisionLaunch.v1`

Сокращённые request/event contracts **не определяются**. Без изменений наследуются exact existing `OwnerInteractionEnvelope`/immutable preview/render receipt/Touch ID/`OwnerDecisionEvent` semantics из Codex-root package. DSH получает только `DSHDecisionLaunch`: `decision_request_ref`, safe label, Controller deep-link capability, expiry and non-authoritative display digest. Controller/native trusted renderer заново получает canonical envelope и возвращает exact existing decision event по отдельному authenticated channel. DSH iframe/session/model event, click или displayed bytes не являются render receipt/approval.

### `EffectReceipt.v1`

`action_id`, `idempotency_key`, provider request digest, attempt, provider receipt/ref, outcome=`SUCCEEDED|FAILED|UNKNOWN|RECONCILED`, timestamps и reconciliation evidence.

### `PrivateMemoryRef.v1`

Только `stable_key_hash`, `scope=machine-private`, `kind`, `freshness`, `sensitivity`, `conflict_count`, `available=true|false`, `lookup_capability_ref`; отсутствуют claim/value/path/credential ref contents. Разрешённый helper использует opaque ref внутри Controller boundary и возвращает только separately approved sanitized capsule.

### `MeetingCapture.v1` / `MeetingDigest.v1`

Capture: source/call identity, consent actor/time/evidence, purpose, participant refs, start/end, transcript/source coverage, speaker/time uncertainty, payload refs and retention. Digest: local-PD meeting ref, attributed decisions/agreements/actions/demo/report suggestions, bounded local evidence locators, coverage/classification. Raw transcript, digest and Qwen-derived suggestions остаются в Qwen/LocalPDView, не входят в DSH и сами не approvable/releasable. Outward DSH/tech-base object — новый owner-authored exact text с consumed `DeclassificationDecision` ref/post-scan digest, не MeetingDigest projection.

### `SessionLifecycleRecord.v1`

`session_id`, state=`active|archived|purge_requested|purged_logical|purged_hard|retained_none`, archive/unarchive timestamps, retention class, materialization inventory, per-store erasure receipts and tombstone. Archive reversibly hides only. Delete/purge claims соответствуют минимуму реальных capabilities всех stores.

### `ErasureReceipt.v1`

`store_id`, `object_digest`, `erasure_capability=hard|logical|none`, operation, observed result, residual copies/risks, verifier and time. `hard` требует verified physical/provider semantics; `logical|none` не маскируется словом «удалено».

## Ledgers

| Ledger | Содержимое | Mutation owner |
|---|---|---|
| Admission Ledger | authoritative IngressGateState, source/revision-set/coverage/high-water digests, CloudAdmittedPrompt lifecycle/append+egress receipts, LocalPDDispatch refs | Controller only |
| Work Ledger | specs, work items, graph baselines/deltas, typed order hashes, RunDispatchBindings and dispatch lifecycle | Controller canonical transitions; Codex proposals only |
| Calendar Ledger | demo candidates, external projections, conflicts | Controller; provider write separate |
| Change Ledger | normalized chat/Kaiten/Outlook deltas and cursors | read sidecars through Controller |
| Memory Ledger | candidates, `PrivateMemoryRef`, decisions, Beads operation receipts, expiry | Controller + scoped Beads helper |
| Time Ledger | explicit/derived/provider events and reconciliation | Controller; export effector separate |
| Approval/Effect Ledger | requests, render receipts, decisions, grants, attempts, receipts | Controller/isolated effectors |
| Session/Retention Ledger | archive/unarchive, materializations, erasure capabilities/receipts/tombstones | Controller retention engine |
| Evidence/Audit Ledger | attestations, bundles, verdicts, phase evidence | append-only Controller writer with hash-chain/checkpoints |

## Concurrency/CAS

Каждый transition проверяет current version/hash. Cloud admission CAS, final egress reservation, approval consumption и effect attempt reservation атомарны внутри Controller ledger; cross-store append подтверждается receipt/reconciliation и никогда не объявляется общей транзакцией. Cursor replacement принимает только expected prior cursor. Graph baseline promotion требует matching `from_graph_hash`. Time adjustment создаёт superseding event, не переписывает историю. Duplicate signed admission/effect nonce отклоняется. Ledger hash-chain/checkpoint обнаруживает tamper/reorder/drop; повреждённый segment quarantined и не становится current state.
