# 03. Версионированные контракты

## Общие правила

Все boundary schemas используют JSON Schema 2020-12, `additionalProperties:false`, UTC timestamps, stable IDs, explicit classification/provenance и canonical SHA-256 digest. Unknown version/field is rejected. Text fields имеют byte/character limits и проходят control-character/bidi checks. Locator содержит opaque reference, не credential и не raw query.

## `TaskSignal.v1`

```json
{
  "schema_version": "task-signal.v1",
  "signal_id": "sig_01...",
  "source_ref": "psn_...",
  "source_version": 3,
  "observed_at": "2026-08-12T12:00:00Z",
  "kind": "question",
  "summary": "P-... спрашивает статус утверждённой задачи",
  "facts": [{"key":"topic","value":"release-status","evidence_ref":"ev_..."}],
  "urgency": "normal",
  "max_class": "L1",
  "coverage": {"complete":true,"gap_refs":[]},
  "evidence_refs": ["artifact:sha256:..."],
  "suggested_route": "luna",
  "policy_version": "signal-policy-1",
  "digest": "sha256:..."
}
```

`summary` не содержит commands. `suggested_route` — recommendation, Controller применяет policy сам.

## `IngressGateState.v1`

Обязательные поля: `conversation_scope`, `state_version`, `last_source_sequence`, `last_source_version`, `last_ingest_ordinal`, `scanned_through_sequence`, `prior_scan_complete`, `digest_chain_head`, `mode=normal|pd|quarantine`, `gap_ranges`, `child_parts_pending`, `policy_version`, `updated_at`, `state_digest`. Transition выполняется atomic compare-and-swap по `state_version`. Sequence regression, missing range, conflicting duplicate digest, pending earlier child part или unknown prior watermark запрещают `normal` и cloud eligibility.

Каждый `IngressRecord.v1` содержит `request_id` (nonforgeable random identifier), adapter/account/conversation, provider cursor/sequence/version, assigned ingest ordinal, parent/child relation, media kind, raw digest, received timestamp, prior-state digest и Gate decision/attestation. Request ID проверяется на replay и не выводится из sender-controlled fields.

## `ContextCapsule.v1`

Обязательные поля: `capsule_id`, `purpose`, `task_id|null`, `source_refs`, `facts`, `constraints`, `open_questions`, `coverage`, `max_class`, `policy_attestation`, `token_budget`, `expires_at`, `digest`. Capsule immutable; raw artifact доступен только через отдельно разрешённый evidence read. Для cloud `max_class ∈ {L0,L1}`. `coverage.complete=false` запрещает ответ, утверждающий полноту.

## `TaskSpec.v1`

Обязательные поля: `task_id`, `spec_version`, `title`, `objective`, `in_scope`, `out_of_scope`, `constraints`, `acceptance_checks`, `evidence_required`, `risk_class`, `allowed_effect_types`, `owner_decisions`, `status=draft|frozen|superseded`, `parent_spec_hash|null`, `spec_hash`. Controller при canonical freeze transition вычисляет hash canonical bytes после typed root proposal и required owner decision/policy. Изменение создаёт следующую version; worker не получает draft.

## `WorkOrder.v1`

Обязательные поля: `work_order_id`, `task_id`, `spec_hash`, `role=codex_implementer`, `objective`, `owned_resources`, `context_capsule_refs`, `allowed_tools`, `allowed_effect_types=[]`, `workspace_capability_refs`, `forbidden_actions`, `acceptance_checks`, `evidence_required`, `budgets`, `lease`, `output_schema`, `runtime_constraints`, `profile_manifest_digest`, `sandbox_policy_digest`, `workspace_descriptor`, `worktree_base_ref`, `dispatch_binding_ref|null`. Один WorkOrder имеет одного writing owner. Parallel read-only orders допустимы. Native implementer не получает external/durable mutation effect grant: разрешённые writes ограничены owned resources внутри isolated worktree и enforced sandbox; external effect всегда отдельный `ActionProposal` и deterministic effector. Contract runtime-agnostic: он не фиксирует model slug, executable или launcher. `PROPOSAL / H4 probe`: implementer binding указывает отдельный native Codex app-server/`codex exec` runtime; root child/thread запрещён.

## `EvidenceBundle.v1`

```json
{
  "schema_version":"evidence-bundle.v1",
  "work_order_id":"wo_...",
  "task_id":"task_...",
  "spec_hash":"sha256:...",
  "status":"completed",
  "claims":[{"claim":"AC-... выполнен","evidence_refs":["artifact:sha256:..."]}],
  "change_refs":[],
  "verification":[{"check_id":"check_...","command_ref":"cmd_...","exit_code":0,"output_ref":"artifact:sha256:..."}],
  "deviations":[],
  "residual_risks":[],
  "capabilities_used":[],
  "audit_refs":[],
  "digest":"sha256:..."
}
```

Raw output сохраняется отдельно; bundle содержит bounded summaries и content-addressed refs.

## `ReviewVerdict.v1`

Поля: `review_id`, `task_id`, `spec_hash`, `evidence_bundle_digest`, `reviewer_role`, `verdict=pass|rework|blocked`, `findings[{finding_id,severity,requirement_id,claim,evidence_refs}]`, `missing_evidence`, `independent_checks`, `reviewed_at`, `digest`. `pass` запрещён при unresolved P0/P1 или missing mandatory evidence.

## `ActionProposal.v1`

Поля: `action_id`, `task_id`, `spec_hash`, `action_type`, `principal`, `canonical_payload`, `payload_hash`, `destination_descriptor`, `destination_hash`, `reconciliation_policy_digest`, `effects[]`, `risk_class`, `source_refs`, `required_capability`, `approval_mode=owner|preapproved_policy`, `policy_version`, `expires_at`. `canonical_payload` специфичен для effect type; Controller строит preview из exact canonical payload plus destination/reconciliation tuple.

## Дополнительные authority contracts

### `CapabilityGrant.v1`

`grant_id`, `principal_role`, `principal_instance`, `task_id`, `spec_hash`, `action_id`, `action_type`, `payload_hash`, `approval_id`, `nonce`, `attempt`, `idempotency_key`, `reconciliation_policy_digest`, `resource_scope`, `argument_constraints`, `issued_at`, `expires_at`, `max_uses`, `status`, `policy_version`, `grant_digest`. Credentials не входят. Owner mutation grant требует `max_uses=1`; весь tuple immutable.

### `ApprovalRecord.v1`

Расширяет существующий approval contract: `approval_id`, `interaction_id`, `display_instance_id`, `render_receipt_digest`, `action_id`, `payload_hash`, `destination_hash`, `reconciliation_policy_digest`, `preview_digest`, `rendering_version`, `approver_id`, `recent_auth_proof_ref`, recent-auth class/age, `requested_at`, `approved_at`, `expires_at`, `status`, `policy_version`, `nonce`, `challenge_digest`. Cookie/token/biometric material запрещены. Approval создаётся только из valid `OwnerDecisionEvent`; поля не берутся из transcript/tool result.

### `DeclassificationDecision.v1`

Обязательные поля: `decision_id`, `pd_session_ref`, `input_digest`, `candidate_payload_hash`, `canonical_released_bytes_hash`, `released_fields`, `postscan_attestation{scanner_version,max_class,matched_rule_ids,decision,digest}`, `target_route`, exact `provider_id`, `auth_profile_id`, `retention_profile_id`, `purpose`, `approver_id`, `recent_auth_class`, `recent_auth_age_seconds`, `nonce`, `requested_at`, `approved_at`, `expires_at`, `status=pending|consuming|consumed|rejected|expired|invalidated`, `max_uses=1`, `policy_version`, `decision_digest`. Canonical released bytes сохраняются как immutable artifact; preview и downstream payload строятся из тех же bytes.

Consume выполняется одной transaction/CAS `pending → consuming → consumed` с одновременной проверкой candidate/released-byte hashes, post-scan class/attestation, provider/auth/retention/purpose, owner recent auth, nonce, TTL, status и use count. Любая byte/field/classification splice, candidate regeneration, provider/auth/retention swap, policy/source change или failed postscan invalidates decision; `consuming` uncertainty требует reconciliation и не возвращается в `pending`.

### `RootRuntimeAttestation.v1`

Поля: `runtime_id`, `codex_version`, `clean_home_digest`, `profile_digest`, `effective_config_digest`, ordered `instruction_sources` plus digest, static `mcp_servers`/`skills`/`hooks`/`apps` lists and digests, `sandbox_policy`, `restricted_read_roots` and digest, `network_access=false`, `approval_policy=never`, generated app-server schema digest, `created_at`, `attestation_digest`. Controller сравнивает exact expected attestation на каждом `thread/start` и `thread/resume`; unknown/missing/additional source or capability blocks before turn.

### `WorkerRuntimeAttestation.v1`

Поля: `worker_instance_id`, `work_order_id`, `codex_version`, `agent_role=codex_implementer`, `launch_surface=app_server|exec`, `process_identity`, `root_parent_thread_id=null`, `model_route`, `clean_home_digest`, `generated_profile_digest`, ordered `instruction_sources` plus digest, static tool/MCP/skill lists and digests, `approval_policy=never`, `sandbox_mode=workspace-write`, `sandbox_policy_digest`, `workspace_descriptor_digest`, `worktree_base_ref`, `writable_resources`, `readable_resources`, `network_policy`, `created_at`, `attestation_digest`. Controller сравнивает attestation с `WorkOrder.runtime_constraints` до dispatch и после resume; mismatch блокирует worker. `model_route` и launch surface являются observed runtime metadata, не частью WorkOrder semantics или authority.

### `WorkerDispatchBinding.v1`

`PROPOSAL / H4 probe`: immutable binding содержит `dispatch_binding_id`, `work_order_id`, `task_id`, `spec_hash`, exact `worker_instance_id`, `worker_runtime_attestation_digest`, `profile_manifest_digest`, `workspace_descriptor_digest`, `worktree_base_ref`, `sandbox_policy_digest`, `lease_id`, `bound_at`, `binding_digest`. Binding valid только для отдельного process identity с `root_parent_thread_id=null`; попытка root-spawned child, inherited root read-only/approval posture, sandbox escalation, unknown runtime surface или attestation mismatch блокирует dispatch. После binding фактический runtime записывается в evidence/audit без изменения WorkOrder semantics.

### `OwnerInteractionEnvelope.v1`

Controller формирует typed envelope только для выбранного после AD-15 attested delivery binding. Поля: `interaction_id`, `task_id`, `kind=suggestion|status|approval_request|action_preview|receipt|incident`, `delivery_binding_id`, `display_payload_ref`, `source_refs`, `coverage`, `risk_class`, `action_id|null`, `payload_hash|null`, `destination_hash|null`, `reconciliation_policy_digest|null`, `preview_bytes_ref|null`, `preview_digest|null`, `rendering_version`, `nonce|null`, `challenge_digest|null`, `expires_at|null`, `policy_version`, `controller_attestation`, `envelope_digest`.

Для `approval_request|action_preview` Controller deterministic renderer создаёт immutable `preview_bytes` **только** из current exact `ActionProposal.canonical_payload`, canonical destination descriptor/hash, reconciliation tuple, declared effects/risk/expiry and rendering version. `preview_digest` вычисляется по этим bytes; UI не пересобирает authoritative preview и не нормализует payload. Source/action/policy/destination/reconciliation change invalidates envelope.

### `InteractionRenderReceipt.v1` и `OwnerDecisionEvent.v1`

После фактического render attested adapter возвращает `InteractionRenderReceipt.v1`: `interaction_id`, `delivery_binding_id`, `display_instance_id`, `envelope_digest`, `preview_digest`, `rendering_version`, `rendered_at`, `receipt_digest`. Approval-capable interaction без valid current receipt не принимает decision.

Отдельный authenticated callback создаёт `OwnerDecisionEvent.v1`: `decision_event_id`, `decision=approve|reject`, `interaction_id`, `delivery_binding_id`, `display_instance_id`, `render_receipt_digest`, `envelope_digest`, `preview_digest`, `rendering_version`, `action_id`, `payload_hash`, `destination_hash`, `reconciliation_policy_digest`, `nonce`, `challenge_digest`, `expires_at`, `policy_version`, `approver_id`, `recent_auth_proof_ref`, `received_at`, `event_digest`. Controller regenerates current preview and exact-compares every bound field, current action/policy/source state, render receipt, nonce/challenge/TTL and recent auth before creating ApprovalRecord. Missing, mismatched, replayed, stale or invalidated value rejects and requires a new envelope/render.

`mcpServer/elicitation/request`, built-in command/file/app approvals, `tool/requestUserInput`, tool call/result, transcript/model text, natural-language approval, root acceptance and suggestion click are explicitly non-authoritative and cannot create this event. Root/Luna/implementer/reviewer outputs are proposals/evidence; canonical task state transitions выполняет только Controller.

### `InteractionDeliveryBinding.v1`

`DECISION REQUIRED / AD-15 / H0`: fields `delivery_binding_id`, `kind=personal_plugin_mcp_apps|custom_app_server_client`, exact host/client build and digests, Controller endpoint identity, callback authentication scheme, allowed origins/CSP, UI resource/client bundle digest, rendering version, probe artifact refs, issued/revoked timestamps and binding digest. Personal plugin binding is eligible only after live proof that target Codex desktop renders the MCP Apps component and authenticates direct callback; documentation for ChatGPT/compatible hosts alone is insufficient. Custom app-server client binding represents a separately built local Codex client, not existing desktop UI. No valid binding means interaction route blocked.

## Compatibility

`TaskSignal` ссылается на существующий `InboundEvent`, а cloud capsule может быть преобразован в существующий [SafeEnvelope](../../../../../schemas/safe-envelope.v1.json). `ActionProposal` для reply наследует canonical payload и state machine [approval specification](../private-openclaw-assistant/06-workflows-and-approval-gates.md); несовместимое расширение требует ADR.
