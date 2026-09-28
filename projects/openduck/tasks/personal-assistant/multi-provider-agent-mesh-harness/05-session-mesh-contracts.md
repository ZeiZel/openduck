# 05. Контракты session mesh

## Proposal → admission → sealed dispatch

`SpawnProposal.v1` — bounded untrusted data: `client_nonce`, task description/input artifact refs, preferred eligible profile/role, requested output schema ref и requested limits no greater than policy. Parent/root/run/session/attempt отсутствуют: Controller выводит caller и parent exclusively из authenticated `MeshEndpointBinding.v1`. Запрещены любые proposal/order/run/session/attempt/parent/root/lease/reservation IDs, canonical hashes, effective capabilities, account handle, disclosure/fanout grant, authority timestamps, signatures и binding; Controller mint’ит canonical `proposal_id` после decode.

Controller-only `ProposeSpawn` выполняет strict decode/size/schema check, treats all text as data, rereads parent/root/classification/policy/profile/evidence/limits/health, then calls internal `AdmitAndSeal`. Sealer mint’ит authority IDs, reservations/leases and canonical hashes. Adapter start accepts only a sealed object through an unexported/constructor-guarded capability; decoding caller JSON directly into sealed type невозможно. Model-facing tool name `spawn` is an alias to proposal submission, never to adapter start.

## Proposal idempotency

До admission Controller создаёт canonical proposal digest и durable key `SHA256(binding_generation || caller_session_id || caller_attempt_id || client_nonce || proposal_digest)`. Отдельный unique nonce-scope index `(binding_generation, caller_session_id, caller_attempt_id, client_nonce)` хранит accepted digest/key. CAS record содержит `pending|admitted|terminal`, canonical `proposal_id`, resulting run/session refs и response digest. Exact retry того же nonce+digest+authenticated caller возвращает original record/result и не повторяет reservation/start. Тот же nonce-scope с другим digest получает `idempotency_conflict`; другая generation/session/attempt — иной caller scope и не может probe original response. `pending` после crash reconciles before any new start; blind retry запрещён. Retention не меньше максимума configured retry window, max run/recovery window и journal reconciliation window; purge только после terminal+window и durable tombstone.

## `WorkOrder.v2` и binding

Каждый dispatch содержит:

- `order_kind`, `order_id`, canonical `order_hash`, immutable objective/input refs и output schema;
- `root_run_id`, `parent_run_id`, `parent_session_id`, lineage digest и delegation depth;
- exact `profile_id`, provider/model, runtime/protocol attestation и opaque `account_handle_ref`;
- `workspace_group_id`, roots digest, isolation mode и writer lease policy;
- requested/effective `CapabilityEnvelope`, без implicit inheritance;
- exact `ExecutionLimits.v1` и budget reservation ID;
- classification high-water, provenance set, `CloudDisclosurePlan`/`FanoutGrant` refs;
- idempotency key, lease ID/expiry, schema versions и policy version.

`RunDispatchBinding.v2` подписывает/хеширует все поля, которые влияют на authority. Provider-visible prompt получает bounded task content и non-secret binding summary; полный grant остаётся у Controller.

## `ExecutionLimits.v1`

Closed schema содержит обязательные finite positive safe integers: `max_depth`, `max_children_per_parent`, `max_concurrent_runs`, `max_input_tokens`, `max_output_tokens`, `max_wall_ms`, `max_attempts`, `max_result_bytes`. `cost` — discriminated union:

- `monetary`: ISO-4217 `currency`, `minor_unit_exponent`, `max_minor_units > 0`;
- `non_monetary`: `unit=request|token|compute_ms`, `max_quantity > 0`.

Float, NaN/Inf, `unlimited`, missing, zero, negative, unknown currency/unit и overflow reject. Requested limits may only narrow Controller policy. Profile default has `mesh_spawn=false` until explicit limits and current evidence/mapping are bound.

## Mesh operations

| Tool | Input | Result | Authority rule |
|---|---|---|---|
| `listProfiles` | classification, role, workspace group | eligible bounded profiles | directory snapshot only |
| `spawn` | bounded `SpawnProposal` | accepted proposal or sealed run/session ref | tool aliases Controller `ProposeSpawn`; caller cannot seal |
| `spawnBatch` | bounded independent proposals | refs or atomic rejection | Controller-only batch admission/sealing; no partial admission |
| `send` | session ref, message revision | receipt | active lease + classification recheck |
| `steer` | session ref, bounded delta | receipt | cannot widen order/capabilities/budget |
| `wait` | refs, deadline | status projection | no raw transcript |
| `collect` | refs, output schema | result envelopes | provenance/partial status preserved |
| `cancel` | run/session ref, `revision_ref`, `reason_ref` | cancel receipt | user cancellation is idempotent and propagates both refs to adapter/tools |
| `list` | root/parent filter | graph projection | lineage-scoped |
| `status` | ref | state/health/usage | advisory provider state + canonical Controller state |
| `result` | ref, schema | terminal/partial result | exact attempt and provenance |

## Caller→target authorization matrix

Caller identity всегда берётся из verified `MeshEndpointBinding`; target ref — untrusted selector, который Controller разрешает по canonical lineage.

| Operation | Default allowed target | Optional exact grant | Always denied |
|---|---|---|---|
| `listProfiles` | caller self context | none | foreign classification/workspace/root |
| `spawn`/`spawnBatch` | new direct child of caller | none; profile/order policy still required | supplied parent, ancestor/sibling/foreign-root parent |
| `send`/`steer` | caller's direct child | root→descendant only with `control_descendants` bound to exact root/order/operation | self, sibling, ancestor, foreign root |
| `wait`/`collect`/`status`/`result` | caller's direct child | root→descendant with `observe_descendants` exact grant | sibling/ancestor/foreign root; raw transcript |
| `cancel` | caller's direct child | root→descendant with `control_descendants` exact grant | sibling/ancestor/foreign root |
| `list` | self + direct children bounded projection | root descendant projection with `observe_descendants` | ancestor/sibling subtree/foreign root |

Every request rereads target lineage/root, caller binding generation, exact capability/order/policy and target state before action. Knowledge of opaque ID, result ref or root role alone never authorizes. Child cannot receive sibling/ancestor capability through delegation.

Provider cancellation is a closed envelope. `mode=user` requires exact nonempty `revision_ref` and `reason_ref` end-to-end: Controller receipt, `SessionController`, authenticated provider RPC and runtime-driver seam bind the same pair. `mode=start_compensation` permits an empty revision only with exact internal reason `start_commit_failed`; `mode=batch_compensation` permits an empty revision only with exact internal reason `batch_compensation`. No legacy reason-only form, fallback, or arbitrary internal mode exists.

## State machines

```text
Run: proposed -> admitted -> queued -> starting -> running
     -> collecting -> completed|failed|cancelled|uncertain

Session: reserved -> starting -> ready -> active -> draining
         -> closed|cancelled|failed|orphaned

Disclosure: proposed -> granted -> reserved -> consumed|released|uncertain
```

Terminal state не означает effect success. `completed` означает только validated result envelope. Provider reports are inputs; Controller records transition after binding/revision/lease validation.

## Cycle and capacity enforcement

До reservation и непосредственно перед provider start Controller:

1. строит candidate edge parent→child;
2. проверяет parent/root existence и lineage digest;
3. запрещает self/ancestor/duplicate-active edge;
4. проверяет depth/fanout/root+provider+account+workspace concurrency;
5. резервирует token/cost/wall-time/output budgets;
6. проверяет cloud destinations и PD high-water;
7. вычисляет effective capability intersection;
8. выдаёт single-use lease.

9. seals exact order/binding and only then invokes `SessionStarter`.

Batch не partially spawns при admission failure. Runtime partial startup создаёт per-attempt outcomes и compensation; повтор использует новый attempt ID под тем же idempotency key.

## Result contract

`RunResult.v1` содержит `run_id`, `attempt_id`, provider/profile/model attestations, `status`, output/structured artifact refs, schema-validation status, usage (`reported|estimated|unknown`), timestamps, stop reason, provenance, classification, warnings, primary error и compensation error. Raw reasoning, hidden prompts, credentials и unbounded logs не входят.

## Error contract

`MeshError.v1`: `category`, stable `code`, retryability, phase, provider/profile/run/session/attempt refs, safe message, `primary`, optional `compensation`, recovery state и sanitized evidence refs. Unknown provider text становится `provider_failure_unclassified`; stderr никогда не парсится как authority без strict schema.

## Per-session endpoint authorization

`MeshEndpointBinding.v1` bind’ит Controller endpoint ID, audience (`mesh|workspace|process|network|browser|cua|mcp|effect|ui`), root/run/session/attempt, exact tool allowlist digest, authenticated peer identity (mTLS certificate/SPIFFE-like workload identity or OS IPC equivalent), policy version, issued/expiry, rotation generation и nonce range. Credential доставляется broker-to-process through non-model-visible channel, не argv/env/prompt/session log. Request includes single-use nonce + message digest; Controller atomically consumes nonce. Rotation/revoke closes prior generation. Wrong audience, peer, process, session, attempt, expiry, nonce reuse or post-revoke call is rejected and audited without payload.

## Owner-only UI lifecycle

`ui-bind`, `ui-revoke`, `ui-rotate` и `root-close` are closed, digest-bound owner-signed Controller operations, not UI or endpoint capabilities. `ui-revoke` may target an exact child association; `ui-rotate` and `root-close` require the exact root association. Every operation binds revision/trust digests, association digest, session/channel/root/run/attempt/peer, endpoint ID+generation and both operation and endpoint expiry.

For `ui-revoke|ui-rotate|root-close`, Controller first durably records a bounded `PreparedLifecycleEffect` in the provider-revision journal, fenced by exact association and nonce/payload. Only then may it call the mesh lifecycle seam; it revalidates after preparation and immediately again before the callback. The callback result is consumed into exactly one receipt in the same revision-journal CAS. A crash after mesh commit but before that CAS retries the same exact operation; a conflicting association/nonce never reaches the callback. Expired receipts/prepared effects are inert and pruned by a later durable commit. The shared receipt+prepared cap is 256, with 32 reserved slots for monotone `ui-revoke|root-close`; ordinary lifecycle churn cannot consume that reserve.

`LifecycleRootBinding` is a read-only historical lookup for the exact root endpoint generation. It can be used by the owner-only rotate/close path after expiry or revocation, but never authorizes model/UI operations. Rotate returns its sole durable successor on retry; close revokes the exact root lineage. A field or generation mismatch is denied.
