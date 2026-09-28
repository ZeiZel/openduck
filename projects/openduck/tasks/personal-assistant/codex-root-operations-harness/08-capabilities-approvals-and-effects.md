# 08. Capabilities, approvals и effects

## Два независимых контроля

`VERIFIED / Codex manual`: sandbox определяет технически возможное, approval policy — когда Codex запрашивает разрешение. Они дополняют, но не заменяют domain authorization. App/MCP destructive calls могут elicitate approval; hooks покрывают не все tool paths.

`PROPOSAL`: domain policy использует **CapabilityManifest → CapabilityGrant → ApprovalRecord → Effector**. Model output никогда не является capability.

## Capability classes

| Class | Примеры | Default |
|---|---|---|
| READ_LOCAL | repo/evidence/tech-base scoped read | task/purpose scoped; no raw PD |
| READ_REMOTE | tracker/chat/calendar/web/app read | explicit account/resource allowlist |
| WRITE_LOCAL | isolated worktree, new Inbox artifact | grant; approval по effect policy |
| WRITE_REMOTE | tracker update, message send, calendar/app write | exact owner approval default |
| BROWSER_READ | navigate/fetch/screenshot allowlisted public/auth session | restricted domains/profile; content untrusted |
| BROWSER_MUTATE | click submit/upload/form/purchase | exact ActionProposal + owner approval |
| APP_READ | read allowlisted window/document | bundle/window/resource scope |
| APP_MUTATE | click/type/launch/change state | exact UI action sequence or typed connector action + approval |
| EXEC_LOCAL | approved commands in task sandbox | command/resource constraints, no credentials |
| NETWORK | exact host/protocol/port/purpose | off by default; no wildcard for privileged route |

## Grant invariants

- principal role **и instance**, task/spec hash, effect type, resource, arguments, TTL, use count обязательны;
- deny wins; revoked/expired/unknown grant fails closed;
- one grant cannot cover read and write credential or multiple effect families;
- session-wide grant запрещён для remote/durable mutation baseline;
- credential is resolved by effector from secret reference; models/workers не читают secret file;
- capability consumption и local action transition — одна transaction/CAS;
- broad installed access inventory не означает broad active grant.

Для owner-authorized mutation grant полный tuple равен `(principal_role, principal_instance, task_id, spec_hash, action_id, action_type, payload_hash, approval_id, nonce, attempt, idempotency_key, reconciliation_policy_digest, resource_scope, argument_constraints, expires_at, max_uses=1, policy_version)`. Перед effect transaction сравнивает каждое поле с current ActionProposal/ApprovalRecord/provider manifest, проверяет global/per-effector kill switch и CAS статусы grant/approval/action. Partial match запрещён; поля нельзя брать из разных approved records.

## Approval modes

1. `owner`: exact authenticated preview каждый раз.
2. `preapproved_policy`: unattended effect только если policy заранее утверждена owner, имеет narrow action/resource/value/time/rate constraints, expiry, audit и kill switch.
3. `deny`: effect class запрещён независимо от model request.

`USER REQUIREMENT`: broad read/write/browser/app access является target capability. `CONFLICT`: broad unattended mutations несовместимы с privacy-first/immutable approval. Resolution proposal: capability installation может быть широкой, active grants узкие; reads постепенно allowlist’ятся, mutations остаются `owner` до отдельного policy acceptance.

Preapproved policy содержит canonical action template digest, immutable fixed fields, explicitly parameterized fields with type/enum/range/regex/length bounds, destination/resource allowlist, aggregate value/rate/time window, idempotency/reconciliation profile, expiry and max executions. Execution canonicalizes concrete payload, proves it is an instance of **одного** template, binds new action/idempotency/attempt tuple and consumes policy allowance atomically. Template/approval/grant field splicing, union нескольких policies и default/unbounded parameter запрещены.

## Exact approval

Controller deterministic renderer создаёт immutable preview bytes из current exact `ActionProposal.canonical_payload`, action type, source, canonical destination/account/thread/resource and `destination_hash`, exact text/fields/file digest/UI step, side effects, provider, risk, expiry и exact reconciliation tuple/digest. `preview_digest` вычисляется по этим bytes и `rendering_version`; UI не пересобирает authoritative preview. Edit, normalization, redirect, attachment replacement, destination/reconciliation/source/policy change invalidates envelope/render receipt/approval.

Owner session в выбранном после AD-15 attested Codex-facing interface требует recent re-auth для mutation, nonce/challenge, CSRF/Origin protection и one-time opaque handle. `OwnerDecisionEvent` связывает interaction, display instance/render receipt, preview/action/payload/destination/reconciliation hashes, nonce/challenge/expiry/policy и recent-auth proof. Controller regenerates current preview and exact-compares весь tuple перед созданием ApprovalRecord; mismatch/stale/invalidated render rejected. `Approve` — authenticated callback event, а не prompt/model/tool action: Controller атомарно consumes grant/approval, затем вызывает typed effector.

## Single UI is not ambient authority

`USER DECISION 2026-08-12`: все suggestions, lifecycle status, approval requests и action previews должны быть видимы owner только в одном Codex-facing interface. Это presentation/orchestration convergence, а не утверждение существующей desktop capability и не объединение trust boundaries. `DECISION REQUIRED / AD-15 / H0`: personal plugin + Controller MCP/MCP Apps UI eligible только после pinned target Codex desktop render/authenticated-callback probe; fallback — custom local Codex app-server client; иначе blocked.

Root и agents не получают grants, credentials или право consume approval. `mcpServer/elicitation/request`, built-in command/file/app tool approvals, `tool/requestUserInput`, tool call/result, UI/transcript text, natural-language «одобряю», suggestion click и root acceptance **никогда** не являются `OwnerDecisionEvent`. Только Controller callback boundary проверяет delivery binding, render receipt, recent auth и exact immutable action/approval/grant tuple непосредственно перед deterministic effector. Root сохраняет `approvalPolicy=never`; OpenClaw, Qwen и implementation worker работают без отдельного user-facing UI.

## Effectors

- `reply.send`: exact message/channel/account/thread; no recipient lookup freedom.
- `techbase.create`: exclusive create under trusted Inbox descriptor; no overwrite/edit.
- `task.mutate`: exact tracker/card/field transition; comment separate effect.
- `calendar.propose`: exact calendar/time/timezone; invitation separate/out of baseline.
- `browser.submit`: exact origin/form/action/body digest; redirect invalidates.
- `app.interact`: exact bundle/window identity and bounded action; UI drift blocks.
- `filesystem.write`: exact root/path/content digest/mode; symlink-safe.

## External outcome

States: `PROPOSED → AWAITING_APPROVAL → APPROVED → CONSUMING → CONSUMED|FAILED|UNKNOWN`. `attempt` начинается с 1 и входит в immutable grant tuple; новый attempt возможен только по bound reconciliation policy и с тем же payload/idempotency key либо новым approval, как требует provider manifest. `UNKNOWN` запрещает automatic retry. Reconciliation использует exact bound provider policy/receipt semantics; если non-delivery не доказана, нужен новый preview/approval. Global `egress_disabled` и `mutations_disabled` проверяются внутри той же local transaction, которая consumes full tuple, непосредственно перед effect.

Cross-splice defense: ActionProposal A, Approval B, Grant C или reconciliation profile D никогда не комбинируются даже при одинаковом task/destination/body. Проверяются exact IDs and digests, not semantic equality.

## Codex controls as defense-in-depth

Root/reviewer/Luna custom agents default `read-only`; Luna/Terra могут быть read-only subagents. Implementer получает `workspace-write` только для owned resources в isolated worktree, без external effect grant, через отдельный Controller-launched native Codex app-server/`exec` runtime; он не является root child и не наследует root posture. Network false unless exact WorkOrder requirement and policy allow it. Root harness всегда использует `approvalPolicy=never`: root не может интерактивно расширить sandbox/tool permissions, а нужный blocked access становится typed ActionProposal или new WorkOrder. Domain owner approval исполняется Controller/Effector вне model turn. App-server events сохраняют thread/turn/item identity, но app-server approvals/user-input/elicitation не являются domain approval. `danger-full-access`, `--yolo`, app-server `thread/shellCommand`, experimental process spawn и session approval exceptions запрещены baseline.

## Clean root runtime

Controller генерирует новый empty Codex home/profile из versioned manifest, не копируя user/global config, auth-adjacent files, MCP, skills, hooks, apps или memories. Static allowlist enumerates every enabled MCP/server/tool, skill path+digest, hook path+digest and app connector; unknown discovery is deny. Sandbox: read-only with explicit restricted readable roots, platform defaults only if attested; network false; no writable root.

At every thread start/resume Controller obtains effective config and returned `instructionSources`, MCP startup/tool inventory and actual read-root/sandbox projection; canonicalizes and compares digests to `RootRuntimeAttestation`. Missing/additional/reordered unexpected source, injected global MCP, new skill/hook/app, broader read root, network enablement, approval policy change or config/schema drift blocks before prompt. Resume never trusts prior attestation without recheck.

## Clean native-agent runtimes

Тот же fail-closed principle применяется к Luna, Codex Implementer и Terra: Controller генерирует role profile, static allowlists, read/write roots and network policy, проверяет effective instruction/tool/MCP/skill/hook/app inventory и связывает instance с task/capsule либо WorkOrder. Luna/Terra могут наследовать только не более широкий read-only posture. Implementer запускается отдельным process identity with clean home, fresh isolated worktree and `WorkerDispatchBinding`; `root_parent_thread_id` должен быть null. Inherited root settings, permission escalation или отсутствие separate runtime attestation блокирует dispatch; workspace writes не дают capability на durable/external effect.
