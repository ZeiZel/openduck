# 05. Роли и маршрутизация

## Role registry

| Role | Назначение | Default model/runtime | Default permissions | Не может |
|---|---|---|---|---|
| Codex Root | specification, decomposition, synthesis, acceptance; single user-facing orchestration | Sol / demanding clean Codex profile | read-only; proposal/UI presentation tools | credentials, approval consumption, direct effect |
| Terra Reviewer | complex/security/cross-cutting review | Terra, high reasoning | read-only, targeted evidence | implement in same review |
| Luna Fast | frequent bounded answers and bounded exploration | Luna, medium/low | restricted read-only | mutate, broaden scope |
| OpenClaw Sensor | monitor/correlate allowed chats | local runtime | channel read only | cognitive root, send/write |
| Qwen PD | local PD response/classification | pinned qwen3:8b | tools none, no network | cloud/fallback/export |
| Codex Implementer | execute frozen WorkOrder | separate native Codex app-server/`exec` runtime, probe-gated | generated clean profile, isolated worktree, workspace-write task sandbox | author/freeze/accept spec, external effect, inherit/escalate root permissions |
| Effector | exact typed mutation | deterministic code | one credential/action family | generate or choose intent |
| Owner | goals, decisions, approvals | human | selected attested Codex-facing interface | approval delegated by chat/model/tool/built-in approval events |

`VERIFIED`: current Codex manual classifies Luna as fast/narrow/repeatable, Terra as efficient read-heavy/supporting worker and GPT-5.6/Sol-class route as demanding multi-step reasoning. Exact available model slug is capability-probed at runtime; remembered/configured name alone does not prove availability.

## Deterministic route table

| Condition | Route |
|---|---|
| canonical PD marker or near-miss/sticky PD state | Qwen local or quarantine |
| single-domain factual question, capsule complete, no policy/decision/effect | Luna |
| ambiguous goal, cross-domain work, spec change, conflict, owner decision | Codex Root |
| frozen implementation/operation WorkOrder | separate native Codex Implementer runtime selected by attested capability manifest and `WorkerDispatchBinding` |
| completed/partial execution, security-sensitive or cross-cutting result | Terra Reviewer |
| exact approved typed action | corresponding deterministic Effector |

Model may suggest route, but Controller validates it. Route mismatch, model unavailable or missing required MCP → `ROUTE_BLOCKED`; there is no silent fallback across privacy/capability classes.

## Escalation from Luna

Luna sets `needs_escalation=true` when any of these hold: capsule incomplete/stale; more than one plausible interpretation; user commitment/deadline/policy decision; cross-domain identity merge; proposed mutation; L2/L3; evidence conflict; answer requires more than bounded context. Controller creates/updates a root task without copying Luna’s hidden reasoning.

## Dispatch constraints

- Root may parallelize independent read-only exploration.
- Parallel writes require separate isolated resources/worktrees and single ownership per file/resource.
- Luna and Terra may run as explicit read-only subagents. Implementer never uses a root-spawned child: Controller launches a separate generated native Codex runtime with isolated workspace-write sandbox; inherited root read-only/approval settings, escalation and attestation mismatch block dispatch.
- Worker model selection/runtime identity are recorded in `WorkerDispatchBinding` and EvidenceBundle/audit metadata, not used as WorkOrder authority.
- No worker spawns an unregistered nested worker unless WorkOrder explicitly permits bounded delegation.

## Codex implementer contract

`USER DECISION 2026-08-12`: bounded implementation выполняет dedicated native Codex worker, а не внешний orchestrator. `PROPOSAL / DECISION REQUIRED / AD-16 / H4`: Controller запускает отдельный app-server либо `codex exec` instance, создаёт clean generated implementer home/profile/worktree/workspace-write sandbox, проверяет process identity/config/capability attestation и требует machine-readable status/artifact refs. Это не root subagent: официальный permission model наследует current parent sandbox/approval settings (SRC-CX-05), тогда как separate `codex exec` имеет explicit sandbox surface (SRC-CX-18). Model slug или launch surface может меняться после capability probe без изменения spec semantics; отсутствие required isolation, output schema, cancellation или identity binding оставляет route blocked.

## Single user-facing surface

`USER REQUIREMENT / USER DECISION 2026-08-12`: owner взаимодействует только с одним Codex-facing interface. Root orchestrates and explains; Luna/implementer/Terra/Qwen/OpenClaw не имеют отдельного обязательного user UI. Delivery mechanism не предрешён: preferred personal plugin + Controller MCP/MCP Apps UI допускается только после target-host/render/callback probe; fallback — custom local Codex client на app-server; иначе route blocked. Controller принимает `OwnerDecisionEvent` только по attested callback вне model prompt. Поэтому единый интерфейс не расширяет полномочия root, subagents, transcript или built-in Codex approval/input mechanisms.

## Separation of duties

- Author создаёт draft/freeze proposal; owner decision или утверждённая policy разрешает freeze, а canonical transition выполняет Controller.
- Implementer не является единственным reviewer.
- Reviewer не потребляет mutation grant.
- Root acceptance не является owner approval external effect.
- Capability issuer не хранит destination credential; effector resolves credential reference internally.
