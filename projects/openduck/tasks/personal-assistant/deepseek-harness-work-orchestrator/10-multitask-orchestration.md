# 10. Мультитаск-оркестрация

## Роль Codex root

Codex root занимается goal clarification, specification, decomposition, dependency graph, order freeze proposal and review/acceptance synthesis. Каждый safe primary turn Controller напрямую связывает с persistent external Codex app-server thread; DSH general root model отсутствует. Root не получает raw sensor stream, worker reasoning, full logs, provider credentials or standing effect capability.

## Роли

| Role | Назначение | Input | Output | Baseline capability |
|---|---|---|---|---|
| Qwen local | PD/local extraction and answer | `LocalPDDispatch` + encrypted ref | local-only result | no DSH/Codex/tools/network/fallback |
| Luna/read agent | быстрый bounded lookup/analysis/project prep | role-specific `ReadOrder` + `RunDispatchBinding` | schema-bound Answer/PreparationEvidence | read-only allowlist |
| Codex implementer | frozen WorkOrder | WorkOrder + `RunDispatchBinding` + workspace attestation | diff/check EvidenceBundle | isolated task sandbox; exact grants |
| Terra/reviewer | независимая проверка | review `AgentRunOrder` + `RunDispatchBinding` | schema-bound ReviewVerdict | read/test only by default |
| Codex root | spec/plan/acceptance proposal | summaries/status/evidence refs | TaskSpec/WorkOrder/decision proposal | no ambient source/effect access |

Named model availability проверяется live; role semantics не зависят от конкретного slug.

## Dispatch algorithm

1. Canonical goal становится TaskSpec candidate.
2. Controller freeze’ит accepted spec hash.
3. Planner строит DAG typed orders: implementation only — existing `WorkOrder.v1`; Luna/public lookup/project preparation — role-specific `ReadOrder.v1`; reviewer/general orchestration — role-specific `AgentRunOrder.v1`. Каждое задание имеет exact input/output/evidence schemas, roots, network/toolset, dependencies and budgets.
4. Controller создаёт `DispatchRecord(order_kind, order_hash)` и exact `RunDispatchBinding`; поле `work_order_hash` не существует для non-implementer, а cross-kind/profile/schema fields reject’ятся.
5. Scheduler запускает только ready nodes при concurrency/resource/policy permits и single-use binding.
6. `WorkerRuntimeAttestation.v2` проверяет binding/order kind/hash, OS principal, parent/supervisor, profile/worktree/sandbox/MCP/process parents/toolset and separate model/tool network digests; она strict-superset текущей v1.
7. Worker публикует только output/evidence, matching bound schemas/digests; result acceptor повторно проверяет order/binding/runtime, root видит bounded projection.
8. Reviewer не наследует worker conversation и сверяет immutable target/spec.
9. Acceptance/rework/block transitions выполняет Controller.

## Context budgets

Per root turn допускаются: active goals/spec diffs, graph delta, decision queue, concise progress and evidence index. Chat/mail source, test logs, tool streams, generated files и full diffs остаются artifact refs. Overflow не вызывает silent truncation: context assembler откладывает/суммаризует локально и показывает budget error.

## Concurrency/resource policy

- независимость доказывается DAG и non-overlapping workspace/effect domains;
- один writer на repo/worktree/file set или explicit coordination contract;
- Qwen exact route (`40960/32768`, medium thinking where supported) и Codex concurrency ограничиваются benchmark Mac RAM/CPU;
- rate/cost/token budgets per role/task/day;
- no unbounded recursive subagents;
- cancellation/steering не расширяют scope;
- worker, столкнувшийся с неизвестной зависимостью/permission, возвращает blocker.

## Recovery

Dispatch state и authoritative output refs durable. После crash Controller сверяет process/thread/worktree/effect state: безопасно resume, re-dispatch new attempt или quarantine. Stale process не может commit result после lease expiry. Partial filesystem changes остаются evidence и проходят review; destructive rollback не выполняется автоматически.

## Fast operations

Routine read-only operations могут выполняться approved workflow templates: status lookup, test/log inspection, spec comparison, evidence indexing. Template связывает exact tools/scopes/output schema and expiry; он не является wildcard permission.
