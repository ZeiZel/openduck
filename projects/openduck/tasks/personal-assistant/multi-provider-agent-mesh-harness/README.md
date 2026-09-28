# Multi-provider Agent Mesh Harness — пакет спецификации

## Карточка

| Поле | Значение |
|---|---|
| Status | controlled implementation in progress; all provider/native routes remain disabled |
| Stable ID | `multi-provider-agent-mesh-harness` |
| Базовая версия | 2026-08-25, Europe/Moscow |
| Целевой substrate | OpenDuck Controller + pinned DeepSeek Harness (DSH) + официальные provider runtimes |
| Authority | `VERIFIED / inherited`: Controller остаётся единственным deterministic technical root и TCB |
| Cognitive root | `CONFLICT`: ранее Codex был единственным root; новый запрос требует selectable root |
| Реализация | P1–P5 code slices are in progress and disabled; this package does not authorize CLI/plugin installation, login/OAuth, credential access, Ansible/runtime mutation, P6/P7 canaries, sudo, or account actions |

## Нормативный результат

`USER REQUIREMENT / 2026-08-25`: довести OpenDuck/DSH до harness, в котором Claude, Qwen, DeepSeek, Codex и Kimi выбираются через официально поддерживаемые account/subscription/API/local modalities; предоставить удобное переключение provider/profile; позволить любой provider session запросить параллельные дочерние сессии любого другого provider; определить взаимодействие моделей с system capabilities; подготовить конкретный план надёжного Ansible-развёртывания.

Спецификация **наследует и не переписывает** [DeepSeek Harness Work Orchestrator](../deepseek-harness-work-orchestrator/README.md) и [Codex-root Operations Harness](../codex-root-operations-harness/README.md). Controller остаётся sole authority для admission, scheduling, capabilities, approvals, effects, audit и recovery. Модель, DSH plugin, native provider CLI и child session не получают ambient authority, чужие credentials или прямой model-to-model process channel.

`CONFLICT / 2026-08-25`: selectable session root несовместим с прежним `USER DECISION`, что Codex — единственный cognitive root. Без superseding owner ADR система поддерживает контракт selectable root, но default/production root остаётся Codex.

`CONFLICT / 2026-08-25`: cross-provider cloud fanout несовместим с inherited exactly-one cloud model egress. Safe default — один cloud destination; multi-cloud fanout выключен до отдельного ADR и требует exact destination-bound `CloudDisclosurePlan` + `FanoutGrant` для каждого получателя. Для PD cloud fanout запрещён всегда: PD идёт только в local Qwen route.

## Инварианты

1. Provider session предлагает работу; Controller единолично решает, создаётся ли run и какие capabilities доступны.
2. Между моделями нет прямого доступа к credentials, homes, процессам, sockets, session stores или tool runtimes друг друга.
3. Mesh API — единственный cross-provider канал: `listProfiles`, `spawn`, `spawnBatch`, `send`, `steer`, `wait`, `collect`, `cancel`, `list`, `status`, `result`; model-facing `spawn*` создаёт только bounded untrusted proposal, а sealed order/binding создаёт Controller.
4. Только Controller превращает `SpawnProposal` в typed `WorkOrder`/`RunDispatchBinding`; caller не задаёт authority IDs, hashes, grants, effective capabilities или seal.
5. Capability не наследуется от parent и не расширяется моделью; child получает независимо вычисленное пересечение policy/grant/provider support.
6. System tools/effects всегда Controller-mediated; provider-native tools отключены, sandboxed либо маршрутизируются только через authenticated per-session capability endpoints с audience/peer/expiry/replay binding.
7. PD остаётся local Qwen, `network=none`, без cloud fallback и fanout.
8. Auth создаётся официальным provider flow в изолированном provider home/principal; Controller видит только readiness и opaque handle.
9. Adapter нельзя называть работающим, пока не пройдены real owner-approved no-private-data canary, reconnect, quota, cancel и failure-recovery tests.
10. Ansible hardening улучшает существующие roles/installer, сохраняет transactional boundary и отделяет primary failure от compensation failure.
11. Mesh spawn выключен, пока для profile нет verified `MeshToolTransport` mapping и explicit finite `ExecutionLimits.v1`.
12. DSH AgentLoop/session log не является default UI projection path: bounded status идёт по отдельному authenticated Controller UI channel.
13. Caller/parent/lineage derive only from authenticated endpoint binding; sibling, ancestor и foreign-root targets fail closed.
14. Proposal retries use durable caller-generation/nonce/digest idempotency and never create a second child after lost response/restart.

## Состав

1. [Контекст и цели](00-context-and-goals.md)
2. [Текущее состояние и разрывы](01-current-state-and-gaps.md)
3. [Требования](02-requirements.md)
4. [Матрица provider access](03-provider-access-matrix.md)
5. [Целевая архитектура](04-target-architecture.md)
6. [Контракты session mesh](05-session-mesh-contracts.md)
7. [Provider adapters](06-provider-adapters.md)
8. [Плагины и UX](07-plugins-and-ux.md)
9. [System interaction и security](08-system-interaction-and-security.md)
10. [Observability, recovery и operations](09-observability-recovery-operations.md)
11. [Ansible hardening plan](10-ansible-hardening-plan.md)
12. [Roadmap и gates](11-roadmap-and-gates.md)
13. [Acceptance и test matrix](12-acceptance-and-test-matrix.md)
14. [Решения, риски и конфликты](13-decisions-risks-conflicts.md)
15. [Реестр источников](14-source-register.md)
16. [Трассируемость](15-traceability.md)

## Definition of Ready

Implementation начинается только после: owner ADR по root/fanout и DSH UI feasibility; назначения product/security/operations owners; freeze `SpawnProposal`, `WorkOrder.v2`, `RunDispatchBinding.v2`, `ExecutionLimits.v1`, mesh/auth/error schemas; reproducible provider evidence records; выбора изолированной task branch/worktree; pinned provider CLI matrix; synthetic contract tests; trusted release envelope и Ansible doctor/transaction schemas; rollback rehearsal. Login, subscription use, API key provision, plugin installation, sudo/become, deployment и real canary требуют отдельных команд и approval.
