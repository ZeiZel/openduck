# 00. Контекст и цели

## Проблема

`VERIFIED`: репозиторий описывает себя как synthetic-only; текущий Controller имеет durable authoritative store и линейный lifecycle одного `WorkOrder`, а production local Qwen dispatch отключён. DSH уже содержит Cordis seams, registry/control/report для subagents, per-session model selection и one-shot Claude/Codex bridges, но эти seams не являются authority boundary и не дают безопасный cross-provider session mesh.

`USER REQUIREMENT`: нужен единый OpenDuck/DSH experience, где provider выбирается явно, официальная subscription/account modality переиспользуется без scraping, а root может разложить работу на параллельные сессии разных providers.

## Цели

1. Определить provider-neutral session lifecycle и Controller-mediated mesh.
2. Разделить официальную account readiness от model/session orchestration.
3. Сохранить Controller как TCB при selectable cognitive root.
4. Дать одинаковые switching/mesh affordances в DSH и thin native provider plugins.
5. Определить system/tool/effect boundary, не полагаясь на prompt или in-process filter.
6. Сделать зрелость adapter доказуемой по слоям, включая real no-private-data canary.
7. Дать evidence-specific план исправления существующего Ansible deployment path.

## Не-цели

- установка или обновление Codex/Claude/Qwen/Kimi/DSH;
- login, OAuth/device-code ceremony, ввод API key, покупка подписки или top-up;
- обход provider policy, browser-cookie/token scraping или перенос native auth material;
- прямой model-to-model IPC, общий credential store или shared ambient home;
- выдача system effects модели либо превращение DSH/Cordis/toolFilter в TCB;
- production enablement PD/cloud/effects;
- замена существующих Ansible roles новым инсталлятором.

## Измеримый outcome

Пакет считается готовым к implementation planning, когда requirement, contract, provider matrix, phase gates, acceptance cases и sources образуют полный traceability set; конфликт root/fanout имеет безопасный default; ни одна официально не подтверждённая modality не выдана за доступную; Ansible gaps имеют конкретные regression cases.

## Термины

| Термин | Нормативный смысл |
|---|---|
| Provider profile | Immutable selection provider/model/runtime/auth-handle/policy, без credential bytes. |
| Session root | Provider session, получающая owner goal и право запрашивать mesh operations; не technical root. |
| MeshCoordinator | Controller service, владеющий state machine, lineage, leases, budgets и scheduling. |
| SpawnProposal | Bounded untrusted request from model/plugin; не order, binding, grant или authority. |
| MeshToolTransport | Provider-neutral consumer capability с отдельным pinned mapping для каждого provider runtime. |
| ExecutionLimits | Canonical mandatory finite positive limits с явными units/currency; отсутствие означает spawn disabled. |
| WorkspaceGroup | Controller-owned allowlist roots + isolation/concurrency policy. |
| Capability envelope | Явный набор Controller endpoints; не provider-native permission set. |
| Account handle | Opaque reference на provider-owned/isolated auth state. |
| Real canary | Owner-approved test без private data, доказывающий end-to-end modality и recovery. |
| ProviderEvidenceRecord | Signed reproducible URL/date/runtime/claim/digest/freshness evidence; stale record выключает route. |
| ReleaseEnvelope | Signed immutable release/manifest/platform/arch binding с replay protection. |
