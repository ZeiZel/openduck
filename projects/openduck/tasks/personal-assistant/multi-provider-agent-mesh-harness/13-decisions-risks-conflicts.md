# 13. Решения, риски и конфликты

## Зафиксированные решения и safe defaults

| ID | Attribution | Решение |
|---|---|---|
| D-001 | VERIFIED / inherited | Controller — sole deterministic technical root/TCB; DSH/models/plugins не authority. |
| D-002 | PROPOSAL / safe default | Contract selectable root, runtime default Codex до superseding ADR. |
| D-003 | VERIFIED / inherited | Exactly-one cloud destination default; multi-cloud fanout disabled. |
| D-004 | VERIFIED / inherited | PD sticky и local Qwen only, без cloud/DSH/fanout. |
| D-005 | USER REQUIREMENT | Только official auth/account/subscription/API/local modalities; no scraping. |
| D-006 | PROPOSAL | MeshCoordinator + small consumer-side Go interfaces + manual DI. |
| D-007 | USER REQUIREMENT | Ansible hardening эволюционно улучшает existing roles/installer. |
| D-008 | INDEPENDENT REVIEW / safe default | Model/provider submits only `SpawnProposal`; Controller exclusively admits and seals orders/bindings. |
| D-009 | INDEPENDENT REVIEW / safe default | `mesh_spawn=false` до provider-specific transport mapping, finite limits и fresh evidence. |
| D-010 | INDEPENDENT REVIEW / safe default | UI projection по отдельному Controller channel; DSH AgentLoop/session-log integration disabled до feasibility proof. |
| D-011 | INDEPENDENT REVIEW | Production journal tamper evidence uses protected signed/HMAC independent checkpoints; release uses signed trusted envelope. |
| D-012 | INDEPENDENT REVIEW / safe default | Caller/parent derives only from authenticated endpoint binding; conservative target matrix denies sibling/ancestor/foreign-root control. |
| D-013 | INDEPENDENT REVIEW | Proposal retries use durable caller+generation+nonce+digest idempotency; provider evidence requires pinned technical/security approval trust. |

## Конфликты

| ID | Конфликт | Safe default до ADR |
|---|---|---|
| C-001 | `USER DECISION / 2026-08-12, 2026-08-19`: Codex — sole cognitive root; `USER REQUIREMENT / 2026-08-25`: root selectable между пятью providers. | Codex default и единственный production root; contracts/adapters могут готовиться synthetic. |
| C-002 | Inherited exactly-one cloud egress; `USER REQUIREMENT / 2026-08-25`: root может параллельно вызвать children любых providers. | Один cloud destination; local non-PD children допустимы по policy; multi-cloud требует C-002 superseding ADR + exact plans/grant. |

## Решения, требуемые от человека

| ID | Owner / gate | Решение |
|---|---|---|
| DR-001 | Product owner / P0 | Supersede ли Codex-only root; какие providers допустимы как owner-facing root. |
| DR-002 | Product + Security + Data / P0 | Разрешить ли multi-cloud fanout; destination set, classification, purpose, retention, budget и revoke. |
| DR-003 | Product owner / P0 | Назначить technical, security/privacy и operations approvers. |
| DR-004 | Owner / before P6 per provider | Какую account modality и account alias разрешить для canary; spending/quota cap. |
| DR-005 | Operations / before production | Поддерживать Intel macOS с полной VM matrix или fail-loud объявить unsupported. |
| DR-006 | Data/Security / P2 | TTL/erasure/capture policy для non-PD prompts/results и provider-local transcripts. |
| DR-007 | Product + Security / P0 | Подтверждён ли DSH UI projection path без model/session-log/AgentLoop delivery; иначе утвердить separate Controller UI как постоянную surface. |

## Риски

| ID | Риск | Mitigation / gate |
|---|---|---|
| R-001 | Provider auth/CLI/protocol изменится. | Pin, health/compat probe, downgrade readiness, rollback window. |
| R-002 | Native settings/plugin добавит tools/system prompt. | Isolated clean home, attestation, allowlist, AC-023/024. |
| R-003 | Fanout повторно раскроет данные нескольким clouds. | Exactly-one default, exact plans/grant, atomic reservations. |
| R-004 | Same-UID runtime прочитает чужой provider home. | Separate principal/OS read-deny evidence before P6. |
| R-005 | Rate/quota semantics ложны или неполны. | Source/freshness/unknown; operational canary. |
| R-006 | Parallel writers конфликтуют в workspace. | WorkspaceGroup writer leases/worktrees and bounded concurrency. |
| R-007 | Cancel не останавливает external effects/process. | Controller endpoints, teardown proof, uncertain/reconcile. |
| R-008 | DSH plugin lifecycle становится mutation backdoor. | Proposal-only UI, digest-bound Controller operation. |
| R-009 | Ansible cleanup маскирует primary failure. | Typed primary/compensation, locked journal, fault matrix. |
| R-010 | Manifest v2 expansion разрешит arbitrary artifact. | Closed types, roots/digests/platform/arch validation. |
| R-011 | Real canary использует private data или entitlement без approval. | Fixed synthetic input/workspace and separate owner gates. |
| R-012 | Spec воспринимается как deploy authorization. | NFR-018, README status and P6/P7 explicit approvals. |
| R-013 | Model forged binding bypasses admission. | Proposal-only public API, sealed constructor capability, AC-045. |
| R-014 | Provider exposes mesh tool differently or loses tool-call semantics. | Per-provider mapping/evidence, `mesh_spawn=false`, AC-046/047/053. |
| R-015 | Endpoint credential leaks/replays across children. | Non-model delivery, peer/audience/session/attempt binding, nonce/rotation/revoke, AC-048. |
| R-016 | DSH UI projection becomes model context or wakes AgentLoop. | Separate UI default, DR-007, AC-049. |
| R-017 | Local journal attacker rewrites record and hashes. | Protected HMAC/signature + independent anchor, AC-051. |
| R-018 | Wrong-platform/replayed release is activated. | Signed release envelope + consumed sequence/nonce, AC-052. |
| R-019 | Child guesses target ID and controls sibling/ancestor. | Canonical lineage matrix and exact descendant grants, AC-054/055. |
| R-020 | Lost response causes duplicate child or conflicting nonce reuse. | Durable proposal CAS/idempotency/reconciliation, AC-056. |
| R-021 | Stale evidence is re-signed by unknown/revoked reviewer. | Pinned reviewer roles/keys or exact Controller approval + revocation check, AC-057. |

Unresolved DR не заменяются assumptions. Затронутый route остаётся disabled; остальные safe defaults сохраняются.
