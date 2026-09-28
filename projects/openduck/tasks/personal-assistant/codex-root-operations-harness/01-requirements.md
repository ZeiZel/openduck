# 01. Функциональные и нефункциональные требования

## Функциональные требования

| ID | Требование |
|---|---|
| FR-001 | Controller принимает только schema-valid `TaskSignal.v1`, проверяет provenance, digest, classification и freshness. |
| FR-002 | OpenClaw создаёт signals только из allowlisted read scopes и отражает gaps, edits, deletes и coverage. |
| FR-003 | Canonical `Это ПД` и near-miss перехватываются до Codex/cloud; session latch сохраняется после restart. |
| FR-004 | PD route использует только pinned local Qwen, tools none, fallback none. |
| FR-005 | Любой экспорт производного PD-контента требует отдельного `DeclassificationDecision`; default — metadata-only. |
| FR-006 | Codex root создаёт и версионирует `TaskSpec.v1`, затем выдаёт typed freeze proposal; Controller валидирует proposal и выполняет canonical freeze transition, authority определяется `spec_hash`. |
| FR-007 | Каждый dispatch использует `WorkOrder.v1`, связан с frozen spec и одним owner/workspace. |
| FR-008 | Luna получает только bounded `ContextCapsule` и возвращает typed AnswerCard/EvidenceBundle без mutations. |
| FR-009 | Native Codex implementer выполняет только разрешённый WorkOrder в generated clean task profile, isolated worktree и task-scoped sandbox; не меняет scope/spec, а deviations возвращает root. Dispatch использует отдельный probe-attested native Codex runtime, не root-spawned child с inherited read-only/approval settings; WorkOrder semantics не зависят от конкретного model slug или process launcher. |
| FR-010 | Terra/reviewer выполняет независимую проверку против spec и evidence, возвращая `ReviewVerdict.v1`. |
| FR-011 | Root выдаёт acceptance proposal только при schema validity, matching hashes и acceptance evidence; Controller выполняет canonical accept transition. |
| FR-012 | Controller поддерживает start/resume/interrupt/rework/complete и idempotent recovery. |
| FR-013 | Read/write/browser/app операции представлены typed `ActionProposal.v1`, а не свободным текстом. |
| FR-014 | Capability Broker выдаёт principal-, task-, resource-, action- и TTL-bound grants с `max_uses`. |
| FR-015 | Unattended mutation разрешается только явной pre-approved policy; иначе требуется owner approval exact payload. |
| FR-016 | Approval связывает canonical bytes/hash, destination/account, effect type, policy version, TTL и nonce. |
| FR-017 | Grant consumption и action transition выполняются атомарно; ambiguous external outcome становится `UNKNOWN`. |
| FR-018 | MCP/tools обнаруживаются из versioned inventory; отсутствующий required dependency блокирует route. |
| FR-019 | Memory, tech-base и tracker mutations являются разными effect types с разными grants/approvals. |
| FR-020 | Root context assembler применяет per-plane budgets, allowlists и artifact references вместо raw output. |
| FR-021 | Owner может остановить ingest, cloud egress, dispatch и mutations отдельными kill switches. |
| FR-022 | Audit позволяет восстановить путь signal→spec→work→evidence→review→action без raw sensitive body. |
| FR-023 | Fast-answer route эскалирует root при ambiguity, policy question, cross-domain decision или insufficient evidence. |
| FR-024 | Chat-originated instruction никогда непосредственно не вызывает tool, worker или effect. |
| FR-025 | Единый ingress PD gate является обязательным choke point для webhook, polling, history/backfill, retry/replay, attachments, transcripts, parsers и background jobs; обходной ingest path запрещён. |
| FR-026 | Gate хранит persistent monotonic per-conversation sequence/scan state; gap, out-of-order, replay ambiguity или неполная prior scan переводят conversation в quarantine без cloud route. |
| FR-027 | Attachment/transcript сначала local-parse’ится в quarantine, получает class floor L2 и не может формировать cloud capsule либо снижать класс без отдельного approved declassification. |
| FR-028 | OpenClaw chat sensor имеет baseline `tools deny all`, включая запрет `codex_delegate`; Codex request доступен только authenticated Controller transport с nonforgeable request ID и anti-replay state. |
| FR-029 | Owner CapabilityGrant связывает полный execution tuple: `action_id`, `payload_hash`, `approval_id`, `nonce`, `attempt`, `idempotency_key` и reconciliation policy; transaction проверяет tuple и kill switch перед effect. |
| FR-030 | Каждый root start/resume использует generated clean Codex home/profile, explicit static allowlists и attestation effective config/instruction sources/MCP/read roots; mismatch блокирует turn. |
| FR-031 | Один Codex-facing interface является единственной user-facing orchestration surface: через выбранный после AD-15 interface owner получает goals, suggestions, status, approval requests и exact action previews; OpenClaw, Qwen и implementation workers не требуют отдельного пользовательского UI. До успешного pinned host/callback probe delivery route blocked. |
| FR-032 | Controller создаёт immutable preview bytes из exact current `ActionProposal` canonical payload, destination и reconciliation tuple; `OwnerDecisionEvent` связывает current interaction/render instance, preview digest, action/payload/destination/reconciliation hashes, nonce/challenge, expiry, policy version и recent-authenticated approver proof. Любой mismatch или invalidated preview отвергается. |

## Нефункциональные требования

| ID | Требование |
|---|---|
| NFR-001 | Fail closed при unknown schema/class/policy/capability/destination/model route. |
| NFR-002 | Least privilege: права выдаются на минимальный principal/resource/action/time/use scope. |
| NFR-003 | Raw L2/L3 и PD остаются local-only; cloud видит только разрешённый capsule. |
| NFR-004 | Root task isolation: одна coherent outcome на root thread; cross-task recall off by default. |
| NFR-005 | Context budgets детерминированы; truncation/coverage видимы, silent truncation запрещена. |
| NFR-006 | Boundary objects versioned, `additionalProperties: false`, unknown version rejected. |
| NFR-007 | Queue, approvals, capabilities и task state crash-consistent; uncertain commit poisons executor до reload/reconcile. |
| NFR-008 | Operational logs содержат IDs, hashes, state, latency, reason codes; не содержат body, secrets или auth material. |
| NFR-009 | No silent model/provider fallback, если меняется privacy, capability или quality posture. |
| NFR-010 | Every external mutation has idempotency/reconciliation policy; exactly-once not claimed. |
| NFR-011 | Performance targets утверждаются benchmark: initial proposal signal p95 ≤5 s, Luna answer p95 ≤20 s, dispatch start p95 ≤10 s. |
| NFR-012 | Cost/token budgets задаются per route и per task; exhaustion → partial/blocked, не scope reduction. |
| NFR-013 | Dependencies/models/config are pinned, capability-probed and rollback-tested before production. |
| NFR-014 | Accessibility: approval UI показывает readable exact preview, risk, source, destination и expiry. |
| NFR-015 | Audit retention, source retention и durable knowledge retention управляются раздельно. |
| NFR-016 | Controller и effectors не полагаются на probabilistic model output для authorization. |
| NFR-017 | Per-conversation ingest sequencing и PD latch crash-consistent, monotonic и non-bypassable для всех sync/async source paths. |
| NFR-018 | Declassification authority exact-byte-bound, single-use, recent-authenticated, post-scanned и атомарно consumed. |
| NFR-019 | Chat sensor и root runtime разделены process identity/transport; sensor не имеет model delegation или иных tools. |
| NFR-020 | Root execution environment reproducible: clean home, network off, restricted reads, explicit MCP/skills/hooks/apps and fail-closed configuration attestation. |
| NFR-021 | Single Codex UI не предоставляет root/model ambient authority: Controller вне probabilistic model independently validates and consumes exact approval/capability tuple immediately before any effect. |
| NFR-022 | UI delivery fail-closed: undocumented/unsupported host rendering, missing authenticated callback, stale render receipt или ambiguous user-input channel не деградируют в transcript/tool-based approval и блокируют owner decision/effect route. |

## Приоритеты

`USER REQUIREMENT / USER DECISION 2026-08-12`: FR-003…005, FR-014…017, FR-024…032 и NFR-001…003/016…022 являются P0/P1 review invariants. Никакая latency/UX или single-interface цель не может их ослабить. Остальные требования P1 до production, если roadmap явно не относит их к более поздней фазе.
