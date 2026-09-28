# 12. Roadmap

Каждая фаза начинается deny-by-default и повышает capability только после documented exit. Принятие спецификации не authorizes installation/accounts/real data/effects.

## H0 — decisions и frozen contracts

Deliverables: owners; all unresolved AD plus recorded AD-05/AD-14 user decisions; AD-15 Codex-facing delivery decision/probe plan and AD-16 implementer launch decision; schemas всех contracts; threat model; context budgets; synthetic corpus; capability taxonomy; source/traceability review.

Exit: pinned live probe proves preferred personal plugin + Controller MCP/MCP Apps UI renders on target Codex desktop and provides secure authenticated callback, **or** fallback custom local app-server client is selected with equivalent test plan; otherwise `UI_DELIVERY_BLOCKED` and implementation cannot proceed. No unresolved P0/P1 spec finding; all FR/NFR mapped; rollback/kill switches defined. Rollback: specification-only.

## H1 — synthetic Controller + Codex root

Implement durable Controller state, TaskSignal/Spec/WorkOrder/Evidence/Review/OwnerInteraction/RenderReceipt/DeliveryBinding schemas, generated clean Codex home/profile, local app-server stdio/Unix client, `approvalPolicy=never`, network false, restricted roots/static allowlists, `RootRuntimeAttestation`, read-only root thread and selected AD-15 Codex-facing delivery adapter, structured outputs, event projection and crash recovery.

Exit: synthetic signal→frozen spec→mock evidence→review; all owner suggestions/status/previews visible only through the selected binding; MCP elicitation, built-in approvals, `tool/requestUserInput`, tool result, prompt/UI transcript and suggestion click cannot synthesize `OwnerDecisionEvent`; render receipt/current preview checks pass; schema fuzz; start/resume attestation; injected global MCP/skill/hook/app and raw-file/broader-root tests block; restart/compaction; no external accounts/network/mutations.

## H2 — OpenClaw sensor + PD hardening

Implement single persistent ingress Gate before every live/historical/retry/media/parser/background path, monotonic per-conversation sequence/scan watermark, encrypted queue, signal compiler, sticky PD/Qwen, metadata-only PDHandled, exact declassification CAS and no-network capture. Create separate OpenClaw sensor process with `tools deny all`; Controller transport is authenticated/nonforgeable and absent from model tools.

Exit: adversarial PD/injection/gap/replay/old-marker-after-new/attachment/transcript suite; sensor tool discovery and `codex_delegate` denied; exact declassification concurrency/splice/provider-swap suite; zero PD/cloud bytes; corruption fail-closed; real accounts still disabled.

## H3 — Luna and reviewer

Create project-scoped native Codex custom agents, restricted read roots/MCP, capsule budgets, Luna bounded Q&A/exploration, Sol/root specification/acceptance and independent Terra review.

Exit: bounded-answer corpus meets accuracy/latency; mutation attempts denied; reviewer catches seeded violations; token budgets enforced.

## H4 — native Codex implementer, memory and task read paths

Capability-probe Controller-launched **separate** native Codex app-server/`codex exec` implementer; choose AD-16 launch surface, generate clean home/role profile, isolated workspace/worktree and task-scoped workspace-write sandbox; prove no root-child inheritance/escalation and attest runtime/binding. Produce evidence artifacts; enable tracker/tech-base/memory purpose-scoped reads. Synthetic writes only inside disposable roots. WorkOrder contract remains runtime-agnostic.

Exit: lease/crash/cancel/scope-drift tests; root-child/inherited posture dispatch denied; separate process/runtime attestation required; no credential reads; concurrent ownership checks; stale capsule invalidation.

## H5 — approval-gated effectors

Implement Capability Broker with full action/approval/nonce/attempt/idempotency/reconciliation tuple, exact preview/hash/TTL/re-auth/CAS, canonical bounded preapproved templates, `reply.send`, `techbase.create`, `task.mutate`, browser/app synthetic effectors, receipts and UNKNOWN reconciliation. Start with mock providers.

Exit: AC-018…028 and AC-043…045 green, full-tuple/cross-splice/template-bound tests, kill switches, no mutation without grant/approval, timeout/replay/cancel races pass. Real mutation requires separate owner enablement.

## H6 — one real read-only source pilot

Select one official channel/test account, capability probe/ToS/admin evidence, bounded backfill/gap/revoke. No real write credential.

Exit: owner accepts coverage/privacy/retention; revoke and purge drill; original Private OpenClaw Phase 2 gates pass.

## H7 — one canary mutation

Separate minimal write credential, one peer/resource, owner approval every action, provider reconciliation evidence. Browser/app mutation remains disabled unless it is the separately selected canary.

Exit: exact destination/payload, ambiguity, idempotency, timeout, revoke and incident drills; residual risk signed.

## H8 — controlled expansion

Add one adapter/effect family at a time; preapproved unattended policy only after synthetic + shadow + owner UX/security acceptance. Supply-chain pinning, SLO, capacity, local encrypted backup decision/restore drill follow existing Phase 8 policy.

## Work-item DoD

Requirement IDs traced; threat/context/capability impact reviewed; versioned schema; positive/negative/fault tests; redacted telemetry; rollback/revoke/purge; artifact evidence; reviewer verdict; no secret/raw PD in repo/log/fixture; owner decision where required.
