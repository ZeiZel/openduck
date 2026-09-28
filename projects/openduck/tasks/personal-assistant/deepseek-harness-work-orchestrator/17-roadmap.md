# 17. Roadmap и phase gates

Ни один phase не разрешает следующий автоматически; exit фиксирует evidence и explicit promotion. Реальные данные/effects не входят в P0–P6.

## P0 — решения и reproducible research baseline

**Работы:** назначить owners (`DR-001`); freeze spec/schemas/safe defaults; pin DSH tag+full commit and choose fork/distribution ownership (`DR-002`); choose synthetic fixture, branch/worktree and rollback; record no-real-credential/account/non-loopback-provider-network/effect baseline. Future source/effect/backup decisions remain deferred to their own phases and do not block P0.

**Exit:** traceability/static checks pass; DR-001/002 resolved; exact artifact/digest/install-script/lockfile/SBOM work order approved separately; synthetic no-authority baseline attested. Ничего не устанавливается этим phase document.

## P1 — isolated DSH/Controller synthetic substrate

**Работы:** pinned distribution/profile; independent lowest append gate for every cloud path; split `CloudAdmittedPrompt`/`LocalPDDispatch`; snapshot-bound decisions; cross-store `pending→consuming→consumed|uncertain` + append receipt/reconciliation; final authoritative re-read; separate non-session UI channel; general DSH LLM disabled; external Codex protocol/auth/network stub outside DSH; no private MCP/effectors.

**Exit:** POC boots pinned tree; unadmitted input cannot become event; LocalPDDispatch cannot enter DSH/cloud; append-crash and conversation-race fixtures block duplicate/stale egress; UI sentinel absent; exactly one synthetic Codex-stub transport and zero model calls; DSH cannot parent private MCP/Codex/Qwen; Controller unavailable makes UI read-only. If UI cannot remain non-context/non-persistent without general DSH model, P1 blocked by DR-018.

## P2 — PD/local routing and persistence safety

**Работы:** irreversible class high-water; external Qwen sidecar `40960/32768` and medium thinking probe; Controller LocalPDView; strict blank non-prefilled manual owner release editor with fresh auth and all non-manual inputs denied; input/output sentinel scans; injection normalization.

**Exit:** all PD/replay/config-drift/gap/restart/admission-path fixtures pass; zero input/output sentinel outside native PD boundary; no unlatch/history copy; Qwen-derived/prefilled/paste/drop/autofill/AX/AppleScript/synthetic-input release rejected; Qwen failure has no fallback.

## P3 — synthetic source readers

**Работы:** synthetic enterprise-chat/TG/call AX fixture, CuaDriver proxy, manifest-qualified task-tracker webhook/poll, Graph mail delta and calendar `ReadBasic` bounded-poll fixture; coverage/cursors/revoke; public web/Context7 against non-routable synthetic server only.

**Exit:** create/edit/delete/backfill/gap/cursor-loss semantics pass; AX without provider cursor stays `best_effort|unknown`; Outlook conflict fails without scope escalation; synthetic public route denies SSRF/forms/uploads/private payload; reader binaries expose no mutations; no real account/credential/consent/non-loopback network effect.

## P4 — work domains and Command Center read models

**Работы:** demo/calendar projection, WorkGraph/PlanDelta, Kaiten links, Outlook triage, `PrivateMemoryRef`, timers, meeting capture status/coverage projection only while suggestions remain outside DSH, separate owner-authored release path, session archive/purge projection and Command Center routes.

**Exit:** end-to-end synthetic workflow traceable; conflict/stale/classification visible; all durable writes are candidates only.

## P5 — Codex orchestration, workers and review

**Работы:** external persistent app-server **protocol with synthetic auth/network stub only**; no owner login/account/token/cloud call; TaskSpec/WorkOrder + role-specific AgentRunOrder/ReadOrder + DispatchRecord/RunDispatchBinding + v2 attestation; separate synthetic model/tool networks; repository preparation/review fixtures.

**Exit:** malicious DSH plugin cannot read synthetic canary auth/raw-store artifacts or inject second turn; exactly one Codex-stub transport/no real model egress/no duplicated DSH context; model network cannot grant tool egress; cross-kind/schema/evidence binding and review/crash/resume pass. Real Codex owner login/use remains disabled.

## P6 — decisions and shadow effect plane

**Работы:** DSH suggestion launcher + Controller native trusted renderer, inherited exact envelopes/render receipts/Touch ID, per-effect mocks, `UNKNOWN`, kill switches.

**Exit:** all effects point to mocks/non-routable fixtures; forged/replayed/stale previews fail; shadow action diff approved by owner/security.

## P7 — bounded real read-only pilot

**Prerequisites:** common DR-001/004/011/014/020; DR-012 only when selected source may reach real Codex; **только выбранные source decisions**: enterprise-chat/TG → DR-003, Outlook → DR-005/007, task-tracker → DR-006, meeting/call → DR-019, public web/Context7 → DR-022. DR-020 must evidence OS-enforced isolation for every selected credential/raw-store runtime. Real-data/network/Codex-login owner+security authorization, retention/purge drill, least scopes and source/admin/ToS evidence remain required.

**Работы:** подключить **один** source/capability at a time, read-only. Real Codex owner-interactive login/use starts only here after DR-020 and explicit authorization. If safe-public selected, enable its dedicated network profile, run live GET/navigation/SSRF/private-net/form/upload/credential/backpressure conformance, prove immediate revoke/kill switch, and scan zero private payload. No reply/provider/memory/tech-base writes unless separately promoted.

**Exit:** pilot SLO/privacy/coverage and owner usefulness accepted; sidecar isolation attack suite, disconnect/revoke/purge proven; safe-public network (if selected) has bounded live capture and successful revoke.

## P8 — one-effector-at-a-time enablement

Кандидат начинается с reversible local write: для PD/meeting tech-base это только strict owner-authored exact release после consumed DeclassificationDecision, затем create-only Inbox effect. Далее отдельно Beads update, Kaiten/time/calendar/reply effects. Для каждого: dedicated credential/process, exact preview, idempotency/reconciliation, negative destination tests, owner/security approval and rollback.

## P9 — hardening and operations

Supply-chain/update automation with manual promotion, signed artifacts, long-run/load tests, expiry/purge/on-call playbooks, accessibility, disaster drills and optionally local encrypted backup only after DR-015.

## Минимальный product slice

P1–P5 synthetic: safe task + synthetic chat/call/Kaiten/Outlook/public-doc changes → snapshot-bound CloudAdmittedPrompt/crash-safe append → separate UI calendar/graph → Codex protocol stub + typed binding → evidence/reviewer; `Это ПД` uses only LocalPDDispatch/Qwen/LocalPDView. No real credentials/accounts/login/non-loopback provider network/effects.
