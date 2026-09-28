# 14. Решения, конфликты и риски

## Decision register

| ID | Решение | Варианты | Owner / срок | Рекомендация |
|---|---|---|---|---|
| AD-01 | Codex integration | app-server / native interactive / exec batch / Codex MCP under other root | Technical / H0 | app-server stdio/Unix target; native interactive bootstrap |
| AD-02 | Process isolation | native sandbox profiles / containers / hybrid | Technical+Security / H0 | hybrid after app-access probe |
| AD-03 | Cloud auth/data posture | strict API / accepted Codex OAuth / local-only | Data+Security / before cloud real data | inherit stricter existing decision; no assumption |
| AD-04 | First chat source | official API candidates | Product+Security / H6 | dedicated test account, read-only |
| AD-05 | Implementation execution substrate | separate native Codex runtime only; no external worker/orchestrator or root child | `USER DECISION 2026-08-12` | resolved: Controller-launched app-server/`codex exec` implementer; runtime-agnostic WorkOrder, clean home/worktree/workspace-write attestation |
| AD-06 | Declassification | owner-authored only / local model candidate / disabled | Data+Security / H2 | owner-authored only initially |
| AD-07 | Mutation pilot | reply / tech-base / tracker / browser/app | Product+Security / H7 | smallest reversible/reconcilable API effect |
| AD-08 | Preapproved unattended mutations | disabled / narrow policies | Owner+Security / H8 | disabled through pilot |
| AD-09 | Audit integrity/retention | local append-only / hash chain/checkpoints | Security / H5–H8 | metadata journal then reviewed hash chain |
| AD-10 | Memory writes | owner approval / narrow auto-policy / disabled | Data owner / H4 | exact owner approval |
| AD-11 | First official chat adapter | Telegram / enterprise-chat provider integration / another API source | Product+Security / H6 | official API/test account; CUA read not primary adapter |
| AD-12 | Mail/calendar provider | Google plugins / Outlook plugins / disabled | Product+Data+Security / before install/auth | choose one provider family; no parallel broad install |
| AD-13 | Root capability composition | inherit user environment / generated clean profile | Technical+Security / H1 | generated/attested clean profile only |
| AD-14 | User-facing orchestration surface | one Codex-facing interface / multiple component UIs | `USER DECISION 2026-08-12` | resolved: one Codex-facing interface only; Controller retains approval/capability/effect authority; delivery not settled |
| AD-15 | Codex-facing delivery mechanism | personal Codex plugin + Controller MCP/MCP Apps UI / custom local app-server client / blocked | `DECISION REQUIRED / Technical+Security / H0` | preferred plugin only after pinned target Codex desktop render + secure authenticated callback probe; fallback is a new client/UI; otherwise blocked |
| AD-16 | Implementer launch surface | separate native Codex app-server / separate `codex exec` / blocked | `DECISION REQUIRED / Technical+Security / H4` | probe both as needed; never root-spawned child; require clean-home/worktree/workspace-write runtime attestation |

## Explicit conflicts

### C-01: Codex root vs deterministic authority

`USER REQUIREMENT`: Codex root orchestrates. `CONFLICT`: probabilistic model cannot securely own capabilities/commit state. Resolution: Codex owns specification/decomposition/acceptance; Controller owns lifecycle/authorization/effects.

### C-02: broad access vs unattended mutation

`USER REQUIREMENT`: full read-write-browser-app capability. `CONFLICT`: standing broad mutation violates least privilege and exact approval. Resolution: installed/discoverable capabilities may be broad, active grants remain narrow and mutations approval-gated; preapproval is a separate bounded policy.

### C-03: chat monitoring vs context privacy

Monitoring needs raw access; root hygiene forbids raw transcript. Resolution: local raw plane → deterministic DLP/signal compiler → bounded capsule. Root requests targeted excerpt only through policy.

### C-04: PD usefulness vs zero export

Minimal task signal could improve orchestration, but any derived summary leaks information. Resolution: metadata-only default; explicit one-use declassification for exact fields.

### C-05: persistent root vs context rot

Continuity helps decisions, long history degrades reliability. Resolution: one coherent outcome/thread, frozen external spec, bounded evidence and fresh thread reconstruction; compaction non-authoritative.

### C-06: OAuth convenience vs strict privacy

Existing package documents non-equivalence of subscription OAuth and strict API posture. Harness inherits that unresolved decision and prohibits silent route change.

### C-07: one Codex UI vs ambient full authority

`USER REQUIREMENT`: Codex управляет всем через один interface. `CONFLICT`: если UI/model transcript либо built-in Codex approval/input event считать domain authorization boundary, prompt injection или model/tool error получит standing effect authority. `USER DECISION 2026-08-12`: Codex остаётся единственной cognitive/user-facing orchestration surface, но Controller вне probabilistic model независимо проверяет selected delivery binding, immutable preview/render receipt, owner identity, exact approval/capability tuple, kill switch и effect transition. AD-15 отдельно решает, может ли target Codex desktop personal plugin/MCP Apps UI доказать этот callback boundary; иначе нужен custom app-server client либо blocked. Single UI не объединяет trust boundaries.

### C-08: implementer workspace-write vs root child inheritance

Root должен оставаться read-only с `approvalPolicy=never`, тогда как implementer требует isolated workspace-write. Official Codex subagent contract наследует active sandbox/approval posture (SRC-CX-05), поэтому root-spawned child не является допустимым implementer fallback. `PROPOSAL / AD-16`: Controller запускает отдельный native Codex app-server/`exec` runtime (SRC-CX-12, SRC-CX-18) and binds `WorkerRuntimeAttestation`; если отдельная isolation не доказана, dispatch blocked.

## Risk register

| ID | Risk | Likelihood/Impact | Mitigation |
|---|---|---|---|
| R-01 | prompt injection becomes control | M/Critical | data/control separation, typed schemas, no direct dispatch |
| R-02 | PD reaches cloud/tool/log | L/Critical | pre-route sticky gate, no fallback/tools/network, captures |
| R-03 | context pollution causes wrong acceptance | M/High | planes/budgets/artifact refs/independent review |
| R-04 | confused-deputy capability | M/Critical | principal/task/spec/resource/action-bound one-use grants |
| R-05 | worker scope drift | M/High | frozen spec/WorkOrder/ownership/deviation contract |
| R-06 | false evidence or reviewer coupling | M/High | content-addressed artifacts, independent checks/role |
| R-07 | duplicate external effect | M/Critical | CAS, idempotency manifest, UNKNOWN reconciliation |
| R-08 | browser/app UI drift | H/High | exact origin/window/state preview; API preference; block drift |
| R-09 | token/cost runaway | M/Medium | budgets, bounded agents, no silent retry/fallback |
| R-10 | app-server/API version drift | M/High | pinned runtime/generated schemas/contract canary/rollback |
| R-11 | MCP supply-chain or overbroad tools | M/High | pin, required inventory, allowlists, separate effectors |
| R-12 | raw audit/artifact leak | M/High | metadata allowlists, encrypted stores, scoped retrieval/retention |
| R-13 | laptop offline monitoring gap | H/Medium | honest coverage/gap, no 24/7 claim |
| R-14 | owner approval fatigue | M/High | concise exact previews; keep high-risk distinctions; no bundling |
| R-15 | model/provider unavailable | M/Medium | queue/manual/degraded mode; no posture-changing fallback |
| R-16 | broad credential compromise | L/Critical | effect-specific identities/secret refs/revoke drills |
| R-17 | late PD marker bypasses newer cloud derivative | M/Critical | persistent monotonic Gate, gap quarantine, derivative invalidation |
| R-18 | chat sensor directly delegates to Codex | M/Critical | tools deny all, separate authenticated Controller transport |
| R-19 | approval/grant field splicing | M/Critical | full immutable tuple and transactional cross-record digest checks |
| R-20 | global Codex config injects MCP/instructions/read access | M/Critical | generated clean home, explicit allowlists, start/resume attestation |
| R-21 | single UI ошибочно трактуется как full model authority | M/Critical | separate host approval event, Controller tuple enforcement, negative UI/transcript tests |
| R-22 | target Codex desktop не рендерит MCP Apps UI или не даёт secure callback | M/High | AD-15 pinned live probe; custom app-server client fallback; blocked if neither |
| R-23 | stale/misrendered preview или forged display instance binds approval к другим bytes | M/Critical | Controller immutable preview digest, render receipt, exact event tuple/current regeneration |
| R-24 | root-child inheritance leaves implementer read-only or encourages permission escalation | M/High | separate Controller-launched runtime, `root_parent_thread_id=null`, attestation and negative dispatch tests |

## Assumptions requiring evidence

- `ASSUMPTION`: selected Codex auth posture is acceptable for sanitized L0/L1.
- `ASSUMPTION`: first chat platform has official read-only access and usable gaps/edits semantics.
- `ASSUMPTION`: target Mac can meet latency targets under concurrent Qwen/Codex workload.
- `ASSUMPTION`: app-server stable surface remains compatible with pinned Controller-to-Codex integration; verify separately.
