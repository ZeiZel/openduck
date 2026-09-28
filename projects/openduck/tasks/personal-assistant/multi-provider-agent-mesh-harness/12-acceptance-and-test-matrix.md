# 12. Acceptance и test matrix

## Contract и migration

| ID | Level | Acceptance |
|---|---|---|
| AC-001 | Contract | Model/DSH/provider cannot commit lifecycle/capability/approval/effect state; Controller is sole writer/validator. |
| AC-002 | Contract | Selectable root schema accepts five providers; unresolved ADR keeps Codex default and blocks silent alternate root. |
| AC-003 | Contract | Provider profile rejects credential bytes, unknown modality/version and non-opaque account handle; readiness ladder preserved. |
| AC-004 | Contract | All 11 mesh operations validate exact schemas; model-facing spawn accepts only bounded proposal, then Controller alone admits/seals binding, lease/idempotency, classification and provenance. |
| AC-005 | Synthetic | Fake adapters prove start/stream/send/steer/wait/collect/cancel/reconnect/terminal result semantics. |
| AC-006 | Property | Generated graphs cannot create self/ancestor/cycle/duplicate-active edges; restart replay preserves lineage. |
| AC-007 | Property | `ExecutionLimits.v1` rejects every missing/zero/negative/unbounded/overflow/unknown-unit or widening depth/fanout/concurrency/token/cost/wall/output/retry value before dispatch and releases reservations safely. |
| AC-008 | Security | Child receives independently computed capability intersection; parent grant/approval/network/credential cannot propagate. |
| AC-009 | Security | WorkspaceGroup roots and audience/peer/session/attempt-bound endpoints deny cross-root, cross-session, browser/CUA/MCP/network/effect escalation. |
| AC-010 | Security | PD input/result uses local Qwen only; every cloud/fanout/DSH projection attempt is denied with no payload leak. |
| AC-011 | Contract | One cloud destination default enforced; exact plans/grant allow only named recipients and invalidate on source revision/class bump. |
| AC-012 | Go unit | Small interfaces, manual DI, context cancellation and closed error categories compile/test under Go 1.26. |
| AC-013 | Migration | v1 snapshot/order replays into additive v2 refs; dual-read, crash recovery, orphan detection and read-only rollback pass. |

## Synthetic adapters и pinned compatibility

| ID | Level | Acceptance |
|---|---|---|
| AC-014 | Compatibility | Pinned Codex CLI/app-server fixture passes official login-state probe, start/stream/cancel/schema/teardown without exposing auth. |
| AC-015 | Compatibility | Pinned Claude Code/SDK fixture passes stream/final/schema/cancel/teardown; ambient settings/tool drift blocks readiness. |
| AC-016 | Compatibility | Qwen Coding Plan/API/local fixtures pass headless protocol; discontinued OAuth absent; PD/general isolation proven. |
| AC-017 | Compatibility | Kimi OAuth/API fixture passes device-flow state projection, session/interrupt/resume/quota parsing without token export. |
| AC-018 | Compatibility | DeepSeek API fixture requires key ref and exact endpoint/model; no subscription profile/plugin is advertised. |

## DSH/plugins/UX и security

| ID | Level | Acceptance |
|---|---|---|
| AC-019 | DSH contract | Cordis/subagent/model-selection/read-bridge seams are adapters only; direct state/capability mutation fails and absent UI feasibility decision leaves DSH integration unmounted. |
| AC-020 | UI | All Controller-owned packages render synthetic profiles/graph/policy/diagnostics and remain disabled until exact lifecycle operation. |
| AC-021 | UI | Switching provider creates a new immutable session revision, shows capability/destination/quota deltas and cannot change an active turn. |
| AC-022 | UI/schema | Graph/compare/synthesis preserves failed/partial attempts, provider provenance and source coverage under bounded outputs. |
| AC-023 | Security | Unattested native/project/user system instructions or plugins block start; bound sections reproduce exact prompt digest; UI projection is absent from prompt/session log. |
| AC-024 | Security/fault | Provider-native tools and ambient MCP/network/process paths cannot bypass Controller endpoints under malicious prompts/plugins. |
| AC-025 | Observability | JSONL has run/session/provider/attempt correlation and safe enums; secret/raw prompt/token/stdout/stderr canaries never appear. |
| AC-026 | Retention | Encrypted artifacts enforce TTL/class scope and honest hard/logical/none erasure receipts; PD artifacts never enter DSH. |
| AC-027 | Fault injection | Auth expiry, quota, lost ACK, disconnect, cancel failure, tool uncertainty and restart produce specified recovery without blind retry. |
| AC-028 | Metrics | Health/quota/rate/latency/usage/cost expose source/freshness/unknown; incomparable values are not falsely aggregated. |

## Ansible

| ID | Level | Acceptance |
|---|---|---|
| AC-029 | Read-only/macOS | `diagnose.yml`/`--doctor-json` make no state/network/login change and report fixed-root/platform/arch/bundle/gates safely. |
| AC-030 | Schema/fault | Typed error parser accepts only exact bounded v2 JSON, preserves primary+compensation and safely handles malformed/empty/contaminated stderr. |
| AC-031 | Concurrency/fault | Concurrent deployments get unique IDs/locks; journal survives crash, and mutate+rehash cannot verify without protected signer and independently anchored latest checkpoint. |
| AC-032 | Schema/security | Full plan/release envelope rejects extra/missing/wrong typed fields, unsafe root/target, duplicate artifact, symlink/hardlink, unknown key, replay and digest/platform/arch/precondition mismatch. |
| AC-033 | Static/macOS | No play-wide become/example vars; each privileged task is exact; stale key chown and unsafe fixed root fail before mutation. |
| AC-034 | macOS | candidate/activated/failed/rolled-back and four gates are coherent; `activation=false` performs real scoped verify; pointer/marker crash points recover. |
| AC-035 | Fault/macOS | Cleanup/rollback never mask primary; unavailable/failed/performed rollback has explicit diagnostics and retry state. |
| AC-036 | Regression | Fixtures pass for dseditgroup 67, unsafe root, stale key chown, malformed stderr, policy migration, contaminated PF restore, loaded+disabled launchd, masked activation and concurrency. |
| AC-037 | CI/VM | ansible-lint/yamllint/schema/contracts/simulator/fault/secret gates pass; privileged Apple Silicon VM passes fresh/idempotent/upgrade/failure/rollback/retry/concurrent scenarios. |

## Owner-approved real no-private-data canaries

| ID | Level | Acceptance |
|---|---|---|
| AC-038 | Real canary | Codex subscription/API modality separately passes turn, reconnect, quota/rate, cancel/quiescence and failure recovery. |
| AC-039 | Real canary | Claude eligible account/API modality separately passes the same operational suite. |
| AC-040 | Real canary | Qwen Coding Plan/API/general-local modality separately passes the suite; PD remains excluded from cloud canary. |
| AC-041 | Real canary | Kimi membership OAuth/API modality separately passes the operational suite. |
| AC-042 | Real canary | DeepSeek API-key/top-up route passes the operational suite; status remains API, not subscription. |
| AC-043 | Specification | Automated checker proves exact FR/NFR trace rows, every AC/source referenced, all local links resolve and forbidden placeholders absent. |
| AC-044 | Lifecycle/security | Provider/plugin/deployment enable/disable/update/rollback requires exact digest-bound Controller operation and preserves audit/revoke evidence. |

## Independent-review negative and compatibility gates

| ID | Level | Acceptance |
|---|---|---|
| AC-045 | Contract/security | Crafted proposal containing order/run/session/lease/reservation IDs, hashes, effective capability, disclosure grant, seal or binding is rejected; caller cannot reach adapter start or reuse another sealed dispatch. |
| AC-046 | Per-provider compatibility | Codex, Claude, Qwen, Kimi and DeepSeek each separately pass pinned `MeshToolTransport` start→tool exposure→proposal→sealed spawn→collect/cancel mapping; one provider’s mapping cannot satisfy another. |
| AC-047 | Negative/default | Missing/partial/stale mapping, evidence record or limits keeps exact profile `mesh_spawn=false`; health or ordinary turn success cannot override it. |
| AC-048 | Security/replay | Endpoint credential copied to sibling process, another session/attempt/audience, reused nonce, expired/old generation or post-revoke request is rejected before payload processing; credential bytes absent from model/log/argv/env. |
| AC-049 | UI feasibility | With DSH integration absent or malicious, separate Controller UI renders bounded status while model prompt, DSH session event log and AgentLoop receive zero projection bytes/events/turn wakeups. |
| AC-050 | Limits/schema | Monetary currency/minor-unit and non-monetary unit semantics round-trip canonically; missing/unbounded/float/NaN/Inf/overflow/unknown values and policy widening fail closed. |
| AC-051 | Journal tamper evidence | Modify any historical journal entry and recompute all local hashes: verification still fails against protected HMAC/signature and independent anchor; missing/stale/wrong-generation checkpoint blocks promotion. |
| AC-052 | Release trust | Unknown/revoked signing key, bad signature, expired/not-yet-valid/replayed sequence/nonce, or manifest/release/platform/arch/artifact mismatch rejects before first privileged mutation. |
| AC-053 | Evidence freshness | Reproducible P0/P4 record captures exact URLs/date/runtime/claim mapping/source+artifact digests/freshness; stale/missing/digest-mutated evidence atomically disables affected profile/mesh spawn. |
| AC-054 | Foreign-parent security | Proposal carrying any parent/root/run/session/attempt selector, or request from a binding whose authenticated caller differs from canonical parent, is rejected before proposal ID/reservation; no foreign lineage existence oracle. |
| AC-055 | Target authorization | For every mesh operation, generated/self/direct-child/descendant/root/sibling/ancestor/foreign-root cases match the matrix: child never controls sibling/ancestor, and root descendant observation/control requires exact operation-bound grant. |
| AC-056 | Idempotency/crash | Same authenticated generation/session/attempt + nonce + canonical digest concurrently or after crash returns original proposal/run and starts once; same nonce with different digest rejects; retention/reconciliation prevents duplicate after restart. |
| AC-057 | Evidence trust | Profile revision rejects unknown/revoked reviewer key, missing technical/security approval, wrong role/profile/freshness binding, approval-record mismatch and any record digest mutation before changing `mesh_spawn`. |
| AC-058 | Lifecycle/restart | Owner-signed `ui-revoke|ui-rotate|root-close` use exact prepared/receipt fencing across both journals; expiry reaches zero callbacks, shared 256-slot receipt/prepared capacity preserves 32 safety slots, crash retry converges, and a restarted running provider child stays unavailable until an explicit durable route-recovery proof exists. |

Canary data: fixed public synthetic prompt, empty/synthetic workspace, no private source/account content, no write/network/browser/CUA/effect capability. Login/account connection, spend and canary each require separate owner authorization.
