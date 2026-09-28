# 14. Permissions, approvals и effects

## Capability model

Grant связывает:

`principal/runtime_attestation + order_kind/order_hash/RunDispatchBinding + action_type + resource/account/destination + payload_hash + policy_version + TTL + nonce + max_uses + attempt/idempotency + reconciliation policy`.

Capability не следует из DSH tool visibility, model role, OAuth possession, UI button, chat phrase или broad OS permission. Controller проверяет tuple непосредственно перед dispatch и атомарно резервирует use.

## Capability families

| Family | Read | Propose | Effect |
|---|---|---|---|
| Chat | observe allowlisted thread | reply candidate | send/edit/delete/react |
| Kaiten | read watched card/history | change proposal | create/update/move/comment/time-log/delete |
| Outlook Mail | basic read/delta | reply/flag/move candidate | send/reply/move/delete |
| Outlook Calendar | basic read/delta | event proposal | create/update/delete/respond |
| Beads | scoped lookup/status | issue/memory operation candidate | task update, remember/update/forget |
| tech-base | scoped read | note candidate | create/update/purge note |
| Time | read local ledger | adjust/export candidate | provider time-log write |
| Code/project | inspect | WorkOrder/command plan | filesystem write/install/commit/push/deploy |

Delete, permission/admin, credential, publication and destructive filesystem actions are never covered by a general write grant.

## Approval modes

1. `interactive exact`: immutable preview + owner authentication, default for mutations.
2. `pre-approved template`: narrow recurring action with constrained fields/destination/rate/expiry; security review required.
3. `deny`: unsupported/high-risk/ambiguous action.

Model-suggested «approve», DSH transcript/session event, tool response, iframe/overlay click or DSH-rendered bytes are invalid. Exact existing parent `OwnerInteractionEnvelope`/render receipt/Touch ID/`OwnerDecisionEvent` semantics наследуются без сокращения.

## Decision Center

DSH показывает только safe suggestion and launch deep link. Controller-owned native trusted renderer заново получает authoritative envelope and показывает effect type, account/destination, current revision, **все** canonical fields/bytes/diff, attachments, sensitive derivation, risk, policy, expiry and rollback/reconcile behavior. Controller binds one-use nonce, trusted window identity and render receipt. Overlay/clickjacking/background/occluded/stale instance, field splice, edit/regenerate/source/config change invalidate approval.

`PROPOSAL`: Touch ID/local OS auth in native trusted renderer. Exact method is DR-013; until selected, effects remain disabled. DSH never collects biometric result or signs the decision event.

## Effector transaction

1. Resolve current provider identity/revision with read credential or effector preflight.
2. Revalidate kill switch, grant, decision, attestation, payload/destination and freshness.
3. Atomically consume approval/grant and reserve attempt/idempotency key.
4. Effector executes only fixed action schema; no arbitrary URL/method/tool args.
5. Persist provider receipt/outcome.
6. On timeout/ambiguous result mark `UNKNOWN`; block retry until reconciliation.
7. Publish safe status/evidence to DSH.

## Credential separation

Reader and writer registrations/tokens/processes are distinct wherever platform permits. Secret value never входит в DSH, Codex, Qwen, Beads, repo, logs or argv. Controller passes an approved credential-file/keychain reference directly to trusted sidecar. OAuth consent itself is an external state change requiring separate decision.

Before real enablement DR-020 requires a per-runtime threat model and OS-enforced evidence that a malicious DSH plugin cannot read files/env/IPC/process memory or Keychain material, inherit TCC access, attach/debug or invoke raw-store APIs. Separate process/parent tree and opaque credential reference alone do not count.

| Privileged runtime/store | Minimum isolation evidence before P7 real use |
|---|---|
| Codex auth/profile | separate OS principal or proven App Sandbox/read-deny + Keychain ACL; owner-interactive login; DSH has no path/token; model/tool networks separate |
| Graph reader | isolated principal/app container, Keychain ACL, mailbox cache read-deny; no writer token/routes |
| Kaiten reader | isolated principal/container, token Keychain ACL and cache read-deny; mutation routes absent |
| AX/CuaDriver sensor | TCC/Accessibility grant scoped to signed isolated app/principal; DSH cannot inherit/drive it or read capture store |
| Qwen + quarantine/LocalPDView | isolated principal/native IPC, encrypted hard-erasable store read-deny, network/tools/fallback none |
| Beads helper/private stores | isolated helper/principal, path/DB read-deny and capability-scoped operations; DSH sees only PrivateMemoryRef |

Where one mechanism is unavailable, equivalent OS-enforced denial must be demonstrated against the same attack corpus; configuration assertion is insufficient.

## Baseline effects policy

P0–P5: synthetic credentials/auth/network stubs only; all external effects absent. P6: shadow previews only. P7: real read-only source, safe-public network or Codex login is enabled one capability at a time only after its decisions, DR-020 where privileged, DR-022 for public network and explicit owner/security authorization; local acknowledgement/snooze mutates only Controller projection. P8: one reversible effector at a time. No cross-family wildcard.

## Kill switches

Independent final-boundary switches: source ingest, PD local processing, safe-public network, cloud egress, Codex dispatch, worker dispatch, memory writes, tech-base writes, chat send, Kaiten write, Graph mail write, Graph calendar write, time export and all effects. UI state is advisory; final boundary reads authoritative Controller state immediately before call.
