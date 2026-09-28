# 08. System interaction и security

## System prompt assembly

Controller связывает `SystemPromptBinding.v1` с profile/order/policy/workspace/capability/schema digests. Sections:

1. immutable role и scope;
2. classification/provenance rules;
3. available mesh/capability tool schemas;
4. budget/deadline/output contract;
5. untrusted-content framing;
6. exact completion/evidence semantics.

Provider-native global/user/project instructions не наследуются ambiently. Они либо отключены clean home/profile, либо enumerated, hashed, classified и allowlisted. Repository instructions являются untrusted configuration input до Controller policy; prompt не может выдать authority.

## Capability calculation

```text
effective = requested
          ∩ order_allowlist
          ∩ profile_support
          ∩ workspace_group_policy
          ∩ classification_policy
          ∩ owner_grant
          ∩ live_health_constraints
```

Пустое/unknown поле означает deny. Parent envelope не участвует как grant. Approval binding включает exact tool/effect, arguments digest, destination, run/session/attempt, policy version, expiry и single-use nonce.

## Разделённые capability planes

| Plane | Примеры | Boundary |
|---|---|---|
| Workspace | read/write roots, worktree lease | verified roots + path-safe broker |
| Process | build/test command allowlist | subprocess broker; no shell interpolation |
| Network | model transport, public docs, private service | отдельные endpoints/egress policies |
| Browser/CUA | navigation, UI control | isolated session + exact targets/approvals |
| MCP | mesh, docs, domain services | per-session allowlist; no ambient servers |
| Effects | send/write/deploy/account/plugin lifecycle | Controller transaction + receipt |

Provider built-in shell/fs/web/MCP/agent tools disabled in clean profile, sandboxed без authority либо configured to call only the per-session endpoints. ACP `mcpServers: []`, in-process toolFilter и same-UID permissions не считаются достаточным security boundary.

## Endpoint authentication

Controller mint’ит short-lived audience-bound credential только после sealed dispatch. Credential передаётся через broker-owned private IPC/file descriptor/mTLS bootstrap или эквивалентный OS-authenticated channel, недоступный model input, tool output, argv, inherited env, DSH/session log и workspace. Peer presents workload/process identity; Controller проверяет exact root/run/session/attempt, audience, tool digest, policy generation, expiry и atomic single-use nonce. Rotation advances generation and closes old channel; cancel/revoke atomically rejects unused nonces and new streams. Copy credential/channel descriptor в sibling process, другую session/attempt или другую audience не проходит peer/binding check.

UI projection использует отдельные credential/audience/schema и не имеет mesh/tool capabilities. Default UI channel не append’ит projection в model prompt, DSH session event log или AgentLoop inbox и не вызывает turn.

## Credential isolation

- one provider/account handle → one isolated home/principal/ACL set;
- Controller/DSH/model sees alias/readiness only;
- no provider home mounted into another provider runtime/workspace;
- environment credential variables scrubbed; explicit broker injection bypasses argv/log/prompt;
- browser cookies/session storage не читаются и не экспортируются;
- logout/revoke/expiry invalidates new reservations; active sessions move to draining/cancel policy.

## Cloud disclosure и fanout

`CloudDisclosurePlan.v1` bind’ит exact payload/event revisions, classification high-water, destination provider/account/model, purpose, TTL и policy version. `FanoutGrant.v1` перечисляет exact plan IDs; wildcard provider/account/model запрещён. Reservation consumed atomically per destination. Новый edit/backfill/gap/class bump invalidates all unused plans.

Safe default: одна cloud reservation. PD/L3 route rejects every cloud plan before adapter selection. Compare/synthesis across cloud results обрабатывает только already-admitted bounded outputs с собственной classification.

## Threat cases

| Threat | Required control |
|---|---|
| Prompt asks for another provider token | schema has opaque handle only; filesystem deny |
| Child recursively spawns root/ancestor | lineage/cycle check before reservation and dispatch |
| Provider-native plugin invokes shell | clean profile + no native tool, Controller endpoint only |
| DSH plugin widens toolFilter | Controller ignores DSH filter as authority |
| Child copies endpoint credential | peer/session/attempt/audience binding + nonce consumption rejects cross-process replay |
| UI projection leaks into model log | separate UI channel; no AgentLoop/session append; feasibility gate blocks DSH mount |
| Multi-cloud duplicate disclosure | exact plan+grant+atomic reservations |
| Cancellation leaves process/tools alive | bounded teardown + quiescence proof or uncertain |
| Project config overrides system prompt | clean home/attested allowlist; unknown blocks |
| PD marked after first event | sticky high-water invalidates cloud reservations |
