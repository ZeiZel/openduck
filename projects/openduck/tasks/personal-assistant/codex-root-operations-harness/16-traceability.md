# 16. Трассируемость

Каждый requirement имеет normative design/contract, phase, acceptance test и expected evidence. `H#` ссылается на [roadmap](12-roadmap.md), `AC-#` — на [acceptance suite](13-acceptance-and-security-tests.md). Phase exit запрещён при orphan requirement/evidence.

## Functional requirements

| Requirement | Design / contract | Phase | Acceptance | Required evidence |
|---|---|---|---|---|
| FR-001 | [TaskSignal](03-contracts.md), [sensor flow](06-chat-monitoring-and-fast-answers.md) | H1–H2 | AC-001 | schema validation/fuzz report |
| FR-002 | [Sensor contract](06-chat-monitoring-and-fast-answers.md) | H2/H6 | AC-002, AC-004, AC-035 | adapter capability/gap/revoke report |
| FR-003 | [PD marker/route](07-pd-routing-and-declassification.md) | H2 | AC-005, AC-006, AC-037, AC-038 | marker/restart/sequence fixtures |
| FR-004 | [PD authoritative route](07-pd-routing-and-declassification.md) | H2 | AC-006, AC-007 | model/tool/network capture |
| FR-005 | [Declassification](07-pd-routing-and-declassification.md), [contract](03-contracts.md) | H2 | AC-008, AC-042, AC-043, AC-044 | exact decision/CAS/splice fixtures |
| FR-006 | [TaskSpec](03-contracts.md), [root role](05-agent-roles-and-routing.md) | H1 | AC-012 | canonical hash/version fixtures |
| FR-007 | [WorkOrder](03-contracts.md) | H1/H4 | AC-013 | dispatch linkage report |
| FR-008 | [Luna template](04-context-and-subprompting.md), [routing](05-agent-roles-and-routing.md) | H3 | AC-010 | bounded-answer/escalation corpus |
| FR-009 | [Codex implementer contract](05-agent-roles-and-routing.md), [WorkOrder/worker attestation](03-contracts.md) | H4 | AC-012, AC-014, AC-015, AC-050, AC-052 | clean-home/worktree/sandbox separate-runtime attestation, native-route inventory and scope-drift report |
| FR-010 | [Reviewer role](05-agent-roles-and-routing.md), [ReviewVerdict](03-contracts.md) | H3 | AC-016, AC-017 | seeded review results |
| FR-011 | [Evidence/Review contracts](03-contracts.md) | H1/H3 | AC-016 | acceptance decision fixtures |
| FR-012 | [Lifecycle/recovery](11-observability-recovery-lifecycle.md) | H1 | AC-015, AC-030 | restart/interrupt/recovery report |
| FR-013 | [ActionProposal](03-contracts.md), [effectors](08-capabilities-approvals-and-effects.md) | H5 | AC-020, AC-023, AC-026, AC-027 | per-effect canonical fixtures |
| FR-014 | [Grant contract/model](03-contracts.md), [grant invariants](08-capabilities-approvals-and-effects.md) | H5 | AC-018, AC-019, AC-045 | authorization tuple/concurrency report |
| FR-015 | [Approval modes](08-capabilities-approvals-and-effects.md) | H5/H8 | AC-019, AC-028, AC-046 | policy/template/kill-switch evidence |
| FR-016 | [Exact approval](08-capabilities-approvals-and-effects.md) | H5 | AC-020, AC-021, AC-051 | hash/auth/expiry/preview-render binding fixtures |
| FR-017 | [External outcome](08-capabilities-approvals-and-effects.md) | H5 | AC-022, AC-024, AC-025 | CAS/reconciliation report |
| FR-018 | [Inventory/install plan](09-mcp-utilities-inventory.md) | H0–H4 | AC-029 | version/schema/probe inventory |
| FR-019 | [Store separation](10-memory-techbase-and-tasks.md), [effectors](08-capabilities-approvals-and-effects.md) | H4–H5 | AC-023, AC-032, AC-033 | cross-effect denial/write tests |
| FR-020 | [Root context policy](04-context-and-subprompting.md) | H1/H3 | AC-009, AC-011 | context manifest/budget report |
| FR-021 | [Kill switches](11-observability-recovery-lifecycle.md) | H1/H5 | AC-028 | final-boundary switch test |
| FR-022 | [Audit chain](11-observability-recovery-lifecycle.md) | H1/H5 | AC-031 | signal-to-effect audit reconstruction |
| FR-023 | [Luna escalation](05-agent-roles-and-routing.md) | H3 | AC-010 | ambiguity/policy corpus report |
| FR-024 | [Injection controls](06-chat-monitoring-and-fast-answers.md), [architecture](02-architecture.md) | H2 | AC-003 | adversarial injection report |
| FR-025 | [Ingress choke point](02-architecture.md), [sensor pipeline](06-chat-monitoring-and-fast-answers.md) | H2 | AC-038, AC-039 | cross-ingress equivalence report |
| FR-026 | [IngressGateState](03-contracts.md), [PD sequencing](07-pd-routing-and-declassification.md) | H2 | AC-002, AC-037, AC-038 | monotonic state/gap/replay report |
| FR-027 | [Ingress choke point](02-architecture.md), [PD data rules](07-pd-routing-and-declassification.md) | H2 | AC-039 | attachment/transcript no-cloud capture |
| FR-028 | [Sensor boundary](06-chat-monitoring-and-fast-answers.md) | H2 | AC-040, AC-041 | tool discovery/transport forgery report |
| FR-029 | [Grant tuple](03-contracts.md), [grant invariants](08-capabilities-approvals-and-effects.md) | H5 | AC-019, AC-022, AC-045, AC-046 | full-tuple transaction/cross-splice report |
| FR-030 | [Clean root runtime](08-capabilities-approvals-and-effects.md), [Codex placement](09-mcp-utilities-inventory.md) | H1 | AC-029, AC-030, AC-047, AC-048 | start/resume attestation/isolation report |
| FR-031 | [Single user-facing surface](05-agent-roles-and-routing.md), [delivery binding](03-contracts.md) | H0–H1 | AC-049, AC-053 | pinned target-host/plugin or custom-client delivery feasibility report |
| FR-032 | [Owner interaction/decision contracts](03-contracts.md), [exact approval](08-capabilities-approvals-and-effects.md) | H1/H5 | AC-020, AC-021, AC-049, AC-051 | immutable preview/render receipt/current-tuple negative report |

## Nonfunctional requirements

| Requirement | Design | Phase | Acceptance | Required evidence |
|---|---|---|---|---|
| NFR-001 | [Common contract rules](03-contracts.md), [recovery matrix](11-observability-recovery-lifecycle.md) | H1+ | AC-001, AC-029 | negative/fault suite |
| NFR-002 | [Grant invariants](08-capabilities-approvals-and-effects.md) | H5 | AC-018, AC-019 | least-privilege matrix |
| NFR-003 | [Context planes](02-architecture.md), [PD rules](07-pd-routing-and-declassification.md) | H2 | AC-007, AC-011, AC-039 | network/context/media inspection |
| NFR-004 | [Root context policy](04-context-and-subprompting.md) | H1 | AC-011, AC-030 | long-task/thread isolation report |
| NFR-005 | [Budgets/invalidation](04-context-and-subprompting.md) | H1/H3 | AC-004, AC-009 | coverage/overflow fixtures |
| NFR-006 | [Common schema rules](03-contracts.md) | H0/H1 | AC-001, AC-036 | schema lint/fuzz report |
| NFR-007 | [Lifecycle/recovery](11-observability-recovery-lifecycle.md), [queue source](15-source-register.md) | H1/H5 | AC-015, AC-022, AC-030 | crash/uncertain-commit report |
| NFR-008 | [Metrics/audit](11-observability-recovery-lifecycle.md) | H1+ | AC-007, AC-031 | log allowlist/secret scan |
| NFR-009 | [Route table](05-agent-roles-and-routing.md), [PD/model routing](07-pd-routing-and-declassification.md) | H2/H3 | AC-007, AC-030 | outage/reroute test |
| NFR-010 | [External outcome](08-capabilities-approvals-and-effects.md) | H5 | AC-024, AC-025 | provider semantics/reconcile report |
| NFR-011 | [Success measures](00-context-and-goals.md), [roadmap H3](12-roadmap.md) | H2/H3 | AC-034 | p50/p95/RSS benchmark |
| NFR-012 | [Context budgets](04-context-and-subprompting.md), [metrics](11-observability-recovery-lifecycle.md) | H1/H3 | AC-009, AC-034 | token/cost exhaustion report |
| NFR-013 | [Installation plan](09-mcp-utilities-inventory.md) | H0+ | AC-029, AC-030 | SBOM/digests/schema diff/rollback |
| NFR-014 | [Exact approval](08-capabilities-approvals-and-effects.md) | H5 | AC-020, AC-021 | owner UX/accessibility acceptance |
| NFR-015 | [Retention/purge](10-memory-techbase-and-tasks.md) | H4/H6 | AC-031, AC-035 | retention matrix/purge drill |
| NFR-016 | [Control/data planes](02-architecture.md), [capability model](08-capabilities-approvals-and-effects.md) | H1/H5 | AC-003, AC-018 | authorization boundary review |
| NFR-017 | [IngressGateState](03-contracts.md), [ingress choke point](02-architecture.md) | H2 | AC-006, AC-037, AC-038, AC-039 | crash/monotonic/all-path Gate report |
| NFR-018 | [DeclassificationDecision](03-contracts.md), [declassification](07-pd-routing-and-declassification.md) | H2 | AC-008, AC-042, AC-043, AC-044 | exact-byte/postscan/re-auth/CAS report |
| NFR-019 | [Sensor boundary](06-chat-monitoring-and-fast-answers.md), [deployment units](02-architecture.md) | H2 | AC-040, AC-041 | process/tool/transport isolation report |
| NFR-020 | [Clean root runtime](08-capabilities-approvals-and-effects.md), [Codex placement](09-mcp-utilities-inventory.md) | H1 | AC-029, AC-030, AC-047, AC-048 | effective-config/read-root attestation report |
| NFR-021 | [Single UI authority boundary](08-capabilities-approvals-and-effects.md), [architecture](02-architecture.md) | H1/H5 | AC-018, AC-021, AC-045, AC-049, AC-051 | forged model/tool/UI approval and full-tuple authorization report |
| NFR-022 | [UI feasibility gate](09-mcp-utilities-inventory.md), [delivery binding](03-contracts.md) | H0–H1 | AC-049, AC-051, AC-053 | unsupported-host/callback/render-receipt fail-closed report |

## Goals and sources

| Goal | Requirements | Primary sources |
|---|---|---|
| G-01 Root specification/verification | FR-006–012, FR-020, NFR-004–006 | SRC-CX-02…05, SRC-CX-12…16 |
| G-02 Fast bounded answers | FR-008, FR-023, NFR-005/011/012 | SRC-CX-03…06 |
| G-03 Local PD | FR-003–005, FR-025–028, NFR-001/003/009/017–019 | SRC-OD-05…08, SRC-ENV-02 |
| G-04 Scoped workers | FR-007/009/010/014, NFR-002/007/013/016 | SRC-CX-04/05/09/15/16/18 |
| G-05 Broad controlled effects | FR-013–019, FR-029, NFR-002/010/014/016/018 | SRC-CX-09…11/16, SRC-OD-04, SRC-ENV-02 |
| G-06 Recovery | FR-012/017/021/022, NFR-007/008/010 | SRC-CX-12…16, SRC-OD-10 |
| G-07 Owner provenance/control | FR-016/019/021/022, NFR-008/014/015 | SRC-OD-02…04 |
| G-08 Clean Codex root | FR-030, NFR-020 | SRC-CX-12…16, SRC-ENV-02 |
| G-09 Single Codex-facing interface without ambient authority | FR-015/016/031/032, NFR-014/016/021/022 | SRC-CX-09, SRC-CX-10, SRC-CX-11, SRC-CX-12, SRC-CX-16, SRC-CX-21, SRC-CX-22, SRC-OD-04, SRC-USER-01 |

## Static completeness rule

Validation must establish: every `FR-###`/`NFR-###` defined exactly once in [requirements](01-requirements.md); every ID appears in this file; every referenced `AC-###` exists exactly once; all local Markdown links resolve; no unresolved placeholder markers; source IDs used by normative claims exist in [source register](15-source-register.md).
