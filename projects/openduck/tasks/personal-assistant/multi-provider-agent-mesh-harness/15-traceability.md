# 15. Трассируемость

Одна строка соответствует одному requirement ID из [requirements](02-requirements.md). Phases определены в [roadmap](11-roadmap-and-gates.md), acceptance — в [test matrix](12-acceptance-and-test-matrix.md), sources — в [source register](14-source-register.md).

## Functional requirements

| Requirement | Design / contract | Phase | Acceptance | Sources |
|---|---|---|---|---|
| FR-001 | [Authority model](04-target-architecture.md) | P0–P7 | AC-001 | SRC-INH-001, SRC-INH-002, SRC-OD-002 |
| FR-002 | [Authority](04-target-architecture.md); [conflict C-001](13-decisions-risks-conflicts.md) | P0/P7 | AC-002 | SRC-USR-001, SRC-INH-001, SRC-INH-002 |
| FR-003 | [Profile schema](03-provider-access-matrix.md) | P1 | AC-003 | SRC-USR-001, SRC-DSH-003 |
| FR-004 | [Access matrix](03-provider-access-matrix.md) | P0/P4 | AC-003, AC-018 | SRC-USR-001, SRC-OAI-001, SRC-ANT-001, SRC-QWN-001, SRC-DSK-001, SRC-KIM-001 |
| FR-005 | [Credential isolation](08-system-interaction-and-security.md) | P1–P2 | AC-003, AC-008 | SRC-OD-003, SRC-DSH-003 |
| FR-006 | [Mesh operations/state](05-session-mesh-contracts.md) | P1 | AC-004, AC-005 | SRC-USR-001, SRC-DSH-002 |
| FR-007 | [Mesh operations](05-session-mesh-contracts.md) | P1/P3 | AC-004 | SRC-USR-001, SRC-OAI-002, SRC-ANT-002, SRC-KIM-002 |
| FR-008 | [WorkOrder/binding](05-session-mesh-contracts.md) | P1 | AC-004, AC-013 | SRC-INH-001, SRC-OD-002 |
| FR-009 | [Cycle enforcement](05-session-mesh-contracts.md) | P1 | AC-006 | SRC-DSH-002 |
| FR-010 | [Capacity enforcement](05-session-mesh-contracts.md) | P1 | AC-007 | SRC-USR-001, SRC-QWN-002 |
| FR-011 | [Capability calculation](08-system-interaction-and-security.md) | P2 | AC-008 | SRC-INH-001, SRC-DSH-002, SRC-KIM-002 |
| FR-012 | [Architecture](04-target-architecture.md); [capability planes](08-system-interaction-and-security.md) | P2 | AC-009 | SRC-INH-001, SRC-DSH-004 |
| FR-013 | [Capability planes](08-system-interaction-and-security.md) | P2 | AC-009, AC-024 | SRC-USR-001, SRC-DSH-001 |
| FR-014 | [Qwen adapter](06-provider-adapters.md); [cloud security](08-system-interaction-and-security.md) | P2/P4 | AC-010, AC-016 | SRC-INH-002, SRC-OD-004 |
| FR-015 | [Cloud disclosure](08-system-interaction-and-security.md) | P2 | AC-011 | SRC-USR-001, SRC-INH-002 |
| FR-016 | [Cloud disclosure](08-system-interaction-and-security.md); [conflict C-002](13-decisions-risks-conflicts.md) | P0/P2/P7 | AC-002, AC-011 | SRC-INH-002, SRC-USR-001 |
| FR-017 | [Go boundaries](04-target-architecture.md) | P1 | AC-012 | SRC-OD-001, SRC-OD-003 |
| FR-018 | [Error contract](05-session-mesh-contracts.md); [recovery](09-observability-recovery-operations.md) | P1 | AC-005, AC-027 | SRC-OD-002, SRC-DSH-002 |
| FR-019 | [Codex adapter](06-provider-adapters.md) | P4/P6 | AC-014, AC-038 | SRC-OAI-001, SRC-OD-003 |
| FR-020 | [Claude adapter](06-provider-adapters.md) | P4/P6 | AC-015, AC-039 | SRC-ANT-001, SRC-DSH-002 |
| FR-021 | [Qwen adapter](06-provider-adapters.md) | P4/P6 | AC-016, AC-040 | SRC-QWN-001, SRC-QWN-002, SRC-OD-004 |
| FR-022 | [Kimi adapter](06-provider-adapters.md) | P4/P6 | AC-017, AC-041 | SRC-KIM-001, SRC-KIM-002 |
| FR-023 | [DeepSeek adapter](06-provider-adapters.md) | P4/P6 | AC-018, AC-042 | SRC-DSK-001 |
| FR-024 | [Architecture](04-target-architecture.md); [plugins](07-plugins-and-ux.md) | P3 | AC-019 | SRC-DSH-001, SRC-DSH-002, SRC-DSH-003, SRC-DSH-004 |
| FR-025 | [Controller-owned packages](07-plugins-and-ux.md) | P3 | AC-020, AC-044 | SRC-USR-001, SRC-DSH-001 |
| FR-026 | [Thin packages](07-plugins-and-ux.md) | P3 | AC-020, AC-044 | SRC-USR-001, SRC-OAI-002, SRC-ANT-002, SRC-KIM-002, SRC-DSK-001 |
| FR-027 | [Provider switching](07-plugins-and-ux.md) | P3 | AC-021 | SRC-USR-001, SRC-DSH-003, SRC-KIM-001 |
| FR-028 | [Graph/compare/synthesis](07-plugins-and-ux.md) | P3 | AC-022 | SRC-USR-001, SRC-DSH-002 |
| FR-029 | [Approval UX](07-plugins-and-ux.md); [operator surfaces](09-observability-recovery-operations.md) | P3/P5 | AC-020, AC-044 | SRC-USR-001, SRC-DSH-003, SRC-ANS-003 |
| FR-030 | [System prompt](08-system-interaction-and-security.md) | P2 | AC-023 | SRC-INH-001, SRC-DSH-001, SRC-KIM-002 |
| FR-031 | [Event model](09-observability-recovery-operations.md) | P1–P7 | AC-025 | SRC-USR-001, SRC-ANS-002 |
| FR-032 | [Recovery matrix](09-observability-recovery-operations.md) | P1–P7 | AC-027, AC-028 | SRC-USR-001, SRC-DSH-002 |
| FR-033 | [Ansible A/B](10-ansible-hardening-plan.md) | P5 | AC-029, AC-030 | SRC-USR-001, SRC-ANS-001, SRC-ANS-002 |
| FR-034 | [Ansible C/F](10-ansible-hardening-plan.md) | P5 | AC-031, AC-034 | SRC-USR-001, SRC-ANS-001, SRC-ANS-002 |
| FR-035 | [Ansible D–G](10-ansible-hardening-plan.md) | P5 | AC-032, AC-033, AC-034, AC-035 | SRC-USR-001, SRC-ANS-001, SRC-ANS-002 |
| FR-036 | [Ansible H/I](10-ansible-hardening-plan.md) | P5 | AC-036, AC-037 | SRC-USR-001, SRC-ANS-003 |
| FR-037 | [Maturity declaration](06-provider-adapters.md); [P6](11-roadmap-and-gates.md) | P4/P6 | AC-038, AC-039, AC-040, AC-041, AC-042 | SRC-USR-001, SRC-OAI-001, SRC-ANT-001, SRC-QWN-001, SRC-DSK-001, SRC-KIM-001 |
| FR-038 | [Migration](04-target-architecture.md) | P1 | AC-013 | SRC-OD-002 |
| FR-039 | [Proposal/admission](05-session-mesh-contracts.md); [authority](04-target-architecture.md) | P1 | AC-004, AC-045, AC-054 | SRC-REV-001, SRC-INH-001, SRC-OD-002 |
| FR-040 | [Transport mappings](06-provider-adapters.md); [Go boundary](04-target-architecture.md) | P1/P4 | AC-046, AC-047 | SRC-REV-001, SRC-OAI-001, SRC-ANT-001, SRC-QWN-002, SRC-KIM-002, SRC-DSK-001 |
| FR-041 | [Endpoint authorization](05-session-mesh-contracts.md); [security](08-system-interaction-and-security.md) | P2 | AC-048 | SRC-REV-001, SRC-INH-001 |
| FR-042 | [UI boundary](04-target-architecture.md); [plugin feasibility](07-plugins-and-ux.md) | P0/P3 | AC-019, AC-049 | SRC-REV-001, SRC-DSH-001, SRC-DSH-004 |
| FR-043 | [Profile defaults](03-provider-access-matrix.md); [limits](05-session-mesh-contracts.md) | P0/P1/P4 | AC-047, AC-050 | SRC-REV-001 |
| FR-044 | [Journal checkpoints](10-ansible-hardening-plan.md) | P5 | AC-031, AC-051 | SRC-REV-001, SRC-ANS-002 |
| FR-045 | [Release envelope](10-ansible-hardening-plan.md) | P5 | AC-032, AC-052 | SRC-REV-001, SRC-ANS-001, SRC-ANS-002 |
| FR-046 | [Volatile provider evidence](06-provider-adapters.md); [P0/P4](11-roadmap-and-gates.md) | P0/P4 | AC-047, AC-053, AC-057 | SRC-REV-001, SRC-OAI-001, SRC-ANT-001, SRC-QWN-001, SRC-DSK-001, SRC-KIM-001 |
| FR-047 | [Target authorization matrix](05-session-mesh-contracts.md) | P1/P2 | AC-055 | SRC-REV-001, SRC-INH-001 |
| FR-048 | [Proposal idempotency](05-session-mesh-contracts.md); [owner UI lifecycle](05-session-mesh-contracts.md); [recovery](09-observability-recovery-operations.md) | P1/P4 | AC-056, AC-058 | SRC-REV-001, SRC-OD-002 |

## Nonfunctional requirements

| Requirement | Design / contract | Phase | Acceptance | Sources |
|---|---|---|---|---|
| NFR-001 | [Contracts](05-session-mesh-contracts.md); [capability calculation](08-system-interaction-and-security.md) | P1–P7 | AC-003, AC-004, AC-011 | SRC-INH-001, SRC-INH-002 |
| NFR-002 | [Capability planes](08-system-interaction-and-security.md) | P2–P7 | AC-008, AC-009, AC-024 | SRC-INH-001, SRC-DSH-003 |
| NFR-003 | [Credential isolation](08-system-interaction-and-security.md); [event model](09-observability-recovery-operations.md) | P2–P7 | AC-024, AC-025 | SRC-USR-001, SRC-DSH-003 |
| NFR-004 | [Deployment units](04-target-architecture.md); [security](08-system-interaction-and-security.md) | P2/P6 | AC-024 | SRC-OD-003, SRC-DSH-003 |
| NFR-005 | [State machines](05-session-mesh-contracts.md); [recovery](09-observability-recovery-operations.md); [journal](10-ansible-hardening-plan.md) | P1–P7 | AC-006, AC-013, AC-027, AC-051 | SRC-OD-002, SRC-REV-001 |
| NFR-006 | [Capacity enforcement](05-session-mesh-contracts.md) | P1 | AC-006, AC-007 | SRC-USR-001 |
| NFR-007 | [Adapter contract](06-provider-adapters.md); [recovery](09-observability-recovery-operations.md) | P1/P4 | AC-005, AC-027 | SRC-DSH-002, SRC-QWN-002 |
| NFR-008 | [Adapters/evidence](06-provider-adapters.md); [promotion](11-roadmap-and-gates.md) | P4–P7 | AC-014, AC-015, AC-016, AC-017, AC-018, AC-053, AC-057 | SRC-OAI-001, SRC-ANT-001, SRC-QWN-002, SRC-KIM-001, SRC-DSK-001, SRC-REV-001 |
| NFR-009 | [Event model/correlation](09-observability-recovery-operations.md) | P1–P7 | AC-025 | SRC-USR-001, SRC-ANS-002 |
| NFR-010 | [Artifacts/retention](09-observability-recovery-operations.md) | P2–P7 | AC-026 | SRC-INH-002 |
| NFR-011 | [Metrics](09-observability-recovery-operations.md) | P1–P7 | AC-028 | SRC-KIM-001, SRC-QWN-001 |
| NFR-012 | [Plugins/UX](07-plugins-and-ux.md) | P3 | AC-020, AC-021, AC-022 | SRC-USR-001, SRC-DSH-003 |
| NFR-013 | [Cloud disclosure](08-system-interaction-and-security.md) | P2–P7 | AC-010, AC-011 | SRC-INH-002, SRC-OD-004 |
| NFR-014 | [Go boundaries](04-target-architecture.md) | P1 | AC-012 | SRC-OD-001 |
| NFR-015 | [Ansible transaction/compensation](10-ansible-hardening-plan.md) | P5 | AC-031, AC-034, AC-035, AC-036 | SRC-ANS-001, SRC-ANS-002, SRC-ANS-003 |
| NFR-016 | [Acceptance matrix](12-acceptance-and-test-matrix.md); [roadmap](11-roadmap-and-gates.md) | P0–P6 | AC-037, AC-038, AC-039, AC-040, AC-041, AC-042 | SRC-USR-001 |
| NFR-017 | [Readiness ladder](03-provider-access-matrix.md); [maturity](06-provider-adapters.md) | P0–P7 | AC-003, AC-043 | SRC-OAI-001, SRC-ANT-001, SRC-QWN-001, SRC-DSK-001, SRC-KIM-001 |
| NFR-018 | [Package status](README.md); [promotion rules](11-roadmap-and-gates.md) | P0–P7 | AC-043, AC-044 | SRC-USR-001, SRC-OD-001 |
| NFR-019 | [Proposal/admission](05-session-mesh-contracts.md) | P1–P7 | AC-045 | SRC-REV-001, SRC-INH-001 |
| NFR-020 | [Endpoint auth](08-system-interaction-and-security.md); [UI boundary](04-target-architecture.md) | P2/P3 | AC-048, AC-049 | SRC-REV-001 |
| NFR-021 | [Profile defaults](03-provider-access-matrix.md); [roadmap gates](11-roadmap-and-gates.md); [release/journal](10-ansible-hardening-plan.md) | P0–P7 | AC-047, AC-049, AC-050, AC-051, AC-052, AC-053 | SRC-REV-001 |
| NFR-022 | [Authenticated caller/target matrix](05-session-mesh-contracts.md); [endpoint auth](08-system-interaction-and-security.md) | P1/P2 | AC-054, AC-055 | SRC-REV-001, SRC-INH-001 |

## Exact completeness rules

1. Requirement IDs extracted from [requirements](02-requirements.md) equal first-column IDs above; each occurs once in this matrix.
2. Every `AC-###` defined in [acceptance](12-acceptance-and-test-matrix.md) is referenced by at least one row; references resolve to exactly one definition.
3. Every `SRC-*` defined in [source register](14-source-register.md) is referenced by at least one row; references resolve to exactly one definition.
4. Every relative Markdown link resolves from its containing file.
5. Placeholder markers and orphan/stale phase names block promotion.
6. Requirement/design/phase/acceptance/source change is one atomic specification change set.
