# 21. Трассируемость

Одна строка соответствует одному requirement ID. `P#` определены в [roadmap](17-roadmap.md), `AC-###` — в [acceptance suite](18-acceptance-tests.md), `SRC-*` — в [source register](20-source-register.md). Phase exit запрещён при orphan/duplicate ID, unresolved link or missing evidence.

## Functional requirements

| Requirement | Design / contract | Phase | Acceptance | Sources |
|---|---|---|---|---|
| FR-001 | [Architecture](02-target-architecture.md); [Command Center](15-command-center-ux.md) | P1–P4 | AC-031 | SRC-USR-01, SRC-USR-02, SRC-DSH-02, SRC-DSH-03 |
| FR-002 | [Codex placement](02-target-architecture.md); [Multitask](10-multitask-orchestration.md) | P1/P5/P7 | AC-023, AC-045, AC-046 | SRC-USR-02, SRC-OD-03, SRC-OAI-01, SRC-OAI-02, SRC-OAI-03, SRC-OAI-04 |
| FR-003 | [Architecture](02-target-architecture.md); [Permissions](14-permissions-approvals-effects.md) | P1 | AC-003, AC-033 | SRC-USR-02, SRC-OD-02, SRC-OD-03 |
| FR-004 | [Distribution/compatibility](02-target-architecture.md); [inventory](13-plugin-and-sidecar-inventory.md) | P0–P1 | AC-001, AC-002, AC-049, AC-053 | SRC-DSH-01, SRC-DSH-07 |
| FR-005 | [All-path ingress](04-ingress-and-pd.md); [admission contract](03-contracts-and-ledgers.md) | P1–P2 | AC-003, AC-041, AC-042 | SRC-DSH-02, SRC-DSH-08, SRC-DSH-11, SRC-OD-02, SRC-OD-06 |
| FR-006 | [Ingress/privacy](04-ingress-and-pd.md); [cloud/local contracts](03-contracts-and-ledgers.md) | P1–P2 | AC-003, AC-004, AC-041, AC-042, AC-044 | SRC-DSH-02, SRC-DSH-08, SRC-DSH-09, SRC-OD-02 |
| FR-007 | [PD high-water](04-ingress-and-pd.md); [LocalPDDispatch](03-contracts-and-ledgers.md) | P2 | AC-003, AC-005, AC-043, AC-044, AC-055 | SRC-USR-03, SRC-OD-01, SRC-OD-05, SRC-DSH-05 |
| FR-008 | [Declassification](04-ingress-and-pd.md); [contract](03-contracts-and-ledgers.md) | P2 | AC-006, AC-043 | SRC-OD-02, SRC-USR-03 |
| FR-009 | [Injection containment](04-ingress-and-pd.md); [chat boundary](05-chat-capture.md) | P2 | AC-007 | SRC-DSH-10, SRC-OD-02 |
| FR-010 | [Chat adapter](05-chat-capture.md) | P3/P7 | AC-008, AC-057 | SRC-USR-01, SRC-APL-01, SRC-APL-02, SRC-APL-03 |
| FR-011 | [Chat adapter](05-chat-capture.md) | P3/P7 | AC-009, AC-057 | SRC-USR-01, SRC-APL-02, SRC-APL-03 |
| FR-012 | [Coverage/history](05-chat-capture.md); [CoverageState](03-contracts-and-ledgers.md) | P3 | AC-010 | SRC-OD-01, SRC-OD-02 |
| FR-013 | [Conversation processing](05-chat-capture.md); [ChatDigest](03-contracts-and-ledgers.md) | P3–P4 | AC-011 | SRC-USR-01, SRC-OD-01 |
| FR-014 | [Reply boundary](05-chat-capture.md); [effect transaction](14-permissions-approvals-effects.md) | P6/P8 | AC-011, AC-034 | SRC-OD-02, SRC-USR-01 |
| FR-015 | [Demo lifecycle](06-demo-calendar-planning.md); [DemoCandidate](03-contracts-and-ledgers.md) | P4 | AC-012 | SRC-USR-01, SRC-OD-01 |
| FR-016 | [Calendar projection](06-demo-calendar-planning.md); [CalendarItem](03-contracts-and-ledgers.md) | P4 | AC-013 | SRC-USR-01, SRC-MS-04, SRC-KTN-01 |
| FR-017 | [WorkGraph](06-demo-calendar-planning.md); [graph contract](03-contracts-and-ledgers.md) | P4 | AC-014 | SRC-USR-01, SRC-OD-03 |
| FR-018 | [Baseline/PlanDelta](06-demo-calendar-planning.md); [PlanDelta](03-contracts-and-ledgers.md) | P4 | AC-014 | SRC-USR-01, SRC-OD-03 |
| FR-019 | [Kaiten reader](07-kaiten.md) | P3/P7 | AC-015 | SRC-KTN-01, SRC-KTN-02, SRC-KTN-03 |
| FR-020 | [Kaiten changes](07-kaiten.md); [TaskChange](03-contracts-and-ledgers.md) | P3 | AC-015 | SRC-KTN-01, SRC-KTN-02 |
| FR-021 | [Kaiten reconciliation](07-kaiten.md); [TaskLink](03-contracts-and-ledgers.md) | P4 | AC-015 | SRC-USR-01, SRC-KTN-01 |
| FR-022 | [Kaiten writer](07-kaiten.md); [permissions](14-permissions-approvals-effects.md) | P6/P8 | AC-016, AC-034 | SRC-KTN-01, SRC-OD-02 |
| FR-023 | [Outlook permissions](08-outlook.md) | P3/P7 | AC-017, AC-048 | SRC-MS-01, SRC-MS-06, SRC-ENV-01 |
| FR-024 | [Mail tracking](08-outlook.md); [MailChange](03-contracts-and-ledgers.md) | P3–P4 | AC-017 | SRC-MS-01, SRC-MS-03, SRC-MS-05 |
| FR-025 | [Calendar permission conflict](08-outlook.md); [CalendarChange](03-contracts-and-ledgers.md) | P3–P4 | AC-018, AC-048 | SRC-MS-02, SRC-MS-04, SRC-MS-05, SRC-MS-06 |
| FR-026 | [Outlook effectors](08-outlook.md); [permissions](14-permissions-approvals-effects.md) | P6/P8 | AC-019 | SRC-MS-01, SRC-ENV-01 |
| FR-027 | [Store separation](09-beads-and-memory.md) | P4 | AC-020 | SRC-OD-04, SRC-USR-01 |
| FR-028 | [Memory lifecycle](09-beads-and-memory.md); [MemoryRecord](03-contracts-and-ledgers.md) | P4 | AC-020 | SRC-OD-04, SRC-USR-01 |
| FR-029 | [Reuse workflow](09-beads-and-memory.md) | P4–P5 | AC-021 | SRC-OD-04, SRC-USR-01 |
| FR-030 | [PrivateMemoryRef](03-contracts-and-ledgers.md); [memory boundary](09-beads-and-memory.md) | P4/P8 | AC-020, AC-021 | SRC-OD-04, SRC-OD-01 |
| FR-031 | [Create-only tech-base](09-beads-and-memory.md); [declassification](04-ingress-and-pd.md) | P2/P4/P8 | AC-006, AC-022, AC-059 | SRC-OD-01, SRC-OD-04 |
| FR-032 | [Typed order dispatch](10-multitask-orchestration.md); [contracts](03-contracts-and-ledgers.md) | P5 | AC-023, AC-050 | SRC-OD-03, SRC-OAI-02, SRC-OAI-05 |
| FR-033 | [Roles/orders](10-multitask-orchestration.md) | P5 | AC-024, AC-050 | SRC-USR-01, SRC-OD-03, SRC-DSH-03, SRC-DSH-06 |
| FR-034 | [Concurrency/context](10-multitask-orchestration.md) | P5 | AC-024, AC-039 | SRC-OD-03, SRC-DSH-02 |
| FR-035 | [Work recovery](10-multitask-orchestration.md); [recovery matrix](16-observability-recovery-retention.md) | P5 | AC-025 | SRC-OAI-02, SRC-OD-03 |
| FR-036 | [Time semantics](11-time-tracking.md); [TimeEntry](03-contracts-and-ledgers.md) | P4 | AC-026 | SRC-USR-01 |
| FR-037 | [Time reconciliation](11-time-tracking.md) | P4 | AC-027 | SRC-USR-01, SRC-KTN-01 |
| FR-038 | [Time export](11-time-tracking.md); [permissions](14-permissions-approvals-effects.md) | P6/P8 | AC-027, AC-034 | SRC-KTN-01, SRC-OD-02 |
| FR-039 | [Review workflow](12-review-and-project-preparation.md); [dispatch binding](03-contracts-and-ledgers.md) | P5 | AC-023, AC-028, AC-050 | SRC-USR-01, SRC-OD-03 |
| FR-040 | [Project preparation](12-review-and-project-preparation.md); [ReadOrder binding](03-contracts-and-ledgers.md) | P5 | AC-023, AC-029, AC-050 | SRC-USR-01, SRC-OD-03 |
| FR-041 | [Evidence/acceptance](12-review-and-project-preparation.md); [contracts](03-contracts-and-ledgers.md) | P5 | AC-030 | SRC-OD-03, SRC-OAI-02 |
| FR-042 | [Information architecture](15-command-center-ux.md); [UI channel](02-target-architecture.md) | P1/P4 | AC-031, AC-063 | SRC-USR-01, SRC-DSH-02, SRC-DSH-03 |
| FR-043 | [UI provenance/search](15-command-center-ux.md); [audit](16-observability-recovery-retention.md) | P1/P4–P5 | AC-031, AC-035, AC-063 | SRC-OD-02, SRC-DSH-02 |
| FR-044 | [Trusted decision renderer](14-permissions-approvals-effects.md); [UX](15-command-center-ux.md) | P6 | AC-032, AC-047 | SRC-OD-02, SRC-OAI-06 |
| FR-045 | [Metrics/audit](16-observability-recovery-retention.md) | P1+ | AC-035, AC-052 | SRC-OD-02, SRC-DSH-07 |
| FR-046 | [Retention/erasure](16-observability-recovery-retention.md); [ErasureReceipt](03-contracts-and-ledgers.md) | P2/P7 | AC-036, AC-056, AC-061 | SRC-OD-01, SRC-OD-02, SRC-DSH-09 |
| FR-047 | [Kill switches](14-permissions-approvals-effects.md) | P1/P6 | AC-037 | SRC-OD-01, SRC-OD-03 |
| FR-048 | [Scheduler](16-observability-recovery-retention.md); [reminders](06-demo-calendar-planning.md) | P4 | AC-038 | SRC-USR-01, SRC-DSH-03, SRC-APL-04 |
| FR-049 | [Primary-agent invariant](02-target-architecture.md); [Codex placement](02-target-architecture.md) | P1/P5/P7 | AC-042, AC-045, AC-046 | SRC-USR-02, SRC-DSH-02, SRC-DSH-06, SRC-DSH-08, SRC-DSH-11, SRC-OAI-02 |
| FR-050 | [Safe-public tools](13-plugin-and-sidecar-inventory.md); [phase gate](17-roadmap.md) | P3/P7 | AC-054, AC-062 | SRC-USR-01, SRC-DSH-04 |
| FR-051 | [Requested integrations](13-plugin-and-sidecar-inventory.md); [architecture](02-target-architecture.md) | P3/P7 | AC-049, AC-060, AC-062 | SRC-USR-01, SRC-DSH-04, SRC-OD-03 |
| FR-052 | [PD route](04-ingress-and-pd.md); [Qwen sidecar](13-plugin-and-sidecar-inventory.md) | P2 | AC-055 | SRC-USR-01, SRC-OLL-01, SRC-OLL-02, SRC-OD-05 |
| FR-053 | [Call capture](05-chat-capture.md); [MeetingCapture](03-contracts-and-ledgers.md) | P3/P7 | AC-059 | SRC-USR-01, SRC-OD-01, SRC-APL-02, SRC-APL-03 |
| FR-054 | [Meeting workflow](05-chat-capture.md); [create-only tech-base](09-beads-and-memory.md) | P2/P4/P8 | AC-006, AC-022, AC-059 | SRC-USR-01, SRC-OD-01, SRC-OD-04 |
| FR-055 | [Session lifecycle UX](15-command-center-ux.md); [SessionLifecycleRecord](03-contracts-and-ledgers.md) | P4 | AC-061 | SRC-USR-01, SRC-DSH-11 |
| FR-056 | [Retention/purge](16-observability-recovery-retention.md); [session contracts](03-contracts-and-ledgers.md) | P4/P7 | AC-036, AC-061 | SRC-USR-01, SRC-DSH-09, SRC-DSH-11 |

## Nonfunctional requirements

| Requirement | Design / contract | Phase | Acceptance | Sources |
|---|---|---|---|---|
| NFR-001 | [Ingress quarantine](04-ingress-and-pd.md); [effect transaction](14-permissions-approvals-effects.md) | P1+ | AC-003, AC-034, AC-041, AC-042 | SRC-OD-02, SRC-DSH-08 |
| NFR-002 | [PD route](04-ingress-and-pd.md); [redacted audit](16-observability-recovery-retention.md) | P2+ | AC-004, AC-035, AC-044 | SRC-USR-03, SRC-OD-02, SRC-DSH-07 |
| NFR-003 | [Deployment units](02-target-architecture.md); [capabilities](14-permissions-approvals-effects.md) | P1+ | AC-033, AC-049 | SRC-DSH-04, SRC-DSH-07, SRC-OAI-06 |
| NFR-004 | [Privileged runtime boundaries](14-permissions-approvals-effects.md); [architecture](02-target-architecture.md) | P1/P5/P7 | AC-033, AC-045, AC-051, AC-062 | SRC-OAI-01, SRC-OD-01 |
| NFR-005 | [Snapshot-bound ledgers](03-contracts-and-ledgers.md); [audit](16-observability-recovery-retention.md) | P1+ | AC-035, AC-042, AC-052 | SRC-OD-02, SRC-OD-06 |
| NFR-006 | [Cloud append lifecycle](03-contracts-and-ledgers.md); [recovery](16-observability-recovery-retention.md) | P1+ | AC-025, AC-034, AC-042, AC-052 | SRC-OD-02, SRC-OD-06 |
| NFR-007 | [Context budgets](10-multitask-orchestration.md); [UI channel](02-target-architecture.md) | P1/P5 | AC-023, AC-039, AC-046, AC-063 | SRC-OD-03, SRC-DSH-02 |
| NFR-008 | [Metrics](16-observability-recovery-retention.md); [UX](15-command-center-ux.md) | P4–P5 | AC-039 | SRC-USR-01 |
| NFR-009 | [Health/recovery](16-observability-recovery-retention.md) | P3+ | AC-010, AC-015, AC-017, AC-018, AC-038, AC-057 | SRC-MS-02, SRC-KTN-02, SRC-OD-01 |
| NFR-010 | [Versioned contracts](03-contracts-and-ledgers.md); [compatibility](02-target-architecture.md) | P0+ | AC-002, AC-042 | SRC-DSH-01, SRC-DSH-07 |
| NFR-011 | [Supply chain](13-plugin-and-sidecar-inventory.md); [compatibility](02-target-architecture.md) | P0+ | AC-001, AC-002, AC-049, AC-053 | SRC-DSH-04, SRC-DSH-07 |
| NFR-012 | [Calendar semantics](06-demo-calendar-planning.md); [time](11-time-tracking.md); [UX](15-command-center-ux.md) | P4 | AC-012, AC-013, AC-026, AC-031, AC-058 | SRC-USR-01, SRC-MS-04 |
| NFR-013 | [Accessibility/anti-fatigue](15-command-center-ux.md); [trusted decisions](14-permissions-approvals-effects.md) | P4/P6 | AC-031, AC-032, AC-047, AC-058 | SRC-OAI-06, SRC-USR-01 |
| NFR-014 | [Observability/audit](16-observability-recovery-retention.md) | P1+ | AC-035, AC-044 | SRC-DSH-07, SRC-OD-02 |
| NFR-015 | [Retention/erasure](16-observability-recovery-retention.md); [memory](09-beads-and-memory.md) | P2+ | AC-036, AC-056, AC-061 | SRC-OD-01, SRC-OD-04, SRC-DSH-09 |
| NFR-016 | [Synthetic roadmap](17-roadmap.md); [acceptance policy](18-acceptance-tests.md) | P0–P6 | AC-040, AC-051, AC-062 | SRC-USR-02, SRC-OD-01 |
| NFR-017 | [Compatibility boundary](02-target-architecture.md); [roadmap](17-roadmap.md) | P0+ | AC-001, AC-002, AC-053 | SRC-DSH-01, SRC-ENV-02 |
| NFR-018 | [Injection containment](04-ingress-and-pd.md) | P2+ | AC-007 | SRC-DSH-10, SRC-OD-02 |
| NFR-019 | [Resource policy](10-multitask-orchestration.md); [health](16-observability-recovery-retention.md) | P2/P5 | AC-039, AC-055 | SRC-OD-05, SRC-USR-01, SRC-OLL-01 |
| NFR-020 | [Package status](README.md); [phase gates](17-roadmap.md) | P0+ | AC-040, AC-051 | SRC-USR-02, SRC-ENV-01 |
| NFR-021 | [Primary-agent/final-gate invariant](02-target-architecture.md); [cloud admission](03-contracts-and-ledgers.md) | P1/P5/P7 | AC-042, AC-046 | SRC-DSH-02, SRC-DSH-06, SRC-OAI-02 |
| NFR-022 | [Privileged auth/raw-store boundary](14-permissions-approvals-effects.md); [phase gate](17-roadmap.md) | P1/P5/P7 | AC-045, AC-051, AC-062 | SRC-OAI-01, SRC-OAI-02 |
| NFR-023 | [Worker attestation/binding](03-contracts-and-ledgers.md); [Codex placement](02-target-architecture.md) | P5/P7 | AC-023, AC-045, AC-046, AC-050 | SRC-OAI-06, SRC-OD-03 |
| NFR-024 | [LocalPDView](03-contracts-and-ledgers.md); [PD route](04-ingress-and-pd.md) | P2 | AC-004, AC-044 | SRC-USR-03, SRC-OD-02 |
| NFR-025 | [Crash-dump posture](16-observability-recovery-retention.md) | P2/P5 | AC-056 | SRC-OD-01, SRC-DSH-07 |
| NFR-026 | [Chat coverage](05-chat-capture.md); [CoverageState](03-contracts-and-ledgers.md) | P3/P7 | AC-057 | SRC-APL-02, SRC-APL-03, SRC-OD-02 |

## Exact completeness rules

1. Extract IDs from [requirements](01-requirements.md); set equality with the first column above is mandatory, and count per ID equals one.
2. Every referenced AC exists exactly once in [acceptance tests](18-acceptance-tests.md); every defined AC is referenced by at least one row.
3. Every `SRC-*` used above exists exactly once in [source register](20-source-register.md), and every registered source is used.
4. Every local Markdown link resolves relative to its containing file.
5. Placeholder markers, orphan files and stale phase names block promotion.
6. Change of requirement/design/phase/AC/source requires the same change set to update this matrix.
