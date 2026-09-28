# 14. Трассируемость требований

## Нормативный статус

Эта матрица — machine-parsable phase-exit artifact. Одна строка соответствует одному requirement ID; значения с несколькими ссылками разделяются `<br>`, а не объединяют требования. На каждом Phase exit и в Definition of Done CI/static check обязан доказать: все FR/NFR из [продуктовых требований](01-product-requirements.md) присутствуют ровно один раз; все OD/AC IDs существуют; evidence artifact заполнен фактической ссылкой/идентификатором прогона. Пустой, orphan или stale mapping блокирует exit.

## Functional requirements

| Requirement ID | Contract / policy | OD-ID | AC-ID | Evidence / phase gate |
|---|---|---|---|---|
| FR-001 | [Allowlist и inbound policy](05-channel-and-call-integrations.md) | OD-201<br>OD-202 | AC-001<br>AC-027 | Phase 2 exit: adapter conformance + revocation report |
| FR-002 | [InboundEvent/provenance contracts](02-system-architecture.md)<br>[Provenance schema](07-tech-base-calendar-data-contracts.md) | OD-101<br>OD-202 | AC-001<br>AC-025 | Phase 2 exit: schema fixtures + source locator evidence |
| FR-003 | [Queue/dedup architecture](02-system-architecture.md) | OD-102<br>OD-204 | AC-010 | Phase 2 exit: duplicate/edit/restart report |
| FR-004 | [Watcher boundary](02-system-architecture.md) | OD-104<br>OD-106 | AC-028<br>AC-031 | Phase 1 exit: labeled urgency evaluation + benchmark |
| FR-005 | [Notification UX](01-product-requirements.md) | OD-106<br>OD-205 | AC-015<br>AC-028 | Phase 2 exit: notification/gap acceptance report |
| FR-006 | [Product modes and scope](01-product-requirements.md) | OD-106<br>OD-205 | AC-029 | Phase 2 exit: peer/thread snooze scope test |
| FR-010 | [Per-channel-peer sessions](02-system-architecture.md) | OD-101<br>OD-105 | AC-003<br>AC-030 | Phase 1 exit: session isolation fixture report |
| FR-011 | [Safe envelope/evidence gate](04-data-classification-egress-policy.md) | OD-301<br>OD-302<br>OD-303 | AC-004<br>AC-005 | Phase 3 exit: captured egress + schema validation evidence |
| FR-012 | [Reply lifecycle](06-workflows-and-approval-gates.md) | OD-401<br>OD-402 | AC-006<br>AC-021 | Phase 4 exit: draft/edit/reject/expiry transition report |
| FR-013 | [Exact preview contract](06-workflows-and-approval-gates.md) | OD-401<br>OD-403 | AC-007<br>AC-032 | Phase 4 exit: canonical preview/encoding fixtures |
| FR-014 | [Canonical hash binding](06-workflows-and-approval-gates.md) | OD-401<br>OD-402 | AC-006 | Phase 4 exit: byte mutation/hash evidence |
| FR-015 | [Component capability boundaries](02-system-architecture.md)<br>[Approval auth contract](06-workflows-and-approval-gates.md) | OD-402A<br>OD-404 | AC-003<br>AC-020<br>AC-023 | Phase 4 exit: dispatcher dependency/capability review |
| FR-016 | [CapabilityManifest/delivery semantics](05-channel-and-call-integrations.md)<br>[Action state machine](06-workflows-and-approval-gates.md) | OD-404<br>OD-405 | AC-008<br>AC-009<br>AC-010 | Phase 4 exit: both delivery branches + reconciliation report |
| FR-020 | [Summary/report contract](07-tech-base-calendar-data-contracts.md) | OD-502<br>OD-704 | AC-025<br>AC-026 | Phase 5/7 exit: attributed summary review fixture |
| FR-021 | [Candidate workflow](06-workflows-and-approval-gates.md) | OD-101<br>OD-502 | AC-020<br>AC-025 | Phase 5 exit: candidate lifecycle/version report |
| FR-022 | [Candidate/provenance schema](07-tech-base-calendar-data-contracts.md) | OD-101<br>OD-502 | AC-025 | Phase 5 exit: required-field and source-version fixtures |
| FR-023 | [No-inferred-date rule](07-tech-base-calendar-data-contracts.md) | OD-602 | AC-011 | Phase 6 exit: explicit/ambiguous date corpus |
| FR-024 | [Separate approval types](06-workflows-and-approval-gates.md) | OD-402<br>OD-504<br>OD-603<br>OD-704 | AC-020 | Relevant Phase exit: cross-action rejection evidence |
| FR-025 | [FD-relative Inbox writer](07-tech-base-calendar-data-contracts.md) | OD-503<br>OD-504 | AC-012<br>AC-024 | Phase 5 exit: traversal/collision/TOCTOU filesystem diff |
| FR-026 | [Calendar proposal contract](07-tech-base-calendar-data-contracts.md) | OD-601<br>OD-602<br>OD-603 | AC-011<br>AC-020 | Phase 6 exit: proposal-only provider/local receipt |
| FR-030 | [Calls consent pipeline](05-channel-and-call-integrations.md) | OD-701<br>OD-702 | AC-019<br>AC-026 | Phase 7 exit: consent/purpose/retention evidence |
| FR-031 | [Local transcription route](05-channel-and-call-integrations.md) | OD-703 | AC-019<br>AC-026 | Phase 7 exit: no-network capture + transcript report |
| FR-032 | [Speaker uncertainty contract](05-channel-and-call-integrations.md) | OD-703<br>OD-704 | AC-019<br>AC-026 | Phase 7 exit: diarization confidence acceptance |
| FR-033 | [Separate audio/transcript retention](05-channel-and-call-integrations.md)<br>[Purge contract](07-tech-base-calendar-data-contracts.md) | OD-705<br>OD-806 | AC-018<br>AC-026 | Phase 7/8 exit: expiry/purge manifests |

## Non-functional requirements

| Requirement ID | Contract / policy | OD-ID | AC-ID | Evidence / phase gate |
|---|---|---|---|---|
| NFR-001 | [Fail-closed invariants](03-security-privacy-threat-model.md) | OD-103<br>OD-402<br>OD-405 | AC-013<br>AC-016<br>AC-021<br>AC-022 | MVP gate: fault suite with zero outbound/mutation |
| NFR-002 | [L0–L3 egress policy](04-data-classification-egress-policy.md) | OD-103<br>OD-301<br>OD-303 | AC-004<br>AC-005 | Phase 3 exit: network capture + deny decisions |
| NFR-003 | [Queue/sleep/recovery operations](09-observability-operations-recovery.md) | OD-102<br>OD-204<br>OD-804 | AC-010<br>AC-015<br>AC-017 | Phase 2/8 exit: restart/gap/restore evidence |
| NFR-004 | [Integrity/version contracts](02-system-architecture.md)<br>[Schema evolution](07-tech-base-calendar-data-contracts.md) | OD-101<br>OD-102<br>OD-401 | AC-006<br>AC-016<br>AC-025 | MVP gate: hash/corruption/version-conflict report |
| NFR-005 | [Redacted audit](09-observability-operations-recovery.md) | OD-102<br>OD-406<br>OD-801 | AC-008<br>AC-009<br>AC-023 | Phase 4/8 exit: audit field allowlist + transition evidence |
| NFR-006 | [SLO/performance proposals](09-observability-operations-recovery.md) | OD-104<br>OD-803 | AC-031 | Phase 1 baseline + Phase 8 capacity/SLO report |
| NFR-007 | [Adapter interface/manifest](05-channel-and-call-integrations.md) | OD-201<br>OD-203<br>OD-204<br>OD-405 | AC-002<br>AC-008<br>AC-009<br>AC-027 | Phase 2/4 exit: adapter conformance report |
| NFR-008 | [Approval UX invariants](01-product-requirements.md)<br>[Exact preview](06-workflows-and-approval-gates.md) | OD-401<br>OD-402A | AC-007<br>AC-023 | Phase 4 exit: owner usability/security acceptance |
| NFR-009 | [Localization requirement](01-product-requirements.md) | OD-106<br>OD-401 | AC-032 | MVP gate: Russian UX/source-language/encoding report |

## Phase-exit validation rules

1. Из [01-product-requirements.md](01-product-requirements.md) автоматически извлекаются все `FR-[0-9]{3}` и `NFR-[0-9]{3}`; set equality с первым столбцом обязательна.
2. Каждый `OD-*` должен существовать в [roadmap](10-implementation-roadmap.md), каждый `AC-*` — в [acceptance](11-verification-and-acceptance.md).
3. До фактического прогона колонка evidence означает обязательный тип artifact; на Phase exit её копия в delivery record заменяется ссылкой/ID immutable отчёта и approver.
4. Изменение requirement, contract, OD или AC без обновления этой матрицы делает пакет `STALE` и блокирует rollout.
5. Grouping requirement IDs в одной строке запрещён; это позволяет автоматическую проверку полноты и дублей.
