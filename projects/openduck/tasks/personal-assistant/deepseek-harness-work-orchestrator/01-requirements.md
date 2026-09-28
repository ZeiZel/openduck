# 01. Требования

## Функциональные требования

| ID | Требование | Приоритет |
|---|---|---|
| FR-001 | DSH предоставляет единую owner-facing surface для inbox, календаря, графика, задач, времени, review, memory и approvals. | Must |
| FR-002 | Codex cognitive root создаёт/версирует спецификации и планы, принимает bounded evidence и формирует acceptance/rework proposals; raw operational streams в root не поступают, а Codex runtime не является дочерним процессом DSH. | Must |
| FR-003 | Controller остаётся единственным technical authority для ingress, lifecycle, routing, grants, approvals, effects, audit и recovery. | Must |
| FR-004 | Runtime запускается как pinned DSH distribution/profile с одним ingress fork и attested bundle set; любое обновление требует compatibility/security gate и rollback artifact. | Must |
| FR-005 | Каждый cloud/model-visible append path независимо — prompt, steer, followup, subagent prompt, attachment, import, resume, fork, scheduled job, background job, tool-context injection, plugin call и internal inbox call — до parse/model/tool/log предъявляет `CloudAdmittedPrompt`, связанный с immutable conversation event/revision set, authoritative complete-through/coverage/high-water version и current runtime policy; path без gate hard-disabled. | Must |
| FR-006 | Raw content, включая input/output, attachments и OCR, не попадает в DSH session/event bus, persistence, browser stores, search, telemetry или cloud: local PD использует отдельный `LocalPDDispatch` вне DSH seam, а cloud append проходит crash-safe reservation/receipt/reconciliation и final egress revalidation. | Must |
| FR-007 | `Это ПД`, near-miss или deterministic policy detection необратимо повышает session high-water class и создаёт Controller-only `LocalPDDispatch` во внешний Qwen sidecar: без DSH/Codex attestation, tools/network/fallback; downgrade/unlatch запрещён. | Must |
| FR-008 | Non-local передача PD возможна только как exact bytes, вручную набранные owner в blank non-prefilled trusted editor после fresh auth, и consumed `DeclassificationDecision` в новой clean session; paste/drop/autofill/AX/AppleScript/synthetic input и model/Qwen-derived release запрещены. | Must |
| FR-009 | Содержимое внешнего источника никогда напрямую не инициирует tool, worker, memory write или effect. | Must |
| FR-010 | Enterprise-chat collector читает только явно разрешённые account/room/thread scopes и сохраняет стабильный source locator. | Must |
| FR-011 | Telegram collector читает только явно разрешённые account/chat/topic scopes и сохраняет стабильный source locator. | Must |
| FR-012 | Chat pipeline отражает create/edit/delete, dedup, out-of-order, backfill, revoke и coverage gap; неопределённость переводит conversation в quarantine. | Must |
| FR-013 | Для нового диалога система формирует notification/digest, agreement/task/demo candidates и reply draft с attribution и confidence. | Must |
| FR-014 | Отправка/редактирование сообщения отделена от чтения и требует exact recipient/body/attachment approval и idempotent effect receipt. | Must |
| FR-015 | Дата демо создаётся как candidate только из явной даты/времени или прямого owner input; неоднозначность не разрешается моделью молча. | Must |
| FR-016 | Command Center объединяет подтверждённые demo/calendar items из Outlook, Kaiten и owner input, сохраняя source-of-truth и конфликты. | Must |
| FR-017 | Planner строит versioned WorkGraph с задачами, зависимостями, capacity, milestones, critical path и confidence. | Must |
| FR-018 | Изменение срока, статуса, зависимости или capacity создаёт PlanDelta и impact alert, но не переписывает baseline без подтверждения. | Must |
| FR-019 | Kaiten reader наблюдает только allowlisted spaces/boards/cards/fields и поддерживает per-resource cursor/coverage. | Must |
| FR-020 | Каждое Kaiten create/update/move/archive/comment/time-log событие нормализуется в TaskChange с old/new digest и author/time provenance. | Must |
| FR-021 | Kaiten reconciliation сопоставляет карточки с WorkItem/WorkOrder и показывает plan/fact, blockers, stale links и unmatched records. | Must |
| FR-022 | Любая Kaiten mutation является отдельным ActionProposal и не выполняется read credential/process. | Must |
| FR-023 | Outlook reader использует Microsoft Graph с минимальными delegated read scopes; baseline — `Mail.ReadBasic`, а calendar scope/strategy остаётся conflict-preserving decision без silent escalation. | Must |
| FR-024 | Mail triage показывает sender/subject/time/thread/importance и создаёт candidate; body/attachments требуют отдельного scope/decision. | Must |
| FR-025 | Calendar delta по умолчанию выключен: `Calendars.ReadBasic` допускает только bounded polling после live probe; если delta требует `Calendars.Read`, нужен отдельный owner/security decision, без auto-escalation. | Must |
| FR-026 | Mail send/reply/move и calendar create/update/delete используют отдельные writer credentials/effectors и остаются disabled до решения. | Must |
| FR-027 | Beads issue lifecycle используется для durable task tracking; memory не подменяет issue status, а issue не хранит raw sensitive transcript. | Must |
| FR-028 | Проверенное решение сохраняется как versioned MemoryRecord с stable key, scope, claim, provenance, evidence, freshness и sensitivity. | Must |
| FR-029 | Перед исследованием/реализацией orchestrator выполняет scoped memory lookup и показывает reused/stale/conflicting evidence. | Must |
| FR-030 | DSH/UI/model видит для private global memory только metadata-only `PrivateMemoryRef`; private claim/value остаётся вне DSH, а создание/обновление/forget выполняется отдельными Controller operations. | Must |
| FR-031 | Non-private chat/work/review summaries могут стать candidates; Qwen-derived PD/meeting digest/report остаётся local-only и не approvable/releasable. Первый tech-base writer принимает только owner-authored exact declassified bytes после consumed decision и делает exclusive create-new; update/purge deferred. | Should |
| FR-032 | Codex root превращает цель в versioned TaskSpec и frozen implementation `WorkOrder.v1`; общие DAG/read/review запуски используют отдельный `AgentRunOrder.v1`/`ReadOrder.v1`, а `DispatchRecord` и `RunDispatchBinding` связывают exact `order_kind+order_hash`, role, schemas, evidence и runtime attestation без `work_order_hash` у non-implementer. | Must |
| FR-033 | Router назначает bounded роли через disjoint contracts: `LocalPDDispatch` для внешнего Qwen, `ReadOrder` для Luna/read/project-prep, `WorkOrder` только implementer и `AgentRunOrder` для reviewer/general run; cross-kind dispatch запрещён. | Must |
| FR-034 | Scheduler параллелит только независимые работы, ограничивает concurrency/resources и передаёт root лишь typed status/evidence. | Must |
| FR-035 | Work lifecycle поддерживает queue/start/interrupt/resume/rework/complete/block с idempotent recovery и cancel propagation. | Must |
| FR-036 | Time ledger различает planned, explicit timer и derived candidate; start/stop/resume требуют owner/work-item binding. | Must |
| FR-037 | Система сверяет время с WorkGraph и Kaiten, показывает отклонение/overrun и никогда не выдаёт derived activity за подтверждённый факт. | Must |
| FR-038 | Экспорт time log в Kaiten/другой provider является отдельным exact-approved effect с interval/task/duration preview. | Must |
| FR-039 | Review workflow получает role-specific `AgentRunOrder` + `RunDispatchBinding` с immutable target/base/diff/spec, input/output schemas и evidence contract, выполняет risk-based checks и возвращает attributed findings без mutation по умолчанию. | Must |
| FR-040 | Project preparation получает role-specific `ReadOrder` + `RunDispatchBinding` с repo/base/dirty/instruction digests, probe allowlist, output schema/evidence contract; выполняет read-only discovery и exact command preview до mutation. | Must |
| FR-041 | Завершение работы требует EvidenceBundle, независимый ReviewVerdict и Controller-validated acceptance transition. | Must |
| FR-042 | Command Center показывает unified inbox, calendar, WorkGraph/Gantt, watched Kaiten changes, mail changes, timers, work queue и system health. | Must |
| FR-043 | Любая карточка UI раскрывает provenance, freshness, classification, coverage, related records и audit path без утечки raw PD. | Must |
| FR-044 | Decision Center DSH показывает suggestion/launch affordance, но authoritative preview/render receipt/Touch ID выполняет Controller-owned native trusted renderer; overlay/clickjacking/stale UI не может создать grant. | Must |
| FR-045 | Audit/metrics позволяют восстановить путь source→candidate→spec→work→evidence→review→effect и явно показывают degraded state. | Must |
| FR-046 | Retention engine применяет per-class/source TTL и per-store `erasure_capability=hard|logical|none`; raw PD запрещён в non-hard stores, а purge receipt не заявляет физическое удаление без evidence. | Must |
| FR-047 | Owner имеет независимые kill switches для ingest, cloud egress, Codex dispatch, local model, memory writes и каждого effector. | Must |
| FR-048 | Controller host scheduler создаёт reminders/digests/reconciliation jobs и через собственное native приложение планирует local macOS notifications; missed windows/gaps видимы после wake/restart. | Should |
| FR-049 | DSH служит UI/event host без general root LLM: каждый safe `CloudAdmittedPrompt` Controller напрямую связывает с persistent Codex app-server thread; ordinary DSH agent/model/subagent routes disabled либо блокируют rollout как unresolved feasibility. | Must |
| FR-050 | Public-web reader допускает широкий read-only GET/navigation по public HTTP(S), без semantic total-resource cap, но с per-response/concurrency/time/backpressure limits; forms, uploads, credentials, private/link-local networks, non-GET effects и SSRF запрещены. Real network включается только отдельным P7 decision/gate с live conformance и revoke proof. | Must |
| FR-051 | Context7 и другие public-doc tools получают только public/safe queries через optional safe-public MCP; private payload/source refs и private MCP никогда не передаются, DSH никогда не parent’ит private MCP, а real network disabled до отдельного P7 gate. | Must |
| FR-052 | PD Qwen pin фиксирует `num_ctx=40960`, route `contextWindow=40960`, working budget `32768`, semantic thinking profile `medium`; boolean-only Qwen adapter обязан иметь explicit tested mapping либо пометить medium unsupported, без silent substitution; exact model/config benchmarked, no fallback. | Must |
| FR-053 | Meeting/call capture требует explicit consent/purpose/source/coverage, локальную transcript обработку через `LocalPDDispatch` и honest speaker/time uncertainty; raw/Qwen-derived digest/candidates не выходят в DSH. | Must |
| FR-054 | Qwen MeetingDigest и agreement/action/demo/report suggestions остаются local PD и не approvable/releasable; DSH или create-only tech-base получает только отдельно owner-authored exact bytes после fresh auth, consumed `DeclassificationDecision` и post-scan. | Must |
| FR-055 | DSH user-session archive является reversible visibility operation, сохраняет log/accounting и не называется удалением; unarchive восстанавливает projection без потери provenance. | Must |
| FR-056 | Session delete/purge проходит Controller retention ledger, tombstone и per-store erasure receipts; unsupported physical erase отображается `logical|none`, а search/cache/index/materializations проверяются отдельно. | Must |

## Нефункциональные требования

| ID | Требование |
|---|---|
| NFR-001 | Fail-closed: unknown schema/class/source/coverage/permission/approval/outcome блокирует затронутый route/effect. |
| NFR-002 | Privacy: raw L2/L3/PD не появляется в cloud, DSH log, telemetry, search index, crash dump или unapproved memory. |
| NFR-003 | Least privilege: process, credential, MCP, filesystem, network и provider scopes минимальны и раздельны для read/write. |
| NFR-004 | Secrets находятся вне repo/prompt/log/Beads; каждый credential/raw-store runtime (Codex, Graph, Kaiten, AX/CuaDriver, Qwen/quarantine, Beads/private stores) имеет OS-enforced isolation from malicious DSH plugin via separate principal/App Sandbox/read-deny/Keychain ACL evidence; process parent/ref alone insufficient. |
| NFR-005 | Authority records canonical, versioned и tamper-evident; cloud privacy decision bind’ит immutable event/revision set, complete-through watermark, authoritative gate/coverage digest и high-water version; transcript/model memory не authoritative. |
| NFR-006 | Idempotency/recovery: cross-store cloud append использует `pending→consuming→consumed|uncertain`, append receipt/reconciliation and no blind retry; restart/retry не создаёт duplicate work/effect, ambiguous outcome остаётся `UNKNOWN|uncertain`. |
| NFR-007 | Context hygiene: budgets, allowlists и artifact references не допускают raw operational bulk в Codex root. |
| NFR-008 | Performance: synthetic p95 ingest→UI ≤60s; UI остаётся отзывчивым при согласованном concurrent workload. |
| NFR-009 | Availability honesty: sleep, auth expiry, rate limit, cursor loss и source outage всегда отражаются как gap/stale/degraded. |
| NFR-010 | Schema/versioning: breaking contract/DSH/plugin change блокирует rollout до migration, replay и rollback tests. |
| NFR-011 | Supply chain: exact versions/digests/SBOM, reviewed install scripts и reproducible bundle; unreviewed external plugin не загружается. |
| NFR-012 | UX/time semantics используют русский язык и Europe/Moscow по умолчанию, сохраняя исходный timezone/locale источника. |
| NFR-013 | Decision UX keyboard-accessible, различает read/propose/effect и не стимулирует blind approval. |
| NFR-014 | Observability хранит allowlisted metadata, не secrets/raw bodies; telemetry default off. |
| NFR-015 | Retention/purge охватывают source cache, DSH persistence, indexes, memory, evidence, logs и future backups. |
| NFR-016 | Все phase gates воспроизводимы на synthetic fixtures без real accounts/data/effects. |
| NFR-017 | Developer-preview risk ограничен pinned fork boundary, contract tests и upstream-change ledger. |
| NFR-018 | Prompt-injection defense проверяет source→sink матрицу, Unicode normalization и независимую authorization каждого sensitive sink. |
| NFR-019 | Local resource budget не допускает swap/thrash: Qwen concurrency/context и DSH/Codex processes ограничены по benchmark. |
| NFR-020 | Specification-only artifact не является authorization: установка, OAuth consent, account connection, permission grant и effect требуют отдельной команды/решения. |
| NFR-021 | Exactly-one cloud model egress: final Controller boundary atomically re-reads authoritative conversation/gate/high-water state and current attestations, invalidates on any new/edit/delete/backfill/gap/revoke/class bump, then reserves only Codex transport; DSH не делает другой LLM call/duplicate context. |
| NFR-022 | Privileged runtime boundary: real Codex owner login/use and every credential/raw-store sidecar require DR-020, explicit authorization and OS-enforced read-deny evidence against same-UID malicious DSH; P0–P6 use synthetic stubs/no real auth. |
| NFR-023 | Model transport network и tool/worker process network разделены и независимо attested; model access не предоставляет tool egress. |
| NFR-024 | LocalPDView имеет Controller-owned native/separate-origin boundary; raw PD prompt/answer не проходит DSH event bus/postMessage/search/localStorage/IndexedDB/service worker/title/telemetry. |
| NFR-025 | App-generated crash dumps/uploads запрещены; host dump controls проверяются, но residual RAM и same-UID read risk явно остаются до OS isolation evidence. |
| NFR-026 | AX-derived coverage имеет `best_effort|unknown`; без authoritative provider cursor/sequence нельзя заявлять complete coverage. |

Точная связь каждого ID с design, phase и acceptance определена ровно одной строкой в [traceability](21-traceability.md).
