# 02. Требования

## Функциональные требования

| ID | Attribution | Требование |
|---|---|---|
| FR-001 | VERIFIED / inherited | Controller остаётся единственным deterministic authority/TCB для admission, lifecycle, capabilities, approvals, effects, audit и recovery. |
| FR-002 | USER REQUIREMENT + CONFLICT | Контракты поддерживают selectable session root из Claude/Qwen/DeepSeek/Codex/Kimi, но Codex остаётся default до superseding owner ADR. |
| FR-003 | USER REQUIREMENT | Controller публикует provider directory с immutable profiles, model metadata, auth modality, readiness, limits и policy eligibility. |
| FR-004 | USER REQUIREMENT | Используются только официально поддержанные subscription/account/API/local modalities; scraping cookies/tokens и перенос private auth material запрещены. |
| FR-005 | PROPOSAL | Auth readiness выражается состоянием и opaque account-handle ref; credentials остаются в изолированном provider home/principal. |
| FR-006 | USER REQUIREMENT | Provider-neutral lifecycle поддерживает start, turn stream, send/steer, wait/collect, cancel, status/result, reconnect и terminal recovery. |
| FR-007 | USER REQUIREMENT | Per-session mesh MCP предоставляет `listProfiles`, `spawn`, `spawnBatch`, `send`, `steer`, `wait`, `collect`, `cancel`, `list`, `status`, `result`; model-facing `spawn*` семантически вызывает Controller `proposeSpawn*` и не запускает provider напрямую. |
| FR-008 | VERIFIED / inherited | Только Controller admission превращает bounded untrusted `SpawnProposal` в sealed typed `WorkOrder`/role order + exact `RunDispatchBinding`; caller-supplied seal, authority fields или готовый binding отклоняются. |
| FR-009 | PROPOSAL | Mesh хранит root/parent lineage, запрещает self-edge, ancestor-edge, duplicate active edge и любой cycle. |
| FR-010 | USER REQUIREMENT | Каждый admitted spawn имеет canonical `ExecutionLimits.v1` с mandatory finite positive depth, fanout, concurrency, token, wall-time, retry, output и discriminated monetary/non-monetary cost limits; missing/zero/negative/unbounded/unknown-unit limits отклоняются. |
| FR-011 | VERIFIED / inherited | Child не наследует capabilities/approvals/network/credentials parent; effective envelope вычисляется заново и не может расширить grant. |
| FR-012 | PROPOSAL | `WorkspaceGroup` связывает allowlisted roots, isolation mode, writer concurrency и cleanup policy; cross-group access запрещён. |
| FR-013 | USER REQUIREMENT | Filesystem, subprocess, network, browser, CUA, MCP и effects доступны только через раздельные Controller-owned per-session endpoints с non-model-visible audience-bound credential, authenticated peer identity/mTLS-or-equivalent, expiry/rotation/nonce/replay/revoke. |
| FR-014 | VERIFIED / inherited | PD dispatch идёт только в pinned local Qwen profile с `network=none`, без cloud fallback, cloud result и mesh fanout. |
| FR-015 | CONFLICT + PROPOSAL | Каждый cloud recipient требует exact destination-bound `CloudDisclosurePlan`; multi-recipient execution дополнительно требует consumed `FanoutGrant`. |
| FR-016 | VERIFIED / inherited | До ADR по fanout Controller резервирует максимум один cloud destination, по умолчанию Codex; иной cloud recipient требует explicit owner selection. |
| FR-017 | PROPOSAL | Go 1.26 core использует малые consumer-side interfaces `SessionStarter`, `TurnStreamer`, `SessionController`, `UsageReporter`, `HealthChecker`; `MeshCoordinator` владеет state, adapters внешние, `cmd/main` — manual DI composition root. |
| FR-018 | PROPOSAL | Все provider calls принимают `context.Context`; error taxonomy различает invalid, policy_denied, auth_required, quota, rate_limited, unavailable, protocol, cancelled, deadline, uncertain и compensation failure. |
| FR-019 | VERIFIED + PROPOSAL | Codex adapter использует official CLI/app-server ChatGPT subscription или API-key mode, isolated `CODEX_HOME`, pinned protocol probe и Controller capability endpoint. |
| FR-020 | VERIFIED + PROPOSAL | Claude adapter использует official Claude Code/Agent SDK с native account/subscription или supported API provider, isolated home/settings и stream-json/SDK lifecycle probe. |
| FR-021 | VERIFIED + PROPOSAL | Qwen adapter поддерживает Alibaba Coding Plan/API либо explicit local Qwen; discontinued OAuth не предлагается; PD и general profiles физически/логически разделены. |
| FR-022 | VERIFIED + PROPOSAL | Kimi adapter поддерживает official Kimi Code membership OAuth/device flow либо platform API key, isolated `KIMI_CODE_HOME`, quota/reconnect/cancel probes. |
| FR-023 | VERIFIED | DeepSeek adapter использует API key/top-up API route; subscription automation отсутствует до нового official evidence и ADR. |
| FR-024 | PROPOSAL | DSH Cordis, subagent registry/control/report, model selection UI, `ui-subagent` и Controller read bridge переиспользуются только после feasibility gate; default status/UI projection идёт по отдельному authenticated Controller channel, не через AgentLoop/model prompt/session log. |
| FR-025 | USER REQUIREMENT | Controller-owned plugin set включает provider-directory, session-mesh, provider-switcher, session-graph, compare/synthesis/run-templates, policy/approval-inspector, provider/deployment diagnostics и plugin-lifecycle operations. |
| FR-026 | USER REQUIREMENT | Thin native packages/manifests для Codex/Claude/Qwen/Kimi подключают тот же per-session mesh MCP; DeepSeek идёт через DSH/API adapter без fictitious subscription plugin. |
| FR-027 | USER REQUIREMENT | Provider switcher показывает eligibility/readiness/quota/policy, создаёт новую session revision или clean fork и никогда молча не меняет provider активной turn. |
| FR-028 | PROPOSAL | Session graph и compare/synthesis templates отображают lineage, параллельные attempts, provenance, partial/failed results и synthesis source coverage. |
| FR-029 | USER REQUIREMENT | Policy/diagnostics UI показывает capability envelope, approvals, fanout destination, auth readiness, rate/quota/health и deployment gates; lifecycle mutations требуют exact Controller operation. |
| FR-030 | PROPOSAL | System prompt каждого run собирается из immutable role/profile/policy sections; provider-native system/project instructions считаются input и проходят allowlist/attestation. |
| FR-031 | USER REQUIREMENT | Controller пишет typed event JSONL с run/session/provider/attempt correlation и bounded sanitized projections; raw token/prompt/credential по умолчанию не логируется. |
| FR-032 | USER REQUIREMENT | Recovery поддерживает leases, idempotency, reconnect, cancel propagation, retry budget, quota/rate backoff и отдельные primary/compensation outcomes. |
| FR-033 | USER REQUIREMENT | Ansible получает read-only `diagnose.yml`/`--doctor-json`, shared typed error schema и safe bounded parser. |
| FR-034 | USER REQUIREMENT | Deployment ведёт per-run locked journal и independently anchored `JournalCheckpoint.v1`, HMAC/signed Controller-held protected verifier key, состояния candidate/activated/failed/rolled-back; различает configuration_converged, activation_complete, operational_ready и operator_gate. |
| FR-035 | USER REQUIREMENT | Ansible использует exact per-task become, production vars без example file, full plan validation, true scoped verify при activation=false, cleanup-as-compensation, rollback diagnostics, manifest v2 provider bundles и trusted signed `ReleaseEnvelope.v1`. |
| FR-036 | USER REQUIREMENT | CI/VM gates покрывают lint/schema/contracts, simulator, fault injection, secret canaries, privileged disposable macOS VM, fresh/idempotent/upgrade/failure/rollback/retry, Apple Silicon и отдельное Intel decision. |
| FR-037 | USER REQUIREMENT | Adapter получает status `operational` только после owner-approved real no-private-data canary + reconnect + quota + cancel + failure-recovery; synthetic/compatibility уровни отображаются честно. |
| FR-038 | VERIFIED + PROPOSAL | `WorkOrder.v2`/mesh state вводятся additive с explicit v1 migration/replay/rollback; текущий linear v1 contract не перезаписывается in-place. |
| FR-039 | INDEPENDENT REVIEW | `SpawnProposal.v1` содержит только bounded intent/profile preference/input refs/output request; caller root/run/session/attempt/parent выводятся исключительно из authenticated `MeshEndpointBinding`, а Controller mint’ит order/run/session IDs, hashes, reservations, capabilities, lease и seal. |
| FR-040 | INDEPENDENT REVIEW | Consumer-side `MeshToolTransport` является provider-neutral capability; для Codex/Claude/Qwen/Kimi/DeepSeek фиксируется отдельный pinned mapping start→tool exposure→spawn proposal→collect/cancel, а `mesh_spawn=false` до verified mapping. |
| FR-041 | INDEPENDENT REVIEW | Endpoint authorization bind’ит session/run/attempt/tool/audience/peer identity/policy/expiry/nonce; rotation/revoke invalidates outstanding credentials, cross-session/process replay fail-closed. |
| FR-042 | INDEPENDENT REVIEW | P0 принимает механизм UI projection; до доказательства secure DSH UI integration P3 использует separate Controller UI client/channel без append в model/session log и без AgentLoop wakeup. |
| FR-043 | INDEPENDENT REVIEW | Profile safe default — `mesh_spawn=false`; enablement требует explicit `ExecutionLimits.v1`, verified transport mapping и current policy/evidence record. |
| FR-044 | INDEPENDENT REVIEW | Journal tamper evidence требует independently stored/anchored signed/HMAC checkpoint; локальная hash chain без защищённого anchor не называется tamper-evident. |
| FR-045 | INDEPENDENT REVIEW | Apply/activate принимает только trusted `ReleaseEnvelope.v1`, подписанный pinned key: manifest/release digest, platform, architecture, artifact set, schema/min-installer, sequence/nonce, issued/expiry; unknown key/replay/mismatch блокируют до mutation. |
| FR-046 | INDEPENDENT REVIEW | P0 и каждый P4 refresh создают reproducible `ProviderEvidenceRecord.v1` с official URLs/date/runtime/claim mapping/digests/freshness и signature/Controller approval, bound to pinned technical+security reviewer identities; stale/missing/untrusted record выключает profile/mesh spawn. |
| FR-047 | INDEPENDENT REVIEW | Каждая mesh operation проходит canonical caller→target lineage authorization matrix: child не управляет sibling/ancestor, foreign root всегда deny; root наблюдает/контролирует descendants только с exact order/policy capability. |
| FR-048 | INDEPENDENT REVIEW | Proposal idempotency bind’ит authenticated binding generation/session/attempt + `client_nonce` + canonical proposal digest; exact retry возвращает original proposal/run, conflicting nonce reuse reject, record crash-safe retained не меньше retry/recovery window. |

## Нефункциональные требования

| ID | Attribution | Требование |
|---|---|---|
| NFR-001 | VERIFIED / inherited | Fail-closed при unknown schema/provider/profile/auth/classification/provenance/capability/destination/outcome. |
| NFR-002 | VERIFIED / inherited | Least privilege и no ambient authority применяются к process, credential, filesystem, network, browser, CUA, MCP и effect. |
| NFR-003 | USER REQUIREMENT | Provider credentials, raw tokens/prompts и private account identifiers не попадают в repo, logs, DSH session, Beads или другой provider. |
| NFR-004 | PROPOSAL | Isolation доказуема OS boundary; same-UID file modes, in-process `toolFilter` и environment scrubbing сами по себе недостаточны. |
| NFR-005 | PROPOSAL | Mesh/deployment state versioned, canonical и crash-safe; tamper-evident claim допустим только при independently anchored signed/HMAC checkpoint с protected verifier, uncertain outcome не retry’ится вслепую. |
| NFR-006 | USER REQUIREMENT | Cycle/fanout/depth/concurrency/budget enforcement выполняется до spawn и повторно перед dispatch. |
| NFR-007 | USER REQUIREMENT | Cancellation ограниченно по времени достигает child/process/tool endpoints; невозможность подтвердить quiescence становится `uncertain`. |
| NFR-008 | PROPOSAL | Provider adapter updates pinned по version/digest/protocol evidence, имеют reproducible fresh evidence record и rollback compatibility window; stale evidence disables route. |
| NFR-009 | USER REQUIREMENT | Observability metadata bounded, sanitized, correlated и достаточна для source→run→attempt→result→effect audit без raw content. |
| NFR-010 | USER REQUIREMENT | Artifacts шифруются at rest, имеют per-class TTL/erasure status; telemetry default-off. |
| NFR-011 | PROPOSAL | Quota/rate/health/latency/cost semantics provider-specific, но нормализуются без выдуманных значений; unknown остаётся unknown. |
| NFR-012 | USER REQUIREMENT | UX явно различает root selection, provider switch, model switch, child dispatch, approval, effect и deployment operation. |
| NFR-013 | VERIFIED / inherited | PD high-water sticky; PD payload/result не достигает cloud provider, DSH event bus или compare/synthesis cloud route. |
| NFR-014 | PROPOSAL | Go implementation соответствует Go 1.26, manual DI, small interfaces, explicit context/error handling и boring composition root. |
| NFR-015 | USER REQUIREMENT | Ansible операции идемпотентны, collision-safe, rollback-diagnostic и не маскируют primary failure compensation/cleanup ошибкой. |
| NFR-016 | USER REQUIREMENT | Validation layers разделены на contract, synthetic adapter, pinned CLI compatibility, security/fault injection, macOS VM и real canary. |
| NFR-017 | PROPOSAL | Никакая документация/diagnostic readiness не считается proof of account entitlement или production operation без соответствующего test gate. |
| NFR-018 | VERIFIED / inherited | Specification-only не разрешает install/login/account connection/sudo/become/network/effect или deployment mutation. |
| NFR-019 | INDEPENDENT REVIEW | Untrusted caller cannot construct, sign, hash-seal or cause reuse of `WorkOrder`, `RunDispatchBinding`, capability/disclosure/budget reservation, lease or release envelope. |
| NFR-020 | INDEPENDENT REVIEW | Mesh/capability/UI endpoint credential не доступен model-visible context/log, single-audience, short-lived, rotation/revoke/replay protected и bound to authenticated process/session peer. |
| NFR-021 | INDEPENDENT REVIEW | Missing/stale/unsigned provider evidence, transport mapping, execution limits, UI feasibility decision, journal anchor или release envelope keeps affected feature disabled. |
| NFR-022 | INDEPENDENT REVIEW | Caller identity/lineage никогда не берётся из model/plugin payload; foreign parent/root/run/session/attempt reference cannot influence admission or target authorization. |

Каждый ID имеет ровно одну строку в [traceability](15-traceability.md).
