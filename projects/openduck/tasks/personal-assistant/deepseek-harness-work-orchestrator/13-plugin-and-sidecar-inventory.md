# 13. Инвентарь distribution, UI bundle и sidecar

## Capability labels

- `VERIFIED / upstream` — механизм существует в pinned source.
- `VERIFIED / bounded prototype, not integrated/production` — локальный artifact/probe есть, но target DSH boundary/enablement не доказаны.
- `AVAILABLE, NOT INSTALLED` — capability есть в каталоге, но отсутствует в runtime.
- `PROPOSAL` — компонент надо разработать.
- `DECISION REQUIRED` — подключение блокируется решением/gate.

## Рационализированная поставка DSH

| Artifact | Status | Responsibility | Explicit exclusion |
|---|---|---|---|
| pinned `openduck-dsh-distribution/profile` | PROPOSAL | exact fork commit, profile, disabled default model/agents, manifests/lockfile/SBOM | ambient home plugins, unpinned packages, credentials |
| one `openduck-ingress-fork` | PROPOSAL | CloudAdmittedPrompt gate, idempotent append receipt for every cloud ingress/injection path | DLP/local PD dispatch; bypass route |
| one `openduck-command-center-bridge-ui` bundle | PROPOSAL | separate authenticated UI read-model channel, Command Center routes | session-event domain persistence, model context, authority |
| minimal `openduck-codex-adapter` | PROPOSAL | admission/thread/event mapping to external runner | supervising Codex, auth/token path, ordinary DSH LLM provider |
| optional safe-public tools | PROPOSAL / real network disabled until P7+DR-022 | GET/navigation public web and Context7-safe queries; bounded live/revoke gate | private payload/MCP, forms/uploads/credentials/private nets/effects |
| `openduck-eval` | PROPOSAL / test-only | replay, append-path, injection, privacy, auth/network/compatibility suites | production profile or data |

Controller, а не plugins, владеет DAG, scheduler, memory policy, admission, capability/approval and effects. Официальный DSH Codex package обозначается только как one-shot subagent bridge reference to extend/replace, never normal LLM provider.

## External native/local modules

| Component | Status | Boundary |
|---|---|---|
| `openduck-controller` + Controller MCP/UI proof | VERIFIED / bounded prototype, not DSH-integrated/production | deterministic TCB, ledgers and native trusted decisions |
| external `openduck-codex-runtime` runner | VERIFIED / bounded prototype, not DSH-integrated/production | P5 protocol/auth stub only; real owner login/use P7+DR-020+explicit authorization |
| `openduck-qwen-sidecar` + native `LocalPDView` | PROPOSAL; Ollama/Qwen baseline locally evidenced | Controller-owned `LocalPDDispatch` raw boundary, no DSH/plugin/browser session |
| `openduck-macos-chat-call-sensor` | PROPOSAL | signed AXObserver for allowlisted enterprise-chat/TG/call apps; best-effort/unknown coverage |
| `openduck-cuadriver-proxy` | VERIFIED / bounded prototype, not DSH-integrated/production | bounded snapshots behind Controller; never cloud/private MCP child |
| `openduck-kaiten-reader` | PROPOSAL; official API VERIFIED | read-only token/process, manifest-qualified webhook/poll coverage |
| `openduck-graph-reader` | PROPOSAL | Mail.ReadBasic; calendar polling/delta permission conflict gate |
| `openduck-beads-helper` | PROPOSAL; local policy VERIFIED | typed issue/memory operations; `PrivateMemoryRef` only outward |
| `openduck-techbase-create-writer` | PROPOSAL | owner-authored exact declassified bytes + separate create approval; exclusive create-new only; update/purge deferred |
| `openduck-scheduler-notifier` | PROPOSAL | durable Controller jobs and own-app local macOS notifications |
| per-effect writer modules | PROPOSAL / disabled | reply/Kaiten/Graph/time; separate credentials/processes |

DSH never spawns, parents or directly configures private MCP/readers/Qwen/Codex runtime. Controller/supervisor owns those processes; DSH sees only authenticated safe façades/read models.

## Requested integrations

| Integration | Target use | Baseline policy |
|---|---|---|
| Obsidian | scoped read; approved report create | external Controller module; no copied token; first write create-only |
| CuaDriver | enterprise-chat/TG bounded reads | verified prototype behind Controller; no generic input/app control |
| Kaiten | watched-task reads | external reader; CapabilityManifest determines actual events; no writer in reader |
| Context7 | public technical docs | synthetic until P7/DR-022; no private payload/source refs; live conformance+revoke |
| public web | broad GET/navigation research | synthetic until P7/DR-022; no semantic total cap; bounded response/time/concurrency/backpressure; live deny/revoke evidence |

Configured-in-local-overlay status не наследуется автоматически. Каждый dependency требует source/version/schema/tool/destination/process-parent/network/credential and negative probe. Для credential/raw-store modules process-parent/ref не является isolation: DR-020 требует OS-enforced malicious-DSH denial before real data/auth.

## Outlook catalog note

`AVAILABLE, NOT INSTALLED`: Outlook Email/Calendar plugins есть только в recommended Codex/ChatGPT catalog. Они не DSH dependency и не устанавливаются. Baseline — external Graph reader; calendar permission/strategy решается DR-005 без silent scope escalation.

## Supply-chain acceptance

`VERIFIED`: DSH package management delegates pnpm and source packages may run install/prepare; MCP commands run outside agent sandbox. Distribution допускает только reviewed source and install scripts, exact commit/tarball digests, lockfile, SBOM/license, `allowBuilds` decision, isolated build, offline/reproducible artifact where possible and config-dump comparison. Home-level patches, implicit package discovery and ambient MCP запрещены.

## Install state

Этот пакет ничего не устанавливает. Любой implementation work order отдельно перечисляет digests, destination, commands, build scripts, network domains, credentials absence/presence, rollback and approver.
