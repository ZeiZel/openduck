# 14. Реестр источников

Дата проверки web/local evidence: 2026-08-25. `VERIFIED` означает capability/claim, не enablement, entitlement или operational readiness.

## User и inherited normative sources

| ID | Source | Подтверждает |
|---|---|---|
| SRC-USR-001 | `USER REQUIREMENT / 2026-08-25` | пять providers, official modalities, switching plugins, cross-provider children, system interaction, Ansible plan, specification-only |
| SRC-REV-001 | `INDEPENDENT REVIEW / 2026-08-25 / P1–P2 findings and closure audit` | proposal-only sealing and authenticated-parent derivation, caller→target matrix, proposal idempotency, provider transport/endpoint/UI/limits, anchored journal, trusted release, reviewer-bound volatile evidence |
| SRC-INH-001 | [Codex-root Operations Harness](../codex-root-operations-harness/README.md) и [conflicts](../codex-root-operations-harness/14-decisions-risks-conflicts.md) | Codex cognitive root, Controller TCB, no ambient authority, exact approvals |
| SRC-INH-002 | [DSH Work Orchestrator](../deepseek-harness-work-orchestrator/README.md) и [conflicts](../deepseek-harness-work-orchestrator/19-decisions-risks-conflicts.md) | DSH surface, exactly-one cloud egress, PD local Qwen, inherited gates |

## Local OpenDuck/DSH evidence

| ID | Source | VERIFIED claim |
|---|---|---|
| SRC-OD-001 | [Repository README](../../../../../README.md), lines 1–23 | synthetic-only posture; Go 1.26; no real integrations/cloud route |
| SRC-OD-002 | [store](../../../../../internal/harness/store.go), lines 23–27, 72–73; [controller](../../../../../internal/harness/controller.go), lines 15–29, 56–77, 255–278; [contracts](../../../../../internal/harness/contracts.go), lines 487+, 580+; [worker result](../../../../../internal/harness/worker_result.go), lines 7–43 | sole durable authority, linear lifecycle, Codex/app_server-or-exec/approval-never/workspace-write/network-false bindings |
| SRC-OD-003 | [Codex runner](../../../../../internal/codexruntime/runner.go), [profile](../../../../../internal/codexruntime/profile.go), [broker](../../../../../internal/codexbroker/broker.go), [protocol](../../../../../internal/codexruntime/protocol.go), lines 89–101; [isolation](../../../../../internal/codexruntime/production_isolation.go), lines 33–65 | Codex runtime/broker/profile/login/isolation seams |
| SRC-OD-004 | [local Qwen runtime](../../../../../internal/localpd/runtime.go), lines 15–17, 70–77, 101–118; [protocol](../../../../../internal/localpd/qwen_protocol.go), lines 1–46; [Controller](../../../../../cmd/openduck-controller/main.go), lines 501–503 | pinned synthetic local Qwen; production dispatch unavailable/fail-closed |
| SRC-DSH-001 | [DSH architecture](../../../../../third_party/deepseek-harness/docs/architecture.md), lines 5–27, 94–121 | Cordis plugin/services/events/capability seams; model-visible log; provider/tool extension points |
| SRC-DSH-002 | [subagent contract](../../../../../third_party/deepseek-harness/packages/subagent/subagent/src/types.ts), lines 75–149, 217–261; [Claude bridge](../../../../../third_party/deepseek-harness/packages/subagent/subagent-claude-code/README.md), lines 5–34, 96–105; [Codex bridge](../../../../../third_party/deepseek-harness/packages/subagent/subagent-codex/README.md), lines 5–30, 90–98; [ACP](../../../../../third_party/deepseek-harness/packages/subagent/subagent-acp/README.md), lines 19–33, 94–100 | registry/control contract; current one-shot/final-only limitations; ACP missing enforcement |
| SRC-DSH-003 | [ACP run](../../../../../third_party/deepseek-harness/packages/subagent/subagent-acp/src/run.ts), lines 242–303; [LLM catalog](../../../../../third_party/deepseek-harness/packages/llm/llm-pi-ai/src/catalog.ts), lines 136–160; [model selection](../../../../../third_party/deepseek-harness/packages/client/ui-model-selection/src/client/service.ts), lines 69–94; [sessions API](../../../../../third_party/deepseek-harness/packages/host/apiproxy/src/api/sessions.ts), lines 285–302; [credentials](../../../../../third_party/deepseek-harness/packages/credentials/credentials-local/README.md), lines 52–69; [plugin inventory](../../../../../third_party/deepseek-harness/packages/host/plugin-inventory/src/types.ts), lines 15–28 | ACP `mcpServers=[]`; API-key-only adapter auth acquisition; selection UI; same-UID credential weakness; read-only inventory |
| SRC-DSH-004 | [Controller read bridge](../../../../../plugins/controller-read-bridge/src/index.js), lines 1–100; [browser bridge](../../../../../plugins/controller-read-bridge/src/browser-client.js), lines 1–24; [plugin inventory README](../../../../../plugins/README.md), lines 1–13 | bounded read-only bridge; local plugins currently disabled/read-only |

## Local Ansible evidence

| ID | Source | VERIFIED claim |
|---|---|---|
| SRC-ANS-001 | [site playbook](../../../../../deploy/ansible/site.yml), lines 2–13; [lifecycle](../../../../../deploy/ansible/roles/lifecycle/tasks/main.yml), lines 6–17, 130–168; [plan](../../../../../deploy/ansible/roles/atomic_commit/tasks/plan.yml), lines 32–55; [readiness](../../../../../deploy/ansible/roles/readiness/tasks/main.yml), lines 163–176 | play-wide become/example vars, second-resolution run ID, partial plan validation, activation=false debug-only scoped verify |
| SRC-ANS-002 | [artifacts](../../../../../deploy/ansible/roles/artifacts/tasks/main.yml), lines 1–11; [callback](../../../../../deploy/ansible/callback_plugins/jsonl.py), lines 18–66; [installer](../../../../../internal/macosinstall/installer.go), lines 460–490, 2928–2934; [system ops](../../../../../internal/macosinstall/system_ops.go), lines 155–177; [inspection](../../../../../internal/macosinstall/inspection.go), lines 136–160 | fixed 11 artifacts; shared phase-light journal; active pointer/activated marker ordering; command/error parsing seams |
| SRC-ANS-003 | [static tests](../../../../../deploy/ansible/tests/test_static.py), lines 16–194 | current static/error fixtures and gaps for broader simulator/VM/fault matrix |

## Official provider sources

| ID | Source | VERIFIED claim |
|---|---|---|
| SRC-OAI-001 | [Codex authentication](https://learn.chatgpt.com/docs/auth), [app-server](https://learn.chatgpt.com/docs/app-server) | ChatGPT subscription and API-key sign-in; browser/device/app-server login lifecycle |
| SRC-OAI-002 | [Codex subagents](https://learn.chatgpt.com/docs/agent-configuration/subagents), [OpenAI plugins](https://developers.openai.com/plugins) | official subagent configuration and plugin composition with skills/MCP |
| SRC-ANT-001 | [Claude getting started](https://code.claude.com/docs/en/getting-started), [CLI reference](https://code.claude.com/docs/en/cli-usage) | eligible account/browser login and official automation/stream/schema surfaces |
| SRC-ANT-002 | [Claude agents](https://code.claude.com/docs/en/agents), [plugins](https://code.claude.com/docs/en/plugins) | parallel sessions/agents; plugin manifest/skills/agents/hooks/MCP |
| SRC-QWN-001 | [Qwen authentication](https://qwenlm.github.io/qwen-code-docs/en/users/configuration/auth/) | OAuth discontinued; Coding Plan dedicated endpoint/key; API/local providers |
| SRC-QWN-002 | [Qwen headless](https://qwenlm.github.io/qwen-code-docs/en/users/features/headless/), [subagents](https://qwenlm.github.io/qwen-code-docs/en/users/features/sub-agents/) | JSON/stream-json and subagent/fork semantics/limitations |
| SRC-DSK-001 | [DeepSeek coding-agent integration](https://api-docs.deepseek.com/guides/coding_agents/), [DeepSeek API](https://api-docs.deepseek.com/api/deepseek-api) | API-key integration; no verified harness subscription automation |
| SRC-KIM-001 | [Kimi membership](https://www.kimi.com/code/docs/en/kimi-code/membership.html), [getting started](https://www.kimi.com/code/docs/en/kimi-code-cli/guides/getting-started) | membership quota, OAuth device flow, API key, KIMI_CODE_HOME/session commands |
| SRC-KIM-002 | [Kimi plugins](https://www.kimi.com/code/docs/en/kimi-code-cli/customization/plugins.html), [agents](https://www.kimi.com/code/docs/en/kimi-code-cli/customization/agents) | native plugin MCP/lifecycle and agent/subagent behavior, permission inheritance risk |

## Evidence protocol

- Volatile provider/CLI/auth claims rechecked at each compatibility/canary gate.
- P0/P4 generates one signed `ProviderEvidenceRecord.v1` per provider/profile modality: exact official URL list, UTC retrieval date, pinned runtime/package/protocol/model versions, canonical claim→modality mapping, source-content SHA-256, runtime artifact/schema digests, generator version, freshness deadline, pinned technical/security reviewer identities and record digest/signatures or exact Controller approval ref. The record, not this prose table, is the reproducible promotion artifact.
- Freshness is finite and policy-defined at P0; expiry or any URL/content/runtime/artifact/mapping digest drift atomically sets `mesh_spawn=false` until reviewed P4 refresh. A health probe never extends freshness.
- Official documentation establishes supported modality, not the owner’s entitlement or account readiness.
- Local line references describe inspected snapshot; concurrent dirty changes require a fresh diff before implementation.
- No source entry is authorization to install, log in, spend, deploy or enable effects.
