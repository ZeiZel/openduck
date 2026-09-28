# 15. Реестр источников

Все web/manual claims verified 2026-08-12. Normative links ниже указывают на permanent official OpenAI documentation/source URLs and named sections, не на ephemeral cache paths. Для воспроизводимости использован non-normative fetched artifact `codex-manual.md`, SHA-256 `19ed45b575be208d154fe570a8a05b4c9d7045c4ff4036436eef6f38571f92d5`; digest подтверждает только проверенный corpus на эту дату, не account entitlement, host support или configured enablement.

## Official OpenAI documentation and sources

| ID | Source | Использование |
|---|---|---|
| SRC-CX-01 | [Best practices — Strong first use; AGENTS.md; Configure Codex](https://learn.chatgpt.com/guides/best-practices) | prompt goal/context/constraints/done; AGENTS layering; config/sandbox |
| SRC-CX-02 | [Best practices — Organize long-running chats](https://learn.chatgpt.com/guides/best-practices#organize-long-running-chats) | one coherent outcome/thread, resume/fork/compact, bounded subagents |
| SRC-CX-03 | [Subagents — Why subagent workflows help; Core terms](https://developers.openai.com/codex/agent-configuration/subagents) | context hygiene, summaries, parallel read-heavy work |
| SRC-CX-04 | [Subagents — Choosing models and reasoning; Orchestration](https://developers.openai.com/codex/agent-configuration/subagents) | Sol/Terra/Luna role basis and orchestration |
| SRC-CX-05 | [Subagents — Approvals and sandbox controls; Custom agents; schema](https://developers.openai.com/codex/agent-configuration/subagents) | current sandbox/permission inheritance; child override reapplication; agent model/sandbox/MCP/skills |
| SRC-CX-06 | [Build skills — How ChatGPT and Codex use skills; Best practices](https://developers.openai.com/codex/skills) | progressive disclosure and focused workflows |
| SRC-CX-07 | [Hooks — Where Codex looks; Review and trust](https://developers.openai.com/codex/hooks) | lifecycle events, trust behavior |
| SRC-CX-08 | [Hooks — Tool coverage; Large hook output](https://developers.openai.com/codex/hooks) | hooks incomplete boundary; context spill risk |
| SRC-CX-09 | [Agent approvals & security — Sandbox and approvals](https://developers.openai.com/codex/agent-approvals-security) | sandbox vs approvals; app/MCP side effects |
| SRC-CX-10 | [Agent approvals & security — Network access; defaults](https://developers.openai.com/codex/agent-approvals-security) | network deny/default, proxy/domain/local protections |
| SRC-CX-11 | [Agent approvals & security — Run without prompts; Automatic approval reviews; combinations](https://developers.openai.com/codex/agent-approvals-security) | built-in approval behavior and limitations; not domain authorization |
| SRC-CX-12 | [Codex App Server — Overview; Protocol; Message schema; Lifecycle](https://developers.openai.com/codex/app-server) | official typed JSON-RPC rich-client surface, transports and thread lifecycle; not arbitrary desktop Controller envelopes/callback proof |
| SRC-CX-13 | [Codex App Server — API overview; Process and command execution](https://developers.openai.com/codex/app-server) | thread/turn/model/MCP methods and dangerous shell/process surface |
| SRC-CX-14 | [Codex App Server — App-server threads; Start or resume a thread](https://developers.openai.com/codex/app-server) | persisted threads, required MCP fail-closed, per-thread config |
| SRC-CX-15 | [Codex App Server — Turns; Sandbox read access; Start/interrupt a turn](https://developers.openai.com/codex/app-server) | per-turn model/cwd/sandbox/outputSchema/interrupt |
| SRC-CX-16 | [Codex App Server — Events; Approvals; requestUserInput; MCP elicitation](https://developers.openai.com/codex/app-server) | authoritative item/status events and built-in interaction flows; none is harness `OwnerDecisionEvent` |
| SRC-CX-17 | [Codex SDK — Usage; Sandbox presets](https://developers.openai.com/codex/sdk) | programmatic thread control and sandbox presets |
| SRC-CX-18 | [Non-interactive mode — Permissions; JSONL; structured output](https://developers.openai.com/codex/noninteractive) | separate `codex exec`, explicit sandbox, JSONL/output schema alternative |
| SRC-CX-19 | [Use Codex with the Agents SDK — Codex MCP server](https://developers.openai.com/codex/mcp-server) | Codex-as-specialist alternative and MCP tool contract |
| SRC-CX-20 | [Scheduled tasks — Permissions and security model](https://developers.openai.com/codex/app/automations) | scheduler capability and permission caveats; not direct effect authority |
| SRC-CX-21 | [Add UI to your MCP server — Overview; Start with MCP Apps; ChatGPT extensions; CSP](https://developers.openai.com/plugins/build/chatgpt-ui) | optional iframe UI in ChatGPT/compatible hosts and `ui/*` bridge; does **not** prove target Codex desktop render or secure Controller callback |
| SRC-CX-22 | [Official app-server implementation source](https://github.com/openai/codex/tree/main/codex-rs/app-server) | inspectable version-pinned implementation reference; docs/schema/live probe remain required |

## Repository evidence/specifications

| ID | Source | Использование |
|---|---|---|
| SRC-OD-01 | [Private assistant README](../private-openclaw-assistant/README.md) | scope, no-mutation invariant, gates |
| SRC-OD-02 | [Architecture](../private-openclaw-assistant/02-system-architecture.md) | trust boundaries, components, sessions, schemas |
| SRC-OD-03 | [Data/egress policy](../private-openclaw-assistant/04-data-classification-egress-policy.md) | L0–L3, SafeEnvelope, allow/ask/deny |
| SRC-OD-04 | [Approval workflow](../private-openclaw-assistant/06-workflows-and-approval-gates.md) | exact payload/hash/TTL/CAS/UNKNOWN |
| SRC-OD-05 | [Model routing](../private-openclaw-assistant/08-local-model-and-cloud-routing.md) | Qwen/local role, no silent fallback, OAuth/API conflict |
| SRC-OD-06 | [OpenClaw runtime evidence](../../../../../docs/evidence/openclaw-runtime.md) | pinned runtime/model, denied tools, MCP inventory/probes |
| SRC-OD-07 | [Tracked OpenClaw config](../../../../../deploy/openclaw/config.json) | exact local configuration and tool filters |
| SRC-OD-08 | [PD router implementation](../../../../../deploy/openclaw/pd-router-plugin/index.mjs) | marker/sticky/quarantine/model/tool gates |
| SRC-OD-09 | [Core implementation](../../../../../internal/core/core.go) | classification floor, event/provenance, pseudonyms |
| SRC-OD-10 | [Encrypted queue](../../../../../internal/core/filequeue.go) | leases, crash/uncertain-commit behavior |
| SRC-OD-11 | [SafeEnvelope schema](../../../../../schemas/safe-envelope.v1.json) | compatibility boundary |

## Session/user supplied inventory

| ID | Source | Использование |
|---|---|---|
| SRC-ENV-01 | `USER-SUPPLIED / 2026-08-12`: current session capability/plugin inventory and read-only audit findings | observed Codex Browser/Chrome/CUA surfaces, local GitLab CLI workflow, available-but-not-installed GitHub/Gmail/Google Calendar/Outlook plugins; observation не доказывает auth/install/entitlement |
| SRC-ENV-02 | `USER-SUPPLIED reviewer findings / 2026-08-12` | required all-ingress PD gate, exact declassification/grant/UI-preview tuples, sensor deny-all, clean Codex profiles and UI delivery feasibility gaps |
| SRC-USER-01 | `USER DECISION / 2026-08-12` | one Codex-facing interface; delivery mechanism remains H0 decision/probe; deterministic Controller retains lifecycle/capability/approval/effect authority; bounded implementation uses native Codex runtime only |

## Evidence quality rule

Manual claims are product capability evidence, not proof that current account/runtime enables them. In particular, MCP Apps docs prove ChatGPT/compatible-host UI semantics, not target Codex desktop rendering or a secure Controller callback; app-server docs prove typed rich-client APIs, not arbitrary envelopes in existing desktop UI. Config is intended state, not live proof. Before implementation/enablement each volatile capability gets a pinned live probe with version/time and non-sensitive artifact. User decisions define target architecture but do not prove runtime availability or grant execution authority.
