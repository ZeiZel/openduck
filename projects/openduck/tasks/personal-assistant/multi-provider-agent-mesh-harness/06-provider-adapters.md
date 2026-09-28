# 06. Provider adapters

## Общий adapter contract

Adapter отвечает только за official runtime transport: readiness, start/session, turn stream, control, usage и health. Он не решает classification, fanout, capabilities, approvals, workspace access или effects. Unsupported operation возвращает typed `unsupported`, а не silent degradation.

Каждый adapter обязан:

- pin runtime/protocol version/digest и re-probe при update;
- запускаться в isolated home/principal с credential-scrubbed parent environment;
- не принимать credential bytes через model/mesh payload;
- отделять model transport network от tool/capability network;
- поддерживать context cancellation, bounded streams и deterministic teardown;
- нормализовать provider-native IDs только как evidence;
- сообщать quota/cost `unknown`, если official signal отсутствует.

## `MeshToolTransport` mappings

Одинаковая capability реализуется provider-specific transport, но выдаёт один Controller MCP schema и `MeshEndpointBinding.v1`:

| Provider | Target mapping | Compatibility proof before `mesh_spawn=true` |
|---|---|---|
| Codex | app-server thread configured with exact per-session Controller MCP; tool call → `SpawnProposal`; result/collect returned as tool result | pinned initialize/thread/tool-call/cancel transcript + endpoint audience/peer proof |
| Claude | Agent SDK/CLI isolated MCP config for exact session; SDK tool request → proposal; stream/final collect mapping | pinned SDK/CLI MCP/stream/cancel transcript + config isolation proof |
| Qwen | isolated headless/daemon MCP configuration; stream-json event/tool/result mapping | pinned version MCP + stream-json spawn/collect/cancel transcript; local/PD profiles separate |
| Kimi | isolated Kimi plugin/ACP/server MCP declaration; native event/result mapping | pinned version plugin/MCP/session/interrupt transcript + permission-isolation proof |
| DeepSeek | Controller/DSH API adapter exposes mesh tool schema through provider tool-calling seam; tool result feeds same run | pinned API model tool-call/result/cancel compatibility fixture; no native subscription semantics |

Mapping record names exact runtime/protocol/model, tool schema digest, request/result event mapping, cancellation/quiescence behavior, endpoint auth mode and known unsupported features. Missing/partial/stale mapping means `mesh_spawn=false`; ordinary non-mesh single turn may be separately eligible.

## Codex

`VERIFIED`: official sign-in supports ChatGPT subscription и API key; app-server exposes account login lifecycle. Target — persistent broker-managed app-server session, а не текущий one-shot final-answer bridge. Используются clean `CODEX_HOME`, pinned schema probe, explicit model/profile, approvals denied внутри native runtime и per-session Controller MCP как единственный tool surface. Existing broker/isolation seams переиспользуются; auth tokens не покидают Codex-owned store.

## Claude

`VERIFIED`: official Claude Code supports eligible account login and API-provider use; print/stream-json and Agent SDK expose automation surfaces. Target broker wraps official runtime, disables/denies native tools not routed through Controller, supplies isolated settings/home and captures bounded progress/final/usage. Текущий DSH one-shot bridge годится как compatibility fixture, но не как operational adapter из-за native settings inheritance, отсутствия continuation, usage и human approval path.

## Qwen

Cloud profile использует Alibaba Coding Plan dedicated endpoint/key либо official API configuration; discontinued Qwen OAuth исключён из directory. General local profile может использовать verified local compatible runtime. PD profile остаётся отдельным pinned Qwen `network=none/tools=none` route, не разделяет home/cache/session с general profile и не допускает mesh child/fallback. Headless stream-json является compatibility seam; двунаправленный режим не считается stable до pinned probe.

## Kimi

Target broker использует official Kimi Code CLI/ACP/server capability, `KIMI_CODE_HOME`, membership OAuth device flow либо platform API key. Native plugin/agent functionality не становится authority; built-in permission inheritance отключается/перекрывается Controller endpoints. Quota windows, `/usage`, reconnect, interrupt и session resume проверяются canary suite.

## DeepSeek

Target — dedicated API adapter или DSH `llm-pi-ai` API-key route с explicit base/model, Controller-held credential ref и no native subscription claim. DeepSeek не получает thin fictitious subscription plugin. Provider-specific API compatibility через Claude/OpenAI-compatible tooling не переносит authority или account semantics соответствующего client.

## Volatile provider evidence

`ProviderEvidenceRecord.v1` создаётся в P0 и refreshed перед каждым P4 compatibility decision. Closed record содержит provider/profile/modality, official URL set, UTC retrieval time, runtime/package/protocol/model versions, canonical claim→modality mapping, source-content SHA-256, runtime artifact/schema digests, evidence generator version, `fresh_until`, pinned technical/security reviewer key IDs, exact review decision refs и record digest/signatures. Alternative Controller approval record обязан bind’ить тот же record digest, обе approved reviewer identities/roles, freshness и profile revision. Profile revision verifier rereads trust/revocation registry and validates signatures/approval before enabling. Unknown/revoked signer, missing required reviewer, approval mismatch или digest mutation делает profile `incompatible` и `mesh_spawn=false`, даже если binary отвечает health probe.

## Maturity declaration

| Level | Разрешённая формулировка |
|---|---|
| Contract | «контракт определён» |
| Synthetic | «synthetic adapter прошёл suite» |
| Compatibility | «pinned CLI/protocol совместим с fixture» |
| Canary | «owner account прошёл no-private-data canary» |
| Operational | «canary + reconnect + quota + cancel + recovery пройдены» |

Слово «работает» допустимо только для `Operational` с датой, version/account modality и evidence refs.
