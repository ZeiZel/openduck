# 03. Матрица provider access

## Нормативная матрица

| Provider | Официально подтверждённые modalities | Target adapter | Auth ownership | Status до gates |
|---|---|---|---|---|
| Codex | ChatGPT subscription sign-in; OpenAI API key | native CLI/app-server broker | isolated `CODEX_HOME`/principal; opaque handle | `contract-only`; Codex default root |
| Claude | Pro/Max/Team/Enterprise/Console browser login; supported API/third-party provider | Claude Code/Agent SDK native broker | isolated Claude home/settings/principal | `contract-only` |
| Qwen | Alibaba Cloud Coding Plan dedicated endpoint/key; standard API; explicit local compatible runtime | Qwen Code headless/daemon or local adapter | isolated Qwen home; PD home separate | `contract-only`; discontinued OAuth hidden |
| Kimi | Kimi membership OAuth device flow; Kimi Platform API key | Kimi Code CLI/ACP/server adapter | isolated `KIMI_CODE_HOME`/principal | `contract-only` |
| DeepSeek | API key/top-up API route | DSH `llm-pi-ai`/dedicated API adapter | Controller credential reference in isolated broker | `contract-only`; no subscription claim |

## Profile schema

`ProviderProfile.v1` содержит: `profile_id`, `provider`, `model`, `runtime_kind`, pinned runtime/protocol digests, `auth_modality`, opaque `account_handle_ref`, supported lifecycle features, input/output modalities, `system_policy_id`, tool policy, workspace policy, cloud/local destination, quota semantics, cost semantics, health probe, classification eligibility, `mesh_spawn`, `mesh_transport_mapping_digest`, `execution_limits_digest`, `provider_evidence_digest` и closed `status=disabled|configured|auth_required|ready|degraded|compatible|incompatible`. `compatible` — единственный P4 admission status: в v1 `ready` не означает canary/readiness attestation и не даёт mesh spawn.

Profile не содержит tokens, cookies, browser storage, API key bytes, raw provider config или absolute credential path, видимый модели. Provider/account switch создаёт новую immutable selection revision.

Safe initialization: `mesh_spawn=false`; mapping/limits/evidence поля отсутствуют. Controller может выставить `true` только атомарной profile revision после current mapping compatibility, explicit finite limits и fresh provider evidence.

## Readiness ladder

1. `declared`: source-backed modality и frozen schema.
2. `synthetic`: fake adapter проходит contracts/lifecycle/cancel/errors.
3. `compatible`: pinned real CLI/protocol без private data проходит handshake.
4. `canary`: owner-approved account выполняет no-private-data turn.
5. `operational`: дополнительно пройдены reconnect, quota/rate, cancel, failure recovery.

`USER REQUIREMENT`: UI не сокращает ladder до бинарного «работает». Expired auth, quota/rate window, provider outage и protocol drift немедленно понижают readiness.

## Запрещённые подстановки

- OAuth token, извлечённый из browser storage/cookie, не становится account handle.
- API compatibility не доказывает subscription entitlement.
- Qwen Coding Plan key не называется OAuth.
- DeepSeek API balance/top-up не называется subscription.
- Kimi/Claude/Codex native login state не копируется в DSH credential file.
- Локальный Qwen profile не имеет права fallback в Qwen cloud/Coding Plan.
