# Historical OpenClaw runtime evidence (retired)

This record describes the retired runtime and is retained for provenance only;
it is not an installation or deployment instruction for the current OpenDuck
base.

- Package: `openclaw@2026.7.1-2`; npm lockfile records the resolved package integrity.
- Config: `deploy/openclaw/config.json`; validated with `openclaw config validate`.
- Gateway policy: loopback-only, token auth from owner-only runtime file via `scripts/openclaw-start.sh`, UI `http://127.0.0.1:18789`.
- Model: local Ollama `http://127.0.0.1:11434`, `qwen3:8b` (observed digest `500a1f067a9f…`, Q4_K_M, 8.2B); no fallback/cloud provider.
- Security: browser, exec, process, message/channel mutation, cron, gateway/node/canvas and generic write/delete/mutate tools denied. MCP bridges use read-only exclusion filters; filesystem path is only `tech-base/inbox/OpenDuck`.
- Obsidian direct MCP uses an owner-only generated env file and exact read-only tool allowlist (`vault_list`, `vault_read`, `vault_get_document_map`, `search_simple`, `search_query`, `tag_list`, `active_file_get_path`, `command_list`). The bearer value is never recorded in repository files or evidence.
- CuaDriver is fronted by `deploy/openclaw/cua-readonly-proxy.mjs`: it exposes only safe status tools plus `list_allowed_windows`/`read_allowed_window`, filters bundles through the local overlay, verifies pid/window pairs, and never permits click/type/press/launch or screenshot file output.
- The redundant filesystem bridge is disabled; direct Obsidian MCP is the only Obsidian surface.
- Probe: Ollama `/api/tags` passed; Gateway health returned HTTP 200 and Control UI returned HTTP 200. Synthetic model smoke returned `LAUNCHD_OK` through Ollama `qwen3:8b` with no fallback. MCP discovery verified Context7 (2 read-only tools), Kaiten (8), direct Obsidian (8), and Cua read-only proxy (7). No real chat, calendar, or account data was read.
- No real chat/calendar/account data was connected or processed. No token is stored in tracked files or printed.
