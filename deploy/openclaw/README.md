# OpenClaw local runtime

Pinned packages: `openclaw@2026.7.1-2` and official `@openclaw/codex@2026.7.1-1` (npm integrity recorded in `package-lock.json`).
Runtime is loopback-only at `http://127.0.0.1:18789`, token-authenticated, and configured for
normal requests use the isolated native Codex app-server route `openai/gpt-5.6-sol`; a `Это ПД` first-line marker (and conservative near-miss quarantine) latches the session to exact local Ollama `qwen3:8b` before model resolution. Local Ollama retains native `40960` context, a `32768` working context budget, conservative `medium` thinking enabled, and no model fallbacks. State and token are outside
tracked configuration; never print the token. MCP bridges are read-only filtered and the
filesystem bridge is disabled/reserved; direct Obsidian MCP is the active read-only surface.

Use `scripts/openclaw-cli.sh <command>` for CLI commands. Use `scripts/openclaw-ui.sh` to invoke
the pinned `openclaw dashboard` command. That official flow opens the local Control UI at
`http://127.0.0.1:18789/`, placing the token only in the browser URL fragment/clipboard for
authentication; it does not print the token or store it in tracked files. The launcher expects the
already-running loopback Gateway and does not install or start a different service.
For owner-only direct Gateway RPC diagnostics, use `scripts/openclaw-gateway-call.sh`; it passes
the runtime token explicitly without printing it.

Session maintenance follows the pinned Gateway policy. Archive/restore is a
`sessions.patch` operation and requires the authenticated operator's
`operator.write` scope; the Control UI intentionally disables archive for the
default `main` session, global/unknown rows, and rows with an active run.
Bulk **Delete** is a `sessions.delete` operation and requires
`operator.admin` (the UI sends a normal delete, which archives the transcript
before removing the entry). The tracked runtime keeps the generic agent-tool
`delete` deny in place; that deny does not gate these authenticated Control UI
RPCs and must not be removed as a workaround.

Built-in web tools remain disabled. Browser automation, execution, messaging,
writes/uploads, and elevated tools remain denied. Normal `openai/gpt-5.6-sol`
turns may use only the configured safe `bundle-mcp` surface; private-source MCPs
(Obsidian, Kaiten, CuaDriver, and filesystem bridge) are disabled until a local
sanitizing envelope proxy exists. Enabled MCPs are limited to public Context7,
the SSRF-hardened public web reader, and the synthetic `openduck-controller`
status/tasks/render probe. The Codex provider remains
Codex-harness routed. PD/quarantine sessions retain a provider-wide deny-all
policy and are additionally blocked by the router before any tool call.

The separate `public-search-readonly` MCP server exposes `search_public_web` and
`fetch_public_web`. Search uses the fixed HTTPS DuckDuckGo HTML endpoint and returns
untrusted results without a fixed result-count quota. Fetch accepts only public HTTP(S)
URLs and GET/HEAD; it follows at most five redirects, re-checks DNS on every hop,
rejects credentials, localhost/private/link-local/rebinding targets, and caps each
response at 500,000 bytes and 10 seconds. It never sends cookies/authentication,
submits forms, uploads, executes downloads, or permits unsafe schemes.
