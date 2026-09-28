# Codex UI delivery-binding probe — H0 scaffold evidence

Date: 2026-08-12  
Scope: checked-in plugin source plus the authorized personal-plugin installation. No external account, secret, Controller state, or real-data endpoint was accessed.

## Result

`PARTIAL` for static plugin and stdio-MCP protocol checks.  The AD-15 delivery gate remains **`UI_DELIVERY_BLOCKED`**: a headless source check cannot show that a pinned Codex desktop host discovers this plugin, renders the resource bytes in an MCP Apps iframe, issues a render receipt, or permits a direct replay-protected authenticated Controller callback.

This is deliberately not a secure-callback claim.  There is no callback implementation in the scaffold.

## Artifact under test

- Plugin: `plugins/openduck-control/`
- Bundled stdio server: `scripts/controller_mcp.py`
- Static resource: `assets/owner-preview.html`
- Headless probe: `scripts/codex-ui-binding-probe.py`

The plugin declares one local Python stdio MCP server and no external registered app mapping (`.app.json` is intentionally `{ "apps": {} }`).  The scaffold's only tools are `controller_status`, `controller_tasks`, and `render_delivery_probe`. They contain fixed synthetic output, have `readOnlyHint: true`, `destructiveHint: false`, and `openWorldHint: false`, and expose no approval, mutation, authentication, persistence, or effect capability. `controller_status` and `controller_tasks` may perform only fixed, bounded localhost reads; they disable proxies and redirects and convert all failures to safe disconnected/UI-blocked projections.

`render_delivery_probe` associates `ui://openduck-control/owner-preview.html` with its result.  Resource reads return the checked-in static HTML with MIME type `text/html;profile=mcp-app`.  The demo has explicit `DEMO ONLY` / `UI_DELIVERY_BLOCKED` text and a permanently disabled approval button.  It also contains a separate read-only loopback origin probe: the button stays disabled until the host exposes an opaque token through Codex's documented `window.openai.toolResponseMetadata` private bridge; feature detection and a short bounded hydration poll are used, with no arbitrary `postMessage` listener.  The token is held only in a closure and is never rendered, persisted, logged, or returned to the model.  The fetch is fixed to `http://127.0.0.1:8788/v1/controller/origin-probe`, uses `credentials: omit`, `cache: no-store`, `redirect: error`, `referrerPolicy: no-referrer`, and is constrained by a loopback-only CSP.  This probe is non-authoritative and cannot generate an `OwnerDecisionEvent` or approve an action.

## Evidence command

```sh
python3 scripts/codex-ui-binding-probe.py
python3 <codex-skills>/plugin-creator/scripts/validate_plugin.py plugins/openduck-control
```

The first command exercises `initialize`, `tools/list`, both permitted calls, `resources/list`, `resources/read`, and rejection of an authority-like unknown tool. It also prints the SHA-256 of the exact resource bytes. The canonical validator checks the checked-in package. Separately, the reviewed package was copied to a local plugin directory, registered in the personal marketplace, and installed/enabled as `openduck-control@personal`; the installed cache is managed by the local Codex installation. The repository and installed-cache resource bytes have the same SHA-256: `fd3e09770e152b3d63b172b5a316891ba6ced90cb08cc21edac56220ccb12781`. These installation checks do **not** start the Codex Desktop renderer or prove a live callback.

The resource additionally presents a bounded task-lifecycle dashboard. It requests only `GET /v1/controller/tasks`, renders IDs/states/versions plus boolean evidence/review/decision-presence with `textContent`, and never exposes a WorkOrder, preview, callback handle, decision proof or any operation control.

## What this proves

- The checked-in manifest points to existing `.mcp.json` and `.app.json` files.
- The MCP configuration is a local stdio definition rather than an HTTP endpoint.
- The server advertises exactly the three intended read-only status/task/render-probe tools.
- The MCP resource URI, metadata association, MIME type, and static HTML bytes agree.
- The synthetic UI contains no approval/callback mechanism; its only network operation is the explicit, bounded, non-authoritative loopback origin probe gated by private `_meta`.

## What remains unverified and blocks AD-15

- The exact target Codex desktop build and installed plugin bundle digest.
- Discovery and enablement by the current Codex Desktop task/session (the installation is present, but this session did not perform a live desktop discovery probe).
- Whether that desktop host actually supports and renders this MCP Apps resource.
- Iframe CSP/origin behavior and any host bridge behavior.
- An attested `InteractionRenderReceipt` / display instance binding.
- A direct Controller-authenticated, origin-protected, replay-protected callback that does not route decision material through model text, tool input/output, built-in approval, elicitation, or `tool/requestUserInput`.
- Forged iframe, `postMessage`, tool-result, stale-display, and callback replay negative tests.

The current static demo intentionally has no callback, so those properties cannot be inferred from the source or from this probe.

The Controller's diagnostic origin route is opt-in via `-origin-probe` (default
off) and is independent from authenticated callbacks. It accepts only `GET` and
`OPTIONS` on `127.0.0.1:8788`, requires a syntactically valid non-`null` HTTP(S)
`Origin`, and echoes that observed value only with `origin_trust: "untrusted"`.
The `X-OpenDuck-UI-Probe` value is a one-time high-entropy anti-noise token, not
authorization; it is neither echoed nor persisted.

## Source basis

The current official Codex manual says that an MCP server can return optional UI, that the shared MCP Apps route associates a UI resource using `_meta.ui.resourceUri`, and that the resource runs in a compatible host's iframe using a JSON-RPC `postMessage` bridge.  It also says a bundled plugin MCP server is configured by `.mcp.json`, while `.app.json` maps an already registered MCP connection rather than defining a UI resource.  The manual identifies Codex app-server as the interface for a separately built rich client; its protocol/schema are version-specific.  These are format/design sources, not proof of this desktop host's runtime support.

- [Add UI to your MCP server](https://developers.openai.com/plugins/build/chatgpt-ui.md)
- [Package your plugin](https://developers.openai.com/plugins/build/plugins)
- [Codex App Server](https://learn.chatgpt.com/docs/app-server.md)

## Root-only next steps for a live probe

The remaining work is a separately scoped, read-only live probe in a new Codex task or restarted desktop session.  It must record the target build, prove plugin discovery and MCP startup, and show whether the host renders the exact resource bytes.  It must not be treated as proof of authority: the scaffold still has no callback.  A later implementation must separately prove origin/CSP, recent authentication, nonce/challenge, TTL, replay protection, preview/action/destination hashes, render receipt, stale-instance rejection, and negative tests for forged frames/messages, tool-result injection, stale displays, and callback replay.  Until both the host rendering and a real authenticated callback are independently proven, retain `UI_DELIVERY_BLOCKED`; a custom app-server client fallback must not be relabeled as existing Codex Desktop UI.
