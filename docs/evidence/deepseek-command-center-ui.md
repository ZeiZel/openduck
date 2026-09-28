# DeepSeek Harness Command Center UI

Status: **implemented as an isolated static UI-only bundle; live Controller integration not attempted**.

The bundle in `deploy/deepseek-harness/command-center/` is a small bridge surface for the planned separate authenticated loopback Controller channel. It has no AgentLoop, provider, model, session, or DeepSeek Harness runtime dependency. The navigation exposes Today, Inbox, Calendar, Plan/graph, Tasks, Memory, Time, Reviews, Decisions, Health, and Sessions. All rendered content comes from an allowlisted metadata-only projection; synthetic fixtures are used until the Controller contract is available.

The UI uses an in-memory UI-channel state machine. It first performs a bootstrap with a fresh client nonce, validates the exact `ui-channel-session.v1` response, and keeps the returned bearer token only in JavaScript memory. The token is never placed in a URL, browser store, log, or DOM. Bootstrap and authenticated requests explicitly use `credentials: omit` (no cookies). Every subsequent request carries the session nonce and a fresh one-use request nonce. Expiry, 401/403, network exception, invalid bootstrap, or invalid response clears the session and fails closed.

The authenticated loopback Controller bridge is used as follows:

- `POST /v1/ui/bootstrap` — ephemeral `ui-channel-session.v1` acquisition; no credentials cookie.
- `GET /v1/read/<route>` — typed route read model; failure renders an empty `degraded_read_only` projection and disables the composer.
- `POST /v1/composer` with `application/octet-stream` — raw composer bytes are sent once to the Controller and immediately cleared from the DOM. Only a validated opaque route/status result is rendered; Controller response bodies are never rendered.

Each read response must pass a bounded depth/node/key/string/item pre-scan before any recursive sentinel scan or domain validation, then match `command-center-read-model.v1`, the route-specific allowlist, and the raw/PD sentinel scan. Arbitrary summaries, titles, and body-like fields are not rendered; only bounded metadata projections are used. Any sentinel, unknown key, malformed date, or schema mismatch rejects the entire response.

The shell has a restrictive CSP (`default-src 'none'`, same-origin script/style/connect, no frames or objects). There are no remote URLs, durable browser stores, service workers, evaluator calls, title changes, postMessage calls, or telemetry. The UI does not create a DSH session event and does not receive Qwen output. Trusted decisions and LocalPDView remain Controller/native responsibilities. Synthetic fixtures are available only with an explicit `?synthetic=1` developer-mode label; Controller-down production state is empty and read-only.

## Verification

Run from the repository root:

```sh
node scripts/dsh-command-center-sentinel.mjs
```

The deterministic suite checks the CSP, forbidden browser capabilities, exact network surface, complete route set, metadata-only fixture sanitization, and raw composer clearing. It does not start a service, access an account, or make network requests.

This evidence does not claim DR-018 is resolved. A reviewed DSH fork/client bridge and an authenticated Controller endpoint are still required before real data or effects are enabled.
