#!/usr/bin/env node
/** Deterministic UI-only sentinel suite; it never starts a service or performs network I/O. */
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const dir = resolve(root, "deploy/deepseek-harness/command-center");
const source = async (name) => readFile(resolve(dir, name), "utf8");
const now = "2026-08-19T16:00:00Z";
const base = (extra) => ({ schema_version: "command-center-read-model.v1", generated_at: now, ...extra });
const rows = {
  inbox: { items: [{ id: "i", summary: "safe", source: "TG", classification: "L0", updated_at: now }] },
  calendar: { items: [{ id: "c", title: "safe", start: now, end: "2026-08-19T17:00:00Z", timezone: "Europe/Moscow", status: "confirmed" }] },
  workgraph: { graph_id: "g", baseline_version: "1", nodes: [{ id: "n", title: "safe", status: "running" }], edges: [] },
  tasks: { items: [{ id: "t", title: "safe", status: "open", source: "Kaiten", version: 1 }] },
  time: { active_task_id: "t", planned_seconds: 60, spent_seconds: 30 },
  reviews: { items: [{ id: "r", target_id: "t", status: "review", finding_count: 1 }] },
  "memory-metadata": { items: [{ id: "m", scope: "repo", sensitivity: "SAFE", status: "candidate", provenance_count: 1 }] },
  health: { status: "ready", controller_available: true, effects_enabled: false }
};

test("static shell has a strict local-only CSP", async () => {
  const html = await source("index.html");
  assert.match(html, /default-src 'none'/); assert.match(html, /script-src 'self'/); assert.match(html, /connect-src 'self'/); assert.match(html, /frame-ancestors 'none'/);
  assert.doesNotMatch(html, /<script[^>]+src=["']https?:/i); assert.doesNotMatch(html, /<iframe/i);
});

test("UI contains no durable browser store, service worker, evaluator, or telemetry seam", async () => {
  const [html, app] = await Promise.all([source("index.html"), source("app.js")]); const combined = `${html}\n${app}`;
  for (const forbidden of ["localStorage", "sessionStorage", "indexedDB", "caches.", "serviceWorker", "eval(", "new Function", "sendBeacon", "postMessage(", "document.title"]) assert.equal(combined.includes(forbidden), false, `forbidden capability: ${forbidden}`);
  assert.doesNotMatch(combined, /https?:\/\/(?!127\.0\.0\.1)/i);
});

test("bootstrap/auth state machine uses only in-memory bearer and fresh request nonces", async () => {
  const app = await source("app.js");
  assert.match(app, /fetch\("\/v1\/ui\/bootstrap"/); assert.match(app, /client_nonce/); assert.match(app, /Authorization.*Bearer/); assert.match(app, /X-UI-Nonce/); assert.match(app, /X-UI-Request-Nonce/);
  assert.equal((app.match(/credentials: "omit"/g) || []).length, 2); assert.doesNotMatch(app, /[?&](?:token|nonce)=/i); assert.match(app, /state\.auth = null/); assert.match(app, /Date\.now\(\) >= state\.auth\.expiresAt/);
  const { validSession } = await import(`${dir}/app.js`);
  const session = { schema_version: "ui-channel-session.v1", session_id: "s", channel_id: "c", token: "a".repeat(44), client_nonce: "cn", origin: "http://127.0.0.1:3000", host: "127.0.0.1:8788", issued_at: now, expires_at: "2099-01-01T00:00:00Z", ephemeral: true, persistent: false };
  assert.equal(validSession(session), true); assert.equal(validSession({ ...session, persistent: true }), false);
});

test("network surface uses exact bridge paths and bounded async chat", async () => {
  const app = await source("app.js");
  for (const route of ["inbox", "calendar", "workgraph", "tasks", "memory-metadata", "time", "reviews", "health"]) assert.match(app, new RegExp(`/v1/read/\\$\\{wireRoute\\}`));
  assert.match(app, /controllerFetch\("\/v1\/chat\/runs"/); assert.match(app, /\/v1\/chat\/runs\/\$\{encodeURIComponent\(runId\)\}/); assert.match(app, /application\/json/); assert.match(app, /credentials: "omit"/); assert.match(app, /catch \(_error\) \{ clearAuth/); assert.doesNotMatch(app, /controllerFetch\("\/v1\/chat"/);
  assert.doesNotMatch(app, /fetch\([^)]*https?:/i);
});

test("exact read schemas reject unknown keys and every allowed visible field rejects raw/PD sentinels", async () => {
  const { validateRead, hasSentinel, withinBounds } = await import(`${dir}/app.js`);
  assert.equal(hasSentinel("RAW_PD_SENTINEL"), true); assert.equal(hasSentinel("QWEN_OUTPUT_SENTINEL"), true);
  assert.equal(withinBounds({ deep: { deeper: { value: "x" } } }), true); assert.equal(withinBounds({ deep: { deeper: { value: { more: { too: { deep: { for: { the: { boundary: "x" } } } } } } } } }), false); assert.equal(withinBounds({ huge: "x".repeat(257) }), false);
  for (const [route, fields] of Object.entries(rows)) {
    const payload = base(fields); assert.ok(validateRead(route, payload), `baseline ${route}`); assert.equal(validateRead(route, { ...payload, extra: true }), null, `unknown key ${route}`);
    for (const [key, value] of Object.entries(fields)) {
      if (Array.isArray(value)) { for (let index = 0; index < value.length; index += 1) for (const field of Object.keys(value[index])) { const mutated = structuredClone(payload); mutated[key][index][field] = "RAW_PD_SENTINEL"; assert.equal(validateRead(route, mutated), null, `${route}.${key}[${index}].${field}`); } }
      else if (typeof value === "string") { const mutated = { ...payload, [key]: "QWEN_OUTPUT_SENTINEL" }; assert.equal(validateRead(route, mutated), null, `${route}.${key}`); }
    }
  }
  const app = await source("app.js"); assert.match(app, /withinBounds\(payload\).*hasSentinel\(payload\)/s); assert.match(app, /function validAssistantResult\(value\).*withinBounds\(value\).*hasSentinel\(value\)/s);
});

test("controller-down projection is empty unless explicit synthetic dev mode is selected", async () => {
  const app = await source("app.js"); const fixtures = await source("fixtures.js");
  assert.match(app, /if \(!state\.synthetic\) return emptyModel/); assert.match(app, /synthetic=1/); assert.match(app, /degraded_read_only/); assert.match(app, /SYNTHETIC DEV FIXTURE/); assert.match(app, /state\.model = null/); assert.doesNotMatch(app, /state\.model = safeModel\(SYNTHETIC/);
  assert.doesNotMatch(fixtures, /RAW_PD_SENTINEL|QWEN_OUTPUT_SENTINEL|PERSONAL_DATA/i);
});

test("chat accepts only exact bounded async result", async () => {
  const app = await source("app.js");
  assert.match(app, /CHAT_RESULT_SCHEMA/); assert.match(app, /validAssistantResult\(result\)/); assert.match(app, /renderAssistantResult/); assert.match(app, /pollChatRun/); assert.match(app, /cancelChatRun/);
});

console.log("dsh-command-center: PASS (bridge protocol sentinels, no network/services started)");
