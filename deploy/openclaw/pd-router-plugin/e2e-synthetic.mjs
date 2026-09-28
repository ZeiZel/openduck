import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { PDPolicy } from "./index.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const config = JSON.parse(fs.readFileSync(path.join(root, "config.json"), "utf8"));
assert.equal(config.agents.defaults.model.primary, "openai/gpt-5.6-sol");
assert.equal(config.agents.list.find((a) => a.id === "main").model.primary, "openai/gpt-5.6-sol");
assert.equal(config.models.providers.openai.agentRuntime.id, "codex");
assert.equal(config.plugins.entries.codex.enabled, true);
assert.deepEqual(config.agents.defaults.model.fallbacks, []);
assert.deepEqual(config.tools.byProvider["openai/gpt-5.6-sol"].allow, ["bundle-mcp"]);
assert.equal(config.tools.byProvider["openai/gpt-5.6-sol"].deny, undefined);
assert.ok(config.tools.byProvider["ollama/qwen3:8b"].deny.includes("*"));
assert.ok(config.tools.deny.includes("exec"));
assert.ok(config.tools.deny.includes("browser"));
assert.ok(config.tools.deny.includes("message"));
assert.ok(config.tools.deny.includes("write"));
assert.ok(config.tools.deny.includes("edit"));
assert.ok(config.tools.deny.includes("apply_patch"));
assert.equal(config.tools.exec.mode, "auto");
assert.equal(config.tools.exec.applyPatch.enabled, false);
assert.equal(config.agents.defaults.sandbox.mode, "all");
assert.equal(config.agents.defaults.sandbox.workspaceAccess, "none");
assert.ok(config.tools.sandbox.tools.alsoAllow.includes("bundle-mcp"));

const controller = config.mcp.servers["openduck-controller"];
assert.equal(controller.enabled, true);
assert.deepEqual(controller.toolFilter.include, ["controller_status", "controller_tasks", "render_delivery_probe"]);
assert.equal(controller.command, "python3");

const controllerScript = path.resolve(root, "..", "..", "plugins/openduck-control/scripts/controller_mcp.py");
const rpcLines = [
  { jsonrpc: "2.0", id: 1, method: "initialize", params: {} },
  { jsonrpc: "2.0", id: 2, method: "tools/list", params: {} },
  { jsonrpc: "2.0", id: 3, method: "tools/call", params: { name: "controller_status", arguments: {} } },
  { jsonrpc: "2.0", id: 4, method: "tools/call", params: { name: "render_delivery_probe", arguments: {} } },
];
const rpcOutput = execFileSync(controller.command, [controllerScript], {
  cwd: path.resolve(root, "..", ".."),
  input: rpcLines.map((line) => JSON.stringify(line)).join("\n") + "\n",
  encoding: "utf8",
});
const rpc = rpcOutput.trim().split("\n").map((line) => JSON.parse(line));
const listedTools = rpc.find((line) => line.id === 2)?.result?.tools ?? [];
assert.deepEqual(listedTools.map((tool) => tool.name), ["controller_status", "render_delivery_probe", "controller_tasks"]);
assert.ok(listedTools.every((tool) => tool.annotations?.readOnlyHint === true && tool.annotations?.destructiveHint === false));
const status = rpc.find((line) => line.id === 3)?.result?.structuredContent;
assert.equal(status?.schema_version, "controller-status.v1");
assert.equal(status?.external_effects, false);
const preview = rpc.find((line) => line.id === 4)?.result?.structuredContent;
assert.equal(preview?.authoritative, false);
assert.equal(rpc.find((line) => line.id === 4)?.result?._meta?.ui?.resourceUri, "ui://openduck-control/owner-preview.html");
for (const privateServer of ["obsidian-direct", "kaiten-readonly", "cuadriver-readonly", "obsidian-filesystem-bridge"]) {
  assert.equal(config.mcp.servers[privateServer].enabled, false, `${privateServer} must stay disabled for cloud Codex`);
}
assert.equal(config.mcp.servers.context7.enabled, true);
assert.equal(config.mcp.servers["public-search-readonly"].enabled, true);

const state = path.join(fs.mkdtempSync("/tmp/openduck-pd-e2e-"), "state.json");
const policy = new PDPolicy({ statePath: state });
assert.deepEqual(policy.beforeModelResolve({ sessionKey: "normal", prompt: "synthetic normal request" }), {});
assert.deepEqual(policy.beforeModelResolve({ sessionKey: "pd", prompt: "Это ПД\nsynthetic only" }), { providerOverride: "ollama", modelOverride: "qwen3:8b" });
assert.equal(policy.beforeToolCall({ sessionKey: "pd", toolName: "codex_delegate" }).block, true);
assert.equal(new PDPolicy({ statePath: state }).mode("pd", "restart probe"), "pd");
console.log("synthetic unified-route E2E passed");
