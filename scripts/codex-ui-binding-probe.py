#!/usr/bin/env python3
"""Headless contract probe for the repo-local OpenDuck Codex plugin scaffold.

It validates only static bundle/protocol facts. It cannot test installed-plugin
discovery, a desktop host's iframe rendering, origin/CSP enforcement, user auth,
or a direct Controller callback; those remain a required live H0 probe.
"""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
PLUGIN = REPO_ROOT / "plugins" / "openduck-control"
SERVER = PLUGIN / "scripts" / "controller_mcp.py"
ASSET = PLUGIN / "assets" / "owner-preview.html"
RESOURCE_URI = "ui://openduck-control/owner-preview.html"
RESOURCE_MIME = "text/html;profile=mcp-app"
EXPECTED_TOOLS = {"controller_status", "render_delivery_probe", "controller_tasks"}
READ_ONLY = {"readOnlyHint": True, "destructiveHint": False, "openWorldHint": False}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def read_json(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    require(isinstance(data, dict), f"{path.name} must contain an object")
    return data


def request(proc: subprocess.Popen[str], payload: dict[str, Any]) -> dict[str, Any]:
    require(proc.stdin is not None and proc.stdout is not None, "stdio unavailable")
    proc.stdin.write(json.dumps(payload) + "\n")
    proc.stdin.flush()
    line = proc.stdout.readline()
    require(line != "", f"server ended before response to {payload['method']}")
    reply = json.loads(line)
    require(reply.get("jsonrpc") == "2.0", f"non-JSON-RPC reply to {payload['method']}")
    return reply


def valid_status(value: Any) -> bool:
    if not isinstance(value, dict):
        return False
    required = {"schema_version", "mode", "delivery_state", "external_effects", "owner_decision_callback", "task_counts"}
    if set(value) != required or value["schema_version"] != "controller-status.v1" or value["mode"] != "synthetic" or value["delivery_state"] != "UI_DELIVERY_BLOCKED":
        return False
    if value["external_effects"] is not False or value["owner_decision_callback"] is not False or not isinstance(value["task_counts"], dict):
        return False
    return all(isinstance(state, str) and isinstance(count, int) and not isinstance(count, bool) and count >= 0 for state, count in value["task_counts"].items())


def valid_tasks(value: Any) -> bool:
    if not isinstance(value, dict) or set(value) != {"schema_version", "mode", "tasks"}:
        return False
    if value["schema_version"] != "controller-task-list.v1" or value["mode"] != "synthetic" or not isinstance(value["tasks"], list):
        return False
    return all(isinstance(task, dict) and set(task) == {"id", "state", "version", "has_work_order", "has_evidence", "has_review", "decision_count"} and isinstance(task["id"], str) and task["id"] and isinstance(task["state"], str) and isinstance(task["version"], int) and not isinstance(task["version"], bool) and task["version"] >= 1 and all(isinstance(task[key], bool) for key in ("has_work_order", "has_evidence", "has_review")) and isinstance(task["decision_count"], int) and not isinstance(task["decision_count"], bool) and task["decision_count"] >= 0 for task in value["tasks"])


def validate_static_bundle() -> None:
    manifest = read_json(PLUGIN / ".codex-plugin" / "plugin.json")
    require(manifest["name"] == "openduck-control", "manifest name")
    require(re.fullmatch(r"\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?", manifest["version"]) is not None, "strict semver")
    require(manifest.get("mcpServers") == "./.mcp.json", "MCP manifest path")
    require(manifest.get("apps") == "./.app.json", "apps manifest path")
    require(manifest["interface"]["capabilities"] == ["Read"], "read-only plugin capability")
    require("mutation" not in json.dumps(manifest).lower(), "mutation capability must not enter manifest")

    mcp = read_json(PLUGIN / ".mcp.json")
    servers = mcp.get("mcpServers")
    require(isinstance(servers, dict) and set(servers) == {"openduck-controller"}, "one bundled MCP server")
    server = servers["openduck-controller"]
    require(server == {"command": "python3", "args": ["scripts/controller_mcp.py"], "cwd": "."}, "static local stdio launch definition")

    apps = read_json(PLUGIN / ".app.json")
    require(apps == {"apps": {}}, "no registered external app mapping")

    html = ASSET.read_text(encoding="utf-8")
    require("DEMO ONLY" in html and "UI_DELIVERY_BLOCKED" in html, "explicit static UI warning")
    require("disabled" in html and "Approval unavailable" in html, "no operable approval control")
    require("Approval unavailable" in html, "approval control remains disabled")
    require("http://127.0.0.1:8788/v1/controller/origin-probe" in html, "probe origin is fixed to loopback")
    require("http://127.0.0.1:8788/v1/controller/tasks" in html, "task projection origin is fixed to loopback")
    require("credentials: \"omit\"" in html and "cache: \"no-store\"" in html and "redirect: \"error\"" in html and "referrerPolicy: \"no-referrer\"" in html, "probe fetch is bounded")
    require("connect-src http://127.0.0.1:8788" in html, "HTML CSP pins loopback connect origin")
    require("window.openai" in html and "toolResponseMetadata" in html, "Codex private tool metadata bridge")
    require("openDuckReceivePrivateMeta" not in html and "postMessage" not in html, "no unsupported or wildcard metadata bridge")
    require("setInterval" in html and "metadataPolls >= 20" in html, "metadata hydration polling is bounded")
    require("localStorage" not in html and "sessionStorage" not in html and "document.cookie" not in html, "probe token is not persisted")
    require("console.log" not in html and "console.error" not in html, "probe token is not logged")


def validate_protocol() -> str:
    proc = subprocess.Popen([sys.executable, str(SERVER)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        init = request(proc, {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18", "clientInfo": {"name": "headless-probe", "version": "0.1.0"}}})
        require(init["result"]["capabilities"] == {"tools": {}, "resources": {}}, "advertised MCP capabilities")
        listed = request(proc, {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
        tool_list = listed["result"]["tools"]
        require({tool["name"] for tool in tool_list} == EXPECTED_TOOLS, "tool surface is bounded read-only lifecycle/status/render")
        for tool in tool_list:
            require(tool["annotations"] == READ_ONLY, f"read-only annotations for {tool['name']}")
            require(tool["inputSchema"] == {"type": "object", "properties": {}, "additionalProperties": False}, f"no inputs for {tool['name']}")
            require("approval" not in tool["name"].lower() and "mutat" not in tool["name"].lower(), f"no authority tool {tool['name']}")
        status = request(proc, {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "controller_status", "arguments": {}}})
        require(valid_status(status["result"]["structuredContent"]), "synthetic status result")
        omitted_arguments = request(proc, {"jsonrpc": "2.0", "id": 31, "method": "tools/call", "params": {"name": "controller_status"}})
        require(omitted_arguments["result"]["structuredContent"] == status["result"]["structuredContent"], "omitted arguments equivalent to empty object")
        for invalid_params in ([], {"name": "controller_status", "arguments": {"unexpected": True}}, {"name": "controller_status", "extra": 1}):
            invalid = request(proc, {"jsonrpc": "2.0", "id": 32, "method": "tools/call", "params": invalid_params})
            require(invalid["error"]["code"] == -32602, "invalid tool params rejected")
        task_list = request(proc, {"jsonrpc": "2.0", "id": 33, "method": "tools/call", "params": {"name": "controller_tasks", "arguments": {}}})
        require(valid_tasks(task_list["result"]["structuredContent"]), "synthetic task projection")
        rendered = request(proc, {"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "render_delivery_probe", "arguments": {}}})
        private_meta = rendered["result"]["_meta"]
        require(set(private_meta) == {"ui"}, "render metadata is private UI metadata")
        require(private_meta["ui"]["resourceUri"] == RESOURCE_URI, "render UI resource association")
        token = private_meta["ui"].get("probeToken")
        require(isinstance(token, str) and re.fullmatch(r"[A-Za-z0-9_-]{32,128}", token), "opaque probe token shape")
        require(private_meta["ui"]["csp"] == {"connectDomains": ["http://127.0.0.1:8788"]}, "private UI CSP metadata")
        require(token not in json.dumps(rendered["result"]["structuredContent"]) and token not in json.dumps(rendered["result"]["content"]), "probe token stays out of model-visible result")
        resources = request(proc, {"jsonrpc": "2.0", "id": 5, "method": "resources/list", "params": {}})
        require(resources["result"]["resources"] == [{"uri": RESOURCE_URI, "name": "OpenDuck synthetic owner preview", "description": "Immutable synthetic preview; no authority or callback.", "mimeType": RESOURCE_MIME}], "resource inventory")
        resource = request(proc, {"jsonrpc": "2.0", "id": 6, "method": "resources/read", "params": {"uri": RESOURCE_URI}})
        content = resource["result"]["contents"][0]
        require(content["mimeType"] == RESOURCE_MIME and content["text"] == ASSET.read_text(encoding="utf-8"), "immutable static resource bytes")
        unknown = request(proc, {"jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": {"name": "approve_owner_decision", "arguments": {}}})
        require(unknown["error"]["code"] == -32602, "authority-like tool rejected")
        return hashlib.sha256(content["text"].encode("utf-8")).hexdigest()
    finally:
        proc.terminate()
        proc.wait(timeout=5)


def main() -> int:
    try:
        validate_static_bundle()
        digest = validate_protocol()
    except Exception as exc:
        print(f"FAIL: {exc}")
        return 1
    print("HEADLESS_RESULT=PARTIAL")
    print("DELIVERY_GATE=UI_DELIVERY_BLOCKED")
    print(f"RESOURCE_SHA256={digest}")
    print("PROVEN=manifest,mcp-stdio-protocol,read-only-tool-inventory,static-mcp-app-resource,private-token-gated-loopback-probe,no-approval-callback")
    print("UNVERIFIED=desktop-plugin-discovery,desktop-iframe-render,host-CSP-enforcement,authenticated-controller-callback,render-receipt,replay-protection")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
