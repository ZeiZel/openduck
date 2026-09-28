#!/usr/bin/env python3
"""A dependency-free, synthetic MCP stdio server for the H0 delivery probe.

This server intentionally has no authenticated callback, persistence, approval
endpoint, or mutation tool.  It performs only bounded reads from fixed loopback
status/origin-probe endpoints and serves a static MCP Apps resource.
"""

from __future__ import annotations

import json
import secrets
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

SERVER_NAME = "openduck-controller-probe"
SERVER_VERSION = "0.1.0"
RESOURCE_URI = "ui://openduck-control/owner-preview.html"
RESOURCE_MIME = "text/html;profile=mcp-app"
ASSET_PATH = Path(__file__).resolve().parent.parent / "assets" / "owner-preview.html"

READ_ONLY_ANNOTATIONS = {
    "readOnlyHint": True,
    "destructiveHint": False,
    "openWorldHint": False,
}
STATUS_URL = "http://127.0.0.1:8788/v1/controller/status"
TASKS_URL = "http://127.0.0.1:8788/v1/controller/tasks"
ORIGIN_PROBE_URL = "http://127.0.0.1:8788/v1/controller/origin-probe"
MAX_STATUS_BYTES = 64 * 1024
TASK_STATES = {"OBSERVED", "SIGNAL_READY", "SPEC_DRAFT", "SPEC_FROZEN", "DISPATCHED", "WORK_RUNNING", "EVIDENCE_READY", "REVIEWING", "ACCEPTED", "BLOCKED", "CANCELLED"}


def response(message_id: Any, result: dict[str, Any]) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": message_id, "result": result}


def error(message_id: Any, code: int, message: str) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": message_id,
        "error": {"code": code, "message": message},
    }


def tools() -> list[dict[str, Any]]:
    return [
        {
            "name": "controller_status",
            "title": "Read synthetic Controller status",
            "description": "Read bounded synthetic Controller metadata from the fixed loopback status endpoint. It cannot change state.",
            "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
            "outputSchema": {
                "type": "object",
                "properties": {
                    "schema_version": {"const": "controller-status.v1"},
                    "mode": {"const": "synthetic"},
                    "delivery_state": {"const": "UI_DELIVERY_BLOCKED"},
                    "external_effects": {"const": False},
                    "owner_decision_callback": {"const": False},
                    "task_counts": {"type": "object"},
                },
                "required": ["schema_version", "mode", "delivery_state", "external_effects", "owner_decision_callback", "task_counts"],
                "additionalProperties": False,
            },
            "annotations": READ_ONLY_ANNOTATIONS,
        },
        {
            "name": "render_delivery_probe",
            "title": "Render synthetic delivery probe",
            "description": "Use this only to request the immutable synthetic MCP Apps preview resource. It cannot approve or authorize anything.",
            "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
            "outputSchema": {
                "type": "object",
                "properties": {
                    "mode": {"const": "synthetic"},
                    "delivery_state": {"const": "UI_DELIVERY_BLOCKED"},
                    "resource_uri": {"const": RESOURCE_URI},
                    "authoritative": {"const": False},
                },
                "required": ["mode", "delivery_state", "resource_uri", "authoritative"],
                "additionalProperties": False,
            },
            "annotations": READ_ONLY_ANNOTATIONS,
            "_meta": {"ui": {"resourceUri": RESOURCE_URI}},
        },
        {
            "name": "controller_tasks",
            "title": "Read synthetic task lifecycle",
            "description": "Read the bounded synthetic task lifecycle projection from the fixed loopback Controller. It cannot create, change, approve, or execute a task.",
            "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
            "outputSchema": {
                "type": "object",
                "properties": {"schema_version": {"const": "controller-task-list.v1"}, "mode": {"const": "synthetic"}, "tasks": {"type": "array"}},
                "required": ["schema_version", "mode", "tasks"],
                "additionalProperties": False,
            },
            "annotations": READ_ONLY_ANNOTATIONS,
            "_meta": {"ui": {"resourceUri": RESOURCE_URI}},
        },
    ]


def status_result() -> dict[str, Any]:
    structured = fetch_status()
    return {
        "structuredContent": structured,
        "content": [{"type": "text", "text": "Controller status is read-only; UI delivery remains blocked."}],
    }


def disconnected_status() -> dict[str, Any]:
    return {"schema_version": "controller-status.v1", "mode": "synthetic", "delivery_state": "UI_DELIVERY_BLOCKED", "external_effects": False, "owner_decision_callback": False, "task_counts": {}}


def valid_status(value: Any) -> bool:
    if not isinstance(value, dict):
        return False
    required = {"schema_version", "mode", "delivery_state", "external_effects", "owner_decision_callback", "task_counts"}
    if set(value) != required:
        return False
    if value["schema_version"] != "controller-status.v1" or value["mode"] != "synthetic" or value["delivery_state"] != "UI_DELIVERY_BLOCKED":
        return False
    if value["external_effects"] is not False or value["owner_decision_callback"] is not False or not isinstance(value["task_counts"], dict):
        return False
    return all(k in TASK_STATES and isinstance(v, int) and not isinstance(v, bool) and v >= 0 for k, v in value["task_counts"].items())


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def fetch_status() -> dict[str, Any]:
    request = urllib.request.Request(STATUS_URL, method="GET", headers={"Accept": "application/json"})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())
    try:
        with opener.open(request, timeout=2.0) as response:
            if response.status != 200:
                return disconnected_status()
            body = response.read(MAX_STATUS_BYTES + 1)
            if len(body) > MAX_STATUS_BYTES:
                return disconnected_status()
            value = json.loads(body.decode("utf-8"))
            return value if valid_status(value) else disconnected_status()
    except Exception:
        return disconnected_status()


def disconnected_tasks() -> dict[str, Any]:
    return {"schema_version": "controller-task-list.v1", "mode": "synthetic", "tasks": []}


def valid_tasks(value: Any) -> bool:
    if not isinstance(value, dict) or set(value) != {"schema_version", "mode", "tasks"}:
        return False
    if value["schema_version"] != "controller-task-list.v1" or value["mode"] != "synthetic" or not isinstance(value["tasks"], list):
        return False
    seen: set[str] = set()
    for task in value["tasks"]:
        if not isinstance(task, dict) or set(task) != {"id", "state", "version", "has_work_order", "has_evidence", "has_review", "decision_count"}:
            return False
        if not isinstance(task["id"], str) or not task["id"] or task["id"] in seen or task["state"] not in TASK_STATES or not isinstance(task["version"], int) or isinstance(task["version"], bool) or task["version"] < 1:
            return False
        if not all(isinstance(task[key], bool) for key in ("has_work_order", "has_evidence", "has_review")) or not isinstance(task["decision_count"], int) or isinstance(task["decision_count"], bool) or task["decision_count"] < 0:
            return False
        seen.add(task["id"])
    return True


def fetch_tasks() -> dict[str, Any]:
    request = urllib.request.Request(TASKS_URL, method="GET", headers={"Accept": "application/json"})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())
    try:
        with opener.open(request, timeout=2.0) as response:
            if response.status != 200:
                return disconnected_tasks()
            body = response.read(MAX_STATUS_BYTES + 1)
            if len(body) > MAX_STATUS_BYTES:
                return disconnected_tasks()
            value = json.loads(body.decode("utf-8"))
            return value if valid_tasks(value) else disconnected_tasks()
    except Exception:
        return disconnected_tasks()


def tasks_result() -> dict[str, Any]:
    return {"structuredContent": fetch_tasks(), "content": [{"type": "text", "text": "Synthetic task lifecycle is read-only. No task, approval, or effect can be created from this view."}]}


def render_result() -> dict[str, Any]:
    structured = {
        "mode": "synthetic",
        "delivery_state": "UI_DELIVERY_BLOCKED",
        "resource_uri": RESOURCE_URI,
        "authoritative": False,
    }
    return {
        "structuredContent": structured,
        "content": [{"type": "text", "text": "Synthetic immutable preview requested. It has no approval, callback, or Controller authority."}],
        # _meta is private tool-result metadata.  The opaque value is never
        # placed in structuredContent, model-visible text, the resource DOM,
        # storage, or logs.  The UI may use it for one bounded read-only probe.
        "_meta": {
            "ui": {
                "resourceUri": RESOURCE_URI,
                "probeToken": secrets.token_urlsafe(32),
                "csp": {"connectDomains": ["http://127.0.0.1:8788"]},
            }
        },
    }


def handle(request: dict[str, Any]) -> dict[str, Any] | None:
    message_id = request.get("id")
    method = request.get("method")
    if not isinstance(method, str):
        return error(message_id, -32600, "Invalid Request")
    if method == "notifications/initialized":
        return None
    if method == "initialize":
        return response(message_id, {
            "protocolVersion": "2025-06-18",
            "capabilities": {"tools": {}, "resources": {}},
            "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
            "instructions": "H1 read-only status and static render probe. No approval, mutation, authentication, or callback capability exists.",
        })
    if method == "ping":
        return response(message_id, {})
    if method == "tools/list":
        return response(message_id, {"tools": tools()})
    if method == "resources/list":
        return response(message_id, {"resources": [{
            "uri": RESOURCE_URI,
            "name": "OpenDuck synthetic owner preview",
            "description": "Immutable synthetic preview; no authority or callback.",
            "mimeType": RESOURCE_MIME,
        }]})
    if method == "resources/read":
        uri = (request.get("params") or {}).get("uri")
        if uri != RESOURCE_URI:
            return error(message_id, -32002, "Unknown resource")
        return response(message_id, {"contents": [{
            "uri": RESOURCE_URI,
            "mimeType": RESOURCE_MIME,
            "text": ASSET_PATH.read_text(encoding="utf-8"),
            "_meta": {"ui": {"prefersBorder": True}},
        }]})
    if method == "tools/call":
        params = request.get("params", {})
        if not isinstance(params, dict) or "name" not in params or not isinstance(params.get("name"), str):
            return error(message_id, -32602, "Invalid tool arguments")
        arguments = params.get("arguments", {})
        # Some Codex/OpenAI bridge versions omit arguments for a zero-arg
        # tool, send null, or serialize an empty object as "{}". All three
        # are equivalent here; reject any non-empty payload to keep the
        # Controller surface strictly zero-argument and read-only.
        if arguments is None:
            arguments = {}
        if isinstance(arguments, str):
            try:
                arguments = json.loads(arguments)
            except json.JSONDecodeError:
                arguments = None
        if not isinstance(arguments, dict) or arguments:
            return error(message_id, -32602, "Invalid tool arguments")
        name = params["name"]
        if name == "controller_status":
            return response(message_id, status_result())
        if name == "render_delivery_probe":
            return response(message_id, render_result())
        if name == "controller_tasks":
            return response(message_id, tasks_result())
        return error(message_id, -32602, "Unknown tool")
    return error(message_id, -32601, "Method not found")


def main() -> int:
    for line in sys.stdin:
        try:
            request = json.loads(line)
            if not isinstance(request, dict):
                raise ValueError("request must be an object")
            result = handle(request)
            if result is not None:
                print(json.dumps(result, ensure_ascii=False), flush=True)
        except (ValueError, json.JSONDecodeError) as exc:
            print(json.dumps(error(None, -32700, f"Parse error: {exc}")), flush=True)
        except Exception as exc:  # Fail closed without exposing tracebacks to the client.
            print(json.dumps(error(None, -32603, f"Internal error: {type(exc).__name__}")), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
