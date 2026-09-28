#!/usr/bin/env python3
"""Deterministic DR-018 synthetic probe.

This module deliberately does not import DeepSeek Harness or start a provider.
It proves the safe read-model policy in an in-process request harness and emits
BLOCKED for the missing live DSH integration prerequisites. The HTTP Handler is
an unexecuted adapter sketch; this probe does not claim an HTTP round trip.
"""

from __future__ import annotations

import argparse
import http.client
import json
import pathlib
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any


ROOT = pathlib.Path(__file__).resolve().parents[3]
PROFILE = ROOT / "profiles/dsh/openduck-synthetic/profile.json"
PINNED = ROOT / "third_party/deepseek-harness"


def read_profile() -> dict[str, Any]:
    return json.loads(PROFILE.read_text(encoding="utf-8"))


def assert_profile(profile: dict[str, Any]) -> list[str]:
    checks: list[str] = []
    assert profile["mode"] == "synthetic"
    assert profile["agent_loop"]["enabled"] is False
    assert profile["llm"]["providers"] == []
    assert profile["llm"]["model_resolution"] == "deny"
    assert profile["session"]["persistence"] == "disabled"
    assert profile["session"]["prompt"] == "deny"
    assert profile["subagents"]["private_children"] == "deny"
    assert profile["read_model"]["cache"] == "memory-only"
    assert profile["read_model"]["session_events"] is False
    assert profile["read_model"]["post_message"] is False
    assert all(value is False for value in profile["browser"].values())
    assert profile["controller"]["writes"] is False
    assert profile["server"]["prompt_api"] == "deny"
    assert profile["server"]["mutation_methods"] == "deny"
    assert profile["network"]["provider_egress"] is False
    checks.extend(("profile:no-agent-loop", "profile:no-provider", "profile:no-session-persistence",
                   "profile:memory-only-read-model", "profile:no-browser-durable-store",
                   "profile:no-server-prompt-api", "profile:no-provider-egress"))
    return checks


class ReadModel:
    """Memory-only synthetic projection; no persistence or mutation API."""

    def __init__(self, controller_up: bool) -> None:
        self.controller_up = controller_up

    def status(self) -> dict[str, Any]:
        if not self.controller_up:
            return {"schema": "openduck.command-center.status.v1", "state": "degraded_read_only", "writable": False}
        return {"schema": "openduck.command-center.status.v1", "state": "ready", "writable": False}

    def projection(self) -> dict[str, Any]:
        return {
            "schema": "openduck.command-center.read-model.v1",
            "state": "ready" if self.controller_up else "degraded_read_only",
            "inbox": [{"id": "synthetic-inbox-1", "text": "SYNTHETIC_INBOX_SENTINEL"}],
            "calendar": [{"id": "synthetic-demo-1", "title": "SYNTHETIC_CALENDAR_SENTINEL"}],
            "work_graph": [{"id": "synthetic-work-1", "title": "SYNTHETIC_WORKGRAPH_SENTINEL"}],
            "writable": False,
        }

    def request(self, method: str, path: str) -> tuple[int, dict[str, Any]]:
        """Apply the same method/path policy as the optional HTTP adapter."""
        if method == "GET" and path == "/health":
            return 200, self.status()
        if method == "GET" and path == "/v1/read-model":
            return (200 if self.controller_up else 503), self.projection()
        if method in {"POST", "PUT", "PATCH", "DELETE"}:
            return 405, {"error": "mutations_denied", "state": "read_only"}
        return 404, {"error": "not_found"}


class Handler(BaseHTTPRequestHandler):
    server: "ProbeServer"

    def _send(self, code: int, payload: dict[str, Any]) -> None:
        body = json.dumps(payload, separators=(",", ":")).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/health":
            self._send(200, self.server.model.status())
        elif self.path == "/v1/read-model":
            self._send(200 if self.server.model.controller_up else 503, self.server.model.projection())
        else:
            self._send(404, {"error": "not_found"})

    def do_POST(self) -> None:  # noqa: N802
        self._send(405, {"error": "mutations_denied", "state": "read_only"})

    do_PUT = do_POST
    do_PATCH = do_POST
    do_DELETE = do_POST

    def log_message(self, _format: str, *_args: object) -> None:
        return


class ProbeServer(ThreadingHTTPServer):
    allow_reuse_address = True

    def __init__(self, address: tuple[str, int], controller_up: bool) -> None:
        super().__init__(address, Handler)
        self.model = ReadModel(controller_up)


def request(port: int, method: str, path: str) -> tuple[int, dict[str, Any]]:
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
    conn.request(method, path, body=b"{}" if method != "GET" else None)
    response = conn.getresponse()
    body = json.loads(response.read())
    conn.close()
    return response.status, body


def runtime_checks() -> list[str]:
    checks: list[str] = []
    model = ReadModel(controller_up=True)
    status, projection = model.request("GET", "/v1/read-model")
    assert status == 200 and projection["writable"] is False
    raw = json.dumps(projection)
    assert "SYNTHETIC_INBOX_SENTINEL" in raw and "SYNTHETIC_CALENDAR_SENTINEL" in raw
    checks.append("runtime:separate-memory-only-read-model")
    status, denied = model.request("POST", "/v1/prompt")
    assert status == 405 and denied["error"] == "mutations_denied"
    checks.append("runtime:prompt-and-mutation-apis-denied")

    down = ReadModel(controller_up=False)
    status, payload = down.request("GET", "/v1/read-model")
    assert status == 503 and payload["state"] == "degraded_read_only" and payload["writable"] is False
    checks.append("runtime:controller-down-degraded-read-only")
    return checks


def live_gate() -> dict[str, Any]:
    """Return honest live status without installing or contacting a provider."""
    node_modules = PINNED / "node_modules"
    return {
        "status": "BLOCKED",
        "reason": "pinned DSH dependencies are not materialized; live web boot was not attempted",
        "pinned_source": PINNED.exists(),
        "dependencies_materialized": node_modules.is_dir(),
        "network": "not attempted",
        "credentials": "not read",
        "real_effects": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", action="store_true", help="emit one JSON report")
    parser.add_argument("--require-live", action="store_true", help="fail because the live gate is blocked")
    args = parser.parse_args()
    checks = assert_profile(read_profile()) + runtime_checks()
    report = {"schema": "deepseek-harness.dr018.probe.v1", "result": "BLOCKED", "checks": checks, "live_gate": live_gate()}
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print("DR-018: BLOCKED (synthetic read-model harness PASS; live DSH boot BLOCKED)")
        print("checks: " + ", ".join(checks))
        print("live: " + report["live_gate"]["reason"])
    return 3 if args.require_live else 0


if __name__ == "__main__":
    raise SystemExit(main())
