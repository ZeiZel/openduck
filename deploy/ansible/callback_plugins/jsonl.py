"""Small local, non-secret JSONL callback for deployment diagnostics."""
from __future__ import annotations

import json
import os
import time
from pathlib import Path

from ansible.plugins.callback import CallbackBase


class CallbackModule(CallbackBase):
    CALLBACK_VERSION = 2.0
    CALLBACK_TYPE = "notification"
    CALLBACK_NAME = "openduck_jsonl"
    CALLBACK_NEEDS_WHITELIST = False

    _events = {"playbook_start", "ok", "changed", "failed", "skipped", "unreachable"}
    _fields = (
        "run_id", "release_digest", "phase", "reason_code", "primary_reason_code", "compensation_reason_code", "scope",
        "recovery_state", "mode", "check_mode", "changed", "converged",
        "rollback_reason_code", "rollback_state",
    )

    def __init__(self):
        super().__init__()
        self._path = Path(os.environ.get("OPENDUCK_ANSIBLE_LOG", ".openduck/ansible-logs/run.jsonl"))
        self._path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        try:
            os.chmod(self._path.parent, 0o700)
        except OSError:
            pass

    def _write(self, event: str, projection=None) -> None:
        if event not in self._events:
            return
        record = {"ts": int(time.time()), "event": event}
        if isinstance(projection, dict):
            for field in self._fields:
                if field in projection:
                    record[field] = projection[field]
        old = os.umask(0o077)
        try:
            with self._path.open("a", encoding="utf-8") as stream:
                stream.write(json.dumps(record, sort_keys=True) + "\n")
            os.chmod(self._path, 0o600)
        finally:
            os.umask(old)

    def v2_playbook_on_start(self, playbook):
        self._write("playbook_start")

    def v2_runner_on_ok(self, result):
        projection = result._result.get("openduck_diagnostic")
        if not isinstance(projection, dict) and isinstance(result._result.get("msg"), dict):
            projection = result._result.get("msg")
        self._write("changed" if result._result.get("changed") else "ok", projection)

    def v2_runner_on_failed(self, result, ignore_errors=False):
        self._write("failed", result._result.get("openduck_diagnostic"))

    def v2_runner_on_skipped(self, result):
        self._write("skipped", result._result.get("openduck_diagnostic"))

    def v2_runner_on_unreachable(self, result):
        self._write("unreachable", result._result.get("openduck_diagnostic"))
