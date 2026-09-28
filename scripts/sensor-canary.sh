#!/bin/sh
# Synthetic-only sender canary. It builds the private sidecar, enables the
# opt-in sensor route, and sends one bounded fixture through stdio -> HTTP ->
# encrypted queue -> Controller projection. It never prints event contents.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
STATE="$ROOT/.openduck"
BIN="$STATE/bin"
mkdir -p "$BIN"
chmod 700 "$STATE" "$BIN"
GOCACHE=${GOCACHE:-/tmp/openduck-gocache} go build -o "$BIN/openduck-controller" "$ROOT/cmd/openduck-controller"
GOCACHE=${GOCACHE:-/tmp/openduck-gocache} go build -o "$BIN/openduck-sensor-sidecar" "$ROOT/cmd/openduck-sensor-sidecar"
chmod 700 "$BIN/openduck-controller" "$BIN/openduck-sensor-sidecar"
"$ROOT/scripts/controller-install.sh" --sensor-enabled >/dev/null
controller_pid=""
if ! curl -fsS --connect-timeout 2 http://127.0.0.1:8788/readyz >/dev/null 2>&1; then
  "$BIN/openduck-controller" -listen 127.0.0.1:8788 -state .openduck/controller.enc -sensor-enabled >/dev/null 2>&1 &
  controller_pid=$!
  trap '[ -z "$controller_pid" ] || kill "$controller_pid" 2>/dev/null || true' EXIT HUP INT TERM
fi
ready=0
for _ in 1 2 3 4 5 6 7 8 9 10; do
  if curl -fsS --connect-timeout 1 http://127.0.0.1:8788/readyz >/dev/null 2>&1; then ready=1; break; fi
  sleep 0.2
done
if [ "$ready" -ne 1 ]; then
  echo "sensor canary: controller not ready" >&2
  exit 1
fi
ack=$(printf '%s\n' '{"id":"evt-synthetic-canary","text":"Synthetic status request for canary.","classification":"L1","provenance":{"adapter_id":"synthetic-sensor","account_id":"account-synthetic","source_event_id":"source-synthetic-canary","schema_version":"1.0","trace_id":"trace-1","channel":"synthetic","conversation_id":"conversation-synthetic","sender":"fixture","timestamp":"2026-08-13T00:00:00Z","version":1,"digest":"sha256:synthetic","timezone":"UTC","ingested_at":"2026-08-13T00:00:00Z"}}' | "$BIN/openduck-sensor-sidecar")
case "$ack" in
  *"task_"*"SIGNAL_READY"*) echo "sensor canary: PASS (synthetic task projected)" ;;
  *) echo "sensor canary: FAIL (metadata-only acknowledgement unexpected)" >&2; exit 1 ;;
esac
"$ROOT/scripts/controller-status.sh" | sed -n '1,20p'
