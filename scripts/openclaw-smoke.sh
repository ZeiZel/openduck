#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
export OPENCLAW_CONFIG_PATH="$ROOT/deploy/openclaw/config.json" OPENCLAW_STATE_DIR="$ROOT/.openclaw-state"
export OPENCLAW_GATEWAY_TOKEN=$(cat "$ROOT/.openclaw-state/gateway.token")
exec "$ROOT/deploy/openclaw/node_modules/.bin/openclaw" agent --session-key launchd-smoke --message 'Synthetic only. Reply exactly LAUNCHD_OK' --json
