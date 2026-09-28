#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
STATE="$ROOT/.openclaw-state"

# The OpenClaw dashboard command is the supported way to build the
# token-authenticated Control UI URL.  Keep the token in the environment only;
# the command writes a non-secret URL to its logs and places the auth fragment
# in the browser/clipboard for the local owner.
export OPENCLAW_CONFIG_PATH="$ROOT/deploy/openclaw/config.json"
export OPENCLAW_STATE_DIR="$STATE"
umask 077
if [ ! -r "$STATE/gateway.token" ]; then
  echo "gateway token file missing" >&2
  exit 1
fi
OPENCLAW_GATEWAY_TOKEN=$(cat "$STATE/gateway.token")
export OPENCLAW_GATEWAY_TOKEN

exec "$ROOT/deploy/openclaw/node_modules/.bin/openclaw" dashboard
