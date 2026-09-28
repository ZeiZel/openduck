#!/bin/sh
set -eu

# Owner-only RPC helper. The shared gateway token is read from runtime state
# and passed to this one gateway-call surface; it is never printed or stored.
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
STATE="$ROOT/.openclaw-state"
export OPENCLAW_CONFIG_PATH="$ROOT/deploy/openclaw/config.json"
export OPENCLAW_STATE_DIR="$STATE"
umask 077

if [ "$#" -lt 1 ]; then
  echo "usage: scripts/openclaw-gateway-call.sh <method> [gateway call options]" >&2
  exit 2
fi
if [ ! -r "$STATE/gateway.token" ]; then
  echo "gateway token file missing" >&2
  exit 1
fi
OPENCLAW_GATEWAY_TOKEN=$(cat "$STATE/gateway.token")
export OPENCLAW_GATEWAY_TOKEN
METHOD=$1
shift
exec "$ROOT/deploy/openclaw/node_modules/.bin/openclaw" gateway call "$METHOD" "$@" --token "$OPENCLAW_GATEWAY_TOKEN"
