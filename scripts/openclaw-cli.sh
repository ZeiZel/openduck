#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
export OPENCLAW_CONFIG_PATH="$ROOT/deploy/openclaw/config.json"
export OPENCLAW_STATE_DIR="$ROOT/.openclaw-state"
umask 077
OPENCLAW_GATEWAY_TOKEN=$(cat "$ROOT/.openclaw-state/gateway.token")
export OPENCLAW_GATEWAY_TOKEN
if [ -r "$ROOT/.openclaw-state/obsidian-auth.env" ]; then
  OBSIDIAN_AUTHORIZATION=$(cat "$ROOT/.openclaw-state/obsidian-auth.env")
  export OBSIDIAN_AUTHORIZATION
fi
exec "$ROOT/deploy/openclaw/node_modules/.bin/openclaw" "$@"
