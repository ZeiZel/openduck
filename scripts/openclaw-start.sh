#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
STATE="$ROOT/.openclaw-state"
export OPENCLAW_CONFIG_PATH="$ROOT/deploy/openclaw/config.json"
export OPENCLAW_STATE_DIR="$STATE"
# Prefer the system Docker socket alias so launchd/Gateway does not need to
# resolve the per-user ~/.docker/run path inside the sandbox runtime.
export DOCKER_HOST="unix:///var/run/docker.sock"
export DOCKER_CONTEXT="default"
umask 077
if [ ! -r "$STATE/gateway.token" ]; then echo "gateway token file missing" >&2; exit 1; fi
if [ -r "$STATE/obsidian-auth.env" ]; then OBSIDIAN_AUTHORIZATION=$(cat "$STATE/obsidian-auth.env"); export OBSIDIAN_AUTHORIZATION; fi
OPENCLAW_GATEWAY_TOKEN=$(cat "$STATE/gateway.token")
export OPENCLAW_GATEWAY_TOKEN
exec "$ROOT/deploy/openclaw/node_modules/.bin/openclaw" gateway run --bind loopback --port 18789
