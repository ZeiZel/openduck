#!/bin/sh
set -eu
OBSIDIAN_AUTHORIZATION=$(cat "$(dirname "$0")/../.openclaw-state/obsidian-auth.env")
export OBSIDIAN_AUTHORIZATION
code=$(curl -sS -o /dev/null -w '%{http_code}' -H "Authorization: $OBSIDIAN_AUTHORIZATION" http://127.0.0.1:27123/mcp/ || true)
printf '%s\n' "$code"
