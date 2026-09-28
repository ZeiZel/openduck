#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
OUT="$ROOT/.openclaw-state/obsidian-auth.env"
umask 077
CONFIG_PATH=${CODEX_CONFIG_PATH:-"$HOME/.codex/config.toml"}
case "$CONFIG_PATH" in
  "$HOME"/*|/*) ;;
  *) echo "CODEX_CONFIG_PATH must be an absolute local path" >&2; exit 2 ;;
esac
test -r "$CONFIG_PATH"
awk '/^\[mcp_servers\.obsidian\.http_headers\]/{f=1;next} f&&/^Authorization[[:space:]]*=/{gsub(/^[^=]*=[[:space:]]*"|"[[:space:]]*$/,""); if ($0 !~ /^Bearer [^[:space:]]+$/) exit 2; print $0; exit}' "$CONFIG_PATH" > "$OUT"
test -s "$OUT"
case "$(wc -l < "$OUT")" in 1) ;; *) exit 1;; esac
chmod 600 "$OUT"
