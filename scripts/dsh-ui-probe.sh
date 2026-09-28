#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
mode="--require-live"
args=()
for arg in "$@"; do
  if [[ "$arg" == "--synthetic-only" ]]; then
    mode=""
  else
    args+=("$arg")
  fi
done
if [[ -n "$mode" ]]; then
  exec python3 "$ROOT_DIR/deploy/deepseek-harness/probe/openduck_synthetic_probe.py" "${args[@]}" "$mode"
fi
exec python3 "$ROOT_DIR/deploy/deepseek-harness/probe/openduck_synthetic_probe.py" "${args[@]}"
