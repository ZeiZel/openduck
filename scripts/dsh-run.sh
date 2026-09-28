#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if (($# == 0)); then
  set -- --host 127.0.0.1
fi
exec "$ROOT_DIR/scripts/dsh-base.sh" --profile openduck "$@"
