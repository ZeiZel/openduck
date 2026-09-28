#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUNTIME_DIR="${DSH_RUNTIME_DIR:-$ROOT_DIR/.dsh-runtime}"
DSH_HOME_DIR="${DSH_HOME:-$ROOT_DIR/.dsh-home}"
DSH_BIN="$RUNTIME_DIR/node_modules/.bin/dsh"

if [[ ! -x "$DSH_BIN" ]]; then
  printf 'dsh-base: runtime not installed; run scripts/dsh-install.sh\n' >&2
  exit 127
fi
export DSH_HOME="$DSH_HOME_DIR"
export COREPACK_ENABLE_PROJECT_SPEC=0
exec "$DSH_BIN" "$@"
