#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if (($# == 0)); then
  set -- --host 127.0.0.1
fi
DSH_HOME_DIR="${DSH_HOME:-$ROOT_DIR/.dsh-home}"
PROFILE_DIR="$DSH_HOME_DIR/profiles/openduck"
patches=()
if [[ -d "$PROFILE_DIR" ]]; then
  for patch in "$PROFILE_DIR"/openduck-*.patch.yml; do
    [[ -f "$patch" ]] && patches+=(--patch "$patch")
  done
fi
if [[ -f "$PROFILE_DIR/openduck-cli-root.disabled" ]]; then
  export OPENDUCK_CLI_ROOT_DISABLED=1
else
  export OPENDUCK_CLI_ROOT_DISABLED=0
fi
exec "$ROOT_DIR/scripts/dsh-base.sh" --profile openduck "${patches[@]}" "$@"
