#!/bin/sh
# Unprivileged regression check: legacy wrappers cannot execute staged data.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
for script in macos-boundary-install.sh macos-boundary-stop.sh macos-boundary-rollback.sh macos-boundary-verify.sh; do
  sh -n "$ROOT/scripts/$script"
done
for script in macos-boundary-install.sh macos-boundary-stop.sh macos-boundary-rollback.sh; do
  if "$ROOT/scripts/$script" >/dev/null 2>&1; then
    echo "$script unexpectedly succeeded" >&2; exit 1
  fi
  ! rg -q -- 'staged-source|--apply|--stop|--rollback|exec "\$INSTALLER' "$ROOT/scripts/$script"
done
rg -q 'deploy/ansible/site.yml' "$ROOT/scripts/macos-boundary-install.sh"
echo 'macos-boundary-bundle-test: PASS (legacy mutation wrappers disabled)'
