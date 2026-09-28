#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

echo "P2A synthetic conformance: focused tests"
go test ./internal/syntheticpd ./internal/localpd ./internal/dshbridge ./internal/dshbridgehttp ./internal/synthetic
echo "P2A synthetic conformance: bounded race set"
go test -race ./internal/syntheticpd ./internal/localpd ./internal/dshbridge ./internal/dshbridgehttp
echo "P2A synthetic conformance: full verification"
go test ./...
go vet ./...
node scripts/dsh-command-center-sentinel.mjs
scripts/dsh-verify.sh
git diff --check

if rg -n --hidden --glob '*.log' --glob '*.json' --glob '*.txt' --glob '*.md' 'RAW_PD_SENTINEL|SYNTHETIC_PD_SENTINEL' docs/evidence deploy internal 2>/dev/null; then
  echo 'raw synthetic sentinel leaked into generated/evidence output' >&2
  exit 1
fi
echo 'P2A synthetic conformance: PASS (no live services, sockets, accounts, models, or effects)'
