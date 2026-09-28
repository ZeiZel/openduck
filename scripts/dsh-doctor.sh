#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
runtime=${DSH_RUNTIME_DIR:-"$root/.dsh-runtime"}
dsh_home=${DSH_HOME:-"$root/.dsh-home"}
report() { if command -v "$1" >/dev/null 2>&1; then printf 'provider %-10s installed\n' "$1"; else printf 'provider %-10s missing\n' "$1"; fi; }
[[ -x "$runtime/node_modules/.bin/dsh" ]] && printf 'dsh runtime    ready (%s)\n' "$runtime" || printf 'dsh runtime    missing (run make install)\n'
[[ -d "$dsh_home/profiles/openduck" ]] && printf 'profile        installed (%s)\n' "$dsh_home/profiles/openduck" || printf 'profile        missing (run make install)\n'
report codex
report claude
report kimi
if command -v cua-driver >/dev/null 2>&1; then
  if cua-driver permissions status --json >/dev/null 2>&1; then printf '%s\n' 'computer MCP   Cua Driver found; permission status readable'; else printf '%s\n' 'computer MCP   Cua Driver found; permission status unavailable'; fi
else
  printf '%s\n' 'computer MCP   Cua Driver missing'
fi
printf '%s\n' 'CLI subscription status is not probed: this doctor checks executable presence only and never reads login or credential state.'
printf '%s\n' 'Browser MCP requires a separately configured local MCP command. Computer control is only enabled by the explicit Cua Driver MCP overlay.'
