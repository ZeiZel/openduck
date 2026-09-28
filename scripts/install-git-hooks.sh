#!/usr/bin/env bash
set -euo pipefail
repo=''
while (($#)); do
  case "$1" in
    --repo) [[ $# -ge 2 ]] || { printf 'Usage: %s [--repo PATH]\n' "$0" >&2; exit 2; }; repo=$2; shift 2 ;;
    -h|--help) printf 'Usage: %s [--repo PATH]\n' "$0"; exit 0 ;;
    *) printf 'Usage: %s [--repo PATH]\n' "$0" >&2; exit 2 ;;
  esac
done
git_cmd=(git); [[ -z "$repo" ]] || git_cmd+=( -C "$repo" )
root=$("${git_cmd[@]}" rev-parse --show-toplevel 2>/dev/null) || { printf 'Not a Git worktree\n' >&2; exit 1; }
"$root/scripts/check-main-only-git.sh" ${repo:+--repo "$repo"} >/dev/null
hooks="$root/.githooks"
[[ -d "$hooks" && -x "$hooks/pre-commit" && -x "$hooks/pre-push" && -x "$hooks/reference-transaction" ]] || { printf 'main-only hooks are incomplete: %s\n' "$hooks" >&2; exit 1; }
existing=$(git -C "$root" config --local --get core.hooksPath 2>/dev/null || true)
if [[ -n "$existing" && "$existing" != .githooks ]]; then
  printf 'Refusing to replace existing core.hooksPath=%s; set it to .githooks explicitly first\n' "$existing" >&2
  exit 1
fi
git -C "$root" config --local core.hooksPath .githooks
printf 'Installed main-only hooks in %s\n' "$root"
