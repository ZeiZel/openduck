#!/usr/bin/env bash
set -euo pipefail
usage() { printf 'Usage: %s [--repo PATH]\n' "$0" >&2; }
repo=''
while (($#)); do
  case "$1" in
    --repo) [[ $# -ge 2 ]] || { usage; exit 2; }; repo=$2; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) usage; exit 2 ;;
  esac
done
git_cmd=(git); [[ -z "$repo" ]] || git_cmd+=( -C "$repo" )
fail() { printf 'main-only guard: %s\n' "$1" >&2; exit 1; }
top=$("${git_cmd[@]}" rev-parse --show-toplevel 2>/dev/null) || fail 'not inside a Git worktree'
git_dir=$("${git_cmd[@]}" rev-parse --git-dir 2>/dev/null) || fail 'cannot resolve Git directory'
common_dir=$("${git_cmd[@]}" rev-parse --git-common-dir 2>/dev/null) || fail 'cannot resolve common Git directory'
case "$git_dir" in /*) ;; *) git_dir=$top/$git_dir ;; esac
case "$common_dir" in /*) ;; *) common_dir=$top/$common_dir ;; esac
git_dir=$(cd "$git_dir" && pwd -P); common_dir=$(cd "$common_dir" && pwd -P)
[[ "$git_dir" == "$common_dir" ]] || fail 'primary checkout only: linked worktrees are not allowed'
branch=$("${git_cmd[@]}" symbolic-ref --quiet --short HEAD 2>/dev/null) || fail 'detached HEAD is not allowed'
[[ "$branch" == main ]] || fail "current branch must be main (got $branch)"
worktree_count=$("${git_cmd[@]}" worktree list --porcelain | awk '$1 == "worktree" { count++ } END { print count + 0 }')
[[ "$worktree_count" == 1 ]] || fail "exactly one worktree is required (found $worktree_count)"
branches=$("${git_cmd[@]}" for-each-ref --format='%(refname:short)' refs/heads)
[[ "$branches" == main ]] || fail 'only the local main branch may exist'
printf 'main-only guard: repository is valid (%s)\n' "$top"
