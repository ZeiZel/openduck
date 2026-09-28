#!/usr/bin/env bash
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd -P)
tmp=$(mktemp -d "${TMPDIR:-/tmp}/openduck-main-only.XXXXXX")
trap 'rm -rf "$tmp"' EXIT
git -C "$tmp" init -q -b main
git -C "$tmp" config user.name test; git -C "$tmp" config user.email test@example.invalid
printf 'test\n' > "$tmp/file"; git -C "$tmp" add file; git -C "$tmp" commit -qm initial
mkdir "$tmp/.githooks"; cp "$root/.githooks"/* "$tmp/.githooks/"; chmod +x "$tmp/.githooks"/*
mkdir "$tmp/scripts"; cp "$root/scripts/check-main-only-git.sh" "$tmp/scripts/"
cp "$root/scripts/install-git-hooks.sh" "$tmp/scripts/"; chmod +x "$tmp/scripts/install-git-hooks.sh"
git -C "$tmp" config --local core.hooksPath "$tmp/.githooks"
git -C "$tmp" commit --allow-empty -qm main-commit
head=$(git -C "$tmp" rev-parse HEAD)
zero=0000000000000000000000000000000000000000
if printf '%s %s refs/heads/topic\n' "$zero" "$head" | "$tmp/.githooks/reference-transaction" prepared >/dev/null 2>&1; then printf 'topic creation was allowed\n' >&2; exit 1; fi
if printf '%s %s refs/heads/topic\n' "$head" "$head" | "$tmp/.githooks/reference-transaction" prepared >/dev/null 2>&1; then printf 'topic update was allowed\n' >&2; exit 1; fi
printf '%s %s refs/heads/topic\n' "$head" "$zero" | "$tmp/.githooks/reference-transaction" prepared >/dev/null
if printf '%s %s refs/heads/main\n' "$head" "$zero" | "$tmp/.githooks/reference-transaction" prepared >/dev/null 2>&1; then printf 'main deletion was allowed\n' >&2; exit 1; fi
printf '%s %s refs/tags/v1\n' "$zero" "$head" | "$tmp/.githooks/reference-transaction" prepared >/dev/null
printf '%s %s refs/tags/v1\n' "$head" "$zero" | "$tmp/.githooks/reference-transaction" prepared >/dev/null
printf '%s %s refs/remotes/origin/main\n' "$zero" "$head" | "$tmp/.githooks/reference-transaction" prepared >/dev/null
printf '%s %s refs/tags/fetched\n' "$zero" "$head" | "$tmp/.githooks/reference-transaction" prepared >/dev/null
printf '%s %s refs/heads/main\n' "$head" "$head" | "$tmp/.githooks/reference-transaction" prepared >/dev/null
prepush() { (cd "$tmp" && printf '%s\n' "$1" | "$tmp/.githooks/pre-push" >/dev/null 2>&1); }
prepush "refs/heads/main $head refs/heads/main $zero"
if prepush "refs/heads/main $head refs/heads/main $head"; then :; else printf 'main push unexpectedly rejected\n' >&2; exit 1; fi
printf 'next\n' >> "$tmp/file"; git -C "$tmp" add file; git -C "$tmp" commit -qm next
next=$(git -C "$tmp" rev-parse HEAD)
if ! prepush "refs/heads/main $next refs/heads/main $head"; then printf 'fast-forward main push was rejected\n' >&2; exit 1; fi
non_ff=$(git -C "$tmp" commit-tree "$(git -C "$tmp" rev-parse HEAD^{tree})" </dev/null)
if prepush "refs/heads/main $non_ff refs/heads/main $head"; then printf 'non-fast-forward main push was allowed\n' >&2; exit 1; fi
if prepush "refs/heads/topic $head refs/heads/main $zero"; then printf 'non-main push was allowed\n' >&2; exit 1; fi
if prepush "refs/heads/main $zero refs/heads/main $head"; then printf 'main deletion push was allowed\n' >&2; exit 1; fi
if prepush "refs/tags/v1 $head refs/tags/v1 $zero"; then printf 'tag push was allowed\n' >&2; exit 1; fi
detached="$tmp/detached"; git -C "$tmp" worktree add --detach -q "$detached" HEAD
if (cd "$detached" && "$tmp/scripts/check-main-only-git.sh"); then printf 'linked worktree was allowed\n' >&2; exit 1; fi
git -C "$tmp" worktree remove -f "$detached"
upstream="$tmp/upstream.git"; seed="$tmp/seed"
git init -q --bare "$upstream"; git init -q -b main "$seed"
git -C "$seed" config user.name test; git -C "$seed" config user.email test@example.invalid
printf 'upstream\n' > "$seed/file"; git -C "$seed" add file; git -C "$seed" commit -qm upstream
git -C "$seed" tag fetched-tag; git -C "$seed" push -q "$upstream" main --tags
git -C "$tmp" remote add upstream "$upstream"; git -C "$tmp" fetch -q upstream main --tags
[[ -n "$(git -C "$tmp" rev-parse refs/remotes/upstream/main)" && -n "$(git -C "$tmp" rev-parse refs/tags/fetched-tag)" ]]
git -C "$tmp" config --local core.hooksPath /tmp/custom-hooks
if "$tmp/scripts/install-git-hooks.sh" --repo "$tmp" >/dev/null 2>&1; then printf 'existing hooksPath was replaced\n' >&2; exit 1; fi
git -C "$tmp" config --local core.hooksPath .githooks
"$tmp/scripts/install-git-hooks.sh" --repo "$tmp" >/dev/null
[[ "$(git -C "$tmp" config --local --get core.hooksPath)" == .githooks ]]
printf 'main-only hook tests passed (%s)\n' "$tmp"
