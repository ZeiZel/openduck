#!/usr/bin/env bash
set -euo pipefail

# Bun silently substitutes itself for `node` when no real Node is on PATH, so
# `node --test` becomes `bun <file>` and every node:test file fails with an
# unrelated "Cannot use test outside of the test runner" error. Resolve Node
# here, in bash, before any workspace script can be misrouted.
MIN_MAJOR=22
MIN_MINOR=19
MIN_PATCH=0

die() { echo "require-node: $*" >&2; exit 2; }

node_bin=$(command -v node || true)
[[ -n "$node_bin" ]] || die "node is not on PATH; the plugin suites need Node >= $MIN_MAJOR.$MIN_MINOR.$MIN_PATCH (bun would silently run them as bun)"

runtime=$("$node_bin" -e 'process.stdout.write(typeof Bun === "undefined" ? process.versions.node : "bun")' 2>/dev/null) || die "$node_bin is not an executable Node runtime"
[[ "$runtime" != bun ]] || die "$node_bin resolves to bun, not Node; the plugin suites require the real node:test runner"
[[ "$runtime" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+) ]] || die "unrecognized node version: $runtime"

major=${BASH_REMATCH[1]}; minor=${BASH_REMATCH[2]}; patch=${BASH_REMATCH[3]}
if ((major < MIN_MAJOR)) || { ((major == MIN_MAJOR)) && { ((minor < MIN_MINOR)) || { ((minor == MIN_MINOR)) && ((patch < MIN_PATCH)); }; }; }; then
  die "node $runtime is older than the required $MIN_MAJOR.$MIN_MINOR.$MIN_PATCH"
fi
