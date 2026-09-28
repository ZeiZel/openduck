#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SOURCE_DIR="$ROOT_DIR/third_party/deepseek-harness"
PATCH_DIR="$ROOT_DIR/third_party/deepseek-harness-patches"
DEST_DIR=""

usage() { printf 'Usage: %s --source DIR --destination DIR [--check]\n' "$0" >&2; }
CHECK=0
while (($#)); do
  case "$1" in
    --source) [[ $# -ge 2 ]] || { usage; exit 2; }; SOURCE_DIR="$2"; shift 2 ;;
    --destination) [[ $# -ge 2 ]] || { usage; exit 2; }; DEST_DIR="$2"; shift 2 ;;
    --check) CHECK=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) usage; exit 2 ;;
  esac
done

[[ -d "$SOURCE_DIR" && -f "$SOURCE_DIR/LOCK.json" ]] || { echo 'pinned source/LOCK.json is required' >&2; exit 1; }
[[ -n "$DEST_DIR" ]] || { usage; exit 2; }

expected_commit="$(jq -r '.commit' "$SOURCE_DIR/LOCK.json")"
[[ "$expected_commit" == '99f6f02fecdb7dff40c3fbc9470f5907c29f74ca' ]] || {
  echo "refusing unpinned DSH commit: $expected_commit" >&2; exit 1;
}
[[ ! -e "$DEST_DIR" ]] || { echo "destination exists: $DEST_DIR" >&2; exit 1; }
mkdir -p "$(dirname "$DEST_DIR")"
cp -R "$SOURCE_DIR/." "$DEST_DIR/"

for patch_file in "$PATCH_DIR"/[0-9][0-9][0-9][0-9]-*.patch; do
  [[ -f "$patch_file" ]] || continue
  patch -d "$DEST_DIR" -p1 --batch --forward --fuzz=0 < "$patch_file"
done

if ((CHECK)); then
  command -v node >/dev/null || { echo 'node is required for fixture check' >&2; exit 1; }
  node --experimental-strip-types "$DEST_DIR/packages/core/session/tests/openduck-admission.spec.ts"
fi

echo "DSH ingress fork patches applied: commit=$expected_commit destination=$DEST_DIR"
