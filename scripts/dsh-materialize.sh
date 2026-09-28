#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SOURCE_DIR="$ROOT_DIR/third_party/deepseek-harness"
LOCK_FILE="$SOURCE_DIR/LOCK.json"
DEST_DIR="$SOURCE_DIR.materialized"
ARCHIVE=""
DOWNLOAD=0

usage() {
  printf 'Usage: %s --archive FILE | --download [--destination DIR]\n' "$0" >&2
}

while (($#)); do
  case "$1" in
    --archive) [[ $# -ge 2 ]] || { usage; exit 2; }; ARCHIVE="$2"; shift 2 ;;
    --download) DOWNLOAD=1; shift ;;
    --destination) [[ $# -ge 2 ]] || { usage; exit 2; }; DEST_DIR="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) usage; exit 2 ;;
  esac
done

if ((DOWNLOAD)); then
  [[ -z "$ARCHIVE" ]] || { echo '--download and --archive are mutually exclusive' >&2; exit 2; }
  command -v curl >/dev/null || { echo 'curl is required for explicit --download' >&2; exit 1; }
  url="$(python3 - "$LOCK_FILE" <<'PY'
import json, sys
print(json.load(open(sys.argv[1], encoding='utf-8'))["archive"]["url"])
PY
)"
  tmp_archive="$(mktemp -t dsh-archive.XXXXXX)"
  trap 'rm -f "$tmp_archive"' EXIT
  curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 -o "$tmp_archive" "$url"
  ARCHIVE="$tmp_archive"
fi

[[ -n "$ARCHIVE" ]] || { usage; echo 'a local archive is required; network is opt-in via --download' >&2; exit 2; }
[[ -f "$ARCHIVE" ]] || { echo "missing archive: $ARCHIVE" >&2; exit 1; }
[[ -f "$LOCK_FILE" ]] || { echo "missing lock: $LOCK_FILE" >&2; exit 1; }

"$ROOT_DIR/scripts/dsh-verify.sh" --source "$SOURCE_DIR" --archive "$ARCHIVE"

python3 - "$ARCHIVE" "$LOCK_FILE" <<'PY'
import json, pathlib, posixpath, sys, tarfile

archive = pathlib.Path(sys.argv[1])
lock = json.loads(pathlib.Path(sys.argv[2]).read_text(encoding="utf-8"))
expected_root = f"deepseek-harness-{lock['commit']}"
seen = set(); roots = set()
with tarfile.open(archive, "r:gz") as tf:
    for member in tf.getmembers():
        name = member.name
        if not name or name.startswith("/") or "\\" in name:
            raise SystemExit(f"unsafe archive member name: {name!r}")
        normalized = posixpath.normpath(name)
        if normalized != name or name == "." or name.startswith("../") or "/../" in name:
            raise SystemExit(f"archive traversal member: {name!r}")
        root = name.split("/", 1)[0]
        roots.add(root)
        if root != expected_root:
            raise SystemExit(f"unexpected archive root: {root!r}")
        if name in seen:
            raise SystemExit(f"duplicate archive member: {name!r}")
        seen.add(name)
        if member.islnk() or member.isfifo() or member.ischr() or member.isblk() or member.isdev():
            raise SystemExit(f"unsupported archive member type: {name!r}")
        if member.issym():
            target = member.linkname
            if target.startswith("/") or "\\" in target:
                raise SystemExit(f"unsafe symlink target: {name!r}")
            target_path = posixpath.normpath(posixpath.join(posixpath.dirname(name), target))
            if target_path.split("/", 1)[0] != expected_root or target_path.startswith("../"):
                raise SystemExit(f"symlink escapes archive root: {name!r}")
if roots != {expected_root}:
    raise SystemExit(f"archive must have exactly one pinned root: {sorted(roots)!r}")
print(f"archive safety: {len(seen)} members, root={expected_root}")
PY

tmp_dir="$(mktemp -d -t dsh-source.XXXXXX)"
trap 'rm -rf "$tmp_dir"' EXIT
tar --extract --gzip --file "$ARCHIVE" --directory "$tmp_dir" --no-same-owner
top_dir="$(find "$tmp_dir" -mindepth 1 -maxdepth 1 -type d -print -quit)"
[[ -n "$top_dir" ]] || { echo 'archive has no single top-level directory' >&2; exit 1; }

target_parent="$(dirname "$DEST_DIR")"
mkdir -p "$target_parent"
staged="$(mktemp -d "$target_parent/.dsh-stage.XXXXXX")"
trap 'rm -rf "$tmp_dir" "$staged"' EXIT
cp -R "$top_dir/." "$staged/"
cp "$LOCK_FILE" "$staged/LOCK.json"
cp "$SOURCE_DIR/SOURCE-MANIFEST.sha256" "$staged/SOURCE-MANIFEST.sha256"
[[ ! -e "$DEST_DIR" ]] || { echo "destination exists: $DEST_DIR" >&2; exit 1; }
mv "$staged" "$DEST_DIR"
echo "materialized verified source at $DEST_DIR"
