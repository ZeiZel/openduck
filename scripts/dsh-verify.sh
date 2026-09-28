#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SOURCE_DIR="$ROOT_DIR/third_party/deepseek-harness"
LOCK_FILE="$SOURCE_DIR/LOCK.json"
ARCHIVE=""

usage() {
  printf 'Usage: %s [--archive FILE] [--source DIR]\n' "$0" >&2
}

while (($#)); do
  case "$1" in
    --archive) [[ $# -ge 2 ]] || { usage; exit 2; }; ARCHIVE="$2"; shift 2 ;;
    --source) [[ $# -ge 2 ]] || { usage; exit 2; }; SOURCE_DIR="$2"; LOCK_FILE="$SOURCE_DIR/LOCK.json"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) usage; exit 2 ;;
  esac
done

[[ -f "$LOCK_FILE" ]] || { echo "missing lock: $LOCK_FILE" >&2; exit 1; }
[[ -d "$SOURCE_DIR" ]] || { echo "missing source: $SOURCE_DIR" >&2; exit 1; }

python3 - "$SOURCE_DIR" "$LOCK_FILE" "$ARCHIVE" <<'PY'
import hashlib, json, pathlib, sys

source = pathlib.Path(sys.argv[1]).resolve()
lock_path = pathlib.Path(sys.argv[2]).resolve()
archive = pathlib.Path(sys.argv[3]).resolve() if sys.argv[3] else None
lock = json.loads(lock_path.read_text(encoding="utf-8"))

def digest(path):
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

if archive:
    actual = digest(archive)
    expected = lock["archive"]["sha256"]
    if actual != expected:
        raise SystemExit(f"archive sha256 mismatch: {actual} != {expected}")
    print(f"archive sha256: {actual}")

for name, expected in (("package.json", lock["source"]["packageJsonSha256"]),
                       ("pnpm-lock.yaml", lock["source"]["pnpmLockSha256"]),
                       ("pnpm-workspace.yaml", lock["source"]["workspaceSha256"]),
                       ("SOURCE-MANIFEST.sha256", lock["source"]["manifestSha256"])):
    actual = digest(source / name)
    if actual != expected:
        raise SystemExit(f"{name} sha256 mismatch: {actual} != {expected}")
    print(f"{name} sha256: {actual}")

manifest = source / lock["source"]["manifest"]
expected = {}
for line in manifest.read_text(encoding="utf-8").splitlines():
    if not line or line.startswith("#"): continue
    kind, mode, rel, value = line.split("\t", 3)
    expected[rel] = (kind, mode, value)
actual = {}
for path in sorted(source.rglob("*")):
    rel = "./" + path.relative_to(source).as_posix()
    if rel in {"./LOCK.json", "./SOURCE-MANIFEST.sha256"}: continue
    st = path.lstat()
    mode = format(st.st_mode & 0o777, "o")
    if path.is_symlink(): actual[rel] = ("link", mode, str(path.readlink()))
    elif path.is_file(): actual[rel] = ("file", mode, digest(path))
    elif path.is_dir(): continue
    else: raise SystemExit(f"unsupported source entry: {rel}")
if expected != actual:
    missing = sorted(set(expected) - set(actual)); extra = sorted(set(actual) - set(expected))
    changed = sorted(k for k in set(expected) & set(actual) if expected[k] != actual[k])
    raise SystemExit(f"source manifest mismatch: missing={missing[:3]} extra={extra[:3]} changed={changed[:3]}")
print(f"source manifest: {len(actual)} typed entries verified")

if lock["scripts"]["allowedBuildScripts"]:
    raise SystemExit("non-empty allowedBuildScripts is forbidden for P0")
print(f"lifecycle policy: {len(lock['scripts']['reviewedLifecycleScripts'])} scripts reviewed and blocked; allow list empty")
print(f"verified DSH {lock['tag']} @ {lock['commit']}")
PY
