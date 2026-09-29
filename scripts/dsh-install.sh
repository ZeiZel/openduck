#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUNTIME_DIR="${DSH_RUNTIME_DIR:-$ROOT_DIR/.dsh-runtime}"
DSH_HOME_DIR="${DSH_HOME:-$ROOT_DIR/.dsh-home}"
DSH_VERSION="0.1.7-rc.2"

usage() {
  printf 'Usage: %s [--runtime DIR] [--home DIR]\n' "$0"
}
while (($#)); do
  case "$1" in
    --runtime)
      [[ $# -ge 2 && -n "$2" ]] || { printf 'dsh-install: --runtime needs a directory\n' >&2; exit 2; }
      RUNTIME_DIR="$2"; shift 2 ;;
    --home)
      [[ $# -ge 2 && -n "$2" ]] || { printf 'dsh-install: --home needs a directory\n' >&2; exit 2; }
      DSH_HOME_DIR="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) printf 'dsh-install: unknown argument: %s\n' "$1" >&2; usage >&2; exit 2 ;;
  esac
done

command -v node >/dev/null || { printf 'dsh-install: node >=22.19 is required\n' >&2; exit 127; }
command -v pnpm >/dev/null || { printf 'dsh-install: pnpm is required for native profile management\n' >&2; exit 127; }
node -e 'const [major, minor] = process.versions.node.split(".").map(Number); if (major < 22 || major === 23 || (major === 22 && minor < 19)) process.exit(1)' || { printf 'dsh-install: node ^22.19 or >=24 is required\n' >&2; exit 1; }

prepare_directory() {
  local target="$1" label="$2"
  if [[ -L "$target" ]]; then
    printf 'dsh-install: refusing a symlinked %s directory: %s\n' "$label" "$target" >&2
    exit 1
  fi
  if [[ -e "$target" && ! -d "$target" ]]; then
    printf 'dsh-install: %s path is not a directory: %s\n' "$label" "$target" >&2
    exit 1
  fi
  mkdir -p "$target"
  if [[ -L "$target" ]]; then
    printf 'dsh-install: refusing a symlinked %s directory: %s\n' "$label" "$target" >&2
    exit 1
  fi
  (cd "$target" && pwd -P)
}

RUNTIME_DIR="$(prepare_directory "$RUNTIME_DIR" runtime)"
DSH_HOME_DIR="$(prepare_directory "$DSH_HOME_DIR" home)"
mkdir -p "$DSH_HOME_DIR/profiles"
if [[ -L "$DSH_HOME_DIR/profiles" ]]; then
  printf 'dsh-install: refusing a symlinked profiles directory: %s\n' "$DSH_HOME_DIR/profiles" >&2
  exit 1
fi
if [[ -f "$RUNTIME_DIR/package.json" ]] && ! node -e 'const fs = require("node:fs"); const p = JSON.parse(fs.readFileSync(process.argv[1], "utf8")); process.exit(p.name === "openduck-dsh-runtime" ? 0 : 1)' "$RUNTIME_DIR/package.json"; then
  printf 'dsh-install: refusing to overwrite an unrelated runtime directory: %s\n' "$RUNTIME_DIR" >&2
  exit 1
fi
if [[ "$RUNTIME_DIR" != "$ROOT_DIR/scripts/dsh-runtime" ]]; then
  mkdir -p "$RUNTIME_DIR"
  cp "$ROOT_DIR/scripts/dsh-runtime/package.json" "$RUNTIME_DIR/package.json"
  cp "$ROOT_DIR/scripts/dsh-runtime/pnpm-lock.yaml" "$RUNTIME_DIR/pnpm-lock.yaml"
  cp "$ROOT_DIR/scripts/dsh-runtime/pnpm-workspace.yaml" "$RUNTIME_DIR/pnpm-workspace.yaml"
  mkdir -p "$RUNTIME_DIR/patches"
  cp "$ROOT_DIR/scripts/dsh-runtime/patches/fetch-blob@3.2.0.patch" "$RUNTIME_DIR/patches/fetch-blob@3.2.0.patch"
fi
COREPACK_ENABLE_PROJECT_SPEC=0 pnpm --dir "$RUNTIME_DIR" install --frozen-lockfile --ignore-scripts

export DSH_HOME="$DSH_HOME_DIR"
export COREPACK_ENABLE_PROJECT_SPEC=0
DSH_BIN="$RUNTIME_DIR/node_modules/.bin/dsh"
if [[ ! -x "$DSH_BIN" ]]; then
  printf 'dsh-install: installed runtime has no dsh executable\n' >&2
  exit 1
fi

PROFILE_DIR="$DSH_HOME_DIR/profiles/openduck"
if [[ -L "$PROFILE_DIR" ]]; then
  printf 'dsh-install: refusing a symlinked profile directory: %s\n' "$PROFILE_DIR" >&2
  exit 1
fi
# Seed the profile's pnpm policy before `dsh plugin install` initializes and
# resolves its first dependency graph. This keeps the native DOMException
# replacement active during the very first install as well as upgrades.
mkdir -p "$PROFILE_DIR/patches"
cp "$ROOT_DIR/scripts/dsh-runtime/patches/fetch-blob@3.2.0.patch" "$PROFILE_DIR/patches/fetch-blob@3.2.0.patch"
node - "$PROFILE_DIR/pnpm-workspace.yaml" <<'NODE'
const fs = require('node:fs')
const file = process.argv[2]
let text = fs.existsSync(file) ? fs.readFileSync(file, 'utf8') : 'packages:\n  - .\n\nnodeLinker: hoisted\nautoInstallPeers: false\n'
const key = "  'fetch-blob@3.2.0>node-domexception': '-'"
if (!text.includes("'fetch-blob@3.2.0>node-domexception':")) {
  if (/^overrides:\s*$/m.test(text)) text = text.replace(/^overrides:\s*$/m, `overrides:\n${key}`)
  else text = text.replace(/\s*$/, '') + `\noverrides:\n${key}\n`
}
if (!/^allowUnusedPatches:/m.test(text)) text = text.replace(/\s*$/, '') + '\nallowUnusedPatches: true\n'
fs.writeFileSync(file, text)
NODE
configure_profile() {
node - "$PROFILE_DIR/pnpm-workspace.yaml" <<'NODE'
const fs = require('node:fs')
const file = process.argv[2]
let text = fs.readFileSync(file, 'utf8')
text = text.replace(/^  ['"]@deepseek-ai\/(?:cordis|cosmokit|dsh-app-boot|cordis-plugin-(?:hmr|timer|include|loader))['"]?:.*\n/gm, '')
// Host peers (cordis, dsh-app-boot, config-editor peers, React) must resolve
// from the DSH installation. Auto-installing them into the profile creates a
// second dsh-app-boot instance, and every settings write then fails with
// "profile reload requires the root Include entry".
text = text.replace(/^autoInstallPeers:\s*true\s*$/m, 'autoInstallPeers: false')
// YAML plain scalars cannot start with `@`. Older installer runs wrote scoped
// package names unquoted, which pnpm correctly rejects; normalize them before
// applying this policy so a corrected installer can repair its own profile.
text = text.replace(/^(\s*)@([^:\n]+):(.*)$/gm, "$1'@$2':$3")
if (!/^allowBuilds:\s*$/m.test(text)) text += '\nallowBuilds:\n'
const decisions = new Map([
  ['@deepseek-ai/dsh-subprocess-local', 'true'],
  ['@google/genai', 'false'],
  ['koffi', 'true'],
  ['node-pty', 'true'],
  ['protobufjs', 'false'],
  ['node-addon-require-builtin', 'false'],
])
for (const [name, value] of decisions) {
  const escaped = name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
  const line = new RegExp(`(^[ \\t]*(?:['\"])?${escaped}(?:['\"])?[ \\t]*:[ \\t]*)set this to true or false`, 'm')
  if (line.test(text)) text = text.replace(line, `$1${value}`)
  else if (!new RegExp(`^[ \\t]*(?:['\"])?${escaped}(?:['\"])?[ \\t]*:`, 'm').test(text)) {
    const yamlName = name.startsWith('@') ? `'${name}'` : name
    text += `  ${yamlName}: ${value}\n`
  }
}
if (!/^overrides:\s*$/m.test(text)) {
  text += '\noverrides:\n'
}
fs.writeFileSync(file, text)
NODE
}

if [[ -f "$PROFILE_DIR/package.json" ]]; then configure_profile; fi
# The pinned DSH installation already ships dsh-base and dsh-web-app. Select
# them as installation-owned bundles, exactly like `dsh --from-default-profile
# web`, instead of installing second copies into the profile: a profile copy
# brings its own dsh-app-boot/config-editor instances, and every native
# settings write then fails with "profile reload requires the root Include entry".
select_installation_bundles() {
node - "$PROFILE_DIR/package.json" <<'NODE'
const fs = require('node:fs')
const file = process.argv[2]
if (!fs.existsSync(file)) process.exit(0)
const pkg = JSON.parse(fs.readFileSync(file, 'utf8'))
const owned = ['@deepseek-ai/dsh-base', '@deepseek-ai/dsh-web-app']
pkg.dependencies ??= {}
for (const name of owned) delete pkg.dependencies[name]
for (const [name, spec] of Object.entries(pkg.dependencies)) {
  const candidate = typeof spec === 'string' && spec.startsWith('file:') ? spec.slice(5) : ''
  if (candidate.endsWith('.tgz') && !fs.existsSync(candidate)) delete pkg.dependencies[name]
}
pkg.dsh ??= {}
pkg.dsh.profile ??= {}
const bundles = Array.isArray(pkg.dsh.profile.bundles) ? pkg.dsh.profile.bundles : []
pkg.dsh.profile.bundles = [...owned, ...bundles.filter(name => !owned.includes(name))]
fs.writeFileSync(file, `${JSON.stringify(pkg, null, 2)}\n`)
NODE
}
select_installation_bundles
"$DSH_BIN" plugin --profile openduck install
if [[ -L "$PROFILE_DIR" ]]; then
  printf 'dsh-install: refusing a symlinked profile directory: %s\n' "$PROFILE_DIR" >&2
  exit 1
fi
configure_profile
select_installation_bundles
node - "$PROFILE_DIR/pnpm-workspace.yaml" <<'NODE'
const fs = require('node:fs')
const file = process.argv[2]
let text = fs.readFileSync(file, 'utf8')
if (!text.includes('fetch-blob@3.2.0: patches/fetch-blob@3.2.0.patch')) text += '\npatchedDependencies:\n  fetch-blob@3.2.0: patches/fetch-blob@3.2.0.patch\n'
// The stock bundles (and their fetch-blob) come from the patched installation,
// so the profile usually has no fetch-blob. Keep the guard for third-party
// plugins that bring one, without failing installs that do not.
if (!/^allowUnusedPatches:/m.test(text)) text += '\nallowUnusedPatches: true\n'
fs.writeFileSync(file, text)
NODE

BUNDLE_ARCHIVE_DIR="$RUNTIME_DIR/bundles"
mkdir -p "$BUNDLE_ARCHIVE_DIR"
if [[ -L "$BUNDLE_ARCHIVE_DIR" ]]; then
  printf 'dsh-install: refusing a symlinked bundle directory: %s\n' "$BUNDLE_ARCHIVE_DIR" >&2
  exit 1
fi
PACK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/openduck-base.XXXXXX")"
cleanup_bundle_archive() {
  rm -rf -- "$PACK_DIR"
}
trap cleanup_bundle_archive EXIT
(cd "$ROOT_DIR/plugins/openduck-base" && npm pack --pack-destination "$PACK_DIR" --ignore-scripts)
set -- "$PACK_DIR"/*.tgz
if (($# != 1)) || [[ ! -f "$1" ]]; then
  printf 'dsh-install: expected exactly one OpenDuck base bundle archive\n' >&2
  exit 1
fi
ARCHIVE_DIGEST="$(shasum -a 256 "$1" | awk '{print $1}')"
ARCHIVE_PATH="$BUNDLE_ARCHIVE_DIR/openduck-base-${ARCHIVE_DIGEST}.tgz"
if [[ ! -f "$ARCHIVE_PATH" ]]; then cp "$1" "$ARCHIVE_PATH"; fi

"$DSH_BIN" plugin --profile openduck add "$ARCHIVE_PATH"

if [[ ! -e "$PROFILE_DIR/openduck-cli-root.disabled" ]]; then
  "$ROOT_DIR/scripts/dsh-connect.sh" cli-chat
fi

printf '\nDSH installed at %s\nProfile: %s\nRun: %s\n' "$RUNTIME_DIR" "$DSH_HOME_DIR/profiles/openduck" "$ROOT_DIR/scripts/dsh-run.sh"
