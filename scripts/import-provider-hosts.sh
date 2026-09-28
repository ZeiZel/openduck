#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)

# Imports already acquired, pinned official macOS arm64 provider executables
# into provider source directories. It performs no network access and never
# reads provider credentials or OAuth state.
CODEX_SOURCE=""
CLAUDE_SOURCE=""
KIMI_SOURCE=""
QWEN_SOURCE=""
OUTPUT_DIR=""

die() { echo "import-provider-hosts: $*" >&2; exit 2; }
while (($#)); do
  case "$1" in
    --output-dir) OUTPUT_DIR=${2:?missing value}; shift 2 ;;
    --codex) CODEX_SOURCE=${2:?missing value}; shift 2 ;;
    --claude) CLAUDE_SOURCE=${2:?missing value}; shift 2 ;;
    --kimi) KIMI_SOURCE=${2:?missing value}; shift 2 ;;
    --qwen) QWEN_SOURCE=${2:?missing value}; shift 2 ;;
    *) die "unknown option: $1" ;;
  esac
done
[[ "$OUTPUT_DIR" = /* ]] || die "--output-dir must be absolute"

import_native() {
  local provider=$1 source=$2 leaf=$3 expected_team=$4
  [[ "$source" = /* && -f "$source" && ! -L "$source" ]] || die "$provider source must be an absolute regular file"
  [[ "$(file -b "$source")" == *"Mach-O 64-bit executable arm64"* ]] || die "$provider source is not a native arm64 Mach-O"
  codesign --verify --strict --verbose=2 "$source" >/dev/null 2>&1 || die "$provider code signature is invalid"
  local signing team cdhash artifact_digest image_identity
  signing=$(codesign -dv --verbose=4 "$source" 2>&1)
  team=$(printf '%s\n' "$signing" | awk -F= '$1=="TeamIdentifier" {print $2}')
  cdhash=$(printf '%s\n' "$signing" | awk -F= '$1=="CDHash" {print $2}')
  [[ "$team" == "$expected_team" && "$cdhash" =~ ^[0-9a-fA-F]{40}$ ]] || die "$provider signing identity mismatch"
  local target="$OUTPUT_DIR/$provider/host/$leaf"
  [[ ! -e "$target" ]] || die "refusing to overwrite $target"
  mkdir -p "$(dirname "$target")"
  cp -p "$source" "$target"
  chmod 0550 "$target"
	artifact_digest=$(shasum -a 256 "$target" | awk '{print $1}')
	image_identity=$({ printf 'darwin-cdhash-v1\0'; printf '%s' "$cdhash" | xxd -r -p; } | shasum -a 256 | awk '{print $1}')
	printf '{"schema":"openduck.provider-host-identity.v1","provider":"%s","team_id":"%s","artifact_digest":"sha256:%s","image_identity":"sha256:%s"}' "$provider" "$team" "$artifact_digest" "$image_identity" >"$OUTPUT_DIR/$provider/host/host-identity.json"
	chmod 0440 "$OUTPUT_DIR/$provider/host/host-identity.json"
}

import_archive() {
  local provider=$1 archive=$2 source_leaf=$3 target_leaf=$4 expected_sha=$5 format=$6 team=$7
  [[ "$archive" = /* && -f "$archive" && ! -L "$archive" ]] || die "$provider archive must be an absolute regular file"
  [[ "$(shasum -a 256 "$archive" | awk '{print $1}')" == "$expected_sha" ]] || die "$provider pinned archive sha256 mismatch"
  local scratch
  scratch=$(mktemp -d "${TMPDIR:-/tmp}/openduck-host.XXXXXX")
  scratch=$(cd "$scratch" && pwd -P)
  # RETURN traps fire for every nested function and can remove the extraction
  # root before the archive import has completed. Clean this private scratch
  # directory explicitly at the end of the function instead.
	while IFS= read -r member; do
	  [[ -n "$member" && "$member" != /* && "$member" != ".." && "$member" != ../* && "$member" != */../* && "$member" != *$'\n'* ]] || die "$provider archive contains an unsafe path"
	done < <(bsdtar -tf "$archive")
  if [[ "$format" == zip ]]; then
    bsdtar --safe-writes -xf "$archive" -C "$scratch"
  else
    bsdtar --safe-writes -xzf "$archive" -C "$scratch"
  fi
  local candidate
  candidate=$(find "$scratch" -type f -path "*/$source_leaf" -perm -111 -print | head -1)
  [[ -n "$candidate" ]] || die "$provider archive lacks executable $source_leaf"
  import_native "$provider" "$candidate" "$target_leaf" "$team"
  rm -rf "$scratch"
}

import_qwen_closure() {
  local archive=$1 expected=c1909e12b7c8bd9abe669c09487fdf65ef8b2d60cc04755fead0dd8ee0ce4152
  [[ "$archive" = /* && -f "$archive" && ! -L "$archive" ]] || die "qwen archive must be an absolute regular file"
  [[ "$(shasum -a 256 "$archive" | awk '{print $1}')" == "$expected" ]] || die "qwen pinned archive sha256 mismatch"
  local scratch root target manifest signing cdhash team identity
  scratch=$(mktemp -d "${TMPDIR:-/tmp}/openduck-qwen.XXXXXX")
  scratch=$(cd "$scratch" && pwd -P)
  # See import_archive: cleanup is explicit after all extracted files have
  # been hashed and copied.
  while IFS= read -r member; do
    [[ "$member" =~ ^qwen-code/([A-Za-z0-9@._+/-]+)?$ && "$member" != */../* ]] || die "qwen archive contains a non-canonical path"
  done < <(bsdtar -tf "$archive")
  bsdtar --safe-writes -xzf "$archive" -C "$scratch"
  root="$scratch/qwen-code"
  [[ -f "$root/node/bin/node" && -f "$root/lib/cli-entry.js" ]] || die "qwen closure lacks node or cli entry"
  import_native qwen "$root/node/bin/node" node HX7739G8FX
  target="$OUTPUT_DIR/qwen/host/qwen-code-darwin-arm64.tar.gz"
  [[ ! -e "$target" ]] || die "refusing to overwrite $target"
  cp -p "$archive" "$target"
  chmod 0440 "$target"
  manifest="$OUTPUT_DIR/qwen/host/qwen-closure.sha256"
  signing=$(codesign -dv --verbose=4 "$root/node/bin/node" 2>&1)
  team=$(printf '%s\n' "$signing" | awk -F= '$1=="TeamIdentifier" {print $2}')
  cdhash=$(printf '%s\n' "$signing" | awk -F= '$1=="CDHash" {print $2}')
  identity="$OUTPUT_DIR/qwen/host/host-identity.json"
  (cd "$ROOT_DIR" && go run ./cmd/openduck-closure-manifest \
    --root "$root" --archive "$archive" --host-identity "$identity" \
    --node-cdhash "$cdhash" --node-team-id "$team" --out "$manifest")
  rm -rf "$scratch"
}

[[ -z "$CODEX_SOURCE" ]] || import_native codex "$CODEX_SOURCE" codex 2DC432GLL2
[[ -z "$CLAUDE_SOURCE" ]] || import_native claude "$CLAUDE_SOURCE" claude Q6L2SF6YDW
# Pinned release inputs. The caller must first verify the archive digest, then
# pass the extracted executable; importer additionally checks its signature.
[[ -z "$KIMI_SOURCE" ]] || import_archive kimi "$KIMI_SOURCE" kimi kimi-code "d3a9cc0272caa68e89e747e68e1730ab86b29cdeee8d05a976f207d19020449a" zip 2J9472RW75
[[ -z "$QWEN_SOURCE" ]] || import_qwen_closure "$QWEN_SOURCE"
[[ -n "$CODEX_SOURCE$CLAUDE_SOURCE$KIMI_SOURCE$QWEN_SOURCE" ]] || die "at least one provider input is required"
