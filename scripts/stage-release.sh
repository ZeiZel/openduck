#!/usr/bin/env bash
set -euo pipefail

# Build an unsigned, descriptor-safe release stage. This command is deliberately
# unprivileged: it never signs, reads credentials, or invokes Ansible/install.
ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
OUTPUT_DIR=""
RELEASE_ID=""
VERSION=""
KEY_ID=""
RUN_ID=""
NONCE=""
ISSUED_AT=""
EXPIRES_AT=""
SEQUENCE=""
MIN_INSTALLER=""
PLATFORM=$(go env GOOS)
ARCH=$(go env GOARCH)
TARGET_ROOT='/Library/Application Support/OpenDuck'
PROVIDER_SOURCES=()
POLICY_BUNDLE=""
POLICY_TRUST=""
PROVIDER_CATALOG_INPUT=""
PROVIDER_CATALOG_OUTPUT=""

usage() {
  cat <<'EOF'
Usage: scripts/stage-release.sh --output-dir DIR --release-id ID --version X.Y.Z \
  --key-id ID --run-id ID --nonce NONCE --sequence N \
  --issued-at RFC3339 --expires-at RFC3339 --min-installer X.Y.Z \
  [--platform darwin] [--arch arm64] [--provider-source provider=DIR]
  [--provider-policy-bundle FILE --provider-policy-trust FILE]
  [--provider-catalog-input FILE --provider-catalog-output DIR]

Creates an unsigned release stage, ManifestV2 and signing request. Provider
sources must contain the complete closed inactive group for one provider,
including provider-bundle.json and provider-trust.json, unless both dedicated
--provider-policy-bundle and --provider-policy-trust arguments are supplied.
If a source pair is present, it must match every supplied policy pair
byte-for-byte. No private key, sudo, network, or installation is used.
EOF
}

die() { echo "stage-release: $*" >&2; exit 2; }

while (($#)); do
  case "$1" in
    --output-dir) OUTPUT_DIR=${2:?missing value}; shift 2 ;;
    --release-id) RELEASE_ID=${2:?missing value}; shift 2 ;;
    --version) VERSION=${2:?missing value}; shift 2 ;;
    --key-id) KEY_ID=${2:?missing value}; shift 2 ;;
    --run-id) RUN_ID=${2:?missing value}; shift 2 ;;
    --nonce) NONCE=${2:?missing value}; shift 2 ;;
    --sequence) SEQUENCE=${2:?missing value}; shift 2 ;;
    --issued-at) ISSUED_AT=${2:?missing value}; shift 2 ;;
    --expires-at) EXPIRES_AT=${2:?missing value}; shift 2 ;;
    --min-installer) MIN_INSTALLER=${2:?missing value}; shift 2 ;;
    --platform) PLATFORM=${2:?missing value}; shift 2 ;;
    --arch) ARCH=${2:?missing value}; shift 2 ;;
    --target-root) TARGET_ROOT=${2:?missing value}; shift 2 ;;
    --provider-source) PROVIDER_SOURCES+=("${2:?missing value}"); shift 2 ;;
    --provider-policy-bundle) POLICY_BUNDLE=${2:?missing value}; shift 2 ;;
    --provider-policy-trust) POLICY_TRUST=${2:?missing value}; shift 2 ;;
    --provider-catalog-input) PROVIDER_CATALOG_INPUT=${2:?missing value}; shift 2 ;;
    --provider-catalog-output) PROVIDER_CATALOG_OUTPUT=${2:?missing value}; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown option: $1" ;;
  esac
done

[[ -n "$OUTPUT_DIR" && -n "$RELEASE_ID" && -n "$VERSION" && -n "$KEY_ID" && -n "$RUN_ID" && -n "$NONCE" && -n "$SEQUENCE" && -n "$ISSUED_AT" && -n "$EXPIRES_AT" && -n "$MIN_INSTALLER" ]] || { usage >&2; exit 2; }
[[ "$PLATFORM" == "$(go env GOOS)" && "$ARCH" == "$(go env GOARCH)" ]] || die "platform/architecture must match the local Go target"
[[ "$OUTPUT_DIR" = /* ]] || die "--output-dir must be absolute"
mkdir -p "$OUTPUT_DIR"
OUTPUT_DIR=$(cd "$OUTPUT_DIR" && pwd -P)
case "$OUTPUT_DIR" in
  '/Library/Application Support/OpenDuck'|'/Library/Application Support/OpenDuck/'*) die "output must be outside fixed install root" ;;
esac

cd "$ROOT_DIR"
"$ROOT_DIR/scripts/require-node.sh"
echo 'stage-release: bun frozen install and plugin verification'
bun install --frozen-lockfile
bun run test:plugins
bun run typecheck:plugins
echo 'stage-release: Go verification'
go test ./...
go vet ./...

if [[ -n "$PROVIDER_CATALOG_INPUT" || -n "$PROVIDER_CATALOG_OUTPUT" ]]; then
  [[ -n "$PROVIDER_CATALOG_INPUT" && -n "$PROVIDER_CATALOG_OUTPUT" ]] || die "catalog input and output must be supplied together"
  [[ "$PROVIDER_CATALOG_INPUT" = /* && "$PROVIDER_CATALOG_OUTPUT" = /* ]] || die "catalog paths must be absolute"
  echo 'stage-release: generate inactive provider catalog'
  go run ./cmd/openduck-provider-catalog generate --input "$PROVIDER_CATALOG_INPUT" --output-root "$PROVIDER_CATALOG_OUTPUT"
  PROVIDER_SOURCES=("codex=$PROVIDER_CATALOG_OUTPUT" "claude=$PROVIDER_CATALOG_OUTPUT" "qwen=$PROVIDER_CATALOG_OUTPUT" "kimi=$PROVIDER_CATALOG_OUTPUT")
fi

bundle_tmp=$(mktemp -d "$OUTPUT_DIR/.openduck-bundle.XXXXXX")
stage="$bundle_tmp/stage"
release_dir="$bundle_tmp/release"
cleanup() { rm -rf "$bundle_tmp"; }
trap cleanup EXIT
mkdir -p "$stage/bin"
mkdir -p "$release_dir"

if [[ -n "$POLICY_BUNDLE" || -n "$POLICY_TRUST" ]]; then
  [[ -n "$POLICY_BUNDLE" && -n "$POLICY_TRUST" ]] || die "policy bundle and trust must be supplied together"
  [[ -f "$POLICY_BUNDLE" && -f "$POLICY_TRUST" && ! -L "$POLICY_BUNDLE" && ! -L "$POLICY_TRUST" ]] || die "policy inputs must be regular files"
  cp -p "$POLICY_BUNDLE" "$stage/provider-bundle.json"
  cp -p "$POLICY_TRUST" "$stage/provider-trust.json"
fi

base_bins=(codex openduck-anchor openduck-checkpoint openduck-codex-broker openduck-codex-login openduck-codex-runtime openduck-controller openduck-egress openduck-installer openduck-native-mcp openduck-owner-grant openduck-provider-attestor openduck-readiness)
for name in "${base_bins[@]}"; do
  echo "stage-release: build $name"
  go build -trimpath -buildvcs=false -o "$stage/bin/$name" "./cmd/$([[ "$name" == codex ]] && echo openduck || echo "$name")"
done

provider_seen=""
for spec in ${PROVIDER_SOURCES[@]+"${PROVIDER_SOURCES[@]}"}; do
  provider=${spec%%=*}; source=${spec#*=}
  [[ "$provider" != "$spec" && "$provider" =~ ^(claude|codex|deepseek|kimi|qwen)$ ]] || die "provider source must be PROVIDER=DIR"
  [[ -d "$source" ]] || die "provider source is not a directory: $source"
  [[ ",$provider_seen," != *",$provider,"* ]] || die "duplicate provider source: $provider"
  provider_seen="$provider_seen,$provider"
  provider_root="$source"
  if [[ -d "$source/providers/$provider" ]]; then
    provider_root="$source/providers/$provider"
  fi
  # Copy only the exact catalog subtree; packager performs the final closed
  # inventory, mode, canonical JSON, and all-or-none group validation.
  mkdir -p "$stage/providers/$provider"
  for leaf in plugin-descriptor.json runtime-descriptor.json dsh-adapter-descriptor.json topology.json; do
    if [[ -e "$provider_root/$leaf" ]]; then
      [[ -f "$provider_root/$leaf" && ! -L "$provider_root/$leaf" ]] || die "provider leaf must be a regular file: $provider_root/$leaf"
      cp -p "$provider_root/$leaf" "$stage/providers/$provider/$leaf"
    fi
  done
	if [[ "$provider" != deepseek ]]; then
	  host_leaf=$provider
	  [[ "$provider" != kimi ]] || host_leaf=kimi-code
	  [[ "$provider" != qwen ]] || host_leaf=node
	  [[ -f "$provider_root/host/$host_leaf" && ! -L "$provider_root/host/$host_leaf" && -x "$provider_root/host/$host_leaf" ]] || die "provider source lacks verified host executable: $provider"
	  mkdir -p "$stage/providers/$provider/host"
	  cp -p "$provider_root/host/$host_leaf" "$stage/providers/$provider/host/$host_leaf"
	  [[ -f "$provider_root/host/host-identity.json" && ! -L "$provider_root/host/host-identity.json" ]] || die "$provider source lacks host identity descriptor"
	  cp -p "$provider_root/host/host-identity.json" "$stage/providers/$provider/host/host-identity.json"
	  if [[ "$provider" == qwen ]]; then
	    for closure_leaf in qwen-code-darwin-arm64.tar.gz qwen-closure.sha256; do
	      [[ -f "$provider_root/host/$closure_leaf" && ! -L "$provider_root/host/$closure_leaf" ]] || die "qwen source lacks closed runtime artifact: $closure_leaf"
	      cp -p "$provider_root/host/$closure_leaf" "$stage/providers/qwen/host/$closure_leaf"
	    done
	  fi
	fi
  source_has_bundle=false
  source_has_trust=false
  [[ -e "$source/provider-bundle.json" ]] && source_has_bundle=true
  [[ -e "$source/provider-trust.json" ]] && source_has_trust=true
  if $source_has_bundle || $source_has_trust; then
    $source_has_bundle && $source_has_trust || die "provider source has an incomplete policy pair: $provider"
    [[ ! -L "$source/provider-bundle.json" && ! -L "$source/provider-trust.json" ]] || die "provider policy links are forbidden"
    if [[ ! -f "$stage/provider-bundle.json" ]]; then
      cp -p "$source/provider-bundle.json" "$stage/provider-bundle.json"
      cp -p "$source/provider-trust.json" "$stage/provider-trust.json"
    else
      cmp -s "$source/provider-bundle.json" "$stage/provider-bundle.json" || die "provider policy bundle differs between sources"
      cmp -s "$source/provider-trust.json" "$stage/provider-trust.json" || die "provider policy trust differs between sources"
    fi
  elif [[ ! -f "$stage/provider-bundle.json" ]]; then
    [[ -n "$POLICY_BUNDLE" && -n "$POLICY_TRUST" ]] || die "provider source lacks policy pair: $provider"
  fi
  daemon="openduck-provider-$provider"
  go build -trimpath -buildvcs=false -o "$stage/bin/$daemon" "./cmd/$daemon"
done

chmod u=rwx,go= "$stage"/bin/*
manifest="$release_dir/openduck.release-manifest.v2.json"
request="$release_dir/openduck.release-signing-request.v1.json"
echo 'stage-release: package unsigned manifest and signing request'
go run ./cmd/openduck-release-packager package \
  --stage-root "$stage" --manifest-out "$manifest" --signing-request-out "$request" \
  --release-id "$RELEASE_ID" --version "$VERSION" --target-root "$TARGET_ROOT" \
  --platform "$PLATFORM" --arch "$ARCH" --key-id "$KEY_ID" --operation deploy \
  --run-id "$RUN_ID" --activation false --sequence "$SEQUENCE" --nonce "$NONCE" \
  --issued-at "$ISSUED_AT" --expires-at "$EXPIRES_AT" --min-installer "$MIN_INSTALLER"

final_bundle="$OUTPUT_DIR/$RELEASE_ID"
[[ ! -e "$final_bundle" ]] || die "release bundle already exists: $final_bundle"
go run ./cmd/openduck-release-publisher --staging "$bundle_tmp" --target "$final_bundle" || die "release bundle publication collision or unsafe output parent"
[[ -d "$final_bundle" && ! -e "$bundle_tmp" ]] || die "release bundle publication failed"
trap - EXIT
final_stage="$final_bundle/stage"
manifest="$final_bundle/release/openduck.release-manifest.v2.json"
request="$final_bundle/release/openduck.release-signing-request.v1.json"
helper_digest=$(shasum -a 256 "$final_stage/bin/openduck-installer" | awk '{print $1}')
manifest_digest=$(shasum -a 256 "$manifest" | awk '{print $1}')
request_digest=$(shasum -a 256 "$request" | awk '{print $1}')
printf 'stage=%s\nmanifest=%s\nsigning_request=%s\ninstaller_sha256=%s\nmanifest_sha256=%s\nsigning_request_sha256=%s\n' \
  "$final_stage" "$manifest" "$request" "$helper_digest" "$manifest_digest" "$request_digest"
