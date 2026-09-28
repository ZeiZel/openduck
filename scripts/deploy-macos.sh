#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
STAGE_SCRIPT="${STAGE_SCRIPT_OVERRIDE:-$ROOT_DIR/scripts/stage-release.sh}"
ANSIBLE_DIR="$ROOT_DIR/deploy/ansible"
PLAYBOOK="$ANSIBLE_DIR/site.yml"
RECOVERY_PLAYBOOK="$ANSIBLE_DIR/recover-partial-install.yml"
INVENTORY="$ANSIBLE_DIR/inventory/localhost.yml"
ANSIBLE_PLAYBOOK="${ANSIBLE_PLAYBOOK_OVERRIDE:-ansible-playbook}"
GO_BIN="${GO_BIN_OVERRIDE:-go}"
FIXED_ROOT="${OPENDUCK_FIXED_ROOT_OVERRIDE:-/Library/Application Support/OpenDuck}"
TRUST_ANCHOR="${OPENDUCK_TRUST_ANCHOR_OVERRIDE:-/Library/Application Support/OpenDuck.release-trust.v1.json}"
die() { echo "deploy-macos: $*" >&2; exit 2; }
usage() {
  cat <<'EOF'
Usage:
  bun run deploy:macos -- bootstrap-trust --acknowledge-trust-bootstrap \
    --trust-bundle FILE --trust-sha256 SHA256 --bootstrap-helper FILE
    --bootstrap-helper-sha256 SHA256
  bun run deploy:macos -- prepare --output-dir DIR --release-id ID --version X.Y.Z
    --key-id ID --sequence N --min-installer X.Y.Z [--valid-for-hours 24]
    [--provider-source PROVIDER=DIR ...]
  bun run deploy:macos -- apply --bundle DIR --release-digest SHA256
    --signature FILE --trust-bundle FILE --bootstrap-helper FILE
    --bootstrap-helper-sha256 SHA256
    [--recover-partial-install --readiness-sha256 SHA256]
EOF
}
[[ $# -gt 0 ]] || { usage >&2; exit 2; }
command_name=$1; shift
case "$command_name" in bootstrap-trust|prepare|apply) ;; -h|--help) usage; exit 0 ;; *) die "expected bootstrap-trust, prepare or apply" ;; esac
is_sha256() { [[ "$1" =~ ^[0-9a-f]{64}$ ]]; }
is_abs() { [[ "$1" == /* && "$1" != *$'\n'* && "$1" != *$'\r'* ]]; }

if [[ "$command_name" == bootstrap-trust ]]; then
  acknowledge=false; trust_source=; trust_digest=; trust_helper=; helper_digest=
  while (($#)); do
    case "$1" in
      --acknowledge-trust-bootstrap) acknowledge=true; shift;;
      --trust-bundle) trust_source=${2:?missing value}; shift 2;; --trust-sha256) trust_digest=${2:?missing value}; shift 2;;
      --bootstrap-helper) trust_helper=${2:?missing value}; shift 2;; --bootstrap-helper-sha256) helper_digest=${2:?missing value}; shift 2;;
      -h|--help) usage; exit 0;; *) die "unknown bootstrap-trust option: $1";;
    esac
  done
  $acknowledge || die "bootstrap-trust requires --acknowledge-trust-bootstrap"
  [[ -n "$trust_source" && -n "$trust_digest" && -n "$trust_helper" && -n "$helper_digest" ]] || die "bootstrap-trust requires trust/helper paths and exact digests"
  is_sha256 "$trust_digest" || die "trust digest must be lowercase SHA-256"; is_sha256 "$helper_digest" || die "helper digest must be lowercase SHA-256"
  for path in "$trust_source" "$trust_helper"; do is_abs "$path" || die "bootstrap paths must be absolute"; done
  case "$trust_source" in "$FIXED_ROOT"/*|"$FIXED_ROOT") die "trust source must be outside fixed install root";; esac
  case "$trust_helper" in "$FIXED_ROOT"/*|"$FIXED_ROOT") die "bootstrap helper must be outside fixed install root";; esac
  python3 - "$trust_source" "$trust_helper" <<'PY'
import pathlib, sys
for value in sys.argv[1:]:
    p=pathlib.Path(value)
    if ".." in p.parts or not p.exists() or not p.is_file(): raise SystemExit("unsafe bootstrap path")
    cur=pathlib.Path(p.anchor)
    for part in p.parts[1:]:
        cur /= part
        if cur.is_symlink(): raise SystemExit("bootstrap path contains symlink")
if pathlib.Path(sys.argv[1]).resolve() == pathlib.Path(sys.argv[2]).resolve(): raise SystemExit("trust and helper paths overlap")
PY
  # Validate the bundle offline first. The privileged ceremony applies the same
  # gates, but it runs under a no_log Ansible task, so a non-canonical bundle
  # would surface only as an opaque non-zero helper exit.
  (cd "$ROOT_DIR" && "$GO_BIN" run ./cmd/openduck-release-packager verify-trust --trust-bundle "$trust_source") || die "trust bundle rejected before the privileged ceremony"
  echo "bootstrapping fixed release trust anchor (explicit owner action)"
  "$ANSIBLE_PLAYBOOK" --ask-become-pass -i "$INVENTORY" "$ANSIBLE_DIR/bootstrap-release-trust.yml" \
    -e release_trust_anchor_action=bootstrap \
    -e release_trust_anchor_source="$trust_source" \
    -e release_trust_anchor_sha256="$trust_digest" \
    -e release_trust_anchor_bootstrap_helper_path="$trust_helper" \
    -e release_trust_anchor_bootstrap_helper_sha256="$helper_digest"
  echo "trust_anchor_state=bootstrapped"
  exit 0
fi

if [[ "$command_name" == prepare ]]; then
  output_dir= release_id= version= key_id= sequence= min_installer=
  valid_hours=24 platform= arch= policy_bundle= policy_trust= catalog_input= catalog_output=
  provider_sources=()
  while (($#)); do
    case "$1" in
      --output-dir) output_dir=${2:?missing value}; shift 2;; --release-id) release_id=${2:?missing value}; shift 2;;
      --version) version=${2:?missing value}; shift 2;; --key-id) key_id=${2:?missing value}; shift 2;;
      --sequence) sequence=${2:?missing value}; shift 2;; --min-installer) min_installer=${2:?missing value}; shift 2;;
      --valid-for-hours) valid_hours=${2:?missing value}; shift 2;; --platform) platform=${2:?missing value}; shift 2;;
      --arch) arch=${2:?missing value}; shift 2;; --provider-source) provider_sources+=("${2:?missing value}"); shift 2;;
      --provider-policy-bundle) policy_bundle=${2:?missing value}; shift 2;; --provider-policy-trust) policy_trust=${2:?missing value}; shift 2;;
      --provider-catalog-input) catalog_input=${2:?missing value}; shift 2;; --provider-catalog-output) catalog_output=${2:?missing value}; shift 2;;
      -h|--help) usage; exit 0;; *) die "unknown prepare option: $1";;
    esac
  done
  [[ -n "$output_dir" && -n "$release_id" && -n "$version" && -n "$key_id" && -n "$sequence" && -n "$min_installer" ]] || die "prepare requires output, release, version, key, sequence, and min-installer"
  is_abs "$output_dir" || die "--output-dir must be absolute"
  [[ "$valid_hours" =~ ^([1-9]|1[0-9]|2[0-4])$ ]] || die "--valid-for-hours must be 1..24"
  [[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ && "$min_installer" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "versions must be X.Y.Z"
  [[ "$sequence" =~ ^[1-9][0-9]*$ ]] || die "sequence must be a positive integer"
  [[ -z "$policy_bundle" && -z "$policy_trust" ]] || { [[ -n "$policy_bundle" && -n "$policy_trust" ]] || die "policy bundle and trust must be supplied together"; }
  [[ -z "$catalog_input" && -z "$catalog_output" ]] || { [[ -n "$catalog_input" && -n "$catalog_output" ]] || die "catalog input and output must be supplied together"; }
  for path in "$policy_bundle" "$policy_trust" "$catalog_input" "$catalog_output"; do [[ -z "$path" ]] || { is_abs "$path" || die "all paths must be absolute"; }; done
  for spec in ${provider_sources[@]+"${provider_sources[@]}"}; do [[ "$spec" == *=* ]] || die "provider source must be PROVIDER=DIR"; is_abs "${spec#*=}" || die "provider source path must be absolute"; done
  read -r run_id nonce issued_at expires_at < <(python3 - "$valid_hours" <<'PY'
import datetime, secrets, sys
hours = int(sys.argv[1]); now = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
stamp = now.strftime('%Y%m%d-%H%M%S'); token = secrets.token_hex(12)
fmt = lambda d: d.isoformat().replace('+00:00','Z')
print(f"{stamp}-{token} openduck-{stamp}-{token} {fmt(now)} {fmt(now + datetime.timedelta(hours=hours))}")
PY
  )
  [[ -n "$platform" ]] || platform=$(go env GOOS); [[ -n "$arch" ]] || arch=$(go env GOARCH)
  args=("--output-dir" "$output_dir" --release-id "$release_id" --version "$version" --key-id "$key_id" --run-id "$run_id" --nonce "$nonce" --sequence "$sequence" --issued-at "$issued_at" --expires-at "$expires_at" --min-installer "$min_installer" --platform "$platform" --arch "$arch")
  for spec in ${provider_sources[@]+"${provider_sources[@]}"}; do args+=(--provider-source "$spec"); done
  [[ -z "$policy_bundle" ]] || args+=(--provider-policy-bundle "$policy_bundle" --provider-policy-trust "$policy_trust")
  [[ -z "$catalog_input" ]] || args+=(--provider-catalog-input "$catalog_input" --provider-catalog-output "$catalog_output")
  "$STAGE_SCRIPT" "${args[@]}"; bundle="$output_dir/$release_id"
  echo "deployment_state=unsigned"; echo "activation=false"; echo "bundle=$bundle"
  if [[ -d "$bundle/stage/providers" ]]; then echo "providers=inactive (not activated)"; else echo "providers=base-only"; fi
  exit 0
fi

bundle= release_digest= signature= trust_bundle= bootstrap_helper= bootstrap_digest= readiness_digest= recover=false
while (($#)); do
  case "$1" in
    --bundle) bundle=${2:?missing value}; shift 2;; --release-digest) release_digest=${2:?missing value}; shift 2;;
    --signature) signature=${2:?missing value}; shift 2;; --trust-bundle) trust_bundle=${2:?missing value}; shift 2;;
    --bootstrap-helper) bootstrap_helper=${2:?missing value}; shift 2;; --bootstrap-helper-sha256) bootstrap_digest=${2:?missing value}; shift 2;;
    --recover-partial-install) recover=true; shift;; --readiness-sha256) readiness_digest=${2:?missing value}; shift 2;;
    -h|--help) usage; exit 0;; *) die "unknown apply option: $1";;
  esac
done
[[ -n "$bundle" && -n "$release_digest" && -n "$signature" && -n "$trust_bundle" && -n "$bootstrap_helper" && -n "$bootstrap_digest" ]] || die "apply requires all release and bootstrap authority inputs"
is_sha256 "$release_digest" || die "release digest must be lowercase SHA-256"; is_sha256 "$bootstrap_digest" || die "bootstrap digest must be lowercase SHA-256"
if $recover; then is_sha256 "$readiness_digest" || die "recovery requires --readiness-sha256"; fi
for path in "$bundle" "$signature" "$trust_bundle" "$bootstrap_helper"; do is_abs "$path" || die "apply paths must be absolute"; done
[[ -f "$TRUST_ANCHOR" && ! -L "$TRUST_ANCHOR" ]] || die "fixed release trust anchor is absent; run bootstrap-trust first"
if $recover; then
  [[ -f "$TRUST_ANCHOR" && ! -L "$TRUST_ANCHOR" ]] || die "partial recovery is unsupported until the fixed release trust anchor is bootstrapped"
fi
metadata=$(python3 - "$bundle" "$signature" "$trust_bundle" "$bootstrap_helper" "$release_digest" <<'PY'
import json, os, pathlib, sys
bundle, signature, trust, helper = map(pathlib.Path, sys.argv[1:5]); supplied_digest=sys.argv[5]
def check(p, kind):
    if not p.is_absolute(): raise SystemExit("relative path")
    if ".." in p.parts: raise SystemExit("parent traversal is ambiguous")
    cur = pathlib.Path(p.anchor)
    for part in p.parts[1:]:
        cur /= part
        if cur.is_symlink(): raise SystemExit(f"symlink path component: {p}")
    if not p.exists() or (kind == "file" and not p.is_file()) or (kind == "dir" and not p.is_dir()): raise SystemExit(f"unsafe or missing path: {p}")
check(bundle,"dir"); check(signature,"file"); check(trust,"file"); check(helper,"file")
bundle=bundle.resolve(strict=True); signature=signature.resolve(strict=True); trust=trust.resolve(strict=True); helper=helper.resolve(strict=True)
release, stage = bundle/"release", bundle/"stage"; check(release,"dir"); check(stage,"dir")
request, manifest = release/"openduck.release-signing-request.v1.json", release/"openduck.release-manifest.v2.json"
check(request,"file"); check(manifest,"file")
if helper == bundle or str(helper).startswith(str(bundle)+os.sep): raise SystemExit("bootstrap helper may not be inside bundle")
fixed=pathlib.Path('/Library/Application Support/OpenDuck').resolve(strict=False)
if helper == fixed or str(helper).startswith(str(fixed)+os.sep): raise SystemExit("bootstrap helper may not be inside fixed install root")
if str(signature).startswith(str(bundle)+os.sep) or str(trust).startswith(str(bundle)+os.sep): raise SystemExit("signature and trust must be outside bundle")
if signature == trust or signature == request or trust == request: raise SystemExit("authority paths overlap")
with request.open(encoding="utf-8") as f: data=json.load(f)
required=("release_id","release_version","run_id","activation","operation","expires_at")
if any(not isinstance(data.get(k),str) or not data[k] for k in required): raise SystemExit("signing request metadata incomplete")
if data["operation"] != "deploy" or data["activation"] != "false": raise SystemExit("only inactive deploy envelopes are supported")
if data.get("release_digest") != supplied_digest: raise SystemExit("release digest does not match signing request")
print("\t".join((data["release_id"],data["release_version"],data["run_id"],str(request.resolve()),str(manifest.resolve()),str(stage.resolve()),str(bundle))))
PY
) || die "unsafe or incomplete apply inputs"
IFS=$'\t' read -r release_id release_version run_id release_request release_manifest staged_source bundle <<<"$metadata"
now=$(python3 - <<'PY'
import datetime
print(datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat().replace('+00:00','Z'))
PY
)
envelope="$bundle/release/openduck.release-envelope.v1.json"; [[ ! -L "$envelope" ]] || die "envelope may not be a symlink"
cd "$ROOT_DIR"
if [[ -e "$envelope" ]]; then
  verify_dir=$(mktemp -d "$bundle/release/.verify-envelope.XXXXXX")
  verify_envelope="$verify_dir/openduck.release-envelope.v1.json"
  trap 'rm -rf "$verify_dir"' EXIT
  echo "strictly verifying existing release envelope"
  "$GO_BIN" run ./cmd/openduck-release-packager finalize --signing-request "$release_request" --signature "$signature" --trust-bundle "$trust_bundle" --envelope-out "$verify_envelope" --now "$now"
  cmp -s "$verify_envelope" "$envelope" || die "existing envelope does not match exact signing inputs"
  rm -rf "$verify_dir"; trap - EXIT
else
  echo "finalizing external release signature"
  "$GO_BIN" run ./cmd/openduck-release-packager finalize --signing-request "$release_request" --signature "$signature" --trust-bundle "$trust_bundle" --envelope-out "$envelope" --now "$now"
fi
extra=(-e "release_id=$release_id" -e "release_version=$release_version" -e "release_digest=$release_digest" -e "release_run_id=$run_id" -e "release_activation=false" -e "release_envelope=$envelope" -e "release_manifest=$release_manifest" -e "release_trust_bundle=$trust_bundle" -e "staged_source=$staged_source" -e "openduck_bootstrap_helper_path=$bootstrap_helper" -e "openduck_bootstrap_helper_sha256=$bootstrap_digest")
if $recover; then
  recovery_extra=(-e openduck_recovery_confirm=quarantine-partial-install-v1 -e openduck_recovery_bootstrap_helper_path="$bootstrap_helper" -e openduck_recovery_bootstrap_helper_sha256="$bootstrap_digest" -e openduck_recovery_readiness_sha256="$readiness_digest")
  echo "recovery check (no mutation)"; "$ANSIBLE_PLAYBOOK" --check -i "$INVENTORY" "$RECOVERY_PLAYBOOK" "${recovery_extra[@]}"
  echo "recovery apply"; "$ANSIBLE_PLAYBOOK" --ask-become-pass -i "$INVENTORY" "$RECOVERY_PLAYBOOK" -e openduck_recovery_apply=true "${recovery_extra[@]}"
fi
echo "deployment check (no mutation)"; "$ANSIBLE_PLAYBOOK" --check --ask-become-pass -i "$INVENTORY" "$PLAYBOOK" "${extra[@]}"
echo "deployment apply"; "$ANSIBLE_PLAYBOOK" --ask-become-pass -i "$INVENTORY" "$PLAYBOOK" "${extra[@]}"
echo "deployment_state=applied"; echo "activation=false"
