#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P); script="$ROOT_DIR/scripts/deploy-macos.sh"
role_defaults="$ROOT_DIR/deploy/ansible/roles/release_trust_anchor/defaults/main.yml"
for key in release_trust_anchor_action release_trust_anchor_source release_trust_anchor_sha256 release_trust_anchor_bootstrap_helper_path release_trust_anchor_bootstrap_helper_sha256; do
  grep -q "^$key:" "$role_defaults" || { echo "missing role default: $key" >&2; exit 1; }
  grep -q -- "$key=" "$script" || { echo "wrapper drift: $key" >&2; exit 1; }
done
tmp=$(mktemp -d "${TMPDIR:-/tmp}/openduck-deploy-test.XXXXXX"); tmp=$(cd "$tmp" && pwd -P); trap 'rm -rf "$tmp"' EXIT

stage="$tmp/fake-stage.sh"
printf '%s\n' '#!/usr/bin/env bash' 'set -eu' 'printf "%s\n" "$@" > "$FAKE_ARGS"' 'mkdir -p "$FAKE_BUNDLE/stage/providers" "$FAKE_BUNDLE/release"' 'printf "%s" "{\"release_id\":\"release-test\",\"release_version\":\"1.0.0\",\"run_id\":\"aaaaaaaa-1111\",\"activation\":\"false\",\"operation\":\"deploy\",\"release_digest\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"expires_at\":\"2099-01-01T00:00:00Z\"}" > "$FAKE_BUNDLE/release/openduck.release-signing-request.v1.json"' 'printf "%s" "{}" > "$FAKE_BUNDLE/release/openduck.release-manifest.v2.json"' > "$stage"; chmod 700 "$stage"
sed "s#STAGE_SCRIPT=\"\${STAGE_SCRIPT_OVERRIDE:-\$ROOT_DIR/scripts/stage-release.sh}\"#STAGE_SCRIPT=\"\$STAGE_SCRIPT_OVERRIDE\"#" "$script" > "$tmp/prepare.sh"; chmod 700 "$tmp/prepare.sh"
FAKE_BUNDLE="$tmp/out/release" FAKE_ARGS="$tmp/stage-args" STAGE_SCRIPT_OVERRIDE="$stage" "$tmp/prepare.sh" prepare --output-dir "$tmp/out" --release-id release-test --version 1.0.0 --key-id test-key --sequence 1 --min-installer 1.0.0 >/dev/null
grep -qx -- '--release-id' "$tmp/stage-args"

bundle="$tmp/bundle"; mkdir -p "$bundle/stage" "$bundle/release"; helper="$tmp/pretrusted-helper"; printf x > "$helper"; chmod 700 "$helper"
fixed_root="$tmp/fixed-root"; mkdir -p "$fixed_root"; trust_anchor="$tmp/fixed-root.release-trust.v1.json"; printf '{}' > "$trust_anchor"
local_dir="$tmp/local-overlay"; mkdir -p "$local_dir"; printf '{}' > "$local_dir/config.json"; printf '{}' > "$local_dir/local-overlay.json"; chmod 600 "$local_dir/config.json" "$local_dir/local-overlay.json"
printf '%s' '{"release_id":"release-test","release_version":"1.0.0","run_id":"aaaaaaaa-1111","activation":"false","operation":"deploy","release_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","expires_at":"2099-01-01T00:00:00Z"}' > "$bundle/release/openduck.release-signing-request.v1.json"
printf '{}' > "$bundle/release/openduck.release-manifest.v2.json"; printf '{}' > "$tmp/signature.json"
# Canonical member order (schema, keys, revoked) is part of the trust contract.
printf '%s' '{"schema":"openduck.release-trust.v1","keys":{"test-key":"7792ec65233f388b4063dc00bdd12464704de511fda32fb30183b4a412e1da13"},"revoked":[]}' > "$tmp/trust.json"
go_fake="$tmp/go"; ansible_fake="$tmp/ansible"; log="$tmp/ansible.log"
printf '%s\n' '#!/usr/bin/env bash' 'set -eu' 'out=' 'previous=' 'for arg in "$@"; do [[ "$previous" == --envelope-out ]] && out="$arg"; previous="$arg"; done' '[[ -n "$out" ]]' '[[ "${FAKE_GO_FAIL:-0}" == 1 ]] && exit 17' 'printf "{}" > "$out"' > "$go_fake"; chmod 700 "$go_fake"
printf '%s\n' '#!/usr/bin/env bash' 'set -eu' 'printf "%s\n" "$*" >> "$FAKE_ANSIBLE_LOG"' 'if [[ "${FAKE_ANSIBLE_FAIL:-0}" == 1 ]]; then exit 19; fi' > "$ansible_fake"; chmod 700 "$ansible_fake"
FAKE_ANSIBLE_LOG="$log" ANSIBLE_PLAYBOOK_OVERRIDE="$ansible_fake" "$script" bootstrap-trust --acknowledge-trust-bootstrap --trust-bundle "$tmp/trust.json" --trust-sha256 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa --bootstrap-helper "$helper" --bootstrap-helper-sha256 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa >/dev/null
[[ $(wc -l < "$log" | tr -d ' ') == 1 ]]; [[ $(cat "$log") == *bootstrap-release-trust.yml* && $(cat "$log") == *release_trust_anchor_sha256=aaaaaaaa* && $(cat "$log") == *ask-become-pass* ]]
: > "$log"
if FAKE_ANSIBLE_LOG="$log" ANSIBLE_PLAYBOOK_OVERRIDE="$ansible_fake" "$script" bootstrap-trust --trust-bundle "$tmp/trust.json" --trust-sha256 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa --bootstrap-helper "$helper" --bootstrap-helper-sha256 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa >/dev/null 2>&1; then exit 1; fi
# A non-canonical trust bundle must be refused offline, before any privileged task.
printf '%s' '{"keys":{"test-key":"7792ec65233f388b4063dc00bdd12464704de511fda32fb30183b4a412e1da13"},"revoked":[],"schema":"openduck.release-trust.v1"}' > "$tmp/trust-alphabetical.json"
: > "$log"
if FAKE_ANSIBLE_LOG="$log" ANSIBLE_PLAYBOOK_OVERRIDE="$ansible_fake" "$script" bootstrap-trust --acknowledge-trust-bootstrap --trust-bundle "$tmp/trust-alphabetical.json" --trust-sha256 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa --bootstrap-helper "$helper" --bootstrap-helper-sha256 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa >/dev/null 2>&1; then exit 1; fi
[[ ! -s "$log" ]]
: > "$log"
args=(apply --bundle "$bundle" --release-digest aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa --signature "$tmp/signature.json" --trust-bundle "$tmp/trust.json" --bootstrap-helper "$helper" --bootstrap-helper-sha256 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa --require-local-openclaw-config --recover-partial-install --readiness-sha256 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa)
FAKE_ANSIBLE_LOG="$log" GO_BIN_OVERRIDE="$go_fake" ANSIBLE_PLAYBOOK_OVERRIDE="$ansible_fake" OPENDUCK_FIXED_ROOT_OVERRIDE="$fixed_root" OPENDUCK_TRUST_ANCHOR_OVERRIDE="$trust_anchor" OPENDUCK_LOCAL_CONFIG_DIR_OVERRIDE="$local_dir" "$script" "${args[@]}"
[[ $(wc -l < "$log" | tr -d ' ') == 4 ]]; [[ $(sed -n '1p' "$log") == --check* ]]; [[ $(sed -n '2p' "$log") == --ask-become-pass* ]]; [[ $(sed -n '3p' "$log") == --check*ask-become-pass* ]]; [[ $(sed -n '4p' "$log") == --ask-become-pass* ]]
[[ $(grep -c -- '--ask-become-pass' "$log") == 3 ]]; [[ $(grep -c sudo "$log") == 0 ]]
rm "$local_dir/config.json"
if OPENDUCK_LOCAL_CONFIG_DIR_OVERRIDE="$local_dir" OPENDUCK_TRUST_ANCHOR_OVERRIDE="$trust_anchor" "$script" "${args[@]}" >/dev/null 2>&1; then exit 1; fi
printf '{bad' > "$local_dir/config.json"; chmod 600 "$local_dir/config.json"
if OPENDUCK_LOCAL_CONFIG_DIR_OVERRIDE="$local_dir" OPENDUCK_TRUST_ANCHOR_OVERRIDE="$trust_anchor" "$script" "${args[@]}" >/dev/null 2>&1; then exit 1; fi
printf '{}' > "$local_dir/config.json"; chmod 644 "$local_dir/config.json"
if OPENDUCK_LOCAL_CONFIG_DIR_OVERRIDE="$local_dir" OPENDUCK_TRUST_ANCHOR_OVERRIDE="$trust_anchor" "$script" "${args[@]}" >/dev/null 2>&1; then exit 1; fi
chmod 600 "$local_dir/config.json"; rm "$local_dir/local-overlay.json"; ln -s config.json "$local_dir/local-overlay.json"
if OPENDUCK_LOCAL_CONFIG_DIR_OVERRIDE="$local_dir" OPENDUCK_TRUST_ANCHOR_OVERRIDE="$trust_anchor" "$script" "${args[@]}" >/dev/null 2>&1; then exit 1; fi

printf wrong > "$bundle/release/openduck.release-envelope.v1.json"
if FAKE_ANSIBLE_LOG="$tmp/no-log" GO_BIN_OVERRIDE="$go_fake" ANSIBLE_PLAYBOOK_OVERRIDE="$ansible_fake" OPENDUCK_FIXED_ROOT_OVERRIDE="$fixed_root" OPENDUCK_TRUST_ANCHOR_OVERRIDE="$trust_anchor" "$script" "${args[@]}" >/dev/null 2>&1; then exit 1; fi
[[ ! -e "$tmp/no-log" ]]
rm -f "$bundle/release/openduck.release-envelope.v1.json"
if FAKE_GO_FAIL=1 FAKE_ANSIBLE_LOG="$tmp/no-log2" GO_BIN_OVERRIDE="$go_fake" ANSIBLE_PLAYBOOK_OVERRIDE="$ansible_fake" OPENDUCK_FIXED_ROOT_OVERRIDE="$fixed_root" OPENDUCK_TRUST_ANCHOR_OVERRIDE="$trust_anchor" "$script" "${args[@]}" >/dev/null 2>&1; then exit 1; fi
[[ ! -e "$tmp/no-log2" ]]
if "$script" apply --bundle "$bundle/../bundle" --release-digest bad --signature "$tmp/signature.json" --trust-bundle "$tmp/trust.json" --bootstrap-helper "$helper" --bootstrap-helper-sha256 bad >/dev/null 2>&1; then exit 1; fi
if "$script" apply --bundle "$bundle" --release-digest aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa --signature "$tmp/signature.json" --trust-bundle "$tmp/trust.json" --bootstrap-helper "$bundle/stage/nope" --bootstrap-helper-sha256 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa >/dev/null 2>&1; then exit 1; fi
echo 'test-deploy-macos: passed'
