#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
CI_MODE=0; DOCTOR=0
case "${1:-}" in --ci) CI_MODE=1;; --doctor) DOCTOR=1;; "") ;; *) echo "usage: $0 [--ci|--doctor]" >&2; exit 2;; esac
need_tool() { command -v "$1" >/dev/null 2>&1; }
run_syntax_check() {
  playbook=$1
  shift
  ansible-playbook --syntax-check --inventory localhost, --connection local "$playbook" "$@"
}
missing=""
for tool in python3 ansible-playbook ansible-lint yamllint go rg; do
  if need_tool "$tool"; then printf 'tool %-18s ok\n' "$tool"; else printf 'tool %-18s missing\n' "$tool"; missing="$missing $tool"; fi
done
if [ "$DOCTOR" -eq 1 ]; then
  if [ -n "$missing" ]; then printf 'doctor: missing required tools:%s\n' "$missing"; else echo 'doctor: all required tools available'; fi
  exit 0
fi
if [ -n "$missing" ]; then
  if [ "$CI_MODE" -eq 1 ]; then printf 'ci: missing required tools:%s\n' "$missing" >&2; exit 1; fi
  printf 'local: verification incomplete; missing required tools (run --doctor for details):%s\n' "$missing" >&2
  exit 3
fi
cd "$ROOT"
export PYTHONPYCACHEPREFIX="${TMPDIR:-/tmp}/openduck-p5-pycache"
P5_TMP=$(mktemp -d "${TMPDIR:-/tmp}/openduck-p5.XXXXXX")
cleanup() {
  if [ -n "${P5_TMP:-}" ] && [ "$P5_TMP" != / ] && [ -d "$P5_TMP" ]; then
    find "$P5_TMP" -depth -delete
  fi
}
trap cleanup EXIT HUP INT TERM
export ANSIBLE_LOCAL_TEMP="$P5_TMP/ansible-local"
echo 'yaml: parse'
python3 - <<'PY'
from pathlib import Path
import yaml
for path in sorted(Path("deploy/ansible").rglob("*.y*ml")):
    yaml.safe_load(path.read_text())
PY
echo 'yaml: lint'; yamllint deploy/ansible
echo 'ansible: lint'; ansible-lint deploy/ansible
echo 'ansible: syntax checks'
cd "$ROOT/deploy/ansible"
run_syntax_check site.yml \
  -e release_id=release-p5-syntax \
  -e release_version=0.0.0 \
  -e release_digest=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
  -e release_run_id=aaaaaaaa-1111 \
  -e release_activation=false \
  -e release_envelope=/private/tmp/openduck-p5-envelope.json \
  -e release_manifest=/private/tmp/openduck-p5-manifest.json \
  -e release_trust_bundle=/private/tmp/openduck-p5-trust.json \
  -e staged_source=/private/tmp/openduck-p5-stage \
  -e openduck_bootstrap_helper_path=/private/tmp/openduck-p5-installer \
  -e openduck_bootstrap_helper_sha256=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
run_syntax_check rollback.yml \
  -e release_id=release-p5-syntax \
  -e release_version=0.0.0 \
  -e release_digest=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
  -e release_run_id=aaaaaaaa-1111 \
  -e release_activation=false \
  -e release_envelope=/private/tmp/openduck-p5-envelope.json \
  -e release_manifest=/private/tmp/openduck-p5-manifest.json \
  -e release_trust_bundle=/private/tmp/openduck-p5-trust.json \
  -e staged_source=/private/tmp/openduck-p5-stage \
  -e openduck_bootstrap_helper_path=/private/tmp/openduck-p5-installer \
  -e openduck_bootstrap_helper_sha256=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
run_syntax_check diagnose.yml
run_syntax_check recover-partial-install.yml \
  -e openduck_recovery_confirm=quarantine-partial-install-v1 \
  -e openduck_recovery_bootstrap_helper_path=/private/tmp/openduck-p5-installer \
  -e openduck_recovery_bootstrap_helper_sha256=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb \
  -e openduck_recovery_readiness_sha256=cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
cd "$ROOT"
echo 'python: tests'; python3 -m unittest discover -s deploy/ansible/tests -p 'test*.py'
echo 'go: macOS release/install tests and vet'
GOCACHE="${TMPDIR:-/tmp}/openduck-p5-go-cache" go test ./internal/macosinstall ./internal/macosrelease ./cmd/openduck-installer
GOCACHE="${TMPDIR:-/tmp}/openduck-p5-go-cache" go vet ./internal/macosinstall ./internal/macosrelease ./cmd/openduck-installer
echo 'ci: VM matrix contract'
python3 - <<'PY'
import json
from pathlib import Path
matrix = json.loads(Path("deploy/ansible/ci/macos-vm-matrix.json").read_text())
assert matrix["platform"] == "macos"
assert {row["name"] for row in matrix["scenarios"]} == {"fresh", "idempotent", "upgrade", "injected_failure", "rollback", "retry", "concurrent", "two_daemon_inactive_contract", "provider_attestor_restart_substitution_rollback"}
assert matrix["intel"]["status"] == "decision_required"
for row in matrix["scenarios"]:
    assert row["artifacts"] and row["receipt"]
PY
echo 'security: secret canary scan'
if rg -l --hidden --glob '!.git/**' --glob '!third_party/**' --glob '!deploy/ansible/tests/fixtures/**' '(BEGIN (RSA|EC|OPENSSH|PRIVATE) KEY|AKIA[0-9A-Z]{16}|sk-[A-Za-z0-9]{20,}|xox[baprs]-[A-Za-z0-9-]{20,})' .; then
  echo 'secret canary: possible credential material found (paths only above)' >&2; exit 1
fi
echo 'secret canary: clean'
