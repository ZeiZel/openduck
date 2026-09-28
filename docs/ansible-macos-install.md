# Installing the macOS boundary with Ansible

`deploy/ansible/site.yml` is the only supported mutating entry point. A signed
ReleaseEnvelope v1 authorizes exactly one `--deploy` transaction and binds its
ManifestV2, release identity, run ID, platform, artifact set, nonce and
`activation=true|false` intent. Ansible projects inputs but the fixed trusted
installer repeats cryptographic admission before mutation.

Local prerequisites: Go 1.26, pinned Bun 1.3.14, Ansible, and Node >= 22.19.0
on `PATH`. The plugin suites run on the `node:test` runner and Bun silently
substitutes itself for a missing `node`, so `scripts/require-node.sh`
preflights this and `prepare` stops with a legible error instead of a
misrouted test failure.

The convenience wrapper `bun run deploy:macos` creates fresh unsigned bundles
and then performs the external-signature finalization followed by Ansible
check/apply. Prepare a base-only release with optional provider source groups:

```sh
bun run deploy:macos -- prepare \
  --output-dir "$PWD/.openduck/prepared-release" \
  --release-id "openduck-$(date -u +%Y%m%d-%H%M%S)" \
  --version 0.1.0 --key-id release-key --sequence 1 --min-installer 1.0.0 \
  --valid-for-hours 24
```

Send the printed signing request to the approved external Ed25519 signer. The
signer is deliberately not part of this repository: it holds the private key
and must stay outside the tree that builds releases. It has to return an
`openduck.release-signature.v1` document whose `payload_digest` is the SHA-256
of the request's base64-decoded `unsigned_payload_b64` and whose `signature` is
the lowercase hex Ed25519 signature over those same payload bytes, plus an
`openduck.release-trust.v1` bundle mapping the `key_id` to the lowercase hex
public key.

The trust bundle is compared byte for byte, not field by field. The anchor
ceremony re-encodes the decoded `TrustBundle` struct and requires the supplied
bytes to equal that encoding exactly, so the member order is part of the
contract: `schema`, then `keys`, then `revoked` (an empty array, never `null`),
with no whitespace. A signer that serializes from a hash map will emit
`keys`, `revoked`, `schema` in alphabetical order and is rejected by
`decodeStrictTrust` before any anchor is written — and, because the invoking
task runs under `no_log`, the failure surfaces only as a non-zero helper exit.
The exact accepted form is:

```json
{"schema":"openduck.release-trust.v1","keys":{"release-key":"64_lowercase_hex_public_key"},"revoked":[]}
```

Apply requires the exact lowercase release digest, signature and trust files,
plus an independently trusted bootstrap helper and its digest:

Before the first apply, bootstrap the fixed root-owned trust anchor exactly
once. This is a separate owner-confirmed operation; apply and partial recovery
never initialize or overwrite it:

```sh
bun run deploy:macos -- bootstrap-trust --acknowledge-trust-bootstrap \
  --trust-bundle /absolute/path/openduck.release-trust.v1.json \
  --trust-sha256 64_lowercase_hex_trust_digest \
  --bootstrap-helper /absolute/path/pretrusted/openduck-installer \
  --bootstrap-helper-sha256 64_lowercase_hex_helper_digest
```

The complete sequence is `prepare -> external sign -> bootstrap-trust once ->
apply`. The fixed anchor at `/Library/Application Support/OpenDuck.release-trust.v1.json`
is deliberately outside the quarantined install root and must already exist
for ordinary apply and partial recovery; recovery is rejected with an explicit
gate when it is absent.

```sh
bun run deploy:macos -- apply \
  --bundle /absolute/path/.openduck/prepared-release/openduck-YYYYMMDD-HHMMSS \
  --release-digest 64_lowercase_hex_release_digest \
  --signature /absolute/path/openduck.release-signature.v1.json \
  --trust-bundle /absolute/path/openduck.release-trust.v1.json \
  --bootstrap-helper /absolute/path/pretrusted/openduck-installer \
  --bootstrap-helper-sha256 64_lowercase_hex_helper_digest
```

For the known interrupted bootstrap, add `--recover-partial-install
--readiness-sha256 64_lowercase_hex`. Recovery check runs first; a failed
check or recovery stops before later mutations. The wrapper rejects relative
or symlink paths, staged helpers as authority, mismatched release digests,
pre-existing envelopes, expired requests, and activation requests. It never
reads credentials or invokes sudo; Ansible prompts for the become password.

Boundary deployment does not materialize local OpenClaw/domain configuration.
Those files remain manually provisioned ignored inputs. If desired, add
`--require-local-openclaw-config`; the wrapper then checks (without printing or
copying) owner-private strict JSON files `deploy/openclaw/config.json` and
`deploy/openclaw/local-overlay.json` before finalization.

For non-mutating delivery validation, run `scripts/verify-ansible-p5.sh --ci`
from the repository root. It lint-checks the tree and runs `--syntax-check`
against `site.yml`, `rollback.yml`, and `diagnose.yml` using localhost and
placeholder paths only. `--doctor` reports missing local tools; an ordinary
incomplete local run exits `3` rather than reporting success.

The signed run ID is not a temporary-path name. Each real site or rollback
invocation creates its own random root-owned `0700` handoff below
`/private/var/run`; stale or concurrent runs cannot share helper or error-JSON
paths. Cleanup is reported separately and never replaces a primary failure.

```sh
cd deploy/ansible
ansible-playbook --ask-become-pass -i inventory/localhost.yml site.yml \
  -e release_id=release-20260826 -e release_version=1.2.3 \
  -e release_digest=SHA256 -e release_run_id=0123456789abcdef \
  -e release_activation=false -e release_envelope=/absolute/path/envelope.json \
  -e release_manifest=/absolute/path/release.manifest.v2.json \
  -e release_trust_bundle=/absolute/path/trust.json -e staged_source=/absolute/path/stage \
  -e openduck_bootstrap_helper_path=/absolute/path/pretrusted/openduck-installer \
  -e openduck_bootstrap_helper_sha256=INDEPENDENT_SHA256
```

On upgrade, authority is only the installed root:wheel, 0700, single-link
helper whose digest is bound to root-owned `configured.release` and installed
ManifestV2. A fresh bootstrap uses an independently acquired helper digest;
staged helpers are never executable authority. Legacy install/stop/rollback
scripts are fail-closed migration stubs.

`--check` does not consume a nonce or mutate install state, PF, launchd or
services. It still requires become credentials to read the root:wheel `0700`
trusted helper and create the random guarded handoff; PlanV2 itself runs
unprivileged after ownership transfer. `activation=false` configures and verifies the sealed release but
does not require live readiness. Rollback requires a separate signed rollback
envelope and fresh nonce. Journal/checkpoint gates remain installer-owned;
Ansible neither repairs nor bypasses them. Standalone `diagnose.yml` is
read-only and executes readiness only after a root:wheel `0700`, single-link,
non-symlink installed helper is bound to the root-owned configured-release
ManifestV2 digest; otherwise it emits only a bounded unavailable posture.
