# OpenDuck macOS Ansible deployment

This is the primary local device-setup entry point. Production deployment is
one signed, nonce-consuming transaction: Ansible performs unprivileged input
projection and then invokes exactly one trusted installer operation,
`--deploy --activation=true|false`. The installer repeats strict signature,
artifact, platform, root, run-id, and intent admission before it obtains the
deployment lock or opens the fixed root.

The caller must provide a `ReleaseEnvelope.v1` whose signed intent is exactly
`operation=deploy`, whose `run_id` is the supplied safe hexadecimal run ID,
and whose `activation` value matches `release_activation`. The envelope,
manifest, and trust bundle are input paths only; Ansible does not treat their
contents or Jinja facts as cryptographic authority. The fixed durable nonce
route is never caller-configurable.

The signed `run_id` is an audit/admission binding, not a temporary-path name.
Each actual apply or rollback invocation independently allocates a random
root-owned `0700` handoff directory below `/private/var/run`; retries using
the same envelope do not reuse an Ansible helper/error path. Every helper and
designated error JSON file is restricted to that exact bounded directory, and
cleanup is secondary to a recorded primary transaction failure.

Before a privileged run, validate the Ansible delivery harness without
executing any tasks:

```sh
scripts/verify-ansible-p5.sh --doctor  # reports required local tools
scripts/verify-ansible-p5.sh --ci      # runs lint, tests and syntax checks
```

The normal harness invocation also fails with exit status `3` when a required
tool is missing, so a local incomplete verification cannot appear successful.
Its syntax checks use only the localhost inventory and placeholder paths; they
do not run tasks, become, sudo, network, login, or provider operations.

Ansible never executes or copies `staged_source/bin/openduck-installer` as an
executable. On upgrade, the sole helper authority is the fixed installed
`.openduck-installer`; it must be a root:wheel, regular, non-symlink,
single-link `0700` file beneath trusted fixed-root ancestry and its digest must
match the root-owned installed admitted ManifestV2. On a fresh install, supply
both bootstrap inputs below: the helper path and SHA-256 are out-of-band
operator authority, and the digest must not be derived from the release
manifest or staged projection. Bootstrap paths under either `staged_source` or
the fixed install root are rejected. If any fixed install root already exists,
bootstrap is refused: a missing or malformed `configured.release`/installed
ManifestV2 is an upgrade repair failure, never a fallback to bootstrap.

```sh
cd deploy/ansible
ansible-playbook --ask-become-pass -i inventory/localhost.yml site.yml \
  -e release_id=release-20260826 \
  -e release_version=1.2.3 \
  -e release_digest=SHA256 \
  -e release_run_id=0123456789abcdef \
  -e release_activation=false \
  -e release_envelope=/absolute/path/release-envelope.json \
  -e release_manifest=/absolute/path/release.manifest.v2.json \
  -e release_trust_bundle=/absolute/path/release-trust.json \
  -e staged_source=/absolute/path/to/release-stage \
  -e openduck_bootstrap_helper_path=/absolute/path/to/pretrusted/openduck-installer \
  -e openduck_bootstrap_helper_sha256=64_lowercase_hex_from_independent_authority
```

`release.manifest.v2` contains a bounded typed artifact set, not a fixed list
of eleven names. Each artifact has a unique safe relative target, type,
platform, architecture, version, and SHA-256. The stage role rejects unknown
fields, links, hardlinks, unsafe modes, traversal, duplicate paths, and digest
mismatches before the privileged helper is invoked; authoritative admission is
still performed by the installer over a sealed snapshot.

Use `--check` for projection and planning. It performs no release nonce
consumption, root normalization, job stop, PF, launchd, or activation. It does
require become credentials: root must read the root:wheel `0700` trusted helper
and create a random `0700` handoff under `/private/var/run`. Root seals and
hashes it, transfers the exact directory and helper to the non-root invoking
user, then the read-only plan executes unprivileged:

```sh
ansible-playbook --check --ask-become-pass -i inventory/localhost.yml site.yml \
  -e release_id=release-20260826 \
  -e release_version=1.2.3 \
  -e release_digest=SHA256 \
  -e release_run_id=0123456789abcdef \
  -e release_activation=false \
  -e release_envelope=/absolute/path/release-envelope.json \
  -e release_manifest=/absolute/path/release.manifest.v2.json \
  -e release_trust_bundle=/absolute/path/release-trust.json \
  -e staged_source=/absolute/path/to/release-stage \
  -e openduck_bootstrap_helper_path=/absolute/path/to/pretrusted/openduck-installer \
  -e openduck_bootstrap_helper_sha256=64_lowercase_hex_from_independent_authority
```

The resulting `openduck.deployment-plan.v2` is a closed canonical report: it
binds the admitted release, run ID, platform, architecture and activation
intent; its ordered install, rollback and cleanup operations use only safe
relative source/target paths, typed artifact digests, fixed modes and owners.
Ansible validates this exact schema against the stage projection. It does not
accept a generic JSON object, and planning does not acquire the deployment
lock, consume a nonce, or materialize a snapshot.

Provider packages are deliberately staged under `providers/inactive/<name>`.
Each signed group contains a daemon binary, runtime descriptor and canonical
`topology.json` that declares only expected future identities and
`activation_state=inactive`, `provisioned=false`. Base deployment creates no
provider principal, channel, listener, LaunchDaemon or egress authority.
Install, rollback and cleanup plans contain the same exact inactive provider
targets, so a partial provider revision cannot be reported as coherent.

`operational_ready` is never inferred from release markers. The readiness
contract requires fresh bounded evidence for core activation, the exact live
daemon job/PID/executable digest, authenticated channel health, current
account and canary references, provider revision compatibility and persisted
session recovery. Missing, stale or substituted evidence is projected only as
an allowlisted reason code and leaves the gate `unavailable`; diagnostics do
not retain command output, account values or provider responses.

The current readiness binary intentionally has no operational provider
attestor. `launchctl` PID plus `ps` path plus a hash of the installed file is
not accepted because it cannot bind the executing image across exec/restart,
the effective UID/GID, or the authenticated channel peer credential. Until a
privileged macOS attestor can supply one atomic observation binding job label,
PID, start identity, executing CDHash (or equivalent authoritative image
identity), service credentials and channel peer to the signed topology and
release evidence, provider operational readiness remains `unavailable`.

The native MCP path uses a host-launched, provider-specific stdio shim. The
Controller never launches the official provider host and the shim receives no
session binding, bearer, endpoint, credential, URL or provider command in
argv/environment. It connects only to the fixed root-owned Controller Unix
socket. The server derives PID with `LOCAL_PEERPID`, UID/GID with
`LOCAL_PEERCRED`, CDHash/start identity/parent PID from the Darwin kernel, and
accepts the shim only when its direct provider-host parent matches a fresh
server-side registration for the durable session. Restart, PID reuse, parent
substitution, code substitution, expiry and rollback/revocation all fail
closed. Until that registered association exists, the installed attestor and
readiness helper report unavailable.

Rollback is a separate owner action. It requires a fresh envelope and nonce
signed with `operation=rollback` and `activation=false`; a deploy envelope is
never reused for rollback. Run `rollback.yml` with the same explicit release
inputs, replacing only the envelope with that rollback envelope. A failed
deployment records that separate admission is required rather than attempting
to replay its deploy nonce automatically.

## Explicit partial-bootstrap quarantine

`recover-partial-install.yml` is the sole recovery route for the one observed
interrupted bootstrap shape. It is not included by `site.yml`, does not consume
a release nonce, and never removes files. `--check` only validates the supplied
authority and reports `check_only`; it does not copy or execute a helper. The
non-check operation copies that independently pretrusted helper to a random
root-owned handoff, re-hashes it, then asks it to atomically rename the fixed
root to a root-owned sibling quarantine. Before rename, the helper atomically
writes and fsyncs one root-owned receipt under the trusted Application Support
parent. That receipt binds the fixed source name, source filesystem device and
inode, the CSPRNG quarantine leaf, and both independent authority digests.
After rename it fsyncs the parent, verifies that the destination has the exact
recorded device/inode, and atomically commits the receipt as `quarantined`.
Only after a successful `quarantined` result may you run a normal fresh
`site.yml` deployment with a new signed envelope.

The quarantine move uses a no-follow descriptor for the already trusted parent
and macOS `renameatx_np` with `RENAME_EXCL`, `RENAME_NOFOLLOW_ANY`, and
`RENAME_RESOLVE_BENEATH`. The helper compares that open descriptor's exact
device, inode, owner, group, and mode with the descriptor-rooted parent before
the syscall. A destination collision, `EINVAL`, or `ENOTSUP` is manual-review;
there is no ordinary rename fallback.

The helper itself admits an intentionally closed tree only: fixed root
`root:wheel 0711`; root-owned, single-link `0700` `.openduck-installer` with
the independent bootstrap digest; root-owned, single-link `0700`
`.openduck-readiness` with a separately supplied digest from an independently
verified signed release catalog; and exactly empty root-owned
`releases/controller` ancestry (`releases 0711`, `controller 0750`). It rejects
all selectors (`configured`, `candidate`, `active`, `previous`), provider or
state trees, release children, symlinks, hardlinks, mode/owner drift,
`.openduck-service-login`, and every other extra leaf. Those are manual-review
cases: do not delete them to make recovery pass.

The operator must explicitly supply the fixed confirmation and two digests;
the readiness digest is never read from the partial root or inferred from a
staged helper:

```sh
cd deploy/ansible
ansible-playbook --check --ask-become-pass -i inventory/localhost.yml recover-partial-install.yml \
  -e openduck_recovery_confirm=quarantine-partial-install-v1 \
  -e openduck_recovery_bootstrap_helper_path=/absolute/path/to/pretrusted/openduck-installer \
  -e openduck_recovery_bootstrap_helper_sha256=64_lowercase_hex_from_independent_authority \
  -e openduck_recovery_readiness_sha256=64_lowercase_hex_from_independently_verified_catalog

# Only after the check-mode input validation and an operator review:
ansible-playbook --ask-become-pass -i inventory/localhost.yml recover-partial-install.yml \
  -e openduck_recovery_apply=true \
  -e openduck_recovery_confirm=quarantine-partial-install-v1 \
  -e openduck_recovery_bootstrap_helper_path=/absolute/path/to/pretrusted/openduck-installer \
  -e openduck_recovery_bootstrap_helper_sha256=64_lowercase_hex_from_independent_authority \
  -e openduck_recovery_readiness_sha256=64_lowercase_hex_from_independently_verified_catalog
```

The operation has no delete path and no automatic restore path: a quarantine is
durable evidence for manual forensic review. A failed precondition or a rename
failure leaves the fixed root in place and fails closed. An error after rename
is reported only as `uncertain; manual review required`: do not run `site.yml`
and do not manually move or delete either path. A subsequent explicit recovery
invocation with the same authority digests may reconcile only the exact pending
receipt and recorded destination, then commit it; inconsistent receipt/source/
destination state remains manual-review and can never allocate a second
quarantine.

`--apply`, `--stop`, and `--activate` are rejected legacy mutation commands.
They are retained only as rejected migration inputs, never as a production
fallback. Read-only plan and verification commands do not consume release
nonces. The playbook uses `command.argv`, never `shell`, `raw`, or `sudo`, and
the local JSONL callback writes only whitelisted metadata with restrictive
permissions.
