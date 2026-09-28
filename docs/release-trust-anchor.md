# Release trust anchor ceremony

`site.yml` must verify release envelopes with the fixed root-owned public-key
anchor at `/Library/Application Support/OpenDuck.release-trust.v1.json`.
A trust JSON supplied beside a staged release is comparison material only: its
bytes and SHA-256 must equal the installed anchor before it is admitted.

The anchor is never initialized by deployment, rollback, or recovery. Before
the first deployment, use an independently provisioned root-owned
`openduck-installer`, verifying both the helper and trust JSON SHA-256 out of
band:

```sh
ansible-playbook --ask-become-pass deploy/ansible/bootstrap-release-trust.yml \
  -e release_trust_anchor_action=bootstrap \
  -e release_trust_anchor_source=/absolute/path/openduck.release-trust.v1.json \
  -e release_trust_anchor_sha256=LOWERCASE_SHA256_VERIFIED_OUT_OF_BAND \
  -e release_trust_anchor_bootstrap_helper_path=/absolute/path/pretrusted/openduck-installer \
  -e release_trust_anchor_bootstrap_helper_sha256=LOWERCASE_HELPER_SHA256_VERIFIED_OUT_OF_BAND
```

The helper may initially be owned by the invoking user, but must be a regular
single-link file that is not writable by group or others and must match the
separately verified digest. The role copies it to a random root-owned `0700`
handoff before execution.

Rekey is intentionally not implemented. A safe rekey needs a durable
root-owned monotonic sequence/replay ledger and an explicit recovery model;
replacing the anchor from a merely signed one-shot file would allow A→B→A
replay. Until that separate design is delivered, rotation fails closed and is
an offline owner migration, not a release-apply feature.

The ceremony rejects links, mutable files, malformed or empty bundles, a
bootstrap collision and staged trust-file substitution.
