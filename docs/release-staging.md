# Reproducible release staging

`scripts/stage-release.sh` is the unprivileged bridge from the Bun workspace
and Go catalog to `openduck-release-packager`. It first runs
`scripts/require-node.sh`: the plugin suites use the `node:test` runner, and
Bun silently substitutes itself for `node` when no real Node is on `PATH`, so
every suite would otherwise fail with an unrelated "Cannot use test outside of
the test runner" error. Node >= 22.19.0 must resolve on `PATH`. It then runs
`bun install --frozen-lockfile`, plugin tests/typechecks, `go test ./...`, `go vet ./...`,
builds the catalog's mandatory binaries, and creates a fresh stage outside the
fixed macOS install root. The packager then emits an unsigned ManifestV2 and
signing request. Stage, manifest, and request are published together as one
immutable release bundle; a failed run cleans its private temporary bundle
and an existing release ID is never overwritten.

Example (all release bindings are explicit and must be supplied by the
operator):

```sh
bun run stage:release -- \
  --output-dir /absolute/path/release-output \
  --release-id release-20260830 --version 1.0.0 \
  --key-id release-key --run-id 0123456789abcdef --nonce unique-release-nonce \
  --sequence 1 --issued-at 2026-08-30T10:00:00Z \
  --expires-at 2026-08-30T12:00:00Z --min-installer 1.0.0
```

The command prints the published bundle's `stage`, `manifest`, and
`signing_request` paths. Provider policy is release-wide. The dedicated
`--provider-policy-bundle FILE --provider-policy-trust FILE` pair is copied
once. Any policy pair also supplied in provider sources must be byte-identical
to that dedicated pair; if no dedicated pair is supplied, every provider
source must contain both files and all copies must be byte-identical. Symlinks,
incomplete pairs, and conflicting copies are rejected.

An optional provider is accepted only as a complete inactive group. Its source
directory must contain `provider-bundle.json`, `provider-trust.json`, and the
exact catalogued descriptor leaves for that provider, unless both dedicated
`--provider-policy-bundle` and `--provider-policy-trust` arguments are
supplied. If a source pair is present, it must match every supplied policy
pair byte-for-byte. Add one or more flags:

```sh
--provider-source codex=/absolute/path/codex-group
```

Imported provider hosts alone are not a packageable provider group. A
rootless catalog generator must first produce the inactive descriptor schema
and bounded evidence-review requests; only after the operator supplies a
verified `provider-bundle.json` and `provider-trust.json` can the complete
group pass packager admission. The staging command deliberately rejects
host-only or placeholder inputs.

The command prints only bounded stage/output paths and SHA-256 digests,
including the staged `openduck-installer` digest for independent bootstrap
verification. It never reads credentials, signs, invokes `sudo`, starts a
daemon, or installs anything. Use the printed paths as inputs to the separate
offline signing and approval process, then to `deploy/ansible/site.yml`.

Publication is a single same-parent atomic rename. The command deliberately
does not call `sync(2)`: that flushes every mounted volume, and one stalled
volume wedges the release pipeline indefinitely after the bundle is already
complete.

`third_party/deepseek-harness` is intentionally excluded from this workspace
build and retains its upstream pnpm contract.
