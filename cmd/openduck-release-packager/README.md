# Offline release packaging

`openduck-release-packager` is intentionally an unprivileged preparation
tool. It has no private-key flag, credential input, environment configuration,
network client, or signing implementation. Its only signing boundary is a
portable request containing the exact canonical unsigned `ReleaseEnvelope.v1`
bytes for a separate human-approved signing system.

## Human inputs

Before packaging, an operator supplies and records these values: a unique
`release-id` (not a digest), semantic release version, intended platform and
architecture, signer `key-id`, operation, installer `run-id`, explicit
activation intent, monotonic sequence, single-use nonce, issuance and expiry
times, and the minimum installer version. The fixed production target root is
`/Library/Application Support/OpenDuck`.

The staged root always contains the closed eleven-artifact core/helper/runtime
catalog. It may additionally contain only complete, catalogued inactive
provider sets: `provider-bundle.json` plus `provider-trust.json`, and one or
more known all-or-none descriptor groups for Codex, Claude, Qwen, Kimi, or the
DeepSeek API/DSH adapter. A descriptor group cannot appear without the policy
pair, and the signed disabled bundle must name exactly its selected runtime
profiles. Runtime descriptors are parsed against the fixed transport schema;
plugin descriptors are separately canonical disabled metadata. DeepSeek has
only `providers/deepseek/dsh-adapter-descriptor.json`—never a native plugin or
subscription artifact.

The only optional installation destination is the fixed inactive root
`/Library/Application Support/OpenDuck/providers/inactive`: `providers` is a
trusted root-owned traversal parent, while inactive leaves are protected
root:`_openduck` metadata. Provider policy and descriptors do not enable a
profile, mount a plugin, start a runtime, create a socket, or provision a key.
`provider-lifecycle-operation.json` and `controller-owner-ed25519.json` are
intentionally excluded; a later owner-approved lifecycle gate handles those
separately.

Links, hardlinks, writable files/directories, unknown files, arbitrary
destinations, and incomplete/colliding groups are rejected. Packaging reads
the root through a descriptor, hashes every file, validates the disabled policy
at the explicit `issued-at` instant, and never changes the stage.

## Package, sign, finalize

Run this on the staging machine; every path is absolute and both outputs must
be new paths outside the staged root.

```sh
go run ./cmd/openduck-release-packager package \
  --stage-root /absolute/stage \
  --manifest-out /absolute/release/openduck.release-manifest.v2.json \
  --signing-request-out /absolute/release/openduck.release-signing-request.v1.json \
  --release-id release-20260826 --version 1.2.3 \
  --target-root '/Library/Application Support/OpenDuck' \
  --platform darwin --arch arm64 --key-id release-key \
  --operation deploy --run-id aaaaaaaa-1111 --activation false \
  --sequence 42 --nonce release-nonce \
  --issued-at 2026-08-26T10:00:00Z --expires-at 2026-08-26T12:00:00Z \
  --min-installer 1.0.0
```

Send only the request to the secure signing system. Before decoding anything,
the human signer checks its explicit `release_id`, `release_version`,
`target_root`, `platform`, `arch`, `manifest_digest`, `artifact_set_digest`,
`release_digest`, operation/run/activation, sequence, nonce, issuance/expiry,
and minimum-installer fields. The packager binds those fields to the canonical
unsigned envelope bytes. The signing system then signs decoded
`unsigned_payload_b64` with the request's `ed25519` key ID and returns a new
strict JSON file (all fields required):

```json
{"schema":"openduck.release-signature.v1","algorithm":"ed25519","key_id":"release-key","payload_digest":"<request payload_digest>","signature":"<128 lowercase hex characters>"}
```

Back on a machine with the pinned public trust bundle, finalization verifies
the request, exact payload digest and bindings, signature, key revocation, and
expiry before it atomically creates a new signed envelope. `--now` is explicit
so this offline verification is auditable and reproducible.

```sh
go run ./cmd/openduck-release-packager finalize \
  --signing-request /absolute/release/openduck.release-signing-request.v1.json \
  --signature /absolute/release/external-signature.v1.json \
  --trust-bundle /absolute/release/openduck.release-trust.v1.json \
  --envelope-out /absolute/release/openduck.release-envelope.v1.json \
  --now 2026-08-26T10:30:00Z
```

All generated outputs are mode `0600`, written through a same-directory random
temporary file, fsynced, then atomically published with a no-replace hard-link
operation; the temporary file is removed and the parent directory is fsynced.
They never overwrite an existing file. The resulting manifest, envelope and
trust bundle are the three immutable inputs to `openduck-installer` admission.
