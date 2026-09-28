# Provider catalog workflow

`openduck-provider-catalog` is the only pre-release compiler for optional
provider groups. It is offline: it does not launch a daemon, use a provider
account, read a credential, or create an owner operation.

`generate` consumes a canonical input file and a verified import root. Each
provider import supplies real pinned compatibility, unsigned evidence, limits,
the disabled daemon, and (except DeepSeek) the host binary plus importer-issued
host identity. The compiler checks the binary SHA-256 against that identity,
requires the pinned provider Team ID, and preserves the imported image identity.
DeepSeek is API-only and rejects host input. It emits catalog leaves using
`InactiveDescriptorV1`, which intentionally has no socket, UID/GID, manifest,
release, key epoch, or peer identity.

The output contains `provider-catalog-material.json` and separate portable
technical and security evidence signing requests per profile. They are review
inputs, not activation authority.

`finalize-evidence` takes that material, the canonical public evidence trust
bundle, two distinct approved Ed25519 evidence records, and the complete base
release stage. It emits new `provider-bundle.json` and `provider-trust.json`
only if every approval is current, trusted, non-revoked, role-distinct, and
bound to the exact profile revision/evidence digest. It then uses the same
`macosrelease.ValidateCatalogPayloads` gate as release packaging.

Evidence trust is not owner authority. The later P7 conversion to an active
descriptor needs separately installed `providerrevision.OwnerTrust` and an
exact signed `ProviderLifecycleOperation` (`install`, `activate`, and
`profile-enable` as applicable), plus real observed system bindings. A base
release installation rejects any pre-existing post-principal socket/key state
because it cannot safely interpret it without that active descriptor.

The staging workflow should run `generate` before copying optional provider
leaves, obtain the two external approvals, then run `finalize-evidence` before
`openduck-release-packager package`. No synthetic compatibility mappings or
placeholder “pinned” versions are accepted.
