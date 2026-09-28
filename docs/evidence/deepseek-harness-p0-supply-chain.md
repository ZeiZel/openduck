# DeepSeek Harness P0 supply-chain evidence

Status: `LOCKED / NO-EFFECTS / NO-INSTALL`

The materialized source is pinned to DeepSeek Harness tag `dsh-v0.1.0-rc.7` at
commit `99f6f02fecdb7dff40c3fbc9470f5907c29f74ca`.

## Immutable inputs

- Source archive URL and SHA-256 are recorded in `third_party/deepseek-harness/LOCK.json`.
- `SOURCE-MANIFEST.sha256` enumerates every pinned regular file and symbolic link with entry type,
  mode, and SHA-256/target; the verifier rejects additions, removals, mode changes, link changes,
  and content drift. The lock also hashes `pnpm-workspace.yaml`.
- The pinned `pnpm-lock.yaml` and root `package.json` digests are recorded in the lock.
- The source license and upstream third-party notices remain in the materialized tree.

## Lifecycle and build policy

The pinned tree inventory includes root/subprocess `postinstall` scripts and native `prepack`
scripts. They are reviewed and explicitly blocked by the P0 materializer. The upstream workspace
also declares native build permissions for esbuild, lefthook, node-pty, koffi, and the local
subprocess package; these are recorded as reviewed-but-disabled, not executed. The P0 allow-build
list is empty. No package manager install, provider, telemetry, network, MCP, credential, or
external effect is enabled by this work order.

Run `scripts/dsh-verify.sh` against the tree and a separately obtained local archive before use.
`scripts/dsh-materialize.sh` requires a local archive by default; `--download` is an explicit
operator action and is not part of build or test. Before extraction it rejects absolute/traversal
members, multiple roots, devices/FIFOs/hardlinks, and escaping symlinks. The materializer stages
into a sibling temporary directory and never writes to a user home directory.

## SBOM and license gate

No dependency installation is promoted by P0. Before any build promotion, generate a CycloneDX or
SPDX SBOM from the pinned lockfile in an isolated, offline-capable environment, attach the exact
tool version and output digest, and review `LICENSE` plus `THIRD_PARTY_NOTICES.md`. Any new
dependency, lifecycle script, native build, or lock/config drift fails verification and requires a
new pinned source review.

## Rollback / LKG

The last-known-good record is this lock and manifest pair. Rollback is selecting the previous
reviewed lock/manifest pair and discarding the staged materialization; no live account, provider,
credential, or external state is changed by the rollback.
