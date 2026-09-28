# Phase 1 evidence template

Environment: synthetic-only, local-only, no accounts, no egress. Record commit, Go version,
schema/policy versions, synthetic corpus identifier, and immutable test run IDs.

## Host baseline (OD-108)

Attach owner-approved evidence for FileVault, screen lock, restricted runtime identity,
non-world-readable state, Keychain-only references, localhost/firewall probe, and encrypted-backup
decision. `scripts/host-baseline-check.sh` is a read-only probe and does not establish these facts.

## Performance (OD-104)

Record p50/p95 latency, throughput, peak RSS, queue depth/backpressure and truncation behavior.
The local model benchmark is blocked until separately authorized model installation; no Ollama or
cloud fallback is enabled by this repository.

Run `scripts/benchmark-evidence.sh` to produce a deterministic synthetic DLP benchmark. The
read-only host probe currently reports FileVault `fail`, screen lock `pass`, restrictive state
permissions `pass`, loopback `pass`, and encrypted backup `manual` on this machine; these are
evidence only and never mutate host settings.
