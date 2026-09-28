# ADR 0002: security baseline and limitations

Before real data, the owner must evidence FileVault, screen lock, a dedicated restricted runtime,
non-world-readable state, Keychain-only secret references, loopback/firewall verification and an
encrypted-backup decision. Phase 0 does not claim these host controls are configured. The current
user decision is to keep backups disabled (`backups.enabled=false`) during synthetic/local pre-pilot
work; no backup copies are created and no cloud backup is configured. Future backup capability is
reserved for a separately approved local encrypted design and is not implemented by this ADR. Raw L2/L3,
credentials and unknown classifications are local-only; operational audit is redacted. The
synthetic implementation provides an encrypted local queue when a runtime key reference is supplied;
it performs lookup only and does not create, rotate, or print keys. A persistent encrypted pseudonym
mapping store is implemented as a local primitive, but is not connected to any cloud route. It does
not prove host encryption. Queue corruption fails closed. OD-104 local-model
benchmark and OD-108 host evidence remain blocked pending explicit authorization and owner evidence.

The production composition derives a separate pseudonym-store key from the queue key with the
domain label `openduck/pseudonym-store/v1`; only the Keychain reference and local encrypted paths
are configuration, never key material. The mapping store is injected even while egress is disabled.
