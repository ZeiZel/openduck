# H0/H1 controller schemas

`contracts.v1.json` and `runtime-interactions.v1.json` are strict JSON Schema 2020-12
entry points for the lifecycle, runtime and interaction contracts introduced in H0/H1.
The Go `openduck/internal/harness` boundary is the
authoritative validator: it rejects unknown versions and fields through `DecodeStrict`,
validates cross-contract bindings, and verifies canonical SHA-256 self-digests.

Cross-contract bindings additionally require Controller state and an exact current-preview
comparison, which JSON Schema alone cannot express.
