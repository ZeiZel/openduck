# Synthetic platform anchor

`platformanchor` is the bounded DR-020 seam used by tests and local synthetic
composition. Frames are a four-byte big-endian length followed by strict JSON;
the only namespaces are `admission`, `chat`, and `runtime-lease`. Checkpoints
use monotonic expected/next CAS and durable temp-file + fsync + rename +
directory-sync persistence under a separate flock file. Request IDs are
persisted for lost-reply retries and cross-namespace replay is rejected.

Production composition now has typed, fail-closed wrappers over the sealed
`macoschannel.Conn` boundary. `NewProductionStore` accepts only a checkpoint
created from `ProductionClient`; synthetic checkpoints, `net.Conn`, and
`PeerAttestation` cannot satisfy those constructors. Every production frame
checks the channel evidence against an exact role/channel/release policy and
has a bounded operation deadline.

This is still only the production integration seam: an independently owned
checkpoint service, launchd registration, credential provisioning, and live
ChatGPT/model network access are not implemented in this slice. `SyntheticPeer`
and the synthetic constructors remain test-only.
