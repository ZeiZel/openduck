# Synthetic OpenClaw sensor ingress

The Controller has an opt-in `-sensor-enabled` composition path. It mounts the
local-only `POST /v1/sensor/events` endpoint and wires it to a purpose-derived
AES-GCM `core.FileQueue` plus the existing Controller `IngestSignal` method.
The default LaunchAgent does not pass this flag, so the route is absent in the
normal read-only runtime.

`scripts/sensor-canary.sh` is the bounded operational canary: it builds both
private binaries with mode `0700`, prepares the LaunchAgent with
`--sensor-enabled`, and sends one synthetic fixture through the sidecar. A
canary must be run only on a healthy local Controller; if launchd/bootstrap or
Controller state is unavailable, the script fails closed and does not enable a
partial route.

The Controller-state Keychain secret is never exposed to the sidecar: the
independent `openduck/sensor-hmac` Keychain item authenticates envelopes, while
the queue and replay tombstones use a purpose-derived Controller-owned key.
The envelope is HMAC-SHA256 authenticated with the sensor subkey,
has a bounded timestamp, and uses a one-time request/nonce pair. A non-loopback
peer, bad signature, stale message, replay, prompt-injection control text, or
PD marker is rejected by the deterministic ingress scanner before
queue/projection. This scanner is a separate transport policy and is not
represented as authoritative model DLP classification. Accepted synthetic events are
compiled to a sealed `TaskSignal.v1` with `MaxClass=L1`; the event body remains
in the encrypted queue and is not returned in the acknowledgement.
Replay tombstones are encrypted and atomically replaced before enqueue, survive
process restart, and fail closed on decode/integrity/commit uncertainty.

`cmd/openduck-sensor-sidecar` is the bounded sender seam: it reads one or more
synthetic `InboundEvent` objects from stdio, obtains the Keychain secret itself,
and can only call the fixed loopback endpoint. The OpenClaw model receives no
key and cannot forge an envelope. No OpenClaw model tool can access this
transport. No real accounts, chat
credentials, outbound network, or external effects are enabled by this change.
