# macOS boundary bundle (DR-020)

This repository contains a disabled, offline deployment bundle for six
LaunchDaemons: checkpoint, anchor, egress, Codex runtime, Codex broker, and
Controller. The checked-in templates are generated from the same argument
renderer used by the fixed-root installer.
The anchor template uses channel-specific release roots:
`releases/anchor/<release-id>` and
`releases/anchor-checkpoint/<release-id>`. Each immutable release is owned by
root with the consuming service group, mode 0550, and contains a root-owned
group-readable `manifest.json` mode 0440 plus a leaf
`openduck-anchor` binary mode 0550, which is the exact layout verified through
the already-open root descriptor by `macoschannel`. They do not use shell interpolation or launchd
socket activation. The install script defaults to a deterministic dry-run and,
with explicit `--apply`, delegates all mutation to the fd-relative Go
installer. Apply installs disabled plist files but never bootstraps jobs. The
exact staged allowlist includes all six daemons, the Codex CLI, the owner grant
and service-login tools, `.openduck-installer`, and `.openduck-readiness`; both
the shell wrapper and Go installer validate the same `release.manifest` and
`bin/<artifact>` layout.

The disabled Controller daemon is fully parameterized for production
admission. Its `-state` argument is the private state directory, never the
legacy `controller.enc` file. The Controller's local release is a distinct
root-owned, Controller-group-readable immutable copy under
`releases/controller/<release-id>`; the
anchor peer is represented only by exact release and UID/GID pins. The
Controller reads a separate service-owned copy of the anchor channel key from
`keys/controller-anchor/service.key`. Its contents and epoch must match the
anchor channel, but neither daemon shares a writable key directory. Static
verification checks the owner and mode without reading credential bytes.

The anchor/Controller Unix channel uses a dedicated `_openduck_channel`
group, distinct from both services' primary groups. The channel directory is
owned by `_openduck_anchor:_openduck_channel` at mode 0750 and `anchor.sock`
is pinned to the same owner/group at mode 0660. Both daemon manifests require
the exact numeric `CHANNEL_GID`. Live verification fails closed until
`_openduck_anchor` and `_openduck` membership in that group is visible; this
membership is a later sudo operation and was not performed by this work.

The offline installer is now implemented in `internal/macosinstall` and exposed
only through `cmd/openduck-installer`. It opens the fixed system root through
`os.OpenRoot`, rejects symlink, hard-link, special-bit, content, and staged
manifest mismatches, creates six independent service state/home/log/key roots,
root-owned service-group-readable verified release roots, five pairwise channel groups, and six
disabled LaunchDaemons. The initial staged installer is copied to the fixed
root as root-owned `.openduck-installer`. The same helper exposes `--activate`
to finalize PF evidence and health-check six dependency-ordered jobs without a
manual freshness gap, plus the installed root-only `.openduck-service-login`
wrapper (the same verified helper forced into `--service-login` mode), which
validates the root-owned nonsecret resolved login config before dropping to Controller. Login,
the live egress canary, and launchctl bootstrap remain explicit operator
gates. PF finalization derives status, rules, boot identity, policy digest,
and the canonical bounded evidence record directly through fixed system
operations; it does not trust caller-supplied evidence hashes. No sudo, launchctl,
account creation, login, credential read, model request, or network request
was performed by this slice.

The PF anchor permits only the runtime principal to reach the IPv4 loopback
model proxy and immediately blocks every other principal for that endpoint;
the following rules continue to block direct runtime/broker egress and admit
network egress only through the dedicated egress principal.

The service topology is `_openduck`, `_openduck_anchor`,
`_openduck_checkpoint`, `_openduck_egress`, `_openduck_codex`, and
`_openduck_broker`, with root-owned traversal-only
parents mode 0711, private service roots mode 0700, and channel roots mode
0750 with explicit service ownership. `macos-boundary-stop.sh` and
`macos-boundary-rollback.sh` are strict wrappers around the fixed-root helper;
stop is reverse-order and rollback retains state/auth/checkpoint roots. The
installer refuses Apply, PF finalization, or activation with `STOP_REQUIRED`
unless `launchctl print` proves every one of the six labels absent; upgrades
therefore require the stop wrapper before any release, plist, principal, or PF
mutation. The
readiness command verifies principals, canonical key records, release hashes,
resolved disabled plists, canonical current-boot PF evidence plus a live PF
status/rules query on every invocation, a broker-completion login proof, and an
authenticated decrypted completed chat-ledger record bound by a canonical
canary proof to the active release, current boot, exact approved request, and
exact result digest. Only the explicit `openduck-live-egress-canary` chat ID
can produce that proof; ordinary completed chats cannot advance readiness.
Live launchd PID/state is also required. It reports `SUDO_PROVISIONING_REQUIRED` →
`ACTIVATION_APPROVAL_REQUIRED` → `SERVICE_LOGIN_REQUIRED` →
`LIVE_EGRESS_CANARY_REQUIRED` → `READY` without mutating the host. Activation
precedes login because the login helper uses the authenticated broker/runtime
channel; the started services remain PF- and Seatbelt-confined throughout.
No mutable `current` symlink is used.

Validation: `scripts/macos-boundary-bundle-test.sh` and `sh -n
scripts/macos-boundary-*.sh` pass on the development host. `plutil -lint` is
used by the static test when available. The installed readiness helper refuses
to report `READY` until all six principals and plists, every canonical key
record, release manifests and binary hashes, current-boot PF evidence, service
login completion proof, authenticated completed canary record, and live launchd jobs have been checked.
