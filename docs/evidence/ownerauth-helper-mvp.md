# Native owner-auth helper MVP

Status: implemented but not wired to Controller or callback; real approvals and
effects remain disabled.

`native/openduck-auth-helper/main.swift` is a macOS AppKit helper using
`LocalAuthentication`. It displays the synthetic preview and emits `rendered`
only after the window is visible. A later challenge opens an approval dialog.
Approval is accepted only when `deviceOwnerAuthenticationWithBiometrics` is
available and `biometryType == .touchID`; password, watch, and fallback
authentication are rejected. The helper returns only decision, challenge,
session, display instance, and timestamp. It does not emit reusable proof.

`internal/ownerauth` runs a pinned absolute executable with owner-only `0700`
permissions, rejects symlinks/non-regular files and non-owner files, verifies a
SHA-256 digest, sanitizes environment and working directory, bounds JSONL lines
to 64 KiB, and kills the process on deadline or protocol failure. The opaque
proof reference is supplied by the future Controller and is copied through
without interpretation; this package does not authenticate or authorize it.

The helper is intentionally unsigned/ad-hoc for development. A deployment must
record the exact binary hash in a trusted local configuration and replace it
when signing/notarization is introduced. No install, LaunchAgent, callback,
network permission, or effect execution is performed by this milestone.

Verification: `GOCACHE=/tmp/openduck-gocache go test ./...`; Swift
compilation was run with `swiftc` on the host and produced a temporary binary in
`/tmp` after allowing the system compiler cache.
