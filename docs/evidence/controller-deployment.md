# Controller deployment boundary

The repository provides `scripts/controller-install.sh`, `controller-start.sh`,
`controller-stop.sh`, and `controller-status.sh` for the local synthetic H1 runtime.
Installation is explicit and idempotent. It creates the owner-only `.openduck` directory,
ensures the macOS Keychain item `service=openduck`, `account=controller-state` exists, and
refuses to replace an existing item or accept a value other than exactly 32 bytes. A newly
generated value is passed directly to `/usr/bin/security`; it is never printed, placed in a
plist, or committed to the repository.

The LaunchAgent runs only the built native binary, with an explicit loopback address and
repository working directory. Its plist contains no token, password, or environment-based
secret. Logs and encrypted state are under `.openduck` with owner-only permissions. `--activate`
is required to bootstrap and kickstart the LaunchAgent; without it the installer only prepares
the files. The helpers do not read chats, contact external services, or execute effects.

The optional `--origin-probe` installer flag appends `-origin-probe` to the generated LaunchAgent.
This only permits the Controller's non-authoritative origin/CORS probe for local integration
diagnostics. It does not enable the authenticated callback, owner approvals, or any effect. The
flag is omitted by default and is regenerated idempotently on every installer run.

To build the native Touch ID owner-auth helper for local development (without installing or wiring
it into the Controller), run:

```sh
scripts/build-owner-auth-helper.sh
```

The output is written to `.openduck/bin/openduck-auth-helper`; the build script never launches it.

After an owner-approved activation, `controller-status.sh` checks `/readyz` and then reports the
synthetic `/v1/controller/status` response. A non-ready or unavailable Controller is a failure;
the Codex plugin remains fail-closed in that case.
