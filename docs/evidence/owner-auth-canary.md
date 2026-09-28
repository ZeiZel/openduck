# Native owner-auth canary

The canary is a synthetic two-phase probe for the pinned native helper. It
starts no Controller, does not access accounts or credentials, and has no
effect executor or callback. The helper receives only a fixed preview and a
synthetic destination. Output is exactly `PASS` or `FAIL`; proof references
and preview contents are never printed.

Build the helper first (if needed), then obtain its trusted digest from the
same local binary without copying it into a config:

```sh
scripts/build-owner-auth-helper.sh
HELPER="$PWD/.openduck/bin/openduck-auth-helper"
DIGEST="$(shasum -a 256 "$HELPER" | awk '{print $1}')"
scripts/owner-auth-canary.sh "$HELPER" "$DIGEST"
```

The last command opens the synthetic preview and then asks for the local
Touch ID decision. `PASS` means the pinned process completed both protocol
phases and the injected synthetic authority returned a controller-shaped
proof reference. It does not authorize any real action.

## Root live probe (2026-08-13)

The root live canary completed with `PASS` using helper SHA-256
`b7fe1c39828c5bf227f650750d505b7fa0e371f990144180479ba18663ebc557`.
The helper is ad-hoc signed with no TeamIdentifier. Controller callback,
external effects, and real-data integrations remained disabled.
