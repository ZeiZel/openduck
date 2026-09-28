# Local domain overlay

The tracked configuration is a portable, disabled template. Machine- or
organisation-specific values belong in an ignored local overlay and must never
be committed, copied into fixtures, or printed in diagnostics.

Copy `local-overlay.example.json` to `local-overlay.json` and fill only the
values required on the current machine. Keep `cua.driverPath` and
`cua.allowedBundles` empty unless the owner has explicitly approved the local
UI boundary. The runtime fails closed when the driver path is missing or the
allowlist is empty.

Provision this overlay manually on the host; it is deliberately separate from
the Ansible boundary deployment. Do not put tokens, cookies, authorization headers, or
credential paths in this file; use the OS credential store and the runtime's
app-managed authentication instead.
