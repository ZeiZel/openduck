# Typed Codex broker

`codexbroker` is the Controller-facing seam for the owner Codex runtime. Its
public API contains only attestation, inventory, ChatGPT login lifecycle,
turn, cancel, and close operations. Runtime process handles, stdio, JSON-RPC,
profile homes, executable paths, and interpreter paths are intentionally not
part of the API.

`NewProduction` fails closed until a separately attested service principal and
installed runtime are supplied. The fake backend is provider-free and exists
only for bounded contract tests; it never launches a process or performs
login/network I/O.
