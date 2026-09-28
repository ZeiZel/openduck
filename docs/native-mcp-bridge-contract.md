# Controller-owned native MCP bridge

This is the only allowed native-host MCP surface. It is pinned to the official
[MCP 2025-11-25 stdio transport](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports)
and [tools contract](https://modelcontextprotocol.io/specification/2025-11-25/server/tools), retrieved 2026-08-30.

An official host launches the fixed `openduck-native-mcp` shim over stdio. The
shim forwards only line-delimited MCP JSON-RPC to the fixed root-owned Controller
Unix socket `/private/var/run/openduck/native-mcp.sock`; it receives no binding,
credential, provider endpoint, session configuration, or arbitrary socket path.
The Controller obtains `LOCAL_PEERCRED`, verifies shim PID/parent-chain/CDHash
and UID/GID against its server-side registered host/session, then resolves the
memory-only `openduck-native-mcp-session.v1` contract server-side.

The contract includes provider/profile/revision, UI session and channel,
root/run/mesh session/attempt, the UI endpoint generation and expiry, plus the
peer identity. For every `initialize`, `ping`, and `tools/list`, Controller
validates the current association, revision, endpoint and process identity. For
every `tools/call` it repeats that validation, consumes a fresh durable UI
nonce, resolves the private matching mesh capability, then consumes a second
fresh mesh nonce for the typed operation. Expiry, rotation, revocation,
session/provider/profile mismatch, peer substitution and replay fail closed.
Only `codex`, `claude`, `qwen`, and `kimi` are valid native providers;
`deepseek` remains API-only and cannot obtain this contract.

Only these tool names may be registered, in this order:

- `openduck_mesh_spawn`, `openduck_mesh_spawnBatch`, `openduck_mesh_send`
- `openduck_mesh_steer`, `openduck_mesh_wait`, `openduck_mesh_collect`
- `openduck_mesh_cancel`, `openduck_mesh_list`, `openduck_mesh_status`
- `openduck_mesh_result`, `openduck_mesh_listProfiles`

All input schemas are strict and Controller decodes them into existing typed
mesh contracts. There is deliberately no `proposeMesh`, generic RPC, endpoint,
audience, nonce, credential, provider URL, network client, resource, prompt,
sampling, filesystem, or subprocess tool.

The shim dials only that fixed socket and fails closed when it is absent. A
native package may be marked available only after the root-owned Controller
listener, `LOCAL_PEERCRED`+parent-chain attestor and provider-specific official
host registration have end-to-end evidence. Until then packages remain
explicitly unavailable rather than claiming an unusable MCP command.
