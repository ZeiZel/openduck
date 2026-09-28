# OpenDuck base bundle

`@openduck/openduck-base` is the deployment-neutral native DeepSeek Harness bundle. It registers the `openduckBase` Cordis service, a typed `openduck` settings namespace, and a native DSH settings card. The card exposes configured Codex CLI, Claude Code CLI, and Kimi ACP subscription delegation choices and marks composition-affecting selections as requiring a DSH restart. Credentials are never fields in this package: each CLI provider uses its own installed authentication.

The native OpenDuck history panel uses a loopback DSH RPC to list and read configured external CLI sessions. Users add exact existing canonical project directories in settings; the panel exposes aliases instead of filesystem roots, paginates summaries and messages, and never writes to provider history.

`native-providers.patch.yml` mounts the real DSH Codex, Claude Code, and Kimi ACP host providers. They remain inert until a preset exposes a matching `dsh-tool-subagent` row and an agent invokes it. `native-computer.patch.yml` mounts the real generic DSH MCP client against `cua-driver mcp`; it is explicit opt-in, uses standard driver permissions, and does not use direct capture or a bypass flag. If the Driver cannot reconnect, its optional bridge stays unavailable while DSH continues to run. Browser control needs a separately installed/configured browser MCP server.

Work-specific integrations belong in an external bundle such as `dsh-process`. Install that bundle into the profile with `dsh plugin --profile openduck add <package-or-path>`; its patch layer is then composed after this package. The base service exposes `settings()`, `status()`, `controller`, `providers()`, `mcp()`, and `externalPackages()` without embedding corporate URLs or credentials.
