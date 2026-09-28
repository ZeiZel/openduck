# Native DeepSeek Harness installation

OpenDuck uses the published native DeepSeek Harness CLI `0.1.0-rc.7`. The installer keeps the CLI, its frozen pnpm dependency graph, profile dependencies, and mutable DSH home in ignored local directories; it does not modify the vendored Harness source and does not read credentials.

From the OpenDuck checkout, install Node 22.19 through 22.x, or Node 24 or
newer, and pnpm, then run:

```sh
make install
```

This creates `.dsh-runtime`, `.dsh-home`, and the named `openduck` profile with the native `dsh-base`, `dsh-web-app`, and generic `@openduck/openduck-base` bundles. Inspect the composed profile without booting it:

```sh
make dump-config
```

Run the loopback web surface with the native DSH session/model stack. These native model and session requests are owned by DSH; enabling the optional OpenDuck Controller boundary is a separate deployment decision:

```sh
make run PORT=3080
```

`openduck-base` registers the `openduck` settings namespace and `openduckBase` service. Its default Controller state is disabled; enabling a Controller adapter requires an authenticated deployment overlay. The native DSH settings document remains authoritative at `.dsh-home/settings.yaml`.

The installer also writes a profile-local pnpm policy that allows only the reviewed native dependencies (`node-pty`, `koffi`, and the DSH subprocess helper) to run build scripts; optional packages stay denied.

An external work plugin is added through the native profile contract, so `dsh-process` stays outside this repository's generic base:

```sh
make connect-plugin PLUGIN=/path/to/dsh-process
make dump-config
```

The profile manager accepts registry packages, local paths, and Git URLs. Keep secrets in the DSH credential provider or the approved machine secret store; never put them in `cordis.patch.yml`, package manifests, or shell history.

The repository `Makefile` exposes the normal local lifecycle: `make help`, `make install`, `make run`, `make dump-config`, `make doctor`, and `make test`. `make connect-codex`, `make connect-claude`, and `make connect-kimi` install the corresponding native DSH provider package and persist an auto-loaded profile patch; they do not start a model or read authentication state. `make connect-cli-chat` creates the OpenDuck CLI root-chat preset as an owned text-only composition and enables its route for the next DSH start. It mounts no DSH host-tool schemas; if another deployment layer contributes one, the CLI adapter drops it rather than forwarding it to a subscription CLI. DSH tools cannot run in CLI-root mode. In the OpenDuck settings panel, enable CLI root chat, save an existing canonical workspace and the explicit model allowlist, then restart DSH and select that preset. Enter `default` to use that subscribed CLI's configured default model. Codex and Claude also accept an exact installed model id; Kimi ACP uses its configured default because its ACP protocol does not advertise a model-selection request. The configured CLI workspace is fixed for every root-chat turn; select it deliberately before starting the session. The route stays disabled if its managed agent composition is edited; run `make connect-cli-chat` to restore the text-only preset. `make disconnect-cli-chat` disables the route at the next restart while retaining the generated preset. `make connect-computer` installs DSH's MCP client and checks the installed Cua Driver's permission status before persisting the explicit `cua-driver mcp` patch. It never grants permissions, uses direct capture, or sends a computer action. A disconnected Cua Driver leaves this optional bridge unavailable without stopping DSH.
