# Native DeepSeek Harness installation

OpenDuck uses the published native DeepSeek Harness CLI `0.1.7-rc.2`. The installer keeps the CLI, its frozen pnpm dependency graph, profile dependencies, and mutable DSH home in ignored local directories; it does not modify the vendored Harness source and does not read credentials.

From the OpenDuck checkout, install Node 22.19 through 22.x, or Node 24 or
newer, and pnpm, then run:

```sh
make install
```

This creates `.dsh-runtime`, `.dsh-home`, and the named `openduck` profile. Like DSH's own `web` template, the profile selects the installation-owned `dsh-base` and `dsh-web-app` bundles without installing second copies, and installs only the generic `@openduck/openduck-base` bundle (and any external plugins). Host peers such as `cordis`, `dsh-app-boot` and `dsh-llm` resolve from the installation (`autoInstallPeers: false`); a duplicate `dsh-app-boot` makes every native settings write fail with `profile reload requires the root Include entry`, and the installer repairs older profiles that carried those copies. The pinned runtime patches `fetch-blob@3.2.0` to use Node's built-in `DOMException`, so installs no longer pull the deprecated `node-domexception`. Inspect the composed profile without booting it:

```sh
make dump-config
```

Run the loopback web surface with the native DSH session/model stack. These native model and session requests are owned by DSH; enabling the optional OpenDuck Controller boundary is a separate deployment decision:

```sh
make run PORT=3080
```

`openduck-base` registers the `openduck` settings entry and `openduckBase` service. Its default Controller state is disabled; enabling a Controller adapter requires an authenticated deployment overlay. DSH 0.1.7 stores live plugin settings in the profile patch (`cordis.patch.yml`) and imports a legacy `.dsh-home/settings.yaml` once. Browser RPC for OpenDuck and external plugins is served as exact `/api/<channel>/<endpoint>` routes behind DSH's browser authentication.

The installer also writes a profile-local pnpm policy that allows only the reviewed native dependencies (`node-pty`, `koffi`, and the DSH subprocess helper) to run build scripts; optional packages stay denied.

An external work plugin is added through the native profile contract, so `dsh-process` stays outside this repository's generic base:

```sh
make connect-plugin PLUGIN=/path/to/dsh-process
make dump-config
```

The profile manager accepts registry packages, local paths, and Git URLs. Keep secrets in the DSH credential provider or the approved machine secret store; never put them in `cordis.patch.yml`, package manifests, or shell history.

The repository `Makefile` exposes the normal local lifecycle: `make help`, `make install`, `make run`, `make dump-config`, `make doctor`, and `make test`. A normal install creates the managed OpenDuck CLI root-chat preset. On startup OpenDuck discovers installed `codex`, `claude`, and `kimi` executables and lists each CLI's configured default model; it does not inspect credentials or make a model request. Select one of those models in a blank session and OpenDuck atomically applies the text-only CLI-root preset. Each turn runs in that session’s selected workspace, so there is no global CLI workspace setting.

The CLI-root preset is a native `@deepseek-ai/dsh-agent-preset` row (`openduck-cli-root`) in the OpenDuck bundle patch; DSH 0.1.7 no longer reads `$DSH_HOME/.agent-presets`. It mounts no DSH host-tool schemas. If another deployment layer contributes one, the adapter drops it rather than forwarding it to a subscription CLI. DSH tools cannot run in CLI-root mode; use an AIRun or native-tool preset for host tools. A started session keeps its existing composition, so begin a new CLI-root session before selecting a subscription CLI model; a blank chat that already carries a CLI model is switched to the preset automatically. `make connect-cli-chat` re-enables a route previously disabled by `make disconnect-cli-chat` for the next start.

The OpenDuck settings panel reports only normalized installed/sign-in state. Choosing an installed but signed-out Codex or Claude model launches that provider’s own Terminal sign-in flow. Kimi status is intentionally unknown because its CLI has no supported status command; use the visible Sign in action. The Make equivalents are `make login-codex`, `make login-claude`, and `make login-kimi`. Codex and Claude can also be given explicit configured model IDs in settings; the reserved `default` selection omits a model argument and uses the subscribed CLI’s configured default. Kimi ACP uses its configured default because its ACP protocol does not advertise a model-selection request. `make connect-computer` installs DSH's MCP client and checks the installed Cua Driver's permission status before persisting the explicit `cua-driver mcp` patch. It never grants permissions, uses direct capture, or sends a computer action. A disconnected Cua Driver leaves this optional bridge unavailable without stopping DSH.
