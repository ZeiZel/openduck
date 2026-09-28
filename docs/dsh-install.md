# Native DeepSeek Harness installation

OpenDuck uses the published native DeepSeek Harness CLI `0.1.0-rc.7`. The installer keeps the CLI, its frozen pnpm dependency graph, profile dependencies, and mutable DSH home in ignored local directories; it does not modify the vendored Harness source and does not read credentials.

From the OpenDuck checkout, install Node 22.19 through 22.x, or Node 24 or
newer, and pnpm, then run:

```sh
./scripts/dsh-install.sh
```

This creates `.dsh-runtime`, `.dsh-home`, and the named `openduck` profile with the native `dsh-base`, `dsh-web-app`, and generic `@openduck/openduck-base` bundles. Inspect the composed profile without booting it:

```sh
./scripts/dsh-run.sh --dump-config
./scripts/dsh-run.sh --dump-default-config
```

Run the loopback web surface with the native DSH session/model stack. These native model and session requests are owned by DSH; enabling the optional OpenDuck Controller boundary is a separate deployment decision:

```sh
./scripts/dsh-run.sh --host 127.0.0.1 --port 3080
```

`openduck-base` registers the `openduck` settings namespace and `openduckBase` service. Its default Controller state is disabled; enabling a Controller adapter requires an authenticated deployment overlay. The native DSH settings document remains authoritative at `.dsh-home/settings.yaml`.

The installer also writes a profile-local pnpm policy that allows only the reviewed native dependencies (`node-pty`, `koffi`, and the DSH subprocess helper) to run build scripts; optional packages stay denied.

An external work plugin is added through the native profile contract, so `dsh-process` stays outside this repository's generic base:

```sh
./scripts/dsh-base.sh plugin --profile openduck add /path/to/dsh-process
./scripts/dsh-run.sh --dump-config
```

The profile manager accepts registry packages, local paths, and Git URLs. Keep secrets in the DSH credential provider or the approved machine secret store; never put them in `cordis.patch.yml`, package manifests, or shell history.
