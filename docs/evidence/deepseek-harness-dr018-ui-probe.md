# DR-018 synthetic UI-only probe

Status: **BLOCKED** for DR-018. The deterministic synthetic read-model harness passes its local checks. An exact dependency materialization and a real pinned web boot were attempted in an isolated `/private/tmp` copy; the standard web profile renders, but exposes a model route, while the deny overlay cannot boot because the stock web/API composition hard-requires model/session services.

## What is implemented

`profiles/dsh/openduck-synthetic/profile.json` is a probe expectation and deny-overlay input. Stock DSH does **not** consume or enforce this JSON file. The companion `cordis.patch.yml` is the attempted overlay; the live attempt shows that stock DSH cannot boot with the required model/session rows disabled. The JSON documents the intended no-AgentLoop/no-provider/no-session-persistence/no-durable-browser-store policy, not an achieved runtime guarantee. The Controller read model is memory-only in the standalone probe only; no live Controller HTTP endpoint is exercised by this script.

`deploy/deepseek-harness/probe/openduck_synthetic_probe.py` runs without third-party dependencies. It verifies the profile, evaluates synthetic inbox/calendar/work-graph sentinels in an in-process memory-only request harness, denies prompt and mutation methods, and returns the `degraded_read_only` projection when the Controller is down. It does not claim a live HTTP round trip, import, or alter DSH.

Run:

```sh
./scripts/dsh-ui-probe.sh --synthetic-only
./scripts/dsh-ui-probe.sh --synthetic-only --json
# exits 3: the live DR-018 gate is blocked
./scripts/dsh-ui-probe.sh --json
```

The standard-profile browser capture (run from the isolated materialized DSH copy) is reproducible with:

```sh
cd /private/tmp/dsh-wo04-live.ZPXz5d/source/apps/web
node scripts/dsh-ui-probe-browser.mjs http://127.0.0.1:4173
```

## Evidence and limits

The synthetic probe proves only the isolated channel and deny policy. It does not prove a DSH session/event absence, browser storage absence under the target deny overlay, server-side prompt denial, no provider process, or no external effects. The live gate remains BLOCKED.

## Live attempt evidence (2026-08-19)

The exact pinned source `dsh-v0.1.0-rc.7` at commit `99f6f02fecdb7dff40c3fbc9470f5907c29f74ca` was copied to `/private/tmp/dsh-wo04-live.ZPXz5d`. Corepack downloaded exact `pnpm@11.7.0` into the same temporary tree. `pnpm install --frozen-lockfile --ignore-scripts` completed with 925 packages and the lockfile supply-chain policy passing. No lifecycle/native build scripts ran. The library and static web builds completed in the temporary copy.

The standard `dsh web --host 127.0.0.1 --port 4173` boot completed. Headless Chromium loaded `DeepSeek Harness`; at capture time it had no IndexedDB databases, no Cache Storage entries, no service-worker registrations, and no sessionStorage entries. Its only localStorage key was the non-content workspace-view preference `dsh.workspace.view.v5`. The standard boot also wrote `/private/tmp/dsh-wo04-live.ZPXz5d/dsh-home/storages/workspace.json`. This is a UI boot observation only, not a DR-018 pass: `POST /api/host.describe` returned `provider=deepseek-official` and `model=deepseek-v4-flash`.

The custom `openduck-synthetic` overlay disabled `agent`, `agent-default-model`, `llm`, `llm-pi-ai`, `llm-retry`, session title/model rows, session persistence/query/telemetry, credentials, attachments, conversation/model/subagent/trajectory UI. Its boot failed closed with ten pending entries: `dsh-goal`, `dsh-goal-round-driver`, `dsh-command-goal`, `dsh-session-checkpoint-policy`, `dsh-agent-loop`, `dsh-llm-deepseek`, `dsh-message-feedback`, `dsh-workspace`, `dsh-session-projection-cache`, and `dsh-host-apiproxy`. They require `agents`, `llm`, `sessionPersistence`, `agentDefaultModel`, `attachments`, `sessionQuery`, or `workspaceRegistry`.

This is the precise DR-018 blocker: the stock web bundle is not a UI-only host. Disabling the model/session plane breaks the API/UI dependency graph, while leaving it enabled exposes a model route. A reviewed upstream fork or isolated web-client/bridge that supplies a separate Command Center channel without these required services is necessary. Provider calls, credential access, non-loopback network, and external effects are **UNVERIFIED/BLOCKED**, not PASS claims; the target deny-overlay never booted.

## Reproduction manifest

Machine-readable evidence is stored in [live-attempt-2026-08-19.json](../../deploy/deepseek-harness/probe/live-attempt-2026-08-19.json).

The pinned-source pre-build verifier passed with `7466 typed entries`, lifecycle allow-list empty, and the following digests: `LOCK.json=5e9df9b0aab70e20fc99dd47fce7b8396caeaf4276ac232441745d2f78a3e4bb`, `package.json=d1c81c2fa4a68c5aa4092122bed6160b2e245451260d630a70dba4f282c65f34`, `pnpm-lock.yaml=f517dc3978d57531cda747df62a2abdde1df5b9f25415fcf1fc5d51f8b7547ea`, `pnpm-workspace.yaml=39d569ce64de5fcfff5db3467304d143bbc6816c03442357af854827f3718f5f`, `SOURCE-MANIFEST.sha256=3a5895683e5f2bf3bb9e19cfa9fdc7f939e786fd927aeca7abad95f71337b2c6`.

Environment: Node `v24.18.1`, Corepack `0.35.0`, exact pnpm `11.7.0`. Commands in the isolated copy were `pnpm install --frozen-lockfile --ignore-scripts`, `pnpm run build:lib`, `pnpm run build:web`, `pnpm dsh web --host 127.0.0.1 --port 4173`, and, from the isolated web-app directory, `node scripts/dsh-ui-probe-browser.mjs http://127.0.0.1:4173`. Install, library build, web build, standard boot, and browser capture exited 0; the custom deny-overlay boot exited 1 with the pending-service list above. Generated `node_modules`, `lib`, `dist`, browser profile, and temporary DSH home were kept outside the repository under `/private/tmp`; no generated output is evidence of a source change.
