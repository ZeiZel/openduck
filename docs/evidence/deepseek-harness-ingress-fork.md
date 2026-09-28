# DeepSeek Harness ingress fork — WO-03

Status: `BOUNDED_FAIL_CLOSED` (2026-08-19)

The patch series targets only DSH `dsh-v0.1.0-rc.7` at commit
`99f6f02fecdb7dff40c3fbc9470f5907c29f74ca`. It is applied to a copied source
tree by [`scripts/dsh-apply-patches.sh`](../../scripts/dsh-apply-patches.sh).
The script rejects any other commit, never downloads dependencies, does not run
package lifecycle scripts, and leaves the pinned source untouched.

## Patch series

1. `0001-admission-module.patch` preserves the original host guard for the
   pinned API entry points; `0006` moves the authoritative receipt logic to
   the session package so ACP, the direct append seam, and the agent loop share
   one implementation.
2. `0002-api-ingress-guard.patch` gates prompt, fork, and queue mutation before
   agent resolution, attachment persistence, inbox splice, or model dispatch.
3. The lowest durable inbox mutation seam is guarded in `0006` at
   `Session.append`; it carries the typed receipt rather than a Boolean permit.
4. `0005-final-model-egress.patch` adds the final `llm.stream` gate in the
   upstream `dsh-agent-loop`; omitted Controller wiring rejects model egress.
5. `0006-core-admission-wiring.patch` validates parseable bounded proof times,
   exact target/session/content/policy/runtime digests, injected signature
   verification, and a shared max-one-use ledger. It denies raw ACP content
   before `saveImages`, seed/import/resume/fork reconstruction in `Session`,
   direct user/inbox append, tool results outside an admitted turn, and final
   model dispatch without the same receipt-bound user content. It also guards
direct `assistant/message` append, because that durable event is model-visible
on a later step; only the model dispatch that consumed the session receipt
may append it. Dispatch authorization is one-use: one assistant event is
permitted, and tool results must consume an exact model-issued tool-call id;
the authorization is removed after the expected events or turn end.

6. `0007-call-scoped-model-append.patch` replaces that session-wide state with
   a private-symbol-branded capability minted by the successful
   `consumeModelAdmission` call. AgentLoop carries the opaque value only to
   the exact assistant append and then to exact tool-result appends. An
   `AsyncLocalStorage` context is installed solely around those synchronous
   internal calls; public `Session.append` has neither the value nor the
   context, including while `llm.stream` is active. The capability is identity
   checked against the dispatch and each expected tool-call id is consumed.

The guarded ingress matrix is: prompt, steer, followup, subagent, attachment,
import, resume, fork, scheduled job, background job, tool-context injection,
plugin call, and internal inbox mutation.

## Evidence

The patched upstream check runs in the applied DSH tree. It exercises the actual
`AdmissionLedger`, direct append and seed guards, and model gate, including
forged signature, malformed/expired/overlong time window, digest mismatch, and
replay. Thirteen concrete producer closures invoke those installed guards for
prompt/queue-like append, direct append, seed/import/resume/fork/subagent,
attachment, schedule/background, tool-context/plugin, and final model cases;
each observes zero durable-sequence, blob, and model counters on denial.
The test additionally stages a pending receipt for a different session/content
and proves that it cannot authorize a direct `assistant/message` injection.
It also consumes a legitimate dispatch, then proves that a second assistant
append and an arbitrary tool result in that same session are both denied.
Run:

```sh
scripts/dsh-apply-patches.sh \
  --source third_party/deepseek-harness \
  --destination /private/tmp/dsh-wo03-check \
  --check
```

Observed result: `WO-03 core admission PASS (signature, expiry, digest,
one-use receipt, append, model gate)`.

On 2026-08-19, the series was also applied directly to the disposable WO04
dependency tree at `/private/tmp/dsh-wo04-live.ZPXz5d/source` after every patch
matched with `--dry-run`; a reversible archive of original target files was
kept at `/private/tmp/dsh-wo04-wo03-backup/target-files.tar`. The focused
TypeScript checks for `dsh-session`, `dsh-agent-loop`, `dsh-acp`, and
`dsh-host-apiproxy` passed after rebuilding the affected session declarations,
and the complete `pnpm typecheck` passed.

The `assistant/message` guard and unrelated-pending-receipt negative case were
added after that run; the same focused checks and complete `pnpm typecheck`
were rerun successfully against the updated disposable tree.

The subsequent call-context P0 closure cleanly reapplied on 2026-08-19:

```sh
scripts/dsh-apply-patches.sh \
  --source third_party/deepseek-harness \
  --destination /private/tmp/dsh-wo03-callcap-replay \
  --check
```

It exited `0` and emitted the core-admission PASS line. The new fixture creates
an admitted dispatch, attempts a plugin-facing assistant append before the
AgentLoop-owned append (denied), allows the branded internal assistant append,
then denies forged tool ids and a replay of the genuine tool id. In the WO04
dependency tree, the exact direct checks also exited `0`:

```sh
node --experimental-strip-types packages/core/session/tests/openduck-admission.spec.ts
./node_modules/.bin/tsc -p packages/core/session/tsconfig.json
./node_modules/.bin/tsc --noEmit -p packages/core/agent-loop/tsconfig.json
```

`pnpm --filter @deepseek-ai/dsh-session exec tsc -p tsconfig.json` was not a
PASS for this final rerun: Corepack refused pnpm 11.7.0 because its registry
signature fetch could not be verified (all of `@pnpm/exe`, `@pnpm/macos-arm64`,
and `pnpm` fetches failed). Thus the evidence deliberately does not claim a
final `pnpm typecheck` after 0007; the direct installed compiler checks above
are the reproducible local result.

Exact disposable-tree commands and results were:

```sh
node --experimental-strip-types packages/core/session/tests/openduck-admission.spec.ts
pnpm --filter @deepseek-ai/dsh-session exec tsc -p tsconfig.json
pnpm --filter @deepseek-ai/dsh-agent-loop exec tsc --noEmit -p tsconfig.json
pnpm --filter @deepseek-ai/dsh-acp exec tsc --noEmit -p tsconfig.json
pnpm --filter @deepseek-ai/dsh-host-apiproxy exec tsc --noEmit -p tsconfig.json
pnpm typecheck
```

All commands exited `0`; the only emitted warnings were expected unsupported
Linux-native optional package platform warnings on macOS.

## Explicit integration boundary

This work remains fail-closed. The Controller must inject an
`AdmissionRuntime` containing a persistent `AdmissionLedger`, snapshot digests,
and signature verifier. API, ACP, direct session construction/append, and final
model stream deny without it. Schedule, jobs, hooks, SDK, headless, and
subagent continuation have no bypass around the `Session` seed/append and
`llm.stream` gates. The current fixture proves their shared producers rather
than constructing every full host runtime; an end-to-end fixture for each
assembled transport remains a defence-in-depth follow-up. No credentials,
provider network, real chat data, or external effects are used.
