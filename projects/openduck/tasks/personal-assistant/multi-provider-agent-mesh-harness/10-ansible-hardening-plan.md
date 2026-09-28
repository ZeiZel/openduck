# 10. Ansible hardening plan

`PROPOSAL`: улучшать существующие `preflight`, `stage`, `lifecycle`, `principals`, `layout`, `artifacts`, `ownership`, `policy`, `launchd`, `atomic_commit`, `activation`, `readiness`, `diagnostics`, `rollback` и Go installer. Не создавать второй competing installer.

## A. Read-only diagnosis

1. Добавить `deploy/ansible/diagnose.yml`, совместимый с `--check`, без play-wide `become`.
2. Добавить installer/readiness `--doctor-json` с `openduck.doctor.v1`: platform/arch, fixed-root safety, principals, manifest, candidate/active markers, policy/PF/launchd, auth/provider bundle readiness и four gates.
3. Doctor не чинит state, не грузит launchd/PF, не делает login/network; privileged read task использует exact `become: true`, остальные `false`.
4. Выход sanitized, bounded и secret-canary tested.

## B. Typed errors

1. Общий `openduck.provisioning-error.v2` используется Go helper и Ansible parser.
2. Exact schema: run/release/phase/scope, primary reason, compensation reason, recovery state, safe evidence refs; extra/invalid/malformed/empty/oversize → `helper_failed_unclassified`.
3. Parser читает designated JSON channel/file, а не contaminated stderr; legacy stderr только diagnostic, не authority.
4. PF restore, policy migration, launchd и cleanup сохраняют primary+compensation отдельно.

## C. Per-run transaction journal

1. Run ID — collision-resistant CSPRNG/UUID + release digest prefix, не second-resolution epoch.
2. Exclusive lock создаётся до staging; journal path derived/validated, `0700/0600`, O_APPEND/fsync, monotonic seq/hash chain.
3. После каждой authority phase Controller/trusted helper создаёт `JournalCheckpoint.v1` с run/release, last seq/hash, phase, wall/monotonic time, previous checkpoint digest и HMAC/signature. Signing key находится в protected Controller/Keychain-backed verifier boundary; callback/installer/journal writer не может читать key. Checkpoint anchor хранится вне writable per-run tree в root-owned append-only/CAS store, а digest additionally входит в Controller durable ledger.
4. Verify требует непрерывную chain + latest independently anchored signature. Mutation+rehash journal без verifier key/anchor update обнаруживается. Если protected signer/anchor недоступен, deployment может заявлять только crash-detecting hash chain, но production promotion blocked и термин `tamper-evident` не используется.
5. Typed phases: preflight, stage, plan, configure, activate, verify, commit, compensate, rollback, cleanup.
6. Callback пишет только bounded projection в run-specific journal; общий `run.jsonl` становится optional index без authority.

## D. Plan и manifest v2

1. `--plan-json` валидируется closed schema: exact version/release/run/root, ordered operations, source/target/digest/mode/owner/group, preconditions, rollback/cleanup plan, activation intent.
2. Cross-field checks запрещают path вне fixed root, symlink/hardlink ambiguity, duplicate target, unknown artifact type и digest mismatch.
3. `release.manifest.v2` содержит typed `core`, `provider_runtime`, `provider_plugin`, `policy`, `helper` artifacts с platform/arch/version/digest/required/activation group.
4. Legacy fixed 11-artifact manifest читается только migration window; provider expansion идёт через validator, не arbitrary vars list.
5. Release input обёрнут в `ReleaseEnvelope.v1`: exact envelope/manifest/release digests, platform, architecture, ordered artifact set digest, schema/min-installer version, signer key ID, monotonic sequence/nonce, issued/expiry и signature pinned trusted release key.
6. Controller/trusted installer atomically consumes sequence/nonce before first mutation. Unknown/revoked key, expired/not-yet-valid envelope, replay, manifest/release/platform/arch/artifact mismatch и signature failure reject before privileged copy/chown/apply.

## E. Privilege и variables

1. Удалить play-wide `become`; каждый mutating/read-privileged task declares exact become.
2. `vars/example.yml` не загружается production playbook; required inputs приходят из explicit inventory/extra-vars file, validated до privilege.
3. Fixed root remains non-overridable; unsafe root regression blocks before any filesystem effect.
4. Staged source/keys проверяются lstat/owner/mode/nlink/digest до privileged copy/chown; stale key chown запрещён.

## F. Transaction states и gates

```text
candidate -> configured -> activated -> operational
     |            |            |
   failed ------ rollback ---- rolled-back
```

- `configuration_converged`: files/principals/policies/manifests exact.
- `activation_complete`: active pointer + activated marker + PF/launchd transaction committed.
- `operational_ready`: scoped verify/health passes for enabled components.
- `operator_gate`: login/canary/manual action still required or satisfied.

`active.release` публикуется как commit pointer только после final activated marker/durable state, либо оба меняются в one recoverable transaction. `activation=false` запускает настоящий scoped verify для configured non-active bundle и возвращает evidence, а не debug message.

## G. Compensation и rollback

Cleanup — compensation step с собственным outcome; failure не заменяет primary. Rollback пишет selected target, validation evidence, actions, verify result и `performed|unavailable|failed|rolled_back`. First-install no-target честно `unavailable`; retry requires explicit recovery state. Candidate remnants очищаются только после guarded ownership/path checks.

## H. Regression gates

Обязательные fixtures/tests:

1. `dseditgroup` exit 67 при ambiguous empty/malformed stderr;
2. unsafe fixed root и path traversal/symlink/hardlink;
3. stale key chown/ownership drift;
4. malformed/empty/oversize stderr и typed error JSON;
5. policy migration primary/compensation;
6. PF restore output contaminated stderr;
7. launchd `loaded + disabled` contradictory state;
8. activation primary masked by cleanup/rollback failure;
9. concurrent deployment/run ID collision/lock contention;
10. `activation=false` true scoped verify;
11. manifest v1 migration и v2 provider bundle expansion;
12. journal entry mutation + full local rehash without protected checkpoint key, missing/stale anchor и wrong checkpoint generation;
13. release envelope unknown/revoked key, replayed sequence/nonce, platform/arch/manifest/artifact/digest mismatch, expiry и signature corruption.

## I. CI и macOS verification

- every PR: `ansible-lint`, `yamllint`, JSON schema/contracts, static safety, deterministic simulator, fault injection, secret canaries;
- disposable privileged macOS VM: fresh install, idempotent rerun, upgrade, injected failure, rollback, retry, concurrent attempt;
- Apple Silicon mandatory;
- `DECISION REQUIRED / Operations owner / before production`: Intel supported with identical VM suite or explicitly unsupported with fail-loud preflight.
