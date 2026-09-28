# 12. Review и подготовка проектов

## Review intake

Review target задаётся immutable review-profile `AgentRunOrder.v1` tuple: repository/project, resolved target/base commits, diff digest, TaskSpec/acceptance and prior-evidence digests, input/finding/`ReviewVerdict` schemas, checks allowlist, independence constraints, read/test capabilities, separate network policy and deadline. Matching `RunDispatchBinding` связывает exact order hash, reviewer role/runtime attestation and expected evidence schema. Review/Luna/general DAG не используют implementation `WorkOrder.v1`; branch/chat link без resolved commit/diff недостаточны.

## Review workflow

1. Read-only resolve target and base; attest current repository/worktree.
2. Gather spec, changed files, relevant tests/contracts and previous findings.
3. Risk-based analysis: correctness, security/privacy, concurrency, data loss, compatibility, observability and tests.
4. Run only approved non-mutating checks; build/test commands with expected workspace writes must be declared.
5. Produce findings with severity, exact location, evidence and remediation; no praise-only filler.
6. Verify fixes in a clean independent context and return `ReviewVerdict`.
7. Publishing comment/approval/merge is a separate provider effect, disabled by default.

## Project preparation

`prepare project` означает project-preparation-profile `ReadOrder.v1` + `RunDispatchBinding`, которые bind’ят repository identity, requested base, observed branch/HEAD/dirty-state digest, instruction/policy digest, read roots/probe allowlist, output schema and `ProjectPreparationEvidence`. Это candidate plan:

- locate repo and instructions; load scoped memory;
- inspect branch/base/dirty state and repository rules;
- select isolated worktree/task branch for specification/feature work;
- identify toolchains/dependencies, credentials by reference, services, ports and MCPs;
- run read-only doctor/version/capability probes;
- propose exact dependency install/service start/config mutations;
- define canonical verification and rollback;
- create TaskSpec/WorkOrder only after scope/authority known.

No command in a chat/source is trusted. ReadOrder не содержит install/start/write/git-effect verbs. Dependency install, network download, service start, new OAuth, git commit/push/MR and destructive cleanup требуют нового implementation/effect order по existing approval policy.

## Workspace isolation

- primary dev/main tree is not switched to feature branch;
- unrelated dirty state is preserved;
- worktree path/repo/base/branch bound into WorkOrder and runtime attestation;
- workers know they share codebase and may not revert others;
- write roots, network domains, commands and timeouts are explicit;
- result includes git diff/check evidence, not only narrative.

## EvidenceBundle minimum

Order kind/hash, `RunDispatchBinding`/runtime-attestation hashes, bound input/output/evidence schema digests, spec/work hashes where applicable, target before/after, changed files, command/test results with exit status, skipped checks with reason, logs/artifacts by ref, dependency/SBOM delta, residual risks and rollback status. Secrets/raw PD are redacted before bundle assembly.

## Acceptance

Codex root may recommend accept/rework, but Controller validates hashes, required checks, reviewer independence, unresolved findings and owner policy before transition. Completion does not imply commit/push/deploy/provider update.
