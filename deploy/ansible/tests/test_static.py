import unittest
import json
import sys
import os
import subprocess
import tempfile
from pathlib import Path


ROOT = Path(__file__).parents[1]
PLAYBOOK = (ROOT / "site.yml").read_text()
sys.path.insert(0, str(ROOT))
from filter_plugins.openduck_diagnostics import safe_error_json, provisioning_verify_v1, readiness_v1, doctor_v1


class AnsibleStaticTests(unittest.TestCase):
    def test_stage_uses_bounded_release_projection(self):
        stage = (ROOT / "roles/stage/tasks/main.yml").read_text()
        defaults = (ROOT / "roles/stage/defaults/main.yml").read_text()
        self.assertIn("openduck_release_input_projection", stage)
        self.assertIn("stage_effective_release_envelope", stage)
        self.assertIn("stage_effective_release_manifest", stage)
        self.assertIn("stage_effective_release_trust_bundle", stage)
        self.assertIn("stage_effective_release_run_id", stage)
        self.assertIn("stage_effective_release_operation", stage)
        self.assertIn("stage_effective_release_activation", stage)
        self.assertIn("stage_release_nonce_store_path", defaults)
        self.assertIn("stage_artifact_set_digest", stage)
        self.assertIn("stage_release_projection.release_version", stage)
        self.assertIn("bin/openduck-installer", stage)
        self.assertNotIn("openduck_manifest_entries", stage)
        self.assertNotIn("openduck_artifacts:", stage)
        self.assertNotIn("from_json", stage)
        for playbook in (PLAYBOOK, (ROOT / "rollback.yml").read_text()):
            self.assertIn('release_id: "{{ stage_release_id }}"', playbook)
            self.assertIn('openduck_release_artifacts: "{{ stage_release_artifacts }}"', playbook)

    def test_stage_preserves_explicit_false_activation_intent(self):
        stage = (ROOT / "roles/stage/tasks/main.yml").read_text()
        example = (ROOT / "vars/example.yml").read_text()
        self.assertIn(
            "release_activation | default(openduck_activate | default(false))",
            stage,
        )
        self.assertNotIn(
            "release_activation | default(openduck_activate | default(false), true)",
            stage,
        )
        self.assertNotIn("openduck_activate:", example)
        self.assertNotIn("openduck_rollback_on_failure:", example)

    def test_privilege_is_declared_per_concrete_task(self):
        """No include/block can silently grant root to a later task."""
        selected = [
            ROOT / "site.yml", ROOT / "rollback.yml", ROOT / "diagnose.yml", ROOT / "recover-partial-install.yml",
            *sorted((ROOT / "roles").glob("*/tasks/*.yml")),
        ]
        try:
            import yaml
        except ImportError as error:
            self.fail("PyYAML is required for privilege static validation: %s" % error)

        metadata = {"name", "when", "tags", "vars", "register", "changed_when", "failed_when", "check_mode", "no_log", "loop", "loop_control", "environment", "any_errors_fatal", "ignore_errors", "delegate_to"}

        def inspect(tasks, path):
            for task in tasks or []:
                self.assertIsInstance(task, dict, path.as_posix())
                for branch in ("block", "rescue", "always"):
                    if branch in task:
                        self.assertIsNot(task.get("become"), True, "%s has block-level become=true" % path)
                        inspect(task[branch], path)
                action = [key for key in task if key not in metadata | {"become", "block", "rescue", "always"}]
                if action:
                    self.assertEqual(len(action), 1, "%s ambiguous task %r" % (path, task.get("name")))
                    if action[0] in {"ansible.builtin.include_role", "ansible.builtin.include_tasks"}:
                        self.assertNotIn("become", task, "%s include carries privilege" % path)
                    else:
                        self.assertIn("become", task, "%s task %r lacks explicit become" % (path, task.get("name")))

        for path in selected:
            document = yaml.safe_load(path.read_text())
            if path.name in {"site.yml", "rollback.yml", "diagnose.yml", "recover-partial-install.yml"}:
                for play in document:
                    inspect(play.get("tasks"), path)
            else:
                inspect(document, path)

    def test_required_roles_are_explicit(self):
        required = {
            "preflight", "stage", "lifecycle", "principals", "layout", "artifacts",
            "ownership", "policy", "launchd", "trusted_helper", "atomic_commit", "activation",
            "readiness", "diagnostics",
        }
        self.assertTrue(all(f"name: {role}" in PLAYBOOK for role in required))

    def test_no_unsafe_execution_modules(self):
        files = list(ROOT.rglob("*.yml")) + list(ROOT.rglob("*.yaml"))
        text = "\n".join(path.read_text() for path in files)
        self.assertNotIn("ansible.builtin.shell", text)
        self.assertNotIn("ansible.builtin.raw", text)
        self.assertNotIn("sudo ", text)
        self.assertNotIn("macos-boundary-install.sh", text)

    def test_only_bounded_roles_have_command_module(self):
        command_files = [path for path in ROOT.rglob("*.yml") if "ansible.builtin.command:" in path.read_text()]
        self.assertEqual(
            {"diagnose" if path.name == "diagnose.yml" else path.parent.parent.name for path in command_files},
            {"lifecycle", "atomic_commit", "readiness", "rollback", "diagnose", "partial_install_recovery", "release_trust_anchor"},
        )

    def test_release_trust_anchor_is_outside_quarantined_install_root(self):
        trust = (ROOT.parents[1] / "internal/macosrelease/trust_anchor.go").read_text()
        role = (ROOT / "roles/release_trust_anchor/defaults/main.yml").read_text()
        recovery = (ROOT.parents[1] / "internal/macosinstall/recovery.go").read_text()
        fixed = "/Library/Application Support/OpenDuck.release-trust.v1.json"
        self.assertIn(fixed, trust)
        self.assertIn(fixed, role)
        self.assertNotIn('/Library/Application Support/OpenDuck/release-trust.v1.json', trust)
        self.assertNotIn('Mkdir("OpenDuck"', trust)
        self.assertNotIn(fixed, recovery)

    def test_partial_install_recovery_is_separate_and_explicit(self):
        playbook = (ROOT / "recover-partial-install.yml").read_text()
        role = (ROOT / "roles/partial_install_recovery/tasks/main.yml").read_text()
        self.assertNotIn("site.yml", playbook)
        self.assertIn("openduck_recovery_confirm", role)
        self.assertIn("openduck_recovery_apply", role)
        self.assertIn("--recover-partial-install", role)
        self.assertIn("--recovery-readiness-sha256", role)
        self.assertIn("openduck-recovery-", role)
        self.assertNotIn("recurse: true", role)
        self.assertIn("not ansible_check_mode", role)
        installer = (ROOT.parents[1] / "internal/macosinstall/recovery.go").read_text()
        self.assertIn("openduck.partial-install-receipt.v1", installer)
        self.assertIn("SourceDevice", installer)
        self.assertIn("SourceInode", installer)
        self.assertIn("syncRecoveryParent", installer)
        self.assertIn("ErrPartialInstallRecoveryUncertain", installer)
        rename = (ROOT.parents[1] / "internal/macosinstall/recovery_rename_darwin.go").read_text()
        self.assertIn("RenameatxNp", rename)
        self.assertIn("RENAME_EXCL", rename)
        self.assertIn("RENAME_NOFOLLOW_ANY", rename)
        self.assertIn("recoveryRenameResolveBeneath", rename)
        self.assertNotIn("parent.Rename(rootName", installer)

    def test_deploy_is_literal_and_convergence_contract_is_present(self):
        text = "\n".join(path.read_text() for path in ROOT.rglob("*.yml"))
        self.assertNotIn("openduck_installer_args", text)
        self.assertNotIn("+ openduck_helper_args", text)
        self.assertNotIn("/bin/{{ openduck_installer_name }}", text)
        self.assertIn("openduck_installer_name == 'openduck-installer'", text)
        self.assertNotIn("openduck_manifest_name", text)
        self.assertIn("- --deploy", text)
        self.assertNotIn("- --apply", text)
        self.assertNotIn("- --stop", text)
        self.assertNotIn("- --activate", text)
        self.assertIn("openduck_release_artifacts", text)
        self.assertNotIn("openduck_artifacts == [", text)
        self.assertIn("--verify-json", text)
        self.assertIn("full", text)

    def test_mutating_installer_commands_bind_typed_manifest_v2_inputs(self):
        try:
            import yaml
        except ImportError as error:
            self.fail("PyYAML is required for command static validation: %s" % error)

        required = {
            "--release-id": "{{ release_id }}",
            "--release-version": "{{ release_version }}",
            "--release-digest": "{{ release_digest }}",
            "--release-envelope": "{{ release_envelope }}",
            "--release-manifest": "{{ release_manifest }}",
            "--release-trust-bundle": "{{ release_trust_bundle }}",
            "--release-nonce-store": "{{ openduck_release_nonce_store_path }}",
            "--binary-dir": "{{ staged_source }}",
        }
        cases = {
            "roles/atomic_commit/tasks/apply.yml": "--deploy",
            "roles/rollback/tasks/main.yml": "--rollback",
        }

        def command_argvs(tasks):
            for task in tasks or []:
                for branch in ("block", "rescue", "always"):
                    yield from command_argvs(task.get(branch))
                command = task.get("ansible.builtin.command")
                if isinstance(command, dict) and isinstance(command.get("argv"), list):
                    yield command["argv"]

        for relative, operation in cases.items():
            path = ROOT / relative
            text = path.read_text()
            self.assertNotIn("openduck_manifest_entries", text, relative)
            self.assertNotIn("selectattr('1'", text, relative)
            self.assertNotIn("map(attribute='0')", text, relative)
            self.assertIn("trusted_helper_digest", text, relative)
            argv = [value for value in command_argvs(yaml.safe_load(text)) if operation in value]
            self.assertEqual(len(argv), 1, relative)
            if operation == "--deploy":
                self.assertTrue(any(str(value).startswith("--activation=") for value in argv[0]), relative)
            for flag, value in required.items():
                self.assertIn(flag, argv[0], "%s lacks %s" % (relative, flag))
                self.assertEqual(argv[0][argv[0].index(flag) + 1], value, "%s binds %s incorrectly" % (relative, flag))

    def test_plan_v2_uses_complete_admission_and_closed_projection(self):
        for relative in ("roles/atomic_commit/tasks/plan.yml",):
            text = (ROOT / relative).read_text()
            self.assertIn("--plan-json", text)
            self.assertIn("openduck_deployment_plan_v2", text)
            self.assertNotIn("from_json", text)
            for flag in ("--activation=", "--release-id", "--release-version", "--release-digest", "--run-id", "--binary-dir", "--release-envelope", "--release-manifest", "--release-trust-bundle", "--release-nonce-store"):
                self.assertIn(flag, text, relative)
        plan = (ROOT / "roles/atomic_commit/tasks/plan.yml").read_text()
        self.assertIn("trusted_helper_path", plan)
        self.assertIn("trusted_helper_digest", plan)
        self.assertIn("ansible.builtin.copy", plan)
        self.assertIn("ansible.builtin.tempfile", plan)
        self.assertNotIn("preflight_log_dir", plan)
        self.assertIn("path: /private/var/run", plan)
        self.assertIn("prefix: openduck-plan-", plan)
        self.assertNotIn("openduck-plan-{{ openduck_effective_run_id }}", plan)
        self.assertIn("root-owned", plan)
        self.assertIn("always:", plan)
        self.assertIn("Remove only validated root-owned PlanV2 handoff before transfer", plan)
        self.assertIn("Remove only validated transferred PlanV2 handoff without privilege", plan)
        self.assertIn("become: false", plan)
        self.assertNotIn('src: "{{ staged_source }}/bin/openduck-installer"', plan)

    def test_plan_handoff_rejects_replacement_concurrency_stale_paths_and_cleanup_masking(self):
        plan = (ROOT / "roles/atomic_commit/tasks/plan.yml").read_text()
        self.assertIn("random", plan)
        self.assertIn("ansible_user_uid | int != 0", plan)
        self.assertIn("atomic_commit_plan_tempdir.path", plan)
        self.assertNotIn("recurse: true", plan)
        self.assertIn("Stat sealed PlanV2 helper without following links", plan)
        self.assertIn("Restat transferred PlanV2 directory and helper as invoking user", plan)
        self.assertIn("not (atomic_commit_plan_user_stats.results[1].stat.islnk", plan)
        self.assertIn("nlink | default(0) | int) == 1", plan)
        self.assertIn("checksum == trusted_helper_digest", plan)
        self.assertIn("inode == atomic_commit_plan_helper_root_stat.stat.inode", plan)
        self.assertIn("failed_when: false", plan)
        self.assertIn("atomic_commit_plan_primary_failure", plan)
        self.assertIn("atomic_commit_plan_cleanup_failed", plan)
        self.assertIn("atomic_commit_plan_dir_transferred", plan)
        self.assertIn("Restat root-owned PlanV2 handoff before pre-transfer cleanup", plan)
        self.assertIn("Restat transferred PlanV2 handoff before unprivileged cleanup", plan)
        self.assertLess(
            plan.index("always:"),
            plan.index("Restat root-owned PlanV2 handoff before pre-transfer cleanup"),
        )

        def assert_lstat_guard_consumed(result, guard_task, sensitive_task):
            result_at = plan.index("register: %s" % result)
            guard_at = plan.index(guard_task, result_at)
            consumed_at = plan.index("%s.stat.isdir" % result, guard_at)
            sensitive_at = plan.index(sensitive_task, consumed_at)
            self.assertLess(result_at, guard_at, result)
            self.assertLess(guard_at, consumed_at, result)
            self.assertLess(consumed_at, sensitive_at, result)

        assert_lstat_guard_consumed(
            "atomic_commit_plan_dir_root_stat",
            "Require newly created root-owned PlanV2 handoff metadata",
            "Copy selected trusted helper into root-owned PlanV2 handoff",
        )
        assert_lstat_guard_consumed(
            "atomic_commit_plan_pretransfer_cleanup_stat",
            "Require intact root-owned PlanV2 handoff before pre-transfer cleanup",
            "Remove only validated root-owned PlanV2 handoff before transfer",
        )
        assert_lstat_guard_consumed(
            "atomic_commit_plan_transferred_cleanup_stat",
            "Require intact transferred PlanV2 handoff before unprivileged cleanup",
            "Remove only validated transferred PlanV2 handoff without privilege",
        )

    def test_apply_and_readiness_cleanup_do_not_mask_primary_failure(self):
        for relative, primary, cleanup in (
            ("roles/atomic_commit/tasks/apply.yml", "atomic_commit_apply_primary_failed", "atomic_commit_apply_cleanup_failed"),
            ("roles/readiness/tasks/main.yml", "readiness_primary_failed", "readiness_cleanup_failed"),
        ):
            text = (ROOT / relative).read_text()
            self.assertIn("failed_when: false", text, relative)
            self.assertIn(primary, text, relative)
            self.assertIn(cleanup, text, relative)
            self.assertLess(text.index("Fail closed while preserving"), text.index("Fail closed on"), relative)

    def test_random_invocation_handoffs_separate_signed_run_id_and_reject_stale_paths(self):
        lifecycle = (ROOT / "roles/lifecycle/tasks/main.yml").read_text()
        rollback_play = (ROOT / "rollback.yml").read_text()
        sanitizer = (ROOT / "roles/diagnostics/tasks/sanitize_helper_error.yml").read_text()
        for text in (lifecycle, rollback_play):
            self.assertIn("ansible.builtin.tempfile", text)
            self.assertIn("path: /private/var/run", text)
            self.assertIn("prefix: openduck-ansible-", text)
            self.assertIn("[a-z0-9_]{6,128}", text)
            self.assertNotIn("openduck-ansible-{{ release_run_id }}", text)
            self.assertNotIn("openduck-ansible-{{ openduck_effective_run_id }}", text)
        self.assertIn("lifecycle_effective_run_id: \"{{ release_run_id }}\"", lifecycle)
        self.assertIn("lifecycle_run_tempdir.path", lifecycle)
        self.assertIn("islnk", lifecycle)
        self.assertIn("gr_name", lifecycle)
        self.assertIn("mode | default('') == '0700'", lifecycle)
        self.assertIn("rollback_run_dir_initial_stat", rollback_play)
        self.assertIn("[a-z0-9_]{6,128}/helper-error", sanitizer)

    def test_random_run_handoff_guards_copies_execution_error_reads_and_cleanup(self):
        def assert_guard_consumed_before(text, result, guard_task, sensitive_task, field="isdir"):
            """A root lstat only counts when its guarded assertion precedes the operation."""
            result_at = text.index("register: %s" % result)
            guard_at = text.index(guard_task, result_at)
            consumed_at = text.index("%s.stat.%s" % (result, field), guard_at)
            sensitive_at = text.index(sensitive_task, consumed_at)
            self.assertLess(result_at, consumed_at, result)
            self.assertLess(result_at, guard_at, "%s must have a post-lstat guard" % result)
            self.assertLess(consumed_at, sensitive_at, "%s must guard %s" % (result, sensitive_task))

        for relative, handoff in (
            ("roles/lifecycle/tasks/main.yml", "lifecycle_run_handoff.path"),
            ("roles/atomic_commit/tasks/apply.yml", "lifecycle_run_handoff.path"),
            ("roles/readiness/tasks/main.yml", "lifecycle_run_handoff.path"),
            ("roles/rollback/tasks/main.yml", "rollback_run_handoff.path"),
        ):
            text = (ROOT / relative).read_text()
            self.assertIn("follow: false", text, relative)
            self.assertIn("nlink", text, relative)
            self.assertIn(
                handoff + " is match('^/private/var/run/openduck-ansible-[a-z0-9_]{6,128}$')",
                text,
                relative,
            )
            self.assertNotIn("openduck-ansible-{{", text, relative)
        site = (ROOT / "site.yml").read_text()
        self.assertIn("failed_when: false", site)
        self.assertIn("openduck_run_cleanup_failed", site)
        self.assertIn("not (openduck_deployment_failed", site)
        self.assertIn("before Apply helper execution", (ROOT / "roles/atomic_commit/tasks/apply.yml").read_text())
        self.assertIn("before scoped verification execution", (ROOT / "roles/readiness/tasks/main.yml").read_text())
        self.assertIn("before installed readiness execution", (ROOT / "roles/readiness/tasks/main.yml").read_text())
        self.assertIn("before helper execution", (ROOT / "roles/rollback/tasks/main.yml").read_text())

        lifecycle = (ROOT / "roles/lifecycle/tasks/main.yml").read_text()
        assert_guard_consumed_before(
            lifecycle, "lifecycle_run_dir_stat", "Require random root-owned invocation handoff metadata",
            "Copy selected trusted helper before pre-mutation root execution"
        )
        assert_guard_consumed_before(
            lifecycle, "lifecycle_preflight_run_dir_stat", "Require intact root-owned invocation handoff before helper execution",
            "Invoke installed helper full verification"
        )

        apply = (ROOT / "roles/atomic_commit/tasks/apply.yml").read_text()
        assert_guard_consumed_before(
            apply, "atomic_commit_apply_run_dir_stat", "Require intact random invocation handoff before Apply helper copy",
            "Copy deploy helper"
        )
        assert_guard_consumed_before(
            apply, "atomic_commit_apply_exec_dir_stat", "Require intact random invocation handoff before Apply helper execution",
            "Run literal sealed deploy operation"
        )
        assert_guard_consumed_before(
            apply, "atomic_commit_apply_cleanup_dir_stat", "Require intact random invocation handoff before Apply helper cleanup",
            "Remove only guarded Apply helper copy"
        )

        readiness = (ROOT / "roles/readiness/tasks/main.yml").read_text()
        assert_guard_consumed_before(
            readiness, "readiness_run_dir_stat", "Require intact random invocation handoff before readiness helper copy",
            "Copy readiness helper to fixed per-run path"
        )
        assert_guard_consumed_before(
            readiness, "readiness_verify_dir_stat", "Require intact random invocation handoff before scoped verification execution",
            "Run read-only scoped verification JSON"
        )
        assert_guard_consumed_before(
            readiness, "readiness_exec_dir_stat", "Require intact random invocation handoff before installed readiness execution",
            "Inspect installed live readiness state after activation"
        )
        assert_guard_consumed_before(
            readiness, "readiness_cleanup_dir_stat", "Require intact random invocation handoff before readiness helper cleanup",
            "Remove only guarded readiness helper copies"
        )

        rollback = (ROOT / "roles/rollback/tasks/main.yml").read_text()
        assert_guard_consumed_before(
            rollback, "rollback_run_dir_stat", "Require intact root-owned random rollback handoff",
            "Copy rollback helper to fixed per-run path"
        )
        assert_guard_consumed_before(
            rollback, "rollback_exec_dir_stat", "Require intact random rollback handoff before helper execution",
            "Invoke literal rollback without reactivation"
        )
        assert_guard_consumed_before(
            rollback, "rollback_cleanup_dir_stat", "Require intact random rollback handoff before cleanup",
            "Remove only validated random rollback handoff"
        )

        sanitizer = (ROOT / "roles/diagnostics/tasks/sanitize_helper_error.yml").read_text()
        assert_guard_consumed_before(
            sanitizer, "diagnostics_helper_error_dir_stat", "Inspect designated helper error file without following links",
            "Require bounded root-owned helper error file before reading"
        )
        assert_guard_consumed_before(
            sanitizer, "diagnostics_helper_error_stat", "Require bounded root-owned helper error file before reading",
            "Read only an exact bounded designated helper error channel", field="isreg"
        )
        assert_guard_consumed_before(
            site, "openduck_run_cleanup_dir_stat", "Require intact random invocation handoff before final cleanup",
            "Remove only validated random invocation handoff directory"
        )

    def test_explicit_rollback_cannot_return_false_success(self):
        text = (ROOT / "rollback.yml").read_text()
        self.assertIn("Require rollback completion", text)
        self.assertIn("rollback_performed | default(false) | bool", text)

    def test_check_mode_does_not_enable_become(self):
        self.assertNotIn('become: "{{ not (ansible_check_mode | default(false) | bool) }}"', PLAYBOOK)
        self.assertNotIn("vars/example.yml", PLAYBOOK)
        self.assertIn("become: false", PLAYBOOK)
        self.assertIn("become: true", PLAYBOOK)
        docs = (ROOT / "README.md").read_text() + (ROOT.parent.parent / "docs/ansible-macos-install.md").read_text()
        self.assertIn("--check ", docs)
        self.assertNotIn("--diff=false", docs)
        self.assertIn("requires become credentials", docs)
        self.assertIn("random", docs)
        config = (ROOT / "ansible.cfg").read_text()
        self.assertIn("become_ask_pass = False", config)
        self.assertNotIn("become_ask_pass = True", config)

    def test_callback_does_not_log_result_payloads(self):
        callback = (ROOT / "callback_plugins/jsonl.py").read_text()
        self.assertIn("result._result", callback)
        self.assertNotIn("stdout", callback)
        self.assertNotIn("stderr", callback)
        self.assertNotIn("invocation", callback)

    def test_helper_error_contract_is_closed_and_commands_use_fixed_flag(self):
        text = "\n".join(path.read_text() for path in ROOT.rglob("*.yml"))
        parser = (ROOT / "roles/diagnostics/tasks/sanitize_helper_error.yml").read_text()
        for operation in ("--deploy", "--rollback", "--verify-json"):
            self.assertIn(operation, text)
        self.assertGreaterEqual(text.count("- --error-json-file"), 3)
        self.assertIn("openduck.provisioning-error.v2", parser)
        self.assertIn("helper_failed_unclassified", parser)
        self.assertIn("diagnostics_effective_run_id", parser)
        self.assertIn("release_digest", parser)

    def test_runtime_command_output_uses_closed_dtos_without_raw_json_filters(self):
        lifecycle = (ROOT / "roles/lifecycle/tasks/main.yml").read_text()
        readiness = (ROOT / "roles/readiness/tasks/main.yml").read_text()
        diagnose = (ROOT / "diagnose.yml").read_text()
        sanitizer = (ROOT / "roles/diagnostics/tasks/sanitize_helper_error.yml").read_text()
        for text in (lifecycle, readiness, diagnose, sanitizer):
            self.assertNotIn("from_json", text)
            self.assertNotIn(".stderr", text)
        self.assertIn(
            "lifecycle_preflight_full_result.stdout | openduck_provisioning_verify_v1",
            lifecycle,
        )
        self.assertIn(
            "readiness_verify_result.stdout | openduck_provisioning_verify_v1",
            readiness,
        )
        self.assertIn(
            "readiness_installed_result.stdout | openduck_readiness_v1",
            readiness,
        )
        self.assertIn(
            "openduck_doctor_result.stdout | default('') | openduck_doctor_v1",
            diagnose,
        )
        self.assertIn("no_log: true", lifecycle)
        self.assertIn("no_log: true", readiness)
        self.assertIn("no_log: true", diagnose)

    def test_helper_execution_never_uses_staged_installer_as_source_or_argv(self):
        executable_roles = (
            "roles/atomic_commit/tasks/plan.yml",
            "roles/atomic_commit/tasks/apply.yml",
            "roles/lifecycle/tasks/main.yml",
            "roles/readiness/tasks/main.yml",
            "roles/rollback/tasks/main.yml",
        )
        for relative in executable_roles:
            text = (ROOT / relative).read_text()
            self.assertNotIn('src: "{{ staged_source }}/bin/openduck-installer"', text, relative)
            self.assertNotIn('- "{{ staged_source }}/bin/openduck-installer"', text, relative)

    def test_trusted_helper_role_has_closed_upgrade_and_bootstrap_authorities(self):
        text = (ROOT / "roles/trusted_helper/tasks/main.yml").read_text()
        for required in (
            "trusted_helper_installed_helper_digest", "configured.release",
            "release-manifest.v2.json", "openduck_bootstrap_helper_path",
            "openduck_bootstrap_helper_sha256", "fresh_bootstrap",
            "installed_upgrade", "trusted_helper_digest",
        ):
            self.assertIn(required, text)
        self.assertIn("not openduck_bootstrap_helper_path.startswith(staged_source ~ '/')", text)
        self.assertIn("not openduck_bootstrap_helper_path.startswith(trusted_helper_root ~ '/')", text)
        self.assertIn("configured.release", text)
        self.assertIn("trusted_helper_bootstrap_contract.path", text)
        self.assertIn("trusted_helper_bootstrap_contract", text)
        self.assertNotIn("staged_source }}/bin/openduck-installer", text)

    def test_diagnostic_projection_is_allowlisted_and_rootless_callback_is_restrictive(self):
        diagnostics = (ROOT / "roles/diagnostics/tasks/main.yml").read_text()
        callback = (ROOT / "callback_plugins/jsonl.py").read_text()
        for field in ("run_id", "release_digest", "phase", "reason_code", "scope", "recovery_state"):
            self.assertIn(field, diagnostics)
            self.assertIn(field, callback)
        self.assertIn("rollback_state", diagnostics)
        self.assertIn("rollback_state", callback)
        self.assertIn("os.umask(0o077)", callback)
        self.assertIn("os.chmod(self._path, 0o600)", callback)
        self.assertNotIn("task_name", callback)
        self.assertNotIn("stdout", callback)
        self.assertNotIn("stderr", callback)
        self.assertIn("diagnostics_effective_error.recovery_state | default('none')", diagnostics)
        self.assertIn("'unavailable'", diagnostics)

    def test_error_contract_golden_fixtures_cover_primary_pf_and_rollback_unavailable(self):
        fixture_dir = ROOT / "tests/fixtures"
        for name, phase, reason, recovery in (
            ("helper_error_pf_failure.json", "activate", "pf_rules_invalid", "manual_review"),
            ("helper_error_rollback_unavailable.json", "activate", "rollback_absent", "rollback_unavailable"),
            ("helper_error_launchd_shutdown_failure.json", "stop", "launchd_shutdown_failed", "manual_review"),
            ("helper_error_rollback_restore_failure.json", "rollback", "rollback_restore_failed", "manual_review"),
            ("helper_error_policy_upgrade_failure.json", "apply", "policy_upgrade_failed", "manual_review"),
            ("helper_error_apply_restore_failure.json", "apply", "apply_restore_failed", "manual_review"),
        ):
            value = json.loads((fixture_dir / name).read_text())
            self.assertEqual(value["schema"], "openduck.provisioning-error.v2")
            self.assertEqual(value["version"], 2)
            self.assertEqual(value["phase"], phase)
            self.assertEqual(value["reason_code"], reason)
            self.assertEqual(value["primary_reason_code"], reason)
            self.assertEqual(value["compensation_reason_code"], "")
            self.assertEqual(value["scope"], "installer")
            self.assertEqual(value["recovery_state"], recovery)

    def test_error_parser_uses_designated_file_and_preserves_primary_error(self):
        parser = (ROOT / "roles/diagnostics/tasks/sanitize_helper_error.yml").read_text()
        rollback = (ROOT / "roles/rollback/tasks/main.yml").read_text()
        self.assertIn("ansible.builtin.slurp", parser)
        self.assertIn("diagnostics_helper_error_path", parser)
        self.assertNotIn(".stderr", parser)
        self.assertNotIn("openduck_helper_result.stdout", parser)
        self.assertIn("ansible.builtin.assert", parser)
        self.assertIn("failed_when: false", parser)
        self.assertNotIn("rescue:", parser)
        self.assertIn("rollback_primary_helper_error", rollback)
        self.assertIn("rollback_error", rollback)
        self.assertIn("rollback_target_present", rollback)
        for path in ROOT.rglob("*.yml"):
            text = path.read_text()
            self.assertNotIn("openduck_helper_result", text, path.as_posix())

    def test_error_allowlist_matches_current_go_constants(self):
        parser = (ROOT / "roles/diagnostics/tasks/sanitize_helper_error.yml").read_text()
        for value in (
            "pf_rules_invalid", "pf_load_failed", "pf_restore_failed",
            "launchd_enable_failed", "launchd_bootstrap_failed",
            "launchd_kickstart_failed", "launchd_health_failed",
            "launchd_shutdown_failed",
            "rollback_restore_failed",
            "policy_upgrade_failed", "apply_restore_failed",
            "rollback_absent", "rollback_unverified", "rollback_plist_unavailable",
            "stop_required", "verification_failed", "provisioning_failed",
            "deploy", "plan", "finalize", "installer", "retry_safe", "manual_review",
        ):
            self.assertIn(value, parser)

    def test_verify_json_scope_value_cannot_consume_error_flag(self):
        for relative in (
            "roles/lifecycle/tasks/main.yml",
            "roles/readiness/tasks/main.yml",
        ):
            text = (ROOT / relative).read_text()
            self.assertIn("- --verify-json=full", text)
            self.assertNotIn("- --verify-json\n          - --error-json", text)

    def test_installed_readiness_is_hash_pinned_before_execution(self):
        readiness = (ROOT / "roles/readiness/tasks/main.yml").read_text()
        self.assertIn("checksum_algorithm: sha256", readiness)
        self.assertIn("bin/openduck-readiness", readiness)
        self.assertIn("readiness_installed_helper_stat.stat.checksum", readiness)

    def test_standalone_doctor_executes_only_a_manifest_bound_installed_helper(self):
        diagnose = (ROOT / "diagnose.yml").read_text()
        self.assertIn("configured.release", diagnose)
        self.assertIn("release-manifest.v2.json", diagnose)
        self.assertIn("checksum_algorithm: sha256", diagnose)
        self.assertIn("openduck_doctor_readiness_digest", diagnose)
        self.assertIn("openduck_doctor_helper.stat.checksum == openduck_doctor_readiness_digest", diagnose)
        self.assertIn("Run bounded doctor JSON only from a verified installed helper", diagnose)
        self.assertIn("when: openduck_doctor_safe | bool", diagnose)
        self.assertIn("installed_readiness_helper_or_manifest_unsafe", diagnose)
        self.assertIn("invalid_doctor_projection", diagnose)
        self.assertNotIn("from_json", diagnose)
        for forbidden in ("--deploy", "--rollback", "--activate", "--repair", "--login"):
            self.assertNotIn(forbidden, diagnose)
        self.assertNotIn("ansible.builtin.uri", diagnose)
        self.assertNotIn("ansible.builtin.get_url", diagnose)
        docs = (ROOT.parent.parent / "docs/ansible-macos-install.md").read_text()
        self.assertIn("single-link", docs)
        self.assertIn("bounded unavailable posture", docs)

    def test_legacy_preflight_does_not_require_new_error_flag(self):
        lifecycle = (ROOT / "roles/lifecycle/tasks/main.yml").read_text()
        self.assertIn("- --verify-json=full", lifecycle)
        self.assertNotIn("- --error-json", lifecycle)
        parser = (ROOT / "roles/diagnostics/tasks/sanitize_helper_error.yml").read_text()
        self.assertIn("openduck_safe_error_json", parser)
        self.assertIn("safe_error_json", parser)
        for fixture in ("legacy_helper_empty.stderr", "legacy_helper_text.stderr"):
            raw = (ROOT / "tests/fixtures" / fixture).read_text()
            self.assertFalse(raw.strip().startswith("{"), fixture)

    def test_bounded_error_filter_is_quiet_for_legacy_and_malformed_inputs(self):
        valid = json.dumps({"schema": "openduck.provisioning-error.v2"})
        cases = [None, "", "legacy helper failed", "{bad", "[]", valid + "x", "{" + ("x" * 5000) + "}"]
        for value in cases:
            self.assertEqual(safe_error_json(value), {})
        self.assertEqual(safe_error_json(valid)["schema"], "openduck.provisioning-error.v2")
        self.assertEqual(safe_error_json("\ud800"), {})
        self.assertEqual(safe_error_json(valid, 0), {})
        self.assertEqual(safe_error_json(valid, True), {})
        self.assertEqual(safe_error_json(valid, "invalid"), {})

    def test_duplicate_helper_error_keys_fall_back_without_raw_projection(self):
        duplicate = ('{"schema":"openduck.provisioning-error.v2",'
                     '"reason_code":"pf_load_failed",'
                     '"reason_code":"attacker_controlled"}')
        self.assertEqual(safe_error_json(duplicate), {})
        self.assertNotIn("attacker_controlled", json.dumps(safe_error_json(duplicate)))
        sanitizer = (ROOT / "roles/diagnostics/tasks/sanitize_helper_error.yml").read_text()
        self.assertIn("reason_code: helper_failed_unclassified", sanitizer)
        self.assertNotIn("diagnostics_helper_error_candidate |", sanitizer)

    def test_verify_readiness_and_doctor_dtos_fail_closed_without_raw_payloads(self):
        contaminated = [None, "", "{bad", "{}x", "x" * 70000]
        for value in contaminated:
            self.assertEqual(provisioning_verify_v1(value)["available"], False)
            self.assertEqual(readiness_v1(value)["available"], False)
            self.assertEqual(doctor_v1(value)["available"], False)
        self.assertEqual(readiness_v1("state=READY\nreason=all good\nnext=READY\n")["state"], "READY")
        self.assertFalse(readiness_v1("state=READY\nreason=bad\\nraw\nnext=READY\n")["available"])

    def test_provider_daemon_role_is_inactive_contract_only(self):
        role = (ROOT / "roles/provider_daemons/tasks/main.yml").read_text()
        self.assertIn("provider_daemon", role)
        self.assertIn("provider_topology", role)
        self.assertIn("activation_state: inactive", role)
        self.assertIn("principals_provisioned: false", role)
        for forbidden in ("ansible.builtin.command", "ansible.builtin.shell", "launchctl", "dseditgroup", "socket", "uri:"):
            self.assertNotIn(forbidden, role)

    def test_provider_attestor_is_manifest_bound_and_diagnosed_without_execution(self):
        diagnose = (ROOT / "diagnose.yml").read_text()
        self.assertIn("bin/openduck-provider-attestor", diagnose)
        self.assertIn(".openduck-provider-attestor", diagnose)
        self.assertIn("openduck_doctor_attestor_safe", diagnose)
        self.assertIn("bin/openduck-native-mcp", diagnose)
        self.assertIn("openduck_doctor_native_mcp_safe", diagnose)
        self.assertNotIn('"{{ openduck_provider_attestor_path }}"\n          -', diagnose)

    def test_doctor_accepts_only_allowlisted_provider_reason_codes(self):
        report = {"schema": "openduck.doctor.v1", "version": 1, "platform": "darwin", "arch": "arm64",
                  "fixed_root": {"fixed": True, "safe_directory": True},
                  "markers": {"candidate": True, "configured": True, "active": True, "activated": True,
                              "activation_intent": False, "failed": False, "rolled_back": False, "manifest": True},
                  "gates": {"configuration_converged": "observed", "activation_complete": "observed",
                            "operational_ready": "unavailable", "operator_gate": "required"},
                  "reason_codes": ["provider_daemon_identity_unverified"]}
        self.assertTrue(doctor_v1(json.dumps(report))["available"])
        report["reason_codes"] = ["raw_provider_output"]
        self.assertFalse(doctor_v1(json.dumps(report))["available"])

    def test_sanitizer_dynamic_mini_playbook_has_quiet_fallbacks(self):
        digest = "a" * 64
        # The designated channel is intentionally rooted in /private/var/run
        # and must not be fabricated by an unprivileged test. Exact accepted
        # JSON and malformed legacy inputs are exercised directly through the
        # closed filter above. Ansible 14 executes task queues through an
        # in-process local RPC server, which is deliberately unavailable in
        # sandboxed test runners; syntax-check still proves this exact include
        # and its bounded variables remain parseable without executing tasks.
        include_path = ROOT / "roles/diagnostics/tasks/sanitize_helper_error.yml"
        playbook = """---
- hosts: localhost
  gather_facts: false
  connection: local
  vars:
    diagnostics_effective_run_id: aaaaaaaa-1111
    release_digest: %s
    diagnostics_helper_phase: activate
    diagnostics_run_dir: ''
    diagnostics_helper_error_path: ''
  tasks:
    - include_tasks: %s
    - debug:
        var: diagnostics_helper_error
""" % (digest, str(include_path))
        with tempfile.TemporaryDirectory(prefix="openduck-ansible-sanitizer-") as tempdir:
            temp_path = Path(tempdir)
            playbook_path = temp_path / "sanitizer.yml"
            playbook_path.write_text(playbook)
            env = dict(
                os.environ,
                ANSIBLE_CONFIG=str(ROOT / "ansible.cfg"),
                ANSIBLE_LOCAL_TEMP=str(temp_path / "local"),
                ANSIBLE_REMOTE_TEMP=str(temp_path / "remote"),
            )
            result = subprocess.run(
                ["ansible-playbook", "--syntax-check", "-i", "localhost,", str(playbook_path)],
                cwd=ROOT,
                env=env,
                text=True,
                capture_output=True,
                check=False,
                timeout=60,
            )
            output = result.stdout + result.stderr
            self.assertEqual(result.returncode, 0, output)
            self.assertIn("playbook", output)


if __name__ == "__main__":
    unittest.main()
