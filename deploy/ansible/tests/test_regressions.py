import json
import os
import re
import subprocess
import unittest
from pathlib import Path

import yaml


ROOT = Path(__file__).parents[1]


def tasks(path):
    return yaml.safe_load(path.read_text())


def flatten(items):
    for item in items or []:
        yield item
        for branch in ("block", "rescue", "always"):
            yield from flatten(item.get(branch, []))


class HistoricalRegressionTests(unittest.TestCase):
    def test_fixture_catalog_is_closed_and_deterministic(self):
        value = json.loads((ROOT / "tests/fixtures/regression_cases.json").read_text())
        self.assertEqual(value["schema"], "openduck.ansible.regression-fixtures.v1")
        self.assertEqual(
            [case["name"] for case in value["cases"]],
            ["dseditgroup_exit_67", "unsafe_root_and_paths", "stale_key_ownership",
             "primary_compensation_separation", "activation_false_scoped_verify",
             "release_replay_and_signature"],
        )

    def test_unsafe_root_and_stage_inputs_are_structured_assertions(self):
        site = yaml.safe_load((ROOT / "site.yml").read_text())
        stage = tasks(ROOT / "roles/stage/tasks/main.yml")
        site_asserts = [task for play in site for task in flatten(play.get("tasks", [])) if "ansible.builtin.assert" in task]
        self.assertTrue(any("openduck_root == '/Library/Application Support/OpenDuck'" in str(task) for task in site_asserts))
        stage_asserts = [task for task in flatten(stage) if "ansible.builtin.assert" in task]
        self.assertTrue(any("staged_source is match('^/')" in str(task) for task in stage_asserts))
        self.assertTrue(any("not stage_source_stat.stat.islnk" in str(task) for task in stage_asserts))

    def test_stale_key_ownership_has_no_adhoc_mutation(self):
        ownership = tasks(ROOT / "roles/ownership/tasks/main.yml")
        actions = [key for task in flatten(ownership) for key in task if key.startswith("ansible.builtin.")]
        self.assertEqual(actions, ["ansible.builtin.set_fact", "ansible.builtin.assert"])

    def test_primary_failure_and_compensation_are_separate_facts(self):
        rollback = tasks(ROOT / "roles/rollback/tasks/main.yml")
        assignments = [task["ansible.builtin.set_fact"] for task in flatten(rollback) if "ansible.builtin.set_fact" in task]
        merged = " ".join(str(value) for value in assignments)
        self.assertIn("rollback_primary_helper_error", merged)
        self.assertIn("rollback_error", merged)
        diagnostics = (ROOT / "roles/diagnostics/tasks/main.yml").read_text()
        self.assertIn("primary_reason_code:", diagnostics)
        self.assertIn("compensation_reason_code:", diagnostics)

    def test_activation_false_is_passed_as_typed_deploy_input(self):
        apply = tasks(ROOT / "roles/atomic_commit/tasks/apply.yml")
        commands = [task["ansible.builtin.command"]["argv"] for task in flatten(apply) if "ansible.builtin.command" in task]
        deploy = next(argv for argv in commands if "--deploy" in argv)
        self.assertIn("--activation={{ 'true' if (openduck_activate | bool) else 'false' }}", deploy)
        lifecycle = (ROOT / "roles/lifecycle/tasks/main.yml").read_text()
        self.assertIn("not openduck_activate", lifecycle)
        self.assertIn("lifecycle_full_verify_ok", lifecycle)

    def test_release_projection_exposes_typed_facts_and_fixed_nonce(self):
        stage = (ROOT / "roles/stage/tasks/main.yml").read_text()
        self.assertIn("openduck_release_input_projection", stage)
        self.assertIn("stage_release_projection.artifact_set_digest", stage)
        self.assertIn("stage_release_projection.release_version", stage)
        self.assertIn("stage_release_nonce_store_path", stage)

    def test_gap_pf_policy_compensation(self):
        pattern = "^(TestApplyAtomicallyMigratesLegacySharedPolicies|TestFailedApplyRestoresLegacyPoliciesAndRemovedMarkersExactly|TestApplyCompensationFailureIsManualReview|TestActivationErrorSchemaPreservesPrimaryAndCompensationReasons|TestFinalizeCompensationRetainsLeaseOnPFRestoreOrReleaseFailure)$"
        result = subprocess.run(
            ["go", "test", "-count=1", "-run", pattern, "./internal/macosinstall"],
            cwd=ROOT.parent.parent,
            env={**os.environ, "GOCACHE": "/private/tmp/openduck-macosinstall-cache"},
            text=True,
            capture_output=True,
            timeout=150,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_var_run_handoffs_are_regrouped_before_root_wheel_assertion(self):
        # macOS gives a new directory the group of its parent, and
        # /private/var/run is root:daemon. Every handoff allocated there must be
        # normalized to root:wheel explicitly, or the root:wheel assertion that
        # follows can never pass.
        for role in ("release_trust_anchor", "partial_install_recovery", "lifecycle"):
            items = list(flatten(tasks(ROOT / "roles" / role / "tasks/main.yml")))
            allocations = [
                (index, item)
                for index, item in enumerate(items)
                if item.get("ansible.builtin.tempfile", {}).get("path") == "/private/var/run"
            ]
            self.assertTrue(allocations, role)
            for index, item in allocations:
                variable = item["register"]
                normalizers = [
                    later
                    for later in items[index + 1:]
                    if later.get("ansible.builtin.file", {}).get("path") == "{{ %s.path }}" % variable
                ]
                self.assertTrue(normalizers, f"{role}: {variable} is never regrouped")
                normalizer = normalizers[0]["ansible.builtin.file"]
                self.assertEqual(normalizer["owner"], "root", role)
                self.assertEqual(normalizer["group"], "wheel", role)
                self.assertEqual(normalizer["mode"], "0700", role)
                self.assertIs(normalizers[0]["become"], True, role)

    def test_every_openduck_variable_read_has_a_definition(self):
        # Undefined variables survive --syntax-check and surface only as a
        # runtime crash under sudo, one role at a time. openduck_log_dir,
        # openduck_rollback_on_failure and openduck_release_projection each
        # reached an operator that way. Definitions are collected generously;
        # only reads with no definition anywhere are reported.
        defined = set()
        for plugin in ROOT.glob("filter_plugins/*.py"):
            defined |= set(re.findall(r"""["']([a-z][a-z0-9_]*)["']\s*:""", plugin.read_text()))

        def collect(node):
            if isinstance(node, dict):
                for key, value in node.items():
                    if key.split(".")[-1] in ("set_fact", "vars") and isinstance(value, dict):
                        defined.update(value)
                    if key == "register" and isinstance(value, str):
                        defined.add(value)
                    if key == "loop_control" and isinstance(value, dict):
                        defined.update(str(v) for v in value.values())
                    collect(value)
            elif isinstance(node, list):
                for value in node:
                    collect(value)

        playbooks = [path for path in ROOT.rglob("*.yml") if "tests" not in path.parts]
        for path in playbooks:
            document = yaml.safe_load(path.read_text())
            if document is None:
                continue
            if path.parent.name in ("defaults", "vars") and isinstance(document, dict):
                defined.update(document)
            collect(document)
        defined.update(re.findall(r"([a-z][a-z0-9_]*)=", (ROOT / "../../scripts/deploy-macos.sh").read_text()))

        undefined = []
        for path in sorted(playbooks):
            # A file may read play-scoped openduck_ variables, and a role file
            # may also read its own role-prefixed ones.
            prefixes = ["openduck_"]
            if "roles" in path.parts:
                prefixes.append(path.parts[path.parts.index("roles") + 1] + "_")
            pattern = re.compile(r"\b(?:%s)[a-z0-9_]+\b" % "|".join(prefixes))
            for number, line in enumerate(path.read_text().splitlines(), 1):
                for match in pattern.finditer(line):
                    name, tail = match.group(0), line[match.end():]
                    if name in defined:
                        continue
                    if re.match(r"\s*:", tail):                 # a mapping key, not a read
                        continue
                    if re.match(r"\s*\|\s*default\(", tail):     # explicitly guarded
                        continue
                    undefined.append("%s:%d %s" % (path.relative_to(ROOT), number, name))
        self.assertEqual(undefined, [])

    def test_journal_rehash_and_independent_anchor_are_installer_owned(self):
        """Ansible delegates journal authority rather than emulating it.

        The deploy transaction verifies the sealed installer; the installer
        owns the independent checkpoint/anchor topology and its protected
        checkpoint.  Keep this regression executable so a stale placeholder
        cannot mask a missing adversarial production guarantee.
        """
        pattern = (
            "^(TestJournalAuthorityTopologyRejectsDescriptorReuseAndPinDrift|"
            "TestProtectedCheckpointCoversHistoryAndRejectsRehashedMutation|"
            "TestProvisioningJournalRejectsWrongCheckpointBindingsAndAnchor)$"
        )
        result = subprocess.run(
            ["go", "test", "-count=1", "-run", pattern, "./internal/macosinstall"],
            cwd=ROOT.parent.parent,
            env={**os.environ, "GOCACHE": "/private/tmp/openduck-journal-cache"},
            text=True,
            capture_output=True,
            timeout=150,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
