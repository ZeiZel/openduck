import json
import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).parents[3]
SCRIPT = ROOT / "scripts/verify-ansible-p5.sh"


class AnsibleP5CITests(unittest.TestCase):
    def test_matrix_is_disposable_arm64_and_intel_is_decision_required(self):
        matrix = json.loads((ROOT / "deploy/ansible/ci/macos-vm-matrix.json").read_text())
        self.assertTrue(matrix["disposable"])
        self.assertEqual(matrix["architectures"], ["arm64"])
        self.assertEqual(matrix["intel"]["status"], "decision_required")
        self.assertEqual(
            {scenario["name"] for scenario in matrix["scenarios"]},
            {"fresh", "idempotent", "upgrade", "injected_failure", "rollback", "retry", "concurrent", "two_daemon_inactive_contract", "provider_attestor_restart_substitution_rollback"},
        )

    def test_gate_has_doctor_and_ci_modes_without_mutation_commands(self):
        text = SCRIPT.read_text()
        self.assertIn("--ci", text)
        self.assertIn("--doctor", text)
        self.assertIn("yamllint", text)
        self.assertIn("ansible-lint", text)
        self.assertIn("ansible: syntax checks", text)
        self.assertIn("--syntax-check", text)
        self.assertIn("--inventory localhost,", text)
        self.assertIn("mktemp -d", text)
        self.assertIn('"$P5_TMP" != /', text)
        self.assertIn('find "$P5_TMP" -depth -delete', text)
        for playbook in ("site.yml", "rollback.yml", "diagnose.yml", "recover-partial-install.yml"):
            self.assertIn("run_syntax_check " + playbook, text)
        self.assertIn("secret canary", text)
        self.assertNotIn("sudo", text.lower())
        self.assertNotIn("curl ", text)
        self.assertNotIn("ssh ", text)
        self.assertNotIn("rm -", text)

    def test_ci_mode_fails_when_required_tool_is_missing(self):
        result = subprocess.run(
            [str(SCRIPT), "--ci"],
            cwd=ROOT,
            env={"PATH": "/usr/bin:/bin"},
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("missing required tools", result.stderr)

    def test_local_mode_fails_closed_when_required_tool_is_missing(self):
        result = subprocess.run(
            [str(SCRIPT)],
            cwd=ROOT,
            env={"PATH": "/usr/bin:/bin"},
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 3)
        self.assertIn("verification incomplete", result.stderr)

    def test_doctor_mode_reports_missing_tools_without_running_mutations(self):
        result = subprocess.run(
            [str(SCRIPT), "--doctor"],
            cwd=ROOT,
            env={"PATH": "/usr/bin:/bin"},
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn("doctor:", result.stdout)

    def test_canonical_gate_invokes_three_non_mutating_syntax_checks(self):
        with tempfile.TemporaryDirectory() as tempdir:
            fake_bin = Path(tempdir) / "bin"
            fake_bin.mkdir()
            capture = Path(tempdir) / "ansible-playbook.args"

            def fake_tool(name, body):
                path = fake_bin / name
                path.write_text("#!/bin/sh\n" + body + "\n")
                path.chmod(path.stat().st_mode | stat.S_IXUSR)

            fake_tool("ansible-playbook", 'printf "%s\\n" "$*" >> "$P5_CAPTURE"')
            for name in ("python3", "ansible-lint", "yamllint", "go"):
                fake_tool(name, "exit 0")
            fake_tool("rg", "exit 1")
            env = dict(os.environ, PATH=str(fake_bin) + ":/usr/bin:/bin", P5_CAPTURE=str(capture))
            result = subprocess.run(
                [str(SCRIPT)], cwd=ROOT, env=env, text=True, capture_output=True, check=False
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            calls = capture.read_text().splitlines()
            self.assertEqual(len(calls), 4)
            for call, playbook in zip(calls, ("site.yml", "rollback.yml", "diagnose.yml", "recover-partial-install.yml")):
                self.assertIn("--syntax-check", call)
                self.assertIn("--inventory localhost,", call)
                self.assertIn("--connection local", call)
                self.assertIn(playbook, call)
                self.assertNotIn("--ask-become-pass", call)
            for call in calls[:2]:
                self.assertIn("release_digest=" + ("a" * 64), call)
                self.assertIn("staged_source=/private/tmp/openduck-p5-stage", call)
            self.assertIn("openduck_recovery_confirm=quarantine-partial-install-v1", calls[3])
            self.assertNotIn("openduck_recovery_apply=true", calls[3])
            self.assertIn("openduck_recovery_readiness_sha256=" + ("c" * 64), calls[3])
            self.assertNotIn("--check", "\n".join(calls))


if __name__ == "__main__":
    unittest.main()
