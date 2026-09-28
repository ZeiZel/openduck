import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path

from deploy.ansible.filter_plugins.openduck_diagnostics import (
    FIXED_NONCE_STORE,
    ReleaseProjectionError,
    deployment_plan_v2,
    bootstrap_helper_contract,
    installed_manifest_helper_digest,
    release_input_projection,
)


class ReleaseProjectionTests(unittest.TestCase):
    platform = "darwin"
    arch = "arm64"
    target_root = "/Library/Application Support/OpenDuck"
    release_id = "release-20260825"
    release_version = "1.2.3"
    release_digest = "a" * 64
    run_id = "aaaaaaaa-1111"

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.stage = self.root / "stage"
        self.stage.mkdir(mode=0o700)
        self.artifacts = [
            ("core", "bin/controller", b"controller"),
            ("helper", "bin/helper", b"helper"),
            ("provider_runtime", "providers/runtime", b"runtime"),
            ("provider_plugin", "providers/plugin", b"plugin"),
        ]
        manifest_artifacts = []
        for index, (kind, path, body) in enumerate(self.artifacts):
            target = self.stage / path
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            target.write_bytes(body)
            target.chmod(0o700)
            manifest_artifacts.append({
                "type": kind,
                "path": path,
                "digest": hashlib.sha256(body).hexdigest(),
                "platform": self.platform,
                "arch": self.arch,
                "version": self.release_version,
                "activation_group": "default",
                "required": index == 0,
            })
        self.manifest = {
            "schema": "openduck.release-manifest.v2",
            "release_id": self.release_id,
            "release_digest": self.release_digest,
            "version": self.release_version,
            "target_root": self.target_root,
            "artifacts": manifest_artifacts,
        }
        manifest_digest = self._digest({
            "schema": self.manifest["schema"],
            "release_id": self.manifest["release_id"],
            "release_digest": self.manifest["release_digest"],
            "version": self.manifest["version"],
            "target_root": self.manifest["target_root"],
            "artifacts": manifest_artifacts,
        })
        artifact_set_digest = self._digest(manifest_artifacts)
        self.envelope = {
            "schema": "openduck.release-envelope.v1",
            "key_id": "release-key",
            "manifest_digest": manifest_digest,
            "artifact_set_digest": artifact_set_digest,
            "release_digest": self.release_digest,
            "release_version": self.release_version,
            "target_root": self.target_root,
            "platform": self.platform,
            "arch": self.arch,
            "min_installer": "1.0.0",
            "operation": "deploy",
            "run_id": self.run_id,
            "activation": "false",
            "nonce": "nonce-20260825",
            "signature": "b" * 128,
            "sequence": 1,
            "issued_at": "2026-08-25T10:00:00Z",
            "expires_at": "2026-08-25T11:00:00Z",
        }
        self.trust = {
            "schema": "openduck.release-trust.v1",
            "keys": {"release-key": "c" * 64},
            "revoked": [],
        }
        self.manifest_path = self._write("manifest.json", self.manifest)
        self.envelope_path = self._write("envelope.json", self.envelope)
        self.trust_path = self._write("trust.json", self.trust)

    def tearDown(self):
        self.tmp.cleanup()

    @staticmethod
    def _digest(value):
        return hashlib.sha256(json.dumps(value, separators=(",", ":")).encode()).hexdigest()

    def _write(self, name, value):
        path = self.root / name
        path.write_text(json.dumps(value, separators=(",", ":")))
        path.chmod(0o600)
        return str(path)

    def _project(self, **kwargs):
        args = dict(
            manifest_path=self.manifest_path,
            envelope_path=self.envelope_path,
            trust_path=self.trust_path,
            staged_root=str(self.stage),
            release_id=self.release_id,
            release_version=self.release_version,
            release_digest=self.release_digest,
            target_root=self.target_root,
            platform=self.platform,
            arch=self.arch,
            nonce_store=FIXED_NONCE_STORE,
            operation="deploy",
            run_id=self.run_id,
            activation=False,
        )
        args.update(kwargs)
        return release_input_projection(**args)

    def test_dynamic_manifest_projects_canonically_and_is_not_signature_authority(self):
        result = self._project()
        self.assertEqual([item["type"] for item in result["artifacts"]], [
            "core", "helper", "provider_runtime", "provider_plugin",
        ])
        self.assertEqual(result["nonce_store"], FIXED_NONCE_STORE)
        self.assertEqual(result["artifact_set_digest"], self.envelope["artifact_set_digest"])
        self.assertNotIn("signature_valid", result)
        self.assertNotIn("trusted", result)

    def test_installed_manifest_helper_digest_is_closed_and_exact(self):
        helper_digest = hashlib.sha256(b"installed-helper").hexdigest()
        manifest = {
            "schema": "openduck.release-manifest.v2",
            "release_id": self.release_id,
            "release_digest": self.release_digest,
            "version": self.release_version,
            "target_root": self.target_root,
            "artifacts": [{
                "type": "helper", "path": "bin/openduck-installer",
                "digest": helper_digest, "platform": self.platform,
                "arch": self.arch, "version": self.release_version,
                "activation_group": "default", "required": True,
            }],
        }
        raw = json.dumps(manifest, separators=(",", ":"))
        self.assertEqual(installed_manifest_helper_digest(raw, self.release_id), helper_digest)
        manifest["artifacts"][0]["digest"] = "A" * 64
        with self.assertRaises(ReleaseProjectionError):
            installed_manifest_helper_digest(json.dumps(manifest), self.release_id)
        manifest["artifacts"][0]["digest"] = helper_digest
        manifest["artifacts"].append(dict(manifest["artifacts"][0]))
        with self.assertRaises(ReleaseProjectionError):
            installed_manifest_helper_digest(json.dumps(manifest), self.release_id)

    def test_bootstrap_contract_refuses_missing_partial_overlap_and_bad_digest_before_filesystem(self):
        good_path = str(self.root / "pretrusted-installer")
        good_digest = "a" * 64
        for path, digest in (
            ("", good_digest), (good_path, ""), (good_path, "A" * 64),
            (str(self.stage / "bin/openduck-installer"), good_digest),
            ("/Library/Application Support/OpenDuck/.openduck-installer", good_digest),
        ):
            with self.assertRaises(ReleaseProjectionError):
                bootstrap_helper_contract(path, digest, str(self.stage), self.target_root)
        self.assertEqual(
            bootstrap_helper_contract(good_path, good_digest, str(self.stage), self.target_root),
            {"path": os.path.realpath(good_path), "digest": good_digest},
        )
        alias_parent = self.root / "stage-alias"
        alias_parent.symlink_to(self.stage, target_is_directory=True)
        with self.assertRaises(ReleaseProjectionError):
            bootstrap_helper_contract(str(alias_parent / "bin/openduck-installer"), good_digest,
                                      str(self.stage), self.target_root)

    def test_closed_schema_rejects_unknown_missing_and_duplicate_keys(self):
        for field in ("unknown", "version", "release_digest"):
            value = dict(self.manifest)
            if field == "unknown":
                value[field] = True
            else:
                value.pop(field)
            path = self._write("bad-manifest.json", value)
            with self.assertRaises(ReleaseProjectionError):
                self._project(manifest_path=path)

        duplicate = '{"schema":"openduck.release-manifest.v2","schema":"other"}'
        path = self.root / "duplicate.json"
        path.write_text(duplicate)
        path.chmod(0o600)
        with self.assertRaises(ReleaseProjectionError):
            self._project(manifest_path=str(path))

    def test_rejects_wrong_bindings_and_artifact_values(self):
        cases = [
            {"schema": "wrong"},
            {"release_id": "other"},
            {"version": "9.9.9"},
            {"release_digest": "d" * 64},
            {"target_root": "/tmp/other"},
            {"artifacts": [{**self.manifest["artifacts"][0], "type": "unknown"}]},
            {"artifacts": [{**self.manifest["artifacts"][0], "path": "../escape"}]},
            {"artifacts": [{**self.manifest["artifacts"][0], "path": "/absolute"}]},
            {"artifacts": [self.manifest["artifacts"][0], self.manifest["artifacts"][0]]},
        ]
        for changes in cases:
            value = dict(self.manifest)
            value.update(changes)
            path = self._write("bad-manifest.json", value)
            with self.assertRaises(ReleaseProjectionError):
                self._project(manifest_path=path)

        for field, value in (("operation", "rollback"), ("run_id", "other-run"), ("activation", "true")):
            envelope = dict(self.envelope)
            envelope[field] = value
            path = self._write("bad-envelope.json", envelope)
            with self.assertRaises(ReleaseProjectionError):
                self._project(envelope_path=path)

    def test_rejects_envelope_and_trust_shape(self):
        for field in ("schema", "manifest_digest", "signature", "sequence"):
            value = dict(self.envelope)
            value[field] = "wrong" if field != "sequence" else 0
            path = self._write("bad-envelope.json", value)
            with self.assertRaises(ReleaseProjectionError):
                self._project(envelope_path=path)

        trust = dict(self.trust)
        trust["keys"] = {"release-key": "z" * 64}
        path = self._write("bad-trust.json", trust)
        with self.assertRaises(ReleaseProjectionError):
            self._project(trust_path=path)

    def test_rejects_symlink_hardlink_unsafe_mode_and_digest_mismatch(self):
        link = self.root / "link.json"
        link.symlink_to(self.manifest_path)
        with self.assertRaises(ReleaseProjectionError):
            self._project(manifest_path=str(link))

        hardlink = self.root / "hardlink.json"
        os.link(self.manifest_path, hardlink)
        with self.assertRaises(ReleaseProjectionError):
            self._project(manifest_path=str(hardlink))

        os.chmod(self.manifest_path, 0o620)
        with self.assertRaises(ReleaseProjectionError):
            self._project()
        os.chmod(self.manifest_path, 0o600)

        (self.stage / "bin/controller").write_bytes(b"tampered")
        with self.assertRaises(ReleaseProjectionError):
            self._project()

    def test_rejects_oversize_input_and_nonfixed_nonce_store(self):
        oversized = self.root / "oversized.json"
        oversized.write_bytes(b"{" + b"x" * (1 << 20) + b"}")
        oversized.chmod(0o600)
        with self.assertRaises(ReleaseProjectionError):
            self._project(manifest_path=str(oversized))
        with self.assertRaises(ReleaseProjectionError):
            self._project(nonce_store=str(self.root / "nonce.json"))

    def test_legacy_manifest_is_rejected_for_mutation(self):
        legacy = dict(self.manifest)
        legacy["schema"] = "openduck.release-manifest.v1"
        path = self._write("legacy-manifest.json", legacy)
        with self.assertRaises(ReleaseProjectionError):
            self._project(manifest_path=path)

class DeploymentPlanV2Tests(unittest.TestCase):
    def setUp(self):
        self.projection = {
            "release_id": "release-20260825", "release_version": "1.2.3", "release_digest": "a" * 64,
            "run_id": "aaaaaaaa-1111", "target_root": "/Library/Application Support/OpenDuck",
            "platform": "darwin", "arch": "arm64", "activation": False,
            "artifacts": [{"type": "core", "path": "bin/openduck-controller", "digest": "b" * 64, "platform": "darwin", "arch": "arm64", "version": "1.2.3", "activation_group": "default", "required": True}],
        }
        base = {key: self.projection[key] for key in ("release_id", "release_version", "release_digest", "run_id", "target_root", "platform", "arch", "activation")}
        base.update({"schema": "openduck.deployment-plan.v2", "version": 2})
        operation = {"source": "bin/openduck-controller", "target": "releases/controller/release-20260825/openduck-controller", "artifact_type": "core", "digest": "b" * 64, "mode": "0550", "owner": "root", "group": "_openduck", "action": "install", "preconditions": ["admission-validated", "digest-match", "target-safe"]}
        rollback = dict(operation, action="rollback", preconditions=["previous-release-verified", "target-safe"])
        cleanup = dict(operation, action="cleanup", preconditions=["candidate-not-active", "target-safe"])
        self.plan = dict(base, operations=[operation], rollback_plan=[rollback], cleanup_plan=[cleanup])

    def test_closed_plan_projection_rejects_field_families_and_cross_bindings(self):
        self.assertEqual(deployment_plan_v2(json.dumps(self.plan, separators=(",", ":")), self.projection)["schema"], "openduck.deployment-plan.v2")
        cases = [
            ("schema", "wrong"), ("release_id", "other"), ("run_id", "bad-run"), ("activation", True),
        ]
        for field, value in cases:
            plan = dict(self.plan)
            plan[field] = value
            with self.assertRaises(ReleaseProjectionError):
                deployment_plan_v2(json.dumps(plan), self.projection)
        for field, value in (("source", "../escape"), ("target", "../escape"), ("digest", "bad"), ("artifact_type", "unknown"), ("mode", "0777"), ("owner", "operator"), ("group", "staff")):
            plan = json.loads(json.dumps(self.plan))
            plan["operations"][0][field] = value
            with self.assertRaises(ReleaseProjectionError):
                deployment_plan_v2(json.dumps(plan), self.projection)
        plan = json.loads(json.dumps(self.plan))
        plan["operations"].append(dict(plan["operations"][0]))
        with self.assertRaises(ReleaseProjectionError):
            deployment_plan_v2(json.dumps(plan), self.projection)


if __name__ == "__main__":
    unittest.main()
