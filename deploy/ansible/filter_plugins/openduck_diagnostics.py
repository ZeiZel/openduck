"""Closed, bounded unprivileged Ansible projections for OpenDuck releases."""
from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from datetime import datetime


MANIFEST_SCHEMA = "openduck.release-manifest.v2"
ENVELOPE_SCHEMA = "openduck.release-envelope.v1"
TRUST_SCHEMA = "openduck.release-trust.v1"
FIXED_NONCE_STORE = "/private/var/db/openduck-release-nonces.json"
MAX_INPUT_BYTES = 1 << 20
MAX_ARTIFACT_BYTES = 64 << 20
MAX_ARTIFACT_SET_BYTES = 256 << 20
MAX_ARTIFACTS = 256
PLAN_SCHEMA = "openduck.deployment-plan.v2"
ARTIFACT_TYPES = {"core", "provider_runtime", "provider_plugin", "provider_daemon", "provider_topology", "provider_host_runtime", "provider_host_closure", "provider_host_identity", "policy", "helper"}
ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
VERSION_RE = re.compile(r"^(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})$")


class ReleaseProjectionError(ValueError):
    """A release input failed early shape/file validation."""


def safe_error_json(value, max_bytes=4096):
    """Return a JSON object candidate or an empty object, never raise."""
    try:
        if not isinstance(value, str) or isinstance(max_bytes, bool):
            return {}
        bound = int(max_bytes)
        if bound <= 0:
            return {}
        raw = value.strip()
        if not raw or len(raw.encode("utf-8")) > bound:
            return {}
        candidate = json.loads(raw, object_pairs_hook=_no_duplicate_object)
    except (ReleaseProjectionError, TypeError, ValueError, UnicodeError, OverflowError, json.JSONDecodeError):
        return {}
    return candidate if isinstance(candidate, dict) else {}


def provisioning_verify_v1(value, max_bytes=65536):
    """Closed projection for ``--verify-json=full`` output.

    Command stdout is an untrusted transport.  In particular this filter must
    never let a malformed, concatenated, or huge helper response become an
    Ansible/Jinja exception (which would commonly print the response).  The
    caller receives only a tiny availability/cleanliness DTO.
    """
    unavailable = {"available": False, "clean": False}
    try:
        if not isinstance(value, str) or isinstance(max_bytes, bool):
            return unavailable
        bound = int(max_bytes)
        if bound < 1 or len(value.encode("utf-8")) > bound:
            return unavailable
        report = json.loads(value, object_pairs_hook=_no_duplicate_object)
        _exact_dict(report, ("schema", "version", "release_digest", "scopes"), "verify schema")
        _require(report["schema"] == "openduck.provisioning.v1" and report["version"] == 1,
                 "verify version")
        _require(_safe_digest(report["release_digest"]), "verify digest")
        scopes = report["scopes"]
        _require(isinstance(scopes, list) and 1 <= len(scopes) <= 16, "verify scopes")
        names = set()
        for scope in scopes:
            _require(isinstance(scope, dict) and set(scope).issubset({"name", "changed", "drift", "reason_codes", "counts", "paths"})
                     and {"name", "changed", "drift", "counts"}.issubset(scope), "verify scope")
            _require(scope["name"] in {"principals", "layout", "artifacts", "ownership", "policy", "launchd"}
                     and scope["name"] not in names and isinstance(scope["changed"], bool)
                     and isinstance(scope["drift"], bool), "verify scope fields")
            names.add(scope["name"])
            _require(isinstance(scope.get("reason_codes", []), list) and len(scope.get("reason_codes", [])) <= 32
                     and all(isinstance(item, str) and ID_RE.fullmatch(item) for item in scope.get("reason_codes", [])),
                     "verify reasons")
            _exact_dict(scope["counts"], ("checked", "drift"), "verify counts")
            _require(all(isinstance(scope["counts"][field], int) and not isinstance(scope["counts"][field], bool)
                         and 0 <= scope["counts"][field] <= 1000000 for field in ("checked", "drift")),
                     "verify counts fields")
            _require(isinstance(scope.get("paths", []), list) and len(scope.get("paths", [])) <= 64
                     and all(isinstance(item, str) and len(item) <= 512 for item in scope.get("paths", [])),
                     "verify paths")
        return {"available": True, "clean": not any(scope["drift"] for scope in scopes)}
    except (ReleaseProjectionError, UnicodeError, ValueError, TypeError, json.JSONDecodeError):
        return unavailable


def readiness_v1(value, max_bytes=4096):
    """Project the three-line readiness protocol without retaining raw text."""
    unavailable = {"available": False, "state": "UNAVAILABLE", "reason": "unavailable", "next": "UNAVAILABLE"}
    try:
        if not isinstance(value, str) or isinstance(max_bytes, bool) or len(value.encode("utf-8")) > int(max_bytes):
            return unavailable
        lines = value.splitlines()
        _require(len(lines) == 3, "readiness line count")
        fields = {}
        for line, key, pattern in zip(lines, ("state", "reason", "next"),
                                      (r"[A-Z_]{1,64}", r"[A-Za-z0-9 _.,:;/-]{1,256}", r"[A-Z_]{1,64}")):
            prefix = key + "="
            _require(line.startswith(prefix) and re.fullmatch(pattern, line[len(prefix):]), "readiness field")
            fields[key] = line[len(prefix):]
        _require(fields["state"] in {"SUDO_PROVISIONING_REQUIRED", "SERVICE_LOGIN_REQUIRED",
                                      "LIVE_EGRESS_CANARY_REQUIRED", "ACTIVATION_APPROVAL_REQUIRED", "READY"},
                 "readiness state")
        _require(fields["next"] in {"SUDO_PROVISIONING_REQUIRED", "SERVICE_LOGIN_REQUIRED",
                                     "LIVE_EGRESS_CANARY_REQUIRED", "ACTIVATION_APPROVAL_REQUIRED", "READY"},
                 "readiness next")
        return {"available": True, **fields}
    except (ReleaseProjectionError, UnicodeError, ValueError, TypeError, OverflowError):
        return unavailable


def doctor_v1(value, max_bytes=16384):
    """Validate doctor v1 and emit only its fixed allowlisted posture DTO."""
    unavailable = {"available": False, "state": "unavailable", "reason": "invalid_doctor_projection"}
    try:
        if not isinstance(value, str) or isinstance(max_bytes, bool) or len(value.encode("utf-8")) > int(max_bytes):
            return unavailable
        report = json.loads(value, object_pairs_hook=_no_duplicate_object)
        _exact_dict(report, ("schema", "version", "platform", "arch", "fixed_root", "markers", "gates", "reason_codes"), "doctor schema")
        _require(report["schema"] == "openduck.doctor.v1" and report["version"] == 1
                 and report["platform"] == "darwin" and _safe_id(report["arch"]), "doctor binding")
        _exact_dict(report["fixed_root"], ("fixed", "safe_directory"), "doctor root")
        _require(all(isinstance(item, bool) for item in report["fixed_root"].values()), "doctor root values")
        _exact_dict(report["markers"], ("candidate", "configured", "active", "activated", "activation_intent", "failed", "rolled_back", "manifest"), "doctor markers")
        _require(all(isinstance(item, bool) for item in report["markers"].values()), "doctor marker values")
        _exact_dict(report["gates"], ("configuration_converged", "activation_complete", "operational_ready", "operator_gate"), "doctor gates")
        _require(all(isinstance(item, str) and item in {"unknown", "observed", "required", "unavailable"} for item in report["gates"].values()), "doctor gate values")
        allowed_reasons = {"provider_topology_absent", "provider_topology_invalid", "provider_evidence_absent",
                           "provider_evidence_invalid", "provider_evidence_stale", "core_activation_unverified",
                           "provider_daemon_identity_unverified", "provider_channel_health_unverified",
                           "provider_account_canary_unverified", "provider_revision_compatibility_unverified",
                           "provider_session_recovery_unverified"}
        _require(isinstance(report["reason_codes"], list) and len(report["reason_codes"]) <= len(allowed_reasons)
                 and report["reason_codes"] == sorted(set(report["reason_codes"]))
                 and all(item in allowed_reasons for item in report["reason_codes"]), "doctor reason codes")
        return {"available": True, "state": "available", "fixed_root": report["fixed_root"],
                "markers": report["markers"], "gates": report["gates"], "reason_codes": report["reason_codes"]}
    except (ReleaseProjectionError, UnicodeError, ValueError, TypeError, json.JSONDecodeError, OverflowError):
        return unavailable


def release_input_projection(manifest_path, envelope_path, trust_path, staged_root,
                             release_id, release_version, release_digest,
                             target_root, platform, arch, nonce_store=FIXED_NONCE_STORE,
                             operation="deploy", run_id="", activation=False,
                             mutation=True, allow_legacy_read_only=False):
    """Project validated v2 files into canonical, literal-argv-safe facts.

    This is deliberately not a trust decision: it never validates an Ed25519
    signature or treats a Jinja result as authority. The root installer repeats
    strict loading and cryptographic admission before its first mutation.
    """
    try:
        _require(isinstance(mutation, bool) and isinstance(allow_legacy_read_only, bool), "mode")
        _require(_safe_id(release_id) and _safe_version(release_version) and _safe_digest(release_digest), "release inputs")
        _require(_safe_absolute(target_root) and _safe_id(platform) and _safe_id(arch), "target binding")
        _require(operation in ("deploy", "rollback") and _safe_run_id(run_id) and isinstance(activation, bool), "operation intent")
        _require(nonce_store == FIXED_NONCE_STORE, "nonce route")
        _safe_stage_root(staged_root)
        manifest = _load_json(manifest_path)
        schema = manifest.get("schema") if isinstance(manifest, dict) else None
        if schema != MANIFEST_SCHEMA:
            _require(allow_legacy_read_only and not mutation and schema == "openduck.release-manifest.v1", "legacy manifest gate")
            raise ReleaseProjectionError("legacy manifest is read-only only and has no mutation projection")
        _validate_manifest(manifest, release_id, release_version, release_digest, target_root, platform, arch)
        envelope = _load_json(envelope_path)
        trust = _load_json(trust_path)
        manifest_digest = _canonical_digest(_manifest_value(manifest))
        artifact_set_digest = _canonical_digest(_artifact_values(manifest["artifacts"]))
        _validate_envelope(envelope, release_digest, release_version, target_root, platform, arch, manifest_digest, artifact_set_digest, operation, run_id, activation)
        _validate_trust(trust)
        artifacts = _verify_artifacts(staged_root, manifest["artifacts"], platform, arch)
        return {
            "schema": MANIFEST_SCHEMA,
            "release_id": release_id,
            "release_version": release_version,
            "release_digest": release_digest,
            "operation": operation,
            "run_id": run_id,
            "activation": activation,
            "target_root": target_root,
            "platform": platform,
            "arch": arch,
            "envelope_path": envelope_path,
            "manifest_path": manifest_path,
            "trust_path": trust_path,
            "nonce_store": FIXED_NONCE_STORE,
            "manifest_digest": manifest_digest,
            "artifact_set_digest": artifact_set_digest,
            "artifacts": artifacts,
        }
    except ReleaseProjectionError:
        raise
    except (OSError, TypeError, ValueError, UnicodeError, OverflowError, json.JSONDecodeError) as error:
        raise ReleaseProjectionError("release input rejected") from error


def _require(condition, name):
    if not condition:
        raise ReleaseProjectionError("release input rejected: " + name)


def _safe_id(value):
    return isinstance(value, str) and bool(ID_RE.fullmatch(value))


def _safe_run_id(value):
    return isinstance(value, str) and bool(re.fullmatch(r"[0-9a-f-]{8,128}", value))


def _safe_digest(value):
    return isinstance(value, str) and bool(DIGEST_RE.fullmatch(value))


def _safe_version(value):
    return isinstance(value, str) and bool(VERSION_RE.fullmatch(value))


def _safe_absolute(value):
    return isinstance(value, str) and value != "/" and len(value) <= 512 and os.path.isabs(value) and os.path.normpath(value) == value


def _safe_relative(value):
    if not isinstance(value, str) or not value or len(value) > 512 or os.path.isabs(value) or os.path.normpath(value) != value:
        return False
    return all(part not in {"", ".", ".."} for part in value.split(os.sep))


def _safe_stage_root(path):
    _require(_safe_absolute(path), "staged root")
    info = os.lstat(path)
    _require(stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode) and not (info.st_mode & 0o022), "staged root metadata")


def _safe_regular(info, maximum):
    return stat.S_ISREG(info.st_mode) and not stat.S_ISLNK(info.st_mode) and info.st_nlink == 1 and 1 <= info.st_size <= maximum and not (info.st_mode & 0o022)


def _read_safe(path, maximum):
    info = os.lstat(path)
    _require(_safe_regular(info, maximum), "unsafe input")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        opened = os.fstat(fd)
        _require(_safe_regular(opened, maximum) and (opened.st_dev, opened.st_ino) == (info.st_dev, info.st_ino), "input race")
        chunks = []
        left = maximum + 1
        while left:
            chunk = os.read(fd, min(65536, left))
            if not chunk:
                break
            chunks.append(chunk)
            left -= len(chunk)
        raw = b"".join(chunks)
        _require(len(raw) == info.st_size and len(raw) <= maximum, "input size")
        return raw
    finally:
        os.close(fd)


def _no_duplicate_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ReleaseProjectionError("duplicate JSON key")
        value[key] = item
    return value


def _load_json(path):
    _require(_safe_absolute(path), "input path")
    raw = _read_safe(path, MAX_INPUT_BYTES)
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=_no_duplicate_object)
    except (UnicodeError, json.JSONDecodeError, ValueError) as error:
        raise ReleaseProjectionError("malformed JSON") from error


def _exact_dict(value, keys, label):
    _require(isinstance(value, dict) and set(value) == set(keys), label)


def _manifest_value(value):
    return {
        "schema": value["schema"], "release_id": value["release_id"], "release_digest": value["release_digest"],
        "version": value["version"], "target_root": value["target_root"], "artifacts": _artifact_values(value["artifacts"]),
    }


def _artifact_values(values):
    return [{"type": item["type"], "path": item["path"], "digest": item["digest"], "platform": item["platform"], "arch": item["arch"], "version": item["version"], "activation_group": item["activation_group"], "required": item["required"]} for item in values]


def _canonical_digest(value):
    raw = json.dumps(value, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    return hashlib.sha256(raw).hexdigest()


def _validate_manifest(value, release_id, release_version, release_digest, target_root, platform, arch):
    _exact_dict(value, ("schema", "release_id", "release_digest", "version", "target_root", "artifacts"), "manifest schema")
    _require(value["schema"] == MANIFEST_SCHEMA and value["release_id"] == release_id and value["release_digest"] == release_digest and value["version"] == release_version and value["target_root"] == target_root, "manifest binding")
    artifacts = value["artifacts"]
    _require(isinstance(artifacts, list) and 1 <= len(artifacts) <= MAX_ARTIFACTS, "manifest artifacts")
    seen = set()
    for artifact in artifacts:
        _exact_dict(artifact, ("type", "path", "digest", "platform", "arch", "version", "activation_group", "required"), "artifact schema")
        _require(artifact["type"] in ARTIFACT_TYPES and _safe_relative(artifact["path"]) and _safe_digest(artifact["digest"]) and artifact["platform"] == platform and artifact["arch"] == arch and _safe_version(artifact["version"]) and _safe_id(artifact["activation_group"]) and isinstance(artifact["required"], bool), "artifact value")
        _require(artifact["path"] not in seen, "duplicate artifact target")
        seen.add(artifact["path"])


def _validate_envelope(value, release_digest, release_version, target_root, platform, arch, manifest_digest, artifact_set_digest, operation, run_id, activation):
    keys = ("schema", "key_id", "manifest_digest", "artifact_set_digest", "release_digest", "release_version", "target_root", "platform", "arch", "min_installer", "operation", "run_id", "activation", "nonce", "signature", "sequence", "issued_at", "expires_at")
    _exact_dict(value, keys, "envelope schema")
    _require(value["schema"] == ENVELOPE_SCHEMA and _safe_id(value["key_id"]) and value["manifest_digest"] == manifest_digest and value["artifact_set_digest"] == artifact_set_digest and value["release_digest"] == release_digest and value["release_version"] == release_version and value["target_root"] == target_root and value["platform"] == platform and value["arch"] == arch and _safe_version(value["min_installer"]) and value["operation"] == operation and value["run_id"] == run_id and value["activation"] == ("true" if activation else "false") and _safe_id(value["nonce"]) and isinstance(value["signature"], str) and bool(re.fullmatch(r"[0-9a-f]{128}", value["signature"])) and isinstance(value["sequence"], int) and not isinstance(value["sequence"], bool) and value["sequence"] > 0, "envelope binding")
    _parse_rfc3339(value["issued_at"])
    _parse_rfc3339(value["expires_at"])


def _parse_rfc3339(value):
    _require(isinstance(value, str) and len(value) <= 64, "timestamp")
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ReleaseProjectionError("timestamp") from error


def _validate_trust(value):
    _exact_dict(value, ("schema", "keys", "revoked"), "trust schema")
    _require(value["schema"] == TRUST_SCHEMA and isinstance(value["keys"], dict) and 1 <= len(value["keys"]) <= MAX_ARTIFACTS and isinstance(value["revoked"], list) and len(value["revoked"]) <= MAX_ARTIFACTS, "trust value")
    revoked = set()
    for key_id, public_key in value["keys"].items():
        _require(_safe_id(key_id) and isinstance(public_key, str) and bool(re.fullmatch(r"[0-9a-f]{64}", public_key)), "trust key")
    for key_id in value["revoked"]:
        _require(_safe_id(key_id) and key_id in value["keys"] and key_id not in revoked, "revocation")
        revoked.add(key_id)


def _verified_artifact_path(root, relative):
    _require(_safe_relative(relative), "artifact path")
    current = root
    for component in relative.split(os.sep)[:-1]:
        current = os.path.join(current, component)
        info = os.lstat(current)
        _require(stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode) and not (info.st_mode & 0o022), "artifact parent")
    path = os.path.join(root, relative)
    _require(os.path.commonpath((root, path)) == root, "artifact containment")
    return path


def _verify_artifacts(root, values, platform, arch):
    total = 0
    projected = []
    for artifact in values:
        _require(artifact["platform"] == platform and artifact["arch"] == arch, "artifact platform")
        path = _verified_artifact_path(root, artifact["path"])
        body = _read_safe(path, MAX_ARTIFACT_BYTES)
        total += len(body)
        _require(total <= MAX_ARTIFACT_SET_BYTES and hashlib.sha256(body).hexdigest() == artifact["digest"], "artifact digest")
        projected.append({"type": artifact["type"], "path": artifact["path"], "digest": artifact["digest"], "platform": artifact["platform"], "arch": artifact["arch"], "version": artifact["version"], "activation_group": artifact["activation_group"], "required": artifact["required"]})
    return projected


def deployment_plan_v2(value, projection):
    """Validate the exact bounded PlanV2 emitted after pure Go admission."""
    try:
        _require(isinstance(value, str) and len(value.encode("utf-8")) <= MAX_INPUT_BYTES and isinstance(projection, dict), "plan input")
        plan = json.loads(value, object_pairs_hook=_no_duplicate_object)
        _exact_dict(plan, ("schema", "version", "release_id", "release_version", "release_digest", "run_id", "target_root", "platform", "arch", "activation", "operations", "rollback_plan", "cleanup_plan"), "plan schema")
        for field in ("release_id", "release_version", "release_digest", "run_id", "target_root", "platform", "arch", "activation"):
            _require(plan[field] == projection.get(field), "plan binding")
        _require(plan["schema"] == PLAN_SCHEMA and plan["version"] == 2 and isinstance(plan["activation"], bool), "plan version")
        artifacts = projection.get("artifacts")
        _require(isinstance(artifacts, list) and 1 <= len(artifacts) <= 64, "plan artifacts")
        expected = {}
        for artifact in artifacts:
            for mapping in _plan_mappings(artifact, plan["release_id"]):
                _require(mapping[0] not in expected, "plan targets")
                expected[mapping[0]] = (artifact, mapping)
        for name, action, required in (("operations", "install", ["admission-validated", "digest-match", "target-safe"]), ("rollback_plan", "rollback", ["previous-release-verified", "target-safe"]), ("cleanup_plan", "cleanup", ["candidate-not-active", "target-safe"])):
            values = plan[name]
            _require(isinstance(values, list) and len(values) == len(expected), "plan list")
            last = ""
            seen = set()
            for item in values:
                _exact_dict(item, ("action", "source", "target", "artifact_type", "digest", "mode", "owner", "group", "preconditions"), "plan operation")
                _require(item["action"] == action and item["preconditions"] == required and item["target"] in expected and item["target"] > last and item["target"] not in seen, "plan order")
                artifact, mapping = expected[item["target"]]
                _require(item["source"] == artifact["path"] and item["artifact_type"] == artifact["type"] and item["digest"] == artifact["digest"] and [item["mode"], item["owner"], item["group"]] == list(mapping[1:]), "plan operation binding")
                last = item["target"]
                seen.add(last)
        return plan
    except (ReleaseProjectionError, UnicodeError, ValueError, TypeError, json.JSONDecodeError) as error:
        if isinstance(error, ReleaseProjectionError):
            raise
        raise ReleaseProjectionError("deployment plan rejected") from error


def installed_manifest_helper_digest(value, release_id):
    """Extract the installer digest from a root-owned admitted ManifestV2.

    The caller establishes filesystem ownership, link count, mode, and the
    fixed installed location.  This parser is deliberately closed so a
    partially-written or look-alike installed record cannot bless a helper.
    """
    try:
        _require(_safe_id(release_id) and isinstance(value, str) and len(value.encode("utf-8")) <= MAX_INPUT_BYTES,
                 "installed manifest input")
        manifest = json.loads(value, object_pairs_hook=_no_duplicate_object)
        _exact_dict(manifest, ("schema", "release_id", "release_digest", "version", "target_root", "artifacts"),
                    "installed manifest schema")
        _require(manifest["schema"] == MANIFEST_SCHEMA and manifest["release_id"] == release_id,
                 "installed manifest binding")
        _require(_safe_digest(manifest["release_digest"]) and _safe_version(manifest["version"]) and
                 manifest["target_root"] == "/Library/Application Support/OpenDuck", "installed manifest fields")
        artifacts = manifest["artifacts"]
        _require(isinstance(artifacts, list) and 1 <= len(artifacts) <= MAX_ARTIFACTS, "installed manifest artifacts")
        installer = []
        seen = set()
        for artifact in artifacts:
            _exact_dict(artifact, ("type", "path", "digest", "platform", "arch", "version", "activation_group", "required"),
                        "installed artifact schema")
            _require(artifact["path"] not in seen and _safe_relative(artifact["path"]) and
                     artifact["type"] in ARTIFACT_TYPES and _safe_digest(artifact["digest"]) and
                     _safe_id(artifact["platform"]) and _safe_id(artifact["arch"]) and
                     _safe_version(artifact["version"]) and _safe_id(artifact["activation_group"]) and
                     isinstance(artifact["required"], bool), "installed artifact fields")
            seen.add(artifact["path"])
            if artifact["type"] == "helper" and artifact["path"] == "bin/openduck-installer":
                installer.append(artifact["digest"])
        _require(len(installer) == 1, "installed helper artifact")
        return installer[0]
    except (ReleaseProjectionError, UnicodeError, ValueError, TypeError, json.JSONDecodeError) as error:
        if isinstance(error, ReleaseProjectionError):
            raise
        raise ReleaseProjectionError("installed manifest rejected") from error


def installed_manifest_artifact_digest_or_empty(value, release_id, artifact_path):
    """Return one installed ManifestV2 artifact digest, or fail closed quietly."""
    try:
        _require(_safe_relative(artifact_path), "installed artifact path")
        _require(_safe_id(release_id) and isinstance(value, str) and len(value.encode("utf-8")) <= MAX_INPUT_BYTES,
                 "installed manifest input")
        manifest = json.loads(value, object_pairs_hook=_no_duplicate_object)
        _exact_dict(manifest, ("schema", "release_id", "release_digest", "version", "target_root", "artifacts"),
                    "installed manifest schema")
        _require(manifest["schema"] == MANIFEST_SCHEMA and manifest["release_id"] == release_id
                 and _safe_digest(manifest["release_digest"]) and _safe_version(manifest["version"])
                 and manifest["target_root"] == "/Library/Application Support/OpenDuck", "installed manifest binding")
        hits = [item.get("digest") for item in manifest["artifacts"] if isinstance(item, dict)
                and item.get("path") == artifact_path]
        _require(len(hits) == 1 and _safe_digest(hits[0]), "installed artifact")
        return hits[0]
    except (ReleaseProjectionError, UnicodeError, ValueError, TypeError, json.JSONDecodeError):
        return ""


def bootstrap_helper_contract(path, digest, staged_root, fixed_root):
    """Validate non-filesystem bootstrap authority inputs before any mutation."""
    try:
        _require(_safe_absolute(path) and _safe_digest(digest) and _safe_absolute(staged_root) and
                 fixed_root == "/Library/Application Support/OpenDuck", "bootstrap inputs")
        physical_path = os.path.realpath(path)
        physical_stage = os.path.realpath(staged_root)
        physical_root = os.path.realpath(fixed_root)
        _require(_safe_absolute(physical_path) and _safe_absolute(physical_stage) and _safe_absolute(physical_root),
                 "bootstrap canonical paths")
        _require(physical_path != physical_stage and not physical_path.startswith(physical_stage + "/"),
                 "bootstrap staged overlap")
        _require(physical_path != physical_root and not physical_path.startswith(physical_root + "/"),
                 "bootstrap installed overlap")
        return {"path": physical_path, "digest": digest}
    except ReleaseProjectionError:
        raise
    except (TypeError, ValueError, UnicodeError, OverflowError) as error:
        raise ReleaseProjectionError("bootstrap helper rejected") from error


def _plan_mappings(artifact, release_id):
    """Exact source-to-output inventory in macosinstall.Installer.Apply."""
    helper = {
        "bin/openduck-installer": ((".openduck-installer", "0700", "root", "wheel"), (".openduck-service-login", "0700", "root", "wheel")),
        "bin/openduck-readiness": ((".openduck-readiness", "0700", "root", "wheel"),),
        "bin/openduck-provider-attestor": ((".openduck-provider-attestor", "0700", "root", "wheel"),),
        "bin/openduck-native-mcp": ((".openduck-native-mcp", "0755", "root", "wheel"),),
        "bin/openduck-owner-grant": (("operator/openduck-owner-grant", "0700", "root", "wheel"),),
        "bin/openduck-codex-login": (("home/controller/bin/openduck-codex-login", "0700", "root", "wheel"),),
    }
    if artifact.get("type") == "helper" and artifact.get("path") in helper:
        return helper[artifact["path"]]
    services = {
        "bin/openduck-checkpoint": ("checkpoint", "core", "_openduck_checkpoint"),
        "bin/openduck-anchor": ("anchor", "core", "_openduck_anchor"),
        "bin/openduck-egress": ("egress", "core", "_openduck_egress"),
        "bin/openduck-codex-runtime": ("runtime", "provider_runtime", "_openduck_codex"),
        "bin/openduck-codex-broker": ("broker", "provider_plugin", "_openduck_broker"),
        "bin/openduck-controller": ("controller", "core", "_openduck"),
    }
    row = services.get(artifact.get("path"))
    if row and artifact.get("type") == row[1]:
        mappings = [("releases/%s/%s/%s" % (row[0], release_id, artifact["path"].split("/", 1)[1]), "0550", "root", row[2])]
        if row[0] == "anchor":
            mappings.append(("releases/anchor-checkpoint/%s/openduck-anchor" % release_id, "0550", "root", "_openduck_checkpoint"))
        return tuple(mappings)
    if artifact.get("path") == "bin/codex" and artifact.get("type") == "core":
        return (("home/runtime/bin/codex", "0700", "root", "wheel"), ("releases/codex/%s/codex" % release_id, "0755", "root", "wheel"))
    provider = artifact.get("activation_group", "").removeprefix("provider-")
    if provider in {"claude", "codex", "deepseek", "kimi", "qwen"}:
        leaf = artifact.get("path", "").rsplit("/", 1)[-1]
        expected = {
            "provider_daemon": "openduck-provider-" + provider,
            "provider_topology": "topology.json",
        }
        if artifact.get("type") in {"provider_host_runtime", "provider_host_closure", "provider_host_identity"}:
            mode = "0550" if artifact.get("type") == "provider_host_runtime" else "0440"
            return (("providers/inactive/%s/host/%s" % (provider, leaf), mode, "root", "_openduck"),)
        if artifact.get("type") in {"provider_runtime", "provider_plugin"} or expected.get(artifact.get("type")) == leaf:
            mode = "0500" if artifact.get("type") == "provider_daemon" else "0440"
            return (("providers/inactive/%s/%s" % (provider, leaf), mode, "root", "_openduck"),)
    raise ReleaseProjectionError("unmapped plan artifact")


class FilterModule:
    def filters(self):
        return {
            "openduck_safe_error_json": safe_error_json,
            "openduck_provisioning_verify_v1": provisioning_verify_v1,
            "openduck_readiness_v1": readiness_v1,
            "openduck_doctor_v1": doctor_v1,
            "openduck_release_input_projection": release_input_projection,
            "openduck_deployment_plan_v2": deployment_plan_v2,
            "openduck_installed_manifest_helper_digest": installed_manifest_helper_digest,
            "openduck_installed_manifest_artifact_digest_or_empty": installed_manifest_artifact_digest_or_empty,
            "openduck_bootstrap_helper_contract": bootstrap_helper_contract,
        }
