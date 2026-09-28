package macosattest

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVerifyNativePackageCommitRejectsMissingMarker(t *testing.T) {
	root := t.TempDir()
	if err := VerifyNativePackageCommit(root, "codex", strings.Repeat("a", 64), strings.Repeat("b", 64), uint32(os.Getgid())); err == nil {
		t.Fatal("missing authority marker accepted")
	}
}

func TestVerifyNativePackageCommitRejectsProviderWritableAuthority(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0770); err != nil {
		t.Fatal(err)
	}
	marker := `{"schema":"openduck.native-package-commit.v1","provider":"codex","inventory_digest":"sha256:` + strings.Repeat("c", 64) + `","package_digest":"` + strings.Repeat("a", 64) + `","receipt_digest":"` + strings.Repeat("b", 64) + `"}`
	if err := os.WriteFile(filepath.Join(root, ".openduck-commit.json"), []byte(marker), 0660); err != nil {
		t.Fatal(err)
	}
	if err := VerifyNativePackageCommit(root, "codex", strings.Repeat("a", 64), strings.Repeat("b", 64), uint32(os.Getgid())); err == nil {
		t.Fatal("provider-writable package authority accepted")
	}
}

func TestVerifyNativePackageCommitRejectsForgedInventory(t *testing.T) {
	root := t.TempDir()
	marker := `{"schema":"openduck.native-package-commit.v1","provider":"codex","inventory_digest":"sha256:` + strings.Repeat("c", 64) + `","package_digest":"` + strings.Repeat("a", 64) + `","receipt_digest":"` + strings.Repeat("b", 64) + `"}`
	if err := os.WriteFile(filepath.Join(root, ".openduck-commit.json"), []byte(marker), 0440); err != nil {
		t.Fatal(err)
	}
	if err := VerifyNativePackageCommit(root, "codex", strings.Repeat("a", 64), strings.Repeat("b", 64), uint32(os.Getgid())); err == nil {
		t.Fatal("forged inventory accepted")
	}
}

func TestKimiPackageDigestBindsLogicalHelperDigest(t *testing.T) {
	files := map[string][]byte{"kimi.plugin.json": []byte("{}\n"), "openduck.controller-tools.json": []byte("{}\n")}
	a := nativePackageDigest(files, "sha256:"+strings.Repeat("a", 64))
	b := nativePackageDigest(files, "sha256:"+strings.Repeat("b", 64))
	if a == b {
		t.Fatal("helper identity is not bound into Kimi package digest")
	}
}

func TestNativePackageDigestGoldens(t *testing.T) {
	raw, err := os.ReadFile("testdata/native-package-digests.golden.json")
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{}
	if json.Unmarshal(raw, &want) != nil {
		t.Fatal("invalid golden")
	}
	r := map[string]any{
		"profile_id": "profile", "profile_revision": "revision", "package_id": "openduck-mesh", "controller_binding_id": "binding", "endpoint_id": "endpoint", "endpoint_generation": json.Number("7"), "endpoint_expires_at": "2026-09-01T00:00:00Z", "association_digest": strings.Repeat("1", 64), "ui_session_id": "ui-session", "ui_channel_id": "ui-channel", "root_run_id": "root-run", "run_id": "run", "mesh_session_id": "mesh-session", "native_lifecycle_projection_digest": strings.Repeat("2", 64), "native_release_id": "release", "native_release_digest": strings.Repeat("3", 64), "native_manifest_digest": strings.Repeat("4", 64), "native_shim_artifact_digest": strings.Repeat("5", 64), "native_socket_generation": json.Number("8"), "native_socket_identity_digest": strings.Repeat("6", 64), "native_host_catalog_generation": json.Number("9"), "native_provider_topology_digest": strings.Repeat("7", 64), "native_host_artifact_digest": strings.Repeat("8", 64), "native_host_team_id": "TEAMID", "native_host_image_identity": strings.Repeat("9", 64), "native_lifecycle_expires_at": "2026-09-01T00:00:00Z", "capabilities": []any{"spawn", "spawnBatch", "send", "steer", "wait", "collect", "cancel", "list", "status", "result", "listProfiles"}, "capability_digest": strings.Repeat("a", 64),
	}
	for _, provider := range []string{"codex", "claude", "qwen", "kimi"} {
		r["provider"] = provider
		files, err := canonicalNativePackageFiles(r)
		if err != nil {
			t.Fatal(err)
		}
		if got := nativePackageDigest(files, "sha256:"+strings.Repeat("5", 64)); got != want[provider] {
			t.Fatalf("%s digest = %s, want %s", provider, got, want[provider])
		}
	}
}
