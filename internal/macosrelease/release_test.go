package macosrelease

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestValidateAdmissionAndNonceAfterValidation(t *testing.T) {
	d := t.TempDir()
	r, store, _, _ := validRequest(t, d)
	if _, err := ValidateAdmission(r); err != nil {
		t.Fatalf("validate positive: %v", err)
	}
	if _, err := Admit(r, store); err != nil {
		t.Fatalf("admit positive: %v", err)
	}
	if _, err := Admit(r, store); err == nil {
		t.Fatal("replayed admission accepted")
	}

	// A failed pure validation must not consume its nonce.
	r2, store2, env, key := validRequest(t, t.TempDir())
	env.Signature = "bad"
	writeJSON(t, r2.EnvelopePath, env)
	if _, err := Admit(r2, store2); err == nil {
		t.Fatal("bad signature accepted")
	}
	env = signEnvelope(t, env, key)
	writeJSON(t, r2.EnvelopePath, env)
	if _, err := Admit(r2, store2); err != nil {
		t.Fatalf("nonce was consumed before pure validation: %v", err)
	}
}

func TestAdmissionRejectsEnvelopeManifestAndArtifactMutations(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*AdmissionRequest, *EnvelopeV1, *ManifestV2, *TrustBundle)
	}{
		{"unknown key", func(_ *AdmissionRequest, e *EnvelopeV1, _ *ManifestV2, _ *TrustBundle) { e.KeyID = "unknown" }},
		{"revoked key", func(_ *AdmissionRequest, _ *EnvelopeV1, _ *ManifestV2, tr *TrustBundle) {
			tr.Revoked = []string{"key-a"}
		}},
		{"not yet valid", func(_ *AdmissionRequest, e *EnvelopeV1, _ *ManifestV2, _ *TrustBundle) {
			e.IssuedAt = time.Unix(1_800_000_000, 0).UTC()
		}},
		{"expired", func(_ *AdmissionRequest, e *EnvelopeV1, _ *ManifestV2, _ *TrustBundle) {
			e.ExpiresAt = time.Unix(1, 0).UTC()
		}},
		{"wrong schema", func(_ *AdmissionRequest, e *EnvelopeV1, _ *ManifestV2, _ *TrustBundle) { e.Schema = "other" }},
		{"minimum installer", func(r *AdmissionRequest, _ *EnvelopeV1, _ *ManifestV2, _ *TrustBundle) { r.InstallerVersion = "0.9.0" }},
		{"release version", func(r *AdmissionRequest, _ *EnvelopeV1, _ *ManifestV2, _ *TrustBundle) {
			r.ExpectedReleaseVersion = "9.0.0"
		}},
		{"platform", func(_ *AdmissionRequest, e *EnvelopeV1, _ *ManifestV2, _ *TrustBundle) { e.Platform = "other" }},
		{"arch", func(_ *AdmissionRequest, e *EnvelopeV1, _ *ManifestV2, _ *TrustBundle) { e.Arch = "other" }},
		{"release binding", func(r *AdmissionRequest, _ *EnvelopeV1, _ *ManifestV2, _ *TrustBundle) {
			r.ExpectedReleaseID = "other-release"
		}},
		{"operation binding", func(_ *AdmissionRequest, e *EnvelopeV1, _ *ManifestV2, _ *TrustBundle) { e.Operation = "rollback" }},
		{"run binding", func(_ *AdmissionRequest, e *EnvelopeV1, _ *ManifestV2, _ *TrustBundle) { e.RunID = "other-run" }},
		{"activation binding", func(_ *AdmissionRequest, e *EnvelopeV1, _ *ManifestV2, _ *TrustBundle) { e.Activation = "true" }},
		{"target root binding", func(r *AdmissionRequest, _ *EnvelopeV1, _ *ManifestV2, _ *TrustBundle) {
			r.ExpectedTargetRoot = "/opt/other"
		}},
		{"manifest digest", func(_ *AdmissionRequest, e *EnvelopeV1, _ *ManifestV2, _ *TrustBundle) {
			e.ManifestDigest = digestBytes([]byte("wrong"))
		}},
		{"artifact set digest", func(_ *AdmissionRequest, e *EnvelopeV1, _ *ManifestV2, _ *TrustBundle) {
			e.ArtifactSetDigest = digestBytes([]byte("wrong"))
		}},
		{"path traversal", func(_ *AdmissionRequest, _ *EnvelopeV1, m *ManifestV2, _ *TrustBundle) {
			m.Artifacts[0].Path = "../escape"
		}},
		{"duplicate target", func(_ *AdmissionRequest, _ *EnvelopeV1, m *ManifestV2, _ *TrustBundle) {
			m.Artifacts = append(m.Artifacts, m.Artifacts[0])
		}},
		{"unknown artifact type", func(_ *AdmissionRequest, _ *EnvelopeV1, m *ManifestV2, _ *TrustBundle) {
			m.Artifacts[0].Type = "arbitrary"
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r, _, env, key := validRequest(t, t.TempDir())
			var m ManifestV2
			var tr TrustBundle
			if err := LoadStrict(r.ManifestPath, &m); err != nil {
				t.Fatal(err)
			}
			if err := LoadStrict(r.TrustBundlePath, &tr); err != nil {
				t.Fatal(err)
			}
			tc.mutate(&r, &env, &m, &tr)
			// Mutations are signed where possible; this proves semantic binding,
			// rather than merely relying on the signature failure.
			if tc.name != "manifest digest" && tc.name != "artifact set digest" && m.Schema == ManifestSchema && validManifest(m) {
				env.ManifestDigest = digest(m)
				env.ArtifactSetDigest = artifactSetDigest(m.Artifacts)
			}
			env = signEnvelope(t, env, key)
			writeJSON(t, r.EnvelopePath, env)
			writeJSON(t, r.ManifestPath, m)
			writeJSON(t, r.TrustBundlePath, tr)
			if _, err := ValidateAdmission(r); err == nil {
				t.Fatal("invalid admission accepted")
			}
		})
	}
}

func TestAdmissionRejectsChangedAndUnsafeArtifact(t *testing.T) {
	t.Run("digest", func(t *testing.T) {
		r, _, _, _ := validRequest(t, t.TempDir())
		if err := os.WriteFile(filepath.Join(r.StagedRoot, "bin", "controller"), []byte("changed"), 0700); err != nil {
			t.Fatal(err)
		}
		if _, err := ValidateAdmission(r); err == nil {
			t.Fatal("changed artifact accepted")
		}
	})
	t.Run("symlink", func(t *testing.T) {
		r, _, _, _ := validRequest(t, t.TempDir())
		p := filepath.Join(r.StagedRoot, "bin", "controller")
		if err := os.Remove(p); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("/dev/null", p); err != nil {
			t.Fatal(err)
		}
		if _, err := ValidateAdmission(r); err == nil {
			t.Fatal("symlink artifact accepted")
		}
	})
	t.Run("hardlink", func(t *testing.T) {
		r, _, _, _ := validRequest(t, t.TempDir())
		p := filepath.Join(r.StagedRoot, "bin", "controller")
		if err := os.Link(p, filepath.Join(r.StagedRoot, "copy")); err != nil {
			t.Fatal(err)
		}
		if _, err := ValidateAdmission(r); err == nil {
			t.Fatal("hardlinked artifact accepted")
		}
	})
	t.Run("intermediate symlink", func(t *testing.T) {
		r, _, _, _ := validRequest(t, t.TempDir())
		bin := filepath.Join(r.StagedRoot, "bin")
		if err := os.Rename(bin, filepath.Join(r.StagedRoot, "real-bin")); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(filepath.Join(r.StagedRoot, "real-bin"), bin); err != nil {
			t.Fatal(err)
		}
		if _, err := ValidateAdmission(r); err == nil {
			t.Fatal("intermediate symlink accepted")
		}
	})
}

func TestDeploymentInputRequiresMatchingSealedAdmissionAndSnapshot(t *testing.T) {
	r, _, _, _ := validRequest(t, t.TempDir())
	a, err := ValidateAdmission(r)
	if err != nil {
		t.Fatal(err)
	}
	s, err := a.MaterializeSnapshot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Remove()
	if _, err := a.DeploymentInput(s); err != nil {
		t.Fatal(err)
	}
	if _, err := a.DeploymentInput(Snapshot{}); err == nil {
		t.Fatal("forged snapshot accepted")
	}
	r2, _, _, _ := validRequest(t, t.TempDir())
	r2.ExpectedReleaseID = r.ExpectedReleaseID + "-other"
	if _, err := ValidateAdmission(r2); err == nil {
		// The signature fixture does not bind this changed expected ID, so this
		// path must reject before it could mix a snapshot with another release.
		t.Fatal("mismatched admission unexpectedly accepted")
	}
}

func TestStrictLoaderRejectsUnsafeInput(t *testing.T) {
	d := t.TempDir()
	p := filepath.Join(d, "input.json")
	for _, tc := range []struct {
		name, body string
		setup      func()
	}{
		{"unknown", `{"schema":"x","extra":true}`, func() {}},
		{"duplicate", `{"schema":"x","schema":"x"}`, func() {}},
		{"trailing", `{"schema":"x"} {}`, func() {}},
		{"group writable", `{"schema":"x"}`, func() { _ = os.Chmod(p, 0660) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := os.WriteFile(p, []byte(tc.body), 0600); err != nil {
				t.Fatal(err)
			}
			tc.setup()
			var out struct {
				Schema string `json:"schema"`
			}
			if err := LoadStrict(p, &out); err == nil {
				t.Fatal("unsafe loader input accepted")
			}
			_ = os.Chmod(p, 0600)
		})
	}
	t.Run("symlink", func(t *testing.T) {
		if err := os.WriteFile(p, []byte(`{"schema":"x"}`), 0600); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(d, "link.json")
		if err := os.Symlink(p, link); err != nil {
			t.Fatal(err)
		}
		var out map[string]any
		if err := LoadStrict(link, &out); err == nil {
			t.Fatal("input symlink accepted")
		}
	})
	t.Run("hardlink", func(t *testing.T) {
		if err := os.WriteFile(p, []byte(`{"schema":"x"}`), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Link(p, filepath.Join(d, "hard.json")); err != nil {
			t.Fatal(err)
		}
		var out map[string]any
		if err := LoadStrict(p, &out); err == nil {
			t.Fatal("input hardlink accepted")
		}
	})
	t.Run("oversize", func(t *testing.T) {
		big := make([]byte, maxInputBytes+1)
		if err := os.WriteFile(p, big, 0600); err != nil {
			t.Fatal(err)
		}
		var out map[string]any
		if err := LoadStrict(p, &out); err == nil {
			t.Fatal("oversized input accepted")
		}
	})
	t.Run("missing", func(t *testing.T) {
		var out map[string]any
		if err := LoadStrict(filepath.Join(d, "missing.json"), &out); err == nil {
			t.Fatal("missing input accepted")
		}
	})
}

func TestNonceStoreRejectsUnsafeAndReplayStates(t *testing.T) {
	d := t.TempDir()
	p := filepath.Join(d, "nonces.json")
	s := FileNonceStore{Path: p}
	if err := s.ConsumeReleaseNonce(2, "nonce-a"); err != nil {
		t.Fatal(err)
	}
	if err := s.ConsumeReleaseNonce(1, "nonce-b"); err == nil {
		t.Fatal("lower sequence accepted")
	}
	if err := s.ConsumeReleaseNonce(3, "nonce-a"); err == nil {
		t.Fatal("reused nonce accepted")
	}
	if err := os.WriteFile(p+".next", []byte("stale"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := s.ConsumeReleaseNonce(4, "nonce-c"); err == nil {
		t.Fatal("stale temporary accepted")
	}
	if err := os.Remove(p + ".next"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("{"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := s.ConsumeReleaseNonce(4, "nonce-c"); err == nil {
		t.Fatal("corrupt nonce state accepted")
	}
	if err := os.WriteFile(p, []byte(`{"schema":"openduck.release-nonce-state.v1","sequence":0,"nonces":[]}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, 0660); err != nil {
		t.Fatal(err)
	}
	if err := s.ConsumeReleaseNonce(4, "nonce-c"); err == nil {
		t.Fatal("unsafe nonce mode accepted")
	}
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/dev/null", p); err != nil {
		t.Fatal(err)
	}
	if err := s.ConsumeReleaseNonce(4, "nonce-c"); err == nil {
		t.Fatal("nonce state link accepted")
	}
}

func validRequest(t *testing.T, d string) (AdmissionRequest, FileNonceStore, EnvelopeV1, ed25519.PrivateKey) {
	t.Helper()
	stage := filepath.Join(d, "stage")
	if err := os.MkdirAll(filepath.Join(stage, "bin"), 0700); err != nil {
		t.Fatal(err)
	}
	body := []byte("controller-v1")
	if err := os.WriteFile(filepath.Join(stage, "bin", "controller"), body, 0700); err != nil {
		t.Fatal(err)
	}
	m := ManifestV2{Schema: ManifestSchema, ReleaseID: "release-a", ReleaseDigest: digestBytes([]byte("release-a")), Version: "1.0.0", TargetRoot: "/opt/openduck", Artifacts: []Artifact{{Type: "core", Path: "bin/controller", Digest: digestBytes(body), Platform: runtime.GOOS, Arch: runtime.GOARCH, Version: "1.0.0", ActivationGroup: "default", Required: true}}}
	pub, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	trust := TrustBundle{Schema: TrustBundleSchema, Keys: map[string]string{"key-a": hex.EncodeToString(pub)}}
	manifestPath, envelopePath, trustPath := filepath.Join(d, "manifest.json"), filepath.Join(d, "envelope.json"), filepath.Join(d, "trust.json")
	writeJSON(t, manifestPath, m)
	writeJSON(t, trustPath, trust)
	env := EnvelopeV1{Schema: EnvelopeSchema, KeyID: "key-a", ManifestDigest: digest(m), ArtifactSetDigest: artifactSetDigest(m.Artifacts), ReleaseDigest: m.ReleaseDigest, ReleaseVersion: m.Version, TargetRoot: m.TargetRoot, Platform: runtime.GOOS, Arch: runtime.GOARCH, MinInstaller: "1.0.0", Operation: "deploy", RunID: "aaaaaaaa-1111", Activation: "false", Nonce: "nonce-a", Sequence: 2, IssuedAt: time.Unix(1_700_000_000, 0).UTC(), ExpiresAt: time.Unix(1_900_000_000, 0).UTC()}
	env = signEnvelope(t, env, private)
	writeJSON(t, envelopePath, env)
	r := AdmissionRequest{EnvelopePath: envelopePath, ManifestPath: manifestPath, TrustBundlePath: trustPath, StagedRoot: stage, ExpectedReleaseID: m.ReleaseID, ExpectedReleaseDigest: m.ReleaseDigest, ExpectedReleaseVersion: m.Version, ExpectedTargetRoot: m.TargetRoot, ExpectedPlatform: runtime.GOOS, ExpectedArch: runtime.GOARCH, ExpectedOperation: "deploy", ExpectedRunID: "aaaaaaaa-1111", ExpectedActivation: false, InstallerVersion: "1.2.0", Now: time.Unix(1_750_000_000, 0).UTC()}
	return r, FileNonceStore{Path: filepath.Join(d, "nonce-state.json")}, env, private
}

func signEnvelope(t *testing.T, e EnvelopeV1, key ed25519.PrivateKey) EnvelopeV1 {
	t.Helper()
	e.Signature = ""
	b, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	e.Signature = hex.EncodeToString(ed25519.Sign(key, b))
	return e
}

func writeJSON(t *testing.T, path string, v any) {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
}
