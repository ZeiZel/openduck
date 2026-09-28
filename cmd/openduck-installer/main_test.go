package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"openduck/internal/macosinstall"
	"openduck/internal/macosrelease"
	"openduck/internal/releasecatalog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestPlanJSONUsesPureAdmissionWithoutNonceLockSnapshotOrFactory(t *testing.T) {
	args, _ := signedMutationArgs(t)
	args[0] = "--plan-json"
	readEnd, writeEnd, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	prior := os.Stdout
	os.Stdout = writeEnd
	priorLock, priorStore, priorSnapshot, priorFactory := acquireDeploymentLock, releaseNonceStore, materializeAdmission, newProduction
	defer func() {
		acquireDeploymentLock, releaseNonceStore, materializeAdmission, newProduction = priorLock, priorStore, priorSnapshot, priorFactory
	}()
	acquireDeploymentLock = func() (io.Closer, error) { t.Fatal("plan acquired deployment lock"); return nil, nil }
	releaseNonceStore = func() macosrelease.NonceStore { t.Fatal("plan opened nonce store"); return nil }
	materializeAdmission = func(macosrelease.Admission) (macosrelease.Snapshot, error) {
		t.Fatal("plan materialized snapshot")
		return macosrelease.Snapshot{}, nil
	}
	newProduction = func(macosrelease.DeploymentInput) (productionInstaller, error) {
		t.Fatal("plan opened production installer")
		return nil, nil
	}
	runErr := run(args)
	_ = writeEnd.Close()
	os.Stdout = prior
	if runErr != nil {
		t.Fatal(runErr)
	}
	raw, err := io.ReadAll(readEnd)
	if err != nil {
		t.Fatal(err)
	}
	_ = readEnd.Close()
	var report macosinstall.DeploymentPlanV2
	if err := json.Unmarshal(raw, &report); err != nil {
		t.Fatalf("invalid plan JSON %q: %v", raw, err)
	}
	if report.Schema != macosinstall.DeploymentPlanSchemaV2 || report.ReleaseID != "release-a" || report.ReleaseDigest == "" || len(report.Operations) != 20 {
		t.Fatalf("unexpected pure plan: %+v", report)
	}
}

func TestTrustAnchorOperationsAreExplicitAndIsolated(t *testing.T) {
	priorBootstrap := bootstrapInstalledTrustAnchor
	t.Cleanup(func() { bootstrapInstalledTrustAnchor = priorBootstrap })
	called := ""
	bootstrapInstalledTrustAnchor = func(source, digest string) error {
		called = source + ":" + digest
		return nil
	}
	if err := run([]string{"--bootstrap-release-trust", "--trust-bootstrap-source", "/private/var/run/trust.json", "--trust-bootstrap-sha256", strings.Repeat("a", 64)}); err != nil {
		t.Fatalf("bootstrap rejected: %v", err)
	}
	if called != "/private/var/run/trust.json:"+strings.Repeat("a", 64) {
		t.Fatalf("bootstrap inputs not preserved: %q", called)
	}
	if err := run([]string{"--bootstrap-release-trust", "--trust-bootstrap-source", "/private/var/run/trust.json", "--trust-bootstrap-sha256", strings.Repeat("a", 64), "--release-id", "release-a"}); err == nil {
		t.Fatal("bootstrap accepted release apply input")
	}
}

func TestFixedReleaseTrustAnchorIsOutsideQuarantinedInstallRoot(t *testing.T) {
	if strings.HasPrefix(macosrelease.ReleaseTrustAnchorPath, macosinstall.SystemRoot+string(filepath.Separator)) || macosrelease.ReleaseTrustAnchorPath == macosinstall.SystemRoot {
		t.Fatalf("release trust anchor is inside quarantined install root: %s", macosrelease.ReleaseTrustAnchorPath)
	}
	if macosrelease.ReleaseTrustAnchorPath != "/Library/Application Support/OpenDuck.release-trust.v1.json" {
		t.Fatalf("unexpected fixed release trust anchor path: %s", macosrelease.ReleaseTrustAnchorPath)
	}
}

func TestPlanJSONRejectsIncompleteAndUnsafeAdmissionWithoutSideEffects(t *testing.T) {
	t.Run("incomplete", func(t *testing.T) {
		withPlanSideEffectsForbidden(t)
		if err := run([]string{"--plan-json", "--activation=false"}); err == nil {
			t.Fatal("incomplete plan invocation accepted")
		}
	})
	for _, tc := range []struct {
		name   string
		mutate func(*testing.T, string)
	}{
		{"symlink staged artifact", func(t *testing.T, path string) {
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("/dev/null", path); err != nil {
				t.Fatal(err)
			}
		}},
		{"hardlink staged artifact", func(t *testing.T, path string) {
			if err := os.Link(path, path+".copy"); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			args, _ := signedMutationArgs(t)
			args[0] = "--plan-json"
			for n := 0; n+1 < len(args); n++ {
				if args[n] == "--binary-dir" {
					tc.mutate(t, filepath.Join(args[n+1], "bin", "openduck-controller"))
					break
				}
			}
			withPlanSideEffectsForbidden(t)
			if err := run(args); err == nil {
				t.Fatal("unsafe plan admission accepted")
			}
		})
	}
}

func withPlanSideEffectsForbidden(t *testing.T) {
	t.Helper()
	priorLock, priorStore, priorSnapshot, priorFactory := acquireDeploymentLock, releaseNonceStore, materializeAdmission, newProduction
	t.Cleanup(func() {
		acquireDeploymentLock, releaseNonceStore, materializeAdmission, newProduction = priorLock, priorStore, priorSnapshot, priorFactory
	})
	acquireDeploymentLock = func() (io.Closer, error) { t.Fatal("plan acquired deployment lock"); return nil, nil }
	releaseNonceStore = func() macosrelease.NonceStore { t.Fatal("plan opened nonce store"); return nil }
	materializeAdmission = func(macosrelease.Admission) (macosrelease.Snapshot, error) {
		t.Fatal("plan materialized snapshot")
		return macosrelease.Snapshot{}, nil
	}
	newProduction = func(macosrelease.DeploymentInput) (productionInstaller, error) {
		t.Fatal("plan opened production installer")
		return nil, nil
	}
}

func TestMutationAdmitsBeforeFactoryAndPersistsNonce(t *testing.T) {
	args, _ := signedMutationArgs(t)
	priorFactory, priorLock, priorNow, priorStore, priorSnapshot := newProduction, acquireDeploymentLock, nowUTC, releaseNonceStore, materializeAdmission
	defer func() {
		newProduction, acquireDeploymentLock, nowUTC, releaseNonceStore, materializeAdmission = priorFactory, priorLock, priorNow, priorStore, priorSnapshot
	}()
	calls := 0
	newProduction = func(input macosrelease.DeploymentInput) (productionInstaller, error) {
		calls++
		_, source, err := input.InstallerBinding()
		if err != nil {
			t.Fatal(err)
		}
		body, err := os.ReadFile(filepath.Join(source, "bin", "openduck-controller"))
		if err != nil || string(body) != "controller" {
			t.Fatalf("factory received changed staged bytes: %q, %v", body, err)
		}
		return testInstaller{}, nil
	}
	acquireDeploymentLock = func() (io.Closer, error) { return testLock{}, nil }
	nowUTC = func() time.Time { return time.Unix(1_750_000_000, 0).UTC() }
	store := &recordingNonceStore{}
	releaseNonceStore = func() macosrelease.NonceStore { return store }
	for n := 0; n+1 < len(args); n++ {
		if args[n] == "--binary-dir" {
			source := args[n+1]
			materializeAdmission = func(a macosrelease.Admission) (macosrelease.Snapshot, error) {
				if err := os.Chmod(filepath.Join(source, "bin", "openduck-controller"), 0700); err != nil {
					return macosrelease.Snapshot{}, err
				}
				if err := os.WriteFile(filepath.Join(source, "bin", "openduck-controller"), []byte("changed"), 0700); err != nil {
					return macosrelease.Snapshot{}, err
				}
				return a.MaterializeSnapshot(t.TempDir())
			}
			break
		}
	}
	if err := run(args); err != nil {
		t.Fatalf("valid release rejected: %v", err)
	}
	if calls != 1 {
		t.Fatalf("factory calls = %d, want 1", calls)
	}
	if store.calls != 1 {
		t.Fatalf("nonce store calls = %d, want 1", store.calls)
	}
}

func TestMutationBadAdmissionNeverReachesFactoryOrNonce(t *testing.T) {
	args, nonce := signedMutationArgs(t)
	for n := 0; n+1 < len(args); n++ {
		if args[n] == "--release-envelope" {
			var e macosrelease.EnvelopeV1
			b, err := os.ReadFile(args[n+1])
			if err != nil {
				t.Fatal(err)
			}
			if err = json.Unmarshal(b, &e); err != nil {
				t.Fatal(err)
			}
			e.Signature = "bad"
			writeTestJSON(t, args[n+1], e)
			break
		}
	}
	priorFactory, priorLock, priorNow, priorStore, priorSnapshot := newProduction, acquireDeploymentLock, nowUTC, releaseNonceStore, materializeAdmission
	defer func() {
		newProduction, acquireDeploymentLock, nowUTC, releaseNonceStore, materializeAdmission = priorFactory, priorLock, priorNow, priorStore, priorSnapshot
	}()
	calls := 0
	newProduction = func(macosrelease.DeploymentInput) (productionInstaller, error) { calls++; return testInstaller{}, nil }
	acquireDeploymentLock = func() (io.Closer, error) { t.Fatal("lock acquired before pure admission"); return nil, nil }
	nowUTC = func() time.Time { return time.Unix(1_750_000_000, 0).UTC() }
	if err := run(args); err == nil {
		t.Fatal("bad signature accepted")
	}
	if calls != 0 {
		t.Fatalf("factory called %d times after rejection", calls)
	}
	if _, err := os.Stat(nonce); !os.IsNotExist(err) {
		t.Fatalf("nonce exists after rejected admission: %v", err)
	}
}

func TestMutationReleaseMismatchNeverReachesFactoryOrNonce(t *testing.T) {
	args, nonce := signedMutationArgs(t)
	for n := 0; n+1 < len(args); n++ {
		if args[n] == "--release-digest" {
			args[n+1] = testDigest([]byte("other-release"))
			break
		}
	}
	priorFactory, priorLock, priorNow, priorStore, priorSnapshot := newProduction, acquireDeploymentLock, nowUTC, releaseNonceStore, materializeAdmission
	defer func() {
		newProduction, acquireDeploymentLock, nowUTC, releaseNonceStore, materializeAdmission = priorFactory, priorLock, priorNow, priorStore, priorSnapshot
	}()
	calls := 0
	newProduction = func(macosrelease.DeploymentInput) (productionInstaller, error) { calls++; return testInstaller{}, nil }
	acquireDeploymentLock = func() (io.Closer, error) { t.Fatal("lock acquired before pure admission"); return nil, nil }
	nowUTC = func() time.Time { return time.Unix(1_750_000_000, 0).UTC() }
	if err := run(args); err == nil {
		t.Fatal("release mismatch accepted")
	}
	if calls != 0 {
		t.Fatalf("factory called %d times after mismatch", calls)
	}
	if _, err := os.Stat(nonce); !os.IsNotExist(err) {
		t.Fatalf("nonce exists after rejected admission: %v", err)
	}
}

func TestMutationRejectsRotatedNonceStorePath(t *testing.T) {
	args, _ := signedMutationArgs(t)
	args = append(args, "--release-nonce-store", filepath.Join(t.TempDir(), "rotated.json"))
	priorFactory := newProduction
	defer func() { newProduction = priorFactory }()
	calls := 0
	newProduction = func(macosrelease.DeploymentInput) (productionInstaller, error) { calls++; return testInstaller{}, nil }
	if err := run(args); err == nil {
		t.Fatal("caller-selected nonce store accepted")
	}
	if calls != 0 {
		t.Fatalf("factory called %d times with rotated store", calls)
	}
}

func TestDeployRejectsLegacyOrUnboundActivationBeforeFactory(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func([]string) []string
	}{
		{"legacy apply", func(args []string) []string { args[0] = "--apply"; return args }},
		{"missing activation", func(args []string) []string {
			for n, value := range args {
				if value == "--activation=false" {
					return append(args[:n], args[n+1:]...)
				}
			}
			return args
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			args, _ := signedMutationArgs(t)
			priorFactory := newProduction
			defer func() { newProduction = priorFactory }()
			calls := 0
			newProduction = func(macosrelease.DeploymentInput) (productionInstaller, error) { calls++; return testInstaller{}, nil }
			if err := run(tc.edit(args)); err == nil {
				t.Fatal("unsafe mutation invocation accepted")
			}
			if calls != 0 {
				t.Fatalf("factory calls = %d, want 0", calls)
			}
		})
	}
}

type testLock struct{}

func (testLock) Close() error { return nil }

type recordingNonceStore struct{ calls int }

func (s *recordingNonceStore) ConsumeReleaseNonce(uint64, string) error { s.calls++; return nil }

type testInstaller struct{}

func (testInstaller) Close() error { return nil }
func (testInstaller) Deploy(context.Context, bool) (macosinstall.DeploymentEvidence, error) {
	return macosinstall.DeploymentEvidence{ReleaseID: "release-a", Configured: true}, nil
}
func (testInstaller) Apply() error                             { return nil }
func (testInstaller) Verify() error                            { return nil }
func (testInstaller) Stop() error                              { return nil }
func (testInstaller) Rollback() error                          { return nil }
func (testInstaller) FinalizePFEvidence(context.Context) error { return nil }
func (testInstaller) Activate(context.Context) error           { return nil }
func (testInstaller) ServiceLogin(context.Context) error       { return nil }
func (testInstaller) SetAuditRun(string, string) error         { return nil }

func TestDryRunPlanDeclaresJournalAuthorityTopology(t *testing.T) {
	p := (&planOnly{release: "release-a"}).plan()
	groups := map[string]bool{}
	for _, group := range p.Groups {
		groups[group] = true
	}
	for _, group := range []string{"_openduck_installer_checkpoint_channel", "_openduck_installer_anchor_channel"} {
		if !groups[group] {
			t.Fatalf("dry-run plan omits journal group %s", group)
		}
	}
	paths := map[string]bool{}
	for _, path := range p.Paths {
		paths[path] = true
	}
	for _, path := range []string{
		"channels/installer-checkpoint", "channels/installer-anchor",
		"releases/checkpoint-installer", "releases/checkpoint-installer/release-a",
		"releases/anchor-installer", "releases/anchor-installer/release-a",
		"releases/installer-checkpoint", "releases/installer-checkpoint/release-a",
		"releases/installer-anchor", "releases/installer-anchor/release-a",
	} {
		if !paths[path] {
			t.Fatalf("dry-run plan omits journal path %s", path)
		}
	}
}

func TestValidErrorJSONPathRequiresExactRandomInvocationDirectory(t *testing.T) {
	valid := "/private/var/run/openduck-ansible-abc_123/helper-error.json"
	if !validErrorJSONPath(valid) {
		t.Fatalf("valid random handoff path rejected: %q", valid)
	}
	for _, path := range []string{
		"/private/var/run/openduck-ansible-aaaaaaaa-1111/helper-error.json", // signed run-id is not a random suffix
		"/private/var/run/openduck-ansible-Abc123/helper-error.json",
		"/private/var/run/openduck-ansible-short/helper-error.json",
		"/private/var/run/openduck-ansible-abc_123/other.json",
		"/private/var/run/openduck-ansible-abc_123/nested/helper-error.json",
		"/private/var/run/openduck-ansible-abc_123/../helper-error.json",
		"/tmp/openduck-ansible-abc_123/helper-error.json",
	} {
		if validErrorJSONPath(path) {
			t.Fatalf("unsafe error channel accepted: %q", path)
		}
	}
}

func signedMutationArgs(t *testing.T) ([]string, string) {
	t.Helper()
	// Production admission always resolves the fixed root-owned anchor.  The
	// command unit tests exercise the sealed-admission seam with their own
	// strict fixture anchor and therefore install this test-only resolver.
	priorResolver := resolveInstalledTrustAnchor
	resolveInstalledTrustAnchor = func(staged string) (string, error) { return staged, nil }
	t.Cleanup(func() { resolveInstalledTrustAnchor = priorResolver })
	d := t.TempDir()
	stage := filepath.Join(d, "stage")
	if err := os.MkdirAll(filepath.Join(stage, "bin"), 0700); err != nil {
		t.Fatal(err)
	}
	artifacts := make([]macosrelease.Artifact, 0)
	for _, entry := range releasecatalog.Entries() {
		if !entry.Mandatory {
			continue
		}
		path := filepath.Join(stage, entry.Path)
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		body := []byte("artifact:" + entry.Path)
		if entry.Path == "bin/openduck-controller" {
			body = []byte("controller")
		}
		mode := os.FileMode(0400)
		if entry.Executable {
			mode = 0500
		}
		if err := os.WriteFile(path, body, mode); err != nil {
			t.Fatal(err)
		}
		artifacts = append(artifacts, macosrelease.Artifact{Type: entry.Type, Path: entry.Path, Digest: testDigest(body), Platform: runtime.GOOS, Arch: runtime.GOARCH, Version: "1.0.0", ActivationGroup: entry.ActivationGroup, Required: entry.Required})
	}
	releaseDigest := testDigest([]byte("release-a"))
	m := macosrelease.ManifestV2{Schema: macosrelease.ManifestSchema, ReleaseID: "release-a", ReleaseDigest: releaseDigest, Version: "1.0.0", TargetRoot: macosinstall.SystemRoot, Artifacts: artifacts}
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	manifestDigest := testJSONDigest(t, m)
	setDigest := testJSONDigest(t, m.Artifacts)
	e := macosrelease.EnvelopeV1{Schema: macosrelease.EnvelopeSchema, KeyID: "key-a", ManifestDigest: manifestDigest, ArtifactSetDigest: setDigest, ReleaseDigest: releaseDigest, ReleaseVersion: m.Version, TargetRoot: m.TargetRoot, Platform: runtime.GOOS, Arch: runtime.GOARCH, MinInstaller: installerVersion, Operation: "deploy", RunID: "aaaaaaaa-1111", Activation: "false", Nonce: "nonce-a", Sequence: 2, IssuedAt: time.Unix(1_700_000_000, 0).UTC(), ExpiresAt: time.Unix(1_900_000_000, 0).UTC()}
	unsigned, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	e.Signature = hex.EncodeToString(ed25519.Sign(key, unsigned))
	envelope, manifest, trust := filepath.Join(d, "envelope.json"), filepath.Join(d, "manifest.json"), filepath.Join(d, "trust.json")
	writeTestJSON(t, envelope, e)
	writeTestJSON(t, manifest, m)
	writeTestJSON(t, trust, macosrelease.TrustBundle{Schema: macosrelease.TrustBundleSchema, Keys: map[string]string{"key-a": hex.EncodeToString(pub)}})
	nonce := filepath.Join(d, "nonce-state.json")
	return []string{"--deploy", "--activation=false", "--run-id", "aaaaaaaa-1111", "--release-id", m.ReleaseID, "--release-version", m.Version, "--release-digest", releaseDigest, "--binary-dir", stage, "--release-envelope", envelope, "--release-manifest", manifest, "--release-trust-bundle", trust}, nonce
}

func testDigest(b []byte) string { sum := sha256.Sum256(b); return hex.EncodeToString(sum[:]) }
func testJSONDigest(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return testDigest(b)
}
func writeTestJSON(t *testing.T, path string, v any) {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, b, 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
}
