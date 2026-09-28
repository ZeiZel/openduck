package macosinstall

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testReleaseDigest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func TestDoctorJSONUsesConfiguredManifestV2WithExactMetadata(t *testing.T) {
	root := t.TempDir()
	release := "release-20260826"
	for _, path := range []string{"releases", "launchd", "seatbelt", "releases/controller", "releases/controller/" + release} {
		if err := os.MkdirAll(filepath.Join(root, path), 0755); err != nil {
			t.Fatal(err)
		}
	}
	writeState := func(name string) {
		path := filepath.Join(root, name)
		if err := os.WriteFile(path, []byte(release+"\n"), 0644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, 0644); err != nil {
			t.Fatal(err)
		}
	}
	writeState("candidate.release")
	writeState("configured.release")
	if err := os.WriteFile(filepath.Join(root, "release.manifest"), []byte("legacy only\n"), 0440); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(root, "release.manifest"), 0440); err != nil {
		t.Fatal(err)
	}
	report := func() DoctorReport {
		raw, err := doctorJSONForRoot(root, "testos", "testarch", uint32(os.Geteuid()), uint32(os.Getegid()))
		if err != nil {
			t.Fatal(err)
		}
		var got DoctorReport
		if err := json.Unmarshal(raw, &got); err != nil {
			t.Fatal(err)
		}
		return got
	}
	if got := report(); got.Markers["manifest"] {
		t.Fatal("legacy release.manifest satisfied the configured ManifestV2 marker")
	}
	v2 := filepath.Join(root, "releases", "controller", release, "release-manifest.v2.json")
	if err := os.WriteFile(v2, []byte(`{"schema":"openduck.release-manifest.v2"}`+"\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if got := report(); got.Markers["manifest"] {
		t.Fatal("writable ManifestV2 metadata satisfied the marker")
	}
	if err := os.Chmod(v2, 0440); err != nil {
		t.Fatal(err)
	}
	if got := report(); !got.Markers["manifest"] || got.Platform != "testos" || got.Arch != "testarch" {
		t.Fatalf("configured ManifestV2 marker was not observed: %+v", got)
	}
	if err := os.WriteFile(filepath.Join(root, "configured.release"), []byte("../escape\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(root, "configured.release"), 0644); err != nil {
		t.Fatal(err)
	}
	if got := report(); got.Markers["manifest"] || got.Markers["configured"] {
		t.Fatalf("unsafe configured selector was accepted: %+v", got.Markers)
	}
}

func TestDoctorMarkersNeverImplyProviderOperationalReadiness(t *testing.T) {
	root := t.TempDir()
	release := "release-20260830"
	for _, path := range []string{"releases/controller/" + release, "launchd", "seatbelt"} {
		if err := os.MkdirAll(filepath.Join(root, path), 0755); err != nil {
			t.Fatal(err)
		}
	}
	for _, selector := range []string{"candidate.release", "configured.release", "active.release", "activated.release"} {
		if err := os.WriteFile(filepath.Join(root, selector), []byte(release+"\n"), 0644); err != nil {
			t.Fatal(err)
		}
	}
	manifest := filepath.Join(root, "releases/controller", release, "release-manifest.v2.json")
	if err := os.WriteFile(manifest, []byte("{}"), 0440); err != nil {
		t.Fatal(err)
	}
	raw, err := doctorJSONForRoot(root, "darwin", "arm64", uint32(os.Geteuid()), uint32(os.Getegid()))
	if err != nil {
		t.Fatal(err)
	}
	var got DoctorReport
	if json.Unmarshal(raw, &got) != nil {
		t.Fatal("invalid doctor JSON")
	}
	if got.Gates["activation_complete"] != "observed" || got.Gates["operational_ready"] != "unavailable" || len(got.ReasonCodes) == 0 {
		t.Fatalf("markers fabricated provider readiness: %+v", got)
	}
}

func TestSafeProvisioningErrorIsOneRedactedObjectAndClassifiesVerifyFull(t *testing.T) {
	raw := SafeProvisioningError([]string{"--verify-json=full", "--release-id", "release-20260824", "--release-digest", testReleaseDigest, "--run-id", "0123456789abcdef", "--error-json"}, errors.New("verify /private/secret service.key failed"))
	if len(raw) == 0 || raw[0] != '{' || raw[len(raw)-1] != '}' || strings.ContainsAny(string(raw), "\r\n") {
		t.Fatalf("error output is not exactly one JSON object: %q", raw)
	}
	var got ProvisioningError
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if got.Schema != provisioningErrorSchema || got.Phase != ErrorPhaseVerify || got.ReasonCode != ErrorReasonVerificationFailed || got.Scope != "installer" || got.ReleaseDigest != testReleaseDigest || got.RunID != "0123456789abcdef" {
		t.Fatalf("unexpected safe error: %+v", got)
	}
	if strings.Contains(string(raw), "private") || strings.Contains(string(raw), "service.key") || strings.Contains(string(raw), "secret") {
		t.Fatalf("safe error leaked raw details: %s", raw)
	}
}

func TestSafeProvisioningErrorClassifiesSealedDeployAndActivation(t *testing.T) {
	for _, tc := range []struct {
		name, activation, want string
	}{
		{"candidate deploy", "--activation=false", ErrorPhaseDeploy},
		{"activating deploy", "--activation=true", ErrorPhaseActivate},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := SafeProvisioningError([]string{"--deploy", tc.activation, "--release-digest", testReleaseDigest, "--run-id", "0123456789abcdef"}, errors.New("failure"))
			var got ProvisioningError
			if err := json.Unmarshal(raw, &got); err != nil {
				t.Fatal(err)
			}
			if got.Phase != tc.want || got.ReleaseDigest != testReleaseDigest || got.RunID != "0123456789abcdef" {
				t.Fatalf("unexpected deploy classification: %+v", got)
			}
		})
	}
}

func TestRunIDValidationAndPlanJSONAreRedacted(t *testing.T) {
	if err := validateRunID("../escape"); err == nil {
		t.Fatal("path traversal run id accepted")
	}
	if err := validateRunID("short"); err == nil {
		t.Fatal("short run id accepted")
	}
	i, err := NewPlanning("release-20260824")
	if err != nil {
		t.Fatal(err)
	}
	b, err := i.PlanJSON(testReleaseDigest)
	if err != nil {
		t.Fatal(err)
	}
	var got InspectionReport
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if got.Schema != provisioningSchema || got.Version != 1 || got.ReleaseDigest != testReleaseDigest {
		t.Fatalf("unexpected report: %+v", got)
	}
	if strings.Contains(string(b), SystemRoot) || strings.Contains(string(b), "service.key") || strings.Contains(string(b), "GeneratedUID") {
		t.Fatalf("report leaked sensitive or absolute data: %s", b)
	}
}

func TestSetAuditRunPreservesExplicitDigestEqualToReleaseID(t *testing.T) {
	root := filepath.Join(t.TempDir(), "root")
	src := filepath.Join(t.TempDir(), "src")
	i, err := newFakeInstaller(root, testReleaseDigest, src)
	if err != nil {
		t.Fatal(err)
	}
	defer i.Close()
	if err := i.SetAuditRun("0123456789abcdef", testReleaseDigest); err != nil {
		t.Fatal(err)
	}
	if i.releaseDigest != testReleaseDigest {
		t.Fatalf("explicit digest was transformed: got %q", i.releaseDigest)
	}
}

func TestVerifyJSONDoesNotCreateRootOrNormalize(t *testing.T) {
	root := filepath.Join(t.TempDir(), "root")
	src := filepath.Join(t.TempDir(), "src")
	i, err := newFakeInstaller(root, "release-20260824", src)
	if err != nil {
		t.Fatal(err)
	}
	defer i.Close()
	if err := i.SetAuditRun("0123456789abcdef", testReleaseDigest); err != nil {
		t.Fatal(err)
	}
	provisioning := filepath.Join(root, "logs", "provisioning")
	if err := os.MkdirAll(provisioning, 0700); err != nil {
		t.Fatal(err)
	}
	priorLog := filepath.Join(provisioning, "0123456789abcdef.jsonl")
	priorBytes := []byte(`{"schema":"prior","secret":"must-remain"}` + "\n")
	if err := os.WriteFile(priorLog, priorBytes, 0600); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	b, err := i.VerifyJSON(context.Background(), testReleaseDigest, []string{"layout"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"drift":true`) {
		t.Fatalf("expected drift report: %s", b)
	}
	after, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(before) != len(after) {
		t.Fatalf("read-only verify created root entries: before=%d after=%d", len(before), len(after))
	}
	gotLog, err := os.ReadFile(priorLog)
	if err != nil || string(gotLog) != string(priorBytes) {
		t.Fatalf("read-only verify mutated audit log: %q", gotLog)
	}
}

func TestVerifyJSONFullUsesAuthoritativeVerify(t *testing.T) {
	i, root := fixture(t)
	if err := i.Apply(); err != nil {
		t.Fatal(err)
	}
	if err := i.FinalizePFEvidence(context.Background()); err != nil {
		t.Fatal(err)
	}
	b, err := i.VerifyJSON(context.Background(), testReleaseDigest, []string{"full"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"name":"full"`) || strings.Contains(string(b), `"drift":true`) {
		t.Fatalf("complete verification unexpectedly drifted: %s", b)
	}
	active := filepath.Join(root, "active.release")
	if err := os.WriteFile(active, []byte("wrong-release\n"), 0644); err != nil {
		t.Fatal(err)
	}
	b, err = i.VerifyJSON(context.Background(), testReleaseDigest, []string{"full"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"drift":true`) || !strings.Contains(string(b), `"changed":true`) {
		t.Fatalf("complete verification did not report drift: %s", b)
	}
	got, err := os.ReadFile(active)
	if err != nil || string(got) != "wrong-release\n" {
		t.Fatalf("full verify mutated active release: %q", got)
	}
}

func TestVerifyJSONRejectsUnknownScope(t *testing.T) {
	root := filepath.Join(t.TempDir(), "root")
	src := filepath.Join(t.TempDir(), "src")
	i, err := newFakeInstaller(root, "release-20260824", src)
	if err != nil {
		t.Fatal(err)
	}
	defer i.Close()
	if _, err := i.VerifyJSON(context.Background(), testReleaseDigest, []string{"full-ish"}); err == nil {
		t.Fatal("unknown verify scope accepted")
	}
}

func TestAuditModesAndWhitelist(t *testing.T) {
	root := filepath.Join(t.TempDir(), "root")
	src := filepath.Join(t.TempDir(), "src")
	i, err := newFakeInstaller(root, "release-20260824", src)
	if err != nil {
		t.Fatal(err)
	}
	defer i.Close()
	i.auditEnabled = true
	i.runID = "0123456789abcdef"
	i.releaseDigest = testReleaseDigest
	i.audit("apply", "started", "started", "", "", true)
	dir, err := os.Stat(filepath.Join(root, "logs", "provisioning"))
	if err != nil {
		t.Fatal(err)
	}
	if dir.Mode().Perm() != 0700 {
		t.Fatalf("audit directory mode=%o", dir.Mode().Perm())
	}
	path := filepath.Join(root, "logs", "provisioning", i.runID+".jsonl")
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0600 {
		t.Fatalf("audit file mode=%o", st.Mode().Perm())
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "service.key") || strings.Contains(string(raw), "GeneratedUID") || strings.Contains(string(raw), "command") {
		t.Fatalf("audit leaked sensitive field: %s", raw)
	}
}

func TestFailedApplyRetainsAuditEvidence(t *testing.T) {
	root := filepath.Join(t.TempDir(), "root")
	i, err := newFakeInstaller(root, "release-20260824", filepath.Join(t.TempDir(), "missing-stage"))
	if err != nil {
		t.Fatal(err)
	}
	defer i.Close()
	i.auditEnabled = true
	i.runID = "0123456789abcdef"
	i.releaseDigest = testReleaseDigest
	if err := i.Apply(); err == nil {
		t.Fatal("expected apply failure")
	}
	dir, err := os.Stat(filepath.Join(root, "logs", "provisioning"))
	if err != nil || dir.Mode().Perm() != 0700 {
		t.Fatalf("audit directory missing after failed apply: %v", err)
	}
	st, err := os.Stat(filepath.Join(root, "logs", "provisioning", i.runID+".jsonl"))
	if err != nil || st.Mode().Perm() != 0600 {
		t.Fatalf("audit file missing after failed apply: %v", err)
	}
}

func TestAuditDoesNotRepairExistingDirectoryDrift(t *testing.T) {
	root := filepath.Join(t.TempDir(), "root")
	src := filepath.Join(t.TempDir(), "stage")
	if err := os.Mkdir(src, 0700); err != nil {
		t.Fatal(err)
	}
	i, err := newFakeInstaller(root, "release-20260824", src)
	if err != nil {
		t.Fatal(err)
	}
	defer i.Close()
	i.auditEnabled = true
	i.runID = "0123456789abcdef"
	i.releaseDigest = testReleaseDigest
	if err := os.MkdirAll(filepath.Join(root, "logs", "provisioning"), 0755); err != nil {
		t.Fatal(err)
	}
	beforeLogs, err := os.Stat(filepath.Join(root, "logs"))
	if err != nil {
		t.Fatal(err)
	}
	beforeProvisioning, err := os.Stat(filepath.Join(root, "logs", "provisioning"))
	if err != nil {
		t.Fatal(err)
	}
	i.audit("apply", "started", "started", "", "", true)
	afterLogs, _ := os.Stat(filepath.Join(root, "logs"))
	afterProvisioning, _ := os.Stat(filepath.Join(root, "logs", "provisioning"))
	if beforeLogs.Mode().Perm() != afterLogs.Mode().Perm() || beforeProvisioning.Mode().Perm() != afterProvisioning.Mode().Perm() {
		t.Fatal("audit repaired pre-existing directory mode")
	}
	if err := i.Apply(); err == nil {
		t.Fatal("expected apply to reject existing audit directory drift")
	}
	afterApplyLogs, _ := os.Stat(filepath.Join(root, "logs"))
	afterApplyProvisioning, _ := os.Stat(filepath.Join(root, "logs", "provisioning"))
	if beforeLogs.Mode().Perm() != afterApplyLogs.Mode().Perm() || beforeProvisioning.Mode().Perm() != afterApplyProvisioning.Mode().Perm() {
		t.Fatal("failed apply repaired pre-existing directory mode")
	}
	if _, err := os.Stat(filepath.Join(root, "state")); !os.IsNotExist(err) {
		t.Fatalf("apply mutated filesystem before audit failure: %v", err)
	}
}
