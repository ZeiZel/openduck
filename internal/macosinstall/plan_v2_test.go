package macosinstall

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"openduck/internal/macosrelease"
	"openduck/internal/releasecatalog"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"
)

type planArtifactSpec struct{ path, typ string }

func admittedPlanFixture(t *testing.T, specs ...planArtifactSpec) macosrelease.Admission {
	t.Helper()
	if len(specs) == 0 {
		specs = canonicalInstallerArtifacts()
	}
	sort.Slice(specs, func(i, j int) bool { return specs[i].path < specs[j].path })
	root, stage := t.TempDir(), filepath.Join(t.TempDir(), "stage")
	if err := os.MkdirAll(stage, 0700); err != nil {
		t.Fatal(err)
	}
	issuedAt := time.Unix(1_700_000_000, 0).UTC()
	payloads := catalogFixturePayloads(t, specs, issuedAt)
	manifest := macosrelease.ManifestV2{Schema: macosrelease.ManifestSchema, ReleaseID: "release-a", ReleaseDigest: testReleaseDigest, Version: "1.0.0", TargetRoot: SystemRoot}
	for _, spec := range specs {
		body := payloads[spec.path]
		if len(body) == 0 {
			t.Fatalf("missing fixture payload for %q", spec.path)
		}
		path := filepath.Join(stage, spec.path)
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		mode := os.FileMode(0500)
		if entry, found := releasecatalog.EntryFor(spec.path); found && !entry.Executable {
			mode = 0400
		}
		if err := os.WriteFile(path, body, mode); err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(body)
		group, required := "default", true
		if entry, found := releasecatalog.EntryFor(spec.path); found && entry.Type == spec.typ {
			group, required = entry.ActivationGroup, entry.Required
		}
		manifest.Artifacts = append(manifest.Artifacts, macosrelease.Artifact{Type: spec.typ, Path: spec.path, Digest: hex.EncodeToString(sum[:]), Platform: runtime.GOOS, Arch: runtime.GOARCH, Version: manifest.Version, ActivationGroup: group, Required: required})
	}
	pub, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	manifestDigest := planJSONDigest(t, manifest)
	artifactSetDigest := planJSONDigest(t, manifest.Artifacts)
	envelope := macosrelease.EnvelopeV1{Schema: macosrelease.EnvelopeSchema, KeyID: "plan-key", ManifestDigest: manifestDigest, ArtifactSetDigest: artifactSetDigest, ReleaseDigest: manifest.ReleaseDigest, ReleaseVersion: manifest.Version, TargetRoot: manifest.TargetRoot, Platform: runtime.GOOS, Arch: runtime.GOARCH, MinInstaller: "1.0.0", Operation: "deploy", RunID: "0123456789abcdef", Activation: "false", Nonce: "plan-nonce", Sequence: 1, IssuedAt: issuedAt, ExpiresAt: time.Unix(1_900_000_000, 0).UTC()}
	unsigned, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	envelope.Signature = hex.EncodeToString(ed25519.Sign(private, unsigned))
	envelopePath, manifestPath, trustPath := filepath.Join(root, "envelope.json"), filepath.Join(root, "manifest.json"), filepath.Join(root, "trust.json")
	writePlanJSON(t, envelopePath, envelope)
	writePlanJSON(t, manifestPath, manifest)
	writePlanJSON(t, trustPath, macosrelease.TrustBundle{Schema: macosrelease.TrustBundleSchema, Keys: map[string]string{"plan-key": hex.EncodeToString(pub)}})
	admission, err := macosrelease.ValidateAdmission(macosrelease.AdmissionRequest{EnvelopePath: envelopePath, ManifestPath: manifestPath, TrustBundlePath: trustPath, StagedRoot: stage, ExpectedReleaseID: manifest.ReleaseID, ExpectedReleaseDigest: manifest.ReleaseDigest, ExpectedReleaseVersion: manifest.Version, ExpectedTargetRoot: manifest.TargetRoot, ExpectedPlatform: runtime.GOOS, ExpectedArch: runtime.GOARCH, ExpectedOperation: "deploy", ExpectedRunID: "0123456789abcdef", ExpectedActivation: false, InstallerVersion: "1.0.0", Now: time.Unix(1_750_000_000, 0).UTC()})
	if err != nil {
		t.Fatal(err)
	}
	return admission
}

func planJSONDigest(t *testing.T, value any) string {
	t.Helper()
	body, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

func writePlanJSON(t *testing.T, path string, value any) {
	t.Helper()
	body, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, body, 0600); err != nil {
		t.Fatal(err)
	}
}

func TestBuildDeploymentPlanV2IsCanonicalAndClosed(t *testing.T) {
	plan, err := BuildDeploymentPlanV2(admittedPlanFixture(t), "0123456789abcdef", false)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Schema != DeploymentPlanSchemaV2 || plan.Version != 2 || len(plan.Operations) != 20 || !hasPlanTarget(plan, "releases/controller/release-a/openduck-controller") {
		t.Fatalf("plan=%+v", plan)
	}
	if _, err = plan.JSON(); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		edit func(*DeploymentPlanV2)
	}{
		{"root", func(p *DeploymentPlanV2) { p.TargetRoot = "/tmp" }},
		{"schema", func(p *DeploymentPlanV2) { p.Schema = "other" }},
		{"version", func(p *DeploymentPlanV2) { p.Version = 1 }},
		{"release id", func(p *DeploymentPlanV2) { p.ReleaseID = "other" }},
		{"release version", func(p *DeploymentPlanV2) { p.ReleaseVersion = "not-a-version" }},
		{"release digest", func(p *DeploymentPlanV2) { p.ReleaseDigest = "bad" }},
		{"platform", func(p *DeploymentPlanV2) { p.Platform = "other" }},
		{"arch", func(p *DeploymentPlanV2) { p.Arch = "other" }},
		{"run", func(p *DeploymentPlanV2) { p.RunID = "bad" }},
		{"source traversal", func(p *DeploymentPlanV2) { p.Operations[0].Source = "../escape" }},
		{"target traversal", func(p *DeploymentPlanV2) { p.Operations[0].Target = "../escape" }},
		{"target mapping", func(p *DeploymentPlanV2) { p.Operations[0].Target = "releases/other/release-a/openduck-controller" }},
		{"digest", func(p *DeploymentPlanV2) { p.Operations[0].Digest = "bad" }},
		{"type", func(p *DeploymentPlanV2) { p.Operations[0].ArtifactType = "unknown" }},
		{"mode", func(p *DeploymentPlanV2) { p.Operations[0].Mode = "0777" }},
		{"owner", func(p *DeploymentPlanV2) { p.Operations[0].Owner = "operator" }},
		{"group", func(p *DeploymentPlanV2) { p.Operations[0].Group = "staff" }},
		{"preconditions", func(p *DeploymentPlanV2) { p.Operations[0].Preconditions = []string{"arbitrary"} }},
		{"ordered preconditions", func(p *DeploymentPlanV2) {
			p.Operations[0].Preconditions = []string{"digest-match", "admission-validated", "target-safe"}
		}},
		{"operation action", func(p *DeploymentPlanV2) { p.Operations[0].Action = "rollback" }},
		{"duplicate target", func(p *DeploymentPlanV2) {
			p.Operations = append(p.Operations, p.Operations[0])
			p.RollbackPlan = append(p.RollbackPlan, p.RollbackPlan[0])
			p.CleanupPlan = append(p.CleanupPlan, p.CleanupPlan[0])
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bad := plan
			bad.Operations = append([]PlanOperation(nil), plan.Operations...)
			bad.RollbackPlan = append([]PlanOperation(nil), plan.RollbackPlan...)
			bad.CleanupPlan = append([]PlanOperation(nil), plan.CleanupPlan...)
			tc.edit(&bad)
			if err := bad.Validate(); err == nil {
				t.Fatal("invalid plan accepted")
			}
		})
	}
}

func TestBuildDeploymentPlanV2MatchesInstallerCopyInventory(t *testing.T) {
	plan, err := BuildDeploymentPlanV2(admittedPlanFixture(t, canonicalInstallerArtifacts()...), "0123456789abcdef", false)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Operations) != 20 || len(plan.RollbackPlan) != 20 || len(plan.CleanupPlan) != 20 {
		t.Fatalf("operations=%d rollback=%d cleanup=%d, want 20 each", len(plan.Operations), len(plan.RollbackPlan), len(plan.CleanupPlan))
	}
	wantTargets := []string{
		".openduck-installer", ".openduck-native-mcp", ".openduck-provider-attestor", ".openduck-readiness", ".openduck-service-login", "home/controller/bin/openduck-codex-login", "home/runtime/bin/codex",
		"operator/openduck-owner-grant", "releases/anchor-checkpoint/release-a/openduck-anchor", "releases/anchor/release-a/openduck-anchor",
		"releases/anchor-installer/release-a/openduck-anchor", "releases/checkpoint-installer/release-a/openduck-checkpoint",
		"releases/broker/release-a/openduck-codex-broker", "releases/checkpoint/release-a/openduck-checkpoint", "releases/codex/release-a/codex",
		"releases/controller/release-a/openduck-controller", "releases/egress/release-a/openduck-egress", "releases/runtime/release-a/openduck-codex-runtime",
		"releases/installer-anchor/release-a/openduck-installer", "releases/installer-checkpoint/release-a/openduck-installer",
	}
	sort.Strings(wantTargets)
	for n, operation := range plan.Operations {
		if operation.Target != wantTargets[n] {
			t.Fatalf("target[%d]=%q, want %q", n, operation.Target, wantTargets[n])
		}
	}
}

func canonicalInstallerArtifacts() []planArtifactSpec {
	values := make([]planArtifactSpec, 0)
	for _, entry := range releasecatalog.Entries() {
		if entry.Mandatory {
			values = append(values, planArtifactSpec{path: entry.Path, typ: entry.Type})
		}
	}
	return values
}

func TestBuildDeploymentPlanV2RejectsUnmappedArtifact(t *testing.T) {
	specs := append(canonicalInstallerArtifacts(), planArtifactSpec{"providers/unknown", "provider_plugin"})
	a := admittedPlanFixture(t, specs...)
	if _, err := BuildDeploymentPlanV2(a, "0123456789abcdef", false); err == nil {
		t.Fatal("unmapped artifact accepted")
	}
}

func TestBuildDeploymentPlanV2IncludesOnlyInactiveProviderOutputs(t *testing.T) {
	for _, tc := range []struct {
		group  string
		target string
	}{
		{"provider-codex", "providers/inactive/codex/runtime-descriptor.json"},
		{"provider-claude", "providers/inactive/claude/runtime-descriptor.json"},
		{"provider-qwen", "providers/inactive/qwen/runtime-descriptor.json"},
		{"provider-kimi", "providers/inactive/kimi/runtime-descriptor.json"},
		{"provider-deepseek", "providers/inactive/deepseek/dsh-adapter-descriptor.json"},
	} {
		t.Run(tc.group, func(t *testing.T) {
			specs := append(canonicalInstallerArtifacts(), catalogGroupArtifactSpecs("provider-policy")...)
			specs = append(specs, catalogGroupArtifactSpecs(tc.group)...)
			plan, err := BuildDeploymentPlanV2(admittedPlanFixture(t, specs...), "0123456789abcdef", false)
			if err != nil {
				t.Fatalf("closed provider plan rejected: %v", err)
			}
			if plan.Activation {
				t.Fatal("inactive provider package turned activation on")
			}
			found := false
			for _, operation := range plan.Operations {
				if operation.Target == tc.target {
					found = operation.Mode == "0440" && operation.Owner == "root" && operation.Group == "_openduck"
				}
				if strings.Contains(operation.Target, "provider-lifecycle-operation") || strings.Contains(operation.Target, "controller-owner-ed25519") || strings.Contains(operation.Target, "subscription") {
					t.Fatalf("standing lifecycle/key/subscription output found: %+v", operation)
				}
			}
			if !found {
				t.Fatalf("inactive provider output missing/mismatched: %s", tc.target)
			}
			provider := strings.TrimPrefix(tc.group, "provider-")
			for _, target := range []string{"providers/inactive/" + provider + "/openduck-provider-" + provider, "providers/inactive/" + provider + "/topology.json"} {
				if !hasPlanTarget(plan, target) {
					t.Fatalf("closed inactive provider contract missing %s", target)
				}
				foundRollback := false
				for _, operation := range plan.RollbackPlan {
					foundRollback = foundRollback || operation.Target == target
				}
				if !foundRollback {
					t.Fatalf("rollback omits coherent provider target %s", target)
				}
			}
		})
	}

	t.Run("orphan policy", func(t *testing.T) {
		specs := append(canonicalInstallerArtifacts(), catalogGroupArtifactSpecs("provider-policy")...)
		if _, err := BuildDeploymentPlanV2(admittedPlanFixture(t, specs...), "0123456789abcdef", false); err == nil {
			t.Fatal("orphan provider policy accepted")
		}
	})

	t.Run("partial group", func(t *testing.T) {
		specs := append(canonicalInstallerArtifacts(), planArtifactSpec{path: "provider-bundle.json", typ: "policy"})
		if _, err := BuildDeploymentPlanV2(admittedPlanFixture(t, specs...), "0123456789abcdef", false); err == nil {
			t.Fatal("partial optional provider group accepted")
		}
	})
}

func hasPlanTarget(plan DeploymentPlanV2, target string) bool {
	for _, operation := range plan.Operations {
		if operation.Target == target {
			return true
		}
	}
	return false
}

func catalogGroupArtifactSpecs(group string) []planArtifactSpec {
	values := make([]planArtifactSpec, 0)
	for _, entry := range releasecatalog.Entries() {
		if entry.ActivationGroup == group {
			values = append(values, planArtifactSpec{path: entry.Path, typ: entry.Type})
		}
	}
	return values
}

func TestBuildDeploymentPlanV2RequiresSealedIntentAndCrossPlanEquality(t *testing.T) {
	admission := admittedPlanFixture(t)
	if _, err := BuildDeploymentPlanV2(macosrelease.Admission{}, "0123456789abcdef", false); err == nil {
		t.Fatal("forged zero admission accepted")
	}
	if _, err := BuildDeploymentPlanV2(admission, "other-run", false); err == nil {
		t.Fatal("different signed run accepted")
	}
	if _, err := BuildDeploymentPlanV2(admission, "0123456789abcdef", true); err == nil {
		t.Fatal("different signed activation accepted")
	}
	plan, err := BuildDeploymentPlanV2(admission, "0123456789abcdef", false)
	if err != nil {
		t.Fatal(err)
	}
	plan.RollbackPlan[0].Digest = testReleaseDigest
	if err := plan.Validate(); err == nil {
		t.Fatal("cross-plan digest drift accepted")
	}
}
