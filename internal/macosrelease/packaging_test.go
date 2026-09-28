package macosrelease

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"openduck/internal/providerbridge"
	"openduck/internal/providerrevision"
	"openduck/internal/providertransport"
	"openduck/internal/releasecatalog"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

func TestPackageIsDeterministicAndFinalizesForAdmission(t *testing.T) {
	d := t.TempDir()
	in := validPackageFixture(t, d)
	m1, err := BuildManifest(in)
	if err != nil {
		t.Fatal(err)
	}
	m2, err := BuildManifest(in)
	if err != nil || !reflect.DeepEqual(m1, m2) {
		t.Fatalf("manifest not deterministic: %v", err)
	}
	if m1.ReleaseID == m1.ReleaseDigest || len(m1.Artifacts) != len(mandatoryCatalogEntries()) {
		t.Fatalf("release identity/digest or artifact catalog invalid: %+v", m1)
	}
	r1, err := BuildSigningRequest(in, m1)
	if err != nil {
		t.Fatal(err)
	}
	r2, err := BuildSigningRequest(in, m2)
	if err != nil || !reflect.DeepEqual(r1, r2) {
		t.Fatalf("request not deterministic: %v", err)
	}
	if r1.ReleaseID != in.ReleaseID || r1.ReleaseVersion != in.Version || r1.TargetRoot != in.TargetRoot || r1.Platform != in.Platform || r1.Arch != in.Arch {
		t.Fatalf("request omits inspectable manifest binding: %+v", r1)
	}
	var unsigned EnvelopeV1
	payload, err := base64.StdEncoding.DecodeString(r1.UnsignedPayload)
	if err != nil || strictDecode(payload, &unsigned) != nil {
		t.Fatal("cannot parse request payload")
	}
	want, err := UnsignedEnvelopePayload(unsigned)
	if err != nil || string(want) != string(payload) {
		t.Fatal("request payload differs from admission signature bytes")
	}

	manifestPath, requestPath, signaturePath, trustPath, envelopePath := filepath.Join(d, "manifest.json"), filepath.Join(d, "request.json"), filepath.Join(d, "signature.json"), filepath.Join(d, "trust.json"), filepath.Join(d, "envelope.json")
	if err := WriteNewCanonical(manifestPath, m1); err != nil {
		t.Fatal(err)
	}
	pub, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteNewCanonical(requestPath, r1); err != nil {
		t.Fatal(err)
	}
	if err := WriteNewCanonical(trustPath, TrustBundle{Schema: TrustBundleSchema, Keys: map[string]string{in.KeyID: hex.EncodeToString(pub)}}); err != nil {
		t.Fatal(err)
	}
	s := ExternalSignatureV1{Schema: SignatureSchema, Algorithm: "ed25519", KeyID: in.KeyID, PayloadDigest: r1.PayloadDigest, Signature: hex.EncodeToString(ed25519.Sign(private, payload))}
	if err := WriteNewCanonical(signaturePath, s); err != nil {
		t.Fatal(err)
	}
	if _, err := Finalize(FinalizeInput{RequestPath: requestPath, SignaturePath: signaturePath, TrustBundlePath: trustPath, EnvelopeOutput: envelopePath, Now: in.IssuedAt.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if _, err := ValidateAdmission(AdmissionRequest{EnvelopePath: envelopePath, ManifestPath: manifestPath, TrustBundlePath: trustPath, StagedRoot: in.StageRoot, ExpectedReleaseID: in.ReleaseID, ExpectedReleaseDigest: m1.ReleaseDigest, ExpectedReleaseVersion: in.Version, ExpectedTargetRoot: in.TargetRoot, ExpectedPlatform: in.Platform, ExpectedArch: in.Arch, ExpectedOperation: in.Operation, ExpectedRunID: in.RunID, ExpectedActivation: in.Activation, InstallerVersion: in.MinInstaller, Now: in.IssuedAt.Add(time.Hour)}); err != nil {
		t.Fatalf("finalized envelope was not admitted: %v", err)
	}
}

func TestPackageRejectsUnsafeOrUnknownStageAndNonCatalogManifest(t *testing.T) {
	for _, tc := range []struct {
		name  string
		alter func(t *testing.T, in PackageInput)
	}{
		{"unknown", func(t *testing.T, in PackageInput) {
			if err := os.WriteFile(filepath.Join(in.StageRoot, "extra"), []byte("x"), 0500); err != nil {
				t.Fatal(err)
			}
		}},
		{"symlink", func(t *testing.T, in PackageInput) {
			p := filepath.Join(in.StageRoot, firstMandatoryCatalogEntry(t).Path)
			if err := os.Remove(p); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("/dev/null", p); err != nil {
				t.Fatal(err)
			}
		}},
		{"hardlink", func(t *testing.T, in PackageInput) {
			entries := mandatoryCatalogEntries()
			if len(entries) < 2 {
				t.Fatal("mandatory catalog unexpectedly short")
			}
			source, target := filepath.Join(in.StageRoot, entries[0].Path), filepath.Join(in.StageRoot, entries[1].Path)
			if err := os.Remove(target); err != nil {
				t.Fatal(err)
			}
			if err := os.Link(source, target); err != nil {
				t.Fatal(err)
			}
		}},
		{"writable", func(t *testing.T, in PackageInput) {
			if err := os.Chmod(filepath.Join(in.StageRoot, firstMandatoryCatalogEntry(t).Path), 0660); err != nil {
				t.Fatal(err)
			}
		}},
		{"writable directory", func(t *testing.T, in PackageInput) {
			if err := os.Chmod(filepath.Join(in.StageRoot, "bin"), 0770); err != nil {
				t.Fatal(err)
			}
		}},
		{"special file mode", func(t *testing.T, in PackageInput) {
			path := filepath.Join(in.StageRoot, firstMandatoryCatalogEntry(t).Path)
			if err := os.Chmod(path, 0500|os.ModeSetgid); err != nil {
				t.Fatal(err)
			}
			info, err := os.Lstat(path)
			if err != nil {
				t.Fatal(err)
			}
			if info.Mode()&os.ModeSetgid == 0 {
				t.Skip("test filesystem did not retain setgid metadata")
			}
		}},
		{"special directory mode", func(t *testing.T, in PackageInput) {
			path := filepath.Join(in.StageRoot, "bin")
			if err := os.Chmod(path, 0700|os.ModeSticky); err != nil {
				t.Fatal(err)
			}
			info, err := os.Lstat(path)
			if err != nil {
				t.Fatal(err)
			}
			if info.Mode()&os.ModeSticky == 0 {
				t.Skip("test filesystem did not retain sticky metadata")
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := validPackageFixture(t, t.TempDir())
			tc.alter(t, in)
			if _, err := BuildManifest(in); err == nil {
				t.Fatal("unsafe stage accepted")
			}
		})
	}
	in := validPackageFixture(t, t.TempDir())
	m, err := BuildManifest(in)
	if err != nil {
		t.Fatal(err)
	}
	m.Artifacts = append(m.Artifacts, m.Artifacts[0])
	if _, err := BuildSigningRequest(in, m); err == nil {
		t.Fatal("duplicate artifact accepted")
	}
	m, _ = BuildManifest(in)
	m.Artifacts[0].Type = "policy"
	if _, err := BuildSigningRequest(in, m); err == nil {
		t.Fatal("catalog collision accepted")
	}
	m, _ = BuildManifest(in)
	m.Artifacts[0].Path = "../escape"
	if _, err := BuildSigningRequest(in, m); err == nil {
		t.Fatal("traversal artifact accepted")
	}
	m, _ = BuildManifest(in)
	m.ReleaseDigest = strings.Repeat("0", 64)
	if _, err := BuildSigningRequest(in, m); err == nil {
		t.Fatal("caller-provided release digest accepted")
	}
	m, _ = BuildManifest(in)
	m.Artifacts[0].Platform = "other"
	if _, err := BuildSigningRequest(in, m); err == nil {
		t.Fatal("manifest platform mismatch accepted")
	}
}

func TestBuildManifestAcceptsOnlyCompleteClosedProviderGroups(t *testing.T) {
	groups := []string{"provider-policy", "provider-codex", "provider-claude", "provider-kimi", "provider-deepseek"}
	for _, group := range groups {
		t.Run(group, func(t *testing.T) {
			if group == "provider-policy" {
				in := validPackageFixture(t, t.TempDir())
				writeProviderPolicyStage(t, in.StageRoot, nil)
				if _, err := BuildManifest(in); err == nil {
					t.Fatal("orphan provider policy accepted")
				}
				return
			}
			in := validPackageFixture(t, t.TempDir())
			added := addCatalogGroup(t, in.StageRoot, group)
			writeProviderPolicyStage(t, in.StageRoot, runtimeEntries(added))
			manifest, err := BuildManifest(in)
			if err != nil {
				t.Fatalf("complete provider group rejected: %v", err)
			}
			if manifest.ReleaseID == manifest.ReleaseDigest || !canonicalCatalog(manifest.Artifacts) {
				t.Fatalf("invalid closed provider manifest: %+v", manifest)
			}
			for _, entry := range added {
				found := false
				for _, artifact := range manifest.Artifacts {
					if artifact.Path == entry.Path {
						found = artifact.Type == entry.Type && artifact.ActivationGroup == group && artifact.Required == entry.Required
					}
				}
				if !found {
					t.Fatalf("provider artifact %q missing or mismatched", entry.Path)
				}
			}
			if _, err := BuildSigningRequest(in, manifest); err != nil {
				t.Fatalf("provider manifest not signing-request eligible: %v", err)
			}
		})
	}

	t.Run("incomplete policy", func(t *testing.T) {
		in := validPackageFixture(t, t.TempDir())
		entry, ok := releasecatalog.EntryFor("provider-bundle.json")
		if !ok {
			t.Fatal("provider bundle missing from catalog")
		}
		writeCatalogStageArtifact(t, in.StageRoot, entry)
		if _, err := BuildManifest(in); err == nil {
			t.Fatal("partial provider policy group accepted")
		}
	})

	t.Run("metadata executable", func(t *testing.T) {
		in := validPackageFixture(t, t.TempDir())
		addCatalogGroup(t, in.StageRoot, "provider-policy")
		if err := os.Chmod(filepath.Join(in.StageRoot, "provider-bundle.json"), 0500); err != nil {
			t.Fatal(err)
		}
		if _, err := BuildManifest(in); err == nil {
			t.Fatal("executable provider metadata accepted")
		}
	})

	t.Run("unapproved lifecycle or subscription leaf", func(t *testing.T) {
		for _, forbidden := range []string{"provider-lifecycle-operation.json", "controller-owner-ed25519.json", "providers/deepseek/subscription.json"} {
			t.Run(forbidden, func(t *testing.T) {
				in := validPackageFixture(t, t.TempDir())
				if strings.HasPrefix(forbidden, "providers/deepseek/") {
					addCatalogGroup(t, in.StageRoot, "provider-deepseek")
				}
				path := filepath.Join(in.StageRoot, forbidden)
				if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte("not-authorized"), 0400); err != nil {
					t.Fatal(err)
				}
				if _, err := BuildManifest(in); err == nil {
					t.Fatalf("forbidden staged leaf accepted: %s", forbidden)
				}
			})
		}
	})
}

// Qwen's production closure is a fixed 74 MiB archive with a 5,790-file
// inventory. A byte-string stand-in would silently train catalog admission to
// accept a fabricated fixed digest, so ordinary unit fixtures must fail closed.
func TestBuildManifestRejectsSyntheticQwenClosureFixture(t *testing.T) {
	in := validPackageFixture(t, t.TempDir())
	added := addCatalogGroup(t, in.StageRoot, "provider-qwen")
	writeProviderPolicyStage(t, in.StageRoot, runtimeEntries(added))
	if _, err := BuildManifest(in); err == nil {
		t.Fatal("synthetic Qwen closure fixture admitted")
	}
}

func TestOptionalProviderPayloadValidationMatchesControllerAtEnvelopeIssuedAt(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*testing.T, string)
	}{
		{"execution limits", func(t *testing.T, stage string) {
			rewriteProviderPolicyFixture(t, stage, true, func(bundle *providerrevision.Bundle, _ *providerbridge.Ed25519TrustBundle) {
				bundle.Profiles[0].Limits.MaxDepth++
			})
		}},
		{"mapping", func(t *testing.T, stage string) {
			rewriteProviderPolicyFixture(t, stage, true, func(bundle *providerrevision.Bundle, _ *providerbridge.Ed25519TrustBundle) {
				bundle.Profiles[0].Mapping.RuntimeVersion = "other-runtime@1"
				if err := bundle.Profiles[0].Mapping.Seal(); err != nil {
					t.Fatal(err)
				}
				bundle.Profiles[0].Profile.MappingDigest = bundle.Profiles[0].Mapping.Digest
			})
		}},
		{"evidence compatibility", func(t *testing.T, stage string) {
			rewriteProviderPolicyFixture(t, stage, true, func(bundle *providerrevision.Bundle, _ *providerbridge.Ed25519TrustBundle) {
				evidence := &bundle.Profiles[0].Evidence
				evidence.RuntimeArtifactDigest = providerbridge.DigestBytes([]byte("other-runtime"))
				if err := evidence.Seal(); err != nil {
					t.Fatal(err)
				}
				reapproveFixtureEvidence(t, evidence)
				bundle.Profiles[0].Profile.ProviderEvidenceDigest = evidence.Digest
			})
		}},
		{"evidence signature", func(t *testing.T, stage string) {
			rewriteProviderPolicyFixture(t, stage, true, func(bundle *providerrevision.Bundle, _ *providerbridge.Ed25519TrustBundle) {
				bundle.Profiles[0].Evidence.Approvals[0].Signature = strings.Repeat("0", ed25519.SignatureSize*2)
			})
		}},
		{"revoked reviewer", func(t *testing.T, stage string) {
			rewriteProviderPolicyFixture(t, stage, true, func(_ *providerrevision.Bundle, trust *providerbridge.Ed25519TrustBundle) {
				trust.Revoked = []string{"technical-ed25519"}
			})
		}},
		{"trust digest", func(t *testing.T, stage string) {
			rewriteProviderPolicyFixture(t, stage, false, func(bundle *providerrevision.Bundle, _ *providerbridge.Ed25519TrustBundle) {
				bundle.TrustBundleDigest = "sha256:" + strings.Repeat("0", 64)
			})
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in, _ := optionalProviderStageFixture(t, "provider-codex")
			tc.mutate(t, in.StageRoot)
			if _, err := BuildManifest(in); err == nil {
				t.Fatal("Controller-incompatible disabled provider policy accepted")
			}
		})
	}

	in, _ := optionalProviderStageFixture(t, "provider-codex")
	payloads := stageCatalogPayloads(t, in.StageRoot)
	if err := ValidateCatalogPayloads(payloads, in.IssuedAt.Add(2*time.Hour)); err == nil {
		t.Fatal("stale provider evidence accepted at a drifted validation instant")
	}
	if _, err := BuildManifest(in); err != nil {
		t.Fatalf("BuildManifest did not use explicit package IssuedAt: %v", err)
	}
	if err := ValidateCatalogPayloads(payloads, time.Time{}); err == nil {
		t.Fatal("zero validation instant accepted")
	}
}

func TestDeepSeekAdapterIsRuntimeOnlyAndContentValidated(t *testing.T) {
	in, entries := optionalProviderStageFixture(t, "provider-deepseek")
	var runtime releasecatalog.Entry
	for _, entry := range entries {
		if entry.Type == "provider_runtime" {
			runtime = entry
		}
	}
	if runtime.Path != "providers/deepseek/dsh-adapter-descriptor.json" {
		t.Fatalf("deepseek catalog runtime=%+v", runtime)
	}
	if _, found := releasecatalog.EntryFor("providers/deepseek/plugin-descriptor.json"); found {
		t.Fatal("DeepSeek native plugin leaf catalogued")
	}
	if _, err := BuildManifest(in); err != nil {
		t.Fatalf("valid DeepSeek transport descriptor rejected: %v", err)
	}
	pluginEntry := runtime
	pluginEntry.Type = "provider_plugin"
	plugin, err := releasecatalog.CanonicalPluginMetadata(pluginEntry)
	if err != nil {
		t.Fatal(err)
	}
	writeStageFixturePayload(t, filepath.Join(in.StageRoot, runtime.Path), plugin)
	if _, err := BuildManifest(in); err == nil {
		t.Fatal("plugin metadata accepted at DeepSeek transport runtime path")
	}
	writeStageFixturePayload(t, filepath.Join(in.StageRoot, runtime.Path), catalogStagePayload(t, runtime))
	if _, err := BuildManifest(in); err != nil {
		t.Fatalf("restored DeepSeek transport descriptor rejected: %v", err)
	}
}

func TestSignedCatalogStageRejectsInactiveProviderDescriptorSubstitution(t *testing.T) {
	in, entries := optionalProviderStageFixture(t, "provider-codex")
	manifest, err := BuildManifest(in)
	if err != nil {
		t.Fatal(err)
	}
	var runtime releasecatalog.Entry
	for _, entry := range entries {
		if entry.Type == "provider_runtime" {
			runtime = entry
		}
	}
	path := filepath.Join(in.StageRoot, runtime.Path)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	descriptor, err := providertransport.DecodeInactiveDescriptor(raw)
	if err != nil {
		t.Fatal(err)
	}
	descriptor.MappingDigest = "sha256:" + strings.Repeat("d", 64)
	if err := descriptor.Seal(); err != nil {
		t.Fatal(err)
	}
	replacement, err := json.Marshal(descriptor)
	if err != nil {
		t.Fatal(err)
	}
	writeStageFixturePayload(t, path, replacement)
	if err := ValidateCatalogStage(in.StageRoot, manifest, in.IssuedAt); err == nil {
		t.Fatal("sealed catalog accepted a substituted channel_gid descriptor")
	}
}

func TestProviderPolicyProfilesMustExactlyMatchSelectedRuntimeGroups(t *testing.T) {
	in := validPackageFixture(t, t.TempDir())
	claude := addCatalogGroup(t, in.StageRoot, "provider-claude")
	codex := catalogGroupEntries(t, "provider-codex")
	writeProviderPolicyStage(t, in.StageRoot, runtimeEntries(codex))
	if _, err := BuildManifest(in); err == nil {
		t.Fatalf("cross-provider policy/runtime swap accepted for %v", claude)
	}
}

func optionalProviderStageFixture(t *testing.T, group string) (PackageInput, []releasecatalog.Entry) {
	t.Helper()
	in := validPackageFixture(t, t.TempDir())
	entries := addCatalogGroup(t, in.StageRoot, group)
	writeProviderPolicyStage(t, in.StageRoot, runtimeEntries(entries))
	if _, err := BuildManifest(in); err != nil {
		t.Fatalf("valid optional provider fixture %q: %v", group, err)
	}
	return in, entries
}

func catalogGroupEntries(t *testing.T, group string) []releasecatalog.Entry {
	t.Helper()
	entries := make([]releasecatalog.Entry, 0)
	for _, entry := range releasecatalog.Entries() {
		if entry.ActivationGroup == group {
			entries = append(entries, entry)
		}
	}
	if len(entries) == 0 {
		t.Fatalf("unknown catalog group %q", group)
	}
	return entries
}

func stageCatalogPayloads(t *testing.T, stage string) map[string][]byte {
	t.Helper()
	payloads := make(map[string][]byte)
	for _, entry := range releasecatalog.Entries() {
		body, err := os.ReadFile(filepath.Join(stage, entry.Path))
		if err == nil {
			payloads[entry.Path] = body
		}
	}
	return payloads
}

func rewriteProviderPolicyFixture(t *testing.T, stage string, bindTrustDigest bool, mutate func(*providerrevision.Bundle, *providerbridge.Ed25519TrustBundle)) {
	t.Helper()
	bundleRaw, err := os.ReadFile(filepath.Join(stage, "provider-bundle.json"))
	if err != nil {
		t.Fatal(err)
	}
	trustRaw, err := os.ReadFile(filepath.Join(stage, "provider-trust.json"))
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := providerrevision.Decode(bundleRaw)
	if err != nil {
		t.Fatal(err)
	}
	trust, err := providerbridge.DecodeEd25519TrustBundle(trustRaw)
	if err != nil {
		t.Fatal(err)
	}
	mutate(&bundle, &trust)
	trustRaw, err = json.Marshal(trust)
	if err != nil {
		t.Fatal(err)
	}
	if bindTrustDigest {
		bundle.TrustBundleDigest = providerbridge.DigestBytes(trustRaw)
	}
	if err := bundle.Seal(); err != nil {
		t.Fatal(err)
	}
	bundleRaw, err = json.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	writeStageFixturePayload(t, filepath.Join(stage, "provider-bundle.json"), bundleRaw)
	writeStageFixturePayload(t, filepath.Join(stage, "provider-trust.json"), trustRaw)
}

func reapproveFixtureEvidence(t *testing.T, evidence *providerbridge.ProviderEvidenceRecord) {
	t.Helper()
	if evidence == nil || len(evidence.Approvals) != 2 {
		t.Fatal("invalid fixture evidence approvals")
	}
	technical := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, ed25519.SeedSize))
	security := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{2}, ed25519.SeedSize))
	for index := range evidence.Approvals {
		approval := &evidence.Approvals[index]
		approval.EvidenceDigest = evidence.Digest
		switch approval.Role {
		case "technical":
			approval.Signature = hex.EncodeToString(ed25519.Sign(technical, []byte(evidence.Digest)))
		case "security":
			approval.Signature = hex.EncodeToString(ed25519.Sign(security, []byte(evidence.Digest)))
		default:
			t.Fatal("unexpected fixture evidence role")
		}
	}
}

func writeStageFixturePayload(t *testing.T, path string, body []byte) {
	t.Helper()
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, body, 0400); err != nil {
		t.Fatal(err)
	}
}

func TestFinalizeRejectsBadBindingTrustSignatureExpiryAndOverwrite(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*SigningRequestV1, *ExternalSignatureV1, *TrustBundle)
	}{
		{"signature", func(_ *SigningRequestV1, s *ExternalSignatureV1, _ *TrustBundle) {
			s.Signature = strings.Repeat("00", ed25519.SignatureSize)
		}},
		{"key", func(_ *SigningRequestV1, s *ExternalSignatureV1, _ *TrustBundle) { s.KeyID = "other-key" }},
		{"revoked", func(_ *SigningRequestV1, _ *ExternalSignatureV1, tr *TrustBundle) {
			tr.Revoked = []string{"release-key"}
		}},
		{"request mismatch", func(r *SigningRequestV1, _ *ExternalSignatureV1, _ *TrustBundle) { r.RunID = "bbbbbbbb-2222" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, in, request, signature, trust := finalizedFixture(t)
			tc.change(&request, &signature, &trust)
			writePackagingJSON(t, filepath.Join(d, "request.json"), request)
			writePackagingJSON(t, filepath.Join(d, "signature.json"), signature)
			writePackagingJSON(t, filepath.Join(d, "trust.json"), trust)
			if _, err := Finalize(FinalizeInput{RequestPath: filepath.Join(d, "request.json"), SignaturePath: filepath.Join(d, "signature.json"), TrustBundlePath: filepath.Join(d, "trust.json"), EnvelopeOutput: filepath.Join(d, "out.json"), Now: in.IssuedAt.Add(time.Hour)}); err == nil {
				t.Fatal("invalid finalization accepted")
			}
		})
	}
	d, in, request, signature, trust := finalizedFixture(t)
	writePackagingJSON(t, filepath.Join(d, "request.json"), request)
	writePackagingJSON(t, filepath.Join(d, "signature.json"), signature)
	writePackagingJSON(t, filepath.Join(d, "trust.json"), trust)
	out := filepath.Join(d, "out.json")
	if _, err := Finalize(FinalizeInput{RequestPath: filepath.Join(d, "request.json"), SignaturePath: filepath.Join(d, "signature.json"), TrustBundlePath: filepath.Join(d, "trust.json"), EnvelopeOutput: out, Now: in.ExpiresAt}); err == nil {
		t.Fatal("expired request accepted")
	}
	if err := WriteNewCanonical(out, request); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(out)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("unsafe output mode: %v %v", info.Mode(), err)
	}
	if err := WriteNewCanonical(out, request); err == nil {
		t.Fatal("overwrite accepted")
	}
}

func TestFinalizeRejectsEveryInspectableRequestBinding(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*SigningRequestV1)
	}{
		{"release id", func(r *SigningRequestV1) { r.ReleaseID = "other-release" }},
		{"release version", func(r *SigningRequestV1) { r.ReleaseVersion = "9.9.9" }},
		{"target root", func(r *SigningRequestV1) { r.TargetRoot = "/opt/other" }},
		{"platform", func(r *SigningRequestV1) { r.Platform = "other" }},
		{"arch", func(r *SigningRequestV1) { r.Arch = "other" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, in, request, signature, trust := finalizedFixture(t)
			tc.change(&request)
			writePackagingJSON(t, filepath.Join(d, "request.json"), request)
			writePackagingJSON(t, filepath.Join(d, "signature.json"), signature)
			writePackagingJSON(t, filepath.Join(d, "trust.json"), trust)
			if _, err := Finalize(FinalizeInput{RequestPath: filepath.Join(d, "request.json"), SignaturePath: filepath.Join(d, "signature.json"), TrustBundlePath: filepath.Join(d, "trust.json"), EnvelopeOutput: filepath.Join(d, "out.json"), Now: in.IssuedAt.Add(time.Hour)}); err == nil {
				t.Fatal("explicit request binding mismatch accepted")
			}
		})
	}
}

func TestFinalizeRejectsNonCanonicalEncodingAndPublicMaterial(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*SigningRequestV1, *ExternalSignatureV1, *TrustBundle)
	}{
		{"raw base64", func(r *SigningRequestV1, _ *ExternalSignatureV1, _ *TrustBundle) {
			r.UnsignedPayload = noncanonicalBase64(r.UnsignedPayload)
		}},
		{"uppercase payload digest", func(r *SigningRequestV1, _ *ExternalSignatureV1, _ *TrustBundle) {
			r.PayloadDigest = strings.ToUpper(r.PayloadDigest)
		}},
		{"uppercase signature", func(_ *SigningRequestV1, s *ExternalSignatureV1, _ *TrustBundle) {
			s.Signature = strings.ToUpper(s.Signature)
		}},
		{"uppercase public key", func(_ *SigningRequestV1, _ *ExternalSignatureV1, tr *TrustBundle) {
			tr.Keys["release-key"] = strings.ToUpper(tr.Keys["release-key"])
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, in, request, signature, trust := finalizedFixture(t)
			tc.change(&request, &signature, &trust)
			writePackagingJSON(t, filepath.Join(d, "request.json"), request)
			writePackagingJSON(t, filepath.Join(d, "signature.json"), signature)
			writePackagingJSON(t, filepath.Join(d, "trust.json"), trust)
			if _, err := Finalize(FinalizeInput{RequestPath: filepath.Join(d, "request.json"), SignaturePath: filepath.Join(d, "signature.json"), TrustBundlePath: filepath.Join(d, "trust.json"), EnvelopeOutput: filepath.Join(d, "out.json"), Now: in.IssuedAt.Add(time.Hour)}); err == nil {
				t.Fatal("noncanonical external material accepted")
			}
		})
	}
}

func TestResolvePackagePathsRejectsPhysicalStageAliases(t *testing.T) {
	d := t.TempDir()
	stage := filepath.Join(d, "stage")
	outside := filepath.Join(d, "outside")
	if err := os.Mkdir(stage, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(outside, 0700); err != nil {
		t.Fatal(err)
	}
	stageAlias := filepath.Join(d, "stage-alias")
	insideAlias := filepath.Join(d, "inside-alias")
	outsideAlias := filepath.Join(d, "outside-alias")
	for link, target := range map[string]string{stageAlias: stage, insideAlias: stage, outsideAlias: outside} {
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := ResolvePackagePaths(stageAlias, filepath.Join(insideAlias, "manifest.json")); err == nil {
		t.Fatal("symlink-parent output into physical staged root accepted")
	}
	wantStage, _ := filepath.EvalSymlinks(stage)
	wantOutputParent, _ := filepath.EvalSymlinks(outside)
	physicalStage, outputs, err := ResolvePackagePaths(stageAlias, filepath.Join(outsideAlias, "manifest.json"))
	if err != nil || physicalStage != wantStage || outputs[0] != filepath.Join(wantOutputParent, "manifest.json") {
		t.Fatalf("aliases not physically resolved: stage=%q outputs=%q err=%v", physicalStage, outputs, err)
	}
}

func TestFinalizeRejectsPhysicalOutputInputAlias(t *testing.T) {
	d, in, request, signature, trust := finalizedFixture(t)
	requestPath := filepath.Join(d, "request.json")
	writePackagingJSON(t, requestPath, request)
	writePackagingJSON(t, filepath.Join(d, "signature.json"), signature)
	writePackagingJSON(t, filepath.Join(d, "trust.json"), trust)
	alias := filepath.Join(d, "output-alias")
	if err := os.Symlink(d, alias); err != nil {
		t.Fatal(err)
	}
	if _, err := Finalize(FinalizeInput{RequestPath: requestPath, SignaturePath: filepath.Join(d, "signature.json"), TrustBundlePath: filepath.Join(d, "trust.json"), EnvelopeOutput: filepath.Join(alias, "request.json"), Now: in.IssuedAt.Add(time.Hour)}); err == nil {
		t.Fatal("physical output/input collision accepted")
	}
}

func TestWriteNewCanonicalNoReplaceRaceAndTempCleanup(t *testing.T) {
	d := t.TempDir()
	out := filepath.Join(d, "release.json")
	stale := out + ".next"
	if err := os.WriteFile(stale, []byte("stale"), 0600); err != nil {
		t.Fatal(err)
	}
	const writers = 24
	start := make(chan struct{})
	results := make(chan error, writers)
	var group sync.WaitGroup
	for n := range writers {
		group.Add(1)
		go func(n int) {
			defer group.Done()
			<-start
			results <- WriteNewCanonical(out, struct {
				Writer int `json:"writer"`
			}{Writer: n})
		}(n)
	}
	close(start)
	group.Wait()
	close(results)
	success := 0
	for err := range results {
		if err == nil {
			success++
		}
	}
	if success != 1 {
		t.Fatalf("expected exactly one atomic publisher, got %d", success)
	}
	info, err := os.Lstat(out)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("unsafe final output: %v %v", info.Mode(), err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Nlink != 1 {
		t.Fatalf("final output has unexpected links: %#v", info.Sys())
	}
	entries, err := os.ReadDir(d)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".release.json.openduck-tmp-") {
			t.Fatalf("temporary output leaked: %s", entry.Name())
		}
	}
	if _, err := os.Stat(stale); err != nil {
		t.Fatalf("unrelated stale temp unexpectedly changed: %v", err)
	}
}

func TestWriteNewCanonicalRejectsReplacedOutputParentAndCleansTemp(t *testing.T) {
	d := t.TempDir()
	parent := filepath.Join(d, "output")
	if err := os.Mkdir(parent, 0700); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(parent, "release.json")
	moved := filepath.Join(d, "output-moved")
	beforeOutputPublishForTest = func() {
		if err := os.Rename(parent, moved); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(parent, 0700); err != nil {
			t.Fatal(err)
		}
	}
	defer func() { beforeOutputPublishForTest = nil }()
	if err := WriteNewCanonical(out, struct {
		Value string `json:"value"`
	}{Value: "x"}); err == nil {
		t.Fatal("replaced output parent accepted")
	}
	for _, path := range []string{filepath.Join(parent, "release.json"), filepath.Join(moved, "release.json")} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatalf("failed publication residue at %s: %v", path, err)
		}
	}
	entries, err := os.ReadDir(moved)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".release.json.openduck-tmp-") {
			t.Fatalf("temp leaked after parent replacement: %s", entry.Name())
		}
	}
}

func TestWritePackageOutputRejectsParentAliasedIntoStageDuringPublish(t *testing.T) {
	d := t.TempDir()
	stage := filepath.Join(d, "stage")
	parent := filepath.Join(d, "output")
	if err := os.Mkdir(stage, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(parent, 0700); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(parent, "release.json")
	moved := filepath.Join(d, "output-moved")
	beforeOutputPublishForTest = func() {
		if err := os.Rename(parent, moved); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(stage, parent); err != nil {
			t.Fatal(err)
		}
	}
	defer func() { beforeOutputPublishForTest = nil }()
	if err := WriteNewCanonicalOutsideStage(stage, out, struct {
		Value string `json:"value"`
	}{Value: "x"}); err == nil {
		t.Fatal("output parent aliased into stage accepted")
	}
	if _, err := os.Lstat(filepath.Join(stage, "release.json")); !os.IsNotExist(err) {
		t.Fatalf("staged root mutated through parent alias: %v", err)
	}
	entries, err := os.ReadDir(moved)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".release.json.openduck-tmp-") {
			t.Fatalf("temp leaked after stage alias: %s", entry.Name())
		}
	}
}

func TestBuildManifestRevalidatesArtifactAfterRead(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(t *testing.T, stage, rel string)
	}{
		{"truncate", func(t *testing.T, stage, rel string) {
			path := filepath.Join(stage, rel)
			if err := os.Chmod(path, 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.Truncate(path, 0); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(path, 0500); err != nil {
				t.Fatal(err)
			}
		}},
		{"extend", func(t *testing.T, stage, rel string) {
			path := filepath.Join(stage, rel)
			if err := os.Chmod(path, 0700); err != nil {
				t.Fatal(err)
			}
			f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = f.Write([]byte("x")); err != nil {
				t.Fatal(err)
			}
			if err = f.Close(); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(path, 0500); err != nil {
				t.Fatal(err)
			}
		}},
		{"replace", func(t *testing.T, stage, rel string) {
			replacement := filepath.Join(stage, "bin", "replacement")
			if err := os.WriteFile(replacement, []byte("replacement"), 0500); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(replacement, filepath.Join(stage, rel)); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := validPackageFixture(t, t.TempDir())
			afterStageReadForTest = func(rel string) { tc.mutate(t, in.StageRoot, rel) }
			defer func() { afterStageReadForTest = nil }()
			if _, err := BuildManifest(in); err == nil {
				t.Fatal("concurrently mutated artifact accepted")
			}
		})
	}
}

func TestBuildManifestRejectsIntermediateParentLink(t *testing.T) {
	in := validPackageFixture(t, t.TempDir())
	bin := filepath.Join(in.StageRoot, "bin")
	real := filepath.Join(in.StageRoot, "real-bin")
	if err := os.Rename(bin, real); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, bin); err != nil {
		t.Fatal(err)
	}
	if _, err := BuildManifest(in); err == nil {
		t.Fatal("intermediate staged parent link accepted")
	}
}

func TestPackagerSourceHasNoPrivateKeyOrEnvironmentInterface(t *testing.T) {
	body, err := os.ReadFile(filepath.Join("..", "..", "cmd", "openduck-release-packager", "main.go"))
	if err != nil {
		t.Fatal(err)
	}
	s := string(body)
	for _, forbidden := range []string{"fs.String(\"private", "fs.Var(\"private", "os.Getenv", "os.LookupEnv", "os.Environ", "\"net/"} {
		if strings.Contains(s, forbidden) {
			t.Fatalf("forbidden packager interface %q", forbidden)
		}
	}
}

func validPackageFixture(t *testing.T, d string) PackageInput {
	t.Helper()
	stage := filepath.Join(d, "stage")
	if err := os.MkdirAll(filepath.Join(stage, "bin"), 0700); err != nil {
		t.Fatal(err)
	}
	for _, spec := range mandatoryCatalogEntries() {
		writeCatalogStageArtifact(t, stage, spec)
	}
	return PackageInput{StageRoot: stage, ReleaseID: "release-20260826", Version: "1.2.3", TargetRoot: "/opt/openduck", Platform: runtime.GOOS, Arch: runtime.GOARCH, KeyID: "release-key", Operation: "deploy", RunID: "aaaaaaaa-1111", Activation: false, Sequence: 42, Nonce: "release-nonce", IssuedAt: time.Unix(1_750_000_000, 0).UTC(), ExpiresAt: time.Unix(1_750_007_200, 0).UTC(), MinInstaller: "1.0.0"}
}

func mandatoryCatalogEntries() []releasecatalog.Entry {
	entries := make([]releasecatalog.Entry, 0)
	for _, entry := range releasecatalog.Entries() {
		if entry.Mandatory {
			entries = append(entries, entry)
		}
	}
	return entries
}

func firstMandatoryCatalogEntry(t *testing.T) releasecatalog.Entry {
	t.Helper()
	entries := mandatoryCatalogEntries()
	if len(entries) == 0 {
		t.Fatal("mandatory catalog missing")
	}
	return entries[0]
}

func addCatalogGroup(t *testing.T, stage, group string) []releasecatalog.Entry {
	t.Helper()
	added := make([]releasecatalog.Entry, 0)
	for _, entry := range releasecatalog.Entries() {
		if entry.ActivationGroup == group {
			writeCatalogStageArtifact(t, stage, entry)
			added = append(added, entry)
		}
	}
	if len(added) == 0 {
		t.Fatalf("unknown catalog group %q", group)
	}
	return added
}

func writeCatalogStageArtifact(t *testing.T, stage string, entry releasecatalog.Entry) {
	t.Helper()
	path := filepath.Join(stage, entry.Path)
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	mode := os.FileMode(0400)
	if entry.Executable {
		mode = 0500
	}
	if err := os.WriteFile(path, catalogStagePayload(t, entry), mode); err != nil {
		t.Fatal(err)
	}
}

func catalogStagePayload(t *testing.T, entry releasecatalog.Entry) []byte {
	t.Helper()
	if entry.Mandatory {
		return []byte("body:" + entry.Path)
	}
	switch entry.Type {
	case "policy":
		return providerPolicyPayloads(t, nil)[entry.Path]
	case "provider_runtime":
		descriptor := providertransport.InactiveDescriptor{Provider: entry.Provider, ProfileID: entry.ProfileID, ProfileRevision: entry.ProfileRevision, MappingDigest: "sha256:" + strings.Repeat("a", 64), RuntimeDigest: "sha256:" + strings.Repeat("b", 64), ProtocolDigest: "sha256:" + strings.Repeat("c", 64), Audience: "mesh"}
		if err := descriptor.Seal(); err != nil {
			t.Fatal(err)
		}
		body, err := json.Marshal(descriptor)
		if err != nil {
			t.Fatal(err)
		}
		return body
	case "provider_plugin":
		body, err := releasecatalog.CanonicalPluginMetadata(entry)
		if err != nil {
			t.Fatal(err)
		}
		return body
	case "provider_daemon":
		return []byte("disabled-daemon:" + entry.Path)
	case "provider_host_runtime":
		return []byte("signed-host-runtime:" + entry.Path)
	case "provider_host_closure":
		return []byte("signed-host-closure:" + entry.Path)
	case "provider_host_identity":
		hostLeaf := entry.Provider
		if entry.Provider == "kimi" {
			hostLeaf = "kimi-code"
		}
		if entry.Provider == "qwen" {
			hostLeaf = "node"
		}
		hostPath := "providers/" + entry.Provider + "/host/" + hostLeaf
		sum := sha256.Sum256([]byte("signed-host-runtime:" + hostPath))
		team := map[string]string{"codex": "2DC432GLL2", "claude": "Q6L2SF6YDW", "kimi": "2J9472RW75", "qwen": "HX7739G8FX"}[entry.Provider]
		return []byte(fmt.Sprintf(`{"schema":"openduck.provider-host-identity.v1","provider":"%s","team_id":"%s","artifact_digest":"sha256:%s","image_identity":"sha256:%s"}`, entry.Provider, team, hex.EncodeToString(sum[:]), strings.Repeat("a", 64)))
	case "provider_topology":
		body, err := releasecatalog.CanonicalProviderTopology(entry)
		if err != nil {
			t.Fatal(err)
		}
		return body
	default:
		t.Fatalf("unexpected optional artifact %q", entry.Path)
		return nil
	}
}

func writeProviderPolicyStage(t *testing.T, stage string, runtime []releasecatalog.Entry) {
	t.Helper()
	for path, body := range providerPolicyPayloads(t, runtime) {
		full := filepath.Join(stage, path)
		if err := os.MkdirAll(filepath.Dir(full), 0700); err != nil {
			t.Fatal(err)
		}
		if existing, err := os.Lstat(full); err == nil && existing.Mode().Perm()&0200 == 0 {
			if err := os.Chmod(full, 0600); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.WriteFile(full, body, 0400); err != nil {
			t.Fatal(err)
		}
	}
}

func runtimeEntries(entries []releasecatalog.Entry) []releasecatalog.Entry {
	out := make([]releasecatalog.Entry, 0, len(entries))
	for _, entry := range entries {
		if entry.Type == "provider_runtime" && !entry.Mandatory {
			out = append(out, entry)
		}
	}
	return out
}

func providerPolicyPayloads(t *testing.T, runtime []releasecatalog.Entry) map[string][]byte {
	t.Helper()
	now := time.Unix(1_750_000_000, 0).UTC()
	technical := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, ed25519.SeedSize))
	security := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{2}, ed25519.SeedSize))
	trust := providerbridge.Ed25519TrustBundle{SchemaVersion: providerbridge.Ed25519TrustBundleV1, PublicKeys: map[string]string{"security-ed25519": hex.EncodeToString(security.Public().(ed25519.PublicKey)), "technical-ed25519": hex.EncodeToString(technical.Public().(ed25519.PublicKey))}, TrustedTechnical: []string{"technical-ed25519"}, TrustedSecurity: []string{"security-ed25519"}, Revoked: []string{}}
	trustRaw, err := json.Marshal(trust)
	if err != nil {
		t.Fatal(err)
	}
	profiles := make([]providerrevision.ProfileBundle, 0, len(runtime))
	for _, entry := range runtime {
		profiles = append(profiles, validDisabledProfileBundle(t, entry, now, technical, security))
	}
	sort.Slice(profiles, func(i, j int) bool { return profiles[i].Profile.ID < profiles[j].Profile.ID })
	bundle := providerrevision.Bundle{SchemaVersion: providerrevision.BundleV1, BundleID: "bundle-test", RevisionID: "revision-test", TrustBundleDigest: providerbridge.DigestBytes(trustRaw), Profiles: profiles}
	if err := bundle.Seal(); err != nil {
		t.Fatal(err)
	}
	if len(profiles) > 0 {
		if err := providerrevision.ValidateBundle(bundle, trust, now); err != nil {
			t.Fatalf("fixture bundle fails Controller validator: %v", err)
		}
	}
	bundleRaw, err := json.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	return map[string][]byte{"provider-bundle.json": bundleRaw, "provider-trust.json": trustRaw}
}

func validDisabledProfileBundle(t *testing.T, entry releasecatalog.Entry, now time.Time, technical, security ed25519.PrivateKey) providerrevision.ProfileBundle {
	t.Helper()
	profile := providerProfileDTO(t, entry)
	compatibility := pinnedCompatibilityFixture(t, entry, profile, now)
	mapping, err := providerbridge.MappingFromCompatibility(compatibility)
	if err != nil {
		t.Fatal(err)
	}
	limits := providerbridge.ExecutionLimits{SchemaVersion: providerbridge.ExecutionLimitsV1, MaxDepth: 1, MaxChildrenPerParent: 1, MaxConcurrentRuns: 1, MaxInputTokens: 1, MaxOutputTokens: 1, MaxWallMS: 1, MaxAttempts: 1, MaxResultBytes: 1, Cost: providerbridge.CostLimit{Kind: "non_monetary", Unit: "token", MaxQuantity: 1}}
	limitsDigest, err := limits.Digest()
	if err != nil {
		t.Fatal(err)
	}
	evidence := providerbridge.ProviderEvidenceRecord{SchemaVersion: providerbridge.EvidenceRecordV1, Provider: profile.Provider, ProfileID: profile.ID, ProfileRevision: profile.Revision, AuthModality: profile.AuthModality, OfficialURLs: []string{"https://evidence.example/" + string(profile.Provider)}, RetrievedAt: now.Add(-time.Hour), FreshUntil: now.Add(time.Hour), RuntimeVersion: compatibility.RuntimeVersion, ProtocolVersion: compatibility.ProtocolVersion, Model: profile.Model, ClaimModalities: map[string]string{"official-provider-route": profile.AuthModality}, SourceContentDigest: providerbridge.DigestBytes([]byte(profile.ID + ":source")), RuntimeArtifactDigest: compatibility.RuntimeArtifactDigest, SchemaDigest: compatibility.ProtocolSchemaDigest, CompatibilityRecordDigest: compatibility.Digest, ProtocolSchemaDigest: compatibility.ProtocolSchemaDigest, MeshToolSchemaDigest: compatibility.MeshToolSchemaDigest, EvidenceGeneratorVersion: "offline-fixture.v1"}
	if err := evidence.Seal(); err != nil {
		t.Fatal(err)
	}
	evidence.Approvals = []providerbridge.EvidenceApproval{
		{SchemaVersion: "provider-evidence-approval.v1", Role: "technical", ReviewerKeyID: "technical-ed25519", ProfileID: profile.ID, ProfileRevision: profile.Revision, EvidenceDigest: evidence.Digest, FreshUntil: evidence.FreshUntil, DecisionRef: "decision-tech-" + string(profile.Provider), Signature: hex.EncodeToString(ed25519.Sign(technical, []byte(evidence.Digest)))},
		{SchemaVersion: "provider-evidence-approval.v1", Role: "security", ReviewerKeyID: "security-ed25519", ProfileID: profile.ID, ProfileRevision: profile.Revision, EvidenceDigest: evidence.Digest, FreshUntil: evidence.FreshUntil, DecisionRef: "decision-security-" + string(profile.Provider), Signature: hex.EncodeToString(ed25519.Sign(security, []byte(evidence.Digest)))},
	}
	profile.ExecutionLimitsDigest = limitsDigest
	profile.MappingDigest = mapping.Digest
	profile.ProviderEvidenceDigest = evidence.Digest
	profile.MeshSpawnEnabled = false
	profile.Status = providerbridge.StatusDisabled
	return providerrevision.ProfileBundle{Profile: profile, Limits: limits, Mapping: mapping, Compatibility: compatibility, Evidence: evidence, ActivationIntent: false}
}

func pinnedCompatibilityFixture(t *testing.T, entry releasecatalog.Entry, profile providerrevision.ProfileDTO, now time.Time) providerbridge.CompatibilityRecord {
	t.Helper()
	operations, err := providerbridge.PinnedMappings()
	if err != nil {
		t.Fatal(err)
	}
	var eventMappings []providerbridge.OperationMapping
	for _, mapping := range operations {
		if mapping.ProfileID == profile.ID {
			eventMappings = append([]providerbridge.OperationMapping(nil), mapping.Operations...)
			break
		}
	}
	if len(eventMappings) == 0 {
		t.Fatalf("no closed mapping fixture for %q", profile.ID)
	}
	runtimeVersion, protocolVersion := pinnedCompatibilityVersions(t, entry.ProfileID)
	operationsRaw, err := json.Marshal(eventMappings)
	if err != nil {
		t.Fatal(err)
	}
	record := providerbridge.CompatibilityRecord{SchemaVersion: providerbridge.CompatibilityRecordV1, Maturity: providerbridge.CompatibilityPinned, Provider: profile.Provider, ProfileID: profile.ID, ProfileRevision: profile.Revision, Model: profile.Model, AuthModality: profile.AuthModality, RuntimeVersion: runtimeVersion, ProtocolVersion: protocolVersion, RuntimeArtifactDigest: providerbridge.DigestBytes([]byte("runtime:" + runtimeVersion)), ProtocolSchemaDigest: providerbridge.DigestBytes([]byte("protocol:" + protocolVersion)), MeshToolSchemaDigest: providerbridge.DigestBytes([]byte("mesh-tools.v1")), TranscriptDigest: providerbridge.DigestBytes(operationsRaw), Operations: eventMappings, Handshake: "success", Start: "success", Stream: "success", Cancel: "cancelled", Teardown: "quiescent", Health: "success", GeneratorVersion: "external-probe.v1", GeneratedAt: now.Add(-time.Hour), SourceReferences: []providerbridge.CompatibilitySource{{Reference: "https://evidence.example/compatibility/" + entry.Provider, Digest: providerbridge.DigestBytes([]byte("source:" + entry.ProfileID))}}}
	if err := record.Seal(); err != nil {
		t.Fatal(err)
	}
	return record
}

func pinnedCompatibilityVersions(t *testing.T, profileID string) (string, string) {
	t.Helper()
	switch profileID {
	case providerbridge.ProfileCodexChatGPT:
		return "codex-app-server@2026.8.25", "app-server-thread.v1"
	case providerbridge.ProfileClaudeCode:
		return "claude-code@2.1.0", "stream-json-mcp.v1"
	case providerbridge.ProfileQwenGeneral:
		return "qwen-code@0.9.0", "stream-json-mcp.v1"
	case providerbridge.ProfileKimiCode:
		return "kimi-code@1.1.0", "acp-mcp.v1"
	case providerbridge.ProfileDeepSeekAPI:
		return "deepseek-api@2026.8", "tool-calling.v1"
	default:
		t.Fatalf("unknown closed runtime profile %q", profileID)
		return "", ""
	}
}

func providerProfileDTO(t *testing.T, entry releasecatalog.Entry) providerrevision.ProfileDTO {
	t.Helper()
	if entry.Provider == "codex" && entry.ProfileID == "codex.chatgpt.app-server" {
		return providerrevision.ProfileDTO{ID: entry.ProfileID, Provider: providerbridge.ProviderCodex, Model: "gpt-5.6", RuntimeKind: "codex-app-server", AuthModality: "chatgpt-subscription", Revision: entry.ProfileRevision, Status: providerbridge.StatusDisabled}
	}
	if entry.Provider == "claude" && entry.ProfileID == "claude.code.cli" {
		return providerrevision.ProfileDTO{ID: entry.ProfileID, Provider: providerbridge.ProviderClaude, Model: "claude-code", RuntimeKind: "claude-code-cli", AuthModality: "account-login-or-api", Revision: entry.ProfileRevision, Status: providerbridge.StatusDisabled}
	}
	if entry.Provider == "qwen" && entry.ProfileID == "qwen.general.headless" {
		return providerrevision.ProfileDTO{ID: entry.ProfileID, Provider: providerbridge.ProviderQwen, Model: "qwen-coder", RuntimeKind: "qwen-headless", AuthModality: "coding-plan-or-api", Revision: entry.ProfileRevision, Status: providerbridge.StatusDisabled}
	}
	if entry.Provider == "kimi" && entry.ProfileID == "kimi.code.acp" {
		return providerrevision.ProfileDTO{ID: entry.ProfileID, Provider: providerbridge.ProviderKimi, Model: "kimi-code", RuntimeKind: "kimi-acp", AuthModality: "membership-oauth-or-api", Revision: entry.ProfileRevision, Status: providerbridge.StatusDisabled}
	}
	if entry.Provider == "deepseek" && entry.ProfileID == "deepseek.api" {
		return providerrevision.ProfileDTO{ID: entry.ProfileID, Provider: providerbridge.ProviderDeepSeek, Model: "deepseek-chat", RuntimeKind: "deepseek-api", AuthModality: "api-key", Revision: entry.ProfileRevision, Status: providerbridge.StatusDisabled}
	}
	t.Fatalf("unknown provider profile %+v", entry)
	return providerrevision.ProfileDTO{}
}

func finalizedFixture(t *testing.T) (string, PackageInput, SigningRequestV1, ExternalSignatureV1, TrustBundle) {
	t.Helper()
	d := t.TempDir()
	in := validPackageFixture(t, d)
	m, err := BuildManifest(in)
	if err != nil {
		t.Fatal(err)
	}
	r, err := BuildSigningRequest(in, m)
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := base64.StdEncoding.DecodeString(r.UnsignedPayload)
	pub, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return d, in, r, ExternalSignatureV1{Schema: SignatureSchema, Algorithm: "ed25519", KeyID: in.KeyID, PayloadDigest: r.PayloadDigest, Signature: hex.EncodeToString(ed25519.Sign(private, payload))}, TrustBundle{Schema: TrustBundleSchema, Keys: map[string]string{in.KeyID: hex.EncodeToString(pub)}}
}

func writePackagingJSON(t *testing.T, path string, value any) {
	t.Helper()
	if err := WriteNewCanonical(path, value); err != nil {
		t.Fatal(err)
	}
}

func noncanonicalBase64(value string) string {
	if strings.HasSuffix(value, "=") {
		return strings.TrimRight(value, "=")
	}
	return value + "="
}
