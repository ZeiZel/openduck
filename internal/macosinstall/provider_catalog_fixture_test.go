package macosinstall

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"

	"openduck/internal/providerbridge"
	"openduck/internal/providerrevision"
	"openduck/internal/providertransport"
	"openduck/internal/releasecatalog"
)

// catalogFixturePayloads builds only public, disabled provider artifacts. It
// deliberately uses the same full bundle validator as production packaging so
// installer tests cannot accidentally admit a policy the Controller rejects.
func catalogFixturePayloads(t *testing.T, specs []planArtifactSpec, validationTime time.Time) map[string][]byte {
	t.Helper()
	payloads := make(map[string][]byte, len(specs))
	runtime := make([]releasecatalog.Entry, 0)
	for _, spec := range specs {
		entry, known := releasecatalog.EntryFor(spec.path)
		if !known || entry.Type != spec.typ {
			payloads[spec.path] = []byte("verified " + spec.path)
			continue
		}
		if entry.Mandatory {
			payloads[entry.Path] = []byte("verified " + entry.Path)
			continue
		}
		switch entry.Type {
		case "provider_runtime":
			payloads[entry.Path] = fixtureRuntimeDescriptor(t, entry)
			runtime = append(runtime, entry)
		case "provider_plugin":
			body, err := releasecatalog.CanonicalPluginMetadata(entry)
			if err != nil {
				t.Fatal(err)
			}
			payloads[entry.Path] = body
		case "provider_daemon":
			payloads[entry.Path] = []byte("disabled-daemon:" + entry.Path)
		case "provider_host_runtime":
			payloads[entry.Path] = []byte("signed-host-runtime:" + entry.Path)
		case "provider_host_closure":
			payloads[entry.Path] = []byte("signed-host-closure:" + entry.Path)
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
			payloads[entry.Path] = []byte(fmt.Sprintf(`{"schema":"openduck.provider-host-identity.v1","provider":"%s","team_id":"%s","artifact_digest":"sha256:%s","image_identity":"sha256:%s"}`, entry.Provider, team, hex.EncodeToString(sum[:]), strings.Repeat("a", 64)))
		case "provider_topology":
			body, err := releasecatalog.CanonicalProviderTopology(entry)
			if err != nil {
				t.Fatal(err)
			}
			payloads[entry.Path] = body
		}
	}
	policy := fixtureProviderPolicyPayloads(t, runtime, validationTime)
	for _, leaf := range []string{"provider-bundle.json", "provider-trust.json"} {
		if _, requested := payloads[leaf]; requested {
			continue
		}
		for _, spec := range specs {
			if spec.path == leaf {
				payloads[leaf] = policy[leaf]
			}
		}
	}
	return payloads
}

func fixtureRuntimeDescriptor(t *testing.T, entry releasecatalog.Entry) []byte {
	t.Helper()
	descriptor := providertransport.InactiveDescriptor{Provider: entry.Provider, ProfileID: entry.ProfileID, ProfileRevision: entry.ProfileRevision, MappingDigest: "sha256:" + strings.Repeat("a", 64), RuntimeDigest: "sha256:" + strings.Repeat("b", 64), ProtocolDigest: "sha256:" + strings.Repeat("c", 64), Audience: "mesh"}
	if err := descriptor.Seal(); err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(descriptor)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func fixtureProviderPolicyPayloads(t *testing.T, runtime []releasecatalog.Entry, now time.Time) map[string][]byte {
	t.Helper()
	technical := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, ed25519.SeedSize))
	security := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{2}, ed25519.SeedSize))
	trust := providerbridge.Ed25519TrustBundle{SchemaVersion: providerbridge.Ed25519TrustBundleV1, PublicKeys: map[string]string{"security-ed25519": hex.EncodeToString(security.Public().(ed25519.PublicKey)), "technical-ed25519": hex.EncodeToString(technical.Public().(ed25519.PublicKey))}, TrustedTechnical: []string{"technical-ed25519"}, TrustedSecurity: []string{"security-ed25519"}, Revoked: []string{}}
	trustRaw, err := json.Marshal(trust)
	if err != nil {
		t.Fatal(err)
	}
	profiles := make([]providerrevision.ProfileBundle, 0, len(runtime))
	for _, entry := range runtime {
		profiles = append(profiles, fixtureDisabledProfileBundle(t, entry, now, technical, security))
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

func fixtureDisabledProfileBundle(t *testing.T, entry releasecatalog.Entry, now time.Time, technical, security ed25519.PrivateKey) providerrevision.ProfileBundle {
	t.Helper()
	profile := fixtureProfileDTO(t, entry)
	compatibility := fixturePinnedCompatibility(t, entry, profile, now)
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

func fixturePinnedCompatibility(t *testing.T, entry releasecatalog.Entry, profile providerrevision.ProfileDTO, now time.Time) providerbridge.CompatibilityRecord {
	t.Helper()
	mappings, err := providerbridge.PinnedMappings()
	if err != nil {
		t.Fatal(err)
	}
	var operations []providerbridge.OperationMapping
	for _, mapping := range mappings {
		if mapping.ProfileID == profile.ID {
			operations = append([]providerbridge.OperationMapping(nil), mapping.Operations...)
			break
		}
	}
	if len(operations) == 0 {
		t.Fatalf("no closed mapping fixture for %q", profile.ID)
	}
	runtimeVersion, protocolVersion := fixturePinnedCompatibilityVersions(t, entry.ProfileID)
	operationsRaw, err := json.Marshal(operations)
	if err != nil {
		t.Fatal(err)
	}
	record := providerbridge.CompatibilityRecord{SchemaVersion: providerbridge.CompatibilityRecordV1, Maturity: providerbridge.CompatibilityPinned, Provider: profile.Provider, ProfileID: profile.ID, ProfileRevision: profile.Revision, Model: profile.Model, AuthModality: profile.AuthModality, RuntimeVersion: runtimeVersion, ProtocolVersion: protocolVersion, RuntimeArtifactDigest: providerbridge.DigestBytes([]byte("runtime:" + runtimeVersion)), ProtocolSchemaDigest: providerbridge.DigestBytes([]byte("protocol:" + protocolVersion)), MeshToolSchemaDigest: providerbridge.DigestBytes([]byte("mesh-tools.v1")), TranscriptDigest: providerbridge.DigestBytes(operationsRaw), Operations: operations, Handshake: "success", Start: "success", Stream: "success", Cancel: "cancelled", Teardown: "quiescent", Health: "success", GeneratorVersion: "external-probe.v1", GeneratedAt: now.Add(-time.Hour), SourceReferences: []providerbridge.CompatibilitySource{{Reference: "https://evidence.example/compatibility/" + entry.Provider, Digest: providerbridge.DigestBytes([]byte("source:" + entry.ProfileID))}}}
	if err := record.Seal(); err != nil {
		t.Fatal(err)
	}
	return record
}

func fixturePinnedCompatibilityVersions(t *testing.T, profileID string) (string, string) {
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

func fixtureProfileDTO(t *testing.T, entry releasecatalog.Entry) providerrevision.ProfileDTO {
	t.Helper()
	for _, profile := range providerbridge.DeclaredProfiles() {
		if profile.ID == entry.ProfileID && string(profile.Provider) == entry.Provider && profile.Revision == entry.ProfileRevision {
			return providerrevision.ProfileDTO{ID: profile.ID, Provider: profile.Provider, Model: profile.Model, RuntimeKind: profile.RuntimeKind, AuthModality: profile.AuthModality, AccountRef: profile.AccountRef, LocalOnly: profile.LocalOnly, MeshSpawnEnabled: false, Revision: profile.Revision, Status: providerbridge.StatusDisabled}
		}
	}
	t.Fatalf("unknown closed profile entry %+v", entry)
	return providerrevision.ProfileDTO{}
}
