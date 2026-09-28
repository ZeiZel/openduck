package providerbridge

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func eligibleRegistryFor(t *testing.T, limits ExecutionLimits) (*Registry, Profile, time.Time) {
	t.Helper()
	now := time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)
	profile := DeclaredProfiles()[0]
	profile.AccountRef, profile.MeshSpawnEnabled, profile.Status = "opaque-account-ref.v1:approved", true, StatusCompatible
	var err error
	profile.ExecutionLimitsDigest, err = limits.Digest()
	if err != nil {
		t.Fatal(err)
	}
	compatibility := pinnedCompatibilityFor(t, profile)
	mapping, err := MappingFromCompatibility(compatibility)
	if err != nil {
		t.Fatal(err)
	}
	profile.MappingDigest = mapping.Digest
	evidence := evidenceForCompatibility(t, profile, compatibility, now)
	profile.ProviderEvidenceDigest = evidence.Digest
	registry, err := NewRegistryWithCompatibility([]Profile{profile}, map[string]ExecutionLimits{profile.ID: limits}, []Mapping{mapping}, []ProviderEvidenceRecord{evidence}, []CompatibilityRecord{compatibility}, trusted(), fixtureVerifier{})
	if err != nil {
		t.Fatal(err)
	}
	return registry, profile, now
}

func TestExecutionLimitsDigestBindsEveryFiniteField(t *testing.T) {
	base := finiteLimits()
	registry, profile, now := eligibleRegistryFor(t, base)
	if eligible, err := registry.MeshEligible(profile.ID, now); !eligible || err != nil {
		t.Fatalf("baseline eligible=%v err=%v", eligible, err)
	}
	mutations := []func(*ExecutionLimits){
		func(l *ExecutionLimits) { l.MaxDepth++ },
		func(l *ExecutionLimits) { l.MaxChildrenPerParent++ },
		func(l *ExecutionLimits) { l.MaxConcurrentRuns++ },
		func(l *ExecutionLimits) { l.MaxInputTokens++ },
		func(l *ExecutionLimits) { l.MaxOutputTokens++ },
		func(l *ExecutionLimits) { l.MaxWallMS++ },
		func(l *ExecutionLimits) { l.MaxAttempts++ },
		func(l *ExecutionLimits) { l.MaxResultBytes++ },
		func(l *ExecutionLimits) { l.Cost.MaxQuantity++ },
		func(l *ExecutionLimits) { l.Cost.Unit = "request" },
	}
	for _, mutate := range mutations {
		changed := base
		mutate(&changed)
		if changed.Validate() != nil {
			t.Fatal("test mutation must stay finite")
		}
		if got, _ := changed.Digest(); got == profile.ExecutionLimitsDigest {
			t.Fatal("mutation retained digest")
		}
		compatibility := pinnedCompatibilityFor(t, profile)
		mapping, err := MappingFromCompatibility(compatibility)
		if err != nil {
			t.Fatal(err)
		}
		evidence := evidenceForCompatibility(t, profile, compatibility, now)
		bad := profile
		bad.MappingDigest, bad.ProviderEvidenceDigest = mapping.Digest, evidence.Digest
		r, err := NewRegistryWithCompatibility([]Profile{bad}, map[string]ExecutionLimits{bad.ID: changed}, []Mapping{mapping}, []ProviderEvidenceRecord{evidence}, []CompatibilityRecord{compatibility}, trusted(), fixtureVerifier{})
		if err != nil {
			t.Fatal(err)
		}
		if eligible, err := r.MeshEligible(bad.ID, now); eligible || !errors.Is(err, ErrLimitsMissing) {
			t.Fatalf("finite mutation enabled: eligible=%v err=%v", eligible, err)
		}
	}
}

func TestConcreteVersionsAndSanitizedCompatibilityMetadata(t *testing.T) {
	profile := DeclaredProfiles()[0]
	record := pinnedCompatibilityFor(t, profile)
	for _, mutate := range []func(*CompatibilityRecord){
		func(r *CompatibilityRecord) { r.RuntimeVersion = "codex@pinned" },
		func(r *CompatibilityRecord) { r.ProtocolVersion = "synthetic/protocol.v1" },
		func(r *CompatibilityRecord) { r.SourceReferences[0].Reference = "https://user@evidence.example/x" },
		func(r *CompatibilityRecord) {
			r.SourceReferences[0].Reference = "https://evidence.example/x?token=value"
		},
		func(r *CompatibilityRecord) { r.Operations[0].RequestEvent = "tool.token=value" },
	} {
		bad := record
		bad.Operations = append([]OperationMapping(nil), record.Operations...)
		bad.SourceReferences = append([]CompatibilitySource(nil), record.SourceReferences...)
		mutate(&bad)
		_ = bad.Seal()
		if err := bad.Validate(); !errors.Is(err, ErrCompatibilityInvalid) {
			t.Fatalf("unsafe compatibility accepted: %v", err)
		}
	}
	synthetic := mustMappings(t)[0]
	syntheticRecord := CompatibilityRecord{SchemaVersion: CompatibilityRecordV1, Maturity: CompatibilitySynthetic, Provider: synthetic.Provider, ProfileID: synthetic.ProfileID, ProfileRevision: DeclaredProfiles()[0].Revision, Model: DeclaredProfiles()[0].Model, AuthModality: DeclaredProfiles()[0].AuthModality, RuntimeVersion: synthetic.RuntimeVersion, ProtocolVersion: synthetic.ProtocolVersion, RuntimeArtifactDigest: synthetic.RuntimeDigest, ProtocolSchemaDigest: synthetic.ProtocolDigest, MeshToolSchemaDigest: synthetic.ToolSchemaDigest, TranscriptDigest: fixedDigest(synthetic.Operations), Operations: synthetic.Operations, Handshake: "unavailable", Start: "unavailable", Stream: "unavailable", Cancel: "unavailable", Teardown: "unavailable", Health: "unavailable", GeneratorVersion: "synthetic-fixture.v1", GeneratedAt: time.Date(2026, 8, 25, 0, 0, 0, 0, time.UTC), SourceReferences: []CompatibilitySource{{Reference: "internal/providerbridge/testdata/not-shipped.json", Digest: fixedDigest(synthetic.Operations)}}}
	if err := syntheticRecord.Seal(); err != nil {
		t.Fatal(err)
	}
	if err := syntheticRecord.Validate(); !errors.Is(err, ErrCompatibilityInvalid) {
		t.Fatalf("non-exact synthetic source accepted: %v", err)
	}
	for _, mapping := range mustMappings(t) {
		if mapping.Maturity != CompatibilitySynthetic || !strings.HasPrefix(mapping.RuntimeVersion, syntheticVersionPrefix) || !strings.HasPrefix(mapping.ProtocolVersion, syntheticVersionPrefix) || strings.Contains(mapping.RuntimeVersion, "@pinned") {
			t.Fatalf("fixture has non-synthetic version: %+v", mapping)
		}
	}
}

func TestGenerateCompatibilityRecordRoundTripUsesDescriptorContent(t *testing.T) {
	draft := pinnedCompatibilityFor(t, DeclaredProfiles()[0])
	draft.RuntimeArtifactDigest, draft.ProtocolSchemaDigest, draft.MeshToolSchemaDigest, draft.TranscriptDigest, draft.Digest = "", "", "", "", ""
	generated, err := GenerateCompatibilityRecord(draft, []byte("runtime"), []byte("protocol"), []byte("tools"), []byte("transcript"))
	if err != nil {
		t.Fatal(err)
	}
	if generated.RuntimeArtifactDigest != DigestBytes([]byte("runtime")) || generated.TranscriptDigest != DigestBytes([]byte("transcript")) {
		t.Fatal("descriptor digest mismatch")
	}
	b, err := CanonicalCompatibilityJSON(generated)
	if err != nil {
		t.Fatal(err)
	}
	roundTrip, err := DecodeCompatibilityRecord(b)
	if err != nil || roundTrip.Digest != generated.Digest {
		t.Fatalf("roundtrip=%+v err=%v", roundTrip, err)
	}
	if _, err := GenerateCompatibilityRecord(draft, nil, []byte("protocol"), []byte("tools"), []byte("transcript")); !errors.Is(err, ErrCompatibilityInvalid) {
		t.Fatalf("empty descriptor accepted: %v", err)
	}
}

func TestEvidenceCanonicalJSONAndSanitization(t *testing.T) {
	now := time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)
	profile := DeclaredProfiles()[0]
	compatibility := pinnedCompatibilityFor(t, profile)
	record := evidenceForCompatibility(t, profile, compatibility, now)
	b, err := CanonicalProviderEvidenceJSON(record)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeProviderEvidenceRecord(b); err != nil {
		t.Fatal(err)
	}
	for _, input := range [][]byte{
		append(append([]byte(nil), b...), ' '),
		[]byte(`{"schema_version":"provider-evidence-record.v1","schema_version":"provider-evidence-record.v1"}`),
		[]byte(`{"stdout":"raw provider output"}`),
		make([]byte, maxEvidenceRecordBytes+1),
	} {
		if _, err := DecodeProviderEvidenceRecord(input); !errors.Is(err, ErrEvidenceInvalid) {
			t.Fatalf("malformed evidence accepted: %v", err)
		}
	}
	for _, mutate := range []func(*ProviderEvidenceRecord){
		func(r *ProviderEvidenceRecord) { r.OfficialURLs = []string{"https://user@official.example/x"} },
		func(r *ProviderEvidenceRecord) { r.OfficialURLs = []string{"https://official.example/x?token=value"} },
		func(r *ProviderEvidenceRecord) { r.OfficialURLs = []string{"https://official.example/x#fragment"} },
		func(r *ProviderEvidenceRecord) {
			r.ClaimModalities = map[string]string{"claim token=value": r.AuthModality}
		},
		func(r *ProviderEvidenceRecord) { r.EvidenceGeneratorVersion = "generator with space" },
		func(r *ProviderEvidenceRecord) { r.Approvals[0].DecisionRef = "decision secret=value" },
		func(r *ProviderEvidenceRecord) { r.Approvals[0].DecisionRef = "https://user@review.example/decision" },
		func(r *ProviderEvidenceRecord) {
			r.ClaimModalities = map[string]string{"a": "a", "b": "b", "c": "c", "d": "d", "e": "e", "f": "f", "g": "g", "h": "h", "i": "i"}
		},
	} {
		bad := record
		bad.OfficialURLs = append([]string(nil), record.OfficialURLs...)
		bad.Approvals = append([]EvidenceApproval(nil), record.Approvals...)
		mutate(&bad)
		_ = bad.Seal()
		if _, err := CanonicalProviderEvidenceJSON(bad); !errors.Is(err, ErrEvidenceInvalid) {
			t.Fatal("unsafe evidence canonicalized")
		}
	}
}

func TestEd25519ReviewerVerifierAndRevocation(t *testing.T) {
	now := time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)
	profile := DeclaredProfiles()[0]
	compatibility := pinnedCompatibilityFor(t, profile)
	record := evidenceForCompatibility(t, profile, compatibility, now)
	tech := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, ed25519.SeedSize))
	security := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{2}, ed25519.SeedSize))
	record.Approvals = []EvidenceApproval{
		{SchemaVersion: "provider-evidence-approval.v1", Role: "technical", ReviewerKeyID: "technical-ed25519", ProfileID: record.ProfileID, ProfileRevision: record.ProfileRevision, EvidenceDigest: record.Digest, FreshUntil: record.FreshUntil, DecisionRef: "decision-tech"},
		{SchemaVersion: "provider-evidence-approval.v1", Role: "security", ReviewerKeyID: "security-ed25519", ProfileID: record.ProfileID, ProfileRevision: record.ProfileRevision, EvidenceDigest: record.Digest, FreshUntil: record.FreshUntil, DecisionRef: "decision-security"},
	}
	record.Approvals[0].Signature = hex.EncodeToString(ed25519.Sign(tech, []byte(record.Digest)))
	record.Approvals[1].Signature = hex.EncodeToString(ed25519.Sign(security, []byte(record.Digest)))
	public := map[string]string{"technical-ed25519": hex.EncodeToString(tech.Public().(ed25519.PublicKey)), "security-ed25519": hex.EncodeToString(security.Public().(ed25519.PublicKey))}
	verifier, err := NewEd25519Verifier(public)
	if err != nil {
		t.Fatal(err)
	}
	trust := TrustRegistry{TrustedTechnical: map[string]bool{"technical-ed25519": true}, TrustedSecurity: map[string]bool{"security-ed25519": true}, Revoked: map[string]bool{}}
	if err := VerifyEvidence(record, trust, verifier, now); err != nil {
		t.Fatal(err)
	}
	revoked := cloneTrust(trust)
	revoked.Revoked["technical-ed25519"] = true
	if err := VerifyEvidence(record, revoked, verifier, now); !errors.Is(err, ErrEvidenceUntrusted) {
		t.Fatalf("revoked=%v", err)
	}
	wrongRole := record
	wrongRole.Approvals = append([]EvidenceApproval(nil), record.Approvals...)
	wrongRole.Approvals[0].Role = "security"
	if err := VerifyEvidence(wrongRole, trust, verifier, now); !errors.Is(err, ErrEvidenceUntrusted) {
		t.Fatalf("wrong role=%v", err)
	}
	wrongProfile := record
	wrongProfile.Approvals = append([]EvidenceApproval(nil), record.Approvals...)
	wrongProfile.Approvals[0].ProfileID = ProfileClaudeCode
	if err := VerifyEvidence(wrongProfile, trust, verifier, now); !errors.Is(err, ErrEvidenceUntrusted) {
		t.Fatalf("wrong profile=%v", err)
	}
	unknownKey := record
	unknownKey.Approvals = append([]EvidenceApproval(nil), record.Approvals...)
	unknownKey.Approvals[0].ReviewerKeyID = "unknown-ed25519"
	if err := VerifyEvidence(unknownKey, trust, verifier, now); !errors.Is(err, ErrEvidenceUntrusted) {
		t.Fatalf("unknown key=%v", err)
	}
	sameReviewer := record
	sameReviewer.Approvals = append([]EvidenceApproval(nil), record.Approvals...)
	sameReviewer.Approvals[1].ReviewerKeyID = sameReviewer.Approvals[0].ReviewerKeyID
	if err := VerifyEvidence(sameReviewer, trust, verifier, now); !errors.Is(err, ErrEvidenceUntrusted) {
		t.Fatalf("same reviewer=%v", err)
	}
	sameDecision := record
	sameDecision.Approvals = append([]EvidenceApproval(nil), record.Approvals...)
	sameDecision.Approvals[1].DecisionRef = sameDecision.Approvals[0].DecisionRef
	if err := VerifyEvidence(sameDecision, trust, verifier, now); !errors.Is(err, ErrEvidenceUntrusted) {
		t.Fatalf("same decision=%v", err)
	}
	overlappingTrust := cloneTrust(trust)
	overlappingTrust.TrustedSecurity["technical-ed25519"] = true
	if err := VerifyEvidence(record, overlappingTrust, verifier, now); !errors.Is(err, ErrEvidenceUntrusted) {
		t.Fatalf("overlapping trust=%v", err)
	}
	encoded, err := json.Marshal(Ed25519TrustBundle{SchemaVersion: Ed25519TrustBundleV1, PublicKeys: public, TrustedTechnical: []string{"technical-ed25519"}, TrustedSecurity: []string{"security-ed25519"}, Revoked: []string{}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeEd25519TrustBundle(encoded); err != nil {
		t.Fatal(err)
	}
	overlappingBundle, err := json.Marshal(Ed25519TrustBundle{SchemaVersion: Ed25519TrustBundleV1, PublicKeys: public, TrustedTechnical: []string{"technical-ed25519"}, TrustedSecurity: []string{"technical-ed25519"}, Revoked: []string{}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeEd25519TrustBundle(overlappingBundle); !errors.Is(err, ErrEvidenceUntrusted) {
		t.Fatalf("overlapping bundle=%v", err)
	}
}

func mustMappings(t *testing.T) []Mapping {
	t.Helper()
	mappings, err := PinnedMappings()
	if err != nil {
		t.Fatal(err)
	}
	return mappings
}

func TestExactVersionBindingRejectsCompatibilitySubstitution(t *testing.T) {
	limits := finiteLimits()
	registry, profile, now := eligibleRegistryFor(t, limits)
	if _, err := registry.Resolve(context.Background(), profile.ID, now); err != nil {
		t.Fatal(err)
	}
	compatibility := pinnedCompatibilityFor(t, profile)
	mapping, err := MappingFromCompatibility(compatibility)
	if err != nil {
		t.Fatal(err)
	}
	otherVersion := compatibility
	otherVersion.RuntimeVersion = "codex-app-server@2026.8.26"
	_ = otherVersion.Seal()
	evidence := evidenceForCompatibility(t, profile, otherVersion, now)
	bad := profile
	bad.MappingDigest, bad.ProviderEvidenceDigest = mapping.Digest, evidence.Digest
	r, err := NewRegistryWithCompatibility([]Profile{bad}, map[string]ExecutionLimits{bad.ID: limits}, []Mapping{mapping}, []ProviderEvidenceRecord{evidence}, []CompatibilityRecord{compatibility}, trusted(), fixtureVerifier{})
	if err != nil {
		t.Fatal(err)
	}
	if eligible, err := r.MeshEligible(bad.ID, now); eligible || err == nil {
		t.Fatalf("substituted concrete version enabled: %v %v", eligible, err)
	}
}

func TestEveryMappingBindingFieldFailsClosed(t *testing.T) {
	limits := finiteLimits()
	_, profile, now := eligibleRegistryFor(t, limits)
	compatibility := pinnedCompatibilityFor(t, profile)
	mapping, err := MappingFromCompatibility(compatibility)
	if err != nil {
		t.Fatal(err)
	}
	evidence := evidenceForCompatibility(t, profile, compatibility, now)
	for _, mutate := range []func(*Mapping){
		func(m *Mapping) { m.RuntimeDigest = fixedDigest("wrong-runtime") },
		func(m *Mapping) { m.ProtocolDigest = fixedDigest("wrong-protocol") },
		func(m *Mapping) { m.ToolSchemaDigest = fixedDigest("wrong-tools") },
		func(m *Mapping) { m.CompatibilityRecordDigest = fixedDigest("wrong-record") },
		func(m *Mapping) { m.RuntimeVersion = "codex-app-server@2026.8.26" },
		func(m *Mapping) { m.ProtocolVersion = "app-server-thread.v2" },
	} {
		badMapping := mapping
		badMapping.Operations = append([]OperationMapping(nil), mapping.Operations...)
		mutate(&badMapping)
		if err := badMapping.Seal(); err != nil {
			t.Fatal(err)
		}
		badProfile := profile
		badProfile.MappingDigest = badMapping.Digest
		r, err := NewRegistryWithCompatibility([]Profile{badProfile}, map[string]ExecutionLimits{badProfile.ID: limits}, []Mapping{badMapping}, []ProviderEvidenceRecord{evidence}, []CompatibilityRecord{compatibility}, trusted(), fixtureVerifier{})
		if err != nil {
			t.Fatal(err)
		}
		if eligible, err := r.MeshEligible(badProfile.ID, now); eligible || err == nil {
			t.Fatalf("mapping substitution enabled: %v %v", eligible, err)
		}
	}
	wrongRevision := mapping
	wrongRevision.ProfileRevision = "other-revision"
	_ = wrongRevision.Seal()
	if _, err := NewRegistryWithCompatibility([]Profile{profile}, map[string]ExecutionLimits{profile.ID: limits}, []Mapping{wrongRevision}, []ProviderEvidenceRecord{evidence}, []CompatibilityRecord{compatibility}, trusted(), fixtureVerifier{}); !errors.Is(err, ErrMappingMissing) {
		t.Fatalf("wrong mapping revision accepted: %v", err)
	}
}
