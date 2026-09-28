package providerbridge

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type fixtureVerifier struct{}

func (fixtureVerifier) Verify(id, payload, signature string) bool { return signature == id+":"+payload }

func evidenceFor(t *testing.T, profile Profile, now time.Time) ProviderEvidenceRecord {
	t.Helper()
	runtimeVersion, protocolVersion, found := concreteVersionsFor(profile.ID)
	if !found {
		t.Fatal("missing pinned protocol")
	}
	protocolDigest := fixedDigest(struct{ Protocol string }{protocolVersion})
	record := ProviderEvidenceRecord{SchemaVersion: EvidenceRecordV1, Provider: profile.Provider, ProfileID: profile.ID, ProfileRevision: profile.Revision, AuthModality: profile.AuthModality, OfficialURLs: []string{"https://official.example/" + string(profile.Provider)}, RetrievedAt: now.Add(-time.Hour), FreshUntil: now.Add(time.Hour), RuntimeVersion: runtimeVersion, ProtocolVersion: protocolVersion, Model: profile.Model, ClaimModalities: map[string]string{"official-provider-route": profile.AuthModality}, SourceContentDigest: fixedDigest(profile.ID + ":source"), RuntimeArtifactDigest: fixedDigest(struct{ Runtime string }{runtimeVersion}), SchemaDigest: protocolDigest, CompatibilityRecordDigest: fixedDigest(profile.ID + ":compatibility"), ProtocolSchemaDigest: protocolDigest, MeshToolSchemaDigest: fixedDigest(struct{ Schema string }{"mesh-tools.v1"}), EvidenceGeneratorVersion: "offline-fixture.v1"}
	if err := record.Seal(); err != nil {
		t.Fatal(err)
	}
	record.Approvals = []EvidenceApproval{
		{SchemaVersion: "provider-evidence-approval.v1", Role: "technical", ReviewerKeyID: "technical-key", ProfileID: profile.ID, ProfileRevision: profile.Revision, EvidenceDigest: record.Digest, FreshUntil: record.FreshUntil, DecisionRef: "decision-tech", Signature: "technical-key:" + record.Digest},
		{SchemaVersion: "provider-evidence-approval.v1", Role: "security", ReviewerKeyID: "security-key", ProfileID: profile.ID, ProfileRevision: profile.Revision, EvidenceDigest: record.Digest, FreshUntil: record.FreshUntil, DecisionRef: "decision-security", Signature: "security-key:" + record.Digest},
	}
	return record
}

func trusted() TrustRegistry {
	return TrustRegistry{TrustedTechnical: map[string]bool{"technical-key": true}, TrustedSecurity: map[string]bool{"security-key": true}, Revoked: map[string]bool{}}
}

func finiteLimits() ExecutionLimits {
	return ExecutionLimits{SchemaVersion: ExecutionLimitsV1, MaxDepth: 1, MaxChildrenPerParent: 1, MaxConcurrentRuns: 1, MaxInputTokens: 1, MaxOutputTokens: 1, MaxWallMS: 1, MaxAttempts: 1, MaxResultBytes: 1, Cost: CostLimit{Kind: "non_monetary", Unit: "token", MaxQuantity: 1}}
}

func finiteLimitsDigest(t *testing.T) string {
	t.Helper()
	digest, err := finiteLimits().Digest()
	if err != nil {
		t.Fatal(err)
	}
	return digest
}

func concreteVersionsFor(profileID string) (string, string, bool) {
	switch profileID {
	case ProfileCodexChatGPT:
		return "codex-app-server@2026.8.25", "app-server-thread.v1", true
	case ProfileClaudeCode:
		return "claude-code@2.1.0", "stream-json-mcp.v1", true
	case ProfileQwenGeneral:
		return "qwen-code@0.9.0", "stream-json-mcp.v1", true
	case ProfileQwenLocalPD:
		return "qwen-local@0.9.0", "local-mcp.v1", true
	case ProfileKimiCode:
		return "kimi-code@1.1.0", "acp-mcp.v1", true
	case ProfileDeepSeekAPI:
		return "deepseek-api@2026.8", "tool-calling.v1", true
	default:
		return "", "", false
	}
}

func TestPinnedMappingsCoverEveryProviderAndOperation(t *testing.T) {
	mappings, err := PinnedMappings()
	if err != nil {
		t.Fatal(err)
	}
	profiles := DeclaredProfiles()
	if len(mappings) != len(profiles) {
		t.Fatalf("mappings=%d profiles=%d", len(mappings), len(profiles))
	}
	seen := map[Provider]int{}
	for _, mapping := range mappings {
		if err := mapping.Validate(); err != nil {
			t.Fatalf("%s: %v", mapping.ProfileID, err)
		}
		seen[mapping.Provider]++
		for _, operation := range requiredMeshOperations {
			found := false
			for _, value := range mapping.Operations {
				found = found || value.Operation == operation
			}
			if !found {
				t.Fatalf("%s lacks %s", mapping.ProfileID, operation)
			}
		}
	}
	for _, provider := range []Provider{ProviderCodex, ProviderClaude, ProviderQwen, ProviderKimi, ProviderDeepSeek} {
		if seen[provider] == 0 {
			t.Fatalf("provider %s has no mapping", provider)
		}
	}
}

func TestDeclaredProfilesAreMetadataOnlyAndDisabled(t *testing.T) {
	profiles := DeclaredProfiles()
	if len(profiles) != 6 {
		t.Fatalf("profiles=%d", len(profiles))
	}
	for _, profile := range profiles {
		if profile.Status != StatusDisabled || profile.MeshSpawnEnabled || profile.AccountRef != "" || profile.ProviderEvidenceDigest != "" {
			t.Fatalf("metadata declaration claims readiness: %+v", profile)
		}
	}
}

func TestEvidenceRejectsStaleMutatedRevokedAndMissingReviewer(t *testing.T) {
	now := time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)
	record := evidenceFor(t, DeclaredProfiles()[0], now)
	if err := VerifyEvidence(record, trusted(), fixtureVerifier{}, now); err != nil {
		t.Fatal(err)
	}
	stale := record
	stale.FreshUntil = now
	if err := VerifyEvidence(stale, trusted(), fixtureVerifier{}, now); !errors.Is(err, ErrEvidenceStale) {
		t.Fatalf("stale: %v", err)
	}
	mutated := record
	mutated.SourceContentDigest = fixedDigest("other")
	if err := VerifyEvidence(mutated, trusted(), fixtureVerifier{}, now); !errors.Is(err, ErrEvidenceDigestMismatch) {
		t.Fatalf("mutated: %v", err)
	}
	revoked := trusted()
	revoked.Revoked["technical-key"] = true
	if err := VerifyEvidence(record, revoked, fixtureVerifier{}, now); !errors.Is(err, ErrEvidenceUntrusted) {
		t.Fatalf("revoked: %v", err)
	}
	missing := record
	missing.Approvals = missing.Approvals[:1]
	if err := VerifyEvidence(missing, trusted(), fixtureVerifier{}, now); !errors.Is(err, ErrEvidenceUntrusted) {
		t.Fatalf("missing: %v", err)
	}
	wrongRevision := record
	wrongRevision.Approvals = append([]EvidenceApproval(nil), record.Approvals...)
	wrongRevision.Approvals[0].ProfileRevision = "other"
	if err := VerifyEvidence(wrongRevision, trusted(), fixtureVerifier{}, now); !errors.Is(err, ErrEvidenceUntrusted) {
		t.Fatalf("revision: %v", err)
	}
}

func TestProfileIdentityAndFullLimitsAreClosed(t *testing.T) {
	profiles := DeclaredProfiles()
	profile := profiles[0]
	profile.AuthModality = "made-up"
	if _, err := NewRegistry([]Profile{profile}, nil, nil, nil, trusted(), fixtureVerifier{}); !errors.Is(err, ErrUnknownProfile) {
		t.Fatalf("modality=%v", err)
	}
	bad := finiteLimits()
	bad.MaxDepth = 0
	if bad.Validate() == nil {
		t.Fatal("missing depth accepted")
	}
	bad = finiteLimits()
	bad.Cost = CostLimit{Kind: "monetary", Currency: "usd", MinorUnitExponent: 2, MaxMinorUnits: 1}
	if bad.Validate() == nil {
		t.Fatal("noncanonical currency accepted")
	}
}

func TestDeclaredProfilesAreDisabledEvenWithFreshEvidenceLimitsAndMappings(t *testing.T) {
	now := time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)
	profiles := DeclaredProfiles()
	mappings, err := PinnedMappings()
	if err != nil {
		t.Fatal(err)
	}
	limits := map[string]ExecutionLimits{}
	evidence := make([]ProviderEvidenceRecord, 0, len(profiles))
	for index := range profiles {
		profile := &profiles[index]
		mapping := mappings[index]
		profile.MappingDigest = mapping.Digest
		profile.ExecutionLimitsDigest = finiteLimitsDigest(t)
		record := evidenceFor(t, *profile, now)
		profile.ProviderEvidenceDigest = record.Digest
		limits[profile.ID] = finiteLimits()
		evidence = append(evidence, record)
	}
	registry, err := NewRegistry(profiles, limits, mappings, evidence, trusted(), fixtureVerifier{})
	if err != nil {
		t.Fatal(err)
	}
	for _, profile := range profiles {
		got, err := registry.Lookup(context.Background(), profile.ID, now)
		if !errors.Is(err, ErrMappingMissing) || got.MeshSpawnEnabled || got.Status != StatusDisabled {
			t.Fatalf("%s got=%+v err=%v", profile.ID, got, err)
		}
	}
	if _, err := registry.Lookup(context.Background(), "unknown", now); !errors.Is(err, ErrUnknownProfile) {
		t.Fatalf("unknown: %v", err)
	}
}

func TestSyntheticMappingsCannotEnableMeshSpawn(t *testing.T) {
	now := time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)
	profiles := DeclaredProfiles()
	mappings, err := PinnedMappings()
	if err != nil {
		t.Fatal(err)
	}
	limits := map[string]ExecutionLimits{}
	evidence := make([]ProviderEvidenceRecord, 0, len(profiles))
	for index := range profiles {
		profile := &profiles[index]
		profile.AccountRef = "opaque-account-ref.v1:account_" + string(rune('a'+index))
		profile.MeshSpawnEnabled = true // persisted Controller revision, not Registry mutation.
		profile.MappingDigest = mappings[index].Digest
		profile.ExecutionLimitsDigest = finiteLimitsDigest(t)
		record := evidenceFor(t, *profile, now)
		profile.ProviderEvidenceDigest = record.Digest
		limits[profile.ID] = finiteLimits()
		evidence = append(evidence, record)
	}
	registry, err := NewRegistry(profiles, limits, mappings, evidence, trusted(), fixtureVerifier{})
	if err != nil {
		t.Fatal(err)
	}
	resolution, err := registry.Resolve(context.Background(), ProfileDeepSeekAPI, now)
	if !errors.Is(err, ErrMappingMissing) || resolution.MeshSpawnEnabled() || resolution.MappingVerified || resolution.EvidenceCurrent {
		t.Fatalf("synthetic mapping enabled: %+v err=%v", resolution, err)
	}
	missingAccount := DeclaredProfiles()[0]
	missingAccount.MeshSpawnEnabled = true
	if _, err := NewRegistry([]Profile{missingAccount}, nil, nil, nil, trusted(), fixtureVerifier{}); !errors.Is(err, ErrProfileIncompatible) {
		t.Fatalf("enabled cloud profile without opaque account ref: %v", err)
	}
	profiles[0].AccountRef = "api-key=not-opaque"
	if _, err := NewRegistry(profiles[:1], nil, nil, nil, trusted(), fixtureVerifier{}); !errors.Is(err, ErrUnknownProfile) {
		t.Fatalf("credential-shaped account ref accepted: %v", err)
	}
}

func TestAdapterRequiresCurrentMeshAudienceAndNeverExecutesProvider(t *testing.T) {
	mappings, err := PinnedMappings()
	if err != nil {
		t.Fatal(err)
	}
	adapter, err := NewPinnedAdapter(mappings[0])
	if err != nil {
		t.Fatal(err)
	}
	if _, err := adapter.Attach(context.Background(), EndpointBinding{BindingID: "binding", ProfileID: mappings[0].ProfileID, Audience: "ui", PeerID: "peer", ExpiresAt: time.Now().Add(time.Hour)}); !errors.Is(err, ErrBindingInvalid) {
		t.Fatalf("wrong audience: %v", err)
	}
	attached, err := adapter.Attach(context.Background(), EndpointBinding{BindingID: "binding", ProfileID: mappings[0].ProfileID, Audience: "mesh", PeerID: "peer", ExpiresAt: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if attached.Mapping.Digest != mappings[0].Digest {
		t.Fatal("mapping changed")
	}
}

func TestSyntheticMechanicsPathIsPerProviderAndRequiresSealedSpawn(t *testing.T) {
	mappings, err := PinnedMappings()
	if err != nil {
		t.Fatal(err)
	}
	for _, mapping := range mappings {
		t.Run(mapping.ProfileID, func(t *testing.T) {
			adapter, err := NewPinnedAdapter(mapping)
			if err != nil {
				t.Fatal(err)
			}
			attached, err := adapter.Attach(context.Background(), EndpointBinding{BindingID: "binding-" + mapping.ProfileID, ProfileID: mapping.ProfileID, Audience: "mesh", PeerID: "fixture-peer", ExpiresAt: time.Now().UTC().Add(time.Hour)})
			if err != nil {
				t.Fatal(err)
			}
			started, err := adapter.StartProvider(context.Background(), attached)
			if err != nil {
				t.Fatal(err)
			}
			tools, err := adapter.ExposeTools(started)
			if err != nil || len(tools) != len(requiredMeshOperations) {
				t.Fatalf("tool exposure=%+v err=%v", tools, err)
			}
			spawn, _ := mappingOperation(mapping, "spawn")
			collect, _ := mappingOperation(mapping, "collect")
			cancel, _ := mappingOperation(mapping, "cancel")
			unsealed := ToolProposal{SchemaVersion: ToolProposalV1, ProfileID: mapping.ProfileID, MappingDigest: mapping.Digest, Operation: "spawn", ClientNonce: "nonce-" + mapping.ProfileID, Objective: "fixture", RequestedRole: "worker", OutputSchema: "result.v1"}
			proposal, err := adapter.Propose(started, spawn.RequestEvent, unsealed)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := adapter.Start(context.Background(), started, proposal, SealedSpawn{}); !errors.Is(err, ErrMappingMissing) {
				t.Fatalf("unsealed start=%v", err)
			}
			sealed, err := sealOfflineFixture(proposal, attached.BindingID)
			if err != nil {
				t.Fatal(err)
			}
			session, err := adapter.Start(context.Background(), started, proposal, sealed)
			if err != nil {
				t.Fatal(err)
			}
			result, err := adapter.Collect(context.Background(), session)
			if err != nil || result.Operation != "collect" || result.ResultEvent != collect.ResultEvent || result.Terminal != "completed" {
				t.Fatalf("collect=%+v err=%v", result, err)
			}
			cancelledProposal, err := adapter.Propose(started, spawn.RequestEvent, ToolProposal{SchemaVersion: ToolProposalV1, ProfileID: mapping.ProfileID, MappingDigest: mapping.Digest, Operation: "spawn", ClientNonce: "cancel-" + mapping.ProfileID, Objective: "fixture", RequestedRole: "worker", OutputSchema: "result.v1"})
			if err != nil {
				t.Fatal(err)
			}
			cancelledSeal, err := sealOfflineFixture(cancelledProposal, attached.BindingID)
			if err != nil {
				t.Fatal(err)
			}
			cancelledSession, err := adapter.Start(context.Background(), started, cancelledProposal, cancelledSeal)
			if err != nil {
				t.Fatal(err)
			}
			cancelled, err := adapter.Cancel(context.Background(), cancelledSession)
			if err != nil || cancelled.Operation != "cancel" || cancelled.ResultEvent != cancel.ResultEvent || cancelled.Terminal != "cancelled" {
				t.Fatalf("cancel=%+v err=%v", cancelled, err)
			}
		})
	}
	if _, err := NewPinnedAdapter(mappings[0]); err != nil {
		t.Fatal(err)
	} else if _, err := (&PinnedAdapter{mapping: mappings[0], sessions: map[string]offlineSession{}}).Mapping(context.Background(), mappings[1].ProfileID); !errors.Is(err, ErrMappingMissing) {
		t.Fatalf("cross-provider mapping accepted: %v", err)
	}
}

func TestOfflineFixturesHaveExactProviderAndNoCredentialFields(t *testing.T) {
	paths, err := filepath.Glob("testdata/*.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) != 6 {
		t.Fatalf("fixtures=%d", len(paths))
	}
	mappings, err := PinnedMappings()
	if err != nil {
		t.Fatal(err)
	}
	byProfile := map[string]Mapping{}
	for _, mapping := range mappings {
		byProfile[mapping.ProfileID] = mapping
	}
	for _, path := range paths {
		bytes, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var fixture struct {
			Provider  string `json:"provider"`
			ProfileID string `json:"profile_id"`
			Events    []struct {
				Operation string `json:"operation"`
				Request   string `json:"request"`
				Result    string `json:"result"`
				Cancel    string `json:"cancel"`
			} `json:"events"`
		}
		if err := json.Unmarshal(bytes, &fixture); err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		if fixture.Provider == "" || fixture.ProfileID == "" || len(fixture.Events) != len(requiredMeshOperations) {
			t.Fatalf("%s invalid", path)
		}
		mapping, found := byProfile[fixture.ProfileID]
		if !found || string(mapping.Provider) != fixture.Provider {
			t.Fatalf("%s has no matching mapping", path)
		}
		adapter, err := NewPinnedAdapter(mapping)
		if err != nil {
			t.Fatal(err)
		}
		for _, event := range fixture.Events {
			operation, err := adapter.OperationForRequestEvent(event.Request)
			if err != nil || operation != event.Operation || event.Result == "" || event.Cancel == "" {
				t.Fatalf("%s event=%+v operation=%q err=%v", path, event, operation, err)
			}
		}
		for _, forbidden := range []string{"api_key", "token", "password", "credential", "subscription"} {
			if containsJSONKey(bytes, forbidden) {
				t.Fatalf("%s contains %s", path, forbidden)
			}
		}
	}
}

func pinnedCompatibilityFor(t *testing.T, profile Profile) CompatibilityRecord {
	t.Helper()
	runtime, protocol, ok := concreteVersionsFor(profile.ID)
	if !ok {
		t.Fatal("protocol")
	}
	operations, _ := PinnedMappings()
	var events []OperationMapping
	for _, mapping := range operations {
		if mapping.ProfileID == profile.ID {
			events = mapping.Operations
		}
	}
	record := CompatibilityRecord{SchemaVersion: CompatibilityRecordV1, Maturity: CompatibilityPinned, Provider: profile.Provider, ProfileID: profile.ID, ProfileRevision: profile.Revision, Model: profile.Model, AuthModality: profile.AuthModality, RuntimeVersion: runtime, ProtocolVersion: protocol, RuntimeArtifactDigest: fixedDigest(struct{ Runtime string }{runtime}), ProtocolSchemaDigest: fixedDigest(struct{ Protocol string }{protocol}), MeshToolSchemaDigest: fixedDigest(struct{ Schema string }{"mesh-tools.v1"}), TranscriptDigest: fixedDigest(events), Operations: events, Handshake: "success", Start: "success", Stream: "success", Cancel: "cancelled", Teardown: "quiescent", Health: "success", GeneratorVersion: "external-probe.v1", GeneratedAt: time.Date(2026, 8, 25, 1, 0, 0, 0, time.UTC), SourceReferences: []CompatibilitySource{{Reference: "https://evidence.example/compatibility/codex", Digest: fixedDigest("source")}}}
	if err := record.Seal(); err != nil {
		t.Fatal(err)
	}
	return record
}

func evidenceForCompatibility(t *testing.T, profile Profile, compatibility CompatibilityRecord, now time.Time) ProviderEvidenceRecord {
	t.Helper()
	record := evidenceFor(t, profile, now)
	record.RuntimeArtifactDigest = compatibility.RuntimeArtifactDigest
	record.RuntimeVersion = compatibility.RuntimeVersion
	record.ProtocolVersion = compatibility.ProtocolVersion
	record.SchemaDigest = compatibility.ProtocolSchemaDigest
	record.ProtocolSchemaDigest = compatibility.ProtocolSchemaDigest
	record.MeshToolSchemaDigest = compatibility.MeshToolSchemaDigest
	record.CompatibilityRecordDigest = compatibility.Digest
	if err := record.Seal(); err != nil {
		t.Fatal(err)
	}
	for i := range record.Approvals {
		record.Approvals[i].EvidenceDigest = record.Digest
		record.Approvals[i].Signature = record.Approvals[i].ReviewerKeyID + ":" + record.Digest
	}
	return record
}

func TestPinnedCompatibilityBindsMappingAndEvidence(t *testing.T) {
	now := time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)
	profile := DeclaredProfiles()[0]
	profile.AccountRef, profile.MeshSpawnEnabled, profile.ExecutionLimitsDigest, profile.Status = "opaque-account-ref.v1:approved", true, finiteLimitsDigest(t), StatusCompatible
	compatibility := pinnedCompatibilityFor(t, profile)
	mapping, err := MappingFromCompatibility(compatibility)
	if err != nil {
		t.Fatal(err)
	}
	profile.MappingDigest = mapping.Digest
	evidence := evidenceForCompatibility(t, profile, compatibility, now)
	profile.ProviderEvidenceDigest = evidence.Digest
	registry, err := NewRegistryWithCompatibility([]Profile{profile}, map[string]ExecutionLimits{profile.ID: finiteLimits()}, []Mapping{mapping}, []ProviderEvidenceRecord{evidence}, []CompatibilityRecord{compatibility}, trusted(), fixtureVerifier{})
	if err != nil {
		t.Fatal(err)
	}
	if eligible, err := registry.MeshEligible(profile.ID, now); err != nil || !eligible {
		t.Fatalf("eligible=%v err=%v", eligible, err)
	}
	for _, mutate := range []func(*ProviderEvidenceRecord){
		func(e *ProviderEvidenceRecord) { e.RuntimeArtifactDigest = fixedDigest("other-runtime") },
		func(e *ProviderEvidenceRecord) {
			e.ProtocolSchemaDigest = fixedDigest("other-protocol")
			e.SchemaDigest = e.ProtocolSchemaDigest
		},
		func(e *ProviderEvidenceRecord) { e.MeshToolSchemaDigest = fixedDigest("other-tools") },
		func(e *ProviderEvidenceRecord) { e.CompatibilityRecordDigest = fixedDigest("other-record") },
	} {
		bad := evidence
		mutate(&bad)
		_ = bad.Seal()
		for i := range bad.Approvals {
			bad.Approvals[i].EvidenceDigest = bad.Digest
			bad.Approvals[i].Signature = bad.Approvals[i].ReviewerKeyID + ":" + bad.Digest
		}
		profileBad := profile
		profileBad.ProviderEvidenceDigest = bad.Digest
		r, err := NewRegistryWithCompatibility([]Profile{profileBad}, map[string]ExecutionLimits{profile.ID: finiteLimits()}, []Mapping{mapping}, []ProviderEvidenceRecord{bad}, []CompatibilityRecord{compatibility}, trusted(), fixtureVerifier{})
		if err != nil {
			t.Fatal(err)
		}
		if eligible, err := r.MeshEligible(profile.ID, now); eligible || err == nil {
			t.Fatalf("digest mismatch enabled: %v %v", eligible, err)
		}
	}
	other := DeclaredProfiles()[1]
	if _, err := NewRegistryWithCompatibility([]Profile{profile}, map[string]ExecutionLimits{profile.ID: finiteLimits()}, []Mapping{mapping}, []ProviderEvidenceRecord{evidence}, []CompatibilityRecord{pinnedCompatibilityFor(t, other)}, trusted(), fixtureVerifier{}); !errors.Is(err, ErrCompatibilityInvalid) {
		t.Fatalf("cross-provider record: %v", err)
	}
}

func TestClosedStatusMatrixPreservesStatusAndOnlyCompatibleAdmits(t *testing.T) {
	now := time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)
	for _, status := range []Status{StatusDisabled, StatusConfigured, StatusAuthRequired, StatusReady, StatusDegraded, StatusCompatible, StatusIncompatible} {
		t.Run(string(status), func(t *testing.T) {
			profile := DeclaredProfiles()[0]
			profile.Status = status
			profile.AccountRef, profile.MeshSpawnEnabled, profile.ExecutionLimitsDigest = "opaque-account-ref.v1:approved", true, finiteLimitsDigest(t)
			compatibility := pinnedCompatibilityFor(t, profile)
			mapping, err := MappingFromCompatibility(compatibility)
			if err != nil {
				t.Fatal(err)
			}
			profile.MappingDigest = mapping.Digest
			evidence := evidenceForCompatibility(t, profile, compatibility, now)
			profile.ProviderEvidenceDigest = evidence.Digest
			registry, err := NewRegistryWithCompatibility([]Profile{profile}, map[string]ExecutionLimits{profile.ID: finiteLimits()}, []Mapping{mapping}, []ProviderEvidenceRecord{evidence}, []CompatibilityRecord{compatibility}, trusted(), fixtureVerifier{})
			if err != nil {
				t.Fatal(err)
			}
			got, err := registry.Lookup(context.Background(), profile.ID, now)
			if got.Status != status {
				t.Fatalf("lookup rewrote signed status: got=%s want=%s", got.Status, status)
			}
			expected := status == StatusCompatible
			if got.MeshSpawnEnabled != expected || (expected && err != nil) || (!expected && !errors.Is(err, ErrProfileIncompatible)) {
				t.Fatalf("status=%s spawn=%v err=%v", status, got.MeshSpawnEnabled, err)
			}
			directory := registry.Directory(context.Background(), now).Profiles()
			if len(directory) != 1 || directory[0].Status != status || directory[0].MeshSpawn != expected || directory[0].Freshness != EvidenceFreshnessCurrent {
				t.Fatalf("directory=%+v", directory)
			}
		})
	}
	unknown := DeclaredProfiles()[0]
	unknown.Status = Status("future-ready")
	if _, err := NewRegistry([]Profile{unknown}, nil, nil, nil, trusted(), fixtureVerifier{}); !errors.Is(err, ErrUnknownProfile) {
		t.Fatalf("unknown status accepted: %v", err)
	}
}

func TestDirectoryFreshnessFailsClosedForStaleAndRevokedEvidence(t *testing.T) {
	now := time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)
	profile := DeclaredProfiles()[0]
	profile.Status, profile.AccountRef, profile.MeshSpawnEnabled, profile.ExecutionLimitsDigest = StatusCompatible, "opaque-account-ref.v1:approved", true, finiteLimitsDigest(t)
	compatibility := pinnedCompatibilityFor(t, profile)
	mapping, err := MappingFromCompatibility(compatibility)
	if err != nil {
		t.Fatal(err)
	}
	profile.MappingDigest = mapping.Digest
	evidence := evidenceForCompatibility(t, profile, compatibility, now)
	evidence.RetrievedAt = now.Add(-2 * time.Hour)
	evidence.FreshUntil = now.Add(-time.Hour)
	if err := evidence.Seal(); err != nil {
		t.Fatal(err)
	}
	for i := range evidence.Approvals {
		evidence.Approvals[i].EvidenceDigest = evidence.Digest
		evidence.Approvals[i].FreshUntil = evidence.FreshUntil
		evidence.Approvals[i].Signature = evidence.Approvals[i].ReviewerKeyID + ":" + evidence.Digest
	}
	profile.ProviderEvidenceDigest = evidence.Digest
	registry, err := NewRegistryWithCompatibility([]Profile{profile}, map[string]ExecutionLimits{profile.ID: finiteLimits()}, []Mapping{mapping}, []ProviderEvidenceRecord{evidence}, []CompatibilityRecord{compatibility}, trusted(), fixtureVerifier{})
	if err != nil {
		t.Fatal(err)
	}
	entry := registry.Directory(context.Background(), now).Profiles()[0]
	if entry.MeshSpawn || entry.Freshness != EvidenceFreshnessStale {
		t.Fatalf("stale entry=%+v", entry)
	}
	revoked := trusted()
	revoked.Revoked["technical-key"] = true
	registry, err = NewRegistryWithCompatibility([]Profile{profile}, map[string]ExecutionLimits{profile.ID: finiteLimits()}, []Mapping{mapping}, []ProviderEvidenceRecord{evidence}, []CompatibilityRecord{compatibility}, revoked, fixtureVerifier{})
	if err != nil {
		t.Fatal(err)
	}
	entry = registry.Directory(context.Background(), now).Profiles()[0]
	if entry.MeshSpawn || entry.Freshness != EvidenceFreshnessUnknown {
		t.Fatalf("revoked entry=%+v", entry)
	}
}

func TestCompatibilityRecordStrictCanonicalAndSanitized(t *testing.T) {
	record := pinnedCompatibilityFor(t, DeclaredProfiles()[0])
	b, err := CanonicalCompatibilityJSON(record)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeCompatibilityRecord(b); err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeCompatibilityRecord(append(b, ' ')); !errors.Is(err, ErrCompatibilityInvalid) {
		t.Fatal("noncanonical accepted")
	}
	if _, err := DecodeCompatibilityRecord([]byte(`{"schema_version":"x","schema_version":"x"}`)); !errors.Is(err, ErrCompatibilityInvalid) {
		t.Fatal("duplicate accepted")
	}
	if _, err := DecodeCompatibilityRecord([]byte(`{"api_key":"x"}`)); !errors.Is(err, ErrCompatibilityInvalid) {
		t.Fatal("secret-shaped field accepted")
	}
	if _, err := DecodeCompatibilityRecord(make([]byte, maxCompatibilityRecordBytes+1)); !errors.Is(err, ErrCompatibilityInvalid) {
		t.Fatal("oversize accepted")
	}
}

// TestSyntheticFixturesDriveTheMechanicsRoute proves only in-memory fixture
// mechanics; testdata is not a provider transcript or compatibility evidence.
func TestSyntheticFixturesDriveTheMechanicsRoute(t *testing.T) {
	paths, err := filepath.Glob("testdata/*.json")
	if err != nil {
		t.Fatal(err)
	}
	mappings, err := PinnedMappings()
	if err != nil {
		t.Fatal(err)
	}
	byProfile := map[string]Mapping{}
	for _, mapping := range mappings {
		byProfile[mapping.ProfileID] = mapping
	}
	for _, path := range paths {
		bytes, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var fixture struct {
			ProfileID string `json:"profile_id"`
			Runtime   string `json:"runtime"`
			Protocol  string `json:"protocol"`
			Events    []struct {
				Operation string `json:"operation"`
				Request   string `json:"request"`
				Result    string `json:"result"`
				Cancel    string `json:"cancel"`
			} `json:"events"`
		}
		if err := json.Unmarshal(bytes, &fixture); err != nil {
			t.Fatal(err)
		}
		mapping, found := byProfile[fixture.ProfileID]
		if !found || mapping.RuntimeVersion != fixture.Runtime || mapping.ProtocolVersion != fixture.Protocol || len(fixture.Events) != len(requiredMeshOperations) {
			t.Fatalf("%s does not match pinned mapping", path)
		}
		t.Run(fixture.ProfileID, func(t *testing.T) {
			adapter, err := NewPinnedAdapter(mapping)
			if err != nil {
				t.Fatal(err)
			}
			attached, err := adapter.Attach(context.Background(), EndpointBinding{BindingID: "fixture-" + fixture.ProfileID, ProfileID: fixture.ProfileID, Audience: "mesh", PeerID: "offline-proof", ExpiresAt: time.Now().UTC().Add(time.Hour)})
			if err != nil {
				t.Fatal(err)
			}
			started, err := adapter.StartProvider(context.Background(), attached)
			if err != nil {
				t.Fatal(err)
			}
			tools, err := adapter.ExposeTools(started)
			if err != nil {
				t.Fatal(err)
			}
			for index, event := range fixture.Events {
				if tools[index].Operation != event.Operation || tools[index].RequestEvent != event.Request || tools[index].ResultEvent != event.Result || tools[index].CancelEvent != event.Cancel {
					t.Fatalf("event %d mismatch: tool=%+v fixture=%+v", index, tools[index], event)
				}
			}
			spawn, _ := mappingOperation(mapping, "spawn")
			proposal, err := adapter.Propose(started, spawn.RequestEvent, ToolProposal{SchemaVersion: ToolProposalV1, ProfileID: fixture.ProfileID, MappingDigest: mapping.Digest, Operation: "spawn", ClientNonce: "fixture-nonce", Objective: "fixture", RequestedRole: "worker", OutputSchema: "result.v1"})
			if err != nil {
				t.Fatal(err)
			}
			sealed, err := sealOfflineFixture(proposal, attached.BindingID)
			if err != nil {
				t.Fatal(err)
			}
			session, err := adapter.Start(context.Background(), started, proposal, sealed)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := adapter.Invoke(context.Background(), started, session, "unknown.native.operation"); !errors.Is(err, ErrMappingMissing) {
				t.Fatalf("unsupported provider event did not fail loud: %v", err)
			}
			for _, event := range fixture.Events {
				switch event.Operation {
				case "spawn":
					continue
				case "spawnBatch":
					batch, err := adapter.Propose(started, event.Request, ToolProposal{SchemaVersion: ToolProposalV1, ProfileID: fixture.ProfileID, MappingDigest: mapping.Digest, Operation: "spawnBatch", ClientNonce: "batch-nonce", Objective: "fixture", RequestedRole: "worker", OutputSchema: "result.v1"})
					if err != nil {
						t.Fatalf("batch proposal: %v", err)
					}
					batchSeal, err := sealOfflineFixture(batch, attached.BindingID)
					if err != nil {
						t.Fatal(err)
					}
					if _, err = adapter.Start(context.Background(), started, batch, batchSeal); !errors.Is(err, ErrMappingMissing) {
						t.Fatalf("batch accepted as single sealed spawn: %v", err)
					}
				case "collect", "cancel":
					continue
				default:
					out, err := adapter.Invoke(context.Background(), started, session, event.Request)
					if err != nil || out.Operation != event.Operation || out.ResultEvent != event.Result {
						t.Fatalf("invoke %s: out=%+v err=%v", event.Operation, out, err)
					}
				}
			}
			collected, err := adapter.Collect(context.Background(), session)
			collect, _ := mappingOperation(mapping, "collect")
			if err != nil || collected.ResultEvent != collect.ResultEvent {
				t.Fatalf("collect=%+v err=%v", collected, err)
			}
		})
	}
}

func containsJSONKey(bytes []byte, key string) bool {
	return string(bytes) == key || contains(string(bytes), "\""+key+"\"")
}
func contains(value, needle string) bool {
	for i := 0; i+len(needle) <= len(value); i++ {
		if value[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
