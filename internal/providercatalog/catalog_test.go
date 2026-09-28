package providercatalog

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"openduck/internal/providerbridge"
	"openduck/internal/providertransport"
	"openduck/internal/qwenclosure"
	"openduck/internal/releasecatalog"
)

func TestGenerateThenFinalizeDisabledCatalog(t *testing.T) {
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	imported, trustRaw, approved := testImport(t, now)
	generated, err := Generate(GenerateInput{BundleID: "bundle-p0", RevisionID: "revision-p0", Imports: []Import{imported}})
	if err != nil {
		t.Fatal(err)
	}
	if len(generated.Requests) != 2 || generated.Requests[0].Role != "security" || generated.Requests[1].Role != "technical" {
		t.Fatalf("expected distinct role requests, got %#v", generated.Requests)
	}
	runtime, ok := generated.Artifacts["providers/codex/runtime-descriptor.json"]
	if !ok {
		t.Fatal("runtime missing")
	}
	if _, err := providertransport.DecodeInactiveDescriptor(runtime); err != nil {
		t.Fatalf("not inactive: %v", err)
	}
	if _, err := providertransport.DecodeDescriptor(runtime); err == nil {
		t.Fatal("pre-release descriptor decoded as active")
	}
	stage := appendMandatory(generated.Artifacts)
	final, err := FinalizeEvidence(generated.Material, trustRaw, approved, now, stage)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := final["provider-bundle.json"]; !ok {
		t.Fatal("bundle missing")
	}
	if _, err := releasecatalog.DecodeProviderTopology(final["providers/codex/topology.json"]); err != nil {
		t.Fatal(err)
	}
}

func appendMandatory(in map[string][]byte) map[string][]byte {
	out := map[string][]byte{}
	for p, b := range in {
		out[p] = b
	}
	for _, entry := range releasecatalog.Entries() {
		if entry.Mandatory {
			out[entry.Path] = []byte("base:" + entry.Path)
		}
	}
	return out
}

func TestGenerateRejectsSyntheticAndHostSubstitution(t *testing.T) {
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	imported, _, _ := testImport(t, now)
	bad := imported
	bad.HostBinary = []byte("substituted")
	if _, err := Generate(GenerateInput{BundleID: "bundle-p0", RevisionID: "revision-p0", Imports: []Import{bad}}); err == nil {
		t.Fatal("host substitution accepted")
	}
	var c providerbridge.CompatibilityRecord
	if err := json.Unmarshal(imported.Compatibility, &c); err != nil {
		t.Fatal(err)
	}
	c.Maturity = providerbridge.CompatibilitySynthetic
	_ = c.Seal()
	bad = imported
	bad.Compatibility, _ = json.Marshal(c)
	if _, err := Generate(GenerateInput{BundleID: "bundle-p0", RevisionID: "revision-p0", Imports: []Import{bad}}); err == nil {
		t.Fatal("synthetic compatibility accepted")
	}
}

func TestGenerateQwenFromPinnedArchiveAndDerivedGolden(t *testing.T) {
	root := filepath.Join("..", "..", ".openduck")
	archivePath := filepath.Join(root, "provider-inputs", "qwen-code-darwin-arm64.tar.gz")
	nodePaths, globErr := filepath.Glob(filepath.Join(root, "qwen-inspect.*", "qwen-code", "node", "bin", "node"))
	if globErr != nil {
		t.Fatal(globErr)
	}
	if len(nodePaths) == 0 {
		t.Skip("private pinned Qwen archive/extracted node is intentionally absent from source control")
	}
	archive, err := os.ReadFile(archivePath)
	if os.IsNotExist(err) {
		t.Skip("private pinned Qwen archive is absent")
	}
	if err != nil {
		t.Fatal(err)
	}
	node, err := os.ReadFile(nodePaths[0])
	if err != nil {
		t.Fatal(err)
	}
	manifestRaw, err := os.ReadFile(filepath.Join("..", "qwenclosure", "testdata", "qwen-code-darwin-arm64.manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := qwenclosure.Decode(manifestRaw)
	if err != nil {
		t.Fatal(err)
	}
	if qwenclosure.DigestBytes(archive) != manifest.ArchiveDigest || qwenclosure.DigestBytes(node) != manifest.NodeDigest {
		t.Fatal("real archive/node does not match derived Qwen golden")
	}
	identityRaw, err := json.Marshal(struct {
		Schema         string `json:"schema"`
		Provider       string `json:"provider"`
		TeamID         string `json:"team_id"`
		ArtifactDigest string `json:"artifact_digest"`
		ImageIdentity  string `json:"image_identity"`
	}{"openduck.provider-host-identity.v1", "qwen", manifest.NodeTeamID, manifest.NodeDigest, qwenclosure.ImageIdentityForCDHash(manifest.NodeCDHash)})
	if err != nil {
		t.Fatal(err)
	}
	if qwenclosure.DigestBytes(identityRaw) != manifest.HostIdentityDigest {
		t.Fatal("derived Qwen host identity does not match golden")
	}
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	imported := qwenImport(t, now, archive, node, identityRaw, manifestRaw)
	generated, err := Generate(GenerateInput{BundleID: "bundle-qwen-real", RevisionID: "revision-qwen-real", Imports: []Import{imported}})
	if err != nil {
		t.Fatalf("real Qwen catalog generation rejected: %v", err)
	}
	for _, leaf := range []string{"providers/qwen/runtime-descriptor.json", "providers/qwen/host/node", "providers/qwen/host/host-identity.json", "providers/qwen/host/qwen-code-darwin-arm64.tar.gz", "providers/qwen/host/qwen-closure.sha256", "providers/qwen/topology.json"} {
		if len(generated.Artifacts[leaf]) == 0 {
			t.Fatalf("Qwen artifact %q missing", leaf)
		}
	}
}

func qwenImport(t *testing.T, now time.Time, archive, node, identity, manifest []byte) Import {
	t.Helper()
	operations := make([]providerbridge.OperationMapping, 0, 11)
	for _, op := range []string{"listProfiles", "spawn", "spawnBatch", "send", "steer", "wait", "collect", "cancel", "list", "status", "result"} {
		operations = append(operations, providerbridge.OperationMapping{Operation: op, RequestEvent: "request." + op, ResultEvent: "result." + op, CancelEvent: "cancel"})
	}
	compat := providerbridge.CompatibilityRecord{SchemaVersion: providerbridge.CompatibilityRecordV1, Maturity: providerbridge.CompatibilityPinned, Provider: providerbridge.ProviderQwen, ProfileID: providerbridge.ProfileQwenGeneral, ProfileRevision: "qwen-headless.v1", Model: "qwen-coder", AuthModality: "coding-plan-or-api", RuntimeVersion: "qwen-code@0.9.0", ProtocolVersion: "stream-json-mcp.v1", RuntimeArtifactDigest: providerbridge.DigestBytes(node), ProtocolSchemaDigest: providerbridge.DigestBytes([]byte("qwen-protocol")), MeshToolSchemaDigest: providerbridge.DigestBytes([]byte("mesh-tools")), TranscriptDigest: providerbridge.DigestBytes([]byte("qwen-transcript")), Operations: operations, Handshake: "success", Start: "success", Stream: "success", Cancel: "cancelled", Teardown: "quiescent", Health: "success", GeneratorVersion: "trusted-importer.v1", GeneratedAt: now.Add(-time.Hour), SourceReferences: []providerbridge.CompatibilitySource{{Reference: "https://example.invalid/qwen", Digest: providerbridge.DigestBytes([]byte("qwen-source"))}}}
	if err := compat.Seal(); err != nil {
		t.Fatal(err)
	}
	compatRaw, _ := json.Marshal(compat)
	limits := providerbridge.ExecutionLimits{SchemaVersion: providerbridge.ExecutionLimitsV1, MaxDepth: 1, MaxChildrenPerParent: 1, MaxConcurrentRuns: 1, MaxInputTokens: 1, MaxOutputTokens: 1, MaxWallMS: 1, MaxAttempts: 1, MaxResultBytes: 1, Cost: providerbridge.CostLimit{Kind: "non_monetary", Unit: "token", MaxQuantity: 1}}
	limitsRaw, _ := json.Marshal(limits)
	evidence := providerbridge.ProviderEvidenceRecord{SchemaVersion: providerbridge.EvidenceRecordV1, Provider: providerbridge.ProviderQwen, ProfileID: compat.ProfileID, ProfileRevision: compat.ProfileRevision, AuthModality: compat.AuthModality, OfficialURLs: []string{"https://example.invalid/qwen"}, RetrievedAt: now.Add(-time.Hour), FreshUntil: now.Add(time.Hour), RuntimeVersion: compat.RuntimeVersion, ProtocolVersion: compat.ProtocolVersion, Model: compat.Model, ClaimModalities: map[string]string{"official": "coding-plan-or-api"}, SourceContentDigest: providerbridge.DigestBytes([]byte("qwen-source")), RuntimeArtifactDigest: compat.RuntimeArtifactDigest, SchemaDigest: compat.ProtocolSchemaDigest, CompatibilityRecordDigest: compat.Digest, ProtocolSchemaDigest: compat.ProtocolSchemaDigest, MeshToolSchemaDigest: compat.MeshToolSchemaDigest, EvidenceGeneratorVersion: "trusted-importer.v1"}
	if err := evidence.Seal(); err != nil {
		t.Fatal(err)
	}
	evidenceRaw, _ := json.Marshal(evidence)
	return Import{Provider: "qwen", Compatibility: compatRaw, Evidence: evidenceRaw, Limits: limitsRaw, Daemon: []byte("qwen-daemon"), HostBinary: node, HostIdentity: identity, HostClosure: map[string][]byte{"qwen-code-darwin-arm64.tar.gz": archive, "qwen-closure.sha256": manifest}}
}

func TestFinalizeRejectsRoleOverlapAndRevocation(t *testing.T) {
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	imported, trustRaw, approved := testImport(t, now)
	generated, err := Generate(GenerateInput{BundleID: "bundle-p0", RevisionID: "revision-p0", Imports: []Import{imported}})
	if err != nil {
		t.Fatal(err)
	}
	var trust providerbridge.Ed25519TrustBundle
	if err := json.Unmarshal(trustRaw, &trust); err != nil {
		t.Fatal(err)
	}
	trust.TrustedSecurity = []string{"technical"}
	raw, _ := json.Marshal(trust)
	if _, err := FinalizeEvidence(generated.Material, raw, approved, now, generated.Artifacts); err == nil {
		t.Fatal("role overlap accepted")
	}
	trust.TrustedSecurity = []string{"security"}
	trust.Revoked = []string{"technical"}
	raw, _ = json.Marshal(trust)
	if _, err := FinalizeEvidence(generated.Material, raw, approved, now, generated.Artifacts); err == nil {
		t.Fatal("revoked approval accepted")
	}
}

func testImport(t *testing.T, now time.Time) (Import, []byte, map[string][]byte) {
	t.Helper()
	ops := make([]providerbridge.OperationMapping, 0, 11)
	for _, op := range []string{"listProfiles", "spawn", "spawnBatch", "send", "steer", "wait", "collect", "cancel", "list", "status", "result"} {
		ops = append(ops, providerbridge.OperationMapping{Operation: op, RequestEvent: "request." + op, ResultEvent: "result." + op, CancelEvent: "cancel"})
	}
	compat := providerbridge.CompatibilityRecord{SchemaVersion: providerbridge.CompatibilityRecordV1, Maturity: providerbridge.CompatibilityPinned, Provider: providerbridge.ProviderCodex, ProfileID: providerbridge.ProfileCodexChatGPT, ProfileRevision: "codex-app-server.v1", Model: "gpt-5.6", AuthModality: "chatgpt-subscription", RuntimeVersion: "codex-app-server@2026.8.30", ProtocolVersion: "app-server-thread.v1", RuntimeArtifactDigest: providerbridge.DigestBytes([]byte("runtime")), ProtocolSchemaDigest: providerbridge.DigestBytes([]byte("protocol")), MeshToolSchemaDigest: providerbridge.DigestBytes([]byte("tools")), TranscriptDigest: providerbridge.DigestBytes([]byte("transcript")), Operations: ops, Handshake: "success", Start: "success", Stream: "success", Cancel: "cancelled", Teardown: "quiescent", Health: "success", GeneratorVersion: "trusted-importer.v1", GeneratedAt: now.Add(-time.Hour), SourceReferences: []providerbridge.CompatibilitySource{{Reference: "https://example.invalid/codex", Digest: providerbridge.DigestBytes([]byte("source"))}}}
	if err := compat.Seal(); err != nil {
		t.Fatal(err)
	}
	compatRaw, _ := json.Marshal(compat)
	limits := providerbridge.ExecutionLimits{SchemaVersion: providerbridge.ExecutionLimitsV1, MaxDepth: 1, MaxChildrenPerParent: 1, MaxConcurrentRuns: 1, MaxInputTokens: 1, MaxOutputTokens: 1, MaxWallMS: 1, MaxAttempts: 1, MaxResultBytes: 1, Cost: providerbridge.CostLimit{Kind: "non_monetary", Unit: "token", MaxQuantity: 1}}
	limitsRaw, _ := json.Marshal(limits)
	evidence := providerbridge.ProviderEvidenceRecord{SchemaVersion: providerbridge.EvidenceRecordV1, Provider: providerbridge.ProviderCodex, ProfileID: compat.ProfileID, ProfileRevision: compat.ProfileRevision, AuthModality: compat.AuthModality, OfficialURLs: []string{"https://example.invalid/codex"}, RetrievedAt: now.Add(-time.Hour), FreshUntil: now.Add(time.Hour), RuntimeVersion: compat.RuntimeVersion, ProtocolVersion: compat.ProtocolVersion, Model: compat.Model, ClaimModalities: map[string]string{"official": "subscription"}, SourceContentDigest: providerbridge.DigestBytes([]byte("source")), RuntimeArtifactDigest: compat.RuntimeArtifactDigest, SchemaDigest: compat.ProtocolSchemaDigest, CompatibilityRecordDigest: compat.Digest, ProtocolSchemaDigest: compat.ProtocolSchemaDigest, MeshToolSchemaDigest: compat.MeshToolSchemaDigest, EvidenceGeneratorVersion: "trusted-importer.v1"}
	if err := evidence.Seal(); err != nil {
		t.Fatal(err)
	}
	unsigned, _ := json.Marshal(evidence)
	tech := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, ed25519.SeedSize))
	sec := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{2}, ed25519.SeedSize))
	trust := providerbridge.Ed25519TrustBundle{SchemaVersion: providerbridge.Ed25519TrustBundleV1, PublicKeys: map[string]string{"technical": hex.EncodeToString(tech.Public().(ed25519.PublicKey)), "security": hex.EncodeToString(sec.Public().(ed25519.PublicKey))}, TrustedTechnical: []string{"technical"}, TrustedSecurity: []string{"security"}}
	trustRaw, _ := json.Marshal(trust)
	evidence.Approvals = []providerbridge.EvidenceApproval{{SchemaVersion: "provider-evidence-approval.v1", Role: "technical", ReviewerKeyID: "technical", ProfileID: evidence.ProfileID, ProfileRevision: evidence.ProfileRevision, EvidenceDigest: evidence.Digest, FreshUntil: evidence.FreshUntil, DecisionRef: "tech-1", Signature: hex.EncodeToString(ed25519.Sign(tech, []byte(evidence.Digest)))}, {SchemaVersion: "provider-evidence-approval.v1", Role: "security", ReviewerKeyID: "security", ProfileID: evidence.ProfileID, ProfileRevision: evidence.ProfileRevision, EvidenceDigest: evidence.Digest, FreshUntil: evidence.FreshUntil, DecisionRef: "security-1", Signature: hex.EncodeToString(ed25519.Sign(sec, []byte(evidence.Digest)))}}
	approvedRaw, _ := json.Marshal(evidence)
	host := []byte("host-runtime")
	hostDigest := providerbridge.DigestBytes(host)
	identity := []byte(`{"schema":"openduck.provider-host-identity.v1","provider":"codex","team_id":"2DC432GLL2","artifact_digest":"` + hostDigest + `","image_identity":"sha256:` + strings.Repeat("a", 64) + `"}`)
	return Import{Provider: "codex", Compatibility: compatRaw, Evidence: unsigned, Limits: limitsRaw, Daemon: []byte("daemon"), HostBinary: host, HostIdentity: identity}, trustRaw, map[string][]byte{compat.ProfileID: approvedRaw}
}
