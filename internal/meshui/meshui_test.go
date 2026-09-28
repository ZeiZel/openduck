package meshui

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"openduck/internal/mesh"
	"openduck/internal/providerbridge"
)

type invoker struct {
	calls    int
	kinds    []string
	payload  []any
	response func(string) MeshUIResponse
	err      error
}

func (i *invoker) InvokeMeshUI(_ context.Context, kind string, payload any) (MeshUIResponse, error) {
	i.calls++
	i.kinds = append(i.kinds, kind)
	i.payload = append(i.payload, payload)
	if i.err != nil {
		return MeshUIResponse{}, i.err
	}
	return i.response(kind), nil
}

const validSpawn = `{"client_nonce":"n","objective":"o","preferred_profile":"deepseek.api","requested_role":"worker","output_schema_ref":"v1","requested_limits":{"max_depth":1,"max_children_per_parent":1,"max_concurrent_runs":1,"max_input_tokens":1,"max_output_tokens":1,"max_wall_ms":1,"max_attempts":1,"max_result_bytes":1,"cost":{"kind":"non_monetary","currency":"","minor_unit_exponent":0,"max_minor_units":0,"unit":"token","max_quantity":1}}}`
const verifiedDigest = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func validProposal() ProposalOutput {
	return ProposalOutput{ProposalID: "proposal-1", RunID: "run-1", SessionID: "session-1", OrderID: "order-1", BindingID: "binding-1"}
}
func validInputAck() OperationAcknowledgement {
	return OperationAcknowledgement{TargetRunID: "run-1", InputRef: "input-1", Digest: verifiedDigest, Status: "sent"}
}
func validCancelAck() OperationAcknowledgement {
	return OperationAcknowledgement{TargetRunID: "run-1", RevisionRef: "revision-1", ReasonRef: "reason-1", Digest: verifiedDigest, Status: "cancelled"}
}
func validRevisionAck(status string) OperationAcknowledgement {
	return OperationAcknowledgement{TargetRunID: "run-1", RevisionRef: "revision-1", Digest: verifiedDigest, Status: status}
}
func validSession() SessionStatusOutput {
	return SessionStatusOutput{State: "running", UsageSource: "unknown"}
}
func validEnvelope() ResultEnvelopeOutput {
	return ResultEnvelopeOutput{RunID: "run-1", AttemptID: "attempt-1", Status: "completed", OutputArtifactRef: "artifact-1", SchemaRef: "result-v1", ProvenanceDigest: verifiedDigest, Classification: "L1"}
}
func validResponse(kind string) MeshUIResponse {
	r := MeshUIResponse{SchemaVersion: ResponseSchema, Kind: kind}
	switch kind {
	case "selection-revision":
		r.Selection = &SelectionOutput{RevisionID: "revision-2"}
	case "mesh-spawn":
		r.Spawn = &SpawnOutput{Proposal: validProposal()}
	case "mesh-spawnBatch":
		r.SpawnBatch = &SpawnBatchOutput{BatchID: "batch-1", Results: []ProposalOutput{validProposal()}}
	case "mesh-send":
		r.Send = &AcknowledgementOutput{Acknowledgement: validInputAck()}
	case "mesh-steer":
		r.Steer = &AcknowledgementOutput{Acknowledgement: validInputAck()}
	case "mesh-wait":
		r.Wait = &SessionStatusOutput{State: "running", UsageSource: "unknown"}
	case "mesh-collect":
		r.Collect = &ResultEnvelopeOutput{RunID: "run-1", AttemptID: "attempt-1", Status: "completed", OutputArtifactRef: "artifact-1", SchemaRef: "result-v1", ProvenanceDigest: verifiedDigest, Classification: "L1"}
	case "mesh-cancel":
		r.Cancel = &AcknowledgementOutput{Acknowledgement: validCancelAck()}
	case "mesh-list":
		r.List = &ListOutput{Runs: []RunListItem{{RunID: "run-1", ProfileID: "deepseek.api", Provider: "deepseek", Status: "running", Depth: 1}}}
	case "mesh-status":
		r.Status = &SessionStatusOutput{State: "running", UsageSource: "unknown"}
	case "mesh-result":
		r.Result = &ResultEnvelopeOutput{RunID: "run-1", AttemptID: "attempt-1", Status: "completed", OutputArtifactRef: "artifact-1", SchemaRef: "result-v1", ProvenanceDigest: verifiedDigest, Classification: "L1"}
	case "mesh-listProfiles":
		r.ListProfiles = &ProfilesOutput{Profiles: disabledProjection().Profiles[:1]}
	case "provider-directory":
		r.Directory = &ProfilesOutput{Profiles: disabledProjection().Profiles[:1]}
	case "ui-session-graph":
		r.Graph = &GraphOutput{Graph: Graph{Nodes: []GraphNode{}, Edges: []GraphEdge{}}}
	case "run-compare":
		r.Compare = &CompareOutput{Compare: Comparison{Runs: []CompareRun{}}}
	case "run-synthesis":
		r.Synthesis = &ResultEnvelopeOutput{RunID: "run-1", AttemptID: "attempt-1", Status: "completed", OutputArtifactRef: "artifact-1", SchemaRef: "result-v1", ProvenanceDigest: verifiedDigest, Classification: "L1"}
	case "run-templates":
		r.Templates = &TemplatesOutput{Templates: Templates{Approved: []Template{}}}
	case "policy-approval-inspector":
		r.Policy = &PolicyOutput{Policy: Policy{Approvals: []PolicyApproval{}}}
	case "provider-diagnostics":
		r.Diagnostics = &DiagnosticsOutput{Diagnostics: Diagnostics{Providers: []ProviderDiagnostic{}}}
	case "deployment-diagnostics":
		r.Deployment = &DeploymentOutput{Status: "healthy", Acknowledgement: validRevisionAck("completed")}
	case "plugin-lifecycle":
		r.PluginLifecycle = &PluginLifecycleOutput{Package: Package{PackageID: "openduck-mesh", Digest: verifiedDigest, Status: "disabled"}, Acknowledgement: validRevisionAck("completed")}
	}
	return r
}

func TestSelectionForwardsWithoutLocalState(t *testing.T) {
	i := &invoker{response: validResponse}
	s := NewProjectionService(i)
	before := projectionJSON(t, s.Projection(context.Background()))
	got, err := s.Select(context.Background(), []byte(`{"profile_id":"deepseek.api","operation":"new-root","base_revision_id":"mesh-disabled"}`))
	if err != nil || got.Selection == nil || got.Selection.RevisionID != "revision-2" || i.calls != 1 || i.kinds[0] != "selection-revision" {
		t.Fatalf("got=%+v err=%v calls=%d", got, err, i.calls)
	}
	if after := projectionJSON(t, s.Projection(context.Background())); after != before {
		t.Fatal("selection mutated local projection")
	}
}

func TestSelectionNilInvokerIsUnavailableAndStateFree(t *testing.T) {
	s := NewProjectionService(nil)
	before := projectionJSON(t, s.Projection(context.Background()))
	got, err := s.Select(context.Background(), []byte(`{"profile_id":"deepseek.api","operation":"new-root","base_revision_id":"mesh-disabled"}`))
	if err != ErrUnavailable || got != (MeshUIResponse{}) {
		t.Fatalf("got=%+v err=%v", got, err)
	}
	if projectionJSON(t, s.Projection(context.Background())) != before {
		t.Fatal("nil selection mutated local projection")
	}
}

func TestInvalidInvokerOutputFailsClosedBeforeServiceReturns(t *testing.T) {
	bad := func(kind string) MeshUIResponse { r := validResponse(kind); r.Kind = "mesh-result"; return r }
	s := NewProjectionService(&invoker{response: bad})
	got, err := s.Select(context.Background(), []byte(`{"profile_id":"deepseek.api","operation":"new-root","base_revision_id":"mesh-disabled"}`))
	if !errors.Is(err, ErrInvalidOutput) || got != (MeshUIResponse{}) {
		t.Fatalf("got=%+v err=%v", got, err)
	}
	secret := func(kind string) MeshUIResponse {
		r := validResponse(kind)
		r.Selection.RevisionID = "secret-revision"
		return r
	}
	s = NewProjectionService(&invoker{response: secret})
	if _, err := s.Select(context.Background(), []byte(`{"profile_id":"deepseek.api","operation":"new-root","base_revision_id":"mesh-disabled"}`)); !errors.Is(err, ErrInvalidOutput) {
		t.Fatalf("secret output err=%v", err)
	}
}

func TestServiceCopiesValidatedInvokerOutput(t *testing.T) {
	shared := validResponse("mesh-result")
	s := NewProjectionService(&invoker{response: func(string) MeshUIResponse { return shared }})
	got, err := s.Propose(context.Background(), "mesh-result", []byte(`{"run_id":"run-1","revision_ref":"revision-1"}`))
	if err != nil {
		t.Fatal(err)
	}
	shared.Result.OutputArtifactRef = "secret-artifact"
	if got.Result == nil || got.Result.OutputArtifactRef != "artifact-1" || got.Validate("mesh-result") != nil {
		t.Fatalf("invoker-owned output escaped validation copy: %+v", got)
	}
}

type snapshotSource struct {
	snapshot ProjectionSnapshot
	err      error
}

type directoryVerifier struct{}

func (directoryVerifier) Verify(id, payload, signature string) bool {
	return signature == id+":"+payload
}

func verifiedDirectory(t *testing.T, status providerbridge.Status, now time.Time) providerbridge.DirectorySnapshot {
	t.Helper()
	profile := providerbridge.DeclaredProfiles()[0]
	profile.Status = status
	profile.AccountRef = "opaque-account-ref.v1:ui_fixture"
	profile.MeshSpawnEnabled = true
	limits := providerbridge.ExecutionLimits{SchemaVersion: providerbridge.ExecutionLimitsV1, MaxDepth: 1, MaxChildrenPerParent: 1, MaxConcurrentRuns: 1, MaxInputTokens: 1, MaxOutputTokens: 1, MaxWallMS: 1, MaxAttempts: 1, MaxResultBytes: 1, Cost: providerbridge.CostLimit{Kind: "non_monetary", Unit: "token", MaxQuantity: 1}}
	var err error
	profile.ExecutionLimitsDigest, err = limits.Digest()
	if err != nil {
		t.Fatal(err)
	}
	fixtures, err := providerbridge.PinnedMappings()
	if err != nil {
		t.Fatal(err)
	}
	var operations []providerbridge.OperationMapping
	for _, fixture := range fixtures {
		if fixture.ProfileID == profile.ID {
			operations = fixture.Operations
			break
		}
	}
	compatibility := providerbridge.CompatibilityRecord{SchemaVersion: providerbridge.CompatibilityRecordV1, Maturity: providerbridge.CompatibilityPinned, Provider: profile.Provider, ProfileID: profile.ID, ProfileRevision: profile.Revision, Model: profile.Model, AuthModality: profile.AuthModality, RuntimeVersion: "codex-app-server@2026.8.25", ProtocolVersion: "app-server-thread.v1", RuntimeArtifactDigest: verifiedDigest, ProtocolSchemaDigest: verifiedDigest, MeshToolSchemaDigest: verifiedDigest, TranscriptDigest: verifiedDigest, Operations: operations, Handshake: "success", Start: "success", Stream: "success", Cancel: "cancelled", Teardown: "quiescent", Health: "success", GeneratorVersion: "ui-fixture.v1", GeneratedAt: now.Add(-time.Hour), SourceReferences: []providerbridge.CompatibilitySource{{Reference: "https://evidence.example/compatibility/codex", Digest: verifiedDigest}}}
	if err := compatibility.Seal(); err != nil {
		t.Fatal(err)
	}
	mapping, err := providerbridge.MappingFromCompatibility(compatibility)
	if err != nil {
		t.Fatal(err)
	}
	profile.MappingDigest = mapping.Digest
	evidence := providerbridge.ProviderEvidenceRecord{SchemaVersion: providerbridge.EvidenceRecordV1, Provider: profile.Provider, ProfileID: profile.ID, ProfileRevision: profile.Revision, AuthModality: profile.AuthModality, OfficialURLs: []string{"https://official.example/codex"}, RetrievedAt: now.Add(-time.Hour), FreshUntil: now.Add(time.Hour), RuntimeVersion: compatibility.RuntimeVersion, ProtocolVersion: compatibility.ProtocolVersion, Model: profile.Model, ClaimModalities: map[string]string{"official-provider-route": profile.AuthModality}, SourceContentDigest: verifiedDigest, RuntimeArtifactDigest: compatibility.RuntimeArtifactDigest, SchemaDigest: compatibility.ProtocolSchemaDigest, CompatibilityRecordDigest: compatibility.Digest, ProtocolSchemaDigest: compatibility.ProtocolSchemaDigest, MeshToolSchemaDigest: compatibility.MeshToolSchemaDigest, EvidenceGeneratorVersion: "ui-fixture.v1"}
	if err := evidence.Seal(); err != nil {
		t.Fatal(err)
	}
	evidence.Approvals = []providerbridge.EvidenceApproval{
		{SchemaVersion: "provider-evidence-approval.v1", Role: "technical", ReviewerKeyID: "technical-key", ProfileID: profile.ID, ProfileRevision: profile.Revision, EvidenceDigest: evidence.Digest, FreshUntil: evidence.FreshUntil, DecisionRef: "decision-tech", Signature: "technical-key:" + evidence.Digest},
		{SchemaVersion: "provider-evidence-approval.v1", Role: "security", ReviewerKeyID: "security-key", ProfileID: profile.ID, ProfileRevision: profile.Revision, EvidenceDigest: evidence.Digest, FreshUntil: evidence.FreshUntil, DecisionRef: "decision-security", Signature: "security-key:" + evidence.Digest},
	}
	profile.ProviderEvidenceDigest = evidence.Digest
	registry, err := providerbridge.NewRegistryWithCompatibility([]providerbridge.Profile{profile}, map[string]providerbridge.ExecutionLimits{profile.ID: limits}, []providerbridge.Mapping{mapping}, []providerbridge.ProviderEvidenceRecord{evidence}, []providerbridge.CompatibilityRecord{compatibility}, providerbridge.TrustRegistry{TrustedTechnical: map[string]bool{"technical-key": true}, TrustedSecurity: map[string]bool{"security-key": true}, Revoked: map[string]bool{}}, directoryVerifier{})
	if err != nil {
		t.Fatal(err)
	}
	return registry.Directory(context.Background(), now)
}

func (s snapshotSource) MeshUIProjection(context.Context) (ProjectionSnapshot, error) {
	return s.snapshot, s.err
}

func TestProjectionIsHonestAndFullyTyped(t *testing.T) {
	p := NewProjectionService(nil).Projection(context.Background())
	if err := p.Validate(); err != nil || p.RevisionID != "mesh-disabled" || len(p.Lifecycle.Packages) != 0 {
		t.Fatalf("projection=%+v err=%v", p, err)
	}
	for _, profile := range p.Profiles {
		if profile.Status != "disabled" || profile.MeshSpawn {
			t.Fatalf("dishonest profile %+v", profile)
		}
	}
	for _, entry := range p.Diagnostics.Providers {
		if entry.Status != "disabled" || entry.Freshness != "unknown" {
			t.Fatalf("dishonest diagnostic %+v", entry)
		}
	}
}

func TestProjectionPreservesVerifiedInjectedDigestAndRejectsMalformedSnapshot(t *testing.T) {
	s := NewProjectionServiceWithSource(nil, snapshotSource{snapshot: ProjectionSnapshot{RevisionID: "controller-revision-7", Package: &PackageSnapshot{PackageID: "openduck-mesh", Digest: verifiedDigest, Status: "disabled"}}})
	p := s.Projection(context.Background())
	if err := p.Validate(); err != nil || p.RevisionID != "controller-revision-7" || len(p.Lifecycle.Packages) != 1 || p.Lifecycle.Packages[0].Digest != verifiedDigest {
		t.Fatalf("projection=%+v err=%v", p, err)
	}
	s = NewProjectionServiceWithSource(nil, snapshotSource{snapshot: ProjectionSnapshot{RevisionID: "secret-revision"}})
	if got := s.Projection(context.Background()); got.RevisionID != "mesh-disabled" {
		t.Fatalf("invalid source projected=%+v", got)
	}
	resultRef := "result-1"
	s = NewProjectionServiceWithSource(nil, snapshotSource{snapshot: ProjectionSnapshot{RevisionID: "controller-revision-8", Compare: &Comparison{Runs: []CompareRun{{Provider: "deepseek", ProfileID: "deepseek.api", Status: "completed", ResultAvailable: true, ResultRef: &resultRef}}}}})
	p = s.Projection(context.Background())
	resultRef = "secret-result"
	if p.Compare.Runs[0].ResultRef == nil || *p.Compare.Runs[0].ResultRef != "result-1" || p.Validate() != nil {
		t.Fatalf("projection retained source pointer: %+v", p)
	}
}

func TestProjectionOverlaysOnlyRegistryDerivedDirectoryAndEligibleLifecycle(t *testing.T) {
	now := time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)
	directory := verifiedDirectory(t, providerbridge.StatusCompatible, now)
	s := NewProjectionServiceWithSource(nil, snapshotSource{snapshot: ProjectionSnapshot{RevisionID: "controller-revision-compatible", ProviderDirectory: directory, Package: &PackageSnapshot{PackageID: "openduck-mesh", Digest: verifiedDigest, Status: "enabled"}}})
	p := s.Projection(context.Background())
	if p.Validate() != nil || len(p.Profiles) != len(providerbridge.DeclaredProfiles()) || len(p.Lifecycle.Packages) != 1 || p.Lifecycle.Packages[0].Status != "enabled" {
		t.Fatalf("projection=%+v", p)
	}
	for _, profile := range p.Profiles {
		if profile.ProfileID == providerbridge.ProfileCodexChatGPT {
			if profile.Status != "compatible" || !profile.MeshSpawn {
				t.Fatalf("eligible profile=%+v", profile)
			}
			continue
		}
		if profile.Status != "disabled" || profile.MeshSpawn {
			t.Fatalf("default profile=%+v", profile)
		}
	}
	for _, diagnostic := range p.Diagnostics.Providers {
		if diagnostic.ProfileID == providerbridge.ProfileCodexChatGPT && (diagnostic.Status != "compatible" || diagnostic.Freshness != "current") {
			t.Fatalf("diagnostic=%+v", diagnostic)
		}
	}
}

func TestProjectionNeverTreatsReadyAsEligibilityOrPackageEnablement(t *testing.T) {
	now := time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)
	directory := verifiedDirectory(t, providerbridge.StatusReady, now)
	s := NewProjectionServiceWithSource(nil, snapshotSource{snapshot: ProjectionSnapshot{RevisionID: "controller-revision-ready", ProviderDirectory: directory}})
	p := s.Projection(context.Background())
	for _, profile := range p.Profiles {
		if profile.ProfileID == providerbridge.ProfileCodexChatGPT && (profile.Status != "ready" || profile.MeshSpawn) {
			t.Fatalf("ready was eligible: %+v", profile)
		}
	}
	for _, diagnostic := range p.Diagnostics.Providers {
		if diagnostic.ProfileID == providerbridge.ProfileCodexChatGPT && diagnostic.Freshness != "current" {
			t.Fatalf("ready diagnostic=%+v", diagnostic)
		}
	}
	s = NewProjectionServiceWithSource(nil, snapshotSource{snapshot: ProjectionSnapshot{RevisionID: "controller-revision-contradiction", ProviderDirectory: directory, Package: &PackageSnapshot{PackageID: "openduck-mesh", Digest: verifiedDigest, Status: "enabled"}}})
	if got := s.Projection(context.Background()); got.RevisionID != "mesh-disabled" || len(got.Lifecycle.Packages) != 0 {
		t.Fatalf("contradictory enabled package projected: %+v", got)
	}
}

func TestAllMeshOperationsUseExactRevisionBoundDTOs(t *testing.T) {
	i := &invoker{response: validResponse}
	s := NewProjectionService(i)
	valid := map[string]string{
		"mesh-spawn": validSpawn, "mesh-spawnBatch": `{"proposals":[` + validSpawn + `]}`,
		"mesh-send": `{"run_id":"run-1","input_ref":"revision-1"}`, "mesh-steer": `{"run_id":"run-1","input_ref":"revision-1"}`,
		"mesh-wait": `{"run_id":"run-1","revision_ref":"revision-1"}`, "mesh-collect": `{"run_id":"run-1","revision_ref":"revision-1"}`,
		"mesh-cancel": `{"run_id":"run-1","reason_ref":"reason-1","revision_ref":"revision-1"}`, "mesh-list": `{"root_id":"root-1","revision_ref":"revision-1"}`,
		"mesh-status": `{"run_id":"run-1","revision_ref":"revision-1"}`, "mesh-result": `{"run_id":"run-1","revision_ref":"revision-1"}`, "mesh-listProfiles": `{}`,
	}
	for kind, body := range valid {
		got, err := s.Propose(context.Background(), kind, []byte(body))
		if err != nil || got.Validate(kind) != nil {
			t.Fatalf("%s got=%+v err=%v", kind, got, err)
		}
	}
	for kind, body := range map[string]string{
		"mesh-spawn": `{"client_nonce":1}`, "mesh-spawnBatch": `{"proposals":[]}`, "mesh-send": `{"run_id":"run-1","input_ref":1}`, "mesh-steer": `{"run_id":"run-1","input_ref":1}`,
		"mesh-wait": `{"run_id":"run-1"}`, "mesh-collect": `{"run_id":"run-1"}`, "mesh-cancel": `{"run_id":"run-1","reason_ref":"reason-1"}`, "mesh-list": `{"root_id":"root-1"}`,
		"mesh-status": `{"run_id":"run-1"}`, "mesh-result": `{"run_id":"run-1"}`, "mesh-listProfiles": `null`,
	} {
		before := i.calls
		if _, err := s.Propose(context.Background(), kind, []byte(body)); err != ErrInvalid || i.calls != before {
			t.Fatalf("%s invalid reached invoker: err=%v", kind, err)
		}
	}
}

func TestSpawnBatchBoundaryMatchesCoordinatorBeforeInvoker(t *testing.T) {
	i := &invoker{response: validResponse}
	s := NewProjectionService(i)
	batch := func(count int) []byte {
		proposals := make([]string, count)
		for n := range proposals {
			proposals[n] = strings.Replace(validSpawn, `"client_nonce":"n"`, `"client_nonce":"n-`+strconv.Itoa(n)+`"`, 1)
		}
		return []byte(`{"proposals":[` + strings.Join(proposals, ",") + `]}`)
	}
	if got, err := s.Propose(context.Background(), "mesh-spawnBatch", batch(16)); err != nil || got.Validate("mesh-spawnBatch") != nil || i.calls != 1 {
		t.Fatalf("16 item batch got=%+v err=%v calls=%d", got, err, i.calls)
	}
	payload, ok := i.payload[0].([]mesh.SpawnProposal)
	if !ok || len(payload) != 16 {
		t.Fatalf("16 item batch payload=%T %#v", i.payload[0], i.payload[0])
	}
	before := i.calls
	if got, err := s.Propose(context.Background(), "mesh-spawnBatch", batch(17)); err != ErrInvalid || got != (MeshUIResponse{}) || i.calls != before {
		t.Fatalf("17 item batch reached invoker: got=%+v err=%v calls=%d", got, err, i.calls)
	}
}

func TestEverySurfaceUsesExactResponseDiscriminatorAndInputValidation(t *testing.T) {
	i := &invoker{response: validResponse}
	s := NewProjectionService(i)
	valid := map[string]string{
		"provider-directory": `{"action":"refresh","profile_id":"deepseek.api"}`, "ui-session-graph": `{"root_id":"root-1"}`, "run-compare": `{"run_ids":["run-1"]}`,
		"run-synthesis": `{"template_id":"template-1","source_result_refs":["result-1"]}`, "run-templates": `{"template_id":"template-1","version":"v1"}`,
		"policy-approval-inspector": `{"decision_ref":"decision-1"}`, "provider-diagnostics": `{"action":"refresh","profile_id":"deepseek.api"}`, "deployment-diagnostics": `{"action":"doctor"}`,
		"plugin-lifecycle": `{"schema_version":"plugin-lifecycle-request.v1","action":"enable","package_id":"openduck-mesh","package_digest":"` + verifiedDigest + `","profile_revision":"revision-1","controller_binding_id":"binding-1","expires_at":"2026-08-26T00:00:00.000Z"}`,
	}
	for kind, body := range valid {
		got, err := s.Propose(context.Background(), kind, []byte(body))
		if err != nil || got.Validate(kind) != nil {
			t.Fatalf("%s: %+v %v", kind, got, err)
		}
		before := i.calls
		unknown := strings.TrimSuffix(body, "}") + `,"unexpected":"value"}`
		if _, err := s.Propose(context.Background(), kind, []byte(unknown)); err != ErrInvalid || i.calls != before {
			t.Fatalf("%s unknown field reached invoker: %v", kind, err)
		}
	}
	for kind, body := range map[string]string{
		"provider-directory": `{"action":"invented","profile_id":"deepseek.api"}`, "ui-session-graph": `{"root_id":1}`, "run-compare": `{"run_ids":[]}`,
		"run-synthesis": `{"template_id":"template-1","source_result_refs":["result-1","result-1"]}`, "run-templates": `{"template_id":"template-1","version":1}`,
		"policy-approval-inspector": `{"decision_ref":1}`, "provider-diagnostics": `{"action":"wrong","profile_id":"deepseek.api"}`, "deployment-diagnostics": `{"action":"wrong"}`,
		"plugin-lifecycle": `{"schema_version":"plugin-lifecycle-request.v1","action":"wrong","package_id":"openduck-mesh","package_digest":"` + verifiedDigest + `","profile_revision":"revision-1","controller_binding_id":"binding-1","expires_at":"2026-08-26T00:00:00.000Z"}`,
	} {
		before := i.calls
		if _, err := s.Propose(context.Background(), kind, []byte(body)); err != ErrInvalid || i.calls != before {
			t.Fatalf("%s invalid reached invoker: %v", kind, err)
		}
	}
}

func TestStrictInputRejectsDuplicateTrailingAndDeepJSONBeforeInvoker(t *testing.T) {
	i := &invoker{response: validResponse}
	s := NewProjectionService(i)
	deep := strings.Repeat(`{"x":`, maxJSONDepth+1) + `0` + strings.Repeat(`}`, maxJSONDepth+1)
	cases := []struct {
		kind string
		body string
		call func([]byte) error
	}{
		{"selection duplicate", `{"profile_id":"deepseek.api","profile_id":"deepseek.api","operation":"new-root","base_revision_id":"mesh-disabled"}`, func(body []byte) error { _, err := s.Select(context.Background(), body); return err }},
		{"mesh trailing", `{"run_id":"run-1","input_ref":"input-1"}{}`, func(body []byte) error { _, err := s.Propose(context.Background(), "mesh-send", body); return err }},
		{"nested over limit", deep, func(body []byte) error {
			_, err := s.Propose(context.Background(), "ui-session-graph", body)
			return err
		}},
	}
	for _, tt := range cases {
		before := i.calls
		if err := tt.call([]byte(tt.body)); err != ErrInvalid || i.calls != before {
			t.Fatalf("%s reached invoker: %v", tt.kind, err)
		}
	}
}

func TestResponseValidationRejectsCrossKindPresenceAndFabrication(t *testing.T) {
	base := validResponse("mesh-result")
	wrongKind := base
	wrongKind.Kind = "mesh-status"
	extra := base
	extra.Status = &SessionStatusOutput{State: "running", UsageSource: "unknown"}
	secret := base
	secret.Result.OutputArtifactRef = "secret-artifact"
	badDigest := base
	badDigest.Result.ProvenanceDigest = "sha256:bad"
	badState := base
	badState.Result.Status = "invented"
	for _, value := range []MeshUIResponse{{}, wrongKind, extra, secret, badDigest, badState} {
		if value.Validate("mesh-result") == nil {
			t.Fatalf("unsafe output accepted: %+v", value)
		}
	}
	missing := Comparison{Runs: []CompareRun{{Provider: "deepseek", ProfileID: "deepseek.api", Status: "running", ResultAvailable: false}}}
	if !missing.valid() {
		t.Fatal("missing result should be representable")
	}
	ref := "result-1"
	available := missing
	available.Runs[0].ResultAvailable, available.Runs[0].ResultRef = true, &ref
	if !available.valid() {
		t.Fatal("available result should be representable")
	}
	available.Runs[0].ResultRef = nil
	if available.valid() {
		t.Fatal("result availability presence rule bypassed")
	}
	send := validResponse("mesh-send")
	send.Send.Acknowledgement.RevisionRef = "revision-1"
	if send.Validate("mesh-send") == nil {
		t.Fatal("send acknowledgement accepted a revision substitution")
	}
	cancel := validResponse("mesh-cancel")
	cancel.Cancel.Acknowledgement.InputRef = "input-1"
	if cancel.Validate("mesh-cancel") == nil {
		t.Fatal("cancel acknowledgement accepted an input substitution")
	}
}

func TestMeshUIHasNoHTTPDSHModelOrLogBoundary(t *testing.T) {
	b, err := os.ReadFile("meshui.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"internal/dshbridge", "net/http", "modelPrompt", "sessionLog", "appendEvent", "AgentLoop"} {
		if strings.Contains(string(b), forbidden) {
			t.Fatalf("forbidden dependency %s", forbidden)
		}
	}
}
func projectionJSON(t *testing.T, value Projection) string {
	t.Helper()
	b, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
