package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"openduck/internal/dshbridge"
	"openduck/internal/mesh"
	"openduck/internal/meshui"
	"openduck/internal/providerbridge"
	"openduck/internal/providerrevision"
)

// meshApplicationFixture exercises the real Controller composition seam: an
// encrypted provider-revision repository, a verified and enabled registry, a
// durable endpoint binding, and the authenticated DSH principal. Its provider
// session adapter is intentionally in-memory and contains opaque references
// only; it never launches a runtime or contacts a provider.
type meshApplicationFixture struct {
	app       *meshApplication
	repo      *providerrevision.Repository
	service   *providerrevision.Service
	binding   mesh.MeshEndpointBinding
	principal dshbridge.UIPrincipal
	profile   providerbridge.Profile
	sessions  *meshApplicationSessions
	clock     *time.Time
}

func newMeshApplicationFixture(t *testing.T) *meshApplicationFixture {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	clock := now
	profile, bundle, trust := meshApplicationBundle(t, now)

	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	repo, err := providerrevision.NewRepository(filepath.Join(t.TempDir(), "provider-revisions.enc"), key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = repo.Close() })
	service, err := providerrevision.NewService(repo, meshApplicationRevisionAuthority{}, providerrevision.TrustSourceFunc(func(_ context.Context, digest string) (providerbridge.Ed25519TrustBundle, error) {
		if digest != bundle.TrustBundleDigest {
			return providerbridge.Ed25519TrustBundle{}, providerrevision.ErrUnavailable
		}
		return trust, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = service.Install(ctx, bundle, "install-mesh-ui", "approval-mesh-ui", 0); err != nil {
		t.Fatalf("install verified fixture: %v", err)
	}
	// The fixture models the result of a separately signed activate operation.
	// Legacy candidate installation is intentionally unable to select current.
	if err = activateMeshApplicationFixtureRevision(ctx, repo, bundle.RevisionID); err != nil {
		t.Fatalf("activate verified fixture: %v", err)
	}
	if err = service.SetEnabled(ctx, bundle.RevisionID, profile.ID, true, "enable-mesh-ui", "approval-mesh-ui", 2); err != nil {
		t.Fatalf("enable verified fixture: %v", err)
	}
	registry, installed, err := service.Registry(ctx)
	if err != nil {
		t.Fatalf("registry: %v", err)
	}
	if installed.Bundle.RevisionID != bundle.RevisionID {
		t.Fatalf("installed revision=%q", installed.Bundle.RevisionID)
	}
	directory, err := newProviderMeshDirectory(registry, meshApplicationLimits(8))
	if err != nil {
		t.Fatal(err)
	}
	directory.now = func() time.Time { return now }
	resolved, err := directory.Lookup(ctx, profile.ID)
	if err != nil || !resolved.Eligible() {
		t.Fatalf("fixture profile is not eligible: profile=%+v err=%v", resolved, err)
	}
	sessions := &meshApplicationSessions{runs: map[string]meshApplicationRun{}}
	ids := &meshApplicationIDs{}
	coordinator, err := mesh.NewCoordinator(mesh.CoordinatorOptions{
		Repository:    mesh.NewMemoryRepository(),
		Directory:     directory,
		Starter:       sessions,
		Sessions:      sessions,
		Endpoints:     mesh.NewEndpointAuthorizer(),
		Clock:         func() time.Time { return clock },
		ID:            ids.next,
		PolicyVersion: "mesh-ui-integration.v1",
		BatchCaps:     meshApplicationLimits(8),
	})
	if err != nil {
		t.Fatal(err)
	}
	binding, err := coordinator.RegisterRoot(ctx, "root-1", "mesh-session-1", "attempt-1", "peer-1", "L1", "workspace-1")
	if err != nil {
		t.Fatal(err)
	}
	binding, err = coordinator.MintUIEndpoint(ctx, binding)
	if err != nil {
		t.Fatal(err)
	}
	principal := dshbridge.UIPrincipal{SessionID: "AAAAAAAAAAAAAAAAAAAAAA", ChannelID: "BBBBBBBBBBBBBBBBBBBBBB"}
	fixture := &meshApplicationFixture{app: &meshApplication{coordinator: coordinator, revisions: service}, repo: repo, service: service, binding: binding, principal: principal, profile: profile, sessions: sessions, clock: &clock}
	fixture.replaceAssociation(t, providerrevision.UIAssociation{
		SessionID:          principal.SessionID,
		ChannelID:          principal.ChannelID,
		RootRunID:          binding.RootRunID,
		RunID:              binding.RunID,
		MeshSessionID:      binding.SessionID,
		AttemptID:          binding.AttemptID,
		PeerID:             binding.PeerID,
		EndpointID:         binding.EndpointID,
		EndpointGeneration: binding.Generation,
		RevisionID:         bundle.RevisionID,
		ExpiresAt:          binding.ExpiresAt,
	})
	return fixture
}

func activateMeshApplicationFixtureRevision(ctx context.Context, repo *providerrevision.Repository, revision string) error {
	old, err := repo.Load(ctx)
	if err != nil {
		return err
	}
	if _, ok := old.Revisions[revision]; !ok || old.CurrentID != "" {
		return providerrevision.ErrInvalid
	}
	next := meshApplicationCloneRevisionSnapshot(old)
	next.CurrentID = revision
	return repo.CompareAndSwap(ctx, old, next)
}

type meshApplicationRevisionAuthority struct{}

func (meshApplicationRevisionAuthority) Authorize(context.Context, providerrevision.Operation) error {
	return nil
}

type meshApplicationIDs struct{ nextID uint64 }

func (s *meshApplicationIDs) next() string {
	s.nextID++
	return fmt.Sprintf("mesh-ui-%03d", s.nextID)
}

type meshApplicationRun struct{ runID, attemptID string }

type meshApplicationSessions struct {
	mu sync.Mutex

	runs          map[string]meshApplicationRun
	inputRefs     []string
	cancellations []mesh.Cancellation
	revisionRefs  []string
	invalidResult bool
}

func (s *meshApplicationSessions) Start(_ context.Context, request mesh.StartRequest) (mesh.SessionRef, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	providerID := "provider-" + request.Order.RunID
	s.runs[providerID] = meshApplicationRun{runID: request.Order.RunID, attemptID: request.Order.AttemptID}
	return mesh.SessionRef{ProviderSessionID: providerID}, nil
}
func (s *meshApplicationSessions) Send(_ context.Context, _ mesh.SessionRef, inputRef string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.inputRefs = append(s.inputRefs, "send:"+inputRef)
	return nil
}
func (s *meshApplicationSessions) Steer(_ context.Context, _ mesh.SessionRef, inputRef string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.inputRefs = append(s.inputRefs, "steer:"+inputRef)
	return nil
}
func (s *meshApplicationSessions) Cancel(_ context.Context, _ mesh.SessionRef, cancellation mesh.Cancellation) error {
	if cancellation.Validate() != nil {
		return mesh.ErrDenied
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cancellations = append(s.cancellations, cancellation)
	return nil
}
func (s *meshApplicationSessions) Status(context.Context, mesh.SessionRef) (mesh.SessionStatus, error) {
	return mesh.SessionStatus{State: "running", UsageSource: "attested"}, nil
}
func (s *meshApplicationSessions) Wait(context.Context, mesh.SessionRef, time.Time) (mesh.SessionStatus, error) {
	return mesh.SessionStatus{State: "completed", UsageSource: "provider"}, nil
}
func (s *meshApplicationSessions) Result(_ context.Context, ref mesh.SessionRef, revisionRef string) (mesh.ResultEnvelope, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	run, found := s.runs[ref.ProviderSessionID]
	if !found {
		return mesh.ResultEnvelope{}, errors.New("unknown fixture provider session")
	}
	s.revisionRefs = append(s.revisionRefs, revisionRef)
	status := "completed"
	if s.invalidResult {
		status = "not-a-session-state"
	}
	return mesh.ResultEnvelope{RunID: run.runID, AttemptID: run.attemptID, Status: status, OutputArtifactRef: "artifact-" + run.runID, SchemaRef: "result-schema-v1", ProvenanceDigest: providerbridge.DigestBytes([]byte("provenance:" + run.runID)), Classification: "L1"}, nil
}

func (f *meshApplicationFixture) context() context.Context {
	return dshbridge.WithUIPrincipal(context.Background(), f.principal)
}

func (f *meshApplicationFixture) association(t *testing.T) providerrevision.UIAssociation {
	t.Helper()
	snapshot, err := f.repo.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	a, ok := snapshot.Associations[f.principal.SessionID+":"+f.principal.ChannelID]
	if !ok {
		t.Fatal("fixture association missing")
	}
	return a
}

func (f *meshApplicationFixture) replaceAssociation(t *testing.T, association providerrevision.UIAssociation) {
	t.Helper()
	old, err := f.repo.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	next := meshApplicationCloneRevisionSnapshot(old)
	next.Associations[association.SessionID+":"+association.ChannelID] = association
	if err = f.repo.CompareAndSwap(context.Background(), old, next); err != nil {
		t.Fatal(err)
	}
}

func (f *meshApplicationFixture) mutateAssociation(t *testing.T, mutate func(*providerrevision.UIAssociation)) {
	t.Helper()
	a := f.association(t)
	mutate(&a)
	f.replaceAssociation(t, a)
}

func (f *meshApplicationFixture) removeAssociation(t *testing.T) {
	t.Helper()
	old, err := f.repo.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	next := meshApplicationCloneRevisionSnapshot(old)
	delete(next.Associations, f.principal.SessionID+":"+f.principal.ChannelID)
	if err = f.repo.CompareAndSwap(context.Background(), old, next); err != nil {
		t.Fatal(err)
	}
}

func meshApplicationCloneRevisionSnapshot(in providerrevision.Snapshot) providerrevision.Snapshot {
	out := in
	out.Revisions = make(map[string]providerrevision.Installed, len(in.Revisions))
	for key, value := range in.Revisions {
		value.Enabled = cloneBoolMap(value.Enabled)
		out.Revisions[key] = value
	}
	out.Receipts = make(map[string]providerrevision.Receipt, len(in.Receipts))
	for key, value := range in.Receipts {
		out.Receipts[key] = value
	}
	out.Associations = make(map[string]providerrevision.UIAssociation, len(in.Associations))
	for key, value := range in.Associations {
		out.Associations[key] = value
	}
	out.Registrations = make(map[string]providerrevision.UIRegistration, len(in.Registrations))
	for key, value := range in.Registrations {
		out.Registrations[key] = value
	}
	return out
}

func cloneBoolMap(in map[string]bool) map[string]bool {
	out := make(map[string]bool, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}

func meshApplicationBundle(t *testing.T, now time.Time) (providerbridge.Profile, providerrevision.Bundle, providerbridge.Ed25519TrustBundle) {
	t.Helper()
	profile := providerbridge.DeclaredProfiles()[3] // qwen.local-pd: verified local fixture route.
	profile.MeshSpawnEnabled = true
	// The fixture carries pinned compatibility/evidence and models an already
	// approved candidate.  The declared catalog itself remains disabled; do not
	// rely on Registry to invent the signed readiness transition here.
	profile.Status = providerbridge.StatusCompatible
	limits := providerbridge.ExecutionLimits{SchemaVersion: providerbridge.ExecutionLimitsV1, MaxDepth: 8, MaxChildrenPerParent: 8, MaxConcurrentRuns: 8, MaxInputTokens: 8, MaxOutputTokens: 8, MaxWallMS: 8_000, MaxAttempts: 8, MaxResultBytes: 8_192, Cost: providerbridge.CostLimit{Kind: "non_monetary", Unit: "token", MaxQuantity: 8}}
	limitsDigest, err := limits.Digest()
	if err != nil {
		t.Fatal(err)
	}
	profile.ExecutionLimitsDigest = limitsDigest
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
		t.Fatal("fixture profile mapping absent")
	}
	compatibility, err := providerbridge.GenerateCompatibilityRecord(providerbridge.CompatibilityRecord{
		SchemaVersion:    providerbridge.CompatibilityRecordV1,
		Maturity:         providerbridge.CompatibilityPinned,
		Provider:         profile.Provider,
		ProfileID:        profile.ID,
		ProfileRevision:  profile.Revision,
		Model:            profile.Model,
		AuthModality:     profile.AuthModality,
		RuntimeVersion:   "qwen-local@0.9.0",
		ProtocolVersion:  "local-mcp.v1",
		Operations:       operations,
		Handshake:        "success",
		Start:            "success",
		Stream:           "success",
		Cancel:           "cancelled",
		Teardown:         "quiescent",
		Health:           "success",
		GeneratorVersion: "offline-fixture.v1",
		GeneratedAt:      now.Add(-time.Minute),
		SourceReferences: []providerbridge.CompatibilitySource{{Reference: "https://evidence.example/mesh-ui", Digest: providerbridge.DigestBytes([]byte("compatibility-source"))}},
	}, []byte("runtime-artifact"), []byte("protocol-schema"), []byte("mesh-tools"), []byte("sanitized-transcript"))
	if err != nil {
		t.Fatalf("pinned compatibility: %v", err)
	}
	mapping, err := providerbridge.MappingFromCompatibility(compatibility)
	if err != nil {
		t.Fatal(err)
	}
	profile.MappingDigest = mapping.Digest

	technicalPublic, technicalPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	securityPublic, securityPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	trust := providerbridge.Ed25519TrustBundle{SchemaVersion: providerbridge.Ed25519TrustBundleV1, PublicKeys: map[string]string{"security-key": hex.EncodeToString(securityPublic), "technical-key": hex.EncodeToString(technicalPublic)}, TrustedTechnical: []string{"technical-key"}, TrustedSecurity: []string{"security-key"}, Revoked: []string{}}
	trustRaw, err := json.Marshal(trust)
	if err != nil {
		t.Fatal(err)
	}
	evidence := providerbridge.ProviderEvidenceRecord{
		SchemaVersion:             providerbridge.EvidenceRecordV1,
		Provider:                  profile.Provider,
		ProfileID:                 profile.ID,
		ProfileRevision:           profile.Revision,
		AuthModality:              profile.AuthModality,
		OfficialURLs:              []string{"https://official.example/qwen"},
		RetrievedAt:               now.Add(-time.Minute),
		FreshUntil:                now.Add(time.Hour),
		RuntimeVersion:            compatibility.RuntimeVersion,
		ProtocolVersion:           compatibility.ProtocolVersion,
		Model:                     profile.Model,
		ClaimModalities:           map[string]string{"official-provider-route": profile.AuthModality},
		SourceContentDigest:       providerbridge.DigestBytes([]byte("evidence-source")),
		RuntimeArtifactDigest:     compatibility.RuntimeArtifactDigest,
		SchemaDigest:              compatibility.ProtocolSchemaDigest,
		CompatibilityRecordDigest: compatibility.Digest,
		ProtocolSchemaDigest:      compatibility.ProtocolSchemaDigest,
		MeshToolSchemaDigest:      compatibility.MeshToolSchemaDigest,
		EvidenceGeneratorVersion:  "offline-fixture.v1",
	}
	if err = evidence.Seal(); err != nil {
		t.Fatal(err)
	}
	evidence.Approvals = []providerbridge.EvidenceApproval{
		{SchemaVersion: "provider-evidence-approval.v1", Role: "technical", ReviewerKeyID: "technical-key", ProfileID: profile.ID, ProfileRevision: profile.Revision, EvidenceDigest: evidence.Digest, FreshUntil: evidence.FreshUntil, DecisionRef: "decision-tech", Signature: hex.EncodeToString(ed25519.Sign(technicalPrivate, []byte(evidence.Digest)))},
		{SchemaVersion: "provider-evidence-approval.v1", Role: "security", ReviewerKeyID: "security-key", ProfileID: profile.ID, ProfileRevision: profile.Revision, EvidenceDigest: evidence.Digest, FreshUntil: evidence.FreshUntil, DecisionRef: "decision-security", Signature: hex.EncodeToString(ed25519.Sign(securityPrivate, []byte(evidence.Digest)))},
	}
	profile.ProviderEvidenceDigest = evidence.Digest
	bundle := providerrevision.Bundle{SchemaVersion: providerrevision.BundleV1, BundleID: "bundle-mesh-ui", RevisionID: "revision-mesh-ui", TrustBundleDigest: providerbridge.DigestBytes(trustRaw), Profiles: []providerrevision.ProfileBundle{{
		Profile: providerrevision.ProfileDTO{ID: profile.ID, Provider: profile.Provider, Model: profile.Model, RuntimeKind: profile.RuntimeKind, AuthModality: profile.AuthModality, AccountRef: profile.AccountRef, LocalOnly: profile.LocalOnly, MeshSpawnEnabled: profile.MeshSpawnEnabled, ExecutionLimitsDigest: profile.ExecutionLimitsDigest, MappingDigest: profile.MappingDigest, ProviderEvidenceDigest: profile.ProviderEvidenceDigest, Revision: profile.Revision, Status: profile.Status},
		Limits:  limits, Mapping: mapping, Compatibility: compatibility, Evidence: evidence, ActivationIntent: true,
	}}}
	if err = bundle.Seal(); err != nil {
		t.Fatal(err)
	}
	return profile, bundle, trust
}

func meshApplicationLimits(max uint64) mesh.ExecutionLimits {
	return mesh.ExecutionLimits{SchemaVersion: mesh.ExecutionLimitsV1, MaxDepth: max, MaxChildrenPerParent: max, MaxConcurrentRuns: max, MaxInputTokens: max, MaxOutputTokens: max, MaxWallMS: max * 1_000, MaxAttempts: max, MaxResultBytes: max * 1_024, Cost: mesh.CostLimit{Kind: "non_monetary", Unit: "token", MaxQuantity: max}}
}

func meshApplicationProposal(nonce string) mesh.SpawnProposal {
	// The root itself consumes one active-run slot, and this fixture exercises a
	// single spawn followed by a two-member batch. Four is the smallest honest
	// request limit that admits those three children without relaxing policy.
	return mesh.SpawnProposal{SchemaVersion: mesh.SpawnProposalV1, ClientNonce: nonce, Objective: "bounded-fixture-objective", InputArtifactRefs: []string{}, PreferredProfile: providerbridge.ProfileQwenLocalPD, RequestedRole: "worker", OutputSchemaRef: "result-schema-v1", RequestedLimits: meshApplicationLimits(4), RequestedTools: []string{}}
}

type meshApplicationOperationInput struct {
	RunID       string `json:"run_id"`
	RootID      string `json:"root_id"`
	InputRef    string `json:"input_ref"`
	RevisionRef string `json:"revision_ref"`
	ReasonRef   string `json:"reason_ref"`
}

func invokeMeshApplication(t *testing.T, f *meshApplicationFixture, kind string, payload any) meshui.MeshUIResponse {
	t.Helper()
	response, err := f.app.InvokeMeshUI(f.context(), kind, payload)
	if err != nil {
		t.Fatalf("%s: %v", kind, err)
	}
	if err = response.Validate(kind); err != nil {
		t.Fatalf("%s response invalid: %v (%+v)", kind, err, response)
	}
	return response
}

func TestMeshApplicationDispatchesAllOperationsThroughVerifiedComposition(t *testing.T) {
	f := newMeshApplicationFixture(t)

	profiles := invokeMeshApplication(t, f, "mesh-listProfiles", struct{}{})
	if len(profiles.ListProfiles.Profiles) != 1 || profiles.ListProfiles.Profiles[0].ProfileID != f.profile.ID || !profiles.ListProfiles.Profiles[0].MeshSpawn || profiles.ListProfiles.Profiles[0].Status != string(providerbridge.StatusCompatible) {
		t.Fatalf("truthful profiles=%+v", profiles.ListProfiles)
	}

	spawn := invokeMeshApplication(t, f, "mesh-spawn", meshApplicationProposal("spawn-one"))
	childID := spawn.Spawn.Proposal.RunID
	if childID == "" || spawn.Spawn.Proposal.Replayed {
		t.Fatalf("spawn=%+v", spawn.Spawn)
	}

	batch := invokeMeshApplication(t, f, "mesh-spawnBatch", []mesh.SpawnProposal{meshApplicationProposal("batch-one"), meshApplicationProposal("batch-two")})
	if batch.SpawnBatch.Partial || len(batch.SpawnBatch.Results) != 2 {
		t.Fatalf("batch=%+v", batch.SpawnBatch)
	}
	waitChildID := batch.SpawnBatch.Results[0].RunID
	collectChildID := batch.SpawnBatch.Results[1].RunID
	if waitChildID == "" || collectChildID == "" || waitChildID == childID || collectChildID == childID || waitChildID == collectChildID {
		t.Fatalf("batch did not produce distinct children for terminal observations: %+v", batch.SpawnBatch)
	}

	send := invokeMeshApplication(t, f, "mesh-send", meshApplicationOperationInput{RunID: childID, InputRef: "input-ref-1"})
	if send.Send.Acknowledgement.Status != "sent" || send.Send.Acknowledgement.InputRef != "input-ref-1" {
		t.Fatalf("send acknowledgement=%+v", send.Send)
	}
	steer := invokeMeshApplication(t, f, "mesh-steer", meshApplicationOperationInput{RunID: childID, InputRef: "input-ref-2"})
	if steer.Steer.Acknowledgement.Status != "sent" || steer.Steer.Acknowledgement.InputRef != "input-ref-2" {
		t.Fatalf("steer acknowledgement=%+v", steer.Steer)
	}
	// A terminal wait revokes the target child endpoint by design. Use a
	// distinct batch child so the remainder of this integration test exercises
	// live operations without weakening the terminal mesh semantics.
	wait := invokeMeshApplication(t, f, "mesh-wait", meshApplicationOperationInput{RunID: waitChildID, RevisionRef: "revision-ref-1"})
	if wait.Wait.State != "completed" || wait.Wait.UsageSource != "provider" {
		t.Fatalf("wait=%+v", wait.Wait)
	}
	collect := invokeMeshApplication(t, f, "mesh-collect", meshApplicationOperationInput{RunID: collectChildID, RevisionRef: "revision-ref-2"})
	if collect.Collect.RunID != collectChildID || collect.Collect.OutputArtifactRef == "" || collect.Collect.SchemaRef == "" || collect.Collect.ProvenanceDigest == "" {
		t.Fatalf("collect fabricated/missing result=%+v", collect.Collect)
	}
	status := invokeMeshApplication(t, f, "mesh-status", meshApplicationOperationInput{RunID: childID, RevisionRef: "revision-ref-3"})
	if status.Status.State != "running" || status.Status.UsageSource != "attested" {
		t.Fatalf("status=%+v", status.Status)
	}
	// The two terminal observations above free their exact child capability.
	// Admit a fresh child for Result rather than treating a terminal child as
	// controllable; this keeps the production terminal invariant exercised.
	resultSpawn := invokeMeshApplication(t, f, "mesh-spawn", meshApplicationProposal("spawn-result"))
	resultChildID := resultSpawn.Spawn.Proposal.RunID
	if resultChildID == "" || resultChildID == childID || resultChildID == waitChildID || resultChildID == collectChildID {
		t.Fatalf("result spawn did not produce a fresh child: %+v", resultSpawn.Spawn)
	}
	result := invokeMeshApplication(t, f, "mesh-result", meshApplicationOperationInput{RunID: resultChildID, RevisionRef: "revision-ref-4"})
	if result.Result.RunID != resultChildID || result.Result.OutputArtifactRef == "" || result.Result.ProvenanceDigest == "" {
		t.Fatalf("result=%+v", result.Result)
	}
	listed := invokeMeshApplication(t, f, "mesh-list", meshApplicationOperationInput{RootID: f.binding.RootRunID, RevisionRef: "revision-ref-5"})
	if len(listed.List.Runs) != 4 {
		t.Fatalf("list=%+v", listed.List)
	}
	for _, item := range listed.List.Runs {
		if item.ProfileID == "" || item.Provider == "" || item.RunID == f.binding.RootRunID {
			t.Fatalf("list fabricated root/provider entry: %+v", item)
		}
	}
	cancel := invokeMeshApplication(t, f, "mesh-cancel", meshApplicationOperationInput{RunID: childID, RevisionRef: "revision-ref-6", ReasonRef: "reason-ref-1"})
	if cancel.Cancel.Acknowledgement.Status != "cancelled" || cancel.Cancel.Acknowledgement.ReasonRef != "reason-ref-1" || cancel.Cancel.Acknowledgement.RevisionRef != "revision-ref-6" {
		t.Fatalf("cancel acknowledgement=%+v", cancel.Cancel)
	}

	f.sessions.mu.Lock()
	defer f.sessions.mu.Unlock()
	if got, want := f.sessions.inputRefs, []string{"send:input-ref-1", "steer:input-ref-2"}; fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("input refs=%v want=%v", got, want)
	}
	if got, want := f.sessions.cancellations, []mesh.Cancellation{{Mode: mesh.CancellationUser, RevisionRef: "revision-ref-6", ReasonRef: "reason-ref-1"}}; fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("cancellations=%v want=%v", got, want)
	}
	if got, want := f.sessions.revisionRefs, []string{"revision-ref-2", "revision-ref-4"}; fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("result revision refs=%v want=%v", got, want)
	}
}

func TestMeshApplicationUIUXOperationsAreBoundAndTruthful(t *testing.T) {
	f := newMeshApplicationFixture(t)
	selection := invokeMeshApplication(t, f, "selection-revision", struct {
		ProfileID      string `json:"profile_id"`
		Operation      string `json:"operation"`
		BaseRevisionID string `json:"base_revision_id"`
	}{ProfileID: f.profile.ID, Operation: "new-root", BaseRevisionID: "revision-mesh-ui"})
	if selection.Selection.ActiveTurnChanged || selection.Selection.RevisionID == "" {
		t.Fatalf("selection lied about turn state: %+v", selection.Selection)
	}
	snapshot, err := f.repo.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.CurrentID != "revision-mesh-ui" || len(snapshot.UX.Selections) != 1 {
		t.Fatalf("selection mutated active revision or was not durable: current=%q selections=%+v", snapshot.CurrentID, snapshot.UX.Selections)
	}

	spawn := invokeMeshApplication(t, f, "mesh-spawn", meshApplicationProposal("ux-graph-child"))
	childID := spawn.Spawn.Proposal.RunID
	graph := invokeMeshApplication(t, f, "ui-session-graph", struct {
		RootID string `json:"root_id"`
	}{RootID: f.binding.RootRunID})
	if len(graph.Graph.Graph.Nodes) != 1 || graph.Graph.Graph.Nodes[0].ID != childID || len(graph.Graph.Graph.Edges) != 0 {
		t.Fatalf("graph is not the exact redacted run journal: %+v", graph.Graph.Graph)
	}
	comparison := invokeMeshApplication(t, f, "run-compare", struct {
		RunIDs []string `json:"run_ids"`
	}{RunIDs: []string{childID}})
	if len(comparison.Compare.Compare.Runs) != 1 || comparison.Compare.Compare.Runs[0].ResultAvailable || comparison.Compare.Compare.Runs[0].ResultRef != nil {
		t.Fatalf("comparison fabricated a result reference: %+v", comparison.Compare)
	}
	templates := invokeMeshApplication(t, f, "run-templates", struct {
		TemplateID string `json:"template_id"`
		Version    string `json:"version"`
	}{TemplateID: "template-1", Version: "v1"})
	if len(templates.Templates.Templates.Approved) != 0 {
		t.Fatalf("templates fabricated an approval: %+v", templates.Templates)
	}
	policy := invokeMeshApplication(t, f, "policy-approval-inspector", struct {
		DecisionType string `json:"decision_type"`
	}{DecisionType: "provider-switch"})
	if len(policy.Policy.Policy.Approvals) != 0 {
		t.Fatalf("policy fabricated an approval: %+v", policy.Policy)
	}
	for _, unavailable := range []struct {
		kind    string
		payload any
	}{
		{"run-synthesis", struct {
			TemplateID       string   `json:"template_id"`
			SourceResultRefs []string `json:"source_result_refs"`
		}{TemplateID: "template-1", SourceResultRefs: []string{"result-1"}}},
		{"deployment-diagnostics", struct {
			Action string `json:"action"`
		}{Action: "status"}},
		{"plugin-lifecycle", struct {
			Action string `json:"action"`
		}{Action: "install"}},
	} {
		if _, err := f.app.InvokeMeshUI(f.context(), unavailable.kind, unavailable.payload); !errors.Is(err, meshui.ErrUnavailable) {
			t.Fatalf("%s claimed evidence or a lifecycle receipt without one: %v", unavailable.kind, err)
		}
	}
}

func TestCandidateOnlyRevisionComposesAsDisabledUnavailable(t *testing.T) {
	f := newMeshApplicationFixture(t)
	ctx := context.Background()
	old, err := f.repo.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	next := meshApplicationCloneRevisionSnapshot(old)
	next.CurrentID = ""
	if err = f.repo.CompareAndSwap(ctx, old, next); err != nil {
		t.Fatal(err)
	}
	registry, installed, err := activeProviderRegistry(ctx, f.service)
	if err != nil {
		t.Fatalf("candidate composition err=%v", err)
	}
	if registry == nil || len(registry.Profiles(ctx)) != 0 || installed.Bundle.RevisionID != "" {
		t.Fatalf("candidate composed as active registry=%v profiles=%d installed=%+v", registry != nil, len(registry.Profiles(ctx)), installed)
	}
	if _, err = f.service.Active(ctx); !errors.Is(err, providerrevision.ErrUnavailable) {
		t.Fatalf("candidate service active err=%v", err)
	}
	if _, err = f.app.MeshUIProjection(ctx); !errors.Is(err, providerrevision.ErrUnavailable) {
		t.Fatalf("candidate projection err=%v", err)
	}
	projection := meshui.NewProjectionServiceWithSource(nil, f.app).Projection(ctx)
	if projection.RevisionID != "mesh-disabled" || len(projection.Lifecycle.Packages) != 0 || len(projection.Profiles) != len(providerbridge.DeclaredProfiles()) {
		t.Fatalf("candidate UI projection=%+v", projection)
	}
	for _, profile := range projection.Profiles {
		if profile.Status != string(providerbridge.StatusDisabled) || profile.MeshSpawn {
			t.Fatalf("candidate projected a non-disabled profile: %+v", profile)
		}
	}
}

func TestMeshApplicationProjectionUsesVerifiedRegistryDirectory(t *testing.T) {
	f := newMeshApplicationFixture(t)
	projection := meshui.NewProjectionServiceWithSource(nil, f.app).Projection(context.Background())
	if projection.RevisionID != "revision-mesh-ui" || len(projection.Profiles) != len(providerbridge.DeclaredProfiles()) {
		t.Fatalf("projection=%+v", projection)
	}
	if len(projection.Lifecycle.Packages) != 1 || projection.Lifecycle.Packages[0].Status != "enabled" {
		t.Fatalf("lifecycle=%+v", projection.Lifecycle)
	}
	seenEligible := false
	for _, profile := range projection.Profiles {
		if profile.ProfileID == f.profile.ID {
			if profile.Status != string(providerbridge.StatusCompatible) || !profile.MeshSpawn {
				t.Fatalf("verified profile projection=%+v", profile)
			}
			seenEligible = true
			continue
		}
		if profile.Status != string(providerbridge.StatusDisabled) || profile.MeshSpawn {
			t.Fatalf("uninstalled profile was promoted: %+v", profile)
		}
	}
	if !seenEligible {
		t.Fatal("verified active profile missing from projection")
	}
}

func TestMeshApplicationFailsClosedForPrincipalAssociationAndBindingMismatches(t *testing.T) {
	f := newMeshApplicationFixture(t)
	assertUnavailable := func(t *testing.T, ctx context.Context) {
		t.Helper()
		if _, err := f.app.InvokeMeshUI(ctx, "mesh-listProfiles", struct{}{}); !errors.Is(err, meshui.ErrUnavailable) {
			t.Fatalf("err=%v", err)
		}
	}
	assertUnavailable(t, context.Background())
	assertUnavailable(t, dshbridge.WithUIPrincipal(context.Background(), dshbridge.UIPrincipal{SessionID: "CCCCCCCCCCCCCCCCCCCCCC", ChannelID: f.principal.ChannelID}))

	baseline := f.association(t)
	cases := []struct {
		name   string
		mutate func(*meshApplicationFixture, *testing.T)
	}{
		{"stale association", func(f *meshApplicationFixture, t *testing.T) {
			f.mutateAssociation(t, func(a *providerrevision.UIAssociation) { a.ExpiresAt = time.Unix(1, 0).UTC() })
		}},
		// Provider revision revocation removes the association from the active
		// set; a revoked UI principal must therefore have the same unavailable
		// result as a never-bound principal.
		{"revoked association", func(f *meshApplicationFixture, t *testing.T) { f.removeAssociation(t) }},
		{"root mismatch", func(f *meshApplicationFixture, t *testing.T) {
			f.mutateAssociation(t, func(a *providerrevision.UIAssociation) { a.RootRunID = "other-root" })
		}},
		{"run mismatch", func(f *meshApplicationFixture, t *testing.T) {
			f.mutateAssociation(t, func(a *providerrevision.UIAssociation) { a.RunID = "other-run" })
		}},
		{"session mismatch", func(f *meshApplicationFixture, t *testing.T) {
			f.mutateAssociation(t, func(a *providerrevision.UIAssociation) { a.MeshSessionID = "other-session" })
		}},
		{"attempt mismatch", func(f *meshApplicationFixture, t *testing.T) {
			f.mutateAssociation(t, func(a *providerrevision.UIAssociation) { a.AttemptID = "other-attempt" })
		}},
		{"peer mismatch", func(f *meshApplicationFixture, t *testing.T) {
			f.mutateAssociation(t, func(a *providerrevision.UIAssociation) { a.PeerID = "other-peer" })
		}},
		{"endpoint mismatch", func(f *meshApplicationFixture, t *testing.T) {
			f.mutateAssociation(t, func(a *providerrevision.UIAssociation) { a.EndpointID = "other-endpoint" })
		}},
		{"generation mismatch", func(f *meshApplicationFixture, t *testing.T) {
			f.mutateAssociation(t, func(a *providerrevision.UIAssociation) { a.EndpointGeneration++ })
		}},
		{"expiry mismatch", func(f *meshApplicationFixture, t *testing.T) {
			f.mutateAssociation(t, func(a *providerrevision.UIAssociation) { a.ExpiresAt = a.ExpiresAt.Add(time.Minute) })
		}},
		{"cross revision", func(f *meshApplicationFixture, t *testing.T) {
			f.mutateAssociation(t, func(a *providerrevision.UIAssociation) { a.RevisionID = "other-revision" })
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f.replaceAssociation(t, baseline)
			tc.mutate(f, t)
			assertUnavailable(t, f.context())
		})
	}
}

func TestMeshApplicationLifecycleUsesExactExpiredHistoricalRootBinding(t *testing.T) {
	f := newMeshApplicationFixture(t)
	ctx := context.Background()
	association := f.association(t)
	if association.RunID != association.RootRunID {
		t.Fatal("fixture must bind a root endpoint")
	}
	// LifecycleRootBinding is intentionally broader than normal UI endpoint
	// lookup: this predecessor has expired and is revoked, but an owner-only
	// rotate/close must still converge an interrupted transition.
	*f.clock = f.binding.ExpiresAt.Add(time.Second)
	if err := f.app.coordinator.RevokeEndpoint(ctx, f.binding.EndpointID, f.binding.Generation); err != nil {
		t.Fatalf("revoke historical root binding: %v", err)
	}
	historical, err := f.app.coordinator.LifecycleRootBinding(ctx, f.binding.EndpointID, f.binding.Generation)
	if err != nil || historical.EndpointID != f.binding.EndpointID || historical.Generation != f.binding.Generation {
		t.Fatalf("expired/revoked historical binding unavailable: binding=%+v err=%v", historical, err)
	}
	target := providerrevision.UIRotateTarget{Association: association}
	bad := target
	bad.Association.EndpointGeneration++
	if _, err := f.app.rotateUIEndpoint(ctx, bad); err == nil {
		t.Fatal("rotation accepted a mismatched historical generation")
	}
	rotated, err := f.app.rotateUIEndpoint(ctx, target)
	if err != nil {
		t.Fatalf("rotate expired/revoked predecessor: %v association=%+v historical=%+v binding=%+v", err, association, historical, f.binding)
	}
	if rotated.EndpointID == association.EndpointID || rotated.Generation != association.EndpointGeneration+1 {
		t.Fatalf("rotation successor=%+v", rotated)
	}
	retry, err := f.app.rotateUIEndpoint(ctx, target)
	if err != nil || retry != rotated {
		t.Fatalf("rotation retry did not return the durable successor: retry=%+v err=%v", retry, err)
	}
	bad = target
	bad.Association.PeerID = "peer-mismatch"
	if err := f.app.closeRootEndpoint(ctx, bad); err == nil {
		t.Fatal("root close accepted a mismatched historical binding")
	}
	if err := f.app.closeRootEndpoint(ctx, target); err != nil {
		t.Fatalf("close exact expired/revoked predecessor: %v", err)
	}
	if _, err := f.app.coordinator.EndpointBinding(ctx, rotated.EndpointID); !errors.Is(err, mesh.ErrUnauthorized) {
		t.Fatalf("historical close left rotated successor usable: %v", err)
	}
}

func TestMeshApplicationInvalidProviderOutputIsRejectedAtUIBoundary(t *testing.T) {
	f := newMeshApplicationFixture(t)
	spawn := invokeMeshApplication(t, f, "mesh-spawn", meshApplicationProposal("invalid-result-spawn"))
	f.sessions.mu.Lock()
	f.sessions.invalidResult = true
	f.sessions.mu.Unlock()
	body := []byte(`{"run_id":"` + spawn.Spawn.Proposal.RunID + `","revision_ref":"revision-ref-invalid"}`)
	service := meshui.NewProjectionService(f.app)
	if _, err := service.Propose(f.context(), "mesh-result", body); !errors.Is(err, meshui.ErrInvalidOutput) {
		t.Fatalf("invalid response passed UI boundary: %v", err)
	}
}
