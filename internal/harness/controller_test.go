package harness

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

type allowAuth struct{}

func (allowAuth) AuthenticateOwnerDecision(context.Context, InteractionDeliveryBinding, OwnerDecisionEvent) error {
	return nil
}

type allowCallback struct{}

func (allowCallback) VerifyCallback(context.Context, DecisionChallenge, string, string) (string, string, error) {
	return "owner", "proof", nil
}

type blockingCallback struct {
	started chan struct{}
	release chan struct{}
}

func (b blockingCallback) VerifyCallback(ctx context.Context, _ DecisionChallenge, _ string, _ string) (string, string, error) {
	close(b.started)
	select {
	case <-b.release:
		return "owner", "proof", nil
	case <-ctx.Done():
		return "", "", ctx.Err()
	}
}

type uncertainRepository struct{ snapshot ControllerSnapshot }

func (r *uncertainRepository) Load(ctx context.Context) (ControllerSnapshot, error) {
	if err := ctx.Err(); err != nil {
		return ControllerSnapshot{}, err
	}
	return cloneSnapshot(r.snapshot), nil
}
func (r *uncertainRepository) Save(context.Context, ControllerSnapshot) error {
	return ErrCommitUncertain
}
func (r *uncertainRepository) CompareAndSwap(context.Context, ControllerSnapshot, ControllerSnapshot) error {
	return ErrCommitUncertain
}

func must[T any](v T, e error) T {
	if e != nil {
		panic(e)
	}
	return v
}
func seal[T any](t *testing.T, v T) T {
	t.Helper()
	s, ok := any(&v).(interface{ Seal() error })
	if !ok {
		t.Fatal("contract has no Seal method")
	}
	if e := s.Seal(); e != nil {
		t.Fatal(e)
	}
	return v
}
func dg(t *testing.T, v any) string { t.Helper(); return must(SHA256(v)) }
func testSignal(t *testing.T) TaskSignal {
	return seal(t, TaskSignal{SignalID: "sig_1", SourceRef: "psn_1", SourceVersion: 1, ObservedAt: time.Now().UTC(), Kind: "question", Summary: "status request", Urgency: "normal", MaxClass: "L1", Coverage: Coverage{Complete: true}, SuggestedRoute: "root", PolicyVersion: "p1"})
}
func testSpec(t *testing.T, id, status string, n int, parent string) TaskSpec {
	return seal(t, TaskSpec{TaskID: id, SpecVersion: n, Title: "synthetic", Objective: "verify synthetic flow", InScope: []string{"harness"}, OutOfScope: []string{"effects"}, Constraints: []string{"network false"}, AcceptanceChecks: []string{"test"}, EvidenceRequired: []string{"artifact:test"}, RiskClass: "L1", AllowedEffectTypes: []string{}, OwnerDecisions: []string{"synthetic"}, Status: status, ParentSpecHash: parent})
}
func testWork(t *testing.T, id, sh string) WorkOrder {
	return seal(t, WorkOrder{WorkOrderID: "wo_1", TaskID: id, SpecHash: sh, Role: "codex_implementer", Objective: "run test", OwnedResources: []string{"worktree"}, AllowedTools: []string{}, AllowedEffectTypes: []string{}, WorkspaceCapabilityRefs: []string{}, ForbiddenActions: []string{"external_effect"}, AcceptanceChecks: []string{"test"}, EvidenceRequired: []string{"artifact:test"}, Budgets: map[string]int{"tokens": 1}, Lease: Lease{ID: "lease_1", ExpiresAt: time.Now().Add(time.Hour).UTC()}, OutputSchema: "evidence-bundle.v1", RuntimeConstraints: []string{"network=false"}, ProfileManifestDigest: dg(t, "profile"), SandboxPolicyDigest: dg(t, "sandbox"), WorkspaceDescriptor: "synthetic-worktree", WorktreeBaseRef: "main"})
}
func testWorker(t *testing.T, w WorkOrder) WorkerRuntimeAttestation {
	return seal(t, WorkerRuntimeAttestation{WorkerInstanceID: "worker_1", WorkOrderID: w.WorkOrderID, CodexVersion: "test", AgentRole: "codex_implementer", LaunchSurface: "exec", ProcessIdentity: "pid:test", ModelRoute: "synthetic", CleanHomeDigest: dg(t, "home"), GeneratedProfileDigest: dg(t, "profile"), InstructionSources: []SourceDigest{}, ToolInventory: []SourceDigest{}, ApprovalPolicy: "never", SandboxMode: "workspace-write", SandboxPolicyDigest: w.SandboxPolicyDigest, WorkspaceDescriptorDigest: dg(t, w.WorkspaceDescriptor), WorktreeBaseRef: w.WorktreeBaseRef, WritableResources: []string{"worktree"}, ReadableResources: []string{"worktree"}, NetworkPolicy: "false", CreatedAt: time.Now().UTC()})
}
func testBinding(t *testing.T, id string, w WorkOrder, a WorkerRuntimeAttestation) WorkerDispatchBinding {
	return seal(t, WorkerDispatchBinding{DispatchBindingID: "db_1", WorkOrderID: w.WorkOrderID, TaskID: id, SpecHash: w.SpecHash, WorkerInstanceID: a.WorkerInstanceID, WorkerRuntimeAttestationDigest: a.AttestationDigest, ProfileManifestDigest: w.ProfileManifestDigest, WorkspaceDescriptorDigest: dg(t, w.WorkspaceDescriptor), WorktreeBaseRef: w.WorktreeBaseRef, SandboxPolicyDigest: w.SandboxPolicyDigest, LeaseID: w.Lease.ID, BoundAt: time.Now().UTC()})
}
func testEvidence(t *testing.T, id string, w WorkOrder) EvidenceBundle {
	return seal(t, EvidenceBundle{WorkOrderID: w.WorkOrderID, TaskID: id, SpecHash: w.SpecHash, Status: "completed", Claims: []EvidenceClaim{{Claim: "test passed", EvidenceRefs: []string{"artifact:test"}}}, Verification: []Verification{{CheckID: "test", CommandRef: "cmd:test", ExitCode: 0, OutputRef: "artifact:test"}}})
}
func testReview(t *testing.T, id, sh string, e EvidenceBundle) ReviewVerdict {
	return seal(t, ReviewVerdict{ReviewID: "review_1", TaskID: id, SpecHash: sh, EvidenceBundleDigest: e.Digest, ReviewerRole: "terra", Verdict: "pass", ReviewedAt: time.Now().UTC()})
}

func flowToAccepted(t *testing.T, c *Controller, id string) TaskRecord {
	t.Helper()
	s := testSignal(t)
	r := must(c.IngestSignal(context.Background(), id, s))
	draft := testSpec(t, id, "draft", 1, "")
	r = must(c.DraftSpec(context.Background(), id, r.Version, draft))
	frozen := testSpec(t, id, "frozen", 1, draft.SpecHash)
	r = must(c.FreezeSpec(context.Background(), id, r.Version, frozen))
	w := testWork(t, id, frozen.SpecHash)
	a := testWorker(t, w)
	b := testBinding(t, id, w, a)
	r = must(c.Dispatch(context.Background(), id, r.Version, w, a, b))
	r = must(c.StartWork(context.Background(), id, r.Version))
	e := testEvidence(t, id, w)
	r = must(c.submitTrustedEvidence(context.Background(), id, r.Version, e))
	r = must(c.BeginReview(context.Background(), id, r.Version))
	return must(c.SubmitReview(context.Background(), id, r.Version, testReview(t, id, frozen.SpecHash, e)))
}

func TestCanonicalDigestAndStrictDecode(t *testing.T) {
	s := testSignal(t)
	if e := s.Validate(); e != nil {
		t.Fatal(e)
	}
	again := testSignal(t)
	again.ObservedAt = s.ObservedAt
	again.Digest = ""
	if e := again.Seal(); e != nil {
		t.Fatal(e)
	}
	if s.Digest != again.Digest {
		t.Fatal("same contract must hash identically")
	}
	var out TaskSignal
	b := must(json.Marshal(s))
	if e := DecodeStrict(append(b[:len(b)-1], []byte(`,"extra":true}`)...), &out); e == nil {
		t.Fatal("unknown field accepted")
	}
	s.SchemaVersion = "task-signal.v9"
	if !errors.Is(s.Validate(), ErrUnknownVersion) {
		t.Fatal("unknown version accepted")
	}
}
func TestLifecycleNegativesAndHashBindings(t *testing.T) {
	c := must(NewController(context.Background(), &MemoryRepository{}))
	r := must(c.IngestSignal(context.Background(), "task_1", testSignal(t)))
	if _, e := c.StartWork(context.Background(), "task_1", r.Version); !errors.Is(e, ErrTransition) {
		t.Fatalf("got %v", e)
	}
	d := testSpec(t, "task_1", "draft", 1, "")
	r = must(c.DraftSpec(context.Background(), "task_1", r.Version, d))
	bad := testSpec(t, "task_1", "frozen", 1, "sha256:"+"00"+string(make([]byte, 62)))
	if _, e := c.FreezeSpec(context.Background(), "task_1", r.Version, bad); !errors.Is(e, ErrBindingMismatch) {
		t.Fatalf("got %v", e)
	}
	r = must(c.FreezeSpec(context.Background(), "task_1", r.Version, testSpec(t, "task_1", "frozen", 1, d.SpecHash)))
	w := testWork(t, "task_1", r.Spec.SpecHash)
	a := testWorker(t, w)
	b := testBinding(t, "task_1", w, a)
	b.SpecHash = dg(t, "wrong")
	if e := b.Seal(); e != nil {
		t.Fatal(e)
	}
	if _, e := c.Dispatch(context.Background(), "task_1", r.Version, w, a, b); !errors.Is(e, ErrBindingMismatch) {
		t.Fatalf("got %v", e)
	}
	b = testBinding(t, "task_1", w, a)
	r = must(c.Dispatch(context.Background(), "task_1", r.Version, w, a, b))
	r = must(c.StartWork(context.Background(), "task_1", r.Version))
	badEvidence := testEvidence(t, "task_1", w)
	badEvidence.SpecHash = dg(t, "different-spec")
	if e := badEvidence.Seal(); e != nil {
		t.Fatal(e)
	}
	if _, e := c.submitTrustedEvidence(context.Background(), "task_1", r.Version, badEvidence); !errors.Is(e, ErrBindingMismatch) {
		t.Fatalf("mismatched evidence accepted: %v", e)
	}
	evidence := testEvidence(t, "task_1", w)
	r = must(c.submitTrustedEvidence(context.Background(), "task_1", r.Version, evidence))
	r = must(c.BeginReview(context.Background(), "task_1", r.Version))
	badReview := testReview(t, "task_1", w.SpecHash, evidence)
	badReview.EvidenceBundleDigest = dg(t, "different-evidence")
	if e := badReview.Seal(); e != nil {
		t.Fatal(e)
	}
	if _, e := c.SubmitReview(context.Background(), "task_1", r.Version, badReview); !errors.Is(e, ErrBindingMismatch) {
		t.Fatalf("mismatched review accepted: %v", e)
	}
}
func TestEncryptedRecoveryCorruptionAndCancellation(t *testing.T) {
	d := t.TempDir()
	p := filepath.Join(d, "controller.enc")
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	repo := must(NewEncryptedFileRepository(p, key))
	c := must(NewController(context.Background(), repo))
	r := must(c.IngestSignal(context.Background(), "task_1", testSignal(t)))
	c2 := must(NewController(context.Background(), repo))
	got := must(c2.Task(context.Background(), "task_1"))
	if got.Version != r.Version {
		t.Fatal("restart lost state")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e := c2.Task(ctx, "task_1"); !errors.Is(e, context.Canceled) {
		t.Fatalf("got %v", e)
	}
	if e := os.WriteFile(p, []byte("not encrypted"), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e := NewEncryptedFileRepository(p, key); !errors.Is(e, ErrRepositoryCorrupt) {
		t.Fatalf("corruption was not fail closed: %v", e)
	}
}

func TestEncryptedRepositoryLoadRejectsUnknownTopLevelAndNestedFields(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, 32)
	path := filepath.Join(t.TempDir(), "controller.enc")
	repo := must(NewEncryptedFileRepository(path, key))
	base := must(CanonicalJSON(ControllerSnapshot{SchemaVersion: "controller-snapshot.v1", Tasks: map[string]TaskRecord{}}))
	var top map[string]any
	if err := json.Unmarshal(base, &top); err != nil {
		t.Fatal(err)
	}
	top["unexpected"] = true
	payload := must(json.Marshal(top))
	if err := os.WriteFile(path, must(repo.seal(payload)), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.Load(context.Background()); !errors.Is(err, ErrRepositoryCorrupt) {
		t.Fatalf("unknown top-level field accepted: %v", err)
	}

	// A semantically valid task with an unknown nested member must fail the same way.
	// Keep this fixture deliberately small: strict decoding runs before semantic validation.
	var nested map[string]any
	nested = map[string]any{"schema_version": "controller-snapshot.v1", "tasks": map[string]any{}}
	tasks := nested["tasks"].(map[string]any)
	tasks["task_1"] = map[string]any{"id": "task_1", "version": 1, "state": "OBSERVED", "signal": map[string]any{}, "transitions": []any{}, "unknown": true}
	nestedPayload := must(json.Marshal(nested))
	if err := os.WriteFile(path, must(repo.seal(nestedPayload)), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.Load(context.Background()); !errors.Is(err, ErrRepositoryCorrupt) {
		t.Fatalf("unknown nested field accepted: %v", err)
	}
}

func TestRuntimeAttestationsRequirePresentUniqueInventoriesAndUTCTimestamps(t *testing.T) {
	root := RootRuntimeAttestation{
		RuntimeID: "root", CodexVersion: "test", CleanHomeDigest: dg(t, "home"),
		ProfileDigest: dg(t, "profile"), EffectiveConfigDigest: dg(t, "config"),
		InstructionSources: []SourceDigest{}, MCPServers: []SourceDigest{}, Skills: []SourceDigest{},
		Hooks: []SourceDigest{}, Apps: []SourceDigest{}, SandboxPolicy: "workspace-write",
		RestrictedReadRoots: []string{}, RestrictedReadRootsDigest: dg(t, []string{}), NetworkAccess: false,
		ApprovalPolicy: "never", AppServerSchemaDigest: dg(t, "app-server"), CreatedAt: time.Now().UTC(),
	}
	if err := root.Seal(); err != nil {
		t.Fatal(err)
	}
	if err := root.Validate(); err != nil {
		t.Fatalf("valid root attestation rejected: %v", err)
	}
	for name, mutate := range map[string]func(*RootRuntimeAttestation){
		"nil inventory":  func(v *RootRuntimeAttestation) { v.Skills = nil },
		"duplicate root": func(v *RootRuntimeAttestation) { v.RestrictedReadRoots = []string{"worktree", "worktree"} },
		"non-UTC timestamp": func(v *RootRuntimeAttestation) {
			v.CreatedAt = time.Date(2026, 8, 12, 12, 0, 0, 0, time.FixedZone("offset", 3600))
		},
	} {
		bad := root
		mutate(&bad)
		if err := bad.Validate(); err == nil {
			t.Errorf("%s accepted", name)
		}
	}

	worker := WorkerRuntimeAttestation{
		WorkerInstanceID: "worker", WorkOrderID: "order", CodexVersion: "test", AgentRole: "codex_implementer",
		LaunchSurface: "exec", ProcessIdentity: "pid:test", ModelRoute: "synthetic", CleanHomeDigest: dg(t, "home"),
		GeneratedProfileDigest: dg(t, "profile"), InstructionSources: []SourceDigest{}, ToolInventory: []SourceDigest{},
		ApprovalPolicy: "never", SandboxMode: "workspace-write", SandboxPolicyDigest: dg(t, "sandbox"),
		WorkspaceDescriptorDigest: dg(t, "workspace"), WorktreeBaseRef: "main", WritableResources: []string{"worktree"},
		ReadableResources: []string{"worktree"}, NetworkPolicy: "false", CreatedAt: time.Now().UTC(),
	}
	if err := worker.Seal(); err != nil {
		t.Fatal(err)
	}
	if err := worker.Validate(); err != nil {
		t.Fatalf("valid worker attestation rejected: %v", err)
	}
	badWorker := worker
	badWorker.ToolInventory = nil
	if err := badWorker.Validate(); err == nil {
		t.Fatal("nil worker inventory accepted")
	}
}

func TestDispatchRejectsSelfConsistentButMismatchedWorkerAttestation(t *testing.T) {
	c := must(NewController(context.Background(), &MemoryRepository{}))
	r := must(c.IngestSignal(context.Background(), "task_1", testSignal(t)))
	draft := testSpec(t, "task_1", "draft", 1, "")
	r = must(c.DraftSpec(context.Background(), "task_1", r.Version, draft))
	r = must(c.FreezeSpec(context.Background(), "task_1", r.Version, testSpec(t, "task_1", "frozen", 1, draft.SpecHash)))
	w := testWork(t, "task_1", r.Spec.SpecHash)
	a := testWorker(t, w)
	b := testBinding(t, "task_1", w, a)
	a.GeneratedProfileDigest = dg(t, "different-profile")
	a.AttestationDigest = ""
	if err := a.Seal(); err != nil {
		t.Fatal(err)
	}
	b.WorkerRuntimeAttestationDigest = a.AttestationDigest
	b.ProfileManifestDigest = a.GeneratedProfileDigest
	b.BindingDigest = ""
	if err := b.Seal(); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Dispatch(context.Background(), "task_1", r.Version, w, a, b); !errors.Is(err, ErrBindingMismatch) {
		t.Fatalf("self-consistent mismatched attestation accepted: %v", err)
	}
}

func TestSnapshotRejectsIncoherentStateAndEncryptedLoadFailsClosed(t *testing.T) {
	repo := must(NewEncryptedFileRepository(filepath.Join(t.TempDir(), "controller.enc"), make([]byte, 32)))
	c := must(NewController(context.Background(), repo))
	accepted := flowToAccepted(t, c, "task_1")
	s := must(c.Snapshot(context.Background()))

	badState := cloneSnapshot(s)
	record := badState.Tasks["task_1"]
	record.State = SignalReady
	badState.Tasks["task_1"] = record
	if e := badState.Validate(); e == nil {
		t.Fatal("accepted artifacts under SIGNAL_READY accepted")
	}

	badTransition := cloneSnapshot(s)
	record = badTransition.Tasks["task_1"]
	record.Transitions[len(record.Transitions)-1].Version--
	badTransition.Tasks["task_1"] = record
	if e := badTransition.Validate(); e == nil {
		t.Fatal("non-monotonic transition version accepted")
	}

	badBinding := cloneSnapshot(s)
	record = badBinding.Tasks["task_1"]
	record.Binding.SpecHash = dg(t, "different-spec")
	if e := record.Binding.Seal(); e != nil {
		t.Fatal(e)
	}
	badBinding.Tasks["task_1"] = record
	if e := badBinding.Validate(); e == nil {
		t.Fatal("mismatched dispatch binding accepted")
	}

	// Encrypting an otherwise well-formed JSON snapshot must not bypass semantic validation.
	payload := must(CanonicalJSON(badBinding))
	ciphertext := must(repo.seal(payload))
	if e := os.WriteFile(repo.path, ciphertext, 0600); e != nil {
		t.Fatal(e)
	}
	if _, e := NewEncryptedFileRepository(repo.path, make([]byte, 32)); !errors.Is(e, ErrRepositoryCorrupt) {
		t.Fatalf("incoherent encrypted snapshot accepted: %v", e)
	}
	if accepted.State != Accepted {
		t.Fatal("test setup did not reach accepted")
	}
}

func TestEncryptedRepositoryCloseZeroizesAndRefusesFurtherUse(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	repo := must(NewEncryptedFileRepository(filepath.Join(t.TempDir(), "controller.enc"), key))
	if e := repo.Close(); e != nil {
		t.Fatal(e)
	}
	if repo.key != nil || !repo.closed {
		t.Fatal("repository key was not cleared on close")
	}
	if _, e := repo.Load(context.Background()); !errors.Is(e, ErrRepositoryClosed) {
		t.Fatalf("closed Load: %v", e)
	}
	if e := repo.Save(context.Background(), ControllerSnapshot{SchemaVersion: "controller-snapshot.v1", Tasks: map[string]TaskRecord{}}); !errors.Is(e, ErrRepositoryClosed) {
		t.Fatalf("closed Save: %v", e)
	}
	if e := repo.Close(); e != nil {
		t.Fatalf("second Close: %v", e)
	}
}

func TestPoisonedControllerHidesSnapshotUntilValidatedReload(t *testing.T) {
	valid := ControllerSnapshot{SchemaVersion: "controller-snapshot.v1", Tasks: map[string]TaskRecord{}}
	repo := &uncertainRepository{snapshot: valid}
	c := must(NewController(context.Background(), repo))
	if _, err := c.IngestSignal(context.Background(), "task_1", testSignal(t)); !errors.Is(err, ErrControllerPoisoned) {
		t.Fatalf("uncertain commit did not poison controller: %v", err)
	}
	if _, err := c.Snapshot(context.Background()); !errors.Is(err, ErrControllerPoisoned) {
		t.Fatalf("poisoned Snapshot exposed state: %v", err)
	}

	// A repository implementation outside this package may return decoded-but-invalid state;
	// Reload must not clear poison until the Controller validates it itself.
	repo.snapshot = ControllerSnapshot{SchemaVersion: "controller-snapshot.v1", Tasks: map[string]TaskRecord{"task_1": {ID: "task_1"}}}
	if err := c.Reload(context.Background()); err == nil {
		t.Fatal("invalid reload cleared poison")
	}
	if _, err := c.Snapshot(context.Background()); !errors.Is(err, ErrControllerPoisoned) {
		t.Fatalf("invalid reload exposed state: %v", err)
	}

	repo.snapshot = valid
	if err := c.Reload(context.Background()); err != nil {
		t.Fatal(err)
	}
	if snapshot, err := c.Snapshot(context.Background()); err != nil || len(snapshot.Tasks) != 0 {
		t.Fatalf("validated reload did not recover: snapshot=%+v err=%v", snapshot, err)
	}
}

func TestActionProposalRejectsMalformedDestination(t *testing.T) {
	payload := json.RawMessage(`{"ok":true}`)
	a := ActionProposal{ActionID: "act", TaskID: "task", SpecHash: dg(t, "spec"), ActionType: "synthetic", Principal: "controller", CanonicalPayload: payload, PayloadHash: dg(t, payload), DestinationDescriptor: json.RawMessage(`{`), DestinationHash: dg(t, "not-used"), ReconciliationPolicyDigest: dg(t, "reconcile"), RiskClass: "L1", RequiredCapability: "none", ApprovalMode: "owner", PolicyVersion: "p1", ExpiresAt: time.Now().Add(time.Hour)}
	if e := a.Validate(); !errors.Is(e, ErrInvalidContract) {
		t.Fatalf("malformed destination accepted or wrong error: %v", e)
	}
}
func TestExactPreviewReceiptAndDecisionRecordOnly(t *testing.T) {
	repo := &MemoryRepository{}
	c := must(NewControllerWithAuthenticator(context.Background(), repo, allowAuth{}))
	r := flowToAccepted(t, c, "task_1")
	binding := seal(t, InteractionDeliveryBinding{DeliveryBindingID: "ui_1", Kind: "custom_app_server_client", HostBuild: "test", HostBuildDigest: dg(t, "build"), ControllerEndpointIdentity: "unix:test", CallbackAuthScheme: "synthetic", AllowedOrigins: []string{"local"}, CSP: "default-src 'none'", UIResourceDigest: dg(t, "bundle"), RenderingVersion: "v1", ProbeArtifactRefs: []string{"artifact:probe"}, IssuedAt: time.Now().UTC()})
	payload := json.RawMessage(`{"message":"hello"}`)
	dest := json.RawMessage(`{"account":"synthetic"}`)
	action := ActionProposal{ActionID: "act_1", TaskID: "task_1", SpecHash: r.Spec.SpecHash, ActionType: "reply.send", Principal: "controller", CanonicalPayload: payload, PayloadHash: dg(t, json.RawMessage(payload)), DestinationDescriptor: dest, DestinationHash: dg(t, json.RawMessage(dest)), ReconciliationPolicyDigest: dg(t, "none"), Effects: []string{"synthetic"}, RiskClass: "L1", SourceRefs: []string{"artifact:s"}, RequiredCapability: "reply.send", ApprovalMode: "owner", PolicyVersion: "p1", ExpiresAt: time.Now().Add(time.Hour).UTC()}
	r, _, _ = c.CreateActionPreview(context.Background(), "task_1", r.Version, binding, action, "controller:test")
	if r.ID == "" {
		t.Fatal("preview failed")
	}
	receipt := seal(t, InteractionRenderReceipt{InteractionID: r.Envelope.InteractionID, DeliveryBindingID: binding.DeliveryBindingID, DisplayInstanceID: "display_1", EnvelopeDigest: r.Envelope.EnvelopeDigest, PreviewDigest: r.Envelope.PreviewDigest, RenderingVersion: "v1", RenderedAt: time.Now().UTC()})
	r = must(c.RecordRenderReceipt(context.Background(), "task_1", r.Version, receipt))
	// Restart must retain the exact delivery binding that was used to create the preview.
	c = must(NewControllerWithAuthenticator(context.Background(), repo, allowAuth{}))
	r = must(c.Task(context.Background(), "task_1"))
	if r.DeliveryBinding == nil || r.DeliveryBinding.BindingDigest != binding.BindingDigest {
		t.Fatal("delivery binding was not persisted across restart")
	}
	event := seal(t, OwnerDecisionEvent{DecisionEventID: "decision_1", Decision: "approve", InteractionID: r.Envelope.InteractionID, DeliveryBindingID: binding.DeliveryBindingID, DisplayInstanceID: receipt.DisplayInstanceID, RenderReceiptDigest: receipt.ReceiptDigest, EnvelopeDigest: r.Envelope.EnvelopeDigest, PreviewDigest: r.Envelope.PreviewDigest, RenderingVersion: "v1", ActionID: action.ActionID, PayloadHash: action.PayloadHash, DestinationHash: action.DestinationHash, ReconciliationPolicyDigest: action.ReconciliationPolicyDigest, Nonce: r.Envelope.Nonce, ChallengeDigest: r.Envelope.ChallengeDigest, ExpiresAt: r.Envelope.ExpiresAt, PolicyVersion: "p1", ApproverID: "owner", RecentAuthProofRef: "opaque:proof", ReceivedAt: time.Now().UTC()})
	// A transcript/tool result has no authenticated callback adapter and is denied before
	// Controller state is touched; only the injected, attested adapter may authenticate.
	if e := (denyAuthenticator{}).AuthenticateOwnerDecision(context.Background(), binding, event); !errors.Is(e, ErrDecisionDenied) {
		t.Fatalf("unauthenticated decision channel accepted: %v", e)
	}
	modified := binding
	modified.HostBuild = "changed"
	if e := modified.Seal(); e != nil {
		t.Fatal(e)
	}
	if _, e := c.RecordOwnerDecision(context.Background(), "task_1", r.Version, modified, event); !errors.Is(e, ErrBindingMismatch) {
		t.Fatalf("modified delivery binding accepted: %v", e)
	}
	forged := event
	forged.PayloadHash = dg(t, "forged")
	if e := forged.Seal(); e != nil {
		t.Fatal(e)
	}
	if _, e := c.RecordOwnerDecision(context.Background(), "task_1", r.Version, binding, forged); !errors.Is(e, ErrBindingMismatch) {
		t.Fatalf("forged decision accepted: %v", e)
	}
	r = must(c.RecordOwnerDecision(context.Background(), "task_1", r.Version, binding, event))
	if r.State != Accepted || len(r.Decisions) != 1 {
		t.Fatal("decision must only be recorded, never execute an effect")
	}
	replay := event
	replay.DecisionEventID = "decision_2"
	if e := replay.Seal(); e != nil {
		t.Fatal(e)
	}
	if _, e := c.RecordOwnerDecision(context.Background(), "task_1", r.Version, binding, replay); !errors.Is(e, ErrDecisionDenied) {
		t.Fatalf("same interaction/nonce replay accepted: %v", e)
	}
	corrupt := must(c.Snapshot(context.Background()))
	corrupt.Tasks["task_1"].Envelope.DeliveryBindingID = "other-binding"
	if e := corrupt.Tasks["task_1"].Envelope.Seal(); e != nil {
		t.Fatal(e)
	}
	if e := corrupt.Validate(); e == nil {
		t.Fatal("persisted envelope/binding relationship corruption accepted")
	}
}

func callbackPreview(t *testing.T, c *Controller, id string, expiry time.Time) TaskRecord {
	r := must(c.Task(context.Background(), id))
	binding := seal(t, InteractionDeliveryBinding{DeliveryBindingID: "cb_ui", Kind: "custom_app_server_client", HostBuild: "test", HostBuildDigest: dg(t, "build"), ControllerEndpointIdentity: "local", CallbackAuthScheme: "synthetic", AllowedOrigins: []string{"local"}, CSP: "default-src 'none'", UIResourceDigest: dg(t, "bundle"), RenderingVersion: "v1", ProbeArtifactRefs: []string{"probe"}, IssuedAt: time.Now().UTC()})
	payload := json.RawMessage(`{"message":"callback"}`)
	dest := json.RawMessage(`{"account":"synthetic"}`)
	a := ActionProposal{ActionID: "cb_action", TaskID: id, SpecHash: r.Spec.SpecHash, ActionType: "reply.send", Principal: "controller", CanonicalPayload: payload, PayloadHash: dg(t, payload), DestinationDescriptor: dest, DestinationHash: dg(t, dest), ReconciliationPolicyDigest: dg(t, "reconcile"), Effects: []string{"synthetic"}, RiskClass: "L1", SourceRefs: []string{"probe"}, RequiredCapability: "reply.send", ApprovalMode: "owner", PolicyVersion: "p1", ExpiresAt: expiry}
	out, _, err := c.CreateActionPreview(context.Background(), id, r.Version, binding, a, "controller:test")
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestCallbackSessionCASReplayExpiryAndRestart(t *testing.T) {
	repo := &MemoryRepository{}
	c := must(NewControllerWithAuthenticators(context.Background(), repo, allowAuth{}, allowCallback{}))
	flowToAccepted(t, c, "callback")
	r := callbackPreview(t, c, "callback", time.Now().Add(time.Hour).UTC())
	r, challenge, handle, e := c.IssueCallbackSession(context.Background(), "callback", r.Version, time.Minute)
	if e != nil || handle == "" || challenge.HandleDigest != digestString(handle) {
		t.Fatalf("issue: %v", e)
	}
	if challenge.ExpiresAt.After(time.Now().Add(time.Minute + time.Second)) {
		t.Fatal("callback ttl was not persisted")
	}
	if _, _, _, e := c.IssueCallbackSession(context.Background(), "callback", r.Version, time.Minute); !errors.Is(e, ErrVersionConflict) {
		t.Fatalf("second live callback session accepted: %v", e)
	}
	r, receipt, rendered, e := c.RenderCallbackSession(context.Background(), "callback", r.Version, challenge.SessionID)
	if e != nil || receipt.ReceiptDigest == "" || rendered.RenderReceiptDigest != receipt.ReceiptDigest {
		t.Fatalf("render: %v", e)
	}
	// Concurrent callers race on the same persisted version; exactly one may win.
	base := r.Version
	var wg sync.WaitGroup
	var wins, conflicts int
	var mu sync.Mutex
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _, err := c.RecordAuthenticatedCallback(context.Background(), "callback", base, challenge.SessionID, handle, "approve")
			mu.Lock()
			defer mu.Unlock()
			if err == nil {
				wins++
			} else if errors.Is(err, ErrVersionConflict) {
				conflicts++
			}
		}()
	}
	wg.Wait()
	if wins != 1 || conflicts != 49 {
		t.Fatalf("CAS results wins=%d conflicts=%d", wins, conflicts)
	}
	// A restarted controller invalidates unfinished sessions; the decided one is retained.
	c2 := must(NewControllerWithAuthenticators(context.Background(), repo, allowAuth{}, allowCallback{}))
	if got := must(c2.Task(context.Background(), "callback")); got.CallbackSessions[challenge.SessionID].State != "DECIDED" {
		t.Fatal("decided session changed on restart")
	}

	flowToAccepted(t, c2, "expired")
	r = callbackPreview(t, c2, "expired", time.Now().Add(-time.Second).UTC())
	if _, _, _, e := c2.IssueCallbackSession(context.Background(), "expired", r.Version, time.Minute); !errors.Is(e, ErrDecisionDenied) {
		t.Fatalf("expired session accepted: %v", e)
	}
}

func TestCallbackRestartInvalidatesIssuedSession(t *testing.T) {
	repo := &MemoryRepository{}
	c := must(NewControllerWithAuthenticators(context.Background(), repo, allowAuth{}, allowCallback{}))
	flowToAccepted(t, c, "restart")
	r := callbackPreview(t, c, "restart", time.Now().Add(time.Hour).UTC())
	r, ch, handle, e := c.IssueCallbackSession(context.Background(), "restart", r.Version, time.Minute)
	if e != nil {
		t.Fatal(e)
	}
	c2 := must(NewControllerWithAuthenticators(context.Background(), repo, allowAuth{}, allowCallback{}))
	got := must(c2.Task(context.Background(), "restart"))
	if got.CallbackSessions[ch.SessionID].State != "INVALIDATED" {
		t.Fatal("unfinished session was not invalidated")
	}
	if _, _, e := c2.RecordAuthenticatedCallback(context.Background(), "restart", got.Version, ch.SessionID, handle, "approve"); !errors.Is(e, ErrDecisionDenied) {
		t.Fatalf("invalidated callback accepted: %v", e)
	}
}

func TestNativeCallbackBindsObservedPreviewAndKeepsHandlePrivate(t *testing.T) {
	repo := &MemoryRepository{}
	c := must(NewControllerWithAuthenticators(context.Background(), repo, allowAuth{}, allowCallback{}))
	flowToAccepted(t, c, "native")
	r := callbackPreview(t, c, "native", time.Now().Add(time.Hour).UTC())
	r, session, err := c.IssueNativeCallbackSession(context.Background(), "native", r.Version, time.Minute)
	if err != nil || session.SessionID == "" || session.handle == "" {
		t.Fatalf("issue native session: %v", err)
	}
	if session.Challenge.HandleDigest == "" {
		t.Fatal("native challenge leaked no handle binding")
	}
	if _, _, _, err := c.AcknowledgeNativeRendered(context.Background(), "native", r.Version, session, "display-nonce", digestString("wrong-preview")); !errors.Is(err, ErrDecisionDenied) {
		t.Fatalf("mismatched observed preview accepted: %v", err)
	}
	r, receipt, challenge, err := c.AcknowledgeNativeRendered(context.Background(), "native", r.Version, session, "display-nonce", r.Envelope.PreviewDigest)
	if err != nil || receipt.DisplayNonce != "display-nonce" || challenge.DisplayNonce != "display-nonce" || challenge.RenderReceiptDigest != receipt.ReceiptDigest {
		t.Fatalf("native render acknowledgement: %v", err)
	}
	if _, _, err := c.RecordNativeAuthenticatedDecision(context.Background(), "native", r.Version, session, "approve", "owner", "proof"); err != nil {
		t.Fatalf("native decision: %v", err)
	}
	got := must(c.Task(context.Background(), "native"))
	if got.CallbackSessions[session.SessionID].State != "DECIDED" {
		t.Fatal("native session did not transition to decided")
	}
	if _, _, err := c.RecordNativeAuthenticatedDecision(context.Background(), "native", r.Version+1, session, "approve", "owner", "proof"); !errors.Is(err, ErrDecisionDenied) {
		t.Fatalf("native replay was not rejected: %v", err)
	}
}

func TestAuthenticatedCallbackRechecksExpiryAfterBlockingVerifier(t *testing.T) {
	repo := &MemoryRepository{}
	cb := blockingCallback{started: make(chan struct{}), release: make(chan struct{})}
	c := must(NewControllerWithAuthenticators(context.Background(), repo, allowAuth{}, cb))
	flowToAccepted(t, c, "blocking")
	r := callbackPreview(t, c, "blocking", time.Now().Add(time.Second).UTC())
	r, ch, handle, err := c.IssueCallbackSession(context.Background(), "blocking", r.Version, 20*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	r, _, _, err = c.RenderCallbackSession(context.Background(), "blocking", r.Version, ch.SessionID)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, _, e := c.RecordAuthenticatedCallback(context.Background(), "blocking", r.Version, ch.SessionID, handle, "approve")
		done <- e
	}()
	<-cb.started
	time.Sleep(30 * time.Millisecond)
	close(cb.release)
	if err := <-done; !errors.Is(err, ErrDecisionDenied) {
		t.Fatalf("expired callback accepted after verifier: %v", err)
	}
}

func TestRenderedCallbackPreventsReceiptOverwrite(t *testing.T) {
	repo := &MemoryRepository{}
	c := must(NewControllerWithAuthenticators(context.Background(), repo, allowAuth{}, allowCallback{}))
	flowToAccepted(t, c, "receipt")
	r := callbackPreview(t, c, "receipt", time.Now().Add(time.Hour).UTC())
	r, ch, _, err := c.IssueCallbackSession(context.Background(), "receipt", r.Version, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	r, receipt, _, err := c.RenderCallbackSession(context.Background(), "receipt", r.Version, ch.SessionID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.RecordRenderReceipt(context.Background(), "receipt", r.Version, receipt); !errors.Is(err, ErrVersionConflict) {
		t.Fatalf("rendered callback receipt overwritten: %v", err)
	}
}

func TestEncryptedRepositoriesCASAcrossInstances(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "controller.enc")
	key := bytes.Repeat([]byte{7}, 32)
	r1 := must(NewEncryptedFileRepository(path, key))
	r2 := must(NewEncryptedFileRepository(path, key))
	c1 := must(NewController(context.Background(), r1))
	c2 := must(NewController(context.Background(), r2))
	signal := testSignal(t)
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for _, c := range []*Controller{c1, c2} {
		wg.Add(1)
		go func(c *Controller) {
			defer wg.Done()
			_, err := c.IngestSignal(context.Background(), "cas", signal)
			results <- err
		}(c)
	}
	wg.Wait()
	close(results)
	var wins, conflicts int
	for err := range results {
		if err == nil {
			wins++
		} else if errors.Is(err, ErrVersionConflict) {
			conflicts++
		} else {
			t.Fatalf("unexpected CAS result: %v", err)
		}
	}
	if wins != 1 || conflicts != 1 {
		t.Fatalf("CAS winners=%d conflicts=%d", wins, conflicts)
	}
}
