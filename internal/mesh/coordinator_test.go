package mesh

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"testing"
	"time"
)

type fakeStarter struct {
	mu      sync.Mutex
	calls   int
	fail    error
	failAt  int
	onStart func(StartRequest)
}
type fakeSessions struct {
	mu                     sync.Mutex
	sends, steers, cancels int
	sendRef, steerRef      string
	cancelRevision         string
	cancelRef, resultRef   string
	result                 ResultEnvelope
	sendErr, steerErr      error
	cancelErr              error
	sendEntered            chan struct{}
	sendRelease            chan struct{}
	cancelEntered          chan struct{}
	cancelRelease          chan struct{}
	status, waitStatus     SessionStatus
	statusErr, waitErr     error
	recoveries             []PersistedSessionRecovery
	recoverErr             error
}

// rawProfileDirectory intentionally bypasses StaticDirectory's construction
// validation so Coordinator eligibility can be tested against a compromised
// or stale directory implementation.
type rawProfileDirectory struct{ profile Profile }

func (d rawProfileDirectory) Lookup(context.Context, string) (Profile, error) { return d.profile, nil }
func (d rawProfileDirectory) List(context.Context) ([]Profile, error) {
	return []Profile{d.profile}, nil
}

type uncertainCASRepository struct {
	inner  Repository
	mu     sync.Mutex
	calls  int
	failAt int
}

// conflictCASRepository is deterministic: only the first allow CAS calls are
// delegated, while every later write conflicts without mutating durable state.
type conflictCASRepository struct {
	inner Repository
	mu    sync.Mutex
	calls int
	allow int
}

// failLoadRepository fails one selected durable read while preserving all
// other operations. It models a post-provider journal outage without making a
// provider callback itself flaky.
type failLoadRepository struct {
	inner  Repository
	mu     sync.Mutex
	calls  int
	failAt int
	err    error
}

func (r *conflictCASRepository) Load(ctx context.Context) (Snapshot, error) {
	return r.inner.Load(ctx)
}
func (r *conflictCASRepository) CompareAndSwap(ctx context.Context, old, next Snapshot) error {
	r.mu.Lock()
	r.calls++
	allowed := r.calls <= r.allow
	r.mu.Unlock()
	if !allowed {
		return ErrVersionConflict
	}
	return r.inner.CompareAndSwap(ctx, old, next)
}

func (r *uncertainCASRepository) Load(ctx context.Context) (Snapshot, error) {
	return r.inner.Load(ctx)
}
func (r *uncertainCASRepository) CompareAndSwap(ctx context.Context, old, next Snapshot) error {
	r.mu.Lock()
	r.calls++
	fail := r.calls == r.failAt
	r.mu.Unlock()
	if fail {
		return ErrCommitUncertain
	}
	return r.inner.CompareAndSwap(ctx, old, next)
}

func (r *failLoadRepository) Load(ctx context.Context) (Snapshot, error) {
	r.mu.Lock()
	r.calls++
	fail := r.calls == r.failAt
	err := r.err
	r.mu.Unlock()
	if fail {
		return Snapshot{}, err
	}
	return r.inner.Load(ctx)
}
func (r *failLoadRepository) CompareAndSwap(ctx context.Context, old, next Snapshot) error {
	return r.inner.CompareAndSwap(ctx, old, next)
}

func (s *fakeSessions) Send(_ context.Context, _ SessionRef, inputRef string) error {
	s.mu.Lock()
	s.sends++
	s.sendRef = inputRef
	entered, release, err := s.sendEntered, s.sendRelease, s.sendErr
	s.sendEntered = nil
	s.mu.Unlock()
	if entered != nil {
		close(entered)
	}
	if release != nil {
		<-release
	}
	return err
}
func (s *fakeSessions) Steer(_ context.Context, _ SessionRef, inputRef string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.steers++
	s.steerRef = inputRef
	return s.steerErr
}
func (s *fakeSessions) Cancel(_ context.Context, _ SessionRef, cancellation Cancellation) error {
	s.mu.Lock()
	s.cancels++
	s.cancelRevision = cancellation.RevisionRef
	s.cancelRef = cancellation.ReasonRef
	if err := cancellation.Validate(); err != nil {
		s.mu.Unlock()
		return err
	}
	entered, release, err := s.cancelEntered, s.cancelRelease, s.cancelErr
	s.cancelEntered = nil
	s.mu.Unlock()
	if entered != nil {
		close(entered)
	}
	if release != nil {
		<-release
	}
	return err
}
func (s *fakeSessions) Status(context.Context, SessionRef) (SessionStatus, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.status.State == "" {
		return SessionStatus{State: "running", UsageSource: "unknown"}, s.statusErr
	}
	return s.status, s.statusErr
}
func (s *fakeSessions) Wait(context.Context, SessionRef, time.Time) (SessionStatus, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.waitStatus.State == "" {
		return SessionStatus{State: "running", UsageSource: "unknown"}, s.waitErr
	}
	return s.waitStatus, s.waitErr
}
func (s *fakeSessions) Result(_ context.Context, _ SessionRef, revisionRef string) (ResultEnvelope, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.resultRef = revisionRef
	return s.result, nil
}

// Test-only sessions explicitly attest their retained routes. Production
// adapters do not get this by default: their volatile route maps cannot prove
// a restarted Controller can route a persisted provider session.
func (s *fakeSessions) RecoverPersistedSessions(_ context.Context, recoveries []PersistedSessionRecovery) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.recoveries = append([]PersistedSessionRecovery(nil), recoveries...)
	return s.recoverErr
}

// unverifiedSessions intentionally forwards the normal session API but not
// PersistedSessionRecoveryVerifier, modelling a fresh process with only a
// volatile routing table.
type unverifiedSessions struct{ sessions *fakeSessions }

func (s unverifiedSessions) Send(ctx context.Context, ref SessionRef, input string) error {
	return s.sessions.Send(ctx, ref, input)
}
func (s unverifiedSessions) Steer(ctx context.Context, ref SessionRef, input string) error {
	return s.sessions.Steer(ctx, ref, input)
}
func (s unverifiedSessions) Cancel(ctx context.Context, ref SessionRef, cancellation Cancellation) error {
	return s.sessions.Cancel(ctx, ref, cancellation)
}
func (s unverifiedSessions) Status(ctx context.Context, ref SessionRef) (SessionStatus, error) {
	return s.sessions.Status(ctx, ref)
}
func (s unverifiedSessions) Wait(ctx context.Context, ref SessionRef, deadline time.Time) (SessionStatus, error) {
	return s.sessions.Wait(ctx, ref, deadline)
}
func (s unverifiedSessions) Result(ctx context.Context, ref SessionRef, revision string) (ResultEnvelope, error) {
	return s.sessions.Result(ctx, ref, revision)
}

type allowDisclosure struct{}

func (allowDisclosure) AuthorizeCloudDisclosure(_ context.Context, request CloudDisclosureRequest) (CloudDisclosure, error) {
	return CloudDisclosure{PlanID: "plan-1", FanoutGrantID: "grant-1", DestinationProvider: request.DestinationProvider, AccountHandleRef: request.AccountHandleRef, Model: request.Model, PayloadDigest: request.PayloadDigest, Purpose: request.Purpose, PolicyVersion: request.PolicyVersion, InputRevision: request.InputRevision, ExpiresAt: request.ExpiresAt, PlanDigest: hash("plan-1"), GrantDigest: hash("grant-1")}, nil
}

func (s *fakeStarter) Start(_ context.Context, r StartRequest) (SessionRef, error) {
	s.mu.Lock()
	s.calls++
	call, hook := s.calls, s.onStart
	fail := s.fail != nil && (s.failAt == 0 || s.failAt == call)
	s.mu.Unlock()
	if hook != nil {
		hook(r)
	}
	if fail {
		return SessionRef{}, s.fail
	}
	if !r.isSealed() {
		return SessionRef{}, ErrInvalidContract
	}
	return SessionRef{ProviderSessionID: "provider-" + r.Order.SessionID}, nil
}

type sequenceIDs struct {
	mu sync.Mutex
	n  int
}

func (s *sequenceIDs) Next() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.n++
	return fmt.Sprintf("mesh-%03d", s.n)
}

func limits() ExecutionLimits {
	return ExecutionLimits{SchemaVersion: ExecutionLimitsV1, MaxDepth: 4, MaxChildrenPerParent: 4, MaxConcurrentRuns: 8, MaxInputTokens: 100, MaxOutputTokens: 100, MaxWallMS: 1000, MaxAttempts: 1, MaxResultBytes: 1024, Cost: CostLimit{Kind: "non_monetary", Unit: "token", MaxQuantity: 100}}
}
func testProfile(local bool) Profile {
	return Profile{ID: "profile-a", Provider: "qwen", Model: "qwen3", AccountHandleRef: "account-a", LocalOnly: local, MeshSpawn: true, Status: "compatible", Limits: limits(), MappingVerified: true, EvidenceCurrent: true, Supported: CapabilityEnvelope{Tools: []string{"collect", "spawn"}}}
}
func setup(t *testing.T, profile Profile) (*Coordinator, MeshEndpointBinding, *fakeStarter, *MemoryRepository, *sequenceIDs) {
	t.Helper()
	d := NewMemoryRepository()
	dir, err := NewStaticDirectory(profile)
	if err != nil {
		t.Fatal(err)
	}
	ids := &sequenceIDs{}
	clock := func() time.Time { return time.Date(2026, 8, 25, 0, 0, 0, 0, time.UTC) }
	starter := &fakeStarter{}
	caps := limits()
	caps.MaxChildrenPerParent = 8
	caps.MaxConcurrentRuns = 16
	caps.MaxInputTokens = 1000
	caps.MaxOutputTokens = 1000
	caps.MaxWallMS = 10000
	caps.MaxResultBytes = 10000
	caps.Cost.MaxQuantity = 1000
	c, err := NewCoordinator(CoordinatorOptions{Repository: d, Directory: dir, Starter: starter, Sessions: &fakeSessions{}, Endpoints: NewEndpointAuthorizer(), Clock: clock, ID: ids.Next, PolicyVersion: "policy-1", BatchCaps: caps})
	if err != nil {
		t.Fatal(err)
	}
	b, err := c.RegisterRoot(context.Background(), "root-1", "session-root", "attempt-root", "peer-root", "L1", "workspace-1")
	if err != nil {
		t.Fatal(err)
	}
	return c, b, starter, d, ids
}
func proposal() SpawnProposal {
	return SpawnProposal{SchemaVersion: SpawnProposalV1, ClientNonce: "nonce-1", Objective: "bounded task", InputArtifactRefs: []string{"artifact-1"}, PreferredProfile: "profile-a", RequestedRole: "worker", OutputSchemaRef: "result-v1", RequestedLimits: limits(), RequestedTools: []string{"spawn"}}
}
func request(b MeshEndpointBinding, p SpawnProposal, nonce string) ProposalRequest {
	return ProposalRequest{Endpoint: EndpointRequest{EndpointID: b.EndpointID, PeerID: b.PeerID, Audience: "mesh", Nonce: nonce, MessageDigest: hash(p)}, Proposal: p}
}

func TestMintUIEndpointSeparatesAudienceWithoutBreakingRootReplay(t *testing.T) {
	c, root, _, repo, _ := setup(t, testProfile(false))
	ctx := context.Background()
	ui, err := c.MintUIEndpoint(ctx, root)
	if err != nil {
		t.Fatalf("mint UI endpoint: %v", err)
	}
	if ui.Audience != "ui" || ui.EndpointID == root.EndpointID || ui.RootRunID != root.RootRunID || ui.RunID != root.RunID || ui.PeerID != root.PeerID {
		t.Fatalf("UI endpoint is not an independently-bound projection: %#v", ui)
	}
	if _, err := c.RotateRootEndpoint(ctx, ui); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("generic root rotation accepted UI binding: %v", err)
	}
	for _, raw := range []string{"spawn", "spawnBatch", "send", "steer", "wait", "collect", "cancel", "list", "status", "result", "listProfiles"} {
		if slices.Contains(ui.AllowedOperations, raw) {
			t.Fatalf("UI endpoint contains raw mesh operation %q: %#v", raw, ui.AllowedOperations)
		}
	}

	digest := hash("listProfiles:revision-1")
	if _, err := c.endpoints.AuthorizeOperationForPolicy(EndpointRequest{EndpointID: ui.EndpointID, PeerID: ui.PeerID, Audience: "mesh", Nonce: "wrong-audience", MessageDigest: digest}, c.now().UTC(), "listProfiles", digest, c.policyVersion); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("UI endpoint accepted as mesh audience: %v", err)
	}
	if _, err := c.endpoints.AuthorizeOperationForPolicy(EndpointRequest{EndpointID: ui.EndpointID, PeerID: ui.PeerID, Audience: "ui", Nonce: "raw-ui-list", MessageDigest: digest}, c.now().UTC(), "listProfiles", digest, c.policyVersion); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("UI endpoint accepted raw mesh operation: %v", err)
	}
	uiDigest := hash("high-level-list-profiles")
	internal, err := c.AuthorizeUIOperation(ctx, EndpointRequest{EndpointID: ui.EndpointID, PeerID: ui.PeerID, Audience: "ui", Nonce: "ui-list", MessageDigest: uiDigest}, "mesh-listProfiles", uiDigest)
	if err != nil || internal.EndpointID != root.EndpointID || internal.Audience != "mesh" {
		t.Fatalf("high-level UI authorization did not return exact internal root: binding=%#v err=%v", internal, err)
	}
	if _, err := c.AuthorizeUIOperation(ctx, EndpointRequest{EndpointID: ui.EndpointID, PeerID: ui.PeerID, Audience: "ui", Nonce: "ui-raw", MessageDigest: digest}, "listProfiles", digest); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("raw mesh name accepted as high-level UI operation: %v", err)
	}
	synthesisDigest := hash("high-level-run-synthesis")
	if _, err := c.AuthorizeUIOperation(ctx, EndpointRequest{EndpointID: ui.EndpointID, PeerID: ui.PeerID, Audience: "ui", Nonce: "ui-synthesis", MessageDigest: synthesisDigest}, "run-synthesis", synthesisDigest); err != nil {
		t.Fatalf("declared unavailable run-synthesis surface was absent from UI authentication contract: %v", err)
	}

	replayed, err := c.RegisterRoot(ctx, "root-1", "session-root", "attempt-root", "peer-root", "L1", "workspace-1")
	if err != nil {
		t.Fatalf("replay root registration after UI mint: %v", err)
	}
	if replayed.EndpointID != root.EndpointID || replayed.Audience != "mesh" {
		t.Fatalf("root replay selected UI endpoint: %#v", replayed)
	}
	snapshot, err := repo.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := snapshot.Validate(); err != nil {
		t.Fatalf("snapshot with separate UI endpoint is invalid: %v", err)
	}
	directory, err := NewStaticDirectory(testProfile(false))
	if err != nil {
		t.Fatal(err)
	}
	restarted, err := NewCoordinator(CoordinatorOptions{Repository: repo, Directory: directory, Starter: &fakeStarter{}, Sessions: &fakeSessions{}, Endpoints: NewEndpointAuthorizer(), Clock: c.now, ID: (&sequenceIDs{}).Next, PolicyVersion: "policy-1", BatchCaps: limits()})
	if err != nil {
		t.Fatal(err)
	}
	restartDigest := hash("restart-high-level-list")
	internal, err = restarted.AuthorizeUIOperation(ctx, EndpointRequest{EndpointID: ui.EndpointID, PeerID: ui.PeerID, Audience: "ui", Nonce: "ui-list-restart", MessageDigest: restartDigest}, "mesh-listProfiles", restartDigest)
	if err != nil || internal.EndpointID != root.EndpointID || internal.Audience != "mesh" {
		t.Fatalf("restart lost UI-to-internal capability bridge: binding=%#v err=%v", internal, err)
	}
}

func TestCanonicalUIOperationMatrixMatchesControllerSurfaceExactly(t *testing.T) {
	want := []string{"selection-revision", "ui-session-graph", "run-compare", "run-synthesis", "provider-directory", "provider-diagnostics", "run-templates", "policy-approval-inspector", "deployment-diagnostics", "plugin-lifecycle", "mesh-spawn", "mesh-spawnBatch", "mesh-send", "mesh-steer", "mesh-wait", "mesh-collect", "mesh-cancel", "mesh-list", "mesh-status", "mesh-result", "mesh-listProfiles"}
	got := canonicalUIOperations()
	if len(got) != 21 || !slices.Equal(got, want) {
		t.Fatalf("canonical UI operation drift: got=%#v want=%#v", got, want)
	}
	got[0] = "mutated-by-caller"
	if slices.Equal(got, canonicalUIOperations()) {
		t.Fatal("canonical UI operation source returned shared mutable storage")
	}
}

func TestUIRotationRenewsDistinctInternalRootAcrossExpiryRestartReplayAndRevoke(t *testing.T) {
	now := time.Date(2026, 8, 30, 10, 0, 0, 0, time.UTC)
	repo := NewMemoryRepository()
	directory, err := NewStaticDirectory(testProfile(false))
	if err != nil {
		t.Fatal(err)
	}
	ids := &sequenceIDs{}
	options := CoordinatorOptions{Repository: repo, Directory: directory, Starter: &fakeStarter{}, Sessions: &fakeSessions{}, Endpoints: NewEndpointAuthorizer(), Clock: func() time.Time { return now }, ID: ids.Next, PolicyVersion: "policy-1", BatchCaps: limits()}
	c, err := NewCoordinator(options)
	if err != nil {
		t.Fatal(err)
	}
	root, err := c.RegisterRoot(context.Background(), "rotate-root", "rotate-session", "rotate-attempt", "rotate-peer", "L1", "rotate-workspace")
	if err != nil {
		t.Fatal(err)
	}
	ui, err := c.MintUIEndpoint(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	now = root.ExpiresAt.Add(time.Second)
	historical, err := c.LifecycleRootBinding(context.Background(), ui.EndpointID, ui.Generation)
	if err != nil {
		t.Fatal(err)
	}
	nextUI, err := c.RotateUIEndpointPair(context.Background(), historical)
	if err != nil || !nextUI.ExpiresAt.After(now) {
		t.Fatalf("rotate=%#v err=%v", nextUI, err)
	}
	if !canonicalUIBinding(nextUI) || !slices.Contains(nextUI.AllowedOperations, "run-synthesis") {
		t.Fatalf("rotation lost canonical UI surface contract: %#v", nextUI.AllowedOperations)
	}
	digest := hash("rotated-ui-list")
	nextRoot, err := c.AuthorizeUIOperation(context.Background(), EndpointRequest{EndpointID: nextUI.EndpointID, PeerID: nextUI.PeerID, Audience: "ui", Nonce: "rotated-ui-nonce", MessageDigest: digest}, "mesh-listProfiles", digest)
	if err != nil || nextRoot.Audience != "mesh" || nextRoot.EndpointID == root.EndpointID || !nextRoot.ExpiresAt.Equal(nextUI.ExpiresAt) {
		t.Fatalf("internal renewal=%#v err=%v", nextRoot, err)
	}
	profiles, err := c.ListProfiles(context.Background(), ListProfilesRequest{Endpoint: EndpointRequest{EndpointID: nextRoot.EndpointID, PeerID: nextRoot.PeerID, Audience: "mesh", Nonce: "rotated-mesh-nonce", MessageDigest: hash("listProfiles:revision-1")}, RevisionRef: "revision-1"})
	if err != nil || len(profiles) != 1 {
		t.Fatalf("invoke after rotate profiles=%#v err=%v", profiles, err)
	}
	restarted, err := NewCoordinator(CoordinatorOptions{Repository: repo, Directory: directory, Starter: &fakeStarter{}, Sessions: &fakeSessions{}, Endpoints: NewEndpointAuthorizer(), Clock: func() time.Time { return now }, ID: ids.Next, PolicyVersion: "policy-1", BatchCaps: limits()})
	if err != nil {
		t.Fatal(err)
	}
	replayed, err := restarted.RotateUIEndpointPair(context.Background(), historical)
	if err != nil || hash(replayed) != hash(nextUI) {
		t.Fatalf("rotation replay=%#v err=%v", replayed, err)
	}
	restartDigest := hash("rotated-ui-restart")
	if _, err = restarted.AuthorizeUIOperation(context.Background(), EndpointRequest{EndpointID: nextUI.EndpointID, PeerID: nextUI.PeerID, Audience: "ui", Nonce: "rotated-ui-restart-nonce", MessageDigest: restartDigest}, "mesh-listProfiles", restartDigest); err != nil {
		t.Fatalf("restart authorization: %v", err)
	}
	if err = restarted.RevokeEndpoint(context.Background(), nextUI.EndpointID, nextUI.Generation); err != nil {
		t.Fatal(err)
	}
	deniedDigest := hash("rotated-ui-revoked")
	if _, err = restarted.AuthorizeUIOperation(context.Background(), EndpointRequest{EndpointID: nextUI.EndpointID, PeerID: nextUI.PeerID, Audience: "ui", Nonce: "rotated-ui-revoked-nonce", MessageDigest: deniedDigest}, "mesh-listProfiles", deniedDigest); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("revoked UI authorized: %v", err)
	}
}

func TestLegacyRawUIBindingCannotProposeSpawnBatch(t *testing.T) {
	c, root, _, repo, _ := setup(t, testProfile(false))
	ui, err := c.MintUIEndpoint(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	old, err := repo.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	next := old.clone()
	legacy := next.EndpointBindings[ui.EndpointID]
	legacy.AllowedOperations = []string{"mesh-spawnBatch", "spawnBatch"}
	legacy.ToolDigest = hash(sortedStrings(legacy.AllowedOperations))
	next.EndpointBindings[ui.EndpointID] = legacy
	if err = repo.CompareAndSwap(context.Background(), old, next); err != nil {
		t.Fatal(err)
	}
	proposals := batchProposals()
	digest := hash(proposals)
	_, err = c.ProposeSpawnBatch(context.Background(), BatchProposalRequest{Endpoint: EndpointRequest{EndpointID: ui.EndpointID, PeerID: ui.PeerID, Audience: "ui", Nonce: "legacy-ui-batch", MessageDigest: digest}, Proposals: proposals})
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("legacy raw UI batch authorized: %v", err)
	}
	highDigest := hash("legacy-high-level-batch")
	if _, err = c.AuthorizeUIOperation(context.Background(), EndpointRequest{EndpointID: ui.EndpointID, PeerID: ui.PeerID, Audience: "ui", Nonce: "legacy-ui-high", MessageDigest: highDigest}, "mesh-spawnBatch", highDigest); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("legacy non-canonical UI allowlist authorized: %v", err)
	}
	if _, err = c.RotateUIEndpointPair(context.Background(), legacy); !errors.Is(err, ErrReconciliationNeeded) {
		t.Fatalf("legacy non-canonical UI allowlist rotated: %v", err)
	}
}
func batchProposals() []SpawnProposal {
	p1 := proposal()
	p1.ClientNonce = "batch-1"
	p2 := proposal()
	p2.ClientNonce = "batch-2"
	return []SpawnProposal{p1, p2}
}
func batchRequest(b MeshEndpointBinding, q []SpawnProposal, nonce string) BatchProposalRequest {
	return BatchProposalRequest{Endpoint: EndpointRequest{EndpointID: b.EndpointID, PeerID: b.PeerID, Audience: "mesh", Nonce: nonce, MessageDigest: hash(q)}, Proposals: q}
}

func lifecycleOperation(t *testing.T, binding MeshEndpointBinding, runID, operation, reference, reason, nonce string) OperationRequest {
	t.Helper()
	r := OperationRequest{Target: TargetRequest{Endpoint: EndpointRequest{EndpointID: binding.EndpointID, PeerID: binding.PeerID, Audience: "mesh", Nonce: nonce}, TargetRunID: runID, Operation: operation}}
	switch operation {
	case "send", "steer":
		r.InputRef = reference
	case "cancel":
		r.RevisionRef, r.ReasonRef = reference, reason
	default:
		r.RevisionRef = reference
	}
	digest, err := r.Digest()
	if err != nil {
		t.Fatal(err)
	}
	r.Target.Endpoint.MessageDigest = digest
	return r
}

func directTarget(binding MeshEndpointBinding, runID, operation, nonce string) TargetRequest {
	return TargetRequest{Endpoint: EndpointRequest{EndpointID: binding.EndpointID, PeerID: binding.PeerID, Audience: "mesh", Nonce: nonce, MessageDigest: hash(runID + ":" + operation)}, TargetRunID: runID, Operation: operation}
}

func TestEndpointBindingReadsOnlyDurableCurrentBinding(t *testing.T) {
	c, minted, _, repo, _ := setup(t, testProfile(true))
	got, err := c.EndpointBinding(context.Background(), minted.EndpointID)
	if err != nil {
		t.Fatal(err)
	}
	if got.EndpointID != minted.EndpointID || got.RootRunID != minted.RootRunID || got.Generation != minted.Generation {
		t.Fatalf("binding=%#v", got)
	}
	s, err := repo.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	next := s.clone()
	next.EndpointRevoked[minted.EndpointID] = true
	if err := repo.CompareAndSwap(context.Background(), s, next); err != nil {
		t.Fatal(err)
	}
	if _, err := c.EndpointBinding(context.Background(), minted.EndpointID); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("revoked binding exposed: %v", err)
	}
}

func TestProposeSealsOnceAndDurablyReplays(t *testing.T) {
	c, b, s, repo, _ := setup(t, testProfile(true))
	p := proposal()
	got, err := c.ProposeSpawn(context.Background(), request(b, p, "call-1"))
	if err != nil {
		t.Fatal(err)
	}
	if got.RunID == "" || got.Replayed {
		t.Fatalf("bad result %#v", got)
	}
	again, err := c.ProposeSpawn(context.Background(), request(b, p, "call-2"))
	if err != nil {
		t.Fatal(err)
	}
	if !again.Replayed || again.RunID != got.RunID {
		t.Fatalf("retry minted a child: %#v %#v", got, again)
	}
	if again.OrderID != got.OrderID || again.BindingID != got.BindingID {
		t.Fatalf("retry lost sealed response: %#v %#v", got, again)
	}
	if s.calls != 1 {
		t.Fatalf("starts=%d", s.calls)
	}
	snap, err := repo.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.Runs) != 2 || len(snap.Proposals) != 1 {
		t.Fatalf("unexpected durable state %#v", snap)
	}
}

func TestStartRequestSealBindsCompleteOrderAndDispatch(t *testing.T) {
	c, b, starter, _, _ := setup(t, testProfile(true))
	var captured StartRequest
	starter.onStart = func(request StartRequest) { captured = request }
	if _, err := c.ProposeSpawn(context.Background(), request(b, proposal(), "seal-capture")); err != nil {
		t.Fatal(err)
	}
	if !captured.SealValid() {
		t.Fatal("coordinator did not produce a valid sealed start request")
	}
	if captured.Order.Task.Objective != "bounded task" || len(captured.Order.Task.InputArtifactRefs) != 1 || captured.Order.Task.RequestedRole != "worker" || captured.Order.Task.OutputSchemaRef != "result-v1" {
		t.Fatalf("sealed task envelope was not propagated: %#v", captured.Order.Task)
	}
	mutatedTask := captured
	mutatedTask.Order.Task.Objective = "substituted"
	if mutatedTask.SealValid() {
		t.Fatal("task envelope substitution retained a valid Controller seal")
	}

	mutatedOrder := captured
	mutatedOrder.Order.Model = "mutated-model"
	if mutatedOrder.SealValid() {
		t.Fatal("order mutation retained a valid Controller seal")
	}
	mutatedBinding := captured
	mutatedBinding.Binding.EndpointID = "mutated-endpoint"
	if mutatedBinding.SealValid() {
		t.Fatal("binding mutation retained a valid Controller seal")
	}
	crossOrder := captured
	crossOrder.Binding.OrderID = "foreign-order"
	crossOrder.Binding.BindingHash = hash(crossOrder.Binding)
	crossOrder = sealStartRequest(crossOrder.Order, crossOrder.Binding)
	if crossOrder.SealValid() {
		t.Fatal("cross-order dispatch binding was sealable")
	}
	literal := StartRequest{Order: captured.Order, Binding: captured.Binding}
	if literal.SealValid() {
		t.Fatal("matching literal fields minted Controller authority")
	}
}
func TestProposalConflictingNonceFailsAndEndpointReplayFails(t *testing.T) {
	c, b, _, _, _ := setup(t, testProfile(true))
	p := proposal()
	if _, err := c.ProposeSpawn(context.Background(), request(b, p, "call-1")); err != nil {
		t.Fatal(err)
	}
	p.Objective = "different"
	if _, err := c.ProposeSpawn(context.Background(), request(b, p, "call-2")); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("conflict=%v", err)
	}
	if _, err := c.ProposeSpawn(context.Background(), request(b, proposal(), "call-1")); !errors.Is(err, ErrReplay) {
		t.Fatalf("replay=%v", err)
	}
}
func TestEndpointNonceCannotBeReusedWithDifferentPayloadDigest(t *testing.T) {
	c, b, _, _, _ := setup(t, testProfile(true))
	p := proposal()
	if _, err := c.ProposeSpawn(context.Background(), request(b, p, "call-1")); err != nil {
		t.Fatal(err)
	}
	p.ClientNonce = "different-proposal"
	if _, err := c.ProposeSpawn(context.Background(), request(b, p, "call-1")); !errors.Is(err, ErrReplay) {
		t.Fatalf("changed digest reused endpoint nonce: %v", err)
	}
}

func TestSnapshotValidateRejectsForgedEndpointDerivedState(t *testing.T) {
	now := time.Date(2026, 8, 25, 0, 0, 0, 0, time.UTC)
	run := Run{ID: "root-1", RootID: "root-1", SessionID: "session-1", AttemptID: "attempt-1", Classification: "L1", WorkspaceGroupID: "workspace-1", State: RunRunning, CreatedAt: now}
	child := Run{ID: "child-1", RootID: run.ID, ParentRunID: run.ID, ParentSessionID: run.SessionID, SessionID: "child-session-1", AttemptID: "child-attempt-1", ProviderSessionID: "provider-child-1", ProfileID: "profile-a", Provider: "qwen", Classification: "L1", WorkspaceGroupID: "workspace-1", Depth: 1, State: RunRunning, CreatedAt: now}
	binding := MeshEndpointBinding{SchemaVersion: EndpointBindingV1, EndpointID: "endpoint-1", Audience: "mesh", RootRunID: run.RootID, RunID: run.ID, SessionID: run.SessionID, AttemptID: run.AttemptID, AllowedOperations: []string{"send", "status"}, ToolDigest: hash([]string{"send", "status"}), PeerID: "peer-1", PolicyVersion: "policy-1", IssuedAt: now, ExpiresAt: now.Add(time.Hour), Generation: 1}
	base := emptySnapshot()
	base.Runs[run.ID] = run
	base.Runs[child.ID] = child
	base.EndpointBindings[binding.EndpointID] = binding
	base.EndpointNonces["endpoint-1:1:nonce-1"] = true
	base.EndpointRevoked[binding.EndpointID] = true
	receiptKey := inputReceiptKey(binding, child.ID, "send", "input-1")
	base.SendReceipts[receiptKey] = SendReceipt{CallerEndpointID: binding.EndpointID, CallerGeneration: binding.Generation, CallerRunID: run.ID, TargetRunID: child.ID, Operation: "send", InputRef: "input-1", Digest: inputReceiptDigest(binding, child.ID, "send", "input-1"), State: "sent"}
	base.Events = []MeshEvent{event(now, "root_registered", run, "")}
	if err := base.Validate(); err != nil {
		t.Fatalf("baseline rejected: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*Snapshot)
	}{
		{"binding unknown run", func(s *Snapshot) {
			b := s.EndpointBindings["endpoint-1"]
			b.RunID = "missing-run"
			s.EndpointBindings["endpoint-1"] = b
		}},
		{"binding digest", func(s *Snapshot) {
			b := s.EndpointBindings["endpoint-1"]
			b.ToolDigest = hash("forged")
			s.EndpointBindings["endpoint-1"] = b
		}},
		{"nonce malformed", func(s *Snapshot) {
			delete(s.EndpointNonces, "endpoint-1:1:nonce-1")
			s.EndpointNonces["not-a-nonce-key"] = true
		}},
		{"nonce generation", func(s *Snapshot) {
			delete(s.EndpointNonces, "endpoint-1:1:nonce-1")
			s.EndpointNonces["endpoint-1:2:nonce-1"] = true
		}},
		{"nonce false", func(s *Snapshot) { s.EndpointNonces["endpoint-1:1:nonce-1"] = false }},
		{"revoke unknown endpoint", func(s *Snapshot) {
			delete(s.EndpointRevoked, "endpoint-1")
			s.EndpointRevoked["unknown-endpoint"] = true
		}},
		{"revoke false", func(s *Snapshot) { s.EndpointRevoked["endpoint-1"] = false }},
		{"receipt wrong key", func(s *Snapshot) {
			r := s.SendReceipts[receiptKey]
			delete(s.SendReceipts, receiptKey)
			s.SendReceipts[hash("forged-receipt-key")] = r
		}},
		{"receipt unknown run", func(s *Snapshot) {
			r := s.SendReceipts[receiptKey]
			r.TargetRunID = "missing-run"
			s.SendReceipts[receiptKey] = r
		}},
		{"receipt digest", func(s *Snapshot) {
			r := s.SendReceipts[receiptKey]
			r.Digest = hash("forged")
			s.SendReceipts[receiptKey] = r
		}},
		{"event unknown enum", func(s *Snapshot) { s.Events[0].Event = "forged" }},
		{"event unknown run", func(s *Snapshot) { s.Events[0].RunID = "missing-run" }},
		{"event duplicate", func(s *Snapshot) { s.Events = append(s.Events, s.Events[0]) }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := base.clone()
			tt.mutate(&s)
			if err := s.Validate(); !errors.Is(err, ErrInvalidContract) {
				t.Fatalf("forged snapshot err=%v", err)
			}
		})
	}
}
func TestLimitsRejectUnsafeAndCannotWiden(t *testing.T) {
	p := limits()
	for _, bad := range []ExecutionLimits{{}, func() ExecutionLimits { x := p; x.MaxDepth = 0; return x }(), func() ExecutionLimits { x := p; x.MaxResultBytes = ^uint64(0); return x }(), func() ExecutionLimits {
		x := p
		x.Cost = CostLimit{Kind: "non_monetary", Unit: "unlimited", MaxQuantity: 1}
		return x
	}()} {
		if bad.Validate() == nil {
			t.Fatalf("accepted %#v", bad)
		}
	}
	wide := p
	wide.MaxInputTokens++
	if wide.Narrows(p) {
		t.Fatal("widening accepted")
	}
}
func TestPDAndOneCloudDefaultFailClosed(t *testing.T) {
	c, b, _, _, _ := setup(t, testProfile(false))
	p := proposal()
	if _, err := c.ProposeSpawn(context.Background(), request(b, p, "call-1")); !errors.Is(err, ErrDisclosure) {
		t.Fatalf("cloud without exact plan=%v", err)
	}
	// A separate controller with an exact plan admits one destination only.
	repoCloud := NewMemoryRepository()
	dirCloud, err := NewStaticDirectory(testProfile(false))
	if err != nil {
		t.Fatal(err)
	}
	idsCloud := &sequenceIDs{}
	nowCloud := func() time.Time { return time.Date(2026, 8, 25, 0, 0, 0, 0, time.UTC) }
	cloud, err := NewCoordinator(CoordinatorOptions{Repository: repoCloud, Directory: dirCloud, Starter: &fakeStarter{}, Disclosure: allowDisclosure{}, Endpoints: NewEndpointAuthorizer(), Clock: nowCloud, ID: idsCloud.Next, PolicyVersion: "policy-1"})
	if err != nil {
		t.Fatal(err)
	}
	cloudBinding, err := cloud.RegisterRoot(context.Background(), "root-cloud", "session-cloud", "attempt-cloud", "peer-cloud", "L1", "workspace-1")
	if err != nil {
		t.Fatal(err)
	}
	p = proposal()
	p.ClientNonce = "nonce-cloud-1"
	if _, err := cloud.ProposeSpawn(context.Background(), request(cloudBinding, p, "cloud-call-1")); err != nil {
		t.Fatal(err)
	}
	p.ClientNonce = "nonce-2"
	if _, err := cloud.ProposeSpawn(context.Background(), request(cloudBinding, p, "cloud-call-2")); !errors.Is(err, ErrDisclosure) {
		t.Fatalf("fanout=%v", err)
	}
	repo := NewMemoryRepository()
	dir, err := NewStaticDirectory(testProfile(false))
	if err != nil {
		t.Fatal(err)
	}
	ids := &sequenceIDs{}
	now := func() time.Time { return time.Date(2026, 8, 25, 0, 0, 0, 0, time.UTC) }
	pd, err := NewCoordinator(CoordinatorOptions{Repository: repo, Directory: dir, Starter: &fakeStarter{}, Endpoints: NewEndpointAuthorizer(), Clock: now, ID: ids.Next, PolicyVersion: "policy-1"})
	if err != nil {
		t.Fatal(err)
	}
	pdBinding, err := pd.RegisterRoot(context.Background(), "root-pd", "session-pd", "attempt-pd", "peer-pd", "PD", "workspace-1")
	if err != nil {
		t.Fatal(err)
	}
	p = proposal()
	p.ClientNonce = "nonce-pd"
	if _, err := pd.ProposeSpawn(context.Background(), request(pdBinding, p, "call-pd")); !errors.Is(err, ErrPDCloudRoute) {
		t.Fatalf("PD route=%v", err)
	}
}
func TestForeignAndAncestorTargetsFailClosed(t *testing.T) {
	c, b, _, _, _ := setup(t, testProfile(true))
	p := proposal()
	child, err := c.ProposeSpawn(context.Background(), request(b, p, "call-1"))
	if err != nil {
		t.Fatal(err)
	}
	target := func(target, operation, nonce string) TargetRequest {
		return TargetRequest{Endpoint: EndpointRequest{EndpointID: b.EndpointID, PeerID: b.PeerID, Audience: "mesh", Nonce: nonce, MessageDigest: hash(target + ":" + operation)}, TargetRunID: target, Operation: operation}
	}
	if _, err := c.AuthorizeTarget(context.Background(), target(child.RunID, "status", "target-1")); err != nil {
		t.Fatal(err)
	}
	if _, err := c.AuthorizeTarget(context.Background(), target("root-1", "status", "target-2")); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("ancestor=%v", err)
	}
	if _, err := c.AuthorizeTarget(context.Background(), target("foreign", "status", "target-3")); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("foreign=%v", err)
	}
	forged := b
	forged.RootRunID = "foreign-root"
	forged.RunID = "foreign-root"
	if _, err := c.AuthorizeTarget(context.Background(), TargetRequest{Endpoint: EndpointRequest{EndpointID: forged.EndpointID, PeerID: "attacker", Audience: "mesh", Nonce: "target-4", MessageDigest: hash("foreign")}, TargetRunID: child.RunID, Operation: "status"}); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("forged binding=%v", err)
	}
}
func TestPendingReplayRequiresReconciliation(t *testing.T) {
	c, b, _, repo, _ := setup(t, testProfile(true))
	p := proposal()
	scope := proposalScope(b, p.ClientNonce, "spawn")
	k := proposalRecordKey(scope, hash(p))
	s, err := repo.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	n := s.clone()
	n.NonceScopes[scope] = k
	n.Runs["pending-run"] = Run{ID: "pending-run", RootID: b.RootRunID, ParentRunID: b.RunID, ParentSessionID: b.SessionID, SessionID: "pending-session", AttemptID: "pending-attempt", ProfileID: "profile-a", Provider: "qwen", Classification: "L1", WorkspaceGroupID: "workspace-1", Depth: 1, State: RunAdmitted, CreatedAt: time.Now().UTC()}
	n.Proposals[k] = ProposalRecord{Key: k, Scope: scope, Digest: hash(p), ProposalID: "proposal-1", RunID: "pending-run", SessionID: "pending-session", OrderID: "pending-order", BindingID: "pending-binding", CallerEndpointID: b.EndpointID, CallerGeneration: b.Generation, RootRunID: b.RootRunID, State: "pending", CreatedAt: time.Now().UTC()}
	if err = repo.CompareAndSwap(context.Background(), s, n); err != nil {
		t.Fatal(err)
	}
	if _, err = c.ProposeSpawn(context.Background(), request(b, p, "call-1")); !errors.Is(err, ErrReconciliationNeeded) {
		t.Fatalf("proposal=%v", err)
	}
	if err = c.Replay(context.Background()); !errors.Is(err, ErrReconciliationNeeded) {
		t.Fatalf("replay=%v", err)
	}
}

func TestReplayRejectsEveryNonFinalInputReceipt(t *testing.T) {
	for _, state := range []string{"pending", "failed", "uncertain"} {
		t.Run(state, func(t *testing.T) {
			c, binding, _, repo, _ := setup(t, testProfile(true))
			child, err := c.ProposeSpawn(context.Background(), request(binding, proposal(), "input-replay-spawn-"+state))
			if err != nil {
				t.Fatal(err)
			}
			input := "input-replay-" + state
			if err = c.Send(context.Background(), lifecycleOperation(t, binding, child.RunID, "send", input, "", "input-replay-send-"+state)); err != nil {
				t.Fatal(err)
			}
			s, err := repo.Load(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			key := inputReceiptKey(binding, child.RunID, "send", input)
			n := s.clone()
			receipt := n.SendReceipts[key]
			receipt.State = state
			run := n.Runs[child.RunID]
			switch state {
			case "pending":
				run.ControlFence = inputControlFence(receipt.Digest)
			case "uncertain":
				run.State = RunUncertain
				run.TerminalAt = c.now().UTC()
				for endpointID, endpoint := range n.EndpointBindings {
					if endpoint.RunID == run.ID {
						n.EndpointRevoked[endpointID] = true
					}
				}
			}
			n.Runs[run.ID] = run
			n.SendReceipts[key] = receipt
			if err = repo.CompareAndSwap(context.Background(), s, n); err != nil {
				t.Fatal(err)
			}
			if err = c.Replay(context.Background()); !errors.Is(err, ErrReconciliationNeeded) {
				t.Fatalf("Replay accepted %s input receipt: %v", state, err)
			}
		})
	}

	t.Run("sent", func(t *testing.T) {
		c, binding, _, _, _ := setup(t, testProfile(true))
		child, err := c.ProposeSpawn(context.Background(), request(binding, proposal(), "input-replay-sent-spawn"))
		if err != nil {
			t.Fatal(err)
		}
		if err = c.Send(context.Background(), lifecycleOperation(t, binding, child.RunID, "send", "input-replay-sent", "", "input-replay-sent-call")); err != nil {
			t.Fatal(err)
		}
		if err = c.Replay(context.Background()); err != nil {
			t.Fatalf("Replay rejected closed sent receipt: %v", err)
		}
	})
}

func TestV1MigrationPreservesLegacyReference(t *testing.T) {
	s, err := MigrateV1(hash("controller-snapshot.v1"), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if s.SchemaVersion != SnapshotV2 || len(s.Events) != 1 || s.Events[0].RecoveryState != "dual_read" {
		t.Fatalf("bad migration %#v", s)
	}
	if _, err := MigrateV1("not-a-digest", time.Now()); !errors.Is(err, ErrInvalidContract) {
		t.Fatalf("invalid legacy accepted: %v", err)
	}
}
func TestLifecycleOperationsEnforceOperationAllowlistAndTarget(t *testing.T) {
	c, b, _, _, _ := setup(t, testProfile(true))
	child, err := c.ProposeSpawn(context.Background(), request(b, proposal(), "spawn-call"))
	if err != nil {
		t.Fatal(err)
	}
	sessions := c.sessions.(*fakeSessions)
	sessions.result = ResultEnvelope{RunID: child.RunID, AttemptID: "mesh-005", Status: "completed", OutputArtifactRef: "artifact-1", SchemaRef: "result-v1", ProvenanceDigest: hash("prov"), Classification: "L1"}
	op := func(operation, reference, reason, nonce string) OperationRequest {
		target := TargetRequest{Endpoint: EndpointRequest{EndpointID: b.EndpointID, PeerID: b.PeerID, Audience: "mesh", Nonce: nonce}, TargetRunID: child.RunID, Operation: operation}
		r := OperationRequest{Target: target}
		switch operation {
		case "send", "steer":
			r.InputRef = reference
		case "cancel":
			r.RevisionRef, r.ReasonRef = reference, reason
		default:
			r.RevisionRef = reference
		}
		digest, err := r.Digest()
		if err != nil {
			t.Fatal(err)
		}
		r.Target.Endpoint.MessageDigest = digest
		return r
	}
	if err := c.Send(context.Background(), op("send", "input-1", "", "op-1")); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Status(context.Background(), op("status", "revision-2", "", "op-2")); err != nil {
		t.Fatal(err)
	}
	if err := c.Cancel(context.Background(), op("cancel", "revision-3", "reason-3", "op-3")); err != nil {
		t.Fatal(err)
	}
	if sessions.sends != 1 || sessions.cancels != 1 || sessions.sendRef != "input-1" || sessions.cancelRevision != "revision-3" || sessions.cancelRef != "reason-3" {
		t.Fatalf("adapter calls %#v", sessions)
	}
	bad := op("status", "revision-4", "", "op-4")
	bad.Target.Operation = "effect"
	if err := c.Send(context.Background(), bad); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("wrong operation passed=%v", err)
	}
}

func TestOperationReferenceUnionRejectsCrossFieldSubstitution(t *testing.T) {
	c, b, _, _, _ := setup(t, testProfile(true))
	child, err := c.ProposeSpawn(context.Background(), request(b, proposal(), "cross-field-spawn"))
	if err != nil {
		t.Fatal(err)
	}
	base := func(operation string) OperationRequest {
		return OperationRequest{Target: TargetRequest{Endpoint: EndpointRequest{EndpointID: b.EndpointID, PeerID: b.PeerID, Audience: "mesh", Nonce: "cross-" + operation, MessageDigest: hash("wrong")}, TargetRunID: child.RunID, Operation: operation}}
	}
	invalid := []struct {
		name      string
		operation string
		request   OperationRequest
	}{
		{"send revision substituted for input", "send", func() OperationRequest { r := base("send"); r.RevisionRef = "ref-1"; return r }()},
		{"send has both refs", "send", func() OperationRequest {
			r := base("send")
			r.InputRef, r.RevisionRef = "input-1", "revision-1"
			return r
		}()},
		{"cancel missing reason", "cancel", func() OperationRequest { r := base("cancel"); r.RevisionRef = "revision-1"; return r }()},
		{"cancel input substituted", "cancel", func() OperationRequest {
			r := base("cancel")
			r.InputRef, r.RevisionRef, r.ReasonRef = "input-1", "revision-1", "reason-1"
			return r
		}()},
		{"status input substituted for revision", "status", func() OperationRequest { r := base("status"); r.InputRef = "input-1"; return r }()},
		{"wait reason substituted for revision", "wait", func() OperationRequest { r := base("wait"); r.ReasonRef = "reason-1"; return r }()},
		{"result mixed refs", "result", func() OperationRequest {
			r := base("result")
			r.RevisionRef, r.ReasonRef = "revision-1", "reason-1"
			return r
		}()},
		{"list input substituted for revision", "list", func() OperationRequest { r := base("list"); r.InputRef = "input-1"; return r }()},
	}
	for _, tt := range invalid {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := tt.request.Digest(); !errors.Is(err, ErrInvalidContract) {
				t.Fatalf("digest accepted substituted fields: %v", err)
			}
			var err error
			switch tt.operation {
			case "send":
				err = c.Send(context.Background(), tt.request)
			case "cancel":
				err = c.Cancel(context.Background(), tt.request)
			case "status":
				_, err = c.Status(context.Background(), tt.request)
			case "wait":
				_, err = c.Wait(context.Background(), tt.request)
			case "result":
				_, err = c.Result(context.Background(), tt.request)
			case "list":
				_, err = c.List(context.Background(), tt.request)
			}
			if !errors.Is(err, ErrUnauthorized) {
				t.Fatalf("substituted %s accepted: %v", tt.operation, err)
			}
		})
	}

	validSend := base("send")
	validSend.InputRef = "same-ref"
	validStatus := base("status")
	validStatus.RevisionRef = "same-ref"
	validCancel := base("cancel")
	validCancel.RevisionRef, validCancel.ReasonRef = "same-ref", "reason-ref"
	sendDigest, err := validSend.Digest()
	if err != nil {
		t.Fatal(err)
	}
	statusDigest, err := validStatus.Digest()
	if err != nil {
		t.Fatal(err)
	}
	cancelDigest, err := validCancel.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if sendDigest == statusDigest || sendDigest == cancelDigest || statusDigest == cancelDigest {
		t.Fatalf("operation reference semantics share a digest: send=%s status=%s cancel=%s", sendDigest, statusDigest, cancelDigest)
	}
}

func TestMeshProfileCannotClaimSpawnBeforeReadiness(t *testing.T) {
	disabled := testProfile(true)
	disabled.Status = "disabled"
	if disabled.Validate() == nil || disabled.Eligible() {
		t.Fatalf("disabled profile claimed mesh spawn: %+v", disabled)
	}
	compatible := testProfile(true)
	compatible.Status = "compatible"
	if compatible.Validate() != nil || !compatible.Eligible() {
		t.Fatalf("compatible profile did not remain eligible: %+v", compatible)
	}
	ready := testProfile(true)
	ready.Status = "ready"
	if ready.Validate() == nil || ready.Eligible() {
		t.Fatalf("informational ready profile claimed mesh spawn: %+v", ready)
	}

	repo := NewMemoryRepository()
	ids := &sequenceIDs{}
	now := time.Date(2026, 8, 25, 0, 0, 0, 0, time.UTC)
	c, err := NewCoordinator(CoordinatorOptions{Repository: repo, Directory: rawProfileDirectory{profile: ready}, Starter: &fakeStarter{}, Sessions: &fakeSessions{}, Endpoints: NewEndpointAuthorizer(), Clock: func() time.Time { return now }, ID: ids.Next, PolicyVersion: "policy-1", BatchCaps: limits()})
	if err != nil {
		t.Fatal(err)
	}
	binding, err := c.RegisterRoot(context.Background(), "ready-root", "ready-session", "ready-attempt", "ready-peer", "L1", "ready-workspace")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = c.ProposeSpawn(context.Background(), request(binding, proposal(), "ready-spawn")); !errors.Is(err, ErrDenied) {
		t.Fatalf("Coordinator trusted ready-only directory entry: %v", err)
	}
}

func TestSendAndSteerNeverDispatchWithoutDurableReceipt(t *testing.T) {
	for _, operation := range []string{"send", "steer"} {
		t.Run(operation, func(t *testing.T) {
			c, binding, _, repo, _ := setup(t, testProfile(true))
			child, err := c.ProposeSpawn(context.Background(), request(binding, proposal(), "receipt-"+operation))
			if err != nil {
				t.Fatal(err)
			}
			sessions := c.sessions.(*fakeSessions)
			conflicts := &conflictCASRepository{inner: repo}
			c.repo = conflicts
			req := OperationRequest{Target: TargetRequest{Endpoint: EndpointRequest{EndpointID: binding.EndpointID, PeerID: binding.PeerID, Audience: "mesh", Nonce: "receipt-" + operation + "-call"}, TargetRunID: child.RunID, Operation: operation}, InputRef: "input-1"}
			digest, err := req.Digest()
			if err != nil {
				t.Fatal(err)
			}
			req.Target.Endpoint.MessageDigest = digest
			if operation == "send" {
				err = c.Send(context.Background(), req)
			} else {
				err = c.Steer(context.Background(), req)
			}
			if !errors.Is(err, ErrVersionConflict) {
				t.Fatalf("receipt CAS exhaustion=%v", err)
			}
			if conflicts.calls != 8 || sessions.sends != 0 || sessions.steers != 0 {
				t.Fatalf("provider dispatched without durable receipt: calls=%d sessions=%+v", conflicts.calls, sessions)
			}
		})
	}
}

func TestLegacyReceiptMigrationConflictNeverDispatches(t *testing.T) {
	for _, operation := range []string{"send", "steer"} {
		t.Run(operation, func(t *testing.T) {
			c, binding, _, repo, _ := setup(t, testProfile(true))
			child, err := c.ProposeSpawn(context.Background(), request(binding, proposal(), "legacy-conflict-"+operation))
			if err != nil {
				t.Fatal(err)
			}
			inputRef := "input-1"
			key := operation + ":" + binding.EndpointID + ":" + child.RunID + ":" + inputRef
			snapshot, err := repo.Load(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			next := snapshot.clone()
			next.SendReceipts[key] = SendReceipt{CallerRunID: child.RunID, TargetRunID: child.RunID, InputRef: inputRef, Digest: legacySendReceiptDigest(child.RunID, operation, inputRef), State: "sent"}
			if err = repo.CompareAndSwap(context.Background(), snapshot, next); err != nil {
				t.Fatal(err)
			}
			sessions := c.sessions.(*fakeSessions)
			conflicts := &conflictCASRepository{inner: repo}
			c.repo = conflicts
			req := OperationRequest{Target: TargetRequest{Endpoint: EndpointRequest{EndpointID: binding.EndpointID, PeerID: binding.PeerID, Audience: "mesh", Nonce: "legacy-conflict-" + operation + "-call"}, TargetRunID: child.RunID, Operation: operation}, InputRef: inputRef}
			digest, err := req.Digest()
			if err != nil {
				t.Fatal(err)
			}
			req.Target.Endpoint.MessageDigest = digest
			if operation == "send" {
				err = c.Send(context.Background(), req)
			} else {
				err = c.Steer(context.Background(), req)
			}
			if !errors.Is(err, ErrVersionConflict) || conflicts.calls != 8 || sessions.sends != 0 || sessions.steers != 0 {
				t.Fatalf("legacy migration dispatched or hid conflict: err=%v calls=%d sessions=%+v", err, conflicts.calls, sessions)
			}
		})
	}
}

func TestSendAndSteerFinalizationConflictsRequireReconciliation(t *testing.T) {
	for _, operation := range []string{"send", "steer"} {
		t.Run(operation, func(t *testing.T) {
			c, binding, _, repo, _ := setup(t, testProfile(true))
			child, err := c.ProposeSpawn(context.Background(), request(binding, proposal(), "finalize-"+operation))
			if err != nil {
				t.Fatal(err)
			}
			sessions := c.sessions.(*fakeSessions)
			conflicts := &conflictCASRepository{inner: repo, allow: 1}
			c.repo = conflicts
			req := OperationRequest{Target: TargetRequest{Endpoint: EndpointRequest{EndpointID: binding.EndpointID, PeerID: binding.PeerID, Audience: "mesh", Nonce: "finalize-" + operation + "-call"}, TargetRunID: child.RunID, Operation: operation}, InputRef: "input-1"}
			digest, err := req.Digest()
			if err != nil {
				t.Fatal(err)
			}
			req.Target.Endpoint.MessageDigest = digest
			if operation == "send" {
				err = c.Send(context.Background(), req)
			} else {
				err = c.Steer(context.Background(), req)
			}
			if !errors.Is(err, ErrReconciliationNeeded) || conflicts.calls != 9 {
				t.Fatalf("post-dispatch conflict was not explicit reconciliation: err=%v calls=%d", err, conflicts.calls)
			}
			if (operation == "send" && sessions.sends != 1) || (operation == "steer" && sessions.steers != 1) {
				t.Fatalf("expected exactly one provider dispatch: %+v", sessions)
			}
			snapshot, err := repo.Load(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			receipt := snapshot.SendReceipts[inputReceiptKey(binding, child.RunID, operation, "input-1")]
			if receipt.State != "pending" {
				t.Fatalf("finalization conflict rewrote receipt: %+v", receipt)
			}
		})
	}
}

func TestCancelFinalizationConflictsRequireReconciliation(t *testing.T) {
	c, binding, _, repo, _ := setup(t, testProfile(true))
	child, err := c.ProposeSpawn(context.Background(), request(binding, proposal(), "finalize-cancel"))
	if err != nil {
		t.Fatal(err)
	}
	sessions := c.sessions.(*fakeSessions)
	// The pending cancel receipt/revocation is durable before the native call;
	// only its post-effect finalization conflicts here.
	conflicts := &conflictCASRepository{inner: repo, allow: 1}
	c.repo = conflicts
	req := OperationRequest{Target: TargetRequest{Endpoint: EndpointRequest{EndpointID: binding.EndpointID, PeerID: binding.PeerID, Audience: "mesh", Nonce: "finalize-cancel-call"}, TargetRunID: child.RunID, Operation: "cancel"}, RevisionRef: "revision-1", ReasonRef: "reason-1"}
	digest, err := req.Digest()
	if err != nil {
		t.Fatal(err)
	}
	req.Target.Endpoint.MessageDigest = digest
	if err = c.Cancel(context.Background(), req); !errors.Is(err, ErrReconciliationNeeded) {
		t.Fatalf("cancel finalization conflict=%v", err)
	}
	if conflicts.calls != 2 || sessions.cancels != 1 || sessions.cancelRef != "reason-1" {
		t.Fatalf("cancel finalization lost semantics: calls=%d sessions=%+v", conflicts.calls, sessions)
	}
	snapshot := mustSnapshot(t, repo)
	if receipt := snapshot.CancelReceipts[cancelReceiptKey(binding.EndpointID, binding.Generation, child.RunID)]; receipt.State != "pending" {
		t.Fatalf("post-effect conflict rewrote cancel receipt: %+v", receipt)
	}
	for endpointID, endpoint := range snapshot.EndpointBindings {
		if endpoint.RunID == child.RunID && !snapshot.EndpointRevoked[endpointID] {
			t.Fatalf("target endpoint remained usable after uncertain cancel: %s", endpointID)
		}
	}
}
func TestSpawnBatchAdmissionIsAtomicAndRetriesDurably(t *testing.T) {
	c, b, s, repo, _ := setup(t, testProfile(true))
	p1 := proposal()
	p1.ClientNonce = "batch-1"
	p2 := proposal()
	p2.ClientNonce = "batch-2"
	requestBatch := func(nonce string) BatchProposalRequest {
		q := []SpawnProposal{p1, p2}
		return BatchProposalRequest{Endpoint: EndpointRequest{EndpointID: b.EndpointID, PeerID: b.PeerID, Audience: "mesh", Nonce: nonce, MessageDigest: hash(q)}, Proposals: q}
	}
	bad := requestBatch("batch-call-1")
	bad.Proposals[1].PreferredProfile = "missing"
	bad.Endpoint.MessageDigest = hash(bad.Proposals)
	if _, err := c.ProposeSpawnBatch(context.Background(), bad); !errors.Is(err, ErrDenied) {
		t.Fatalf("bad batch=%v", err)
	}
	snap, err := repo.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.Runs) != 1 || len(snap.Batches) != 0 {
		t.Fatalf("partial admission %#v", snap)
	}
	got, err := c.ProposeSpawnBatch(context.Background(), requestBatch("batch-call-2"))
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Results) != 2 || s.calls != 2 {
		t.Fatalf("batch=%#v starts=%d", got, s.calls)
	}
	again, err := c.ProposeSpawnBatch(context.Background(), requestBatch("batch-call-3"))
	if err != nil {
		t.Fatal(err)
	}
	if !again.Results[0].Replayed || again.BatchID != got.BatchID || s.calls != 2 {
		t.Fatalf("retry %#v starts=%d", again, s.calls)
	}
}
func TestBatchSnapshotRejectsMalformedAttemptAndPendingReplay(t *testing.T) {
	s := emptySnapshot()
	s.Batches["batch-key"] = BatchRecord{Key: "batch-key", BatchID: "batch-1", Digest: hash("batch"), State: "admitted", Attempts: []BatchAttemptOutcome{{Status: "started", RecoveryState: "active"}}}
	if s.Validate() == nil {
		t.Fatal("malformed attempt accepted")
	}
	c, b, _, repo, _ := setup(t, testProfile(true))
	p := proposal()
	p.ClientNonce = "pending-batch"
	q := []SpawnProposal{p}
	key := hash(fmt.Sprintf("%d:%s:%s:%s", b.Generation, b.SessionID, b.AttemptID, hash(q)))
	old, err := repo.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	next := old.clone()
	scope := fmt.Sprintf("%d:%s:%s:%s", b.Generation, b.SessionID, b.AttemptID, p.ClientNonce)
	proposalKey := hash(scope + ":" + hash(p))
	run := Run{ID: "pending-run", RootID: b.RootRunID, ParentRunID: b.RunID, ParentSessionID: b.SessionID, SessionID: "pending-session", AttemptID: "pending-attempt", ProfileID: "profile-a", Provider: "qwen", Classification: "L1", WorkspaceGroupID: "workspace-1", Depth: 1, State: RunAdmitted, CreatedAt: time.Now()}
	next.Runs[run.ID] = run
	next.NonceScopes[scope] = proposalKey
	next.Proposals[proposalKey] = ProposalRecord{Key: proposalKey, Scope: scope, Digest: hash(p), BatchID: "batch-pending", ProposalID: "pending-proposal", RunID: run.ID, SessionID: run.SessionID, OrderID: "pending-order", BindingID: "pending-binding", State: "pending", CreatedAt: time.Now()}
	next.Batches[key] = BatchRecord{Key: key, BatchID: "batch-pending", Digest: hash(q), State: "pending", ProposalKeys: []string{proposalKey}, CreatedAt: time.Now()}
	if err = repo.CompareAndSwap(context.Background(), old, next); err != nil {
		t.Fatal(err)
	}
	if _, err = c.ProposeSpawnBatch(context.Background(), BatchProposalRequest{Endpoint: EndpointRequest{EndpointID: b.EndpointID, PeerID: b.PeerID, Audience: "mesh", Nonce: "pending-call", MessageDigest: hash(q)}, Proposals: q}); !errors.Is(err, ErrReconciliationNeeded) {
		t.Fatalf("pending replay=%v", err)
	}
}

func TestSnapshotValidateRejectsForgedBatchReferences(t *testing.T) {
	c, b, _, repo, _ := setup(t, testProfile(true))
	q := batchProposals()
	if _, err := c.ProposeSpawnBatch(context.Background(), batchRequest(b, q, "batch-validation-call")); err != nil {
		t.Fatal(err)
	}
	base := mustSnapshot(t, repo)
	if err := base.Validate(); err != nil {
		t.Fatalf("baseline=%v", err)
	}
	var batchKey string
	for key := range base.Batches {
		batchKey = key
	}
	tests := []struct {
		name string
		edit func(*Snapshot)
	}{
		{"duplicate proposal key", func(s *Snapshot) {
			b := s.Batches[batchKey]
			b.ProposalKeys = append(b.ProposalKeys, b.ProposalKeys[0])
			s.Batches[batchKey] = b
		}},
		{"orphan proposal key", func(s *Snapshot) {
			b := s.Batches[batchKey]
			b.ProposalKeys[0] = "missing-proposal"
			s.Batches[batchKey] = b
		}},
		{"proposal batch mismatch", func(s *Snapshot) {
			b := s.Batches[batchKey]
			p := s.Proposals[b.ProposalKeys[0]]
			p.BatchID = "other-batch"
			s.Proposals[p.Key] = p
		}},
		{"attempt duplicate run", func(s *Snapshot) {
			b := s.Batches[batchKey]
			b.Attempts = append(b.Attempts, b.Attempts[0])
			s.Batches[batchKey] = b
		}},
		{"attempt foreign run", func(s *Snapshot) {
			b := s.Batches[batchKey]
			b.Attempts[0].RunID = "foreign-run"
			s.Batches[batchKey] = b
		}},
		{"attempt invalid evidence", func(s *Snapshot) { b := s.Batches[batchKey]; b.Attempts[0].StartReceipt = ""; s.Batches[batchKey] = b }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := base.clone()
			tt.edit(&s)
			if !errors.Is(s.Validate(), ErrInvalidContract) {
				t.Fatal("forged batch accepted")
			}
		})
	}
}

func TestBatchFinalizerNilStarterTerminalizesEveryMemberAndReplays(t *testing.T) {
	c, b, starter, repo, _ := setup(t, testProfile(true))
	c.starter = nil
	q := batchProposals()
	got, err := c.ProposeSpawnBatch(context.Background(), batchRequest(b, q, "nil-starter-call"))
	if !errors.Is(err, ErrStartUncertain) || !errors.Is(err, ErrReconciliationNeeded) || !got.Partial {
		t.Fatalf("result=%#v err=%v", got, err)
	}
	s, err := repo.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	batch := s.Batches[batchRecordKey(b, hash(q))]
	if batch.State != "uncertain" || len(batch.Attempts) != len(q) {
		t.Fatalf("batch=%#v", batch)
	}
	for _, key := range batch.ProposalKeys {
		p := s.Proposals[key]
		if p.State != "terminal" || s.Runs[p.RunID].State != RunUncertain {
			t.Fatalf("unfinalized member proposal=%#v run=%#v", p, s.Runs[p.RunID])
		}
	}
	again, err := c.ProposeSpawnBatch(context.Background(), batchRequest(b, q, "nil-starter-retry"))
	if !errors.Is(err, ErrReconciliationNeeded) || again.BatchID != "" || starter.calls != 0 {
		t.Fatalf("replay=%#v err=%v starts=%d", again, err, starter.calls)
	}
}

func TestBatchFinalizerCompensatesStartedAndTerminalizesUntouched(t *testing.T) {
	c, b, starter, repo, _ := setup(t, testProfile(true))
	starter.fail = errors.New("second start fails")
	starter.failAt = 2
	q := batchProposals()
	got, err := c.ProposeSpawnBatch(context.Background(), batchRequest(b, q, "partial-call"))
	if err != nil || !got.Partial {
		t.Fatalf("result=%#v err=%v", got, err)
	}
	s := mustSnapshot(t, repo)
	batch := s.Batches[batchRecordKey(b, hash(q))]
	if batch.State != "partial" || len(batch.Attempts) != 2 {
		t.Fatalf("batch=%#v", batch)
	}
	if s.Runs[got.Results[0].RunID].State != RunCancelled || s.Runs[got.Results[1].RunID].State != RunFailed {
		t.Fatalf("runs=%#v", s.Runs)
	}
	if c.sessions.(*fakeSessions).cancels != 1 {
		t.Fatalf("compensations=%d", c.sessions.(*fakeSessions).cancels)
	}
	assertRunEndpointsRevoked(t, s, got.Results[0].RunID)
	if s.EndpointRevoked[b.EndpointID] {
		t.Fatal("batch compensation revoked the caller/root endpoint")
	}
	again, err := c.ProposeSpawnBatch(context.Background(), batchRequest(b, q, "partial-retry"))
	if err != nil || !again.Partial || starter.calls != 2 {
		t.Fatalf("replay=%#v err=%v starts=%d", again, err, starter.calls)
	}
}

func TestBatchFinalizerPreservesUncertainWhenCompensationFails(t *testing.T) {
	c, b, starter, repo, _ := setup(t, testProfile(true))
	starter.fail = errors.New("second start fails")
	starter.failAt = 2
	c.sessions.(*fakeSessions).cancelErr = errors.New("cancel unavailable")
	q := batchProposals()
	got, err := c.ProposeSpawnBatch(context.Background(), batchRequest(b, q, "cancel-failure-call"))
	if err != nil || !got.Partial {
		t.Fatalf("result=%#v err=%v", got, err)
	}
	s := mustSnapshot(t, repo)
	batch := s.Batches[batchRecordKey(b, hash(q))]
	if batch.State != "uncertain" || s.Runs[got.Results[0].RunID].State != RunUncertain || s.Runs[got.Results[1].RunID].State != RunFailed {
		t.Fatalf("batch=%#v runs=%#v", batch, s.Runs)
	}
	if len(batch.Attempts) != 2 || batch.Attempts[0].CompensationStatus != "failed" {
		t.Fatalf("attempts=%#v", batch.Attempts)
	}
}

func TestBatchFinalizerEndpointRegisterFailureCompensates(t *testing.T) {
	c, b, starter, repo, _ := setup(t, testProfile(true))
	starter.onStart = func(r StartRequest) {
		old, err := repo.Load(context.Background())
		if err != nil {
			t.Fatalf("load in starter hook: %v", err)
		}
		next := old.clone()
		next.EndpointBindings[r.Binding.EndpointID] = MeshEndpointBinding{SchemaVersion: EndpointBindingV1, EndpointID: r.Binding.EndpointID, Audience: "mesh", RootRunID: r.Order.RootRunID, RunID: r.Order.RunID, SessionID: r.Order.SessionID, AttemptID: r.Order.AttemptID, AllowedOperations: append([]string(nil), r.Order.Effective.Tools...), ToolDigest: hash(sortedStrings(r.Order.Effective.Tools)), PeerID: "broker:" + r.Order.SessionID, PolicyVersion: r.Order.PolicyVersion, IssuedAt: r.Binding.IssuedAt, ExpiresAt: r.Binding.ExpiresAt, Generation: r.Binding.Generation}
		if err = repo.CompareAndSwap(context.Background(), old, next); err != nil {
			t.Fatalf("seed endpoint collision: %v", err)
		}
	}
	q := batchProposals()
	got, err := c.ProposeSpawnBatch(context.Background(), batchRequest(b, q, "endpoint-failure-call"))
	if err != nil || !got.Partial {
		t.Fatalf("result=%#v err=%v", got, err)
	}
	s := mustSnapshot(t, repo)
	batch := s.Batches[batchRecordKey(b, hash(q))]
	if batch.State != "partial" || s.Runs[got.Results[0].RunID].State != RunCancelled || s.Runs[got.Results[1].RunID].State != RunCancelled {
		t.Fatalf("batch=%#v runs=%#v", batch, s.Runs)
	}
	if c.sessions.(*fakeSessions).cancels != 1 || starter.calls != 1 {
		t.Fatalf("compensation=%d starts=%d", c.sessions.(*fakeSessions).cancels, starter.calls)
	}
	assertRunEndpointsRevoked(t, s, got.Results[0].RunID)
	if s.EndpointRevoked[b.EndpointID] {
		t.Fatal("endpoint issue failure revoked caller/root endpoint")
	}
}

func TestBatchStartReceiptCommitUncertaintyCompensatesAndReplayDoesNotRestart(t *testing.T) {
	c, b, starter, repo, _ := setup(t, testProfile(true))
	c.repo = &uncertainCASRepository{inner: repo, failAt: 2} // admission succeeds; first receipt CAS is uncertain.
	q := batchProposals()
	got, err := c.ProposeSpawnBatch(context.Background(), batchRequest(b, q, "receipt-uncertain-call"))
	if !errors.Is(err, ErrCommitUncertain) || !got.Partial || starter.calls != 1 || c.sessions.(*fakeSessions).cancels != 1 {
		t.Fatalf("result=%#v err=%v starts=%d cancels=%d", got, err, starter.calls, c.sessions.(*fakeSessions).cancels)
	}
	if err = c.Replay(context.Background()); !errors.Is(err, ErrReconciliationNeeded) {
		t.Fatalf("replay=%v", err)
	}
	if _, err = c.ProposeSpawnBatch(context.Background(), batchRequest(b, q, "receipt-uncertain-retry")); !errors.Is(err, ErrRepositoryPoisoned) || starter.calls != 1 {
		t.Fatalf("retry=%v starts=%d", err, starter.calls)
	}
}

func TestBatchFinalStateCommitUncertaintyCompensatesAllStartedSessions(t *testing.T) {
	c, b, starter, repo, _ := setup(t, testProfile(true))
	// admission=1, first receipt=2, second receipt=3, batch admitted=4.
	c.repo = &uncertainCASRepository{inner: repo, failAt: 4}
	q := batchProposals()
	got, err := c.ProposeSpawnBatch(context.Background(), batchRequest(b, q, "final-state-uncertain-call"))
	if !errors.Is(err, ErrCommitUncertain) || !got.Partial || starter.calls != 2 || c.sessions.(*fakeSessions).cancels != 2 {
		t.Fatalf("result=%#v err=%v starts=%d cancels=%d", got, err, starter.calls, c.sessions.(*fakeSessions).cancels)
	}
	if err = c.Replay(context.Background()); !errors.Is(err, ErrReconciliationNeeded) {
		t.Fatalf("replay=%v", err)
	}
	if err = c.ReloadAndReplay(context.Background()); !errors.Is(err, ErrReconciliationNeeded) || !c.poisoned.Load() {
		t.Fatalf("unsafe reload cleared poison: err=%v poisoned=%v", err, c.poisoned.Load())
	}
	s := mustSnapshot(t, repo)
	// The first child completed its atomic endpoint+Running CAS before the
	// final batch-state uncertainty and is durably revoked by compensation. The
	// second Start was tracked but its provider-reference CAS was uncertain, so
	// it never reached endpoint issuance; a safe journal must not invent a
	// revoked phantom capability for it.
	assertRunEndpointsRevoked(t, s, got.Results[0].RunID)
	for endpointID, endpoint := range s.EndpointBindings {
		if endpoint.RunID == got.Results[1].RunID {
			t.Fatalf("uncertain pre-issue child unexpectedly retained endpoint %q", endpointID)
		}
	}
	if s.EndpointRevoked[b.EndpointID] {
		t.Fatal("batch final uncertainty revoked caller/root endpoint")
	}
}

func TestPostStartDurabilityFailuresCompensateWithoutMintingEndpoint(t *testing.T) {
	tests := []struct {
		name  string
		nonce string
		wrap  func(Repository) Repository
	}{
		{"provider-reference load", "post-start-load", func(repo Repository) Repository {
			return &failLoadRepository{inner: repo, failAt: 2, err: errors.New("journal unavailable")}
		}},
		{"provider-reference cas exhaustion", "post-start-conflict", func(repo Repository) Repository { return &conflictCASRepository{inner: repo, allow: 1} }},
		{"provider-reference commit uncertain", "post-start-uncertain", func(repo Repository) Repository { return &uncertainCASRepository{inner: repo, failAt: 2} }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, binding, starter, repo, _ := setup(t, testProfile(true))
			c.repo = tt.wrap(repo)
			_, err := c.ProposeSpawn(context.Background(), request(binding, proposal(), tt.nonce))
			if !errors.Is(err, ErrReconciliationNeeded) || starter.calls != 1 {
				t.Fatalf("start durability failure was not reconciliation: err=%v starts=%d", err, starter.calls)
			}
			sessions := c.sessions.(*fakeSessions)
			if sessions.cancels != 1 || sessions.cancelRevision != "" || sessions.cancelRef != "start_commit_failed" {
				t.Fatalf("provider start was not exactly compensated: %+v", sessions)
			}
			s := mustSnapshot(t, repo)
			if len(s.EndpointBindings) != 1 || s.EndpointRevoked[binding.EndpointID] {
				t.Fatalf("undurable start minted/revoked wrong endpoint: bindings=%#v revoked=%#v", s.EndpointBindings, s.EndpointRevoked)
			}
		})
	}
}

func TestFinalRunningCommitFailureRevokesMintedChildEndpoint(t *testing.T) {
	c, binding, starter, repo, _ := setup(t, testProfile(true))
	// admission=1, durable provider reference=2, final Running transition=3.
	c.repo = &uncertainCASRepository{inner: repo, failAt: 3}
	_, err := c.ProposeSpawn(context.Background(), request(binding, proposal(), "final-running-uncertain"))
	if !errors.Is(err, ErrReconciliationNeeded) || starter.calls != 1 {
		t.Fatalf("final transition claimed success: err=%v starts=%d", err, starter.calls)
	}
	sessions := c.sessions.(*fakeSessions)
	if sessions.cancels != 1 || sessions.cancelRevision != "" || sessions.cancelRef != "start_commit_failed" {
		t.Fatalf("final transition did not compensate start: %+v", sessions)
	}
	s := mustSnapshot(t, repo)
	childEndpoints := 0
	for endpointID, endpoint := range s.EndpointBindings {
		if endpoint.RunID != binding.RunID {
			childEndpoints++
			if !s.EndpointRevoked[endpointID] {
				t.Fatalf("minted child endpoint remained active after failed final commit: %s", endpointID)
			}
		}
	}
	if childEndpoints != 0 || s.EndpointRevoked[binding.EndpointID] {
		t.Fatalf("failed final commit left child/root endpoint state unsafe: child=%d revoked=%#v", childEndpoints, s.EndpointRevoked)
	}
}

func TestFinalRunningLoadFailureCompensatesAndKeepsRootUsable(t *testing.T) {
	c, binding, starter, repo, _ := setup(t, testProfile(true))
	// admission load=1, provider-reference load=2, final Running load=3.
	c.repo = &failLoadRepository{inner: repo, failAt: 3, err: errors.New("journal unavailable")}
	_, err := c.ProposeSpawn(context.Background(), request(binding, proposal(), "final-running-load"))
	if !errors.Is(err, ErrReconciliationNeeded) || starter.calls != 1 || c.sessions.(*fakeSessions).cancels != 1 {
		t.Fatalf("final load failure claimed success: err=%v starts=%d sessions=%+v", err, starter.calls, c.sessions)
	}
	s := mustSnapshot(t, repo)
	var childID string
	for endpointID, endpoint := range s.EndpointBindings {
		if endpoint.RunID != binding.RunID {
			childID = endpointID
		}
	}
	if childID != "" || s.EndpointRevoked[binding.EndpointID] {
		t.Fatalf("final load failure endpoint state=%#v", s.EndpointRevoked)
	}
	if _, err = c.EndpointBinding(context.Background(), binding.EndpointID); err != nil {
		t.Fatalf("root endpoint was not usable after child final-load compensation: %v", err)
	}
	if _, err = c.ProposeSpawn(context.Background(), request(binding, proposal(), "final-running-load-retry")); !errors.Is(err, ErrReconciliationNeeded) || starter.calls != 1 {
		t.Fatalf("uncertain single-run replay claimed success/restarted: err=%v starts=%d", err, starter.calls)
	}
}

func TestCancelReceiptExactlyOnceAndStateGate(t *testing.T) {
	c, binding, _, repo, _ := setup(t, testProfile(true))
	child, err := c.ProposeSpawn(context.Background(), request(binding, proposal(), "cancel-once-spawn"))
	if err != nil {
		t.Fatal(err)
	}
	sessions := c.sessions.(*fakeSessions)
	first := lifecycleOperation(t, binding, child.RunID, "cancel", "revision-1", "reason-1", "cancel-once-1")
	if err = c.Cancel(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	if sessions.cancels != 1 || sessions.cancelRevision != "revision-1" || sessions.cancelRef != "reason-1" {
		t.Fatalf("cancel dispatch=%+v", sessions)
	}
	replay := lifecycleOperation(t, binding, child.RunID, "cancel", "revision-1", "reason-1", "cancel-once-2")
	if err = c.Cancel(context.Background(), replay); err != nil || sessions.cancels != 1 {
		t.Fatalf("exact replay dispatched or failed: err=%v sessions=%+v", err, sessions)
	}
	changed := lifecycleOperation(t, binding, child.RunID, "cancel", "revision-1", "reason-2", "cancel-once-3")
	if err = c.Cancel(context.Background(), changed); !errors.Is(err, ErrIdempotencyConflict) || sessions.cancels != 1 {
		t.Fatalf("changed cancellation receipt was accepted: err=%v sessions=%+v", err, sessions)
	}
	s := mustSnapshot(t, repo)
	receipt := s.CancelReceipts[cancelReceiptKey(binding.EndpointID, binding.Generation, child.RunID)]
	if receipt.State != "cancelled" || receipt.Digest != cancelReceiptDigest(binding.EndpointID, binding.Generation, child.RunID, "revision-1", "reason-1") || s.Runs[child.RunID].State != RunCancelled {
		t.Fatalf("cancel receipt/state=%+v run=%+v", receipt, s.Runs[child.RunID])
	}
	for endpointID, endpoint := range s.EndpointBindings {
		if endpoint.RunID == child.RunID && !s.EndpointRevoked[endpointID] {
			t.Fatalf("cancelled target endpoint remained active: %s", endpointID)
		}
	}
	if s.EndpointRevoked[binding.EndpointID] {
		t.Fatal("caller/root endpoint was revoked by target cancel")
	}
	if err = c.Send(context.Background(), lifecycleOperation(t, binding, child.RunID, "send", "input-after-cancel", "", "cancel-once-send")); !errors.Is(err, ErrDenied) {
		t.Fatalf("terminal target accepted input: %v", err)
	}
}

func TestCancelProviderErrorStaysUncertainAndNeverRedispatches(t *testing.T) {
	c, binding, _, repo, _ := setup(t, testProfile(true))
	child, err := c.ProposeSpawn(context.Background(), request(binding, proposal(), "cancel-error-spawn"))
	if err != nil {
		t.Fatal(err)
	}
	sessions := c.sessions.(*fakeSessions)
	sessions.cancelErr = errors.New("provider timeout")
	req := lifecycleOperation(t, binding, child.RunID, "cancel", "revision-1", "reason-1", "cancel-error-1")
	if err = c.Cancel(context.Background(), req); !errors.Is(err, ErrReconciliationNeeded) || sessions.cancels != 1 {
		t.Fatalf("provider cancel error was not uncertain: err=%v sessions=%+v", err, sessions)
	}
	s := mustSnapshot(t, repo)
	if s.Runs[child.RunID].State != RunUncertain || s.CancelReceipts[cancelReceiptKey(binding.EndpointID, binding.Generation, child.RunID)].State != "uncertain" {
		t.Fatalf("provider cancel error lost uncertainty: run=%+v receipt=%+v", s.Runs[child.RunID], s.CancelReceipts)
	}
	if err = c.Cancel(context.Background(), lifecycleOperation(t, binding, child.RunID, "cancel", "revision-1", "reason-1", "cancel-error-2")); !errors.Is(err, ErrReconciliationNeeded) || sessions.cancels != 1 {
		t.Fatalf("uncertain cancellation re-dispatched: err=%v sessions=%+v", err, sessions)
	}
}

func TestDurableControlFenceOrdersInputAndCancellation(t *testing.T) {
	waitEntered := func(t *testing.T, entered <-chan struct{}) {
		t.Helper()
		select {
		case <-entered:
		case <-time.After(2 * time.Second):
			t.Fatal("provider operation did not enter")
		}
	}

	t.Run("cancel first blocks input", func(t *testing.T) {
		c, binding, _, repo, _ := setup(t, testProfile(true))
		child, err := c.ProposeSpawn(context.Background(), request(binding, proposal(), "fence-cancel-spawn"))
		if err != nil {
			t.Fatal(err)
		}
		sessions := c.sessions.(*fakeSessions)
		sessions.cancelEntered, sessions.cancelRelease = make(chan struct{}), make(chan struct{})
		entered, release := sessions.cancelEntered, sessions.cancelRelease
		cancelDone := make(chan error, 1)
		cancelReq := lifecycleOperation(t, binding, child.RunID, "cancel", "revision-1", "reason-1", "fence-cancel-first")
		go func() { cancelDone <- c.Cancel(context.Background(), cancelReq) }()
		waitEntered(t, entered)
		snapshot := mustSnapshot(t, repo)
		key := cancelReceiptKey(binding.EndpointID, binding.Generation, child.RunID)
		receipt := snapshot.CancelReceipts[key]
		if receipt.State != "pending" || snapshot.Runs[child.RunID].ControlFence != cancelControlFence(receipt.Digest) {
			t.Fatalf("Cancel did not durably fence before provider dispatch: receipt=%+v run=%+v", receipt, snapshot.Runs[child.RunID])
		}
		sendReq := lifecycleOperation(t, binding, child.RunID, "send", "input-after-cancel-fence", "", "fence-send-after-cancel")
		if err = c.Send(context.Background(), sendReq); !errors.Is(err, ErrReconciliationNeeded) {
			t.Fatalf("Send crossed pending Cancel fence: %v", err)
		}
		sessions.mu.Lock()
		sends := sessions.sends
		sessions.mu.Unlock()
		if sends != 0 {
			t.Fatal("Send reached provider after Cancel receipt persisted")
		}
		close(release)
		if err = <-cancelDone; err != nil {
			t.Fatalf("fenced Cancel failed: %v", err)
		}
		snapshot = mustSnapshot(t, repo)
		if snapshot.Runs[child.RunID].State != RunCancelled || snapshot.Runs[child.RunID].ControlFence != "" {
			t.Fatalf("Cancel finalization retained fence: %+v", snapshot.Runs[child.RunID])
		}
	})

	t.Run("input first blocks cancel", func(t *testing.T) {
		c, binding, _, repo, _ := setup(t, testProfile(true))
		child, err := c.ProposeSpawn(context.Background(), request(binding, proposal(), "fence-input-spawn"))
		if err != nil {
			t.Fatal(err)
		}
		sessions := c.sessions.(*fakeSessions)
		sessions.sendEntered, sessions.sendRelease = make(chan struct{}), make(chan struct{})
		entered, release := sessions.sendEntered, sessions.sendRelease
		sendDone := make(chan error, 1)
		sendReq := lifecycleOperation(t, binding, child.RunID, "send", "input-before-cancel", "", "fence-input-first")
		go func() { sendDone <- c.Send(context.Background(), sendReq) }()
		waitEntered(t, entered)
		snapshot := mustSnapshot(t, repo)
		receipt := snapshot.SendReceipts[inputReceiptKey(binding, child.RunID, "send", "input-before-cancel")]
		if receipt.State != "pending" || snapshot.Runs[child.RunID].ControlFence != inputControlFence(receipt.Digest) {
			t.Fatalf("Send did not durably fence before provider dispatch: receipt=%+v run=%+v", receipt, snapshot.Runs[child.RunID])
		}
		cancelReq := lifecycleOperation(t, binding, child.RunID, "cancel", "revision-1", "reason-1", "fence-cancel-after-input")
		if err = c.Cancel(context.Background(), cancelReq); !errors.Is(err, ErrReconciliationNeeded) {
			t.Fatalf("Cancel crossed pending input fence: %v", err)
		}
		sessions.mu.Lock()
		cancels := sessions.cancels
		sessions.mu.Unlock()
		if cancels != 0 {
			t.Fatal("Cancel reached provider while Send was pending")
		}
		close(release)
		if err = <-sendDone; err != nil {
			t.Fatalf("fenced Send failed: %v", err)
		}
		snapshot = mustSnapshot(t, repo)
		if snapshot.Runs[child.RunID].ControlFence != "" || snapshot.SendReceipts[inputReceiptKey(binding, child.RunID, "send", "input-before-cancel")].State != "sent" {
			t.Fatalf("Send finalization retained fence: run=%+v receipts=%+v", snapshot.Runs[child.RunID], snapshot.SendReceipts)
		}
		if err = c.Cancel(context.Background(), lifecycleOperation(t, binding, child.RunID, "cancel", "revision-1", "reason-1", "fence-cancel-retry")); err != nil {
			t.Fatalf("Cancel did not proceed after input fence cleared: %v", err)
		}
	})
}

// TestBlockingProviderControlReleasesCoordinatorMutex proves that the durable
// control fence, rather than the in-process mutex, orders a provider call
// against lifecycle safety operations.  Once Send has persisted its pending
// fence, CloseRootEndpoint must promptly report the reconciliation boundary and
// RevokeEndpoint must still be able to make its monotone durable change while
// the native provider call remains blocked.
func TestBlockingProviderControlReleasesCoordinatorMutex(t *testing.T) {
	c, binding, _, repo, _ := setup(t, testProfile(true))
	child, err := c.ProposeSpawn(context.Background(), request(binding, proposal(), "blocked-control-spawn"))
	if err != nil {
		t.Fatal(err)
	}
	sessions := c.sessions.(*fakeSessions)
	sessions.sendEntered, sessions.sendRelease = make(chan struct{}), make(chan struct{})
	entered, release := sessions.sendEntered, sessions.sendRelease
	sendDone := make(chan error, 1)
	sendReq := lifecycleOperation(t, binding, child.RunID, "send", "blocked-control-input", "", "blocked-control-send")
	go func() {
		sendDone <- c.Send(context.Background(), sendReq)
	}()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("provider Send did not enter")
	}

	closeDone := make(chan error, 1)
	go func() { closeDone <- c.CloseRootEndpoint(context.Background(), binding) }()
	select {
	case err = <-closeDone:
		if !errors.Is(err, ErrReconciliationNeeded) {
			t.Fatalf("root close crossed pending Send fence: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("root close waited on blocked provider Send")
	}

	snapshot := mustSnapshot(t, repo)
	var childEndpoint MeshEndpointBinding
	for _, endpoint := range snapshot.EndpointBindings {
		if endpoint.RunID == child.RunID {
			childEndpoint = endpoint
			break
		}
	}
	if childEndpoint.EndpointID == "" {
		t.Fatal("missing child endpoint")
	}
	revokeDone := make(chan error, 1)
	go func() {
		revokeDone <- c.RevokeEndpoint(context.Background(), childEndpoint.EndpointID, childEndpoint.Generation)
	}()
	select {
	case err = <-revokeDone:
		if err != nil {
			t.Fatalf("endpoint revoke waited for or failed during blocked Send: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("endpoint revoke waited on blocked provider Send")
	}
	if !mustSnapshot(t, repo).EndpointRevoked[childEndpoint.EndpointID] {
		t.Fatal("endpoint revoke was not durable")
	}

	close(release)
	if err = <-sendDone; err != nil {
		t.Fatalf("Send failed after release: %v", err)
	}
}

func TestCancelNeverDispatchesWithoutDurablePendingReceipt(t *testing.T) {
	c, binding, _, repo, _ := setup(t, testProfile(true))
	child, err := c.ProposeSpawn(context.Background(), request(binding, proposal(), "cancel-pending-spawn"))
	if err != nil {
		t.Fatal(err)
	}
	conflicts := &conflictCASRepository{inner: repo}
	c.repo = conflicts
	req := lifecycleOperation(t, binding, child.RunID, "cancel", "revision-1", "reason-1", "cancel-pending-call")
	if err = c.Cancel(context.Background(), req); !errors.Is(err, ErrVersionConflict) || c.sessions.(*fakeSessions).cancels != 0 || conflicts.calls != 8 {
		t.Fatalf("cancel dispatched without pending receipt: err=%v calls=%d sessions=%+v", err, conflicts.calls, c.sessions)
	}
	if len(mustSnapshot(t, repo).CancelReceipts) != 0 {
		t.Fatal("failed pending receipt write left a fabricated durable receipt")
	}
}

func TestCancelPostEffectDurabilityFailuresNeverRedispatch(t *testing.T) {
	tests := []struct {
		name  string
		nonce string
		wrap  func(Repository) Repository
	}{
		// authorizeTargetLineage and prepareCancel each load before the native
		// call; finalizeCancel's read is the third durable load.
		{"final load", "cancel-post-load", func(repo Repository) Repository {
			return &failLoadRepository{inner: repo, failAt: 3, err: errors.New("journal unavailable")}
		}},
		{"final commit uncertain", "cancel-post-uncertain", func(repo Repository) Repository { return &uncertainCASRepository{inner: repo, failAt: 2} }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, binding, _, repo, _ := setup(t, testProfile(true))
			child, err := c.ProposeSpawn(context.Background(), request(binding, proposal(), tt.nonce))
			if err != nil {
				t.Fatal(err)
			}
			c.repo = tt.wrap(repo)
			sessions := c.sessions.(*fakeSessions)
			req := lifecycleOperation(t, binding, child.RunID, "cancel", "revision-1", "reason-1", "cancel-post-1")
			if err = c.Cancel(context.Background(), req); !errors.Is(err, ErrReconciliationNeeded) || sessions.cancels != 1 {
				t.Fatalf("post-effect %s returned unsafe result: err=%v sessions=%+v", tt.name, err, sessions)
			}
			s := mustSnapshot(t, repo)
			if receipt := s.CancelReceipts[cancelReceiptKey(binding.EndpointID, binding.Generation, child.RunID)]; receipt.State != "pending" {
				t.Fatalf("post-effect %s finalized unproven receipt: %+v", tt.name, receipt)
			}
			assertRunEndpointsRevoked(t, s, child.RunID)
			// A fresh authenticated retry sees the pending receipt. It must not
			// issue another native cancel even when the earlier final read/CAS
			// outcome was unavailable or uncertain.
			if err = c.Cancel(context.Background(), lifecycleOperation(t, binding, child.RunID, "cancel", "revision-1", "reason-1", "cancel-post-2")); sessions.cancels != 1 {
				t.Fatalf("post-effect %s re-dispatched provider cancel: err=%v sessions=%+v", tt.name, err, sessions)
			}
			if tt.name == "final load" && !errors.Is(err, ErrReconciliationNeeded) {
				t.Fatalf("pending cancel replay=%v", err)
			}
			if tt.name == "final commit uncertain" && !errors.Is(err, ErrRepositoryPoisoned) {
				t.Fatalf("poisoned cancel replay=%v", err)
			}
		})
	}
}

func TestAuthorizeTargetStateMatrixAndTerminalObservation(t *testing.T) {
	for _, observation := range []string{"status", "wait", "result", "collect"} {
		t.Run(observation, func(t *testing.T) {
			c, binding, _, repo, _ := setup(t, testProfile(true))
			child, err := c.ProposeSpawn(context.Background(), request(binding, proposal(), "observe-"+observation))
			if err != nil {
				t.Fatal(err)
			}
			for _, operation := range []string{"send", "steer", "cancel"} {
				if _, err = c.AuthorizeTarget(context.Background(), directTarget(binding, child.RunID, operation, "matrix-live-"+observation+"-"+operation)); err != nil {
					t.Fatalf("live %s denied: %v", operation, err)
				}
			}
			sessions := c.sessions.(*fakeSessions)
			sessions.status = SessionStatus{State: "completed", UsageSource: "provider"}
			sessions.waitStatus = SessionStatus{State: "completed", UsageSource: "provider"}
			sessions.result = ResultEnvelope{RunID: child.RunID, AttemptID: "mesh-005", Status: "completed", OutputArtifactRef: "artifact-1", SchemaRef: "result-v1", ProvenanceDigest: hash("prov"), Classification: "L1"}
			switch observation {
			case "status":
				_, err = c.Status(context.Background(), lifecycleOperation(t, binding, child.RunID, "status", "revision-1", "", "observe-status-call"))
			case "wait":
				_, err = c.Wait(context.Background(), lifecycleOperation(t, binding, child.RunID, "wait", "revision-1", "", "observe-wait-call"))
			case "result":
				_, err = c.Result(context.Background(), lifecycleOperation(t, binding, child.RunID, "result", "revision-1", "", "observe-result-call"))
			case "collect":
				_, err = c.Collect(context.Background(), lifecycleOperation(t, binding, child.RunID, "collect", "revision-1", "", "observe-collect-call"))
			}
			if err != nil {
				t.Fatalf("terminal %s observation=%v", observation, err)
			}
			s := mustSnapshot(t, repo)
			if s.Runs[child.RunID].State != RunCompleted {
				t.Fatalf("terminal %s did not persist completion: %+v", observation, s.Runs[child.RunID])
			}
			for endpointID, endpoint := range s.EndpointBindings {
				if endpoint.RunID == child.RunID && !s.EndpointRevoked[endpointID] {
					t.Fatalf("terminal %s left child endpoint active: %s", observation, endpointID)
				}
			}
			if s.EndpointRevoked[binding.EndpointID] {
				t.Fatalf("terminal %s revoked caller/root endpoint", observation)
			}
			for _, operation := range []string{"send", "steer", "cancel"} {
				if _, err = c.AuthorizeTarget(context.Background(), directTarget(binding, child.RunID, operation, "matrix-terminal-"+observation+"-"+operation)); !errors.Is(err, ErrDenied) {
					t.Fatalf("terminal %s accepted %s: %v", observation, operation, err)
				}
			}
			for _, operation := range []string{"status", "wait", "result", "collect"} {
				if _, err = c.AuthorizeTarget(context.Background(), directTarget(binding, child.RunID, operation, "matrix-observe-"+observation+"-"+operation)); err != nil {
					t.Fatalf("terminal %s denied observation %s: %v", observation, operation, err)
				}
			}
		})
	}
}

func TestLostStartAcknowledgementPersistsSingleRunUncertain(t *testing.T) {
	c, binding, starter, repo, _ := setup(t, testProfile(true))
	starter.fail = errors.Join(ErrStartUncertain, ErrReconciliationNeeded)
	p := proposal()
	if _, err := c.ProposeSpawn(context.Background(), request(binding, p, "lost-start-ack")); !errors.Is(err, ErrStartUncertain) || !errors.Is(err, ErrReconciliationNeeded) {
		t.Fatalf("ambiguous Start did not return typed uncertainty: %v", err)
	}
	if starter.calls != 1 {
		t.Fatalf("ambiguous Start dispatched %d times", starter.calls)
	}
	snapshot := mustSnapshot(t, repo)
	var child Run
	for _, run := range snapshot.Runs {
		if run.ID != binding.RunID {
			child = run
		}
	}
	if child.ID == "" || child.State != RunUncertain || child.ProviderSessionID != "" {
		t.Fatalf("ambiguous Start was claimed failed/running: %+v", child)
	}
	for endpointID, endpoint := range snapshot.EndpointBindings {
		if endpoint.RunID == child.ID && !snapshot.EndpointRevoked[endpointID] {
			t.Fatalf("ambiguous Start exposed child endpoint %s", endpointID)
		}
	}
	if _, err := c.ProposeSpawn(context.Background(), request(binding, p, "lost-start-replay")); !errors.Is(err, ErrReconciliationNeeded) || starter.calls != 1 {
		t.Fatalf("ambiguous Start replayed native work: err=%v starts=%d", err, starter.calls)
	}
	if err := c.ReloadAndReplay(context.Background()); !errors.Is(err, ErrReconciliationNeeded) {
		t.Fatalf("uncertain Start did not block reload: %v", err)
	}
}

func TestLostBatchStartAcknowledgementNeverCompensatesUnprovenSession(t *testing.T) {
	c, binding, starter, repo, _ := setup(t, testProfile(true))
	starter.fail = errors.Join(ErrStartUncertain, ErrReconciliationNeeded)
	result, err := c.ProposeSpawnBatch(context.Background(), batchRequest(binding, batchProposals(), "lost-batch-start-ack"))
	if !errors.Is(err, ErrStartUncertain) || !errors.Is(err, ErrReconciliationNeeded) || !result.Partial {
		t.Fatalf("ambiguous batch Start result=%+v err=%v", result, err)
	}
	if starter.calls != 1 || c.sessions.(*fakeSessions).cancels != 0 {
		t.Fatalf("unproven batch Start was retried/compensated: starts=%d cancels=%d", starter.calls, c.sessions.(*fakeSessions).cancels)
	}
	snapshot := mustSnapshot(t, repo)
	for _, member := range result.Results {
		run := snapshot.Runs[member.RunID]
		if run.State != RunUncertain || run.ProviderSessionID != "" {
			t.Fatalf("batch member claimed a proven terminal outcome: %+v", run)
		}
	}
}

func TestAmbiguousInputControlRevokesTargetAndNeverRedispatches(t *testing.T) {
	for _, operation := range []string{"send", "steer"} {
		t.Run(operation, func(t *testing.T) {
			c, binding, _, repo, ids := setup(t, testProfile(true))
			child, err := c.ProposeSpawn(context.Background(), request(binding, proposal(), "control-uncertain-spawn-"+operation))
			if err != nil {
				t.Fatal(err)
			}
			sessions := c.sessions.(*fakeSessions)
			if operation == "send" {
				sessions.sendErr = errors.Join(ErrControlUncertain, ErrReconciliationNeeded)
			} else {
				sessions.steerErr = errors.Join(ErrControlUncertain, ErrReconciliationNeeded)
			}
			first := lifecycleOperation(t, binding, child.RunID, operation, "input-1", "", "control-uncertain-first-"+operation)
			if operation == "send" {
				err = c.Send(context.Background(), first)
			} else {
				err = c.Steer(context.Background(), first)
			}
			if !errors.Is(err, ErrControlUncertain) || !errors.Is(err, ErrReconciliationNeeded) {
				t.Fatalf("ambiguous %s did not return typed uncertainty: %v", operation, err)
			}
			snapshot := mustSnapshot(t, repo)
			receipt := snapshot.SendReceipts[inputReceiptKey(binding, child.RunID, operation, "input-1")]
			if receipt.State != "uncertain" || snapshot.Runs[child.RunID].State != RunUncertain {
				t.Fatalf("ambiguous %s receipt/run=%+v/%+v", operation, receipt, snapshot.Runs[child.RunID])
			}
			assertRunEndpointsRevoked(t, snapshot, child.RunID)
			before := sessions.sends + sessions.steers
			replay := lifecycleOperation(t, binding, child.RunID, operation, "input-1", "", "control-uncertain-replay-"+operation)
			if operation == "send" {
				err = c.Send(context.Background(), replay)
			} else {
				err = c.Steer(context.Background(), replay)
			}
			if err == nil || sessions.sends+sessions.steers != before {
				t.Fatalf("ambiguous %s replay dispatched: err=%v sessions=%+v", operation, err, sessions)
			}
			different := lifecycleOperation(t, binding, child.RunID, operation, "input-2", "", "control-uncertain-different-"+operation)
			if operation == "send" {
				err = c.Send(context.Background(), different)
			} else {
				err = c.Steer(context.Background(), different)
			}
			if err == nil || sessions.sends+sessions.steers != before {
				t.Fatalf("different input reached uncertain target: err=%v sessions=%+v", err, sessions)
			}

			directory, err := NewStaticDirectory(testProfile(true))
			if err != nil {
				t.Fatal(err)
			}
			restarted, err := NewCoordinator(CoordinatorOptions{Repository: repo, Directory: directory, Starter: &fakeStarter{}, Sessions: sessions, Endpoints: NewEndpointAuthorizer(), Clock: c.now, ID: ids.Next, PolicyVersion: "policy-1", BatchCaps: c.batchCaps})
			if err != nil {
				t.Fatal(err)
			}
			if err = restarted.ReloadAndReplay(context.Background()); !errors.Is(err, ErrReconciliationNeeded) {
				t.Fatalf("restart ignored uncertain %s receipt: %v", operation, err)
			}
		})
	}
}

func TestPolicyRotationRejectsEveryStaleEndpointPathBeforeNonceConsumption(t *testing.T) {
	cA, oldBinding, _, repo, _ := setup(t, testProfile(true))
	child, err := cA.ProposeSpawn(context.Background(), request(oldBinding, proposal(), "policy-a-spawn"))
	if err != nil {
		t.Fatal(err)
	}
	directory, err := NewStaticDirectory(testProfile(true))
	if err != nil {
		t.Fatal(err)
	}
	idsB := &sequenceIDs{n: 100}
	cB, err := NewCoordinator(CoordinatorOptions{Repository: repo, Directory: directory, Starter: &fakeStarter{}, Sessions: &fakeSessions{}, Endpoints: NewEndpointAuthorizer(), Clock: cA.now, ID: idsB.Next, PolicyVersion: "policy-2", BatchCaps: cA.batchCaps})
	if err != nil {
		t.Fatal(err)
	}
	if err := cB.ReloadAndReplay(context.Background()); err != nil {
		t.Fatalf("explicit route recovery failed: %v", err)
	}

	nonces := []string{}
	assertUnauthorized := func(name, nonce string, call func() error) {
		t.Helper()
		nonces = append(nonces, nonce)
		if err := call(); !errors.Is(err, ErrUnauthorized) {
			t.Fatalf("stale policy %s err=%v", name, err)
		}
	}
	assertUnauthorized("spawn", "stale-spawn", func() error {
		_, err := cB.ProposeSpawn(context.Background(), request(oldBinding, proposal(), "stale-spawn"))
		return err
	})
	assertUnauthorized("spawnBatch", "stale-batch", func() error {
		_, err := cB.ProposeSpawnBatch(context.Background(), batchRequest(oldBinding, batchProposals(), "stale-batch"))
		return err
	})
	for _, operation := range []string{"send", "steer", "cancel", "status", "wait", "result", "collect", "list"} {
		operation := operation
		nonce := "stale-" + operation
		assertUnauthorized(operation, nonce, func() error {
			r := lifecycleOperation(t, oldBinding, child.RunID, operation, "revision-1", "reason-1", nonce)
			switch operation {
			case "send":
				return cB.Send(context.Background(), r)
			case "steer":
				return cB.Steer(context.Background(), r)
			case "cancel":
				return cB.Cancel(context.Background(), r)
			case "status":
				_, err := cB.Status(context.Background(), r)
				return err
			case "wait":
				_, err := cB.Wait(context.Background(), r)
				return err
			case "result":
				_, err := cB.Result(context.Background(), r)
				return err
			case "collect":
				_, err := cB.Collect(context.Background(), r)
				return err
			default:
				_, err := cB.List(context.Background(), r)
				return err
			}
		})
	}
	assertUnauthorized("AuthorizeTarget", "stale-target", func() error {
		_, err := cB.AuthorizeTarget(context.Background(), directTarget(oldBinding, child.RunID, "status", "stale-target"))
		return err
	})
	assertUnauthorized("listProfiles", "stale-profiles", func() error {
		revision := "revision-1"
		r := ListProfilesRequest{Endpoint: EndpointRequest{EndpointID: oldBinding.EndpointID, PeerID: oldBinding.PeerID, Audience: "mesh", Nonce: "stale-profiles", MessageDigest: hash("listProfiles:" + revision)}, RevisionRef: revision}
		_, err := cB.ListProfiles(context.Background(), r)
		return err
	})
	if _, err := cB.EndpointBinding(context.Background(), oldBinding.EndpointID); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("stale policy UI binding was exposed: %v", err)
	}
	snapshot := mustSnapshot(t, repo)
	for _, nonce := range nonces {
		key := oldBinding.EndpointID + ":" + fmt.Sprint(oldBinding.Generation) + ":" + nonce
		if snapshot.EndpointNonces[key] {
			t.Fatalf("stale-policy denial consumed nonce %q", nonce)
		}
	}
	if err := cB.RevokeEndpoint(context.Background(), oldBinding.EndpointID, oldBinding.Generation); err != nil {
		t.Fatalf("policy rotation blocked monotone stale endpoint revoke: %v", err)
	}
	newBinding, err := cB.RegisterRoot(context.Background(), "policy-b-root", "policy-b-session", "policy-b-attempt", "policy-b-peer", "L1", "policy-b-workspace")
	if err != nil {
		t.Fatal(err)
	}
	if got, err := cB.EndpointBinding(context.Background(), newBinding.EndpointID); err != nil || got.PolicyVersion != "policy-2" {
		t.Fatalf("new policy binding unusable: binding=%+v err=%v", got, err)
	}
	revision := "revision-b"
	profilesReq := ListProfilesRequest{Endpoint: EndpointRequest{EndpointID: newBinding.EndpointID, PeerID: newBinding.PeerID, Audience: "mesh", Nonce: "policy-b-profiles", MessageDigest: hash("listProfiles:" + revision)}, RevisionRef: revision}
	if profiles, err := cB.ListProfiles(context.Background(), profilesReq); err != nil || len(profiles) != 1 {
		t.Fatalf("new policy endpoint failed: profiles=%+v err=%v", profiles, err)
	}
}

func TestRevokeEndpointRequiresExactGeneration(t *testing.T) {
	c, binding, _, repo, _ := setup(t, testProfile(true))
	if err := c.RevokeEndpoint(context.Background(), binding.EndpointID, binding.Generation+1); !errors.Is(err, ErrDenied) {
		t.Fatalf("generation mismatch=%v", err)
	}
	if err := c.RevokeEndpoint(context.Background(), binding.EndpointID, binding.Generation); err != nil {
		t.Fatal(err)
	}
	if err := c.RevokeEndpoint(context.Background(), binding.EndpointID, binding.Generation); err != nil {
		t.Fatalf("exact revoke was not idempotent: %v", err)
	}
	if !mustSnapshot(t, repo).EndpointRevoked[binding.EndpointID] {
		t.Fatal("exact endpoint revoke was not durable")
	}
}

func TestRestartWithRunningProviderChildRequiresExplicitRouteRecoveryProof(t *testing.T) {
	c, root, _, repo, ids := setup(t, testProfile(true))
	child, err := c.ProposeSpawn(context.Background(), request(root, proposal(), "restart-provider-child"))
	if err != nil {
		t.Fatal(err)
	}
	snapshot := mustSnapshot(t, repo)
	if snapshot.Runs[child.RunID].State != RunRunning || snapshot.Runs[child.RunID].ProviderSessionID == "" {
		t.Fatalf("test fixture did not retain a running provider child: %+v", snapshot.Runs[child.RunID])
	}
	directory, err := NewStaticDirectory(testProfile(true))
	if err != nil {
		t.Fatal(err)
	}

	// A fresh SessionController with no durable route proof must not make the
	// persisted child look controllable merely because it is marked Running.
	restarted, err := NewCoordinator(CoordinatorOptions{Repository: repo, Directory: directory, Starter: &fakeStarter{}, Sessions: unverifiedSessions{sessions: &fakeSessions{}}, Endpoints: NewEndpointAuthorizer(), Clock: c.now, ID: ids.Next, PolicyVersion: "policy-1", BatchCaps: c.batchCaps})
	if err != nil {
		t.Fatal(err)
	}
	if err := restarted.ReloadAndReplay(context.Background()); !errors.Is(err, ErrReconciliationNeeded) {
		t.Fatalf("restart without route recovery proof cleared poison: %v", err)
	}
	if _, err := restarted.RegisterRoot(context.Background(), "root-restart", "session-restart", "attempt-restart", "peer-restart", "L1", "workspace-restart"); !errors.Is(err, ErrRepositoryPoisoned) {
		t.Fatalf("restart without route recovery proof admitted work: %v", err)
	}

	// An explicit verifier is the only constructor-level way to make the same
	// durable running child eligible for normal route-specific handling.
	verifiedSessions := &fakeSessions{}
	verified, err := NewCoordinator(CoordinatorOptions{Repository: repo, Directory: directory, Starter: &fakeStarter{}, Sessions: verifiedSessions, Endpoints: NewEndpointAuthorizer(), Clock: c.now, ID: ids.Next, PolicyVersion: "policy-1", BatchCaps: c.batchCaps})
	if err != nil {
		t.Fatal(err)
	}
	if len(verifiedSessions.recoveries) != 0 {
		t.Fatal("constructor performed external recovery")
	}
	if err := verified.ReloadAndReplay(context.Background()); err != nil {
		t.Fatalf("explicit route recovery proof did not permit replay: %v", err)
	}
	if len(verifiedSessions.recoveries) != 1 || verifiedSessions.recoveries[0].ProviderSessionID != snapshot.Runs[child.RunID].ProviderSessionID || !verifiedSessions.recoveries[0].Start.SealValid() || verifiedSessions.recoveries[0].Start.Order.RunID != child.RunID {
		t.Fatalf("recovery projection was not exact: %+v", verifiedSessions.recoveries)
	}
}

func TestPersistedRecoveryRejectsDuplicateRouteBeforeVerifier(t *testing.T) {
	c, root, _, repo, _ := setup(t, testProfile(true))
	firstProposal := proposal()
	firstProposal.ClientNonce = "recovery-first"
	first, err := c.ProposeSpawn(context.Background(), request(root, firstProposal, "recovery-first-request"))
	if err != nil {
		t.Fatal(err)
	}
	secondProposal := proposal()
	secondProposal.ClientNonce = "recovery-second"
	second, err := c.ProposeSpawn(context.Background(), request(root, secondProposal, "recovery-second-request"))
	if err != nil {
		t.Fatal(err)
	}
	snapshot := mustSnapshot(t, repo)
	run := snapshot.Runs[second.RunID]
	run.ProviderSessionID = snapshot.Runs[first.RunID].ProviderSessionID
	snapshot.Runs[second.RunID] = run
	sessions := &fakeSessions{}
	if recoverPersistedSessionRoutes(context.Background(), snapshot, sessions) || len(sessions.recoveries) != 0 {
		t.Fatalf("duplicate route reached verifier: %+v", sessions.recoveries)
	}
}

func TestRootEndpointRotationAndPoisonedCloseRemainExact(t *testing.T) {
	c, binding, _, repo, _ := setup(t, testProfile(true))
	rotated, err := c.RotateRootEndpoint(context.Background(), binding)
	if err != nil {
		t.Fatal(err)
	}
	if rotated.EndpointID == binding.EndpointID || rotated.Generation != binding.Generation+1 || rotated.RootRunID != binding.RootRunID || rotated.RunID != binding.RunID || rotated.PeerID != binding.PeerID {
		t.Fatalf("root rotation changed identity instead of only endpoint generation: old=%+v new=%+v", binding, rotated)
	}
	snapshot := mustSnapshot(t, repo)
	if !snapshot.EndpointRevoked[binding.EndpointID] || snapshot.EndpointRevoked[rotated.EndpointID] {
		t.Fatalf("root rotation revoke state=%+v", snapshot.EndpointRevoked)
	}
	if _, err = c.EndpointBinding(context.Background(), binding.EndpointID); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("stale root endpoint remained exposed: %v", err)
	}
	if current, err := c.EndpointBinding(context.Background(), rotated.EndpointID); err != nil || current.Generation != rotated.Generation {
		t.Fatalf("rotated endpoint not available for signed UI association: binding=%+v err=%v", current, err)
	}
	if replay, err := c.RotateRootEndpoint(context.Background(), binding); err != nil || replay.EndpointID != rotated.EndpointID || replay.Generation != rotated.Generation {
		t.Fatalf("exact root rotation retry did not return its sole successor: replay=%+v err=%v", replay, err)
	}
	forged := rotated
	forged.PeerID = "foreign-peer"
	if err = c.CloseRootEndpoint(context.Background(), forged); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("forged root close accepted: %v", err)
	}
	// Ordinary effects are poisoned, but exact lifecycle revocation must still
	// consume the reserved monotone safety transition.
	c.poisoned.Store(true)
	if err = c.CloseRootEndpoint(context.Background(), rotated); err != nil {
		t.Fatalf("poisoned exact root close failed: %v", err)
	}
	snapshot = mustSnapshot(t, repo)
	if !snapshot.EndpointRevoked[rotated.EndpointID] {
		t.Fatal("poisoned root close was not durable")
	}
}

func assertRunEndpointsRevoked(t *testing.T, snapshot Snapshot, runIDs ...string) {
	t.Helper()
	want := make(map[string]struct{}, len(runIDs))
	for _, runID := range runIDs {
		want[runID] = struct{}{}
	}
	seen := make(map[string]bool, len(want))
	for endpointID, binding := range snapshot.EndpointBindings {
		if _, target := want[binding.RunID]; !target {
			continue
		}
		seen[binding.RunID] = true
		if !snapshot.EndpointRevoked[endpointID] {
			t.Fatalf("run %s endpoint %s remained active", binding.RunID, endpointID)
		}
	}
	for runID := range want {
		if !seen[runID] {
			t.Fatalf("run %s did not have the expected registered child endpoint", runID)
		}
	}
}

func mustSnapshot(t *testing.T, repo Repository) Snapshot {
	t.Helper()
	s, err := repo.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return s
}
