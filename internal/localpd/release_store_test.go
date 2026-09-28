package localpd

// This synthetic-only transaction is deliberately test-local. Production has
// no mintable release authority until DR-020 supplies an attested durable
// transaction that provides the same re-read/CAS guarantees.

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

type testReleaseFault uint8

const (
	testReleaseNoFault testReleaseFault = iota
	testReleaseAfterReservation
	testReleaseAfterDecisionConsume
	testReleaseAfterIdentityCreation
)

type testReleaseAuthorityTransaction struct {
	mu           sync.Mutex
	state        map[string]ReleaseLifecycle
	receipts     map[string]ReleaseReceipt
	identities   map[string]CleanCloudIdentity
	current      CurrentReleaseState
	authority    SignatureVerifier
	postscan     PostscanResolver
	consumer     DeclassificationConsumer
	now          func() time.Time
	fault        testReleaseFault
	beforeCommit func()
	closed       bool
}

func newTestReleaseAuthorityTransaction() *testReleaseAuthorityTransaction {
	return &testReleaseAuthorityTransaction{
		state:      map[string]ReleaseLifecycle{},
		receipts:   map[string]ReleaseReceipt{},
		identities: map[string]CleanCloudIdentity{},
		now:        func() time.Time { return time.Now().UTC().Truncate(time.Second) },
	}
}

func (t *testReleaseAuthorityTransaction) CurrentReleaseState(context.Context, ReleaseLineage) (CurrentReleaseState, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return CurrentReleaseState{}, ErrReleaseStale
	}
	return t.current, nil
}

func (t *testReleaseAuthorityTransaction) Reconcile(context.Context) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return ErrReleaseUncertain
	}
	for id, s := range t.state {
		if s == ReleaseConsuming {
			t.state[id] = ReleaseUncertain
		}
	}
	return nil
}

func (t *testReleaseAuthorityTransaction) Close() {
	t.mu.Lock()
	t.closed = true
	t.mu.Unlock()
}

func testStateMatchesLineage(s CurrentReleaseState, l ReleaseLineage) bool {
	return s.GateDigest == l.GateDigest && s.SessionDigest == l.SessionDigest && s.PolicyDigest == l.PolicyDigest && s.HighWater == l.HighWater && s.SourceVersion == l.SourceVersion && s.RevisionSetDigest == l.RevisionSetDigest && s.CoverageDigest == l.CoverageDigest && s.ConfigDigest == l.ConfigDigest && s.Class == l.Class && s.Complete && s.GapsClosed && !s.Revoked && !s.Deleted
}

func (t *testReleaseAuthorityTransaction) Commit(_ context.Context, expected CurrentReleaseState, lineage ReleaseLineage, d DeclassificationDecision, b []byte, proof OwnerAuthProof, post PostscanAttestation) (CleanCloudIdentity, ReleaseReceipt, error) {
	// This hook is a test barrier: it fires only after the coordinator has
	// fetched its pre-commit state, proving Commit consults its own current
	// authority rather than trusting that snapshot.
	t.mu.Lock()
	barrier := t.beforeCommit
	t.beforeCommit = nil
	t.mu.Unlock()
	if barrier != nil {
		barrier()
	}

	t.mu.Lock()
	defer t.mu.Unlock()
	current := t.current // authoritative re-read under this transaction CAS lock
	if t.closed || current != expected || !testStateMatchesLineage(current, lineage) {
		return CleanCloudIdentity{}, ReleaseReceipt{}, ErrReleaseStale
	}
	if len(b) == 0 || digestContent(b) != d.ReleasedDigest || d.InputDigest != d.ReleasedDigest || d.CandidateDigest != d.ReleasedDigest || proof.Digest != d.RecentAuthProofDigest || proof.OwnerID != d.ApproverID || proof.AuthContextDigest != d.AuthContextDigest || post.Digest != d.PostscanAttestationDigest || post.ReleasedDigest != d.ReleasedDigest || post.PolicyDigest != d.PolicyDigest || t.authority == nil || t.postscan == nil || t.consumer == nil {
		return CleanCloudIdentity{}, ReleaseReceipt{}, ErrReleaseInput
	}
	if t.state[d.DecisionID] != "" {
		return CleanCloudIdentity{}, ReleaseReceipt{}, ErrReleaseUsed
	}
	t.state[d.DecisionID] = ReleaseConsuming
	if t.fault == testReleaseAfterReservation {
		t.state[d.DecisionID] = ReleaseUncertain
		return CleanCloudIdentity{}, ReleaseReceipt{}, ErrReleaseUncertain
	}
	if err := d.Authorize(t.now(), t.authority, t.postscan, t.consumer); err != nil {
		t.state[d.DecisionID] = ReleaseUncertain
		return CleanCloudIdentity{}, ReleaseReceipt{}, ErrReleaseInput
	}
	if t.fault == testReleaseAfterDecisionConsume {
		t.state[d.DecisionID] = ReleaseUncertain
		return CleanCloudIdentity{}, ReleaseReceipt{}, ErrReleaseUncertain
	}
	id, err := newIdentityID()
	if err != nil {
		t.state[d.DecisionID] = ReleaseUncertain
		return CleanCloudIdentity{}, ReleaseReceipt{}, ErrReleaseRandom
	}
	identity := CleanCloudIdentity{IdentityID: id, Payload: append([]byte(nil), b...), Destination: d.DestinationRoute, Provider: d.ProviderDigest, RetentionDigest: d.RetentionPolicyDigest, PurposeDigest: d.PurposeDigest}
	t.identities[id] = identity
	if t.fault == testReleaseAfterIdentityCreation {
		delete(t.identities, id)
		t.state[d.DecisionID] = ReleaseUncertain
		return CleanCloudIdentity{}, ReleaseReceipt{}, ErrReleaseUncertain
	}
	receipt := ReleaseReceipt{DecisionID: d.DecisionID, IdentityID: id, ReleasedDigest: d.ReleasedDigest, State: ReleaseConsumed, IssuedAt: t.now()}
	t.receipts[d.DecisionID] = receipt
	t.state[d.DecisionID] = ReleaseConsumed
	return identity, receipt, nil
}

func TestSyntheticReleaseTransactionReconcilesStrandedConsumption(t *testing.T) {
	x := newTestReleaseAuthorityTransaction()
	x.state["d"] = ReleaseConsuming
	if err := x.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if x.state["d"] != ReleaseUncertain {
		t.Fatalf("state=%s", x.state["d"])
	}
	x.Close()
	if err := x.Reconcile(context.Background()); !errors.Is(err, ErrReleaseUncertain) {
		t.Fatalf("closed reconcile=%v", err)
	}
}
