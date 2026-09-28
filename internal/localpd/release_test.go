package localpd

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

type releaseInputVerifier struct {
	ok     bool
	native NativeEditorAttestation
}

func (v releaseInputVerifier) VerifyManualKeyboard(string, uint64) bool { return v.ok }
func (v releaseInputVerifier) VerifyNativeEditor(a NativeEditorAttestation) bool {
	return v.ok && a == v.native
}

type releaseAuthority struct{}

func (releaseAuthority) Verify([]byte, string) bool { return true }

type releaseAuth struct {
	proof OwnerAuthProof
	err   error
}

func (a releaseAuth) Authenticate(context.Context) (OwnerAuthProof, error) { return a.proof, a.err }

type releasePostscan struct {
	value PostscanAttestation
	err   error
}

func (r releasePostscan) ResolvePostscan(digest string) (PostscanAttestation, error) {
	if r.err != nil || digest != r.value.Digest {
		return PostscanAttestation{}, errors.New("postscan is not authoritative")
	}
	return r.value, nil
}

type releaseFixture struct {
	now      time.Time
	input    ManualReleaseInput
	decision DeclassificationDecision
	lineage  ReleaseLineage
	state    CurrentReleaseState
	view     *LocalPDViewManager
	tx       *testReleaseAuthorityTransaction
	coord    *ManualReleaseCoordinator
}

type malformedReleaseTransaction struct {
	ReleaseAuthorityTransaction
	mutate func(*CleanCloudIdentity, *ReleaseReceipt)
}

func (t malformedReleaseTransaction) Commit(ctx context.Context, state CurrentReleaseState, lineage ReleaseLineage, d DeclassificationDecision, input []byte, proof OwnerAuthProof, postscan PostscanAttestation) (CleanCloudIdentity, ReleaseReceipt, error) {
	identity, receipt, err := t.ReleaseAuthorityTransaction.Commit(ctx, state, lineage, d, input, proof, postscan)
	if err == nil {
		t.mutate(&identity, &receipt)
	}
	return identity, receipt, err
}

func sealDecision(t *testing.T, d DeclassificationDecision) DeclassificationDecision {
	t.Helper()
	b, err := d.CanonicalUnsigned()
	if err != nil {
		t.Fatal(err)
	}
	d.Digest, err = CanonicalDigest(json.RawMessage(b))
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func releaseHappyFixture(t *testing.T) releaseFixture {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	inputBytes := []byte("the exact owner-entered release bytes")
	released := digestContent(inputBytes)
	lineage := ReleaseLineage{ViewID: "view-1", GateDigest: testDigest, SessionDigest: testDigest, PolicyDigest: testDigest, HighWater: 7, SourceVersion: 3, RevisionSetDigest: testDigest, CoverageDigest: testDigest, ConfigDigest: testDigest, Class: "L2"}
	state := CurrentReleaseState{GateDigest: lineage.GateDigest, SessionDigest: lineage.SessionDigest, PolicyDigest: lineage.PolicyDigest, HighWater: lineage.HighWater, SourceVersion: lineage.SourceVersion, RevisionSetDigest: lineage.RevisionSetDigest, CoverageDigest: lineage.CoverageDigest, ConfigDigest: lineage.ConfigDigest, Class: lineage.Class, Complete: true, GapsClosed: true}
	view := newLocalPDViewManagerWithAuthority(viewAuthorityFixture{})
	issue := signedViewIssue(LocalPDViewIssue{ViewID: lineage.ViewID, BindingVersion: 1, HighWater: lineage.HighWater, SourceVersion: lineage.SourceVersion, SourceDigest: testDigest, RedactionDigest: testDigest, GateDigest: lineage.GateDigest, SessionDigest: lineage.SessionDigest, PolicyDigest: lineage.PolicyDigest, CoverageDigest: lineage.CoverageDigest, Class: lineage.Class, AllowedFields: []string{"summary"}, IssuedAt: now, TTL: time.Minute, Nonce: "nonce", ControllerSignature: testDigest})
	if _, err := view.Issue(issue); err != nil {
		t.Fatal(err)
	}
	post := validContracts()[8].(PostscanAttestation)
	post.ReleasedDigest, post.PolicyDigest = released, lineage.PolicyDigest
	post.IssuedAt, post.ExpiresAt = now.Add(-time.Minute), now.Add(time.Minute)
	post = seal(t, post, func(x PostscanAttestation, d string) PostscanAttestation { x.Digest = d; return x })
	d := validContracts()[6].(DeclassificationDecision)
	d.SessionBindingDigest, d.PolicyDigest = lineage.SessionDigest, lineage.PolicyDigest
	d.InputDigest, d.CandidateDigest, d.ReleasedDigest = released, released, released
	d.PostscanAttestationDigest = post.Digest
	d.IssuedAt, d.RequestedAt, d.RecentAuthAt, d.ApprovedAt, d.ExpiresAt = now.Add(-4*time.Minute), now.Add(-3*time.Minute), now.Add(-2*time.Minute), now.Add(-time.Minute), now.Add(time.Minute)
	d = sealDecision(t, d)
	if err := d.Validate(); err != nil {
		t.Fatalf("fixture decision invalid: %v", err)
	}
	if err := post.Validate(); err != nil {
		t.Fatalf("fixture postscan invalid: %v", err)
	}
	attestation := NativeEditorAttestation{EditorID: "native-editor-1", EventID: "event-1", Revision: 1, ByteDigest: released, GenesisBlank: true, AppendOnly: true, InputKind: ManualKeyboardProvenance}
	input := ManualReleaseInput{Bytes: inputBytes, Provenance: ManualKeyboardProvenance, EditorID: attestation.EditorID, Revision: attestation.Revision, EditorStartedBlank: true, Attestation: attestation}
	tx := newTestReleaseAuthorityTransaction()
	tx.current, tx.authority, tx.postscan, tx.consumer = state, releaseAuthority{}, releasePostscan{value: post}, NewMemoryDeclassificationConsumer()
	tx.now = func() time.Time { return now }
	coord := NewManualReleaseCoordinator(view, releaseInputVerifier{ok: true, native: attestation}, releaseAuthority{}, releaseAuth{proof: OwnerAuthProof{Digest: d.RecentAuthProofDigest, OwnerID: d.ApproverID, AuthContextDigest: d.AuthContextDigest, ChallengeDigest: testDigest, At: now}}, releasePostscan{value: post}, NewMemoryDeclassificationConsumer())
	coord.SetCurrentStateResolver(tx)
	coord.setReleaseTransaction(tx)
	return releaseFixture{now: now, input: input, decision: d, lineage: lineage, state: state, view: view, tx: tx, coord: coord}
}

func TestManualReleaseEndToEndExactCleanTuple(t *testing.T) {
	f := releaseHappyFixture(t)
	identity, err := f.coord.Release(context.Background(), f.input, f.decision, f.lineage, f.now)
	if err != nil {
		t.Fatal(err)
	}
	if identity.IdentityID == "" || string(identity.Payload) != string(f.input.Bytes) || identity.Destination != f.decision.DestinationRoute || identity.Provider != f.decision.ProviderDigest || identity.RetentionDigest != f.decision.RetentionPolicyDigest || identity.PurposeDigest != f.decision.PurposeDigest || len(identity.History) != 0 || len(identity.Attachments) != 0 || len(identity.Handles) != 0 || len(identity.IndexLineage) != 0 {
		t.Fatalf("unclean identity: %#v", identity)
	}
	receipt := f.tx.receipts[f.decision.DecisionID]
	if receipt.DecisionID != f.decision.DecisionID || receipt.IdentityID != identity.IdentityID || receipt.ReleasedDigest != f.decision.ReleasedDigest || receipt.State != ReleaseConsumed || !receipt.IssuedAt.Equal(f.now) {
		t.Fatalf("receipt=%#v", receipt)
	}
	if f.tx.state[f.decision.DecisionID] != ReleaseConsumed {
		t.Fatalf("decision state=%s", f.tx.state[f.decision.DecisionID])
	}
	if _, err := f.coord.Release(context.Background(), f.input, f.decision, f.lineage, f.now); !errors.Is(err, ErrReleaseUsed) {
		t.Fatalf("transaction replay accepted: %v", err)
	}
}

func TestManualReleaseRejectsMalformedReturnedTuple(t *testing.T) {
	mutations := []struct {
		name   string
		mutate func(*CleanCloudIdentity, *ReleaseReceipt)
	}{
		{"destination", func(i *CleanCloudIdentity, _ *ReleaseReceipt) { i.Destination = "wrong" }},
		{"provider", func(i *CleanCloudIdentity, _ *ReleaseReceipt) { i.Provider = testDigest[:len(testDigest)-1] + "0" }},
		{"retention", func(i *CleanCloudIdentity, _ *ReleaseReceipt) {
			i.RetentionDigest = testDigest[:len(testDigest)-1] + "0"
		}},
		{"purpose", func(i *CleanCloudIdentity, _ *ReleaseReceipt) { i.PurposeDigest = testDigest[:len(testDigest)-1] + "0" }},
		{"history", func(i *CleanCloudIdentity, _ *ReleaseReceipt) { i.History = []string{"history"} }},
		{"attachments", func(i *CleanCloudIdentity, _ *ReleaseReceipt) { i.Attachments = []string{"attachment"} }},
		{"handles", func(i *CleanCloudIdentity, _ *ReleaseReceipt) { i.Handles = []string{"handle"} }},
		{"index", func(i *CleanCloudIdentity, _ *ReleaseReceipt) { i.IndexLineage = []string{"index"} }},
		{"receipt", func(_ *CleanCloudIdentity, r *ReleaseReceipt) { r.ReleasedDigest = testDigest }},
	}
	for _, tt := range mutations {
		t.Run(tt.name, func(t *testing.T) {
			f := releaseHappyFixture(t)
			f.coord.setReleaseTransaction(malformedReleaseTransaction{ReleaseAuthorityTransaction: f.tx, mutate: tt.mutate})
			identity, err := f.coord.Release(context.Background(), f.input, f.decision, f.lineage, f.now)
			if !errors.Is(err, ErrReleaseUncertain) || identity.IdentityID != "" {
				t.Fatalf("malformed tuple escaped: identity=%#v err=%v", identity, err)
			}
		})
	}
}

func TestManualReleaseRejectsNonKeyboardAndPrefill(t *testing.T) {
	f := releaseHappyFixture(t)
	f.input.Provenance = PasteProvenance
	if _, err := f.coord.Release(context.Background(), f.input, f.decision, f.lineage, f.now); !errors.Is(err, ErrReleaseInput) {
		t.Fatalf("paste accepted: %v", err)
	}
	f = releaseHappyFixture(t)
	f.input.Prefilled = true
	if _, err := f.coord.Release(context.Background(), f.input, f.decision, f.lineage, f.now); !errors.Is(err, ErrReleaseInput) {
		t.Fatalf("prefill accepted: %v", err)
	}
}

func TestManualReleaseRejectsSplicedAuthAndPostscan(t *testing.T) {
	f := releaseHappyFixture(t)
	f.coord.auth = releaseAuth{proof: OwnerAuthProof{Digest: f.decision.RecentAuthProofDigest, OwnerID: f.decision.ApproverID, AuthContextDigest: testDigest[:len(testDigest)-1] + "0", At: f.now}}
	if _, err := f.coord.Release(context.Background(), f.input, f.decision, f.lineage, f.now); !errors.Is(err, ErrReleaseAuth) {
		t.Fatalf("spliced auth accepted: %v", err)
	}
	f = releaseHappyFixture(t)
	other := f.decision
	other.DecisionID, other.PostscanAttestationDigest = "decision-other", testDigest
	other = sealDecision(t, other)
	if _, err := f.coord.Release(context.Background(), f.input, other, f.lineage, f.now); !errors.Is(err, ErrReleaseInput) {
		t.Fatalf("spliced postscan accepted: %v", err)
	}
}

func TestManualReleaseCommitRereadsEveryLineageField(t *testing.T) {
	mutations := []struct {
		name   string
		mutate func(*CurrentReleaseState)
	}{
		{"gate", func(s *CurrentReleaseState) {
			s.GateDigest = "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
		}},
		{"session", func(s *CurrentReleaseState) {
			s.SessionDigest = "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
		}},
		{"policy", func(s *CurrentReleaseState) {
			s.PolicyDigest = "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
		}},
		{"high-water", func(s *CurrentReleaseState) { s.HighWater++ }},
		{"source-version", func(s *CurrentReleaseState) { s.SourceVersion++ }},
		{"revision-set", func(s *CurrentReleaseState) {
			s.RevisionSetDigest = "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
		}},
		{"coverage", func(s *CurrentReleaseState) {
			s.CoverageDigest = "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
		}},
		{"config", func(s *CurrentReleaseState) {
			s.ConfigDigest = "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
		}},
		{"class", func(s *CurrentReleaseState) { s.Class = "L3" }},
		{"incomplete", func(s *CurrentReleaseState) { s.Complete = false }},
		{"gaps", func(s *CurrentReleaseState) { s.GapsClosed = false }},
		{"revoked", func(s *CurrentReleaseState) { s.Revoked = true }},
		{"deleted", func(s *CurrentReleaseState) { s.Deleted = true }},
	}
	for _, tt := range mutations {
		t.Run(tt.name, func(t *testing.T) {
			f := releaseHappyFixture(t)
			f.tx.beforeCommit = func() {
				f.tx.mu.Lock()
				tt.mutate(&f.tx.current)
				f.tx.mu.Unlock()
			}
			if _, err := f.coord.Release(context.Background(), f.input, f.decision, f.lineage, f.now); !errors.Is(err, ErrReleaseStale) {
				t.Fatalf("lineage drift accepted: %v", err)
			}
			if f.tx.state[f.decision.DecisionID] != "" || len(f.tx.identities) != 0 || len(f.tx.receipts) != 0 {
				t.Fatal("drift created a release result")
			}
		})
	}
}

func TestManualReleaseFailuresBecomeTerminalAndCannotReplay(t *testing.T) {
	for _, fault := range []testReleaseFault{testReleaseAfterReservation, testReleaseAfterDecisionConsume, testReleaseAfterIdentityCreation} {
		t.Run(string(rune('0'+fault)), func(t *testing.T) {
			f := releaseHappyFixture(t)
			f.tx.fault = fault
			identity, err := f.coord.Release(context.Background(), f.input, f.decision, f.lineage, f.now)
			if !errors.Is(err, ErrReleaseUncertain) || identity.IdentityID != "" {
				t.Fatalf("fault %d result=%#v err=%v", fault, identity, err)
			}
			if err := f.tx.Reconcile(context.Background()); err != nil {
				t.Fatal(err)
			}
			if f.tx.state[f.decision.DecisionID] != ReleaseUncertain || len(f.tx.identities) != 0 || len(f.tx.receipts) != 0 {
				t.Fatalf("fault %d was not terminally clean", fault)
			}
			if _, err := f.coord.Release(context.Background(), f.input, f.decision, f.lineage, f.now); !errors.Is(err, ErrReleaseUsed) {
				t.Fatalf("fault %d replay=%v", fault, err)
			}
		})
	}
}
