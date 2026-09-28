package admission

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func appendReceipt(p CloudAdmittedPrompt) CloudAppendReceipt {
	return CloudAppendReceipt{SchemaVersion: CloudAppendReceiptV1, AdmissionID: p.AdmissionID, PromptDigest: p.Digest, ContentDigest: p.ContentDigest, DestinationStore: p.DSHAppendStore, DestinationRecord: "record-1", DestinationSchema: p.DSHAppendSchema, ObservedAppendRevision: 1, ObservedAt: p.IssuedAt, SignerAttestationDigest: fixtureDigest, ReceiptSignature: fixtureDigest, Digest: fixtureDigest}
}

func finalGate(p CloudAdmittedPrompt) FinalGate {
	return FinalGate{Snapshot: AuthoritativeConversationSnapshot{SchemaVersion: AuthoritativeConversationSnapshotV1, ConversationScope: p.ConversationScope, EventRevisionSetDigest: p.EventRevisionSetDigest, CompleteThroughWatermark: p.CompleteThroughWatermark, IngressGateStateDigest: p.IngressGateStateDigest, AuthoritativeCoverageDigest: p.AuthoritativeCoverageDigest, ClassHighWater: p.ClassHighWater, ClassHighWaterVersion: p.ClassHighWaterVersion, Digest: fixtureDigest}, RuntimeDigest: p.TargetRuntimeAttestationDigest, DSHDistributionDigest: p.TargetDSHDistributionAttestationDigest, ProfileDigest: p.TargetCodexProfileAttestationDigest, ModelTransportDigest: p.ModelTransportPolicyDigest, ToolsetDigest: p.ToolsetDigest, ToolNetworkDigest: p.ToolNetworkPolicyDigest, PolicyDigest: p.PolicyDigest, TargetSessionID: p.TargetSessionID, TargetCodexThreadID: p.TargetCodexThreadID, ExpectedRunnerBinding: p.ExpectedRunnerBinding}
}

func TestLedgerLifecycleSingleUse(t *testing.T) {
	l := NewMemoryLedger()
	issued, _ := fixtureTime()
	l.SetClock(func() time.Time { return issued.Add(time.Minute) })
	p := authorizedPrompt(t)
	l.SetReceiptVerifier(func(CloudAppendReceipt) error { return nil })
	if _, err := l.Admit(context.Background(), p, testVerifier(true)); err != nil {
		t.Fatal(err)
	}
	if _, err := l.Admit(context.Background(), p, testVerifier(true)); !errors.Is(err, ErrAdmissionReplay) {
		t.Fatalf("replay: %v", err)
	}
	if _, err := l.Reconcile(context.Background(), p.AdmissionID, appendReceipt(p)); err != nil {
		t.Fatal(err)
	}
	r, err := l.ReserveEgress(context.Background(), p.AdmissionID, finalGate(p))
	if err != nil {
		t.Fatal(err)
	}
	if r.State != StateConsumed || r.Reservation == nil || r.Reservation.EgressNonce == "" {
		t.Fatalf("bad reservation: %#v", r)
	}
	if _, err = l.ReserveEgress(context.Background(), p.AdmissionID, finalGate(p)); !errors.Is(err, ErrEgressReserved) {
		t.Fatalf("duplicate egress: %v", err)
	}
}

func TestLedgerLateReceiptCannotPromoteUncertain(t *testing.T) {
	l := NewMemoryLedger()
	issued, _ := fixtureTime()
	l.SetClock(func() time.Time { return issued.Add(time.Minute) })
	p := authorizedPrompt(t)
	l.SetReceiptVerifier(func(CloudAppendReceipt) error { return nil })
	_, _ = l.Admit(context.Background(), p, testVerifier(true))
	if _, err := l.MarkUncertain(context.Background(), p.AdmissionID, "crash"); err != nil {
		t.Fatal(err)
	}
	if _, err := l.Reconcile(context.Background(), p.AdmissionID, appendReceipt(p)); !errors.Is(err, ErrReceiptMismatch) {
		t.Fatalf("late receipt promoted or wrong error: %v", err)
	}
	r, err := l.Get(context.Background(), p.AdmissionID)
	if err != nil {
		t.Fatal(err)
	}
	if r.State != StateUncertain {
		t.Fatalf("state=%s", r.State)
	}
}

func TestLedgerEncryptedRestartAndTamper(t *testing.T) {
	d := t.TempDir()
	path := filepath.Join(d, "admission.enc")
	key := []byte("01234567890123456789012345678901")
	cp := NewMemoryCheckpointStore()
	p := authorizedPrompt(t)
	issued, _ := fixtureTime()
	l, err := NewLedger(path, key, cp)
	if err != nil {
		t.Fatal(err)
	}
	l.SetClock(func() time.Time { return issued.Add(time.Minute) })
	if _, err = l.Admit(context.Background(), p, testVerifier(true)); err != nil {
		t.Fatal(err)
	}
	_ = l.Close()
	l, err = NewLedger(path, key, cp)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = l.Get(context.Background(), p.AdmissionID); err != nil {
		t.Fatal(err)
	}
	_ = l.Close()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	b[len(b)-1] ^= 0xff
	if err = os.WriteFile(path, b, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = NewLedger(path, key, cp); !errors.Is(err, ErrLedgerCorrupt) {
		t.Fatalf("tamper error=%v", err)
	}
}

func TestLedgerRaceSingleConsumption(t *testing.T) {
	l := NewMemoryLedger()
	issued, _ := fixtureTime()
	l.SetClock(func() time.Time { return issued.Add(time.Minute) })
	p := authorizedPrompt(t)
	l.SetReceiptVerifier(func(CloudAppendReceipt) error { return nil })
	if _, err := l.Admit(context.Background(), p, testVerifier(true)); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	wins := 0
	var mu sync.Mutex
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if _, err := l.Reconcile(context.Background(), p.AdmissionID, appendReceipt(p)); err == nil {
				mu.Lock()
				wins++
				mu.Unlock()
			}
		}(i)
	}
	wg.Wait()
	if wins != 1 {
		t.Fatalf("consumption winners=%d", wins)
	}
}

func TestLedgerExpiry(t *testing.T) {
	l := NewMemoryLedger()
	p := authorizedPrompt(t)
	l.SetReceiptVerifier(func(CloudAppendReceipt) error { return nil })
	issued, _ := fixtureTime()
	l.SetClock(func() time.Time { return issued.Add(time.Minute) })
	if _, err := l.Admit(context.Background(), p, testVerifier(true)); err != nil {
		t.Fatal(err)
	}
	if _, err := l.Reconcile(context.Background(), p.AdmissionID, appendReceipt(p)); err != nil {
		t.Fatal(err)
	}
	l.SetClock(func() time.Time { return p.ExpiresAt.Add(time.Second) })
	if _, err := l.ReserveEgress(context.Background(), p.AdmissionID, finalGate(p)); !errors.Is(err, ErrAdmissionInvalidated) {
		t.Fatalf("expiry=%v", err)
	}
}

func TestLedgerAuthorityRejectsForgedPromptAndReceipt(t *testing.T) {
	l := NewMemoryLedger()
	issued, _ := fixtureTime()
	l.SetClock(func() time.Time { return issued.Add(time.Minute) })
	p := authorizedPrompt(t)
	if _, err := l.Admit(context.Background(), p, testVerifier(false)); err == nil {
		t.Fatal("forged prompt admitted")
	}
	if _, err := l.Get(context.Background(), p.AdmissionID); !errors.Is(err, ErrAdmissionNotFound) {
		t.Fatalf("forged pending persisted: %v", err)
	}
	if _, err := l.Admit(context.Background(), p, testVerifier(true)); err != nil {
		t.Fatal(err)
	}
	if _, err := l.Reconcile(context.Background(), p.AdmissionID, appendReceipt(p)); !errors.Is(err, ErrCloudOnly) {
		t.Fatalf("receipt accepted without verifier: %v", err)
	}
	if _, err := l.Get(context.Background(), p.AdmissionID); err != nil {
		t.Fatal(err)
	}
}

func TestLedgerClonesCallerInputAndOutput(t *testing.T) {
	l := NewMemoryLedger()
	issued, _ := fixtureTime()
	l.SetClock(func() time.Time { return issued.Add(time.Minute) })
	p := authorizedPrompt(t)
	l.SetReceiptVerifier(func(CloudAppendReceipt) error { return nil })
	if _, err := l.Admit(context.Background(), p, testVerifier(true)); err != nil {
		t.Fatal(err)
	}
	p.SourceRefs[0] = "caller-mutated"
	p.SafeCapsule.Fields["summary"] = "caller-mutated"
	r, err := l.Get(context.Background(), p.AdmissionID)
	if err != nil {
		t.Fatal(err)
	}
	if r.Prompt.SourceRefs[0] == "caller-mutated" || r.Prompt.SafeCapsule.Fields["summary"] == "caller-mutated" {
		t.Fatal("caller input aliased into ledger")
	}
	r.Prompt.SourceRefs[0] = "output-mutated"
	r.Prompt.SafeCapsule.Fields["summary"] = "output-mutated"
	r2, err := l.Get(context.Background(), p.AdmissionID)
	if err != nil {
		t.Fatal(err)
	}
	if r2.Prompt.SourceRefs[0] == "output-mutated" || r2.Prompt.SafeCapsule.Fields["summary"] == "output-mutated" {
		t.Fatal("returned record aliases ledger")
	}
}

func TestLedgerCrossInstanceReloadAndImmutableVerifier(t *testing.T) {
	d := t.TempDir()
	path := filepath.Join(d, "admission.enc")
	key := []byte("01234567890123456789012345678901")
	cp := NewMemoryCheckpointStore()
	p := authorizedPrompt(t)
	issued, _ := fixtureTime()
	l1, err := NewLedger(path, key, cp)
	if err != nil {
		t.Fatal(err)
	}
	l2, err := NewLedger(path, key, cp)
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range []*Ledger{l1, l2} {
		l.SetClock(func() time.Time { return issued.Add(time.Minute) })
	}
	l1.SetReceiptVerifier(func(CloudAppendReceipt) error { return nil })
	l2.SetReceiptVerifier(func(CloudAppendReceipt) error { return errors.New("forged verifier") })
	if _, err = l1.Admit(context.Background(), p, testVerifier(true)); err != nil {
		t.Fatal(err)
	}
	if _, err = l2.Reconcile(context.Background(), p.AdmissionID, appendReceipt(p)); err == nil {
		t.Fatal("forged receipt verifier accepted")
	}
	// The second instance must have reloaded the durable state, and the first
	// verifier cannot be replaced after installation.
	if _, err = l2.Reconcile(context.Background(), p.AdmissionID, appendReceipt(p)); err == nil {
		t.Fatal("receipt accepted twice")
	}
	if _, err = l1.Get(context.Background(), p.AdmissionID); err != nil {
		t.Fatal(err)
	}
}

type failingCheckpointStore struct {
	checkpoint LedgerCheckpoint
	fail       bool
}

func (s *failingCheckpointStore) LoadCheckpoint() (LedgerCheckpoint, error) { return s.checkpoint, nil }
func (s *failingCheckpointStore) CommitCheckpoint(expected uint64, next LedgerCheckpoint) error {
	if s.fail {
		return errors.New("simulated checkpoint crash")
	}
	if s.checkpoint.Version != expected {
		return ErrCheckpointMismatch
	}
	s.checkpoint = next
	return nil
}

func TestLedgerCheckpointRejectsRollbackDeletionAndTornCommit(t *testing.T) {
	d := t.TempDir()
	path := filepath.Join(d, "admission.enc")
	key := []byte("01234567890123456789012345678901")
	cp := NewMemoryCheckpointStore()
	p := authorizedPrompt(t)
	l, err := NewLedger(path, key, cp)
	if err != nil {
		t.Fatal(err)
	}
	issued, _ := fixtureTime()
	l.SetClock(func() time.Time { return issued.Add(time.Minute) })
	if _, err = l.Admit(context.Background(), p, testVerifier(true)); err != nil {
		t.Fatal(err)
	}
	old, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	l.SetReceiptVerifier(func(CloudAppendReceipt) error { return nil })
	if _, err = l.Reconcile(context.Background(), p.AdmissionID, appendReceipt(p)); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, old, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = NewLedger(path, key, cp); !errors.Is(err, ErrCheckpointMismatch) {
		t.Fatalf("rollback accepted: %v", err)
	}
	if err = os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if _, err = NewLedger(path, key, cp); !errors.Is(err, ErrCheckpointMismatch) {
		t.Fatalf("state deletion accepted: %v", err)
	}
	// A checkpoint that is deleted/reset while state remains is also poison.
	if err = os.WriteFile(path, old, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = NewLedger(path, key, NewMemoryCheckpointStore()); !errors.Is(err, ErrCheckpointMismatch) {
		t.Fatalf("checkpoint deletion accepted: %v", err)
	}

	path2 := filepath.Join(d, "torn.enc")
	torn := &failingCheckpointStore{}
	l2, err := NewLedger(path2, key, torn)
	if err != nil {
		t.Fatal(err)
	}
	l2.SetClock(func() time.Time { return issued.Add(time.Minute) })
	torn.fail = true
	if _, err = l2.Admit(context.Background(), p, testVerifier(true)); err == nil {
		t.Fatal("torn checkpoint commit accepted")
	}
	if _, err = NewLedger(path2, key, torn); !errors.Is(err, ErrCheckpointMismatch) {
		t.Fatalf("torn state accepted: %v", err)
	}
}
