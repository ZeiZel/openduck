package syntheticadmission

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"openduck/internal/admission"
)

func testStateDir(t *testing.T) string {
	t.Helper()
	d := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(d, 0700); err != nil {
		t.Fatal(err)
	}
	return d
}

func TestCloudAdmissionIsDurableAndOneUseAcrossRestart(t *testing.T) {
	dir := testStateDir(t)
	a, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	first, err := a.AdmitCloud(context.Background(), []byte("safe summary"))
	if err != nil {
		t.Fatal(err)
	}
	if first.ID == "" || first.Status != "consumed" {
		t.Fatalf("unexpected result: %+v", first)
	}
	records, err := a.ledger.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 {
		t.Fatalf("records=%d, want one", len(records))
	}
	if records[first.ID].Reservation == nil {
		t.Fatal("cloud admission was not reserved")
	}
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}

	b, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if _, err := b.AdmitCloud(context.Background(), []byte("safe summary")); !errors.Is(err, ErrSyntheticReplay) {
		t.Fatalf("restart replay err=%v", err)
	}
}

func TestPDDoesNotCreateCloudLedgerRecord(t *testing.T) {
	a, err := New(testStateDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	got, err := a.DispatchLocalPD(context.Background(), []byte("Это ПД: локальный текст"))
	if err != nil {
		t.Fatal(err)
	}
	if got.Handle == "" || got.Status != "queued" {
		t.Fatalf("unexpected local result: %+v", got)
	}
	records, err := a.ledger.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 0 {
		t.Fatalf("PD created cloud records: %d", len(records))
	}
	if _, err := a.DispatchLocalPD(context.Background(), []byte("Это ПД: локальный текст")); !errors.Is(err, ErrSyntheticReplay) {
		t.Fatalf("PD replay err=%v", err)
	}
}

func TestForgedPromptAndReceiptFailClosed(t *testing.T) {
	a, err := New(testStateDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	p, err := a.prompt([]byte("safe"), a.clock())
	if err != nil {
		t.Fatal(err)
	}
	forged := p
	forged.ControllerSignature = "sha256:" + strings.Repeat("00", 32)
	if _, err := a.ledger.Admit(context.Background(), forged, a); err == nil {
		t.Fatal("forged prompt accepted")
	}
	if records, err := a.ledger.Snapshot(context.Background()); err != nil {
		t.Fatal(err)
	} else if len(records) != 0 {
		t.Fatal("forged prompt created record")
	}
	if _, err := a.ledger.Admit(context.Background(), p, a); err != nil {
		t.Fatal(err)
	}
	r, err := a.append.Append(p)
	if err != nil {
		t.Fatal(err)
	}
	r.ReceiptSignature = "sha256:" + strings.Repeat("00", 32)
	if _, err := a.ledger.Reconcile(context.Background(), p.AdmissionID, r); err == nil {
		t.Fatal("forged receipt accepted")
	}
	if got, err := a.ledger.Get(context.Background(), p.AdmissionID); err != nil {
		t.Fatal(err)
	} else if got.State != admission.StateConsuming {
		t.Fatalf("forged receipt changed state: %s", got.State)
	}
}

func TestRestartRecoveryClosesCrashGaps(t *testing.T) {
	// Gap 1: durable admission committed, append was never created.
	dir := testStateDir(t)
	a, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	p, err := a.prompt([]byte("gap-one"), a.clock())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.ledger.Admit(context.Background(), p, a); err != nil {
		t.Fatal(err)
	}
	_ = a.Close()
	b, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	r, err := b.ledger.Get(context.Background(), p.AdmissionID)
	if err != nil {
		t.Fatal(err)
	}
	if r.State != admission.StateUncertain {
		t.Fatalf("absent append state=%s", r.State)
	}
	_ = b.Close()

	// Gap 2: append exists, reconciliation was never committed.
	dir2 := testStateDir(t)
	c, err := New(dir2)
	if err != nil {
		t.Fatal(err)
	}
	p2, err := c.prompt([]byte("gap-two"), c.clock())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.ledger.Admit(context.Background(), p2, c); err != nil {
		t.Fatal(err)
	}
	if _, err := c.append.Append(p2); err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
	d, err := New(dir2)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	r, err = d.ledger.Get(context.Background(), p2.AdmissionID)
	if err != nil {
		t.Fatal(err)
	}
	if r.State != admission.StateConsumed || r.Reservation == nil {
		t.Fatalf("append recovery state=%s reservation=%v", r.State, r.Reservation != nil)
	}
}

func TestTwoAuthoritiesUseLedgerCASForDeterministicIdentity(t *testing.T) {
	dir := testStateDir(t)
	a, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	b, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	defer b.Close()
	if _, err := a.AdmitCloud(context.Background(), []byte("same event")); err != nil {
		t.Fatal(err)
	}
	if _, err := b.AdmitCloud(context.Background(), []byte("same event")); !errors.Is(err, ErrSyntheticReplay) {
		t.Fatalf("second authority err=%v", err)
	}
}

func TestAppendStoreCrossInstanceKeepsDistinctEvents(t *testing.T) {
	dir := testStateDir(t)
	a, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	b, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	p1, err := a.prompt([]byte("event-a"), a.clock())
	if err != nil {
		t.Fatal(err)
	}
	p2, err := b.prompt([]byte("event-b"), b.clock())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = a.append.Append(p1); err != nil {
		t.Fatal(err)
	}
	if _, err = b.append.Append(p2); err != nil {
		t.Fatal(err)
	}
	a.Close()
	b.Close()
	c, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, ok, err := c.append.Query(p1.IdempotencyKey); err != nil || !ok {
		t.Fatalf("event-a missing: %v", err)
	}
	if _, ok, err := c.append.Query(p2.IdempotencyKey); err != nil || !ok {
		t.Fatalf("event-b missing: %v", err)
	}
}

func TestRecoveryCheckpointFailureFailsClosed(t *testing.T) {
	dir := testStateDir(t)
	if _, err := NewSyntheticWithCheckpoint(dir, nil); err == nil {
		t.Fatal("nil external checkpoint accepted")
	}
}

func TestSyntheticCheckpointPathRemainsExplicit(t *testing.T) {
	if _, err := NewSyntheticWithCheckpoint(testStateDir(t), nil); err == nil {
		t.Fatal("nil synthetic checkpoint accepted")
	}
}

func TestAuthorityCloseZeroizesOwnedRuntimeKeys(t *testing.T) {
	a, err := New(testStateDir(t))
	if err != nil {
		t.Fatal(err)
	}
	authorityKey := a.key
	appendKey := a.append.key
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	for name, key := range map[string][]byte{"authority": authorityKey, "append": appendKey} {
		for _, b := range key {
			if b != 0 {
				t.Fatalf("%s key was not zeroized", name)
			}
		}
	}
	if a.key != nil || a.append.key != nil || !a.append.closed {
		t.Fatal("closed authority retained owned key handles")
	}
}
