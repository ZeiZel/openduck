package codexruntime

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

type flakyServiceCheckpoint struct {
	mu       sync.Mutex
	version  uint64
	failOnce bool
	failures int
	after    bool
	requests map[string]struct{}
}

func (c *flakyServiceCheckpoint) CompareAndSwapDigest(requestID string, _ string, expected, next uint64, _ string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.requests[requestID]; ok {
		return nil
	}
	if c.version != expected || next != expected+1 {
		return ErrRunCAS
	}
	if c.failOnce || c.failures > 0 {
		c.failOnce = false
		if c.failures > 0 {
			c.failures--
		}
		if c.after {
			c.version = next
			if c.requests == nil {
				c.requests = map[string]struct{}{}
			}
			c.requests[requestID] = struct{}{}
		}
		return ErrRunCAS
	}
	c.version = next
	return nil
}

func TestPendingTransitionReplayPreservesProspectiveOutcomeAndBlocksOverwrite(t *testing.T) {
	for _, next := range []struct {
		name, state, code string
	}{
		{name: "failed", state: "failed", code: "RUNTIME_FAILED"},
		{name: "cancelled", state: "cancelled", code: "CANCELLED"},
	} {
		t.Run(next.name, func(t *testing.T) {
			key := []byte("01234567890123456789012345678901")
			checkpoint := &flakyServiceCheckpoint{}
			ledger, err := NewEncryptedChatRunLedgerWithCheckpoint(filepath.Join(t.TempDir(), "runs.enc"), key, checkpoint)
			if err != nil {
				t.Fatal(err)
			}
			run, err := ledger.Begin("chat", next.name, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			if _, err := ledger.Transition(run.RunID, run.Version, "running", "", "", time.Now()); err != nil {
				t.Fatal(err)
			}
			checkpoint.failures = 2
			if _, err := ledger.Transition(run.RunID, 2, next.state, "", next.code, time.Now()); !errors.Is(err, ErrRunCAS) {
				t.Fatalf("first uncertain transition err=%v", err)
			}
			pending, err := ledger.Get(run.RunID)
			if err != nil || pending.State != next.state || pending.ErrorCode != next.code || pending.PendingToken == "" || recordDigest(pending) != pending.PendingDigest {
				t.Fatalf("prospective record=%+v err=%v", pending, err)
			}
			if _, err := ledger.Transition(run.RunID, 2, "cancelled", "", "CANCELLED", time.Now()); !errors.Is(err, ErrRunCAS) {
				t.Fatalf("overwrite during uncertain transition err=%v", err)
			}
			reconciled, err := ledger.Begin("chat", next.name, time.Now())
			if err != nil || reconciled.State != next.state || reconciled.ErrorCode != next.code || reconciled.PendingToken != "" {
				t.Fatalf("reconciled=%+v err=%v", reconciled, err)
			}
		})
	}
}

func TestEncryptedChatRunLedgerCASAndRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "runs.enc")
	key := []byte("01234567890123456789012345678901")
	l, err := NewEncryptedChatRunLedger(path, key)
	if err != nil {
		t.Fatal(err)
	}
	r, err := l.Begin("chat", "idem", time.Now())
	if err != nil || r.State != "pending" || r.Version != 1 {
		t.Fatalf("r=%+v err=%v", r, err)
	}
	r2, err := l.Transition(r.RunID, r.Version, "running", "", "", time.Now())
	if err != nil || r2.Version != 2 {
		t.Fatalf("r2=%+v err=%v", r2, err)
	}
	if _, err = l.Transition(r.RunID, r.Version, "completed", "sha256:x", "", time.Now()); !errors.Is(err, ErrRunCAS) {
		t.Fatalf("stale CAS=%v", err)
	}
	if _, err = l.Transition(r.RunID, r2.Version, "completed", "sha256:x", "", time.Now()); err != nil {
		t.Fatal(err)
	}
	l2, err := NewEncryptedChatRunLedger(path, key)
	if err != nil {
		t.Fatal(err)
	}
	again, err := l2.Begin("chat", "idem", time.Now())
	if err != nil || again.State != "completed" {
		t.Fatalf("restart=%+v err=%v", again, err)
	}
	wrong, _ := NewEncryptedChatRunLedger(path, []byte("12345678901234567890123456789012"))
	if _, err := wrong.Begin("x", "y", time.Now()); err == nil {
		t.Fatal("wrong key opened ledger")
	}
}

func TestChatRunServicePersistsBeforePublishingAndSurvivesRestartAsUncertain(t *testing.T) {
	key := []byte("01234567890123456789012345678901")
	ledger, err := NewEncryptedChatRunLedgerWithCheckpoint(filepath.Join(t.TempDir(), "runs.enc"), key, NewMemoryChatCheckpoint())
	if err != nil {
		t.Fatal(err)
	}
	canary, err := NewOwnerCanary(t.TempDir(), &FakeChatTransport{InventoryValue: safeInventory(), Result: AssistantTurnResult{State: "completed", Answer: "OK"}}, allowChatAuth{}, allowChatGate{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	svc, err := NewChatRunService(canary, ledger)
	if err != nil {
		t.Fatal(err)
	}
	order := chatOrder(t, "hello")
	pending, err := svc.Start(context.Background(), order)
	if err != nil || pending.State != "running" {
		t.Fatalf("start=%+v err=%v", pending, err)
	}
	deadline := time.Now().Add(time.Second)
	var got AssistantTurnResult
	for time.Now().Before(deadline) {
		got, err = svc.Get(context.Background(), pending.ChatID)
		if err != nil {
			t.Fatal(err)
		}
		if got.State == "completed" {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if got.State != "completed" || got.Answer != "OK" {
		t.Fatalf("result=%+v", got)
	}
	// A fresh service has only encrypted lifecycle/digest data, never a replayed
	// answer; its visible state is deliberately uncertain.
	fresh, err := NewChatRunService(canary, ledger)
	if err != nil {
		t.Fatal(err)
	}
	got, err = fresh.Get(context.Background(), pending.ChatID)
	if err != nil || got.State != "failed" || got.ErrorCode != "UNCERTAIN_RESTART" {
		t.Fatalf("restart=%+v err=%v", got, err)
	}
}

func TestChatRunServiceReconcilesDurableCASAfterLostReplyBeforeOrAfterCommit(t *testing.T) {
	for _, after := range []bool{false, true} {
		t.Run(map[bool]string{false: "before", true: "after"}[after], func(t *testing.T) {
			key := []byte("01234567890123456789012345678901")
			checkpoint := &flakyServiceCheckpoint{failOnce: true, after: after}
			path := filepath.Join(t.TempDir(), "runs.enc")
			ledger, err := NewEncryptedChatRunLedgerWithCheckpoint(path, key, checkpoint)
			if err != nil {
				t.Fatal(err)
			}
			canary, err := NewOwnerCanary(t.TempDir(), &FakeChatTransport{InventoryValue: safeInventory(), Result: AssistantTurnResult{State: "completed", Answer: "OK"}}, allowChatAuth{}, allowChatGate{}, nil)
			if err != nil {
				t.Fatal(err)
			}
			service, err := NewChatRunService(canary, ledger)
			if err != nil {
				t.Fatal(err)
			}
			order := chatOrder(t, "reconcile")
			if _, err := service.Start(context.Background(), order); !errors.Is(err, ErrRunCAS) {
				t.Fatalf("initial lost reply err=%v", err)
			}
			restarted, err := NewChatRunService(canary, ledger)
			if err != nil {
				t.Fatal(err)
			}
			started, err := restarted.Start(context.Background(), order)
			if err != nil {
				t.Fatalf("reconcile start err=%v", err)
			}
			deadline := time.Now().Add(time.Second)
			for time.Now().Before(deadline) {
				result, getErr := restarted.Get(context.Background(), started.ChatID)
				if getErr == nil && result.State == "completed" {
					return
				}
				time.Sleep(time.Millisecond)
			}
			t.Fatal("reconciled service did not complete")
		})
	}
}
