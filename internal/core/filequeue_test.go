package core

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestFileQueueRecoveryAndCorruption(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "q")
	q, e := NewFileQueue(path, []byte("01234567890123456789012345678901"))
	if e != nil {
		t.Fatal(e)
	}
	if _, e = q.Enqueue(context.Background(), event("persist", 1)); e != nil {
		t.Fatal(e)
	}
	q, e = NewFileQueue(path, []byte("01234567890123456789012345678901"))
	if e != nil || q.Depth() != 1 {
		t.Fatalf("recover %v %d", e, q.Depth())
	}
	if e = os.WriteFile(path, []byte("bad"), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = NewFileQueue(path, []byte("01234567890123456789012345678901")); e == nil {
		t.Fatal("corruption accepted")
	}
}

func TestFileQueueRollbackOnPersistFailure(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "q")
	fail := false
	persist := func(string, []byte) error {
		if fail {
			return errors.New("injected")
		}
		return atomicPersist(path, []byte("x"))
	}
	q, err := NewFileQueueWithPersister(path, []byte("01234567890123456789012345678901"), persist)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = q.Enqueue(context.Background(), event("one", 1)); err != nil {
		t.Fatal(err)
	}
	fail = true
	if _, err = q.Enqueue(context.Background(), event("two", 2)); err == nil {
		t.Fatal("expected persist failure")
	}
	if q.Depth() != 1 {
		t.Fatalf("rollback depth=%d", q.Depth())
	}
}

func TestFileQueueUncertainCommitReloadsThenPoisons(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "q")
	uncertain := false
	persist := func(p string, b []byte) error {
		if err := atomicPersist(p, b); err != nil {
			return err
		}
		if uncertain {
			return &CommitUncertainError{Err: errors.New("dir sync uncertain")}
		}
		return nil
	}
	q, err := NewFileQueueWithPersister(path, []byte("01234567890123456789012345678901"), persist)
	if err != nil {
		t.Fatal(err)
	}
	uncertain = true
	if _, err = q.Enqueue(context.Background(), event("authoritative", 1)); !errors.As(err, new(*CommitUncertainError)) {
		t.Fatalf("want uncertain: %v", err)
	}
	if q.Health().Status != "poisoned" || q.Depth() != 1 {
		t.Fatalf("health=%+v depth=%d", q.Health(), q.Depth())
	}
	if _, err = q.Enqueue(context.Background(), event("overwrite", 2)); !errors.Is(err, ErrQueuePoisoned) {
		t.Fatalf("poison not enforced: %v", err)
	}
	q2, err := NewFileQueue(path, []byte("01234567890123456789012345678901"))
	if err != nil || q2.Depth() != 1 {
		t.Fatalf("reload=%v depth=%d", err, q2.Depth())
	}
}

func TestFileQueueUncertainCorruptReloadFailsClosed(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "q")
	persist := func(p string, b []byte) error {
		if err := os.WriteFile(p, []byte("corrupt"), 0600); err != nil {
			return err
		}
		return &CommitUncertainError{Err: errors.New("uncertain")}
	}
	q, err := NewFileQueueWithPersister(path, []byte("01234567890123456789012345678901"), persist)
	if err != nil {
		t.Fatal(err)
	}
	_, err = q.Enqueue(context.Background(), event("x", 1))
	if !errors.As(err, new(*CommitUncertainError)) || q.Health().Status != "poisoned" {
		t.Fatalf("err=%v health=%+v", err, q.Health())
	}
	if _, _, err = q.Dequeue(context.Background()); !errors.Is(err, ErrQueuePoisoned) {
		t.Fatalf("dequeue=%v", err)
	}
}

func TestKeychainProviderValidatesInputs(t *testing.T) {
	if _, err := (MacOSKeychainProvider{Service: "bad space", Account: "a"}).Key(context.Background()); err == nil {
		t.Fatal("unsafe service accepted")
	}
}

func TestFileQueueRollbackLeaseAckNackAndRestart(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "q")
	fail := false
	persist := func(p string, b []byte) error {
		if fail {
			return errors.New("injected")
		}
		return atomicPersist(p, b)
	}
	q, err := NewFileQueueWithPersister(path, []byte("01234567890123456789012345678901"), persist)
	if err != nil {
		t.Fatal(err)
	}
	_, err = q.Enqueue(context.Background(), event("one", 1))
	if err != nil {
		t.Fatal(err)
	}
	fail = true
	if _, err = q.Lease(context.Background(), "w", time.Minute); err == nil {
		t.Fatal("lease should fail")
	}
	if q.Depth() != 1 {
		t.Fatal(q.Depth())
	}
	fail = false
	l, err := q.Lease(context.Background(), "w", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	fail = true
	if err = q.Ack(context.Background(), l.Token); err == nil {
		t.Fatal("ack should fail")
	}
	fail = false
	if err = q.Nack(context.Background(), l.Token); err != nil {
		t.Fatal(err)
	}
	l, err = q.Lease(context.Background(), "w", 20*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	_ = l
	time.Sleep(30 * time.Millisecond)
	q2, err := NewFileQueue(path, []byte("01234567890123456789012345678901"))
	if err != nil {
		t.Fatal(err)
	}
	if q2.Depth() != 1 {
		t.Fatalf("expired lease not recovered")
	}
	if _, ok, err := q2.Dequeue(context.Background()); err != nil || !ok {
		t.Fatalf("recovery %v %v", ok, err)
	}
}
