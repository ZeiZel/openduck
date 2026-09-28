package core

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestPersistentPseudonymStoreRestartPurgeAndUnknown(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pseudonyms.enc")
	key := []byte("01234567890123456789012345678901")
	s, err := NewPersistentPseudonymStore(context.Background(), path, key)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Put(context.Background(), "scope-a", "P-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "alice"); err != nil {
		t.Fatal(err)
	}
	if mode := mustMode(t, path); mode.Perm() != 0600 {
		t.Fatalf("mode %o", mode.Perm())
	}
	s, err = NewPersistentPseudonymStore(context.Background(), path, key)
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.RehydrateResponse(context.Background(), "scope-a", "hi P-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	if err != nil || got != "hi alice" {
		t.Fatalf("rehydrate=%q err=%v", got, err)
	}
	if _, err = s.RehydrateResponse(context.Background(), "scope-a", "P-BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"); err == nil {
		t.Fatal("unknown accepted")
	}
	if err = s.PurgeScope(context.Background(), "scope-a"); err != nil {
		t.Fatal(err)
	}
	if _, err = s.RehydrateResponse(context.Background(), "scope-a", "P-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"); err == nil {
		t.Fatal("scope purge failed")
	}
	if err = s.Put(context.Background(), "scope-b", "P-CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC", "bob"); err != nil {
		t.Fatal(err)
	}
	if err = s.Purge(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err = s.RehydrateResponse(context.Background(), "scope-b", "P-CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"); err == nil {
		t.Fatal("full purge failed")
	}
}

func TestPersistentPseudonymStoreCorruptionAndCancellation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pseudonyms.enc")
	key := []byte("01234567890123456789012345678901")
	if err := os.WriteFile(path, []byte("bad"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewPersistentPseudonymStore(context.Background(), path, key); err == nil {
		t.Fatal("corruption accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := NewPersistentPseudonymStore(ctx, filepath.Join(dir, "new"), key); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel=%v", err)
	}
}

func TestDurablePseudonymizerRestartEnvelopeRehydrateAndPurge(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pseudonyms.enc")
	key := bytes.Repeat([]byte{7}, 32)
	store, err := NewPersistentPseudonymStore(context.Background(), path, key)
	if err != nil {
		t.Fatal(err)
	}
	p, err := NewDurablePseudonymizer(bytes.Repeat([]byte{9}, 32), store)
	if err != nil {
		t.Fatal(err)
	}
	e := event("status green", 1)
	env1, err := BuildSafeEnvelopeFromSanitizedWithContext(e, p, SanitizedMessage{Speaker: "Alice", Text: "status green"}, SafeEnvelopeContext{Owner: "owner", Purpose: "summarize"})
	if err != nil {
		t.Fatal(err)
	}
	text, err := p.RehydrateResponse(context.Background(), "owner/summarize/manual/test/manual/c", env1.Messages[0].Speaker)
	if err != nil || text != "Alice" {
		t.Fatalf("rehydrate: %q %v", text, err)
	}
	store, err = NewPersistentPseudonymStore(context.Background(), path, key)
	if err != nil {
		t.Fatal(err)
	}
	p, err = NewDurablePseudonymizer(bytes.Repeat([]byte{9}, 32), store)
	if err != nil {
		t.Fatal(err)
	}
	env2, err := BuildSafeEnvelopeFromSanitizedWithContext(e, p, SanitizedMessage{Speaker: "Alice", Text: "status green"}, SafeEnvelopeContext{Owner: "owner", Purpose: "summarize"})
	if err != nil || env1.Messages[0].Speaker != env2.Messages[0].Speaker || env1.SessionRef != env2.SessionRef {
		t.Fatalf("unstable envelope: %#v %#v %v", env1, env2, err)
	}
	if err := p.PurgeScope(context.Background(), "owner/summarize/manual/test/manual/c"); err != nil {
		t.Fatal(err)
	}
	if _, err := p.RehydrateResponse(context.Background(), "owner/summarize/manual/test/manual/c", env1.Messages[0].Speaker); err == nil {
		t.Fatal("purged mapping rehydrated")
	}
}

func TestPersistentPseudonymStorePostRenameUncertainPoisons(t *testing.T) {
	called := false
	persist := func(path string, data []byte) error {
		if err := atomicPersist(path, data); err != nil {
			return err
		}
		called = true
		return &CommitUncertainError{Err: errors.New("directory fsync uncertain")}
	}
	s, err := NewPersistentPseudonymStoreWithPersister(context.Background(), filepath.Join(t.TempDir(), "p.enc"), bytes.Repeat([]byte{3}, 32), persist)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Put(context.Background(), "scope", "P-ABC", "value"); err == nil || !called {
		t.Fatal("expected uncertain commit")
	}
	if err := s.Put(context.Background(), "scope", "P-DEF", "value"); err == nil {
		t.Fatal("poisoned store accepted write")
	}
}

func mustMode(t *testing.T, path string) os.FileMode {
	t.Helper()
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return st.Mode()
}
