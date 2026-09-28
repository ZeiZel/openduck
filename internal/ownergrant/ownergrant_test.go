package ownergrant

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func testDigest() string {
	return "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
}
func testStore(t *testing.T) (*Store, string, ed25519.PrivateKey, ed25519.PublicKey) {
	t.Helper()
	queue, caps := t.TempDir(), t.TempDir()
	if err := os.Chmod(queue, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(caps, 0700); err != nil {
		t.Fatal(err)
	}
	store, err := OpenCurrentStore(queue)
	if err != nil {
		t.Fatal(err)
	}
	pub, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return store, caps, private, pub
}
func approve(t *testing.T, s *Store, caps string, private ed25519.PrivateKey, p PendingOrder, now time.Time) {
	t.Helper()
	if err := s.Consume(p.RequestID, caps, "owner.capability", private, os.Geteuid(), os.Getegid(), now); err != nil {
		t.Fatal(err)
	}
}

func TestRootSignerAndControllerPublicVerifier(t *testing.T) {
	s, caps, private, public := testStore(t)
	defer s.Close()
	now := time.Now().UTC()
	p, err := s.Request(testDigest(), "chat-1", now)
	if !errors.Is(err, ErrApprovalRequired) {
		t.Fatalf("request: %v", err)
	}
	approve(t, s, caps, private, p, now)
	if err := VerifyAndConsume(caps, "owner.capability", p.RequestID, public, p.OrderDigest, p.ChatID, now); err != nil {
		t.Fatal(err)
	}
}
func TestControllerPublicKeyCannotMintAndRejectsWrongKeyOrTamper(t *testing.T) {
	s, caps, private, public := testStore(t)
	defer s.Close()
	now := time.Now().UTC()
	p, _ := s.Request(testDigest(), "chat-1", now)
	approve(t, s, caps, private, p, now)
	wrong, _, _ := ed25519.GenerateKey(rand.Reader)
	if err := VerifyAndConsume(caps, "owner.capability", p.RequestID, wrong, p.OrderDigest, p.ChatID, now); err == nil {
		t.Fatal("wrong public key accepted")
	}
	leaf, _ := CapabilityLeaf("owner.capability", p.RequestID)
	raw, err := os.ReadFile(filepath.Join(caps, leaf))
	if err != nil {
		t.Fatal(err)
	}
	raw[len(raw)-2] ^= 1
	if err := os.WriteFile(filepath.Join(caps, leaf), raw, 0600); err != nil {
		t.Fatal(err)
	}
	if err := VerifyAndConsume(caps, "owner.capability", p.RequestID, public, p.OrderDigest, p.ChatID, now); err == nil {
		t.Fatal("tampered signature accepted")
	}
}
func TestMismatchDoesNotConsumeAndDoubleSpendFails(t *testing.T) {
	s, caps, private, public := testStore(t)
	defer s.Close()
	now := time.Now().UTC()
	p, _ := s.Request(testDigest(), "chat-1", now)
	approve(t, s, caps, private, p, now)
	if err := VerifyAndConsume(caps, "owner.capability", p.RequestID, public, "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", p.ChatID, now); err == nil {
		t.Fatal("mismatch accepted")
	}
	if err := VerifyAndConsume(caps, "owner.capability", p.RequestID, public, p.OrderDigest, p.ChatID, now); err != nil {
		t.Fatalf("valid grant was consumed by mismatch: %v", err)
	}
	if err := VerifyAndConsume(caps, "owner.capability", p.RequestID, public, p.OrderDigest, p.ChatID, now); err == nil {
		t.Fatal("double spend accepted")
	}
}
func TestIdenticalOrdersHaveSeparateRequestScopedGrants(t *testing.T) {
	s, caps, private, public := testStore(t)
	defer s.Close()
	now := time.Now().UTC()
	first, _ := s.Request(testDigest(), "chat-1", now)
	approve(t, s, caps, private, first, now)
	if err := VerifyAndConsume(caps, "owner.capability", first.RequestID, public, first.OrderDigest, first.ChatID, now); err != nil {
		t.Fatal(err)
	}
	second, err := s.Request(testDigest(), "chat-1", now.Add(time.Second))
	if !errors.Is(err, ErrApprovalRequired) || second.RequestID == first.RequestID {
		t.Fatalf("second attempt=%+v err=%v", second, err)
	}
	approve(t, s, caps, private, second, now.Add(time.Second))
	if err := VerifyAndConsume(caps, "owner.capability", second.RequestID, public, second.OrderDigest, second.ChatID, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
}
func TestSecondTabDifferentOrderCannotReceiveOrReplacePendingApproval(t *testing.T) {
	s, _, _, _ := testStore(t)
	defer s.Close()
	now := time.Now().UTC()
	first, err := s.Request(testDigest(), "chat-one", now)
	if !errors.Is(err, ErrApprovalRequired) {
		t.Fatal(err)
	}
	if _, err := s.Request("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "chat-two", now); !errors.Is(err, ErrAlreadyPending) {
		t.Fatalf("different second tab err=%v", err)
	}
	active, err := s.Active(now)
	if err != nil || active.RequestID != first.RequestID || active.ChatID != "chat-one" {
		t.Fatalf("pending changed: %+v err=%v", active, err)
	}
}
func TestStoreRejectsSymlinkAndMode(t *testing.T) {
	queue := t.TempDir()
	if err := os.Chmod(queue, 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenCurrentStore(queue); err == nil {
		t.Fatal("permissive queue accepted")
	}
	queue = t.TempDir()
	if err := os.Chmod(queue, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/tmp", filepath.Join(queue, "pending.0123456789abcdef0123456789abcdef")); err != nil {
		t.Fatal(err)
	}
	s, err := OpenCurrentStore(queue)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.Active(time.Now()); err == nil {
		t.Fatal("symlink pending accepted")
	}
}
func TestConcurrentDoubleSpend(t *testing.T) {
	s, caps, private, public := testStore(t)
	defer s.Close()
	now := time.Now().UTC()
	p, _ := s.Request(testDigest(), "chat-1", now)
	approve(t, s, caps, private, p, now)
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results <- VerifyAndConsume(caps, "owner.capability", p.RequestID, public, p.OrderDigest, p.ChatID, now)
		}()
	}
	wg.Wait()
	close(results)
	successes := 0
	for err := range results {
		if err == nil {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("spends=%d", successes)
	}
}
