package platformanchor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func testDigest(s string) string {
	h := sha256.Sum256([]byte(s))
	return "sha256:" + hex.EncodeToString(h[:])
}

func newStore(t *testing.T) *Store {
	t.Helper()
	s, err := NewSyntheticStoreWithCheckpoint(filepath.Join(t.TempDir(), "state"), NewTestMonotonicCheckpoint())
	if err != nil {
		t.Fatal(err)
	}
	return s
}
func TestProtocolBoundsAndUnknownFields(t *testing.T) {
	var req Request
	if err := decodeJSON([]byte(`{"schema_version":"platform-anchor.v1","request_id":"r","namespace":"admission","operation":"load","key":"x","extra":1}`), &req); !errors.Is(err, ErrProtocol) {
		t.Fatalf("unknown field err=%v", err)
	}
	if err := ReadFrame(bytesReader([]byte{0, 1, 0, 1}), &req); !errors.Is(err, ErrProtocol) {
		t.Fatalf("zero/oversized frame err=%v", err)
	}
	loadWithExpected := Request{SchemaVersion: SchemaVersion, RequestID: "load-expected", Namespace: NamespaceChat, Operation: "load", Key: "run", ExpectedVersion: 1}
	if err := loadWithExpected.validate(); !errors.Is(err, ErrProtocol) {
		t.Fatalf("load expected version err=%v", err)
	}
	if err := (Response{SchemaVersion: SchemaVersion, RequestID: "response", OK: true, Namespace: NamespaceChat, Version: 1}).validate(); !errors.Is(err, ErrProtocol) {
		t.Fatalf("missing success digest err=%v", err)
	}
	if err := (Response{SchemaVersion: SchemaVersion, RequestID: "response", OK: false, Namespace: NamespaceChat, Version: 1, Error: "failed"}).validate(); !errors.Is(err, ErrProtocol) {
		t.Fatalf("failed response checkpoint err=%v", err)
	}
}

type bytesReader []byte

func (b bytesReader) Read(p []byte) (int, error) {
	if len(b) == 0 {
		return 0, io.EOF
	}
	n := copy(p, b)
	return n, nil
}

func TestStoreCASReplayCrossNamespaceAndDeleteFailClosed(t *testing.T) {
	s := newStore(t)
	r := Request{SchemaVersion: SchemaVersion, RequestID: "req-1", Namespace: NamespaceAdmission, Operation: "cas", Key: "ledger", ExpectedVersion: 0, NextVersion: 1, Digest: testDigest("x")}
	got, err := s.Request(r)
	if err != nil || !got.OK || got.Version != 1 {
		t.Fatalf("request=%+v err=%v", got, err)
	}
	if again, err := s.Request(r); err != nil || again.Version != got.Version {
		t.Fatalf("idempotent retry=%+v err=%v", again, err)
	}
	r.Namespace = NamespaceChat
	if _, err := s.Request(r); !errors.Is(err, ErrReplay) {
		t.Fatalf("cross namespace replay=%v", err)
	}
	r.RequestID = "req-2"
	r.Namespace = NamespaceAdmission
	r.ExpectedVersion = 0
	r.NextVersion = 1
	if _, err := s.Request(r); !errors.Is(err, ErrCAS) {
		t.Fatalf("rollback=%v", err)
	}
	if err := os.Remove(s.path); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Load(NamespaceAdmission, "ledger"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("delete load=%v", err)
	}
}

func TestIndependentCheckpointRejectsCoordinatedStateRollback(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	cp := NewTestMonotonicCheckpoint()
	s, err := NewSyntheticStoreWithCheckpoint(dir, cp)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.CAS(NamespaceChat, "run", 0, 1, testDigest("one")); err != nil {
		t.Fatal(err)
	}
	state, err := os.ReadFile(filepath.Join(dir, "anchor.json"))
	if err != nil {
		t.Fatal(err)
	}
	meta, err := os.ReadFile(filepath.Join(dir, "anchor.meta"))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.CAS(NamespaceChat, "run", 1, 2, testDigest("two")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "anchor.json"), state, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "anchor.meta"), meta, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewSyntheticStoreWithCheckpoint(dir, cp); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("coordinated rollback accepted: %v", err)
	}
}

func TestGenerationZeroCheckpointBindingIsImmutableAndRejectsMissingState(t *testing.T) {
	base := t.TempDir()
	stateDir := filepath.Join(base, "state")
	cp := NewTestMonotonicCheckpoint()
	s, err := NewSyntheticStoreWithCheckpoint(stateDir, cp)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(stateDir, "anchor.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := NewSyntheticStoreWithCheckpoint(stateDir, cp); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("missing state after generation-zero binding accepted: %v", err)
	}
	if err := cp.Commit(0, 0, testDigest("different")); !errors.Is(err, ErrCAS) {
		t.Fatalf("generation-zero digest rebound: %v", err)
	}
	_, boundDigest, err := cp.Load()
	if err != nil {
		t.Fatal(err)
	}
	if err := cp.Commit(0, 0, boundDigest); err != nil {
		t.Fatalf("generation-zero idempotence: %v", err)
	}
	_ = s.Close()
}

func TestIndependentCheckpointUsesGlobalGenerationAcrossKeysAndNamespaces(t *testing.T) {
	cp := NewTestMonotonicCheckpoint()
	s, err := NewSyntheticStoreWithCheckpoint(filepath.Join(t.TempDir(), "state"), cp)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.CAS(NamespaceAdmission, "ledger", 0, 1, testDigest("admission")); err != nil {
		t.Fatal(err)
	}
	if err := s.CAS(NamespaceChat, "run", 0, 1, testDigest("chat")); err != nil {
		t.Fatal(err)
	}
	generation, digest, err := cp.Load()
	if err != nil || generation != 2 || digest == "" {
		t.Fatalf("global checkpoint generation=%d digest=%q err=%v", generation, digest, err)
	}
	if got, _, err := s.Load(NamespaceAdmission, "ledger"); err != nil || got != 1 {
		t.Fatalf("admission checkpoint=%d err=%v", got, err)
	}
	if got, _, err := s.Load(NamespaceChat, "run"); err != nil || got != 1 {
		t.Fatalf("chat checkpoint=%d err=%v", got, err)
	}
}

func TestLatestSuccessfulCASReplaySurvivesRequestEvictionAndRestart(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	cp := NewTestMonotonicCheckpoint()
	s, err := NewSyntheticStoreWithCheckpoint(dir, cp)
	if err != nil {
		t.Fatal(err)
	}
	// Fill the replay ledger with a single durable test fixture write.  The
	// former version performed 1025 full fsync-and-rewrite transitions; each
	// transition serializes the growing state, making the race test quadratic
	// without exercising a distinct production path.
	if err := seedRetainedRequests(s, maxRetainedRequests-1); err != nil {
		t.Fatal(err)
	}
	previous := Request{SchemaVersion: SchemaVersion, RequestID: "cas-previous", Namespace: NamespaceChat, Operation: "cas", Key: "run", ExpectedVersion: 0, NextVersion: 1, Digest: testDigest("digest-previous")}
	if _, err := s.Request(previous); err != nil {
		t.Fatal(err)
	}
	latest := Request{SchemaVersion: SchemaVersion, RequestID: "cas-latest", Namespace: NamespaceChat, Operation: "cas", Key: "run", ExpectedVersion: 1, NextVersion: 2, Digest: testDigest("digest-latest")}
	if _, err := s.Request(latest); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	restarted, err := NewSyntheticStoreWithCheckpoint(dir, cp)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	resp, err := restarted.Request(latest)
	if err != nil || !resp.OK || resp.Version != latest.NextVersion || resp.Digest != latest.Digest {
		t.Fatalf("latest CAS replay after eviction/restart: %+v err=%v", resp, err)
	}
}

// seedRetainedRequests creates a valid full replay ledger in one durable
// transition.  It is test-only scaffolding; production requests still take
// the ordinary append, eviction, fsync, and independent-checkpoint path.
func seedRetainedRequests(s *Store, count int) error {
	return s.withLock(func(st *diskState) error {
		for i := 0; i < count; i++ {
			id := fmt.Sprintf("seed-%d", i)
			st.Requests[id] = Response{SchemaVersion: SchemaVersion, RequestID: id, Namespace: NamespaceChat, OK: true}
			st.RequestFingerprints[id] = fmt.Sprintf("seed-fingerprint-%d", i)
			st.RequestOrder = append(st.RequestOrder, id)
		}
		return nil
	})
}

func TestStoreRejectsSymlinkRootAndReplacement(t *testing.T) {
	base := t.TempDir()
	target := filepath.Join(base, "target")
	if err := os.Mkdir(target, 0700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := NewSyntheticStore(link); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("symlink err=%v", err)
	}
	s := newStore(t)
	replacement := filepath.Join(filepath.Dir(s.path), "replacement")
	if err := os.WriteFile(replacement, []byte(`{"schema_version":"platform-anchor.v1","namespaces":{},"requests":{},"request_fingerprints":{}}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(replacement, s.path); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Load(NamespaceAdmission, "x"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("replacement err=%v", err)
	}
}

func TestServerClientAndPeerAttestationPerConnection(t *testing.T) {
	s := newStore(t)
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	peer := SyntheticPeer{UID: 1, Executable: "synthetic", Socket: "pipe"}
	srv, err := NewSyntheticServer(s, peer)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- srv.ServeConn(context.Background(), a) }()
	c, err := NewSyntheticClient(func(context.Context) (net.Conn, error) { return b, nil }, peer)
	if err != nil {
		t.Fatal(err)
	}
	r, err := c.Do(context.Background(), Request{SchemaVersion: SchemaVersion, RequestID: "request-1", Namespace: NamespaceChat, Operation: "cas", Key: "run", ExpectedVersion: 0, NextVersion: 1, Digest: testDigest("d")})
	if err != nil || r.Version != 1 {
		t.Fatalf("r=%+v err=%v", r, err)
	}
	b.Close()
	<-done
}

func TestConcurrentCASOnlyOneWins(t *testing.T) {
	s := newStore(t)
	var wg sync.WaitGroup
	wins := 0
	var mu sync.Mutex
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if err := s.CAS(NamespaceRuntimeLease, "lease", 0, 1, testDigest("d")); err == nil {
				mu.Lock()
				wins++
				mu.Unlock()
			}
		}(i)
	}
	wg.Wait()
	if wins != 1 {
		t.Fatalf("wins=%d", wins)
	}
}

func TestTwoStoresShareStableLockAndRejectPriorSnapshot(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	cp := NewTestMonotonicCheckpoint()
	one, err := NewSyntheticStoreWithCheckpoint(dir, cp)
	if err != nil {
		t.Fatal(err)
	}
	defer one.Close()
	two, err := NewSyntheticStoreWithCheckpoint(dir, cp)
	if err != nil {
		t.Fatal(err)
	}
	defer two.Close()
	if err := one.CAS(NamespaceChat, "run", 0, 1, testDigest("one")); err != nil {
		t.Fatal(err)
	}
	if err := two.CAS(NamespaceChat, "run", 1, 2, testDigest("two")); err != nil {
		t.Fatal(err)
	}
	if v, _, err := one.Load(NamespaceChat, "run"); err != nil || v != 2 {
		t.Fatalf("v=%d err=%v", v, err)
	}
}

func TestRequestRetentionIsBounded(t *testing.T) {
	s := newStore(t)
	for i := 0; i < 64; i++ {
		r := Request{SchemaVersion: SchemaVersion, RequestID: fmt.Sprintf("retained-%d", i), Namespace: NamespaceChat, Operation: "load", Key: "run"}
		if _, err := s.Request(r); err != nil {
			t.Fatal(err)
		}
	}
	b, err := s.root.ReadFile("anchor.json")
	if err != nil {
		t.Fatal(err)
	}
	var st diskState
	if err := json.Unmarshal(b, &st); err != nil {
		t.Fatal(err)
	}
	if len(st.Requests) > maxRetainedRequests || len(st.RequestOrder) > maxRetainedRequests {
		t.Fatalf("retained requests exceeded bound: %d/%d", len(st.Requests), len(st.RequestOrder))
	}
}

func FuzzReadFrameNeverPanics(f *testing.F) {
	f.Add([]byte{0, 0, 0, 1, '{'})
	f.Add([]byte{0xff, 0xff, 0xff, 0xff})
	f.Fuzz(func(t *testing.T, b []byte) {
		var req Request
		_ = ReadFrame(bytesReader(b), &req)
	})
}
