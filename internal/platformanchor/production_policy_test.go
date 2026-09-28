package platformanchor

import (
	"context"
	"errors"
	"net"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"openduck/internal/admission"
	"openduck/internal/macoschannel"
)

type fixtureConn struct {
	net.Conn
	ev macoschannel.Evidence
}

func (c fixtureConn) Evidence() macoschannel.Evidence { return c.ev }

type fixtureDial struct {
	calls atomic.Int32
	ev    macoschannel.Evidence
}

func (d *fixtureDial) Dial(_ context.Context) (productionConn, error) {
	d.calls.Add(1)
	client, server := net.Pipe()
	call := d.calls.Load()
	go func() {
		defer server.Close()
		var req Request
		if ReadFrame(server, &req) != nil {
			return
		}
		if call == 1 {
			return
		}
		_ = WriteFrame(server, Response{SchemaVersion: SchemaVersion, RequestID: req.RequestID, Namespace: req.Namespace, OK: true, Version: 1, Digest: "sha256:" + strings.Repeat("c", 64)})
	}()
	return fixtureConn{Conn: client, ev: d.ev}, nil
}

func productionStateDir(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("/private/tmp", "od-prod-")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(d, 0700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(d) })
	return d
}

func productionPolicyFixture() ProductionPolicy {
	u, g, pu, pg := uint32(1000), uint32(100), uint32(1001), uint32(101)
	d := strings.Repeat("a", 64)
	return ProductionPolicy{
		Channel: "anchor", LocalRole: "server", PeerRole: "client",
		LocalRelease:     macoschannel.ReleasePin{ReleaseID: "local", BinaryDigest: d, SocketDigest: d, ManifestDigest: d},
		PeerRelease:      macoschannel.ReleasePin{ReleaseID: "peer", BinaryDigest: d, SocketDigest: d, ManifestDigest: d},
		ExpectedLocalUID: &u, ExpectedLocalGID: &g, ExpectedPeerUID: &pu, ExpectedPeerGID: &pg, ExpectedKeyEpoch: 7,
	}
}

func productionEvidenceFixture(p ProductionPolicy) macoschannel.Evidence {
	d := "sha256:" + strings.Repeat("b", 64)
	return macoschannel.Evidence{Local: macoschannel.Peer{UID: *p.ExpectedLocalUID, GID: *p.ExpectedLocalGID}, Peer: macoschannel.Peer{UID: *p.ExpectedPeerUID, GID: *p.ExpectedPeerGID}, KeyEpoch: p.ExpectedKeyEpoch, LocalRelease: p.LocalRelease, PeerRelease: p.PeerRelease, Channel: p.Channel, LocalRole: p.LocalRole, PeerRole: p.PeerRole, BindingDigest: d}
}

func TestProductionPolicyValidatesFreshBindingDigest(t *testing.T) {
	p := productionPolicyFixture()
	sp, err := snapshotPolicy(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyProductionEvidence(productionEvidenceFixture(p), sp); err != nil {
		t.Fatalf("valid evidence rejected: %v", err)
	}
	for _, digest := range []string{"", "sha256:" + strings.Repeat("g", 64), "sha1:" + strings.Repeat("a", 64), "sha256:" + strings.Repeat("a", 63)} {
		ev := productionEvidenceFixture(p)
		ev.BindingDigest = digest
		if err := verifyProductionEvidence(ev, sp); !errors.Is(err, ErrPeer) {
			t.Errorf("digest %q accepted: %v", digest, err)
		}
	}
}

func TestProductionPolicyRejectsSharedUID(t *testing.T) {
	p := productionPolicyFixture()
	*p.ExpectedPeerUID = *p.ExpectedLocalUID
	if p.valid() {
		t.Fatal("policy accepted identical local and peer UID")
	}
}

func TestProductionPolicySnapshotsIdentityPointers(t *testing.T) {
	p := productionPolicyFixture()
	ev := productionEvidenceFixture(p)
	sp, err := snapshotPolicy(p)
	if err != nil {
		t.Fatal(err)
	}
	*p.ExpectedLocalUID, *p.ExpectedPeerUID = 9, 10
	if err := verifyProductionEvidence(ev, sp); err != nil {
		t.Fatalf("snapshot unexpectedly invalid: %v", err)
	}
}

func TestDeterministicCASRequestIDStableAndNamespaceBound(t *testing.T) {
	a := deterministicCASRequestID("anchor", 4, 5, "digest")
	if a != deterministicCASRequestID("anchor", 4, 5, "digest") || !strings.HasPrefix(a, "anchor_") {
		t.Fatal(a)
	}
	if a == deterministicCASRequestID("admission", 4, 5, "digest") || a == deterministicCASRequestID("anchor", 4, 6, "digest") {
		t.Fatal("request id collision")
	}
}

func TestProductionStoreRequiresOpaqueCheckpoint(t *testing.T) {
	if _, err := NewProductionStore(productionStateDir(t), nil); !errors.Is(err, ErrProductionSealed) {
		t.Fatalf("nil checkpoint accepted: %v", err)
	}
	store, err := newProductionStoreForTest(productionStateDir(t), NewTestMonotonicCheckpoint())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, err = NewProductionServer(store, productionPolicyFixture()); err != nil {
		t.Fatal(err)
	}
}

func TestProductionAdmissionCheckpointIsOpaqueCheckpoint(t *testing.T) {
	var _ admission.CheckpointStore = (*ProductionAdmissionCheckpoint)(nil)
	client := &ProductionClient{dial: &fixtureDial{ev: productionEvidenceFixture(productionPolicyFixture())}, policy: mustSnapshotPolicy(t, productionPolicyFixture())}
	cp, err := NewProductionAdmissionCheckpoint(client)
	if err != nil {
		t.Fatal(err)
	}
	if cp == nil {
		t.Fatal("nil production admission checkpoint")
	}
}

func TestProductionCheckpointConstructorsRejectUnauthenticatedClient(t *testing.T) {
	for name, makeCheckpoint := range map[string]func(*ProductionClient) (any, error){
		"anchor": func(c *ProductionClient) (any, error) {
			if c == nil || !c.valid() {
				return nil, ErrProductionSealed
			}
			return newProductionAnchorCheckpointForTest(NewTestMonotonicCheckpoint()), nil
		},
		"admission": func(c *ProductionClient) (any, error) { return NewProductionAdmissionCheckpoint(c) },
		"chat":      func(c *ProductionClient) (any, error) { return NewProductionChatLedgerCheckpoint(c) },
	} {
		if _, err := makeCheckpoint(nil); !errors.Is(err, ErrProductionSealed) {
			t.Errorf("%s nil client: err=%v", name, err)
		}
		if _, err := makeCheckpoint(new(ProductionClient)); !errors.Is(err, ErrProductionSealed) {
			t.Errorf("%s zero client: err=%v", name, err)
		}
	}
	p := productionPolicyFixture()
	client := &ProductionClient{dial: &fixtureDial{ev: productionEvidenceFixture(p)}, policy: mustSnapshotPolicy(t, p)}
	if cp := newProductionAnchorCheckpointForTest(NewTestMonotonicCheckpoint()); cp == nil {
		t.Fatal("valid anchor fixture rejected")
	}
	if cp, err := NewProductionAdmissionCheckpoint(client); err != nil || cp == nil {
		t.Fatalf("valid admission client rejected: %v", err)
	}
	if cp, err := NewProductionChatLedgerCheckpoint(client); err != nil || cp == nil {
		t.Fatalf("valid chat client rejected: %v", err)
	}
}

func TestProductionClientRejectsZeroDialer(t *testing.T) {
	if _, err := NewProductionClient(new(macoschannel.Dialer), productionPolicyFixture()); !errors.Is(err, ErrProductionSealed) {
		t.Fatalf("zero dialer accepted: %v", err)
	}
}

func TestProductionClientRetriesSameRequestIDAfterUncertain(t *testing.T) {
	p := productionPolicyFixture()
	ev := productionEvidenceFixture(p)
	d := &fixtureDial{ev: ev}
	client := &ProductionClient{dial: d, policy: mustSnapshotPolicy(t, p)}
	adapter := &productionAdapter{client: client, namespace: NamespaceAdmission}
	err := adapter.casRetry("stable", "ledger", 0, 1, "sha256:"+strings.Repeat("d", 64))
	if err != nil {
		t.Fatalf("retry err=%v", err)
	}
	if d.calls.Load() != 2 {
		t.Fatalf("dial calls=%d", d.calls.Load())
	}
}

func mustSnapshotPolicy(t *testing.T, p ProductionPolicy) productionPolicy {
	t.Helper()
	got, err := snapshotPolicy(p)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func TestProductionServerCloseJoinsRegisteredHandler(t *testing.T) {
	store, err := newProductionStoreForTest(productionStateDir(t), NewTestMonotonicCheckpoint())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	s, err := NewProductionServer(store, productionPolicyFixture())
	if err != nil {
		t.Fatal(err)
	}
	client, server := net.Pipe()
	conn := fixtureConn{Conn: server, ev: productionEvidenceFixture(productionPolicyFixture())}
	done := make(chan error, 1)
	go func() { done <- s.serveConn(context.Background(), conn) }()
	deadline := time.Now().Add(time.Second)
	for {
		s.mu.Lock()
		n := len(s.active)
		s.mu.Unlock()
		if n == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("handler did not register")
		}
		time.Sleep(time.Millisecond)
	}
	closed := make(chan struct{})
	go func() { s.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("Close did not join handler")
	}
	_ = client.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("handler did not exit")
	}
}
