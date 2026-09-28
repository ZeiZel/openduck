package platformanchor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net"
	"openduck/internal/macoschannel"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

type journalFixtureConn struct {
	net.Conn
	ev macoschannel.Evidence
}

func (c journalFixtureConn) Evidence() macoschannel.Evidence { return c.ev }
func (c journalFixtureConn) Seal(domain string, b []byte) (string, error) {
	h := sha256.New()
	h.Write([]byte(domain))
	h.Write([]byte{0})
	h.Write(b)
	return hex.EncodeToString(h.Sum(nil)), nil
}
func (c journalFixtureConn) Verify(d string, b []byte, t string) error {
	x, _ := c.Seal(d, b)
	if x != t {
		return ErrPeer
	}
	return nil
}

type journalFixtureDial struct {
	mu             sync.Mutex
	s              *JournalServer
	serverEvidence macoschannel.Evidence
	calls          int
	drop           bool
}

func (d *journalFixtureDial) Dial(ctx context.Context) (journalConn, error) {
	d.mu.Lock()
	d.calls++
	n := d.calls
	d.mu.Unlock()
	a, b := net.Pipe()
	if d.drop && n == 1 {
		go func() {
			defer b.Close()
			var e journalEnvelope
			if ReadFrame(b, &e) != nil {
				return
			}
			_, _ = d.s.store.journalRequest(e.Request)
		}()
	} else {
		go func() { _ = d.s.serveConn(ctx, journalFixtureConn{b, d.serverEvidence}) }()
	}
	return journalFixtureConn{a, reverseJournalEvidence(d.serverEvidence)}, nil
}
func journalPolicyFixture() (JournalPolicy, JournalPolicy, macoschannel.Evidence) {
	u, g, pu, pg := uint32(1000), uint32(100), uint32(1001), uint32(101)
	x := strings.Repeat("a", 64)
	server := ProductionPolicy{Channel: JournalAudience, LocalRole: "anchor", PeerRole: "installer", LocalRelease: macoschannel.ReleasePin{ReleaseID: "a", BinaryDigest: x, SocketDigest: x, ManifestDigest: x}, PeerRelease: macoschannel.ReleasePin{ReleaseID: "i", BinaryDigest: x, SocketDigest: x, ManifestDigest: x}, ExpectedLocalUID: &u, ExpectedLocalGID: &g, ExpectedPeerUID: &pu, ExpectedPeerGID: &pg, ExpectedKeyEpoch: 3}
	ev := macoschannel.Evidence{Local: macoschannel.Peer{UID: u, GID: g}, Peer: macoschannel.Peer{UID: pu, GID: pg}, KeyEpoch: 3, LocalRelease: server.LocalRelease, PeerRelease: server.PeerRelease, Channel: JournalAudience, LocalRole: "anchor", PeerRole: "installer", BindingDigest: "sha256:" + strings.Repeat("b", 64)}
	client := server
	client.LocalRole, client.PeerRole = "installer", "anchor"
	client.LocalRelease, client.PeerRelease = server.PeerRelease, server.LocalRelease
	client.ExpectedLocalUID, client.ExpectedPeerUID = &pu, &u
	client.ExpectedLocalGID, client.ExpectedPeerGID = &pg, &g
	return JournalPolicy{server, JournalAudience}, JournalPolicy{client, JournalAudience}, ev
}
func reverseJournalEvidence(e macoschannel.Evidence) macoschannel.Evidence {
	e.Local, e.Peer = e.Peer, e.Local
	e.LocalRole, e.PeerRole = e.PeerRole, e.LocalRole
	e.LocalRelease, e.PeerRelease = e.PeerRelease, e.LocalRelease
	return e
}
func TestJournalProductionTransportRetryAndNegative(t *testing.T) {
	d := t.TempDir()
	if e := os.Chmod(d, 0700); e != nil {
		t.Fatal(e)
	}
	cp := NewTestMonotonicCheckpoint()
	s, e := NewSyntheticStoreWithCheckpoint(d, cp)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	sp, cl, ev := journalPolicyFixture()
	srv, e := NewJournalServer(s, sp)
	if e != nil {
		t.Fatal(e)
	}
	dial := &journalFixtureDial{s: srv, serverEvidence: ev, drop: true}
	c := &JournalProductionClient{dial: dial, policy: mustJournalPolicy(t, cl)}
	rel := "sha256:" + strings.Repeat("a", 64)
	one := "sha256:" + strings.Repeat("c", 64)
	if e = c.CAS(context.Background(), "id1", "run", rel, "n1", 0, 1, "", one); e != nil {
		t.Fatal(e)
	}
	if e = c.CAS(context.Background(), "id1", "run", rel, "n2", 0, 1, "", one); !errors.Is(e, ErrReplay) {
		t.Fatalf("conflict=%v", e)
	}
	if e = c.CAS(context.Background(), "id2", "run", rel, "n2", 1, 2, "sha256:"+strings.Repeat("d", 64), "sha256:"+strings.Repeat("e", 64)); !errors.Is(e, ErrCAS) {
		t.Fatalf("stale=%v", e)
	}
	dial.mu.Lock()
	calls := dial.calls
	dial.mu.Unlock()
	if calls < 2 {
		t.Fatalf("calls=%d", calls)
	}
}
func mustJournalPolicy(t *testing.T, p JournalPolicy) productionPolicy {
	t.Helper()
	x, e := p.snapshot()
	if e != nil {
		t.Fatal(e)
	}
	return x
}
func TestJournalTransportRejectsEvidenceAndCancellation(t *testing.T) {
	sp, _, ev := journalPolicyFixture()
	d := t.TempDir()
	if e := os.Chmod(d, 0700); e != nil {
		t.Fatal(e)
	}
	st, e := NewSyntheticStoreWithCheckpoint(d, NewTestMonotonicCheckpoint())
	if e != nil {
		t.Fatal(e)
	}
	defer st.Close()
	srv, e := NewJournalServer(st, sp)
	if e != nil {
		t.Fatal(e)
	}
	for _, mut := range []func(*macoschannel.Evidence){func(x *macoschannel.Evidence) { x.KeyEpoch++ }, func(x *macoschannel.Evidence) { x.Peer.UID++ }, func(x *macoschannel.Evidence) { x.LocalRole = "wrong" }, func(x *macoschannel.Evidence) { x.PeerRelease.ReleaseID = "wrong" }, func(x *macoschannel.Evidence) { x.Channel = "wrong" }} {
		a, b := net.Pipe()
		bad := ev
		mut(&bad)
		if e = srv.serveConn(context.Background(), journalFixtureConn{b, bad}); !errors.Is(e, ErrPeer) {
			t.Fatalf("evidence=%v", e)
		}
		a.Close()
	}
	a, b := net.Pipe()
	defer b.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- srv.serveConn(ctx, journalFixtureConn{b, ev}) }()
	a.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("cancel")
	}
}
