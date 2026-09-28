package platformcheckpoint

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"openduck/internal/macoschannel"
)

type journalDial struct {
	mu        sync.Mutex
	server    *JournalServer
	evidence  macoschannel.Evidence
	calls     int
	dropFirst bool
}

func (d *journalDial) Dial(ctx context.Context) (sealedConn, error) {
	d.mu.Lock()
	d.calls++
	call := d.calls
	d.mu.Unlock()
	left, right := net.Pipe()
	if d.dropFirst && call == 1 {
		go func() {
			defer right.Close()
			var env journalEnvelope
			if ReadFrame(right, &env) != nil {
				return
			}
			b, _ := marshal(env.Request)
			if (&testConn{Conn: right}).Verify(journalRequestDomain, b, env.Tag) != nil {
				return
			}
			// Commit before deliberately losing the response. Retry must use the
			// durable request-id replay record, not create a second signature.
			if env.Request.Operation == "sign" {
				_, _ = d.server.store.JournalSign(env.Request)
			} else {
				_ = d.server.store.JournalVerify(env.Request)
			}
		}()
	} else {
		go func() { _ = d.server.serveConn(ctx, &testConn{Conn: right, ev: d.evidence}) }()
	}
	return &testConn{Conn: left, ev: reverseJournalEvidence(d.evidence)}, nil
}

func journalTransportFixtures() (JournalPolicy, JournalPolicy, macoschannel.Evidence, macoschannel.Evidence) {
	checkpoint := testRelease("checkpoint-release", "a")
	installer := testRelease("installer-release", "b")
	server := JournalPolicy{Policy: Policy{Channel: JournalAudience, LocalRole: "checkpoint", PeerRole: "installer", LocalUID: 1001, LocalGID: 2001, PeerUID: 1002, PeerGID: 2002, KeyEpoch: 9, LocalRelease: checkpoint, PeerRelease: installer}, Audience: JournalAudience}
	client := JournalPolicy{Policy: Policy{Channel: JournalAudience, LocalRole: "installer", PeerRole: "checkpoint", LocalUID: 1002, LocalGID: 2002, PeerUID: 1001, PeerGID: 2001, KeyEpoch: 9, LocalRelease: installer, PeerRelease: checkpoint}, Audience: JournalAudience}
	serverEvidence := macoschannel.Evidence{Local: macoschannel.Peer{UID: 1001, GID: 2001}, Peer: macoschannel.Peer{UID: 1002, GID: 2002}, KeyEpoch: 9, LocalRelease: checkpoint, PeerRelease: installer, Channel: JournalAudience, LocalRole: "checkpoint", PeerRole: "installer", BindingDigest: testDigest(9)}
	clientEvidence := reverseJournalEvidence(serverEvidence)
	return server, client, serverEvidence, clientEvidence
}
func reverseJournalEvidence(e macoschannel.Evidence) macoschannel.Evidence {
	e.Local, e.Peer = e.Peer, e.Local
	e.LocalRelease, e.PeerRelease = e.PeerRelease, e.LocalRelease
	e.LocalRole, e.PeerRole = e.PeerRole, e.LocalRole
	return e
}

func TestProductionJournalClientAuthenticatedE2EAndRetry(t *testing.T) {
	store, err := NewStore(privateDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	serverPolicy, clientPolicy, serverEvidence, _ := journalTransportFixtures()
	server, err := NewJournalServer(store, serverPolicy)
	if err != nil {
		t.Fatal(err)
	}
	dial := &journalDial{server: server, evidence: serverEvidence, dropFirst: true}
	client := newProductionJournalClientForTest(dial, clientPolicy)
	digest := "sha256:" + strings.Repeat("a", 64)
	payload := "sha256:" + strings.Repeat("b", 64)
	sig, err := client.Sign(context.Background(), "request-1", "run-1", digest, "nonce-1", payload, 1)
	if err != nil || len(sig) != 64 {
		t.Fatalf("sign=(%q,%v)", sig, err)
	}
	if err = client.Verify(context.Background(), "verify-1", "run-1", digest, "nonce-1", payload, sig, 1); err != nil {
		t.Fatalf("verify=%v", err)
	}
	dial.mu.Lock()
	calls := dial.calls
	dial.mu.Unlock()
	if calls != 3 {
		t.Fatalf("calls=%d", calls)
	}
	if _, err = client.Sign(context.Background(), "request-1", "run-2", digest, "nonce-1", payload, 1); !errors.Is(err, ErrReplay) {
		t.Fatalf("conflict=%v", err)
	}
}

func TestJournalTransportRejectsDedicatedPolicyAndEvidence(t *testing.T) {
	store, err := NewStore(privateDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	serverPolicy, _, serverEvidence, _ := journalTransportFixtures()
	bad := serverPolicy
	bad.Policy.Channel = "checkpoint-control"
	if _, err = NewJournalServer(store, bad); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("channel=%v", err)
	}
	for name, mutate := range map[string]func(*macoschannel.Evidence){
		"wrong peer":             func(e *macoschannel.Evidence) { e.Peer.UID++ },
		"wrong release":          func(e *macoschannel.Evidence) { e.PeerRelease.ReleaseID = "wrong" },
		"wrong epoch":            func(e *macoschannel.Evidence) { e.KeyEpoch++ },
		"wrong audience channel": func(e *macoschannel.Evidence) { e.Channel = "wrong" },
	} {
		t.Run(name, func(t *testing.T) {
			left, right := net.Pipe()
			defer left.Close()
			defer right.Close()
			badEvidence := serverEvidence
			mutate(&badEvidence)
			server, _ := NewJournalServer(store, serverPolicy)
			if err := server.serveConn(context.Background(), &testConn{Conn: right, ev: badEvidence}); !errors.Is(err, ErrPeer) {
				t.Fatalf("server=%v", err)
			}
		})
	}
}

func TestJournalTransportDeadline(t *testing.T) {
	_, clientPolicy, _, clientEvidence := journalTransportFixtures()
	left, right := net.Pipe()
	defer right.Close()
	d := staticJournalDial{conn: &testConn{Conn: left, ev: clientEvidence}}
	client := newProductionJournalClientForTest(d, clientPolicy)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_, err := client.Sign(ctx, "request-1", "run-1", "sha256:"+strings.Repeat("a", 64), "nonce-1", "sha256:"+strings.Repeat("b", 64), 1)
	if !errors.Is(err, ErrUncertain) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("deadline=%v", err)
	}
}

func TestJournalServerRejectsMalformedFramesBeforeStore(t *testing.T) {
	store, err := NewStore(privateDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	policy, _, evidence, _ := journalTransportFixtures()
	server, err := NewJournalServer(store, policy)
	if err != nil {
		t.Fatal(err)
	}
	for name, frame := range map[string][]byte{
		"unknown":   []byte(`{"request":{},"tag":"","extra":true}`),
		"duplicate": []byte(`{"request":{},"request":{},"tag":""}`),
		"trailing":  []byte(`{"request":{},"tag":""} `),
	} {
		t.Run(name, func(t *testing.T) {
			left, right := net.Pipe()
			done := make(chan error, 1)
			go func() { done <- server.serveConn(context.Background(), &testConn{Conn: right, ev: evidence}) }()
			writeRawJournalFrame(t, left, frame)
			_ = left.Close()
			if err := <-done; !errors.Is(err, ErrProtocol) {
				t.Fatalf("err=%v", err)
			}
		})
	}
	t.Run("oversize", func(t *testing.T) {
		left, right := net.Pipe()
		done := make(chan error, 1)
		go func() { done <- server.serveConn(context.Background(), &testConn{Conn: right, ev: evidence}) }()
		var header [4]byte
		binary.BigEndian.PutUint32(header[:], MaxFrameSize+1)
		if err := writeFull(left, header[:]); err != nil {
			t.Fatal(err)
		}
		_ = left.Close()
		if err := <-done; !errors.Is(err, ErrProtocol) {
			t.Fatalf("err=%v", err)
		}
	})
}
func writeRawJournalFrame(t *testing.T, c net.Conn, frame []byte) {
	t.Helper()
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(frame)))
	if err := writeFull(c, header[:]); err != nil {
		t.Fatal(err)
	}
	if err := writeFull(c, frame); err != nil {
		t.Fatal(err)
	}
}

type staticJournalDial struct{ conn sealedConn }

func (d staticJournalDial) Dial(context.Context) (sealedConn, error) { return d.conn, nil }
