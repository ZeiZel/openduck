package platformcheckpoint

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"openduck/internal/macoschannel"
)

type testConn struct {
	net.Conn
	ev        macoschannel.Evidence
	verifyErr error
}

type reconnectDial struct {
	mu       sync.Mutex
	policy   Policy
	evidence macoschannel.Evidence
	mode     string
	calls    int
	ids      []string
	commits  int
	store    *Store
	read     chan struct{}
}

func (d *reconnectDial) Dial(context.Context) (sealedConn, error) {
	d.mu.Lock()
	d.calls++
	call := d.calls
	d.mu.Unlock()
	left, right := net.Pipe()
	client := &testConn{Conn: left, ev: d.evidence}
	go func() {
		defer right.Close()
		var req envelope
		if ReadFrame(right, &req) != nil {
			return
		}
		d.mu.Lock()
		d.ids = append(d.ids, req.Request.RequestID)
		d.mu.Unlock()
		if d.read != nil && call == 1 {
			close(d.read)
		}
		if d.mode == "before" && call == 1 {
			// The authority did not commit before this connection was lost.
			return
		}
		if d.mode == "cancel" && call == 1 {
			time.Sleep(100 * time.Millisecond)
			return
		}
		if d.mode == "always_uncertain" {
			return
		}
		resp := Response{SchemaVersion: SchemaVersion, RequestID: req.Request.RequestID, OK: true, Generation: req.Request.Next, Digest: req.Request.Digest}
		if d.store != nil {
			err := d.store.CAS(req.Request.RequestID, req.Request.Expected, req.Request.Next, req.Request.Digest)
			if err != nil {
				resp.OK, resp.Error = false, err.Error()
				resp.Generation, resp.Digest = 0, ""
			} else if resp.Generation, resp.Digest, err = d.store.Load(); err != nil {
				resp.OK, resp.Error = false, ErrUnavailable.Error()
				resp.Generation, resp.Digest = 0, ""
			}
			d.mu.Lock()
			if resp.OK && d.commits == 0 {
				d.commits = 1
			}
			d.mu.Unlock()
		}
		if d.mode == "after" && call == 1 {
			// The authority committed, but the response was lost. The retry
			// must replay the same request ID without a second commit.
			return
		}
		if d.mode == "cas" {
			resp.OK = false
			resp.Generation, resp.Digest, resp.Error = 0, "", ErrCAS.Error()
		}
		canonical, _ := marshal(resp)
		tag, _ := (&testConn{Conn: right}).Seal("platform-checkpoint.response", canonical)
		_ = WriteFrame(right, responseEnvelope{Response: resp, Tag: tag})
	}()
	return client, nil
}

func TestProductionClientReconnectsUncertainCASWithSameRequestID(t *testing.T) {
	_, policy, _, evidence := transportFixtures(t)
	for _, mode := range []string{"before", "after"} {
		t.Run(mode, func(t *testing.T) {
			store, err := NewStore(privateDir(t))
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			d := &reconnectDial{policy: policy, evidence: evidence, mode: mode, store: store}
			c := newProductionClientForTest(d, policy)
			if err := c.CAS(context.Background(), "stable", 0, 1, testDigest(1)); err != nil {
				t.Fatalf("CAS: %v", err)
			}
			d.mu.Lock()
			calls, ids := d.calls, append([]string(nil), d.ids...)
			d.mu.Unlock()
			d.mu.Lock()
			commits := d.commits
			d.mu.Unlock()
			if calls != 2 || len(ids) != 2 || ids[0] != "stable" || ids[1] != ids[0] {
				t.Fatalf("calls=%d ids=%v", calls, ids)
			}
			wantCommits := 1
			if commits != wantCommits {
				t.Fatalf("commits=%d want=%d", commits, wantCommits)
			}
			generation, digest, err := store.Load()
			if err != nil || generation != 1 || digest != testDigest(1) {
				t.Fatalf("store=(%d,%q,%v)", generation, digest, err)
			}
		})
	}
}

func TestProductionClientCancellationPreventsReconnect(t *testing.T) {
	_, policy, _, evidence := transportFixtures(t)
	read := make(chan struct{})
	d := &reconnectDial{policy: policy, evidence: evidence, mode: "cancel", read: read}
	ctx, cancel := context.WithCancel(context.Background())
	c := newProductionClientForTest(d, policy)
	go func() { <-read; cancel() }()
	err := c.CAS(ctx, "stable", 0, 1, testDigest(1))
	if !errors.Is(err, ErrUncertain) || !errors.Is(err, context.Canceled) {
		t.Fatalf("err=%v", err)
	}
	d.mu.Lock()
	calls := d.calls
	d.mu.Unlock()
	if calls != 1 {
		t.Fatalf("calls=%d", calls)
	}
}

func TestProductionClientDoesNotRetryTypedCAS(t *testing.T) {
	_, policy, _, evidence := transportFixtures(t)
	d := &reconnectDial{policy: policy, evidence: evidence, mode: "cas"}
	c := newProductionClientForTest(d, policy)
	if err := c.CAS(context.Background(), "stable", 0, 1, testDigest(1)); !errors.Is(err, ErrCAS) {
		t.Fatalf("err=%v", err)
	}
	d.mu.Lock()
	calls := d.calls
	d.mu.Unlock()
	if calls != 1 {
		t.Fatalf("calls=%d", calls)
	}
}

func TestProductionClientCapsUncertainCASAtTwoAttempts(t *testing.T) {
	_, policy, _, evidence := transportFixtures(t)
	d := &reconnectDial{policy: policy, evidence: evidence, mode: "always_uncertain"}
	c := newProductionClientForTest(d, policy)
	err := c.CAS(context.Background(), "stable", 0, 1, testDigest(1))
	if !errors.Is(err, ErrUncertain) {
		t.Fatalf("err=%v", err)
	}
	d.mu.Lock()
	calls, ids := d.calls, append([]string(nil), d.ids...)
	d.mu.Unlock()
	if calls != 2 || len(ids) != 2 || ids[0] != ids[1] {
		t.Fatalf("calls=%d ids=%v", calls, ids)
	}
}

func (c *testConn) Evidence() macoschannel.Evidence { return c.ev }
func (c *testConn) Seal(domain string, canonical []byte) (string, error) {
	h := sha256.New()
	_, _ = h.Write([]byte(domain))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write(canonical)
	return hex.EncodeToString(h.Sum(nil)), nil
}
func (c *testConn) Verify(domain string, canonical []byte, tag string) error {
	if c.verifyErr != nil {
		return c.verifyErr
	}
	want, _ := c.Seal(domain, canonical)
	if tag != want {
		return macoschannel.ErrBinding
	}
	return nil
}

func testRelease(id, digit string) macoschannel.ReleasePin {
	d := strings.Repeat(digit, 64)
	return macoschannel.ReleasePin{ReleaseID: id, BinaryDigest: d, SocketDigest: d, ManifestDigest: d}
}

func transportFixtures(t *testing.T) (Policy, Policy, macoschannel.Evidence, macoschannel.Evidence) {
	t.Helper()
	authorityRelease := testRelease("authority-release", "a")
	controllerRelease := testRelease("controller-release", "b")
	serverPolicy := Policy{
		Channel: "checkpoint-control", LocalRole: "authority", PeerRole: "controller",
		LocalUID: 1001, LocalGID: 2001, PeerUID: 1002, PeerGID: 2002, KeyEpoch: 9,
		LocalRelease: authorityRelease, PeerRelease: controllerRelease,
	}
	clientPolicy := Policy{
		Channel: "checkpoint-control", LocalRole: "controller", PeerRole: "authority",
		LocalUID: 1002, LocalGID: 2002, PeerUID: 1001, PeerGID: 2001, KeyEpoch: 9,
		LocalRelease: controllerRelease, PeerRelease: authorityRelease,
	}
	serverEvidence := macoschannel.Evidence{
		Local: macoschannel.Peer{UID: 1001, GID: 2001}, Peer: macoschannel.Peer{UID: 1002, GID: 2002},
		KeyEpoch: 9, LocalRelease: authorityRelease, PeerRelease: controllerRelease,
		Channel: "checkpoint-control", LocalRole: "authority", PeerRole: "controller", BindingDigest: testDigest(9),
	}
	clientEvidence := macoschannel.Evidence{
		Local: macoschannel.Peer{UID: 1002, GID: 2002}, Peer: macoschannel.Peer{UID: 1001, GID: 2001},
		KeyEpoch: 9, LocalRelease: controllerRelease, PeerRelease: authorityRelease,
		Channel: "checkpoint-control", LocalRole: "controller", PeerRole: "authority", BindingDigest: testDigest(9),
	}
	return serverPolicy, clientPolicy, serverEvidence, clientEvidence
}

func TestTransportLifecycleTypedErrorsAndConcurrentClientSerialization(t *testing.T) {
	store, err := NewStore(privateDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	serverPolicy, clientPolicy, serverEvidence, clientEvidence := transportFixtures(t)
	left, right := net.Pipe()
	serverConn := &testConn{Conn: right, ev: serverEvidence}
	clientConn := &testConn{Conn: left, ev: clientEvidence}
	server, err := NewServer(store, serverPolicy)
	if err != nil {
		t.Fatal(err)
	}
	client, err := newClient(clientConn, clientPolicy)
	if err != nil {
		t.Fatal(err)
	}
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.serveConn(context.Background(), serverConn) }()

	if generation, digest, err := client.Load(context.Background()); err != nil || generation != 0 || digest != "" {
		t.Fatalf("initial load=(%d,%q,%v)", generation, digest, err)
	}
	digest := testDigest(1)
	if err := client.CAS(context.Background(), "cas-1", 0, 1, digest); err != nil {
		t.Fatal(err)
	}
	if err := client.CAS(context.Background(), "cas-1", 0, 1, digest); err != nil {
		t.Fatalf("idempotent replay=%v", err)
	}
	if err := client.CAS(context.Background(), "cas-1", 0, 1, testDigest(2)); !errors.Is(err, ErrReplay) {
		t.Fatalf("typed replay=%v", err)
	}
	if err := client.CAS(context.Background(), "cas-mismatch", 8, 9, testDigest(3)); !errors.Is(err, ErrCAS) {
		t.Fatalf("typed cas=%v", err)
	}

	const callers = 48
	var wg sync.WaitGroup
	errs := make(chan error, callers)
	for range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			generation, got, err := client.Load(context.Background())
			if err == nil && (generation != 1 || got != digest) {
				err = ErrProtocol
			}
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-serveDone:
		// net.Pipe may report its private closed-pipe sentinel from the next
		// SetDeadline rather than EOF; a Unix socket reports EOF here.
		if err != nil && err.Error() != "io: read/write on closed pipe" {
			t.Fatalf("serve=%v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Client.Close did not unblock server")
	}
}

func TestTransportRejectsInvalidPolicyAndEvidence(t *testing.T) {
	store, err := NewStore(privateDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	serverPolicy, clientPolicy, _, clientEvidence := transportFixtures(t)
	bad := serverPolicy
	bad.PeerUID = bad.LocalUID
	if _, err := NewServer(store, bad); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("server policy=%v", err)
	}
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	for name, mutate := range map[string]func(*macoschannel.Evidence){
		"key epoch":       func(e *macoschannel.Evidence) { e.KeyEpoch++ },
		"missing binding": func(e *macoschannel.Evidence) { e.BindingDigest = "" },
		"peer identity":   func(e *macoschannel.Evidence) { e.Peer.UID++ },
	} {
		t.Run(name, func(t *testing.T) {
			badEvidence := clientEvidence
			mutate(&badEvidence)
			if _, err := newClient(&testConn{Conn: left, ev: badEvidence}, clientPolicy); !errors.Is(err, ErrPeer) {
				t.Fatalf("client evidence=%v", err)
			}
		})
	}
}

func TestClientAndServerCancellationInterruptBlockedIO(t *testing.T) {
	serverPolicy, clientPolicy, serverEvidence, clientEvidence := transportFixtures(t)
	t.Run("client load cancellation", func(t *testing.T) {
		left, right := net.Pipe()
		defer right.Close()
		client, err := newClient(&testConn{Conn: left, ev: clientEvidence}, clientPolicy)
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		time.AfterFunc(20*time.Millisecond, cancel)
		started := time.Now()
		_, _, err = client.Load(ctx)
		if !errors.Is(err, context.Canceled) || time.Since(started) > time.Second {
			t.Fatalf("err=%v elapsed=%s", err, time.Since(started))
		}
	})
	t.Run("client earlier deadline", func(t *testing.T) {
		left, right := net.Pipe()
		defer right.Close()
		client, err := newClient(&testConn{Conn: left, ev: clientEvidence}, clientPolicy)
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
		defer cancel()
		started := time.Now()
		_, _, err = client.Load(ctx)
		if !errors.Is(err, context.DeadlineExceeded) || time.Since(started) > time.Second {
			t.Fatalf("err=%v elapsed=%s", err, time.Since(started))
		}
	})
	t.Run("server cancellation", func(t *testing.T) {
		store, err := NewStore(privateDir(t))
		if err != nil {
			t.Fatal(err)
		}
		defer store.Close()
		server, err := NewServer(store, serverPolicy)
		if err != nil {
			t.Fatal(err)
		}
		left, right := net.Pipe()
		defer left.Close()
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- server.serveConn(ctx, &testConn{Conn: right, ev: serverEvidence}) }()
		cancel()
		select {
		case err := <-done:
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("err=%v", err)
			}
		case <-time.After(time.Second):
			t.Fatal("server cancellation did not interrupt read")
		}
	})
	t.Run("server earlier deadline", func(t *testing.T) {
		store, err := NewStore(privateDir(t))
		if err != nil {
			t.Fatal(err)
		}
		defer store.Close()
		server, err := NewServer(store, serverPolicy)
		if err != nil {
			t.Fatal(err)
		}
		left, right := net.Pipe()
		defer left.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
		defer cancel()
		started := time.Now()
		err = server.serveConn(ctx, &testConn{Conn: right, ev: serverEvidence})
		if !errors.Is(err, context.DeadlineExceeded) || time.Since(started) > time.Second {
			t.Fatalf("err=%v elapsed=%s", err, time.Since(started))
		}
	})
}

func TestClientRejectsProtocolBeforeWriting(t *testing.T) {
	_, clientPolicy, _, clientEvidence := transportFixtures(t)
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	client, err := newClient(&testConn{Conn: left, ev: clientEvidence}, clientPolicy)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.CAS(context.Background(), "overflow", ^uint64(0), 0, testDigest(1)); !errors.Is(err, ErrProtocol) {
		t.Fatalf("err=%v", err)
	}
}

func TestCASPostWriteFailuresAreUncertainAndCorrelated(t *testing.T) {
	_, clientPolicy, _, clientEvidence := transportFixtures(t)
	tests := []struct {
		name   string
		mutate func(*responseEnvelope)
		badTag bool
		eof    bool
	}{
		{name: "EOF", eof: true},
		{name: "bad seal", badTag: true},
		{name: "request id", mutate: func(e *responseEnvelope) { e.Response.RequestID = "other" }},
		{name: "generation", mutate: func(e *responseEnvelope) { e.Response.Generation++ }},
		{name: "digest", mutate: func(e *responseEnvelope) { e.Response.Digest = testDigest(7) }},
		{name: "bad response", mutate: func(e *responseEnvelope) { e.Response.Error = "unexpected" }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			left, right := net.Pipe()
			clientConn := &testConn{Conn: left, ev: clientEvidence}
			peer := &testConn{Conn: right}
			client, err := newClient(clientConn, clientPolicy)
			if err != nil {
				t.Fatal(err)
			}
			go func() {
				defer right.Close()
				var request envelope
				if ReadFrame(peer, &request) != nil || tc.eof {
					return
				}
				response := responseEnvelope{Response: Response{SchemaVersion: SchemaVersion, RequestID: request.Request.RequestID, OK: true, Generation: request.Request.Next, Digest: request.Request.Digest}}
				if tc.mutate != nil {
					tc.mutate(&response)
				}
				canonical, _ := marshal(response.Response)
				response.Tag, _ = peer.Seal("platform-checkpoint.response", canonical)
				if tc.badTag {
					response.Tag = strings.Repeat("0", 64)
				}
				_ = WriteFrame(peer, response)
			}()
			err = client.CAS(context.Background(), "request", 0, 1, testDigest(1))
			if !errors.Is(err, ErrUncertain) {
				t.Fatalf("err=%v", err)
			}
		})
	}
}

func TestCASCancellationAfterPossibleWriteIsUncertain(t *testing.T) {
	_, clientPolicy, _, clientEvidence := transportFixtures(t)
	left, right := net.Pipe()
	defer right.Close()
	client, err := newClient(&testConn{Conn: left, ev: clientEvidence}, clientPolicy)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(20*time.Millisecond, cancel)
	err = client.CAS(ctx, "request", 0, 1, testDigest(1))
	if !errors.Is(err, ErrUncertain) || !errors.Is(err, context.Canceled) {
		t.Fatalf("err=%v", err)
	}
}
