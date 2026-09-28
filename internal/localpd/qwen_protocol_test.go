package localpd

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDurableQwenReplayCheckpointReopen(t *testing.T) {
	dir := t.TempDir()
	_ = os.Chmod(dir, 0700)
	cp := NewMemoryQwenReplayCheckpointStore()
	key := []byte("01234567890123456789012345678901")
	s, err := NewTestQwenReplayStore(filepath.Join(dir, "replay"), key, cp)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Reserve("opaque"); err != nil {
		t.Fatal(err)
	}
	if err = s.Complete("opaque"); err != nil {
		t.Fatal(err)
	}
	if c, ok := s.(interface{ Close() error }); ok {
		_ = c.Close()
	}
	s, err = NewTestQwenReplayStore(filepath.Join(dir, "replay"), key, cp)
	if err != nil {
		t.Fatal(err)
	}
	defer s.(interface{ Close() error }).Close()
	if err = s.Reserve("opaque"); !errors.Is(err, ErrQwenReplay) {
		t.Fatalf("replay=%v", err)
	}
}

func TestDefaultQwenProtocolIsExactAndDisabled(t *testing.T) {
	c := DefaultQwenProtocolConfig()
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	if got := NewSyntheticQwenSidecar(false, func([]byte) ([]byte, error) { return []byte("sentinel"), nil }); true {
		h := QwenHandshake{Version: QwenProtocolV1, RuntimeID: "r", RuntimeDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Config: c, ConfigDigest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}
		now := time.Now().UTC()
		r := qwenRequest{Version: QwenProtocolV1, RequestID: "req", Nonce: "nonce", IssuedAt: now, Deadline: now.Add(time.Second), Pair: CurrentQwenPair{RuntimeDigest: h.RuntimeDigest, ConfigDigest: h.ConfigDigest}, Config: c, Payload: []byte("x")}
		r.PayloadDigest, _ = canonicalQwenDigest(r.Payload)
		r.ControllerSignature = "bad"
		h.Pair = r.Pair
		_, err := got.Exchange(context.Background(), h, r)
		if !errors.Is(err, ErrQwenDisabled) {
			t.Fatalf("disabled=%v", err)
		}
	}
}

func TestQwenThinkingBooleanRequiresAttestedMapping(t *testing.T) {
	c := DefaultQwenProtocolConfig()
	s := testQwenSidecar(func(p []byte) ([]byte, error) { return p, nil })
	digest := "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	auth := QwenTestAuthenticator{Token: "synthetic-test-only"}
	h := QwenHandshake{Version: QwenProtocolV1, RuntimeID: "r", RuntimeDigest: digest, Config: c, ConfigDigest: digest}
	now := time.Now().UTC()
	r := qwenRequest{Version: QwenProtocolV1, RequestID: "req", Nonce: "nonce", IssuedAt: now, Deadline: now.Add(time.Second), Pair: CurrentQwenPair{RuntimeDigest: digest, ConfigDigest: digest}, Config: c, Payload: []byte("x"), Think: ptr(true)}
	r.PayloadDigest, _ = canonicalQwenDigest(r.Payload)
	h.Pair = r.Pair
	r.ControllerSignature, _ = auth.Sign(requestUnsigned(r))
	h.ControllerSignature, _ = auth.Sign(handshakeUnsigned(h))
	if _, err := s.Exchange(context.Background(), h, r); !errors.Is(err, ErrQwenThinkingMap) {
		t.Fatalf("unmapped=%v", err)
	}
	m := QwenThinkingMapping{Semantic: QwenThinkingMedium, Boolean: true, PairRuntimeDigest: digest, PairConfigDigest: digest}
	m.Digest, _ = canonicalQwenDigest(struct {
		Semantic string `json:"semantic"`
		Boolean  bool   `json:"boolean"`
	}{m.Semantic, m.Boolean})
	m.ControllerSignature, _ = auth.Sign(mappingUnsigned(m))
	r.Mapping, h.Mapping = &m, &m
	r.ControllerSignature, _ = auth.Sign(requestUnsigned(r))
	h.ControllerSignature, _ = auth.Sign(handshakeUnsigned(h))
	if _, err := s.Exchange(context.Background(), h, r); err != nil {
		t.Fatalf("mapped=%v", err)
	}
	falseThink := false
	r.Think = &falseThink
	r.Nonce = "negative"
	r.ControllerSignature, _ = auth.Sign(requestUnsigned(r))
	if _, err := s.Exchange(context.Background(), h, r); !errors.Is(err, ErrQwenThinkingMap) {
		t.Fatalf("think mismatch=%v", err)
	}
}

func TestQwenSidecarRejectsReplayDriftAndOversize(t *testing.T) {
	c := DefaultQwenProtocolConfig()
	digest := "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	s := testQwenSidecar(func(p []byte) ([]byte, error) { return append([]byte("ok:"), p...), nil })
	h := QwenHandshake{Version: QwenProtocolV1, RuntimeID: "r", RuntimeDigest: digest, Config: c, ConfigDigest: digest}
	now := time.Now().UTC()
	r := qwenRequest{Version: QwenProtocolV1, RequestID: "req", Nonce: "nonce", IssuedAt: now, Deadline: now.Add(time.Second), Pair: CurrentQwenPair{RuntimeDigest: digest, ConfigDigest: digest}, Config: c, Payload: []byte("x")}
	r.PayloadDigest, _ = canonicalQwenDigest(r.Payload)
	h.Pair = r.Pair
	auth := QwenTestAuthenticator{Token: "synthetic-test-only"}
	r.ControllerSignature, _ = auth.Sign(requestUnsigned(r))
	h.ControllerSignature, _ = auth.Sign(handshakeUnsigned(h))
	if _, err := s.Exchange(context.Background(), h, r); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Exchange(context.Background(), h, r); !errors.Is(err, ErrQwenReplay) {
		t.Fatalf("replay=%v", err)
	}
	c.NumCtx = 32768
	h.Config = c
	r.Nonce = "nonce-2"
	r.Config = c
	r.ControllerSignature, _ = auth.Sign(requestUnsigned(r))
	h.ControllerSignature, _ = auth.Sign(handshakeUnsigned(h))
	if _, err := s.Exchange(context.Background(), h, r); !errors.Is(err, ErrQwenConfigDrift) {
		t.Fatalf("drift=%v", err)
	}
}

func TestQwenSidecarOutageAndOutputBound(t *testing.T) {
	c := DefaultQwenProtocolConfig()
	digest := "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	now := time.Now().UTC()
	h := QwenHandshake{Version: QwenProtocolV1, RuntimeID: "r", RuntimeDigest: digest, Config: c, ConfigDigest: digest}
	r := qwenRequest{Version: QwenProtocolV1, RequestID: "req", Nonce: "nonce", IssuedAt: now, Deadline: now.Add(time.Second), Pair: CurrentQwenPair{RuntimeDigest: digest, ConfigDigest: digest}, Config: c, Payload: []byte("x")}
	r.PayloadDigest, _ = canonicalQwenDigest(r.Payload)
	h.Pair = r.Pair
	auth := QwenTestAuthenticator{Token: "synthetic-test-only"}
	r.ControllerSignature, _ = auth.Sign(requestUnsigned(r))
	h.ControllerSignature, _ = auth.Sign(handshakeUnsigned(h))
	s := testQwenSidecar(func([]byte) ([]byte, error) { return nil, errors.New("outage") })
	if _, err := s.Exchange(context.Background(), h, r); !errors.Is(err, ErrQwenUnavailable) {
		t.Fatalf("outage=%v", err)
	}
	s = testQwenSidecar(func([]byte) ([]byte, error) { return make([]byte, maxQwenOutputBytes+1), nil })
	if _, err := s.Exchange(context.Background(), h, r); !errors.Is(err, ErrQwenOutputBound) {
		t.Fatalf("bound=%v", err)
	}
}

func TestQwenReplayStoreSurvivesNewSidecarAndIdentityCollisions(t *testing.T) {
	c := DefaultQwenProtocolConfig()
	d := "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	auth := QwenTestAuthenticator{Token: "k"}
	store := NewMemoryQwenReplayStore()
	h := QwenHandshake{Version: QwenProtocolV1, RuntimeID: "r", RuntimeDigest: d, Config: c, ConfigDigest: d}
	now := time.Now().UTC()
	makeReq := func(id, nonce string) qwenRequest {
		r := qwenRequest{Version: QwenProtocolV1, RequestID: id, Nonce: nonce, IssuedAt: now, Deadline: now.Add(time.Second), Pair: CurrentQwenPair{RuntimeDigest: d, ConfigDigest: d}, Config: c, Payload: []byte("x")}
		r.PayloadDigest, _ = canonicalQwenDigest(r.Payload)
		r.ControllerSignature, _ = auth.Sign(requestUnsigned(r))
		return r
	}
	r := makeReq("id", "nonce")
	h.Pair = r.Pair
	h.ControllerSignature, _ = auth.Sign(handshakeUnsigned(h))
	s := NewSyntheticQwenSidecarContext(true, func(_ context.Context, _ []byte) ([]byte, error) { return []byte("ok"), nil }, auth, store)
	if _, err := s.Exchange(context.Background(), h, r); err != nil {
		t.Fatal(err)
	}
	s = NewSyntheticQwenSidecarContext(true, func(_ context.Context, _ []byte) ([]byte, error) { return []byte("bad"), nil }, auth, store)
	if _, err := s.Exchange(context.Background(), h, r); !errors.Is(err, ErrQwenReplay) {
		t.Fatalf("restart replay=%v", err)
	}
	for _, x := range []qwenRequest{makeReq("id", "other-nonce"), makeReq("other-id", "nonce")} {
		if _, err := s.Exchange(context.Background(), h, x); !errors.Is(err, ErrQwenReplay) {
			t.Fatalf("identity replay=%v", err)
		}
	}
}

func TestQwenContextCancellationIsFailClosed(t *testing.T) {
	c := DefaultQwenProtocolConfig()
	d := "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	auth := QwenTestAuthenticator{Token: "k"}
	store := NewMemoryQwenReplayStore()
	started := make(chan struct{})
	fn := func(ctx context.Context, _ []byte) ([]byte, error) {
		close(started)
		<-ctx.Done()
		return nil, ctx.Err()
	}
	s := NewSyntheticQwenSidecarContext(true, fn, auth, store)
	h := QwenHandshake{Version: QwenProtocolV1, RuntimeID: "r", RuntimeDigest: d, Config: c, ConfigDigest: d}
	now := time.Now().UTC()
	r := qwenRequest{Version: QwenProtocolV1, RequestID: "id", Nonce: "n", IssuedAt: now, Deadline: now.Add(time.Second), Pair: CurrentQwenPair{RuntimeDigest: d, ConfigDigest: d}, Config: c, Payload: []byte("x")}
	r.PayloadDigest, _ = canonicalQwenDigest(r.Payload)
	h.Pair = r.Pair
	h.ControllerSignature, _ = auth.Sign(handshakeUnsigned(h))
	r.ControllerSignature, _ = auth.Sign(requestUnsigned(r))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { _, e := s.Exchange(ctx, h, r); done <- e }()
	<-started
	cancel()
	if err := <-done; !errors.Is(err, ErrQwenUnavailable) {
		t.Fatalf("cancel=%v", err)
	}
}

func ptr(v bool) *bool { return &v }

func testQwenSidecar(fn func([]byte) ([]byte, error)) QwenSidecar {
	auth := QwenTestAuthenticator{Token: "synthetic-test-only"}
	return NewSyntheticQwenSidecarContext(true, func(_ context.Context, p []byte) ([]byte, error) { return fn(p) }, auth, NewMemoryQwenReplayStore())
}
