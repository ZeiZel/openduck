package macoschannel

import (
	"bytes"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
)

func bindingPair(t *testing.T, nonceA, nonceB string) (*authenticatedConn, *authenticatedConn) {
	t.Helper()
	key := []byte("01234567890123456789012345678901")
	pa := ReleasePin{ReleaseID: "release-a", BinaryDigest: digest("a-bin"), SocketDigest: digest("socket"), ManifestDigest: digest("a-manifest")}
	pb := ReleasePin{ReleaseID: "release-b", BinaryDigest: digest("b-bin"), SocketDigest: digest("socket"), ManifestDigest: digest("b-manifest")}
	a := hello{Version: ProtocolVersion, Channel: "codex-control", LocalRole: "controller", PeerRole: "broker", UID: 501, GID: 20, KeyEpoch: 9, Release: pa, Nonce: nonceA}
	b := hello{Version: ProtocolVersion, Channel: "codex-control", LocalRole: "broker", PeerRole: "controller", UID: 502, GID: 21, KeyEpoch: 9, Release: pb, Nonce: nonceB}
	bindingA := deriveBindingKey(key, a, b)
	bindingB := deriveBindingKey(key, b, a)
	if !bytes.Equal(bindingA, bindingB) {
		t.Fatal("binding derivation differs by endpoint")
	}
	d := bindingDigest(bindingA, a, b)
	evA := Evidence{Peer: Peer{UID: b.UID, GID: b.GID}, KeyEpoch: 9, LocalRelease: pa, PeerRelease: pb, Channel: a.Channel, LocalRole: a.LocalRole, PeerRole: a.PeerRole, BindingDigest: d}
	evB := Evidence{Peer: Peer{UID: a.UID, GID: a.GID}, KeyEpoch: 9, LocalRelease: pb, PeerRelease: pa, Channel: b.Channel, LocalRole: b.LocalRole, PeerRole: b.PeerRole, BindingDigest: d}
	left, right := net.Pipe()
	t.Cleanup(func() { _ = left.Close(); _ = right.Close() })
	return newAuthenticatedConn(left, authentication{evidence: evA, binding: bindingA}), newAuthenticatedConn(right, authentication{evidence: evB, binding: bindingB})
}

func TestBindingSealVerifySameAuthenticatedConnection(t *testing.T) {
	a, b := bindingPair(t, strings.Repeat("a", 64), strings.Repeat("b", 64))
	payload := []byte(`{"sequence":1,"operation":"inventory"}`)
	tag, err := a.Seal("codexbroker.frame.v1", payload)
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Verify("codexbroker.frame.v1", payload, tag); err != nil {
		t.Fatalf("peer rejected bound payload: %v", err)
	}
	if a.Evidence().BindingDigest == "" || a.Evidence().BindingDigest != b.Evidence().BindingDigest {
		t.Fatal("missing shared non-secret binding digest")
	}
	if err := a.Verify("codexbroker.frame.v1", payload, tag); !errors.Is(err, ErrBinding) {
		t.Fatalf("outbound tag accepted as inbound: %v", err)
	}
}

func TestBindingRejectsSpliceReplayAndNonCanonicalInputs(t *testing.T) {
	a, b := bindingPair(t, strings.Repeat("a", 64), strings.Repeat("b", 64))
	_, d := bindingPair(t, strings.Repeat("c", 64), strings.Repeat("d", 64))
	payload := []byte("canonical payload")
	tag, err := a.Seal("codexbroker.frame.v1", payload)
	if err != nil {
		t.Fatal(err)
	}
	checks := []struct {
		name    string
		conn    *authenticatedConn
		domain  string
		payload []byte
		tag     string
	}{
		{"other connection", d, "codexbroker.frame.v1", payload, tag},
		{"wrong direction", a, "codexbroker.frame.v1", payload, tag},
		{"wrong domain", b, "codexbroker.attestation.v1", payload, tag},
		{"wrong payload", b, "codexbroker.frame.v1", []byte("canonical payload!"), tag},
		{"wrong tag", b, "codexbroker.frame.v1", payload, strings.Repeat("0", 64)},
		{"uppercase tag", b, "codexbroker.frame.v1", payload, strings.ToUpper(tag)},
	}
	for _, tc := range checks {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.conn.Verify(tc.domain, tc.payload, tc.tag); !errors.Is(err, ErrBinding) {
				t.Fatalf("splice accepted: %v", err)
			}
		})
	}
	for _, mutate := range []func(*Evidence){
		func(ev *Evidence) { ev.Channel = "anchor-control" },
		func(ev *Evidence) { ev.LocalRole, ev.PeerRole = ev.PeerRole, ev.LocalRole },
	} {
		left, right := net.Pipe()
		badEvidence := b.ev
		mutate(&badEvidence)
		bad := newAuthenticatedConn(left, authentication{evidence: badEvidence, binding: append([]byte(nil), b.binding...)})
		t.Cleanup(func() { _ = bad.Close(); _ = right.Close() })
		if err := bad.Verify("codexbroker.frame.v1", payload, tag); !errors.Is(err, ErrBinding) {
			t.Fatalf("channel/role splice accepted: %v", err)
		}
	}
	for _, domain := range []string{"", "Codexbroker.frame.v1", ".codex", "codex..frame", "codex//frame", "codex./frame", "codex.", strings.Repeat("a", maxBindingDomain+1)} {
		if _, err := a.Seal(domain, payload); !errors.Is(err, ErrBinding) {
			t.Fatalf("invalid domain %q accepted: %v", domain, err)
		}
	}
	if _, err := a.Seal("codexbroker.frame.v1", nil); !errors.Is(err, ErrBinding) {
		t.Fatalf("empty canonical bytes accepted: %v", err)
	}
	if _, err := a.Seal("codexbroker.frame.v1", make([]byte, maxBindingCanonical+1)); !errors.Is(err, ErrBinding) {
		t.Fatalf("oversized canonical bytes accepted: %v", err)
	}
}

func TestBindingDerivationCoversExactHandshakeEvidence(t *testing.T) {
	key := []byte("01234567890123456789012345678901")
	p := ReleasePin{ReleaseID: "release", BinaryDigest: digest("bin"), SocketDigest: digest("socket"), ManifestDigest: digest("manifest")}
	a := hello{Version: ProtocolVersion, Channel: "codex-control", LocalRole: "controller", PeerRole: "broker", UID: 501, GID: 20, KeyEpoch: 9, Release: p, Nonce: strings.Repeat("a", 64)}
	b := hello{Version: ProtocolVersion, Channel: "codex-control", LocalRole: "broker", PeerRole: "controller", UID: 502, GID: 21, KeyEpoch: 9, Release: p, Nonce: strings.Repeat("b", 64)}
	want := deriveBindingKey(key, a, b)
	mutations := []func(*hello){
		func(h *hello) { h.Nonce = strings.Repeat("c", 64) },
		func(h *hello) { h.Channel = "anchor-control" },
		func(h *hello) { h.LocalRole = "other" },
		func(h *hello) { h.PeerRole = "other" },
		func(h *hello) { h.Release.ReleaseID = "other" },
		func(h *hello) { h.UID++ },
		func(h *hello) { h.GID++ },
		func(h *hello) { h.KeyEpoch++ },
	}
	for _, mutate := range mutations {
		changed := b
		mutate(&changed)
		if bytes.Equal(want, deriveBindingKey(key, a, changed)) {
			t.Fatal("handshake evidence field omitted from binding derivation")
		}
	}
}

func TestBindingConcurrentUse(t *testing.T) {
	a, b := bindingPair(t, strings.Repeat("a", 64), strings.Repeat("b", 64))
	const workers = 64
	var wg sync.WaitGroup
	errCh := make(chan error, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			payload := []byte("same canonical payload")
			tag, err := a.Seal("codexbroker.frame.v1", payload)
			if err == nil {
				err = b.Verify("codexbroker.frame.v1", payload, tag)
			}
			errCh <- err
		}()
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestBindingCloseZeroizesKeyAndFailsClosed(t *testing.T) {
	a, _ := bindingPair(t, strings.Repeat("a", 64), strings.Repeat("b", 64))
	keyStorage := a.binding
	if len(keyStorage) != 32 || bytes.Equal(keyStorage, make([]byte, 32)) {
		t.Fatal("test seam has no live binding key")
	}
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(keyStorage, make([]byte, 32)) || a.binding != nil {
		t.Fatal("binding key was not zeroized before release")
	}
	if _, err := a.Seal("codexbroker.frame.v1", []byte("x")); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("seal after close err=%v", err)
	}
	if err := a.Verify("codexbroker.frame.v1", []byte("x"), strings.Repeat("0", 64)); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("verify after close err=%v", err)
	}
	if _, err := a.Seal("BAD", nil); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("closed state did not take precedence: %v", err)
	}
}
