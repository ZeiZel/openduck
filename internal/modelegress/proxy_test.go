package modelegress

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

type fakeResolver struct{ ips []net.IP }

func (r fakeResolver) Resolve(context.Context, string) ([]net.IP, error) { return r.ips, nil }

type blockingResolver struct {
	entered chan struct{}
	release chan struct{}
}

func (r blockingResolver) Resolve(context.Context, string) ([]net.IP, error) {
	close(r.entered)
	<-r.release
	return []net.IP{net.ParseIP("10.0.0.1")}, nil
}

type fakeDialer struct {
	conn    net.Conn
	address string
}

const testProxyToken = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func (d *fakeDialer) DialContext(_ context.Context, _ string, address string) (net.Conn, error) {
	d.address = address
	return d.conn, nil
}

func hello(host string, ech bool) []byte {
	sni := append([]byte{0, byte(len(host) >> 8), byte(len(host))}, []byte(host)...)
	name := append([]byte{0, byte(len(sni))}, sni...)
	ext := append([]byte{0, 0, 0, 0, byte(len(name) >> 8), byte(len(name))}, name...)
	if ech {
		ext = append(ext, 0xfe, 0x0d, 0, 0)
	}
	binary.BigEndian.PutUint16(ext[0:2], uint16(len(ext)-2))
	body := make([]byte, 0, 64)
	body = append(body, 3, 3)
	body = append(body, make([]byte, 32)...)
	body = append(body, 0)
	body = append(body, 0, 2, 0, 0)
	body = append(body, 1, 0)
	body = append(body, ext...)
	h := []byte{1, 0, 0, byte(len(body))}
	h[1] = byte(len(body) >> 16)
	h[2] = byte(len(body) >> 8)
	h[3] = byte(len(body))
	rec := []byte{22, 3, 3, byte((len(h) + len(body)) >> 8), byte(len(h) + len(body))}
	return append(rec, append(h, body...)...)
}

func TestCONNECTAndHelloParsing(t *testing.T) {
	r := bufio.NewReader(strings.NewReader("CONNECT api.openai.com:443 HTTP/1.1\r\nHost: api.openai.com:443\r\nProxy-Authorization: " + proxyAuthorization(testProxyToken) + "\r\n\r\n"))
	h, err := readCONNECT(r, testProxyToken)
	if err != nil || h != "api.openai.com" {
		t.Fatalf("%q %v", h, err)
	}
	_, sni, err := readClientHello(bufio.NewReader(bytes.NewReader(hello("api.openai.com", false))))
	if err != nil || sni != "api.openai.com" {
		t.Fatalf("%q %v", sni, err)
	}
	if _, _, err := readClientHello(bufio.NewReader(bytes.NewReader(hello("api.openai.com", true)))); err == nil {
		t.Fatal("ECH accepted")
	}
}

func TestCONNECTRequiresExactHostAuthority(t *testing.T) {
	for _, req := range []string{"CONNECT api.openai.com:443 HTTP/1.1\r\n\r\n", "CONNECT api.openai.com:443 HTTP/1.1\r\nHost: api.openai.com\r\n\r\n"} {
		if _, err := readCONNECT(bufio.NewReader(strings.NewReader(req)), testProxyToken); err == nil {
			t.Fatalf("accepted invalid Host form: %q", req)
		}
	}
}

func TestCONNECTRequiresExactBrokerProxyCredential(t *testing.T) {
	for _, auth := range []string{"", "Basic " + base64.StdEncoding.EncodeToString([]byte("openduck:wrong")), "Bearer " + testProxyToken} {
		req := "CONNECT api.openai.com:443 HTTP/1.1\r\nHost: api.openai.com:443\r\n"
		if auth != "" {
			req += "Proxy-Authorization: " + auth + "\r\n"
		}
		req += "\r\n"
		if _, err := readCONNECT(bufio.NewReader(strings.NewReader(req)), testProxyToken); err == nil {
			t.Fatalf("credential accepted: %q", auth)
		}
	}
}

func TestProxyRejectsPrivateAndUsesNoNetwork(t *testing.T) {
	p := testPolicy(t)
	c, err := issueCapabilityWithToken(p, testProxyToken)
	if err != nil {
		t.Fatal(err)
	}
	a, b := net.Pipe()
	defer b.Close()
	d := &fakeDialer{conn: a}
	go func() { _, _ = io.Copy(io.Discard, b) }()
	go func() {
		_, _ = io.WriteString(b, "CONNECT api.openai.com:443 HTTP/1.1\r\nProxy-Authorization: "+proxyAuthorization(testProxyToken)+"\r\n\r\n")
	}()
	if err := (Proxy{Policy: p, Capability: c, Resolver: fakeResolver{ips: []net.IP{net.ParseIP("10.0.0.1")}}, Dialer: d, Limiter: NewConnectionLimiter(1)}).ServeConn(context.Background(), a); err == nil {
		t.Fatal("private address allowed")
	}
	if d.address != "" {
		t.Fatal("dialer called")
	}
}

func TestPublicIPRejectsSpecialRanges(t *testing.T) {
	for _, s := range []string{"0.1.2.3", "198.18.0.1", "192.0.2.1", "198.51.100.1", "203.0.113.1", "240.0.0.1", "2001:db8::1", "2001:10::1", "fc00::1", "fe80::1"} {
		if publicIP(net.ParseIP(s)) {
			t.Errorf("special address accepted: %s", s)
		}
	}
	if !publicIP(net.ParseIP("8.8.8.8")) {
		t.Fatal("global address rejected")
	}
}

func TestProxyConnectionLimit(t *testing.T) {
	p := testPolicy(t)
	cap, _ := issueCapabilityWithToken(p, testProxyToken)
	first, firstPeer := net.Pipe()
	second, secondPeer := net.Pipe()
	defer firstPeer.Close()
	defer secondPeer.Close()
	resolver := blockingResolver{entered: make(chan struct{}), release: make(chan struct{})}
	proxy := Proxy{Policy: p, Capability: cap, Resolver: resolver, Dialer: &fakeDialer{conn: first}, Limiter: NewConnectionLimiter(1)}
	go func() { _, _ = io.Copy(io.Discard, firstPeer) }()
	go func() {
		_, _ = io.WriteString(firstPeer, "CONNECT api.openai.com:443 HTTP/1.1\r\nHost: api.openai.com:443\r\nProxy-Authorization: "+proxyAuthorization(testProxyToken)+"\r\n\r\n")
	}()
	firstResult := make(chan error, 1)
	go func() { firstResult <- proxy.ServeConn(context.Background(), first) }()
	<-resolver.entered
	go func() {
		_, _ = io.WriteString(secondPeer, "CONNECT api.openai.com:443 HTTP/1.1\r\nHost: api.openai.com:443\r\nProxy-Authorization: "+proxyAuthorization(testProxyToken)+"\r\n\r\n")
	}()
	if err := proxy.ServeConn(context.Background(), second); err != ErrCapacity {
		t.Fatalf("second err=%v", err)
	}
	close(resolver.release)
	if err := <-firstResult; err == nil {
		t.Fatal("first connection unexpectedly accepted")
	}
}

func TestProxySlowUnauthorizedConnectionDoesNotConsumeOutboundSlot(t *testing.T) {
	p := testPolicy(t)
	cap, _ := issueCapabilityWithToken(p, testProxyToken)
	slow, slowPeer := net.Pipe()
	defer slowPeer.Close()
	valid, validPeer := net.Pipe()
	defer validPeer.Close()
	resolver := blockingResolver{entered: make(chan struct{}), release: make(chan struct{})}
	proxy := Proxy{Policy: p, Capability: cap, Resolver: resolver, Dialer: &fakeDialer{conn: valid}, Limiter: NewConnectionLimiter(1)}
	slowDone := make(chan error, 1)
	go func() { slowDone <- proxy.ServeConn(context.Background(), slow) }()
	validDone := make(chan error, 1)
	go func() { validDone <- proxy.ServeConn(context.Background(), valid) }()
	_, _ = io.WriteString(validPeer, "CONNECT api.openai.com:443 HTTP/1.1\r\nHost: api.openai.com:443\r\nProxy-Authorization: "+proxyAuthorization(testProxyToken)+"\r\n\r\n")
	select {
	case <-resolver.entered:
		// A still-silent unauthenticated client did not take the only egress slot.
	case <-time.After(time.Second):
		t.Fatal("slow unauthorized connection exhausted outbound limiter")
	}
	close(resolver.release)
	_ = slowPeer.Close()
	<-slowDone
	<-validDone
}

func TestProxyPreAuthAdmissionBoundsSlowLocalPeers(t *testing.T) {
	p := testPolicy(t)
	cap, _ := issueCapabilityWithToken(p, testProxyToken)
	admission := NewConnectionLimiter(2)
	proxy := Proxy{Policy: p, Capability: cap, Resolver: fakeResolver{ips: []net.IP{net.ParseIP("8.8.8.8")}}, Dialer: &fakeDialer{}, Admission: admission, Limiter: NewConnectionLimiter(1)}
	leftA, rightA := net.Pipe()
	leftB, rightB := net.Pipe()
	defer rightA.Close()
	defer rightB.Close()
	doneA, doneB := make(chan error, 1), make(chan error, 1)
	go func() { doneA <- proxy.ServeConn(context.Background(), leftA) }()
	go func() { doneB <- proxy.ServeConn(context.Background(), leftB) }()
	deadline := time.Now().Add(time.Second)
	for len(admission.slots) != 2 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if len(admission.slots) != 2 {
		t.Fatal("slow peers did not enter pre-auth admission")
	}
	// Thousands of extra slow peers are rejected before they can occupy a
	// waiting pre-auth goroutine/FD budget.
	for range 1000 {
		left, right := net.Pipe()
		if err := proxy.ServeConn(context.Background(), left); err != ErrCapacity {
			t.Fatalf("over-capacity slow peer err=%v", err)
		}
		_ = right.Close()
	}
	_ = rightA.Close()
	<-doneA
	valid, peer := net.Pipe()
	defer peer.Close()
	validDone := make(chan error, 1)
	go func() { validDone <- proxy.ServeConn(context.Background(), valid) }()
	_, _ = io.WriteString(peer, "CONNECT api.openai.com:443 HTTP/1.1\r\nHost: api.openai.com:443\r\nProxy-Authorization: "+proxyAuthorization(testProxyToken)+"\r\n\r\n")
	// The valid request got through pre-auth admission; it may fail later at
	// the fake dialer, which is outside this test's budget assertion.
	status := make([]byte, len("HTTP/1.1 200 Connection Established\r\n\r\n"))
	if _, err := io.ReadFull(peer, status); err != nil {
		t.Fatalf("valid peer did not pass admission: %v", err)
	}
	_ = rightB.Close()
	<-doneB
	_ = peer.Close()
	<-validDone
}

func TestProxyPreAuthDeadlineRemainsBoundedThroughCONNECTAuthentication(t *testing.T) {
	p := testPolicy(t)
	cap, _ := issueCapabilityWithToken(p, testProxyToken)
	client, peer := net.Pipe()
	defer peer.Close()
	proxy := Proxy{Policy: p, Capability: cap, Resolver: fakeResolver{}, Dialer: &fakeDialer{}, Admission: NewConnectionLimiter(1), Limiter: NewConnectionLimiter(1)}
	started := time.Now()
	done := make(chan error, 1)
	go func() { done <- proxy.ServeConn(context.Background(), client) }()
	select {
	case err := <-done:
		elapsed := time.Since(started)
		if err != ErrDenied || elapsed < preAuthDeadline-time.Second || elapsed > preAuthDeadline+time.Second {
			t.Fatalf("pre-auth deadline err=%v elapsed=%s", err, elapsed)
		}
	case <-time.After(preAuthDeadline + 2*time.Second):
		t.Fatal("CONNECT authentication exceeded pre-auth deadline")
	}
}

func TestProxyDialsResolvedNumericAddress(t *testing.T) {
	p := testPolicy(t)
	cap, _ := issueCapabilityWithToken(p, testProxyToken)
	client, peer := net.Pipe()
	upstream, upstreamPeer := net.Pipe()
	defer peer.Close()
	defer upstreamPeer.Close()
	d := &fakeDialer{conn: upstream}
	proxy := Proxy{Policy: p, Capability: cap, Resolver: fakeResolver{ips: []net.IP{net.ParseIP("8.8.8.8")}}, Dialer: d, Limiter: NewConnectionLimiter(1)}
	result := make(chan error, 1)
	go func() { result <- proxy.ServeConn(context.Background(), client) }()
	_, _ = io.WriteString(peer, "CONNECT api.openai.com:443 HTTP/1.1\r\nHost: api.openai.com:443\r\nProxy-Authorization: "+proxyAuthorization(testProxyToken)+"\r\n\r\n")
	status := make([]byte, len("HTTP/1.1 200 Connection Established\r\n\r\n"))
	if _, err := io.ReadFull(peer, status); err != nil {
		t.Fatal(err)
	}
	_, _ = peer.Write(hello("api.openai.com", false))
	got := make([]byte, len(hello("api.openai.com", false)))
	if _, err := io.ReadFull(upstreamPeer, got); err != nil {
		t.Fatal(err)
	}
	if d.address != "8.8.8.8:443" {
		t.Fatalf("dial address=%q", d.address)
	}
	_ = peer.Close()
	_ = upstreamPeer.Close()
	<-result
}

func FuzzParseHelloNoPanic(f *testing.F) {
	f.Add([]byte{1, 2, 3})
	f.Fuzz(func(t *testing.T, b []byte) { _, _ = parseHello(b) })
}
