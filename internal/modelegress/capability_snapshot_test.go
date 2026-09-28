package modelegress

import (
	"bufio"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestCapabilitySnapshotRetainsConcurrentCapabilityAndRotates(t *testing.T) {
	p := testPolicy(t)
	first, err := issueCapabilityWithToken(p, testProxyToken)
	if err != nil {
		t.Fatal(err)
	}
	var snapshot CapabilitySnapshot
	now := time.Now()
	snapshot.Store(first, now)
	if snapshot.Load(now) == nil || snapshot.Load(now.Add(time.Second)) == nil {
		t.Fatal("sequential proxy connections lost current capability")
	}

	var wg sync.WaitGroup
	errs := make(chan error, 32)
	for range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if snapshot.Load(now.Add(time.Second)) == nil {
				errs <- ErrControlUnavailable
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}

	secondToken := "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	second, err := issueCapabilityWithToken(p, secondToken)
	if err != nil {
		t.Fatal(err)
	}
	firstURL, err := ProxyURL(first, "127.0.0.1:8790")
	if err != nil {
		t.Fatal(err)
	}
	snapshot.Store(second, now.Add(2*time.Second))
	current := snapshot.Load(now.Add(3 * time.Second))
	currentURL, err := ProxyURL(current, "127.0.0.1:8790")
	if err != nil {
		t.Fatal(err)
	}
	if currentURL == firstURL {
		t.Fatal("rotated capability retained replayed proxy credential")
	}
	if snapshot.Load(now.Add(2*time.Second+capabilityLifetime)) != nil {
		t.Fatal("expired capability accepted")
	}
}

func TestCapabilityRegistryRefreshesOnlyExactSessionAndRevokesOnClose(t *testing.T) {
	p := testPolicy(t)
	first, err := issueCapabilityWithToken(p, testProxyToken)
	if err != nil {
		t.Fatal(err)
	}
	secondToken := "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	second, err := issueCapabilityWithToken(p, secondToken)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	r := NewCapabilityRegistry(2)
	if _, err := r.Register("runtime-a", first, now); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Register("runtime-b", second, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if !r.Verify(testProxyToken, now.Add(2*time.Second)) || !r.Verify(secondToken, now.Add(2*time.Second)) {
		t.Fatal("second broker session invalidated first token")
	}
	request := "CONNECT api.openai.com:443 HTTP/1.1\r\nHost: api.openai.com:443\r\nProxy-Authorization: " + proxyAuthorization(secondToken) + "\r\n\r\n"
	if host, err := readCONNECTAuthorized(bufio.NewReader(strings.NewReader(request)), func(token string) bool { return r.Verify(token, now.Add(2*time.Second)) }); err != nil || host != "api.openai.com" {
		t.Fatalf("second active session token rejected: host=%q err=%v", host, err)
	}
	// More than 100 renewals of B must retain B's stable token, never refresh
	// A, and never fill capacity with discarded freshly minted tokens.
	for range 101 {
		stable, err := r.Register("runtime-b", second, now.Add(capabilityLifetime-time.Second))
		if err != nil {
			t.Fatal(err)
		}
		url, err := ProxyURL(stable, "127.0.0.1:8790")
		if err != nil || !strings.Contains(url, secondToken) {
			t.Fatalf("stable renewal url=%q err=%v", url, err)
		}
	}
	third, err := issueCapabilityWithToken(p, "1111111111111111111111111111111111111111111111111111111111111111")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Register("runtime-c", third, now.Add(2*time.Second)); !errors.Is(err, ErrCapacity) {
		t.Fatalf("bounded registry err=%v", err)
	}
	if r.Verify(testProxyToken, now.Add(capabilityLifetime)) {
		t.Fatal("renewal of B refreshed unrelated runtime A")
	}
	if !r.Verify(secondToken, now.Add(capabilityLifetime)) {
		t.Fatal("renewed B token expired")
	}
	r.RemoveSession("runtime-b")
	if r.Verify(secondToken, now.Add(capabilityLifetime)) {
		t.Fatal("closed runtime retained token")
	}
	if r.Verify(testProxyToken, now.Add(2*capabilityLifetime)) || r.Verify(secondToken, now.Add(2*capabilityLifetime+time.Second)) {
		t.Fatal("expired egress session token accepted")
	}
}

func TestProductionProxyRegistrySharesOneLimiter(t *testing.T) {
	p := testPolicy(t)
	r := NewCapabilityRegistry(2)
	admission := NewConnectionLimiter(2)
	limiter := NewConnectionLimiter(1)
	first, err := NewProductionProxyWithRegistry(p, r, fakeResolver{}, &fakeDialer{}, admission, limiter)
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewProductionProxyWithRegistry(p, r, fakeResolver{}, &fakeDialer{}, admission, limiter)
	if err != nil {
		t.Fatal(err)
	}
	if first.proxy.Limiter != limiter || second.proxy.Limiter != limiter {
		t.Fatal("per-session proxy created a separate max-connections limiter")
	}
	if first.proxy.Admission != admission || second.proxy.Admission != admission {
		t.Fatal("per-session proxy created separate pre-auth limiter")
	}
}
