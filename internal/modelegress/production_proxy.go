package modelegress

import (
	"context"
	"net"
	"net/url"
	"sync"
	"time"

	"openduck/internal/macoschannel"
)

const capabilityLifetime = 30 * time.Second

// CapabilityRegistry retains a bounded set of independently authenticated
// broker sessions. A new receipt adds a token; it never invalidates an active
// runtime's token. Expired entries are pruned on every access.
type CapabilityRegistry struct {
	mu       sync.Mutex
	sessions map[string]registeredCapability
	max      int
}

type registeredCapability struct {
	cap   ProductionCapability
	token string
	until time.Time
}

func NewCapabilityRegistry(max int) *CapabilityRegistry {
	if max < 1 {
		return nil
	}
	return &CapabilityRegistry{sessions: make(map[string]registeredCapability), max: max}
}

// Register creates a bounded stable egress credential for one exact runtime
// session. Renewing that session refreshes only its original token; a newly
// minted control capability is intentionally discarded and can never crowd
// out unrelated sessions.
func (r *CapabilityRegistry) Register(session string, cap ProductionCapability, now time.Time) (ProductionCapability, error) {
	if r == nil || session == "" || len(session) > 256 || cap == nil {
		return nil, ErrNoCapability
	}
	token, err := proxyToken(cap)
	if err != nil {
		return nil, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.pruneLocked(now)
	if registered, ok := r.sessions[session]; ok {
		registered.until = now.Add(capabilityLifetime)
		r.sessions[session] = registered
		return registered.cap, nil
	}
	if len(r.sessions) >= r.max {
		return nil, ErrCapacity
	}
	r.sessions[session] = registeredCapability{cap: cap, token: token, until: now.Add(capabilityLifetime)}
	return cap, nil
}

func (r *CapabilityRegistry) RemoveSession(session string) {
	if r == nil || session == "" {
		return
	}
	r.mu.Lock()
	delete(r.sessions, session)
	r.mu.Unlock()
}

func (r *CapabilityRegistry) Verify(token string, now time.Time) bool {
	if r == nil {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.pruneLocked(now)
	for _, registered := range r.sessions {
		if registered.token == token {
			return now.Before(registered.until)
		}
	}
	return false
}

func (r *CapabilityRegistry) pruneLocked(now time.Time) {
	for session, registered := range r.sessions {
		if !now.Before(registered.until) {
			delete(r.sessions, session)
		}
	}
}

// CapabilitySnapshot retains the latest authenticated capability for all
// bounded concurrent data-plane connections. Replacing it rotates the proxy
// credential atomically; expired capabilities are never returned.
type CapabilitySnapshot struct {
	mu    sync.RWMutex
	cap   ProductionCapability
	until time.Time
}

func (s *CapabilitySnapshot) Store(cap ProductionCapability, now time.Time) {
	if cap == nil {
		return
	}
	s.mu.Lock()
	s.cap, s.until = cap, now.Add(capabilityLifetime)
	s.mu.Unlock()
}

func (s *CapabilitySnapshot) Load(now time.Time) ProductionCapability {
	s.mu.RLock()
	cap, until := s.cap, s.until
	s.mu.RUnlock()
	if cap == nil || !now.Before(until) {
		return nil
	}
	return cap
}

// SystemResolver and SystemDialer are the only default OS I/O adapters. Tests
// must inject Resolver/Dialer; production construction does not perform I/O.
type SystemResolver struct{}

func (SystemResolver) Resolve(ctx context.Context, host string) ([]net.IP, error) {
	return net.DefaultResolver.LookupIP(ctx, "ip", host)
}

type SystemDialer struct{ d net.Dialer }

func (d SystemDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return d.d.DialContext(ctx, network, address)
}

// ProductionProxy is a model-only proxy whose policy capability was issued
// by an authenticated control server. No listener is owned here; the command
// composition root must obtain one through macoschannel.Listen after all
// deployment proofs succeed.
type ProductionProxy struct {
	proxy Proxy
	close func() error
}

func NewProductionProxy(conn macoschannel.Conn, expected ControlExpectation, resolver Resolver, dialer Dialer, maxConnections int) (*ProductionProxy, error) {
	server, err := NewAuthenticatedControlServer(conn, expected)
	if err != nil {
		return nil, err
	}
	if resolver == nil || dialer == nil || maxConnections < 1 {
		return nil, ErrControlUnavailable
	}
	return &ProductionProxy{proxy: Proxy{Policy: expected.Policy, Capability: server.Capability(), Resolver: resolver, Dialer: dialer, Admission: NewConnectionLimiter(maxConnections), Limiter: NewConnectionLimiter(maxConnections)}, close: func() error { return conn.Close() }}, nil
}

// NewProductionProxyWithCapability is used only after an authenticated
// control server has issued its local capability. It does not accept a
// receipt, path, or unsealed metadata.
func NewProductionProxyWithCapability(policy Policy, cap ProductionCapability, resolver Resolver, dialer Dialer, maxConnections int) (*ProductionProxy, error) {
	if policy.Validate() != nil || cap == nil || verifyCapability(policy, cap) != nil || resolver == nil || dialer == nil || maxConnections < 1 {
		return nil, ErrControlUnavailable
	}
	if _, err := proxyToken(cap); err != nil {
		return nil, ErrControlUnavailable
	}
	return &ProductionProxy{proxy: Proxy{Policy: policy, Capability: cap, Resolver: resolver, Dialer: dialer, Admission: NewConnectionLimiter(maxConnections), Limiter: NewConnectionLimiter(maxConnections)}}, nil
}

// NewProductionProxyWithRegistry shares a single connection limiter and a
// bounded egress-owned token registry across every authenticated session.
func NewProductionProxyWithRegistry(policy Policy, registry *CapabilityRegistry, resolver Resolver, dialer Dialer, admission, limiter *ConnectionLimiter) (*ProductionProxy, error) {
	if policy.Validate() != nil || registry == nil || resolver == nil || dialer == nil || admission == nil || limiter == nil {
		return nil, ErrControlUnavailable
	}
	return &ProductionProxy{proxy: Proxy{Policy: policy, Resolver: resolver, Dialer: dialer, Admission: admission, Limiter: limiter, TokenVerifier: func(token string) bool { return registry.Verify(token, time.Now()) }}}, nil
}

// ProxyURL returns the only child-facing credential form. The value is held
// solely in the broker process environment and is never logged or serialized.
func ProxyURL(cap ProductionCapability, address string) (string, error) {
	token, err := proxyToken(cap)
	if err != nil || address != "127.0.0.1:8790" {
		return "", ErrControlUnavailable
	}
	u := &url.URL{Scheme: "http", User: url.UserPassword("openduck", token), Host: address}
	return u.String(), nil
}

func (p *ProductionProxy) ServeConn(ctx context.Context, client net.Conn) error {
	if p == nil {
		return ErrControlUnavailable
	}
	return p.proxy.ServeConn(ctx, client)
}

func (p *ProductionProxy) Close() error {
	if p == nil || p.close == nil {
		return nil
	}
	return p.close()
}
