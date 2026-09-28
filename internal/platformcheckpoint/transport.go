package platformcheckpoint

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"openduck/internal/macoschannel"
)

type Policy struct {
	Channel, LocalRole, PeerRole         string
	LocalUID, LocalGID, PeerUID, PeerGID uint32
	KeyEpoch                             uint64
	LocalRelease, PeerRelease            macoschannel.ReleasePin
}

func (p Policy) validate() error {
	if p.Channel == "" || p.LocalRole == "" || p.PeerRole == "" || p.LocalRole == p.PeerRole || p.KeyEpoch == 0 || p.LocalUID == p.PeerUID || !validRelease(p.LocalRelease) || !validRelease(p.PeerRelease) {
		return ErrPeer
	}
	return nil
}

func validRelease(p macoschannel.ReleasePin) bool {
	if p.ReleaseID == "" {
		return false
	}
	for _, digest := range []string{p.BinaryDigest, p.SocketDigest, p.ManifestDigest} {
		decoded, err := hex.DecodeString(digest)
		if err != nil || len(decoded) != 32 {
			return false
		}
	}
	return true
}

func (p Policy) verify(e macoschannel.Evidence) error {
	if p.validate() != nil || !validDigest(e.BindingDigest) || e.Channel != p.Channel || e.LocalRole != p.LocalRole || e.PeerRole != p.PeerRole || e.Local.UID != p.LocalUID || e.Local.GID != p.LocalGID || e.Peer.UID != p.PeerUID || e.Peer.GID != p.PeerGID || e.KeyEpoch != p.KeyEpoch || e.LocalRelease != p.LocalRelease || e.PeerRelease != p.PeerRelease {
		return ErrPeer
	}
	return nil
}

type envelope struct {
	Request Request `json:"request"`
	Tag     string  `json:"tag"`
}
type responseEnvelope struct {
	Response Response `json:"response"`
	Tag      string   `json:"tag"`
}

type Server struct {
	store  *Store
	policy Policy
}

// sealedConn is deliberately package-private. Exported construction still
// requires macoschannel.Conn, whose unexported marker cannot be forged by a
// different package; tests can exercise transport failures without weakening
// that production boundary.
type sealedConn interface {
	io.ReadWriteCloser
	SetDeadline(time.Time) error
	Evidence() macoschannel.Evidence
	Seal(string, []byte) (string, error)
	Verify(string, []byte, string) error
}

func NewServer(store *Store, policy Policy) (*Server, error) {
	if store == nil || policy.validate() != nil {
		return nil, ErrUnavailable
	}
	return &Server{store: store, policy: policy}, nil
}
func (s *Server) ServeConn(ctx context.Context, c macoschannel.Conn) error {
	return s.serveConn(ctx, c)
}
func (s *Server) serveConn(ctx context.Context, c sealedConn) error {
	if s == nil || c == nil {
		return ErrUnavailable
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if e := s.policy.verify(c.Evidence()); e != nil {
		return e
	}
	defer c.Close()
	stop, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		select {
		case <-ctx.Done():
			_ = c.Close()
		case <-stop:
		}
	}()
	defer func() { close(stop); <-done }()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		deadline := time.Now().Add(5 * time.Second)
		if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
			deadline = d
		}
		if err := c.SetDeadline(deadline); err != nil {
			return err
		}
		var env envelope
		if e := ReadFrame(c, &env); e != nil {
			if cause := contextCause(ctx); cause != nil {
				return cause
			}
			if errors.Is(e, io.EOF) || errors.Is(e, io.ErrClosedPipe) || errors.Is(e, net.ErrClosed) {
				return nil
			}
			return e
		}
		b, _ := marshal(env.Request)
		if e := c.Verify("platform-checkpoint.request", b, env.Tag); e != nil {
			return e
		}
		if e := env.Request.validate(); e != nil {
			return e
		}
		resp := Response{SchemaVersion: SchemaVersion, RequestID: env.Request.RequestID}
		var e error
		if env.Request.Operation == "load" {
			resp.Generation, resp.Digest, e = s.store.Load()
			if e != nil {
				resp.Error = wireError(e)
			} else {
				resp.OK = true
			}
		} else {
			e = s.store.CAS(env.Request.RequestID, env.Request.Expected, env.Request.Next, env.Request.Digest)
			if e != nil {
				resp.Error = wireError(e)
			} else {
				resp.OK = true
				resp.Generation = env.Request.Next
				resp.Digest = env.Request.Digest
			}
		}
		rb, _ := marshal(resp)
		tag, e := c.Seal("platform-checkpoint.response", rb)
		if e != nil {
			return e
		}
		if e = WriteFrame(c, responseEnvelope{Response: resp, Tag: tag}); e != nil {
			return fmt.Errorf("%w: %v", ErrUncertain, e)
		}
	}
}

// ProductionClient is the authenticated client for the independent
// monotonic checkpoint authority. Its fields are intentionally private so a
// caller cannot mint an authenticated client without the transport boundary.
type ProductionClient struct {
	conn   sealedConn // test-only fixed connection
	dial   productionDialer
	policy Policy
	mu     sync.Mutex
}

type productionDialer interface {
	Dial(context.Context) (sealedConn, error)
}

type sealedDialer struct{ dialer *macoschannel.Dialer }

func (d sealedDialer) Dial(ctx context.Context) (sealedConn, error) { return d.dialer.Dial(ctx) }

// Client is retained as a source-compatible name for existing synthetic
// transport tests and callers. Production composition should use
// ProductionClient explicitly.
type Client = ProductionClient

func NewClient(c macoschannel.Conn, p Policy) (*ProductionClient, error) {
	return newClient(c, p)
}
func newClient(c sealedConn, p Policy) (*ProductionClient, error) {
	if c == nil || p.verify(c.Evidence()) != nil {
		return nil, ErrPeer
	}
	return &ProductionClient{conn: c, policy: p}, nil
}

// NewProductionClient creates a reconnecting checkpoint client. Every
// operation obtains a newly authenticated channel from the concrete Dialer.
func NewProductionClient(d *macoschannel.Dialer, p Policy) (*ProductionClient, error) {
	if d == nil || !d.Valid() || p.validate() != nil {
		return nil, ErrPeer
	}
	return &ProductionClient{dial: sealedDialer{dialer: d}, policy: p}, nil
}

func newProductionClientForTest(d productionDialer, p Policy) *ProductionClient {
	return &ProductionClient{dial: d, policy: p}
}

// Valid reports whether the client still carries the authenticated transport
// and policy captured by NewClient. It is intentionally read-only and exists
// for opaque capability constructors in sibling packages.
func (c *ProductionClient) Valid() bool {
	return c != nil && c.dial != nil && c.policy.validate() == nil
}
func (c *Client) call(ctx context.Context, r Request) (Response, error) {
	if c == nil || (c.conn == nil && c.dial == nil) {
		return Response{}, ErrUnavailable
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := r.validate(); err != nil {
		return Response{}, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	conn := c.conn
	if c.dial != nil {
		var err error
		conn, err = c.dial.Dial(ctx)
		if err != nil {
			return Response{}, err
		}
		if conn == nil || c.policy.verify(conn.Evidence()) != nil {
			if conn != nil {
				_ = conn.Close()
			}
			return Response{}, ErrPeer
		}
		defer conn.Close()
	}
	if err := ctx.Err(); err != nil {
		return Response{}, err
	}
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		select {
		case <-ctx.Done():
			_ = conn.Close()
		case <-stop:
		}
	}()
	defer func() { close(stop); <-done }()
	var e error
	if d, ok := ctx.Deadline(); ok {
		e = conn.SetDeadline(d)
	} else {
		e = conn.SetDeadline(time.Now().Add(5 * time.Second))
	}
	if e != nil {
		if r.Operation == "cas" {
			return Response{}, uncertain(ctx, "deadline", e)
		}
		return Response{}, e
	}
	b, _ := marshal(r)
	tag, e := conn.Seal("platform-checkpoint.request", b)
	if e != nil {
		return Response{}, e
	}
	if e = WriteFrame(conn, envelope{Request: r, Tag: tag}); e != nil {
		if r.Operation == "cas" {
			return Response{}, uncertain(ctx, "request write", e)
		}
		if cause := contextCause(ctx); cause != nil {
			return Response{}, cause
		}
		return Response{}, e
	}
	var env responseEnvelope
	if e = ReadFrame(conn, &env); e != nil {
		if r.Operation == "cas" {
			return Response{}, uncertain(ctx, "response read", e)
		}
		if cause := contextCause(ctx); cause != nil {
			return Response{}, cause
		}
		return Response{}, e
	}
	if env.Response.RequestID != r.RequestID {
		if r.Operation == "cas" {
			return Response{}, fmt.Errorf("%w: response correlation", ErrUncertain)
		}
		return Response{}, ErrProtocol
	}
	rb, _ := marshal(env.Response)
	if e = conn.Verify("platform-checkpoint.response", rb, env.Tag); e != nil {
		if r.Operation == "cas" {
			return Response{}, uncertain(ctx, "response auth", e)
		}
		return Response{}, e
	}
	if e = env.Response.validate(); e != nil {
		if r.Operation == "cas" {
			return Response{}, uncertain(ctx, "response validation", e)
		}
		return Response{}, e
	}
	if r.Operation == "cas" && env.Response.OK && (env.Response.Generation != r.Next || env.Response.Digest != r.Digest) {
		return Response{}, fmt.Errorf("%w: response checkpoint", ErrUncertain)
	}
	if !env.Response.OK {
		switch env.Response.Error {
		case ErrCAS.Error():
			return env.Response, ErrCAS
		case ErrReplay.Error():
			return env.Response, ErrReplay
		case ErrUnavailable.Error():
			return env.Response, ErrUnavailable
		case ErrProtocol.Error():
			return env.Response, ErrProtocol
		case ErrUncertain.Error():
			return env.Response, ErrUncertain
		default:
			return env.Response, ErrUnavailable
		}
	}
	return env.Response, nil
}
func (c *Client) Close() error {
	if c == nil || c.conn == nil {
		return ErrUnavailable
	}
	return c.conn.Close()
}
func (c *Client) Load(ctx context.Context) (uint64, string, error) {
	r := Request{SchemaVersion: SchemaVersion, RequestID: requestID(), Operation: "load"}
	v, e := c.call(ctx, r)
	return v.Generation, v.Digest, e
}
func (c *Client) CAS(ctx context.Context, id string, expected, next uint64, digest string) error {
	r := Request{SchemaVersion: SchemaVersion, RequestID: id, Operation: "cas", Expected: expected, Next: next, Digest: digest}
	var last error
	for attempt := 0; attempt < 2; attempt++ {
		_, e := c.call(ctx, r)
		if e == nil || !errors.Is(e, ErrUncertain) {
			return e
		}
		last = e
		if contextCause(ctx) != nil {
			return e
		}
	}
	return last
}
func requestID() string { return fmt.Sprintf("load-%d", time.Now().UnixNano()) }

func wireError(err error) string {
	for _, candidate := range []error{ErrCAS, ErrReplay, ErrProtocol, ErrUnavailable, ErrUncertain} {
		if errors.Is(err, candidate) {
			return candidate.Error()
		}
	}
	return ErrUnavailable.Error()
}

func uncertain(ctx context.Context, operation string, err error) error {
	if cause := contextCause(ctx); cause != nil {
		return fmt.Errorf("%w: %s: %w", ErrUncertain, operation, cause)
	}
	return fmt.Errorf("%w: %s: %v", ErrUncertain, operation, err)
}

func contextCause(ctx context.Context) error {
	if ctx == nil {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if deadline, ok := ctx.Deadline(); ok && !time.Now().Before(deadline) {
		return context.DeadlineExceeded
	}
	return nil
}
