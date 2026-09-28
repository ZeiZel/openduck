package platformanchor

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"openduck/internal/macoschannel"
	"sync"
	"time"
)

const journalReqDomain = "platform-anchor.journal.request"
const journalRespDomain = "platform-anchor.journal.response"

type JournalPolicy struct {
	ProductionPolicy ProductionPolicy
	Audience         string
}

func (p JournalPolicy) snapshot() (productionPolicy, error) {
	if p.Audience != JournalAudience || p.ProductionPolicy.Channel != JournalAudience {
		return productionPolicy{}, ErrProductionSealed
	}
	return snapshotPolicy(p.ProductionPolicy)
}

type journalConn interface {
	productionConn
	Seal(string, []byte) (string, error)
	Verify(string, []byte, string) error
}
type journalEnvelope struct {
	Request JournalRequest `json:"request"`
	Tag     string         `json:"tag"`
}
type journalResponseEnvelope struct {
	Response JournalResponse `json:"response"`
	Tag      string          `json:"tag"`
}
type JournalServer struct {
	store  *Store
	policy productionPolicy
}

func NewJournalServer(store *Store, p JournalPolicy) (*JournalServer, error) {
	pol, e := p.snapshot()
	if store == nil || e != nil {
		return nil, ErrUnavailable
	}
	return &JournalServer{store, pol}, nil
}

// NewProductionJournalServer preserves the production store's opaque boundary
// while binding the installer journal to the same durable anchor Store.
func NewProductionJournalServer(store *ProductionStore, p JournalPolicy) (*JournalServer, error) {
	if store == nil {
		return nil, ErrUnavailable
	}
	return NewJournalServer(store.store, p)
}
func (s *JournalServer) ServeConn(ctx context.Context, c macoschannel.Conn) error {
	return s.serveConn(ctx, c)
}
func (s *JournalServer) serveConn(ctx context.Context, c journalConn) error {
	if s == nil || c == nil {
		return ErrUnavailable
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if e := verifyProductionEvidence(c.Evidence(), s.policy); e != nil {
		return e
	}
	defer c.Close()
	for {
		d := time.Now().Add(5 * time.Second)
		if x, ok := ctx.Deadline(); ok && x.Before(d) {
			d = x
		}
		if e := c.SetDeadline(d); e != nil {
			return e
		}
		var env journalEnvelope
		if e := ReadFrame(c, &env); e != nil {
			if errors.Is(e, io.EOF) || errors.Is(e, net.ErrClosed) {
				return nil
			}
			return e
		}
		b, _ := encodeJSON(env.Request)
		if env.Request.validate() != nil || c.Verify(journalReqDomain, b, env.Tag) != nil {
			return ErrProtocol
		}
		resp, e := s.store.journalRequest(env.Request)
		if e != nil {
			resp.Error = journalWireError(e)
		}
		rb, _ := encodeJSON(resp)
		tag, e := c.Seal(journalRespDomain, rb)
		if e != nil {
			return e
		}
		if e = WriteFrame(c, journalResponseEnvelope{resp, tag}); e != nil {
			return fmt.Errorf("%w: response", ErrUncertain)
		}
	}
}

type journalDial interface {
	Dial(context.Context) (journalConn, error)
}
type JournalProductionClient struct {
	dial   journalDial
	policy productionPolicy
	mu     sync.Mutex
}

// Valid reports whether this concrete client has a sealed production binding.
// It does not expose the underlying dialer or credentials.
func (c *JournalProductionClient) Valid() bool {
	if c == nil || c.dial == nil {
		return false
	}
	return c.policy.ProductionPolicy.valid()
}

type realJournalDial struct{ d *macoschannel.Dialer }

func (d realJournalDial) Dial(c context.Context) (journalConn, error) { return d.d.Dial(c) }
func NewProductionJournalClient(d *macoschannel.Dialer, p JournalPolicy) (*JournalProductionClient, error) {
	pol, e := p.snapshot()
	if d == nil || !d.Valid() || e != nil {
		return nil, ErrProductionSealed
	}
	return &JournalProductionClient{realJournalDial{d}, pol, sync.Mutex{}}, nil
}
func (c *JournalProductionClient) Load(ctx context.Context, id, run, release, nonce string) (uint64, string, error) {
	r := JournalRequest{SchemaVersion: JournalSchemaVersion, RequestID: id, Audience: JournalAudience, Operation: "load", RunID: run, ReleaseDigest: release, Nonce: nonce}
	x, e := c.call(ctx, r)
	return x.Sequence, x.Digest, e
}
func (c *JournalProductionClient) CAS(ctx context.Context, id, run, release, nonce string, old, next uint64, oldD, newD string) error {
	_, e := c.call(ctx, JournalRequest{SchemaVersion: JournalSchemaVersion, RequestID: id, Audience: JournalAudience, Operation: "cas", RunID: run, ReleaseDigest: release, Nonce: nonce, ExpectedSequence: old, NextSequence: next, ExpectedDigest: oldD, NextDigest: newD})
	return e
}
func (c *JournalProductionClient) call(ctx context.Context, r JournalRequest) (JournalResponse, error) {
	if c == nil || c.dial == nil || r.validate() != nil {
		return JournalResponse{}, ErrProtocol
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	var last error
	for i := 0; i < 2; i++ {
		x, e := c.once(ctx, r)
		if e == nil || !errors.Is(e, ErrUncertain) {
			return x, e
		}
		last = e
	}
	return JournalResponse{}, last
}
func (c *JournalProductionClient) once(ctx context.Context, r JournalRequest) (JournalResponse, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	x, e := c.dial.Dial(ctx)
	if e != nil {
		return JournalResponse{}, e
	}
	defer x.Close()
	if verifyProductionEvidence(x.Evidence(), c.policy) != nil {
		return JournalResponse{}, ErrPeer
	}
	d := time.Now().Add(5 * time.Second)
	if z, ok := ctx.Deadline(); ok && z.Before(d) {
		d = z
	}
	if e = x.SetDeadline(d); e != nil {
		return JournalResponse{}, fmt.Errorf("%w: deadline", ErrUncertain)
	}
	b, _ := encodeJSON(r)
	tag, e := x.Seal(journalReqDomain, b)
	if e != nil {
		return JournalResponse{}, e
	}
	if e = WriteFrame(x, journalEnvelope{r, tag}); e != nil {
		return JournalResponse{}, fmt.Errorf("%w: write", ErrUncertain)
	}
	var env journalResponseEnvelope
	if e = ReadFrame(x, &env); e != nil {
		return JournalResponse{}, fmt.Errorf("%w: read", ErrUncertain)
	}
	rb, _ := encodeJSON(env.Response)
	if env.Response.RequestID != r.RequestID || env.Response.validate() != nil || x.Verify(journalRespDomain, rb, env.Tag) != nil {
		return JournalResponse{}, fmt.Errorf("%w: response", ErrUncertain)
	}
	return env.Response, journalResponseError(env.Response)
}
