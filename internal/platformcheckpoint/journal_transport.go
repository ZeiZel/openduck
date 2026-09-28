package platformcheckpoint

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"openduck/internal/macoschannel"
)

const journalRequestDomain = "platform-checkpoint.journal.request"
const journalResponseDomain = "platform-checkpoint.journal.response"

// JournalPolicy is deliberately separate from the checkpoint-CAS policy. The
// installer journal must use its own listener and authenticated channel.
type JournalPolicy struct {
	Policy   Policy
	Audience string
}

func (p JournalPolicy) validate() error {
	returnErr := p.Policy.validate()
	if returnErr != nil || p.Policy.Channel != JournalAudience || p.Audience != JournalAudience {
		return ErrPeer
	}
	return nil
}
func (p JournalPolicy) verify(e macoschannel.Evidence) error {
	if p.validate() != nil || p.Policy.verify(e) != nil {
		return ErrPeer
	}
	return nil
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
	policy JournalPolicy
}

func NewJournalServer(store *Store, policy JournalPolicy) (*JournalServer, error) {
	if store == nil || policy.validate() != nil {
		return nil, ErrUnavailable
	}
	return &JournalServer{store: store, policy: policy}, nil
}
func (s *JournalServer) ServeConn(ctx context.Context, c macoschannel.Conn) error {
	return s.serveConn(ctx, c)
}
func (s *JournalServer) serveConn(ctx context.Context, c sealedConn) error {
	if s == nil || c == nil {
		return ErrUnavailable
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := s.policy.verify(c.Evidence()); err != nil {
		return err
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
		if err := contextCause(ctx); err != nil {
			return err
		}
		deadline := time.Now().Add(5 * time.Second)
		if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
			deadline = d
		}
		if err := c.SetDeadline(deadline); err != nil {
			return err
		}
		var env journalEnvelope
		if err := ReadFrame(c, &env); err != nil {
			if cause := contextCause(ctx); cause != nil {
				return cause
			}
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrClosedPipe) || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		requestBytes, err := marshal(env.Request)
		if err != nil || env.Request.Validate() != nil || env.Request.Audience != s.policy.Audience {
			return ErrProtocol
		}
		if err = c.Verify(journalRequestDomain, requestBytes, env.Tag); err != nil {
			return err
		}
		response := JournalResponse{SchemaVersion: JournalSchemaVersion, RequestID: env.Request.RequestID, Audience: JournalAudience, RequestDigest: JournalFingerprint(env.Request)}
		if env.Request.Operation == "sign" {
			response.Signature, err = s.store.JournalSign(env.Request)
		} else {
			err = s.store.JournalVerify(env.Request)
		}
		if err != nil {
			response.Error = wireError(err)
		} else {
			response.OK = true
		}
		if response.Validate() != nil {
			return ErrUnavailable
		}
		responseBytes, _ := marshal(response)
		tag, err := c.Seal(journalResponseDomain, responseBytes)
		if err != nil {
			return err
		}
		if err = WriteFrame(c, journalResponseEnvelope{Response: response, Tag: tag}); err != nil {
			return fmt.Errorf("%w: %v", ErrUncertain, err)
		}
	}
}

// ProductionJournalClient reconnects for every call and intentionally exposes
// only typed journal inputs; no channel or store key is ever available to it.
type ProductionJournalClient struct {
	dial   productionDialer
	policy JournalPolicy
	mu     sync.Mutex
}

// Valid reports whether this concrete client still has a sealed production
// transport and policy. It intentionally exposes no transport capability.
func (c *ProductionJournalClient) Valid() bool {
	return c != nil && c.dial != nil && c.policy.validate() == nil
}

func NewProductionJournalClient(d *macoschannel.Dialer, p JournalPolicy) (*ProductionJournalClient, error) {
	if d == nil || !d.Valid() || p.validate() != nil {
		return nil, ErrPeer
	}
	return &ProductionJournalClient{dial: sealedDialer{dialer: d}, policy: p}, nil
}
func newProductionJournalClientForTest(d productionDialer, p JournalPolicy) *ProductionJournalClient {
	return &ProductionJournalClient{dial: d, policy: p}
}
func (c *ProductionJournalClient) Sign(ctx context.Context, requestID, runID, releaseDigest, nonce, payloadDigest string, sequence uint64) (string, error) {
	r := JournalRequest{SchemaVersion: JournalSchemaVersion, RequestID: requestID, Audience: JournalAudience, Operation: "sign", RunID: runID, ReleaseDigest: releaseDigest, Nonce: nonce, PayloadDigest: payloadDigest, Sequence: sequence}
	response, err := c.call(ctx, r)
	return response.Signature, err
}
func (c *ProductionJournalClient) Verify(ctx context.Context, requestID, runID, releaseDigest, nonce, payloadDigest, signature string, sequence uint64) error {
	_, err := c.call(ctx, JournalRequest{SchemaVersion: JournalSchemaVersion, RequestID: requestID, Audience: JournalAudience, Operation: "verify", RunID: runID, ReleaseDigest: releaseDigest, Nonce: nonce, PayloadDigest: payloadDigest, Signature: signature, Sequence: sequence})
	return err
}
func (c *ProductionJournalClient) call(ctx context.Context, r JournalRequest) (JournalResponse, error) {
	if c == nil || c.dial == nil || c.policy.validate() != nil {
		return JournalResponse{}, ErrUnavailable
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := r.Validate(); err != nil {
		return JournalResponse{}, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	var last error
	for attempt := 0; attempt < 2; attempt++ {
		response, err := c.callOnce(ctx, r)
		if err == nil || !errors.Is(err, ErrUncertain) || contextCause(ctx) != nil {
			return response, err
		}
		last = err
	}
	return JournalResponse{}, last
}
func (c *ProductionJournalClient) callOnce(ctx context.Context, r JournalRequest) (JournalResponse, error) {
	conn, err := c.dial.Dial(ctx)
	if err != nil {
		return JournalResponse{}, err
	}
	if conn == nil || c.policy.verify(conn.Evidence()) != nil {
		if conn != nil {
			_ = conn.Close()
		}
		return JournalResponse{}, ErrPeer
	}
	defer conn.Close()
	if err = contextCause(ctx); err != nil {
		return JournalResponse{}, err
	}
	stop, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		select {
		case <-ctx.Done():
			_ = conn.Close()
		case <-stop:
		}
	}()
	defer func() { close(stop); <-done }()
	deadline := time.Now().Add(5 * time.Second)
	if d, ok := ctx.Deadline(); ok {
		deadline = d
	}
	if err = conn.SetDeadline(deadline); err != nil {
		return JournalResponse{}, uncertain(ctx, "deadline", err)
	}
	b, _ := marshal(r)
	tag, err := conn.Seal(journalRequestDomain, b)
	if err != nil {
		return JournalResponse{}, err
	}
	if err = WriteFrame(conn, journalEnvelope{Request: r, Tag: tag}); err != nil {
		return JournalResponse{}, uncertain(ctx, "request write", err)
	}
	var env journalResponseEnvelope
	if err = ReadFrame(conn, &env); err != nil {
		return JournalResponse{}, uncertain(ctx, "response read", err)
	}
	if env.Response.RequestID != r.RequestID || env.Response.Audience != JournalAudience || env.Response.RequestDigest != JournalFingerprint(r) {
		return JournalResponse{}, fmt.Errorf("%w: response correlation", ErrUncertain)
	}
	rb, _ := marshal(env.Response)
	if err = conn.Verify(journalResponseDomain, rb, env.Tag); err != nil {
		return JournalResponse{}, uncertain(ctx, "response auth", err)
	}
	if err = env.Response.Validate(); err != nil {
		return JournalResponse{}, uncertain(ctx, "response validation", err)
	}
	if !env.Response.OK {
		return env.Response, journalResponseError(env.Response)
	}
	if r.Operation == "sign" && len(env.Response.Signature) != 64 {
		return JournalResponse{}, fmt.Errorf("%w: signature", ErrUncertain)
	}
	return env.Response, nil
}
