package platformanchor

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"openduck/internal/macoschannel"
)

// RemoveStaleSocket atomically tombstones an owned socket relative to root.
// It never accepts an absolute path and refuses inode replacement.
func RemoveStaleSocket(root *os.Root, name string) error {
	if root == nil || name == "" || filepath.IsAbs(name) || filepath.Clean(name) != name {
		return ErrUnavailable
	}
	fi, err := root.Lstat(name)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || fi.Mode()&os.ModeSocket == 0 || fi.Mode().Perm()&0077 != 0 {
		return ErrUnavailable
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || uint32(st.Uid) != uint32(os.Getuid()) {
		return ErrUnavailable
	}
	var b [8]byte
	if _, err = rand.Read(b[:]); err != nil {
		return ErrUnavailable
	}
	tomb := ".socket-tombstone-" + hex.EncodeToString(b[:])
	if err = root.Rename(name, tomb); err != nil {
		return ErrUnavailable
	}
	if after, e := root.Lstat(tomb); e != nil {
		return ErrUnavailable
	} else if a, ok := after.Sys().(*syscall.Stat_t); !ok || a.Ino != st.Ino || a.Dev != st.Dev {
		return ErrUnavailable
	}
	return root.Remove(tomb)
}

// PeerAttestation is checked once before every accepted connection. A real
// implementation must bind UID, executable identity and socket identity; the
// synthetic implementation is explicit and never used by production.
type PeerAttestation interface {
	Attest(context.Context, net.Conn) error
}
type SyntheticPeer struct {
	UID        uint32
	Executable string
	Socket     string
}

func (p SyntheticPeer) Attest(_ context.Context, _ net.Conn) error {
	if p.UID == 0 || p.Executable == "" || p.Socket == "" {
		return ErrPeer
	}
	return nil
}

type rejectPeer struct{}

func (rejectPeer) Attest(context.Context, net.Conn) error { return ErrPeer }

type Server struct {
	store  *Store
	peer   PeerAttestation
	closed atomic.Bool
}

func NewSyntheticServer(store *Store, peer PeerAttestation) (*Server, error) {
	if store == nil || peer == nil {
		return nil, ErrUnavailable
	}
	return &Server{store: store, peer: peer}, nil
}

// ProductionPolicy binds every authenticated channel to one release and
// role tuple. Empty fields are rejected; there is no wildcard policy.
type ProductionPolicy struct {
	Channel, LocalRole, PeerRole                                         string
	LocalRelease, PeerRelease                                            macoschannel.ReleasePin
	ExpectedLocalUID, ExpectedLocalGID, ExpectedPeerUID, ExpectedPeerGID *uint32
	ExpectedKeyEpoch                                                     uint64
}

func (p ProductionPolicy) valid() bool {
	return p.Channel != "" && p.LocalRole != "" && p.PeerRole != "" && p.LocalRole != p.PeerRole &&
		releasePinValid(p.LocalRelease) && releasePinValid(p.PeerRelease) &&
		p.ExpectedLocalUID != nil && p.ExpectedLocalGID != nil && p.ExpectedPeerUID != nil && p.ExpectedPeerGID != nil &&
		*p.ExpectedLocalUID != *p.ExpectedPeerUID && p.ExpectedKeyEpoch != 0
}

func validBindingDigest(s string) bool {
	if len(s) != len("sha256:")+64 || s[:len("sha256:")] != "sha256:" {
		return false
	}
	_, err := hex.DecodeString(s[len("sha256:"):])
	return err == nil
}

func releasePinValid(p macoschannel.ReleasePin) bool {
	if p.ReleaseID == "" {
		return false
	}
	for _, digest := range []string{p.BinaryDigest, p.SocketDigest, p.ManifestDigest} {
		if len(digest) != 64 {
			return false
		}
		if _, err := hex.DecodeString(digest); err != nil {
			return false
		}
	}
	return true
}

type productionPolicy struct {
	ProductionPolicy
	localUID, localGID, peerUID, peerGID uint32
}

func snapshotPolicy(p ProductionPolicy) (productionPolicy, error) {
	if !p.valid() {
		return productionPolicy{}, ErrProductionSealed
	}
	return productionPolicy{ProductionPolicy: p, localUID: *p.ExpectedLocalUID, localGID: *p.ExpectedLocalGID, peerUID: *p.ExpectedPeerUID, peerGID: *p.ExpectedPeerGID}, nil
}
func verifyProductionEvidence(ev macoschannel.Evidence, p productionPolicy) error {
	if !p.valid() || ev.Channel != p.Channel || ev.LocalRole != p.LocalRole || ev.PeerRole != p.PeerRole ||
		ev.LocalRelease != p.LocalRelease || ev.PeerRelease != p.PeerRelease || ev.KeyEpoch != p.ExpectedKeyEpoch ||
		!validBindingDigest(ev.BindingDigest) || ev.Local.UID != p.localUID || ev.Local.GID != p.localGID || ev.Peer.UID != p.peerUID || ev.Peer.GID != p.peerGID {
		return ErrPeer
	}
	return nil
}

type ProductionServer struct {
	store  *ProductionStore
	policy productionPolicy
	closed atomic.Bool
	mu     sync.Mutex
	active []productionConn
	wg     sync.WaitGroup
}

// productionConn is deliberately private. It exists only to exercise the
// production state machine with package-local authenticated fixtures; the
// exported boundary remains macoschannel.Conn.
type productionConn interface {
	net.Conn
	Evidence() macoschannel.Evidence
}

func NewProductionServer(store *ProductionStore, policy ProductionPolicy) (*ProductionServer, error) {
	if store == nil || store.store == nil {
		return nil, ErrProductionSealed
	}
	pol, err := snapshotPolicy(policy)
	if err != nil {
		return nil, err
	}
	return &ProductionServer{store: store, policy: pol}, nil
}

func (s *ProductionServer) ServeConn(ctx context.Context, c macoschannel.Conn) error {
	return s.serveConn(ctx, c)
}

func (s *ProductionServer) serveConn(ctx context.Context, c productionConn) error {
	if s == nil || c == nil {
		return ErrUnavailable
	}
	s.mu.Lock()
	if s.closed.Load() {
		s.mu.Unlock()
		return ErrUnavailable
	}
	s.active = append(s.active, c)
	s.wg.Add(1)
	s.mu.Unlock()
	defer c.Close()
	defer func() {
		s.mu.Lock()
		for i, x := range s.active {
			if x == c {
				s.active = append(s.active[:i], s.active[i+1:]...)
				break
			}
		}
		s.mu.Unlock()
		s.wg.Done()
	}()
	if err := verifyProductionEvidence(c.Evidence(), s.policy); err != nil {
		return fmt.Errorf("%w: channel evidence", err)
	}
	for {
		if ctx == nil {
			ctx = context.Background()
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		// Every frame has a bounded deadline, even when the caller supplied an
		// unbounded context. This limits a peer's ability to pin the service.
		deadline := time.Now().Add(5 * time.Second)
		if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
			deadline = d
		}
		if err := c.SetDeadline(deadline); err != nil {
			return err
		}
		var req Request
		if err := ReadFrame(c, &req); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		resp, err := s.store.store.Request(req)
		if err != nil {
			resp = Response{SchemaVersion: SchemaVersion, RequestID: req.RequestID, Namespace: req.Namespace, Error: err.Error()}
		}
		if err := WriteFrame(c, resp); err != nil {
			return fmt.Errorf("%w: %v", ErrUncertain, err)
		}
	}
}

func (s *ProductionServer) Close() {
	if s != nil {
		s.mu.Lock()
		s.closed.Store(true)
		active := append([]productionConn(nil), s.active...)
		s.mu.Unlock()
		for _, c := range active {
			_ = c.Close()
		}
		s.wg.Wait()
	}
}
func (s *Server) ServeConn(ctx context.Context, c net.Conn) error {
	if s == nil || c == nil || s.closed.Load() {
		return ErrUnavailable
	}
	defer c.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(deadline)
	}
	if err := s.peer.Attest(ctx, c); err != nil {
		return fmt.Errorf("%w: %v", ErrPeer, err)
	}
	for {
		var req Request
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		if err := ReadFrame(c, &req); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		resp, err := s.store.Request(req)
		if err != nil {
			resp = Response{SchemaVersion: SchemaVersion, RequestID: req.RequestID, Namespace: req.Namespace, Error: err.Error()}
		}
		if err := WriteFrame(c, resp); err != nil {
			return fmt.Errorf("%w: %v", ErrUncertain, err)
		}
	}
}
func (s *Server) Close() {
	if s != nil {
		s.closed.Store(true)
	}
}

type ConnFactory func(context.Context) (net.Conn, error)
type Client struct {
	dial ConnFactory
	peer PeerAttestation
	mu   sync.Mutex
}

func NewSyntheticClient(dial ConnFactory, peer PeerAttestation) (*Client, error) {
	if dial == nil || peer == nil {
		return nil, ErrUnavailable
	}
	return &Client{dial: dial, peer: peer}, nil
}

type ProductionClient struct {
	dial   productionDial
	policy productionPolicy
	mu     sync.Mutex
}

func (c *ProductionClient) valid() bool {
	return c != nil && c.dial != nil && c.policy.valid()
}

type productionDial interface {
	Dial(context.Context) (productionConn, error)
}
type sealedProductionDialer struct{ dialer *macoschannel.Dialer }

func (d sealedProductionDialer) Dial(ctx context.Context) (productionConn, error) {
	return d.dialer.Dial(ctx)
}

func NewProductionClient(dial *macoschannel.Dialer, policy ProductionPolicy) (*ProductionClient, error) {
	if dial == nil || !dial.Valid() {
		return nil, ErrProductionSealed
	}
	pol, err := snapshotPolicy(policy)
	if err != nil {
		return nil, err
	}
	return &ProductionClient{dial: sealedProductionDialer{dialer: dial}, policy: pol}, nil
}

func (c *ProductionClient) Do(ctx context.Context, req Request) (Response, error) {
	if c == nil || c.dial == nil {
		return Response{}, ErrUnavailable
	}
	if err := req.validate(); err != nil {
		return Response{}, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if ctx == nil {
		ctx = context.Background()
	}
	conn, err := c.dial.Dial(ctx)
	if err != nil {
		return Response{}, err
	}
	defer conn.Close()
	if err := verifyProductionEvidence(conn.Evidence(), c.policy); err != nil {
		return Response{}, fmt.Errorf("%w: channel evidence", err)
	}
	deadline := time.Now().Add(5 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return Response{}, err
	}
	if err := WriteFrame(conn, req); err != nil {
		return Response{}, fmt.Errorf("%w: request write: %v", ErrUncertain, err)
	}
	var resp Response
	if err := ReadFrame(conn, &resp); err != nil {
		return Response{}, fmt.Errorf("%w: %v", ErrUncertain, err)
	}
	if err := resp.validate(); err != nil || resp.RequestID != req.RequestID || resp.Namespace != req.Namespace {
		return Response{}, fmt.Errorf("%w: response binding", ErrProtocol)
	}
	if resp.Error != "" {
		if resp.Error == ErrCAS.Error() {
			return Response{}, ErrCAS
		}
		if resp.Error == ErrReplay.Error() {
			return Response{}, ErrReplay
		}
		return Response{}, fmt.Errorf("%w: %s", ErrProtocol, resp.Error)
	}
	return resp, nil
}
func (c *Client) Do(ctx context.Context, req Request) (Response, error) {
	if c == nil {
		return Response{}, ErrUnavailable
	}
	if err := req.validate(); err != nil {
		return Response{}, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	conn, err := c.dial(ctx)
	if err != nil {
		return Response{}, err
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	if err := c.peer.Attest(ctx, conn); err != nil {
		return Response{}, fmt.Errorf("%w: %v", ErrPeer, err)
	}
	if err := WriteFrame(conn, req); err != nil {
		return Response{}, fmt.Errorf("%w: request write: %v", ErrUncertain, err)
	}
	var resp Response
	if err := ReadFrame(conn, &resp); err != nil {
		return Response{}, fmt.Errorf("%w: %v", ErrUncertain, err)
	}
	if err := resp.validate(); err != nil || resp.RequestID != req.RequestID || resp.Namespace != req.Namespace {
		return Response{}, fmt.Errorf("%w: response binding", ErrProtocol)
	}
	if resp.Error != "" {
		if resp.Error == ErrCAS.Error() {
			return Response{}, ErrCAS
		}
		if resp.Error == ErrReplay.Error() {
			return Response{}, ErrReplay
		}
		return Response{}, fmt.Errorf("%w: %s", ErrProtocol, resp.Error)
	}
	return resp, nil
}

// InMemoryPair is a synthetic-only transport useful for deterministic tests.
func InMemoryPair() (ConnFactory, func(context.Context) net.Conn) {
	a, b := net.Pipe()
	var once sync.Once
	return func(context.Context) (net.Conn, error) { once.Do(func() { go func() { _ = a }() }); return b, nil }, func(context.Context) net.Conn { return a }
}
