package nativemcp

import (
	"context"
	"errors"
	"net"
	"time"
)

// ShimSocketPath is the one fixed, root-owned Controller listener used by the
// provider-host stdio shims. It is not a user/config/plugin supplied endpoint.
const ShimSocketPath = "/private/var/run/openduck/native-mcp.sock"

// SocketPeerSource is implemented by the macOS trust boundary. It obtains
// LOCAL_PEERCRED from the accepted Unix connection and verifies the shim's
// process, parent-chain, CDHash, UID/GID and registered host/session before
// returning a peer identity. It must never derive identity from client bytes.
type SocketPeerSource interface {
	PeerFor(context.Context, net.Conn) (PeerIdentity, error)
}

// SocketSessionResolver resolves all authority on the Controller side after
// peer attestation. The shim receives neither contract nor backend nor bearer.
type SocketSessionResolver interface {
	ResolveNativeMCPSession(context.Context, PeerIdentity) (SessionContract, AttestedBackend, ProcessAttestor, error)
}

// SocketServer terminates the authenticated internal transport and serves the
// standard MCP server directly over the Unix connection. The official host
// sees only stdio to its local shim; arbitrary socket clients fail closed.
type SocketServer struct {
	Peers             SocketPeerSource
	Resolver          SocketSessionResolver
	Now               func() time.Time
	FirstFrameTimeout time.Duration
	IdleTimeout       time.Duration
	WriteTimeout      time.Duration
}

func (s SocketServer) ServeConn(ctx context.Context, conn net.Conn) error {
	if ctx == nil || conn == nil || s.Peers == nil || s.Resolver == nil {
		return ErrUnauthorized
	}
	peer, err := s.Peers.PeerFor(ctx, conn)
	if err != nil {
		return ErrUnauthorized
	}
	contract, backend, attestor, err := s.Resolver.ResolveNativeMCPSession(ctx, peer)
	if err != nil || backend == nil || attestor == nil || contract.Validate(s.now()) != nil || peer.Provider != contract.Provider || peer.PeerID != contract.PeerID {
		return ErrUnauthorized
	}
	bound := backend.BindProcessAttestor(attestor)
	if bound == nil {
		return ErrUnauthorized
	}
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			// Closing is the only portable way to interrupt both a partial read
			// and a blocked write immediately on cancellation.
			_ = conn.Close()
		case <-done:
		}
	}()
	return (Server{Contract: contract, Peers: fixedPeerSource{peer: peer}, Backend: bound, Now: s.Now, FirstFrameTimeout: s.FirstFrameTimeout, IdleTimeout: s.IdleTimeout, WriteTimeout: s.WriteTimeout}).Serve(ctx, conn, conn)
}

func (s SocketServer) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}

type fixedPeerSource struct{ peer PeerIdentity }

func (p fixedPeerSource) Current(context.Context) (PeerIdentity, error) {
	if p.peer.Provider == "" || p.peer.PeerID == "" {
		return PeerIdentity{}, errors.New("peer unavailable")
	}
	return p.peer, nil
}
