package main

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"

	"openduck/internal/macosattest"
)

type nativeMCPListener interface {
	Accept() (net.Conn, error)
	Close() error
}

type nativeMCPRuntime interface{ Close() error }

const (
	nativeMCPMaxConnections = 32
	nativeMCPDrainTimeout   = 5 * time.Second
)

var errNativeMCPDrainTimeout = errors.New("native mcp connection drain timed out")

type boundedNativeMCPRuntime struct {
	listener nativeMCPListener
	server   interface {
		ServeConn(context.Context, net.Conn) error
	}
	cancel context.CancelFunc
	max    int
	drain  time.Duration

	mu       sync.Mutex
	closing  bool
	active   map[net.Conn]struct{}
	wg       sync.WaitGroup
	once     sync.Once
	closeErr error
}

// startNativeMCP starts only after verified production mesh composition. The
// fixed listener refuses to create its parent, so an inactive/unprovisioned
// install cannot accidentally grow an MCP endpoint.
func startNativeMCP(ctx context.Context, app *meshApplication, o productionAdmissionOptions, newListener func(macosattest.SocketBoundary) (nativeMCPListener, error)) (nativeMCPRuntime, error) {
	if !o.nativeMCP || ctx == nil || app == nil || newListener == nil {
		return nil, errors.New("native mcp unavailable")
	}
	registry := macosattest.NewHostRegistry(time.Now)
	app.nativeHosts = registry
	app.launchOfficialHost = macosattest.LaunchOfficialHost
	app.materializeQwen = macosattest.MaterializeQwenClosure
	server, err := newNativeMCPSocketServer(app, registry)
	if err != nil {
		return nil, err
	}
	listener, err := newListener(macosattest.SocketBoundary{RootUID: 0, RootGID: o.channelGID, SocketUID: o.localUID, SocketGID: o.channelGID, RootMode: 0770, SocketMode: 0660})
	if err != nil {
		return nil, err
	}
	return newBoundedNativeMCPRuntime(ctx, listener, server, nativeMCPMaxConnections, nativeMCPDrainTimeout), nil
}

func newBoundedNativeMCPRuntime(ctx context.Context, listener nativeMCPListener, server interface {
	ServeConn(context.Context, net.Conn) error
}, max int, drain time.Duration) *boundedNativeMCPRuntime {
	ownedCtx, cancel := context.WithCancel(ctx)
	r := &boundedNativeMCPRuntime{listener: listener, server: server, cancel: cancel, max: max, drain: drain, active: make(map[net.Conn]struct{})}
	r.wg.Add(1)
	go r.accept(ownedCtx)
	return r
}

func (r *boundedNativeMCPRuntime) accept(ctx context.Context) {
	defer r.wg.Done()
	for {
		conn, err := r.listener.Accept()
		if err != nil {
			return
		}
		r.mu.Lock()
		if r.closing || r.max <= 0 || len(r.active) >= r.max {
			r.mu.Unlock()
			// Overload never queues or delegates an unattested connection.
			_ = conn.Close()
			continue
		}
		r.active[conn] = struct{}{}
		r.wg.Add(1)
		r.mu.Unlock()
		go r.serve(ctx, conn)
	}
}

func (r *boundedNativeMCPRuntime) serve(ctx context.Context, conn net.Conn) {
	defer r.wg.Done()
	defer func() {
		_ = conn.Close()
		r.mu.Lock()
		delete(r.active, conn)
		r.mu.Unlock()
	}()
	_ = r.server.ServeConn(ctx, conn)
}

func (r *boundedNativeMCPRuntime) Close() error {
	if r == nil {
		return nil
	}
	r.once.Do(func() {
		r.mu.Lock()
		r.closing = true
		connections := make([]net.Conn, 0, len(r.active))
		for conn := range r.active {
			connections = append(connections, conn)
		}
		r.mu.Unlock()
		r.cancel()
		r.closeErr = r.listener.Close()
		for _, conn := range connections {
			_ = conn.Close()
		}
		done := make(chan struct{})
		go func() { r.wg.Wait(); close(done) }()
		drain := r.drain
		if drain <= 0 {
			drain = nativeMCPDrainTimeout
		}
		select {
		case <-done:
		case <-time.After(drain):
			r.closeErr = errors.Join(r.closeErr, errNativeMCPDrainTimeout)
		}
	})
	return r.closeErr
}
