package main

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"
)

type channelNativeListener struct {
	connections chan net.Conn
	done        chan struct{}
	once        sync.Once
}

func newChannelNativeListener() *channelNativeListener {
	return &channelNativeListener{connections: make(chan net.Conn, 8), done: make(chan struct{})}
}

func (l *channelNativeListener) Accept() (net.Conn, error) {
	select {
	case conn := <-l.connections:
		return conn, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}
func (l *channelNativeListener) Close() error { l.once.Do(func() { close(l.done) }); return nil }

type blockingConnServer struct{ entered chan struct{} }

func (s blockingConnServer) ServeConn(_ context.Context, conn net.Conn) error {
	select {
	case s.entered <- struct{}{}:
	default:
	}
	var b [1]byte
	_, err := conn.Read(b[:])
	return err
}

func TestNativeMCPRuntimeClosesHungValidPeerBeforeBoundedDrain(t *testing.T) {
	listener := newChannelNativeListener()
	server := blockingConnServer{entered: make(chan struct{}, 1)}
	runtime := newBoundedNativeMCPRuntime(context.Background(), listener, server, 1, time.Second)
	client, accepted := net.Pipe()
	defer client.Close()
	listener.connections <- accepted
	select {
	case <-server.entered:
	case <-time.After(time.Second):
		t.Fatal("valid peer was not served")
	}
	started := time.Now()
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
	if time.Since(started) >= time.Second {
		t.Fatal("shutdown did not interrupt hung peer")
	}
}

func TestNativeMCPRuntimeFloodFailsClosedAtCapacity(t *testing.T) {
	listener := newChannelNativeListener()
	server := blockingConnServer{entered: make(chan struct{}, 1)}
	runtime := newBoundedNativeMCPRuntime(context.Background(), listener, server, 1, time.Second)
	defer runtime.Close()
	firstClient, firstServer := net.Pipe()
	defer firstClient.Close()
	listener.connections <- firstServer
	select {
	case <-server.entered:
	case <-time.After(time.Second):
		t.Fatal("first connection was not served")
	}
	secondClient, secondServer := net.Pipe()
	defer secondClient.Close()
	listener.connections <- secondServer
	_ = secondClient.SetReadDeadline(time.Now().Add(time.Second))
	var b [1]byte
	if _, err := secondClient.Read(b[:]); err == nil {
		t.Fatal("overload connection remained open")
	}
}

type stuckNativeRuntime struct{ err error }

func (s stuckNativeRuntime) Close() error { return s.err }

func TestProductionRuntimeDoesNotRaceMeshTeardownAfterDrainFailure(t *testing.T) {
	meshClosed := false
	runtime := &configuredProductionMeshRuntime{
		native: stuckNativeRuntime{err: errNativeMCPDrainTimeout},
		mesh:   &verifiedMeshComposition{close: func() { meshClosed = true }},
	}
	if err := runtime.Close(); !errors.Is(err, errNativeMCPDrainTimeout) {
		t.Fatalf("Close error = %v", err)
	}
	if meshClosed {
		t.Fatal("mesh tore down while native requests might still be live")
	}
}
