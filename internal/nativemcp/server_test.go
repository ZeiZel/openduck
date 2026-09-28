package nativemcp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

type fixedPeers struct {
	value PeerIdentity
	err   error
}

func (p fixedPeers) Current(context.Context) (PeerIdentity, error) { return p.value, p.err }

type backend struct {
	calls    int
	rejected bool
	seen     []string
}

func (b *backend) BindProcessAttestor(ProcessAttestor) Backend { return b }

type attestor struct{ peer PeerIdentity }

func (h attestor) VerifyNativeMCPPeer(_ context.Context, c SessionContract, p PeerIdentity) error {
	if p != h.peer || c.Provider != p.Provider || c.PeerID != p.PeerID {
		return errors.New("attestation rejected")
	}
	return nil
}

type socketPeers struct{ peer PeerIdentity }

func (p socketPeers) PeerFor(context.Context, net.Conn) (PeerIdentity, error) { return p.peer, nil }

type socketResolver struct {
	c SessionContract
	b *backend
	p PeerIdentity
}

func (r socketResolver) ResolveNativeMCPSession(context.Context, PeerIdentity) (SessionContract, AttestedBackend, ProcessAttestor, error) {
	return r.c, r.b, attestor{peer: r.p}, nil
}

func (b *backend) Authorize(_ context.Context, c SessionContract, p PeerIdentity) error {
	if b.rejected || c.Provider != "codex" || p != (PeerIdentity{Provider: "codex", PeerID: "peer-1"}) {
		return errors.New("denied")
	}
	return nil
}
func (b *backend) Invoke(_ context.Context, _ SessionContract, _ PeerIdentity, op string, args json.RawMessage) (json.RawMessage, error) {
	b.calls++
	b.seen = append(b.seen, op+":"+string(args))
	return json.RawMessage(`{"status":"accepted"}`), nil
}
func contract(now time.Time) SessionContract {
	return SessionContract{SchemaVersion: SessionContractV1, Provider: "codex", ProfileID: "codex-profile", RevisionID: "revision-1", UISessionID: "ui-session", UIChannelID: "ui-channel", RootRunID: "root-1", RunID: "root-1", MeshSessionID: "mesh-session", AttemptID: "attempt-1", EndpointID: "endpoint-1", PeerID: "peer-1", Generation: 1, ExpiresAt: now.Add(time.Minute)}
}
func serve(t *testing.T, s Server, input string) []map[string]any {
	t.Helper()
	var out bytes.Buffer
	if err := s.Serve(context.Background(), strings.NewReader(input), &out); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	result := make([]map[string]any, 0, len(lines))
	for _, line := range lines {
		var v map[string]any
		if json.Unmarshal([]byte(line), &v) != nil {
			t.Fatalf("invalid stdout %q", line)
		}
		result = append(result, v)
	}
	return result
}

func TestSocketServerPartialFrameHitsFirstFrameDeadline(t *testing.T) {
	now := time.Now().UTC()
	peer := PeerIdentity{Provider: "codex", PeerID: "peer-1"}
	s := SocketServer{Peers: socketPeers{peer: peer}, Resolver: socketResolver{c: contract(now), b: &backend{}, p: peer}, Now: func() time.Time { return now }, FirstFrameTimeout: 30 * time.Millisecond, IdleTimeout: time.Second, WriteTimeout: time.Second}
	client, server := net.Pipe()
	defer client.Close()
	done := make(chan error, 1)
	go func() { done <- s.ServeConn(context.Background(), server) }()
	if _, err := client.Write([]byte(`{"jsonrpc":"2.0"`)); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, ErrInvalid) {
			t.Fatalf("partial frame error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("partial frame bypassed per-frame deadline")
	}
}

func TestSocketServerCancellationInterruptsIdlePeer(t *testing.T) {
	now := time.Now().UTC()
	peer := PeerIdentity{Provider: "codex", PeerID: "peer-1"}
	s := SocketServer{Peers: socketPeers{peer: peer}, Resolver: socketResolver{c: contract(now), b: &backend{}, p: peer}, Now: func() time.Time { return now }, FirstFrameTimeout: time.Hour}
	client, server := net.Pipe()
	defer client.Close()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.ServeConn(ctx, server) }()
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("context cancellation did not interrupt idle connection")
	}
}
func TestMCPExposesExactlyBoundChildTools(t *testing.T) {
	now := time.Date(2026, 8, 30, 0, 0, 0, 0, time.UTC)
	b := &backend{}
	s := Server{Contract: contract(now), Peers: fixedPeers{value: PeerIdentity{Provider: "codex", PeerID: "peer-1"}}, Backend: b, Now: func() time.Time { return now }}
	response := serve(t, s, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"host","version":"1"}}}`+"\n"+`{"jsonrpc":"2.0","method":"notifications/initialized"}`+"\n"+`{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}`+"\n"+`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"openduck_mesh_send","arguments":{"run_id":"child-1","input_ref":"artifact-1"}}}`+"\n")
	if len(response) != 3 {
		t.Fatal(len(response))
	}
	tools := response[1]["result"].(map[string]any)["tools"].([]any)
	if len(tools) != 11 {
		t.Fatalf("tools=%d", len(tools))
	}
	if b.calls != 1 || !strings.Contains(b.seen[0], "send:") {
		t.Fatalf("calls=%v", b.seen)
	}
}
func TestMCPRejectsRawMeshInjectionAndCrossAudienceFields(t *testing.T) {
	now := time.Now().UTC()
	b := &backend{}
	s := Server{Contract: contract(now), Peers: fixedPeers{value: PeerIdentity{Provider: "codex", PeerID: "peer-1"}}, Backend: b, Now: func() time.Time { return now }}
	response := serve(t, s, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"host","version":"1"}}}`+"\n"+`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"openduck_mesh_proposeMesh","arguments":{}}}`+"\n"+`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"openduck_mesh_send","arguments":{"run_id":"child-1","input_ref":"artifact-1","endpoint_id":"stolen"}}}`+"\n")
	if b.calls != 0 {
		t.Fatal("backend invoked")
	}
	for _, v := range response[1:] {
		if _, ok := v["error"]; !ok {
			t.Fatal(v)
		}
	}
}
func TestMCPFailsClosedForPeerSubstitutionExpiryAndRevocation(t *testing.T) {
	now := time.Date(2026, 8, 30, 0, 0, 0, 0, time.UTC)
	for name, mutate := range map[string]func(*Server, *backend){"peer": func(s *Server, _ *backend) {
		s.Peers = fixedPeers{value: PeerIdentity{Provider: "claude", PeerID: "peer-2"}}
	}, "expired": func(s *Server, _ *backend) { s.Contract.ExpiresAt = now }, "revoked": func(_ *Server, b *backend) { b.rejected = true }} {
		t.Run(name, func(t *testing.T) {
			b := &backend{}
			s := Server{Contract: contract(now), Peers: fixedPeers{value: PeerIdentity{Provider: "codex", PeerID: "peer-1"}}, Backend: b, Now: func() time.Time { return now }}
			mutate(&s, b)
			var out bytes.Buffer
			err := s.Serve(context.Background(), strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"host","version":"1"}}}`+"\n"), &out)
			if !errors.Is(err, ErrUnauthorized) && !strings.Contains(out.String(), "authorization unavailable") {
				t.Fatalf("err=%v out=%s", err, out.String())
			}
			if b.calls != 0 {
				t.Fatal("invoked")
			}
		})
	}
}
func TestMCPRejectsCrossSessionContract(t *testing.T) {
	now := time.Now().UTC()
	c := contract(now)
	c.RunID = "other-root"
	if c.Validate(now) == nil {
		t.Fatal("cross-session root accepted")
	}
}

func TestMCPRejectsDeepSeekNativeContract(t *testing.T) {
	now := time.Now().UTC()
	c := contract(now)
	c.Provider = "deepseek"
	if c.Validate(now) == nil {
		t.Fatal("DeepSeek native contract accepted")
	}
}

func TestSocketServerResolvesContractOnlyAfterPeerAttestation(t *testing.T) {
	now := time.Date(2026, 8, 30, 0, 0, 0, 0, time.UTC)
	peer := PeerIdentity{Provider: "codex", PeerID: "peer-1"}
	b := &backend{}
	server, client := net.Pipe()
	done := make(chan error, 1)
	go func() {
		done <- (SocketServer{Peers: socketPeers{peer: peer}, Resolver: socketResolver{c: contract(now), b: b, p: peer}, Now: func() time.Time { return now }}).ServeConn(context.Background(), server)
	}()
	_, err := client.Write([]byte(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"host","version":"1"}}}` + "\n"))
	if err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReader(client).ReadBytes('\n')
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(line, []byte(`"protocolVersion":"2025-11-25"`)) {
		t.Fatalf("unexpected %s", line)
	}
	_ = client.Close()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
