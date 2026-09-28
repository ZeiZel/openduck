package codexbroker

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

func fixtureAttestation() BoundaryAttestation {
	return BoundaryAttestation{SchemaVersion: ProtocolV1, RuntimeID: "runtime_1", PeerID: "peer_1", RuntimeBinaryDigest: Digest("runtime"), PolicyDigest: Digest("policy"), IssuedAt: time.Now().UTC(), PeerUID: 1000, PeerGID: 1000, Epoch: 1, BrokerSocketDigest: Digest("socket"), BrokerReleaseDigest: Digest("release"), ExpectedEgressUID: 1002, ExpectedEgressGID: 1003, ExpectedEgressReleaseDigest: Digest("egress-release"), ExpectedEgressSocketDigest: Digest("egress-socket"), Signature: Digest("signature")}
}

type allowPeer struct{ revoked bool }

func (p allowPeer) Verify(context.Context, BoundaryAttestation) error {
	if p.revoked {
		return ErrAttestation
	}
	return nil
}
func fixtureInventory() Inventory {
	return Inventory{SchemaVersion: ProtocolV1, AccountState: "chatgpt", RuntimeVersion: "fixture", RuntimeDigest: Digest("runtime"), ModelOnly: true, Tools: []string{}, MCP: []string{}, Plugins: []string{}, Hooks: []string{}}
}

func TestBrokerTypedAllowlistAndRevalidation(t *testing.T) {
	f := &fake{AttestationValue: fixtureAttestation(), InventoryValue: fixtureInventory(), Answer: "ok"}
	b, err := newBroker(f, f.AttestationValue, allowPeer{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = b.Inventory(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err = b.LoginStart(context.Background(), LoginStart{AccountType: "chatgpt"}); err != nil {
		t.Fatal(err)
	}
	r, err := b.Turn(context.Background(), Turn{SessionID: "session_1", TurnID: "turn_1", Prompt: "hello", Classification: "L0", MaxOutputBytes: 100})
	if err != nil || r.Answer != "ok" {
		t.Fatalf("turn=%+v err=%v", r, err)
	}
	f.Revoked = true
	if _, err = b.Inventory(context.Background()); !errors.Is(err, ErrAttestation) {
		t.Fatalf("revoked runtime err=%v", err)
	}
}

func TestBrokerRejectsInvalidOperationsAndProductionFailsClosed(t *testing.T) {
	f := &fake{AttestationValue: fixtureAttestation(), InventoryValue: fixtureInventory()}
	b, err := newBroker(f, f.AttestationValue, allowPeer{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = b.Turn(context.Background(), Turn{SessionID: "s", TurnID: "turn_1", Prompt: "x", Classification: "L2", MaxOutputBytes: 1}); !errors.Is(err, ErrProtocol) {
		t.Fatal(err)
	}
	if _, err = NewProduction(); !errors.Is(err, ErrUnavailable) {
		t.Fatal(err)
	}
	if err := (frame{Sequence: 1, Kind: "evil"}).validate(0); !errors.Is(err, ErrProtocol) {
		t.Fatal(err)
	}
	if err := (frame{Sequence: 1, Kind: "turn"}).validate(1); !errors.Is(err, ErrReplay) {
		t.Fatal(err)
	}
	if err := (frame{Sequence: 3, Kind: "turn"}).validate(1); !errors.Is(err, ErrOutOfOrder) {
		t.Fatal(err)
	}
	tooBig := make([]byte, MaxFrameBytes+1)
	if err := (frame{Sequence: 1, Kind: "turn", Payload: tooBig}).validate(0); !errors.Is(err, ErrProtocol) {
		t.Fatal(err)
	}
}

func TestTypedCompanionFieldsAreMutuallyExclusive(t *testing.T) {
	if (LoginCompleted{LoginID: "l", Success: true, ErrorCode: "protocol"}).Validate() == nil {
		t.Fatal("successful login accepted error_code")
	}
	if (TurnResult{SessionID: "s", TurnID: "t", State: "completed", Answer: "ok", ErrorCode: "protocol"}).Validate() == nil {
		t.Fatal("completed turn accepted error_code")
	}
	if (TurnResult{SessionID: "s", TurnID: "t", State: "failed", Answer: "late", ErrorCode: "protocol"}).Validate() == nil {
		t.Fatal("failed turn accepted answer")
	}
}

func TestLoginStartedRejectsBareHTTPS(t *testing.T) {
	if (LoginStarted{LoginID: "l", AuthorizationURL: "https://"}).Validate() == nil {
		t.Fatal("bare https URL accepted")
	}
}

func TestVerifiedClientAuthenticatesFirstExplicitAttestation(t *testing.T) {
	left, right := net.Pipe()
	expected := fixtureAttestation()
	attacker := expected
	attacker.RuntimeID = "attacker_runtime"
	c, err := newVerifiedClient(left, expected, allowPeer{})
	if err != nil {
		t.Fatal(err)
	}
	serverDone := make(chan error, 1)
	go func() {
		defer right.Close()
		f, e := readFrame(bufio.NewReader(right))
		if e == nil && f.Kind != "attestation" {
			e = ErrProtocol
		}
		if e == nil {
			e = writeFrame(right, wireFrame{SchemaVersion: ProtocolV1, Direction: "response", Sequence: 1, RequestID: f.RequestID, Kind: "attestation", OK: true, Payload: mustJSON(attacker)})
		}
		serverDone <- e
	}()
	if _, err := c.Attestation(context.Background()); !errors.Is(err, ErrAttestation) {
		t.Fatalf("attacker attestation err=%v", err)
	}
	if err := serverDoneWait(serverDone); err != nil {
		t.Fatal(err)
	}
}

func TestReadFrameRequiresEnvelopePresenceAndConditionalErrorCode(t *testing.T) {
	encode := func(v map[string]any) *bufio.Reader {
		raw := mustJSON(v)
		var n [4]byte
		binary.BigEndian.PutUint32(n[:], uint32(len(raw)))
		var b bytes.Buffer
		b.Write(n[:])
		b.Write(raw)
		return bufio.NewReader(&b)
	}
	base := map[string]any{"schema_version": ProtocolV1, "direction": "response", "sequence": 1, "request_id": "r", "kind": "close", "payload": map[string]any{}, "ok": true}
	missingOK := map[string]any{}
	for k, v := range base {
		if k != "ok" {
			missingOK[k] = v
		}
	}
	if _, err := readFrame(encode(missingOK)); err == nil {
		t.Fatal("missing ok accepted")
	}
	withEmptyError := map[string]any{}
	for k, v := range base {
		withEmptyError[k] = v
	}
	withEmptyError["error_code"] = ""
	if _, err := readFrame(encode(withEmptyError)); err == nil {
		t.Fatal("explicit empty error_code accepted")
	}
	withErrorPayload := map[string]any{}
	for k, v := range base {
		withErrorPayload[k] = v
	}
	withErrorPayload["ok"] = false
	withErrorPayload["error_code"] = "protocol"
	withErrorPayload["payload"] = nil
	if _, err := readFrame(encode(withErrorPayload)); err == nil {
		t.Fatal("error response payload:null accepted")
	}
}

func TestServerContextCancellationClosesIdleTransport(t *testing.T) {
	left, right := net.Pipe()
	defer left.Close()
	f := &fake{AttestationValue: fixtureAttestation(), InventoryValue: fixtureInventory()}
	b, err := newBroker(f, f.AttestationValue, allowPeer{})
	if err != nil {
		t.Fatal(err)
	}
	s := serverForBroker(right, b)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.serve(ctx) }()
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("server remained blocked on idle read after context cancellation")
	}
}

func TestClientContextCancellationInterruptsBlockedWriteAndJoinsReader(t *testing.T) {
	left, right := net.Pipe()
	c := newClient(left).(*client)
	defer right.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := c.Inventory(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("blocked write err=%v", err)
	}
	select {
	case <-c.readDone:
	case <-time.After(time.Second):
		t.Fatal("client reader was not joined after blocked write cancellation")
	}
}

func TestClientCloseDoesNotWaitBehindBlockedWrite(t *testing.T) {
	left, right := net.Pipe()
	c := newClient(left).(*client)
	defer right.Close()
	firstDone := make(chan error, 1)
	go func() { _, err := c.Inventory(context.Background()); firstDone <- err }()
	time.Sleep(20 * time.Millisecond)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	start := time.Now()
	if err := c.Close(ctx); err != nil && !errors.Is(err, ErrClosed) && !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("close err=%v", err)
	}
	if elapsed := time.Since(start); elapsed > 200*time.Millisecond {
		t.Fatalf("Close waited behind blocked writer: %s", elapsed)
	}
	select {
	case <-firstDone:
	case <-time.After(time.Second):
		t.Fatal("blocked writer was not released by Close")
	}
}

func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}
func serverDoneWait(ch <-chan error) error {
	select {
	case err := <-ch:
		return err
	case <-time.After(time.Second):
		return errors.New("server did not finish")
	}
}

func TestBrokerCloseAndOpaqueSpliceDenial(t *testing.T) {
	f := &fake{AttestationValue: fixtureAttestation(), InventoryValue: fixtureInventory()}
	b, err := newBroker(f, f.AttestationValue, allowPeer{})
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Attestation(context.Background()); !errors.Is(err, ErrClosed) {
		t.Fatal(err)
	}
	for _, id := range []string{"../other", "peer\nforged", ""} {
		if opaque(id) {
			t.Fatalf("splice accepted %q", id)
		}
	}
}

func TestBrokerHonorsContextTimeoutAndCancel(t *testing.T) {
	f := &fake{AttestationValue: fixtureAttestation(), InventoryValue: fixtureInventory(), Delay: 50 * time.Millisecond}
	b, err := newBroker(f, f.AttestationValue, allowPeer{})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	if _, err := b.Inventory(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("timeout err=%v", err)
	}
	f.Delay = 0
	if err := b.Cancel(context.Background(), Cancel{SessionID: "session_1", TurnID: "turn_1"}); err != nil {
		t.Fatal(err)
	}
}

func TestBrokerRestartRequiresFreshAttestedConnection(t *testing.T) {
	f1 := &fake{AttestationValue: fixtureAttestation(), InventoryValue: fixtureInventory()}
	b1, err := newBroker(f1, f1.AttestationValue, allowPeer{})
	if err != nil {
		t.Fatal(err)
	}
	if err := b1.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := b1.Inventory(context.Background()); !errors.Is(err, ErrClosed) {
		t.Fatalf("closed connection err=%v", err)
	}
	f2 := &fake{AttestationValue: fixtureAttestation(), InventoryValue: fixtureInventory()}
	b2, err := newBroker(f2, f2.AttestationValue, allowPeer{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b2.Inventory(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestTypedWireStateMachineAndCorrelation(t *testing.T) {
	left, right := net.Pipe()
	f := &fake{AttestationValue: fixtureAttestation(), InventoryValue: fixtureInventory(), Answer: "wire"}
	s, err := newServer(right, f, f.AttestationValue, allowPeer{})
	if err != nil {
		t.Fatal(err)
	}
	serverErr := make(chan error, 1)
	go func() { serverErr <- s.serve(context.Background()) }()
	c := newClient(left)
	if _, err := c.Attestation(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Inventory(context.Background()); err != nil {
		t.Fatal(err)
	}
	started, err := c.LoginStart(context.Background(), LoginStart{AccountType: "chatgpt"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.LoginCompleted(context.Background(), started.LoginID); err != nil {
		t.Fatal(err)
	}
	got, err := c.Turn(context.Background(), Turn{SessionID: "session_wire", TurnID: "turn_1", Prompt: "hello", Classification: "L0", MaxOutputBytes: 64})
	if err != nil || got.Answer != "wire" {
		t.Fatalf("turn=%+v err=%v", got, err)
	}
	closeCtx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_ = c.Close(closeCtx)
	if err := <-serverErr; err != nil {
		t.Fatal(err)
	}
}

func TestTypedWireCancelDoesNotWaitForTurn(t *testing.T) {
	left, right := net.Pipe()
	f := &fake{AttestationValue: fixtureAttestation(), InventoryValue: fixtureInventory(), Delay: 2 * time.Second, TurnEntered: make(chan struct{})}
	s, err := newServer(right, f, f.AttestationValue, allowPeer{})
	if err != nil {
		t.Fatal(err)
	}
	serverErr := make(chan error, 1)
	go func() { serverErr <- s.serve(context.Background()) }()
	c := newClient(left)
	turnDone := make(chan error, 1)
	go func() {
		_, e := c.Turn(context.Background(), Turn{SessionID: "session_cancel", TurnID: "turn_1", Prompt: "hello", Classification: "L0", MaxOutputBytes: 64})
		turnDone <- e
	}()
	// The fake signals only after server.runTurn has entered the backend. That
	// proves the active-turn registration without depending on scheduler sleep.
	select {
	case <-f.TurnEntered:
	case <-time.After(time.Second):
		t.Fatal("turn dispatch did not reach deterministic barrier")
	}
	start := time.Now()
	if err := c.Cancel(context.Background(), Cancel{SessionID: "session_cancel", TurnID: "turn_1"}); err != nil {
		t.Fatal(err)
	}
	if time.Since(start) > time.Second {
		t.Fatal("cancel waited for turn")
	}
	if err := <-turnDone; !errors.Is(err, context.Canceled) {
		t.Fatalf("turn err=%v", err)
	}
	_ = c.Close(context.Background())
	if err := <-serverErr; err != nil {
		t.Fatal(err)
	}
}

func TestTypedWirePreCancelTombstoneIsExactAndSkipsBackendTurn(t *testing.T) {
	left, right := net.Pipe()
	defer left.Close()
	f := &fake{AttestationValue: fixtureAttestation(), InventoryValue: fixtureInventory()}
	b, err := newBroker(f, f.AttestationValue, allowPeer{})
	if err != nil {
		t.Fatal(err)
	}
	s := serverForBroker(right, b)
	done := make(chan error, 1)
	go func() { done <- s.serve(context.Background()) }()
	turn := Turn{SessionID: "session_pre", TurnID: "turn_pre", Prompt: "hello", Classification: "L0", MaxOutputBytes: 64}
	cancel := Cancel{SessionID: turn.SessionID, TurnID: turn.TurnID}
	if err := writeFrame(left, wireFrame{SchemaVersion: ProtocolV1, Direction: "request", Sequence: 1, RequestID: "req_1", Kind: "cancel", Payload: mustJSON(cancel)}); err != nil {
		t.Fatal(err)
	}
	r := bufio.NewReader(left)
	first, err := readFrame(r)
	if err != nil || !first.OK || first.Kind != "cancel" {
		t.Fatalf("cancel response=%+v err=%v", first, err)
	}
	if err := writeFrame(left, wireFrame{SchemaVersion: ProtocolV1, Direction: "request", Sequence: 2, RequestID: "req_2", Kind: "turn", Payload: mustJSON(turn)}); err != nil {
		t.Fatal(err)
	}
	second, err := readFrame(r)
	if err != nil || !second.OK || second.Kind != "turn" {
		t.Fatalf("turn response=%+v err=%v", second, err)
	}
	var got TurnResult
	if err := strictUnmarshal(second.Payload, &got); err != nil || got.State != "cancelled" || got.ErrorCode != "CANCELLED" {
		t.Fatalf("pre-cancel result=%+v err=%v", got, err)
	}
	f.mu.Lock()
	for _, call := range f.Calls {
		if call == "turn" || call == "cancel" {
			t.Fatalf("pre-cancel reached backend: %v", f.Calls)
		}
	}
	f.mu.Unlock()
	if err := writeFrame(left, wireFrame{SchemaVersion: ProtocolV1, Direction: "request", Sequence: 3, RequestID: "req_3", Kind: "close", Payload: []byte("{}")}); err != nil {
		t.Fatal(err)
	}
	if _, err := readFrame(r); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestTypedWireLateCancelDoesNotTombstoneNextTurn(t *testing.T) {
	left, right := net.Pipe()
	f := &fake{AttestationValue: fixtureAttestation(), InventoryValue: fixtureInventory(), Answer: "ok"}
	s, err := newServer(right, f, f.AttestationValue, allowPeer{})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- s.serve(context.Background()) }()
	c := newClient(left)
	first := Turn{SessionID: "session_completed", TurnID: "turn_1", Prompt: "one", Classification: "L0", MaxOutputBytes: 64}
	if _, err := c.Turn(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	if err := c.Cancel(context.Background(), Cancel{SessionID: first.SessionID, TurnID: first.TurnID}); err != nil {
		t.Fatalf("late cancel=%v", err)
	}
	second := Turn{SessionID: first.SessionID, TurnID: "turn_2", Prompt: "two", Classification: "L0", MaxOutputBytes: 64}
	got, err := c.Turn(context.Background(), second)
	if err != nil || got.State != "completed" || got.TurnID != second.TurnID {
		t.Fatalf("second turn=%+v err=%v", got, err)
	}
	// The completed ledger is exact and bounded, not merely the most recent
	// turn per session. A delayed old cancel must remain a no-op after newer
	// turns have completed and must not poison the next turn.
	if err := c.Cancel(context.Background(), Cancel{SessionID: first.SessionID, TurnID: first.TurnID}); err != nil {
		t.Fatalf("delayed older cancel=%v", err)
	}
	third := Turn{SessionID: first.SessionID, TurnID: "turn_3", Prompt: "three", Classification: "L0", MaxOutputBytes: 64}
	got, err = c.Turn(context.Background(), third)
	if err != nil || got.State != "completed" || got.TurnID != third.TurnID {
		t.Fatalf("third turn=%+v err=%v", got, err)
	}
	_ = c.Close(context.Background())
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestStrictWireRejectsUnknownAndDuplicateKeys(t *testing.T) {
	for _, raw := range []string{
		`{"schema_version":"owner-runtime-broker.v1","direction":"request","sequence":1,"request_id":"req_1","kind":"inventory","ok":false,"extra":1}`,
		`{"schema_version":"owner-runtime-broker.v1","direction":"request","sequence":1,"request_id":"req_1","request_id":"req_2","kind":"inventory","ok":false}`,
	} {
		if _, err := readFrame(bufio.NewReader(strings.NewReader(stringFrame(raw)))); !errors.Is(err, ErrProtocol) {
			t.Fatalf("accepted malformed frame: %v", err)
		}
	}
}

func TestErrorCodeIsByteBoundedASCII(t *testing.T) {
	if validErrorCode("ошибка") || validErrorCode("bad code") || validErrorCode("bad\ncode") {
		t.Fatal("unsafe error code accepted")
	}
	if !validErrorCode("cancelled") {
		t.Fatal("safe error code rejected")
	}
}

type stubbornFake struct{ *fake }

func (s stubbornFake) Turn(_ context.Context, in Turn) (TurnResult, error) {
	time.Sleep(400 * time.Millisecond)
	return TurnResult{SessionID: in.SessionID, TurnID: in.TurnID, State: "completed", Answer: "late"}, nil
}

type contextIgnoringAttestation struct {
	*fake
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func (b *contextIgnoringAttestation) Attestation(context.Context) (BoundaryAttestation, error) {
	b.once.Do(func() { close(b.started) })
	<-b.release
	return b.AttestationValue, nil
}

func TestNewBrokerBoundsContextIgnoringAttestation(t *testing.T) {
	f := &contextIgnoringAttestation{
		fake:    &fake{AttestationValue: fixtureAttestation()},
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
	started := time.Now()
	_, err := newBroker(f, f.AttestationValue, allowPeer{})
	if !errors.Is(err, ErrAttestation) {
		t.Fatalf("constructor err=%v, want attestation failure", err)
	}
	if elapsed := time.Since(started); elapsed < backendCallTimeout-100*time.Millisecond || elapsed > backendCallTimeout+time.Second {
		t.Fatalf("constructor duration=%s, want bounded around %s", elapsed, backendCallTimeout)
	}
	select {
	case <-f.started:
	default:
		t.Fatal("backend was not called")
	}
	close(f.release)
}

func TestServerBoundsContextIgnoringRequestAndJoinsWorker(t *testing.T) {
	left, right := net.Pipe()
	f := &contextIgnoringAttestation{
		fake:    &fake{AttestationValue: fixtureAttestation(), InventoryValue: fixtureInventory()},
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
	b := &Broker{backend: f, verifier: allowPeer{}, att: f.AttestationValue}
	s := serverForBroker(right, b)
	serveCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	serverDone := make(chan error, 1)
	go func() { serverDone <- s.serve(serveCtx) }()
	c := newClient(left).(*client)
	requestDone := make(chan error, 1)
	go func() {
		_, err := c.Inventory(context.Background())
		requestDone <- err
	}()
	select {
	case <-f.started:
	case <-time.After(time.Second):
		t.Fatal("request did not reach backend")
	}
	cancel()
	started := time.Now()
	select {
	case <-serverDone:
	case <-time.After(backendCallTimeout + time.Second):
		t.Fatal("server remained blocked behind context-ignoring backend")
	}
	if elapsed := time.Since(started); elapsed > backendCallTimeout+500*time.Millisecond {
		t.Fatalf("shutdown duration=%s, want bounded", elapsed)
	}
	select {
	case <-requestDone:
	case <-time.After(time.Second):
		t.Fatal("client request did not observe closed transport")
	}
	close(f.release)
	_ = c.Close(context.Background())
}

func TestServerBoundsPeerDisconnectBehindContextIgnoringBackend(t *testing.T) {
	left, right := net.Pipe()
	f := &contextIgnoringAttestation{
		fake:    &fake{AttestationValue: fixtureAttestation(), InventoryValue: fixtureInventory()},
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
	b := &Broker{backend: f, verifier: allowPeer{}, att: f.AttestationValue}
	s := serverForBroker(right, b)
	serverDone := make(chan error, 1)
	go func() { serverDone <- s.serve(context.Background()) }()
	client := newClient(left).(*client)
	requestDone := make(chan error, 1)
	go func() {
		_, err := client.Inventory(context.Background())
		requestDone <- err
	}()
	select {
	case <-f.started:
	case <-time.After(time.Second):
		t.Fatal("request did not reach backend")
	}
	_ = left.Close()
	started := time.Now()
	select {
	case <-serverDone:
	case <-time.After(backendCallTimeout + time.Second):
		t.Fatal("peer disconnect left server blocked")
	}
	if elapsed := time.Since(started); elapsed > backendCallTimeout+500*time.Millisecond {
		t.Fatalf("disconnect shutdown duration=%s, want bounded", elapsed)
	}
	close(f.release)
	select {
	case <-requestDone:
	case <-time.After(time.Second):
		t.Fatal("client request did not finish after disconnect")
	}
}

func TestServerShutdownClosesTransportAndJoinsStubbornTurn(t *testing.T) {
	left, right := net.Pipe()
	f := &stubbornFake{&fake{AttestationValue: fixtureAttestation(), InventoryValue: fixtureInventory()}}
	s, err := newServer(right, f, f.AttestationValue, allowPeer{})
	if err != nil {
		t.Fatal(err)
	}
	serverDone := make(chan error, 1)
	go func() { serverDone <- s.serve(context.Background()) }()
	c := newClient(left).(*client)
	if _, err := c.Inventory(context.Background()); err != nil {
		t.Fatal(err)
	}
	turnDone := make(chan error, 1)
	go func() {
		_, e := c.Turn(context.Background(), Turn{SessionID: "session_shutdown", TurnID: "turn_shutdown", Prompt: "x", Classification: "L0", MaxOutputBytes: 10})
		turnDone <- e
	}()
	time.Sleep(15 * time.Millisecond)
	if err := c.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-c.readDone:
	case <-time.After(time.Second):
		t.Fatal("reader not joined")
	}
	select {
	case <-serverDone:
	case <-time.After(time.Second):
		t.Fatal("server did not close transport")
	}
	<-turnDone
}

func TestWireDirectionKindOKMatrix(t *testing.T) {
	a := fixtureAttestation()
	inv := fixtureInventory()
	requests := []struct {
		kind    string
		payload any
	}{
		{"attestation", struct{}{}}, {"inventory", struct{}{}}, {"login.start", LoginStart{AccountType: "chatgpt"}},
		{"login.completed", struct {
			LoginID string `json:"login_id"`
		}{"login_1"}},
		{"turn", Turn{SessionID: "s", TurnID: "t", Prompt: "p", Classification: "L0", MaxOutputBytes: 1}}, {"cancel", Cancel{SessionID: "s", TurnID: "t"}}, {"close", struct{}{}}}
	for _, x := range requests {
		raw, _ := json.Marshal(x.payload)
		f := wireFrame{SchemaVersion: ProtocolV1, Direction: "request", Sequence: 1, RequestID: "r", Kind: x.kind, Payload: raw}
		if err := validateWirePayload(f); err != nil {
			t.Errorf("request %s: %v", x.kind, err)
		}
	}
	responses := []struct {
		kind    string
		payload any
	}{{"attestation", a}, {"inventory", inv}, {"login.start", LoginStarted{LoginID: "l", AuthorizationURL: "https://x"}}, {"login.completed", LoginCompleted{LoginID: "l", Success: true}}, {"turn", TurnResult{SessionID: "s", TurnID: "t", State: "completed", Answer: "a"}}, {"cancel", struct{}{}}, {"close", struct{}{}}}
	for _, x := range responses {
		raw, _ := json.Marshal(x.payload)
		f := wireFrame{SchemaVersion: ProtocolV1, Direction: "response", Sequence: 1, RequestID: "r", Kind: x.kind, OK: true, Payload: raw}
		if err := validateWirePayload(f); err != nil {
			t.Errorf("response %s: %v", x.kind, err)
		}
	}
	for _, x := range responses {
		raw, _ := json.Marshal(x.payload)
		f := wireFrame{SchemaVersion: ProtocolV1, Direction: "response", Sequence: 1, RequestID: "r", Kind: x.kind, OK: false, ErrorCode: "protocol", Payload: raw}
		if err := validateWirePayload(f); err == nil {
			t.Errorf("error response %s accepted payload", x.kind)
		}
	}
}

func stringFrame(raw string) string {
	return string([]byte{0, 0, byte(len(raw) >> 8), byte(len(raw))}) + raw
}
