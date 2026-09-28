package providertransport

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"openduck/internal/macoschannel"
	"openduck/internal/mesh"
	"openduck/internal/providerbridge"
)

type runtimeDriverFake struct {
	mu              sync.Mutex
	proof           RecoveryProof
	recoverErr      error
	recoverCalls    int
	recoverEntered  chan struct{}
	recoverRelease  chan struct{}
	startErr        error
	status          RuntimeStatus
	result          RuntimeResult
	starts          int
	sends           int
	steers          int
	cancels         []mesh.Cancellation
	sendErr         error
	steerErr        error
	cancelErr       error
	lastStart       RuntimeStart
	sessionProof    PersistedSessionProof
	sessionProofErr error
	startEntered    chan struct{}
	startRelease    chan struct{}
	sendEntered     chan struct{}
	sendRelease     chan struct{}
	cancelEntered   chan struct{}
	cancelRelease   chan struct{}
}

func (d *runtimeDriverFake) RecoverSession(context.Context, string) (PersistedSessionProof, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.sessionProof, d.sessionProofErr
}

type durableStartDriver struct {
	runtimeDriverFake
	durableMu      sync.Mutex
	receipts       map[string]RuntimeStart
	bindingRequest map[string]string
	sessions       map[string]RuntimeSession
	invocations    int
	nativeEffects  int
}

func newDurableStartDriver() *durableStartDriver {
	return &durableStartDriver{
		runtimeDriverFake: runtimeDriverFake{proof: RecoveryProof{SchemaVersion: RecoveryProofV1, ReceiptStoreRevision: "durable-receipts-1", RequestIDRetention: true, BindingDigestRetention: true, InflightReconciled: true}},
		receipts:          map[string]RuntimeStart{},
		bindingRequest:    map[string]string{},
		sessions:          map[string]RuntimeSession{},
	}
}

func (d *durableStartDriver) Start(_ context.Context, start RuntimeStart) (RuntimeSession, error) {
	d.durableMu.Lock()
	defer d.durableMu.Unlock()
	d.invocations++
	if previous, ok := d.receipts[start.RequestID]; ok {
		if previous.RequestDigest != start.RequestDigest || previous.BindingID != start.BindingID || previous.BindingHash != start.BindingHash || previous.OrderID != start.OrderID || previous.OrderHash != start.OrderHash {
			return RuntimeSession{}, errors.New("durable request identity conflict")
		}
		return d.sessions[start.RequestID], nil
	}
	if requestID, ok := d.bindingRequest[start.BindingID]; ok && requestID != start.RequestID {
		return RuntimeSession{}, errors.New("durable binding identity conflict")
	}
	session := RuntimeSession{ID: "durable-" + start.BindingID}
	d.receipts[start.RequestID] = start
	d.bindingRequest[start.BindingID] = start.RequestID
	d.sessions[start.RequestID] = session
	d.nativeEffects++
	return session, nil
}

func (d *durableStartDriver) RecoverSession(_ context.Context, route string) (PersistedSessionProof, error) {
	d.durableMu.Lock()
	defer d.durableMu.Unlock()
	for requestID, start := range d.receipts {
		want := "ptv2-" + start.ProfileID + "-" + digestBytes([]byte(start.ProfileID+":"+start.BindingID+":"+start.BindingHash))
		if want == route {
			return PersistedSessionProof{SchemaVersion: PersistedSessionProofV1, RouteRef: route, NativeSessionID: d.sessions[requestID].ID, ProfileID: start.ProfileID, ProfileRevision: start.ProfileRevision, MappingDigest: start.MappingDigest, RuntimeDigest: start.RuntimeDigest, ProtocolDigest: start.ProtocolDigest, OrderID: start.OrderID, OrderHash: start.OrderHash, BindingID: start.BindingID, BindingHash: start.BindingHash, RunID: start.RunID, AttemptID: start.AttemptID, RequestID: start.RequestID, RequestDigest: start.RequestDigest, State: "running"}, nil
		}
	}
	return PersistedSessionProof{}, ErrReconcile
}

func (d *runtimeDriverFake) Recover(context.Context) (RecoveryProof, error) {
	d.mu.Lock()
	d.recoverCalls++
	proof, err := d.proof, d.recoverErr
	entered, release := d.recoverEntered, d.recoverRelease
	d.recoverEntered = nil
	d.mu.Unlock()
	if entered != nil {
		close(entered)
	}
	if release != nil {
		<-release
	}
	return proof, err
}
func (d *runtimeDriverFake) Start(_ context.Context, v RuntimeStart) (RuntimeSession, error) {
	d.mu.Lock()
	d.starts++
	d.lastStart = v
	entered, release, err := d.startEntered, d.startRelease, d.startErr
	d.mu.Unlock()
	if entered != nil {
		close(entered)
	}
	if release != nil {
		<-release
	}
	if err != nil {
		return RuntimeSession{}, err
	}
	return RuntimeSession{ID: "runtime-session-1"}, nil
}
func (d *runtimeDriverFake) Send(context.Context, RuntimeSession, string) error {
	d.mu.Lock()
	d.sends++
	entered, release, err := d.sendEntered, d.sendRelease, d.sendErr
	d.sendEntered = nil
	d.mu.Unlock()
	if entered != nil {
		close(entered)
	}
	if release != nil {
		<-release
	}
	return err
}
func (d *runtimeDriverFake) Steer(context.Context, RuntimeSession, string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.steers++
	return d.steerErr
}
func (d *runtimeDriverFake) Cancel(_ context.Context, _ RuntimeSession, c mesh.Cancellation) error {
	d.mu.Lock()
	d.cancels = append(d.cancels, c)
	entered, release, err := d.cancelEntered, d.cancelRelease, d.cancelErr
	d.cancelEntered = nil
	d.mu.Unlock()
	if entered != nil {
		close(entered)
	}
	if release != nil {
		<-release
	}
	return err
}
func (d *runtimeDriverFake) Status(context.Context, RuntimeSession) (RuntimeStatus, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.status.State == "" {
		return RuntimeStatus{State: "running", UsageSource: "unknown"}, nil
	}
	return d.status, nil
}
func (*runtimeDriverFake) Wait(context.Context, RuntimeSession, time.Time) (RuntimeStatus, error) {
	return RuntimeStatus{State: "running", UsageSource: "unknown"}, nil
}
func (d *runtimeDriverFake) Result(context.Context, RuntimeSession, string) (RuntimeResult, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.result.Status == "" {
		return RuntimeResult{Status: "completed", OutputArtifactRef: "artifact-1", SchemaRef: "schema-1", ProvenanceDigest: "sha256:" + string(bytes.Repeat([]byte("a"), 64)), Classification: "L1"}, nil
	}
	return d.result, nil
}

type serverTestConn struct {
	in                *bytes.Reader
	out               bytes.Buffer
	ev                macoschannel.Evidence
	sealErr, writeErr error
}

func (c *serverTestConn) Read(b []byte) (int, error) { return c.in.Read(b) }
func (c *serverTestConn) Write(b []byte) (int, error) {
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	return c.out.Write(b)
}
func (*serverTestConn) Close() error                      { return nil }
func (*serverTestConn) SetDeadline(time.Time) error       { return nil }
func (c *serverTestConn) Evidence() macoschannel.Evidence { return c.ev }

func (c *serverTestConn) Seal(domain string, raw []byte) (string, error) {
	if c.sealErr != nil {
		return "", c.sealErr
	}
	return domain + ":" + providerDigest(raw), nil
}
func (*serverTestConn) Verify(domain string, raw []byte, tag string) error {
	if tag != domain+":"+providerDigest(raw) {
		return ErrDenied
	}
	return nil
}

func serverFixture(t *testing.T) (*Server, *runtimeDriverFake, Descriptor, macoschannel.ReleasePin) {
	t.Helper()
	d := descriptorFixture(t, "codex", providerbridge.ProfileCodexChatGPT)
	controller := macoschannel.ReleasePin{ReleaseID: "controller-release-1", BinaryDigest: string(bytes.Repeat([]byte("a"), 64)), SocketDigest: string(bytes.Repeat([]byte("b"), 64)), ManifestDigest: string(bytes.Repeat([]byte("c"), 64))}
	driver := &runtimeDriverFake{proof: RecoveryProof{SchemaVersion: RecoveryProofV1, ReceiptStoreRevision: "receipts-1", RequestIDRetention: true, BindingDigestRetention: true, InflightReconciled: true}}
	s, err := NewServer(ServerConfig{Descriptor: d, Driver: driver, ControllerUID: 701, ControllerGID: 702, ControllerRelease: controller})
	if err != nil {
		t.Fatal(err)
	}
	return s, driver, d, controller
}

func serverEvidence(d Descriptor, controller macoschannel.ReleasePin) macoschannel.Evidence {
	return macoschannel.Evidence{Channel: d.Channel, LocalRole: d.PeerIdentity, PeerRole: "controller", Local: macoschannel.Peer{UID: d.PeerUID, GID: d.PeerGID}, Peer: macoschannel.Peer{UID: 701, GID: 702}, KeyEpoch: d.KeyEpoch, LocalRelease: descriptorRelease(d), PeerRelease: controller}
}

func serverContext(t *testing.T) (context.Context, context.CancelFunc, time.Time) {
	t.Helper()
	now := time.Now().UTC()
	ctx, cancel := context.WithDeadline(context.Background(), now.Add(15*time.Second))
	return ctx, cancel, now
}

func serverRequest(d Descriptor, now time.Time, id, operation, session string) request {
	q := request{SchemaVersion: ProtocolV1, Operation: operation, RequestID: id, ProfileID: d.ProfileID, ProfileRevision: d.ProfileRevision, MappingDigest: d.MappingDigest, RuntimeDigest: d.RuntimeDigest, ProtocolDigest: d.ProtocolDigest, Audience: d.Audience, SessionID: session, Nonce: id, Deadline: now.Add(10 * time.Second)}
	switch operation {
	case "start":
		q.SessionID = ""
		q.OrderID, q.OrderHash, q.BindingID, q.BindingHash, q.RunID, q.AttemptID = "order-1", "order-hash-1", "binding-1", "binding-hash-1", "run-1", "attempt-1"
		q.Task = mesh.TaskEnvelope{Objective: "test objective", InputArtifactRefs: []string{"artifact-1"}, RequestedRole: "worker", OutputSchemaRef: "result-v1"}
	case "send", "steer":
		q.InputRef = "input-1"
	case "cancel":
		q.CancelMode, q.RevisionRef, q.ReasonRef = mesh.CancellationUser, "revision-1", "reason-1"
	case "result", "collect":
		q.RevisionRef = "revision-1"
	}
	return q
}

func serverConnFor(t *testing.T, d Descriptor, controller macoschannel.ReleasePin, q request) *serverTestConn {
	t.Helper()
	raw, err := canonical(q)
	if err != nil {
		t.Fatal(err)
	}
	c := &serverTestConn{ev: serverEvidence(d, controller)}
	tag, err := c.Seal(frameBindingDomain, raw)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := canonical(sealedFrame{Payload: raw, Tag: tag})
	if err != nil {
		t.Fatal(err)
	}
	var framed bytes.Buffer
	if err = writeFrame(context.Background(), &framed, wire); err != nil {
		t.Fatal(err)
	}
	c.in = bytes.NewReader(framed.Bytes())
	return c
}

func serverResponse(t *testing.T, c *serverTestConn) response {
	t.Helper()
	raw, err := readFrame(context.Background(), bytes.NewReader(c.out.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	var envelope sealedFrame
	if err = decodeCanonical(raw, &envelope); err != nil {
		t.Fatal(err)
	}
	if err = c.Verify(frameBindingDomain, envelope.Payload, envelope.Tag); err != nil {
		t.Fatal(err)
	}
	var out response
	if err = decodeCanonical(envelope.Payload, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestServerRequiresRecoveryAndReplaysExactStart(t *testing.T) {
	s, driver, d, controller := serverFixture(t)
	ctx, cancel, now := serverContext(t)
	defer cancel()
	q := serverRequest(d, now, "request-1", "start", "")
	if err := s.ServeOnce(ctx, serverConnFor(t, d, controller, q)); !errors.Is(err, ErrReconcile) {
		t.Fatalf("unrecovered serve err=%v", err)
	}
	if driver.starts != 0 {
		t.Fatal("start dispatched before recovery")
	}
	if err := s.Recover(ctx); err != nil {
		t.Fatal(err)
	}
	c := serverConnFor(t, d, controller, q)
	if err := s.ServeOnce(ctx, c); err != nil {
		t.Fatal(err)
	}
	if got := serverResponse(t, c); got.SessionID != "runtime-session-1" || got.RunID != q.RunID || got.AttemptID != q.AttemptID {
		t.Fatalf("start response=%+v", got)
	}
	if err := s.ServeOnce(ctx, serverConnFor(t, d, controller, q)); err != nil {
		t.Fatalf("exact replay err=%v", err)
	}
	driver.mu.Lock()
	starts, gotStart := driver.starts, driver.lastStart
	driver.mu.Unlock()
	if starts != 1 || gotStart.RequestID != q.RequestID || gotStart.OrderHash != q.OrderHash || gotStart.Task.Objective != q.Task.Objective || len(gotStart.Task.InputArtifactRefs) != 1 || gotStart.Task.RequestedRole != q.Task.RequestedRole || gotStart.Task.OutputSchemaRef != q.Task.OutputSchemaRef {
		t.Fatalf("duplicate start dispatched: count=%d start=%+v", starts, gotStart)
	}
	changed := q
	changed.OrderHash = "different-hash"
	if err := s.ServeOnce(ctx, serverConnFor(t, d, controller, changed)); !errors.Is(err, ErrDenied) {
		t.Fatalf("same id changed digest err=%v", err)
	}
	changedID := q
	changedID.RequestID, changedID.Nonce = "request-2", "request-2"
	if err := s.ServeOnce(ctx, serverConnFor(t, d, controller, changedID)); !errors.Is(err, ErrDenied) {
		t.Fatalf("same binding changed request id err=%v", err)
	}
}

func TestServerRestartReliesOnDurableDriverStartIdentity(t *testing.T) {
	d := descriptorFixture(t, "codex", providerbridge.ProfileCodexChatGPT)
	controller := macoschannel.ReleasePin{ReleaseID: "controller-release-1", BinaryDigest: string(bytes.Repeat([]byte("a"), 64)), SocketDigest: string(bytes.Repeat([]byte("b"), 64)), ManifestDigest: string(bytes.Repeat([]byte("c"), 64))}
	driver := newDurableStartDriver()
	newServer := func(t *testing.T) *Server {
		t.Helper()
		server, err := NewServer(ServerConfig{Descriptor: d, Driver: driver, ControllerUID: 701, ControllerGID: 702, ControllerRelease: controller})
		if err != nil {
			t.Fatal(err)
		}
		return server
	}
	ctx, cancel, now := serverContext(t)
	defer cancel()
	q := serverRequest(d, now, "durable-request-1", "start", "")

	first := newServer(t)
	if err := first.Recover(ctx); err != nil {
		t.Fatal(err)
	}
	// Model an ACK that was written by the first daemon but lost by the caller:
	// the response bytes are deliberately never inspected.
	if err := first.ServeOnce(ctx, serverConnFor(t, d, controller, q)); err != nil {
		t.Fatal(err)
	}
	second := newServer(t)
	if err := second.Recover(ctx); err != nil {
		t.Fatal(err)
	}
	replayConn := serverConnFor(t, d, controller, q)
	if err := second.ServeOnce(ctx, replayConn); err != nil {
		t.Fatal(err)
	}
	if got := serverResponse(t, replayConn); got.SessionID != "durable-binding-1" {
		t.Fatalf("restart replay returned another session: %+v", got)
	}
	driver.durableMu.Lock()
	invocations, effects := driver.invocations, driver.nativeEffects
	start := driver.receipts[q.RequestID]
	driver.durableMu.Unlock()
	raw, err := canonical(q)
	if err != nil {
		t.Fatal(err)
	}
	if invocations != 2 || effects != 1 || start.RequestDigest != requestDigest(raw) || start.BindingID != q.BindingID {
		t.Fatalf("durable restart contract lost identity: invocations=%d effects=%d start=%+v", invocations, effects, start)
	}

	// A fresh in-memory Server has no replay map, so the durable driver is the
	// authoritative changed-binding guard after restart.
	third := newServer(t)
	if err := third.Recover(ctx); err != nil {
		t.Fatal(err)
	}
	changed := q
	changed.RequestID, changed.Nonce = "durable-request-2", "durable-request-2"
	if err := third.ServeOnce(ctx, serverConnFor(t, d, controller, changed)); !errors.Is(err, ErrReconcile) {
		t.Fatalf("changed binding identity after restart err=%v", err)
	}
	driver.durableMu.Lock()
	effects = driver.nativeEffects
	driver.durableMu.Unlock()
	if effects != 1 {
		t.Fatalf("changed binding identity duplicated native Start: %d", effects)
	}
}

func TestServerRecoverSessionHydratesControlWithoutAnotherStart(t *testing.T) {
	d := descriptorFixture(t, "codex", providerbridge.ProfileCodexChatGPT)
	controller := macoschannel.ReleasePin{ReleaseID: "controller-release-1", BinaryDigest: string(bytes.Repeat([]byte("a"), 64)), SocketDigest: string(bytes.Repeat([]byte("b"), 64)), ManifestDigest: string(bytes.Repeat([]byte("c"), 64))}
	driver := newDurableStartDriver()
	newServer := func(t *testing.T) *Server {
		t.Helper()
		s, err := NewServer(ServerConfig{Descriptor: d, Driver: driver, ControllerUID: 701, ControllerGID: 702, ControllerRelease: controller})
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	ctx, cancel, now := serverContext(t)
	defer cancel()
	start := serverRequest(d, now, "recover-start-1", "start", "")
	first := newServer(t)
	if err := first.Recover(ctx); err != nil {
		t.Fatal(err)
	}
	if err := first.ServeOnce(ctx, serverConnFor(t, d, controller, start)); err != nil {
		t.Fatal(err)
	}
	route := "ptv2-" + d.ProfileID + "-" + digestBytes([]byte(d.ProfileID+":"+start.BindingID+":"+start.BindingHash))
	fresh := newServer(t)
	if err := fresh.Recover(ctx); err != nil {
		t.Fatal(err)
	}
	recoverRequest := serverRequest(d, now, "recover-proof-1", "recover-session", route)
	recoverConn := serverConnFor(t, d, controller, recoverRequest)
	if err := fresh.ServeOnce(ctx, recoverConn); err != nil {
		t.Fatal(err)
	}
	proof := serverResponse(t, recoverConn).Recovery
	if proof == nil || proof.NativeSessionID == "" {
		t.Fatalf("missing recovery proof: %+v", proof)
	}
	driver.durableMu.Lock()
	invocations, effects := driver.invocations, driver.nativeEffects
	driver.durableMu.Unlock()
	status := serverRequest(d, now, "recover-status-1", "status", proof.NativeSessionID)
	if err := fresh.ServeOnce(ctx, serverConnFor(t, d, controller, status)); err != nil {
		t.Fatalf("recovered status failed: %v", err)
	}
	driver.durableMu.Lock()
	defer driver.durableMu.Unlock()
	if driver.invocations != invocations || driver.nativeEffects != effects || effects != 1 {
		t.Fatalf("recovery dispatched Start: invocations=%d/%d effects=%d/%d", driver.invocations, invocations, driver.nativeEffects, effects)
	}
}

func TestServerRecoverSessionRejectsRouteNativeCollisionAndCapacity(t *testing.T) {
	s, driver, d, controller := serverFixture(t)
	ctx, cancel, now := serverContext(t)
	defer cancel()
	if err := s.Recover(ctx); err != nil {
		t.Fatal(err)
	}
	proofFor := func(binding, native string) PersistedSessionProof {
		route := "ptv2-" + d.ProfileID + "-" + digestBytes([]byte(d.ProfileID+":"+binding+":"+"binding-hash-1"))
		return PersistedSessionProof{SchemaVersion: PersistedSessionProofV1, RouteRef: route, NativeSessionID: native, ProfileID: d.ProfileID, ProfileRevision: d.ProfileRevision, MappingDigest: d.MappingDigest, RuntimeDigest: d.RuntimeDigest, ProtocolDigest: d.ProtocolDigest, OrderID: "order-1", OrderHash: "order-hash-1", BindingID: binding, BindingHash: "binding-hash-1", RunID: "run-1", AttemptID: "attempt-1", RequestID: "request-1", RequestDigest: "sha256:" + strings.Repeat("a", 64), State: "running"}
	}
	first := proofFor("binding-1", "native-1")
	driver.mu.Lock()
	driver.sessionProof = first
	driver.mu.Unlock()
	if err := s.ServeOnce(ctx, serverConnFor(t, d, controller, serverRequest(d, now, "recover-collision-1", "recover-session", first.RouteRef))); err != nil {
		t.Fatal(err)
	}
	second := proofFor("binding-2", "native-1")
	driver.mu.Lock()
	driver.sessionProof = second
	driver.mu.Unlock()
	if err := s.ServeOnce(ctx, serverConnFor(t, d, controller, serverRequest(d, now, "recover-collision-2", "recover-session", second.RouteRef))); !errors.Is(err, ErrReconcile) {
		t.Fatalf("native collision accepted: %v", err)
	}
	s.mu.Lock()
	if len(s.sessions) != 1 || s.sessions["native-1"].routeRef != first.RouteRef {
		t.Fatalf("collision changed published map: %+v", s.sessions)
	}
	s.mu.Unlock()

	limited, limitedDriver, _, _ := serverFixture(t)
	limited.limit = 1
	if err := limited.Recover(ctx); err != nil {
		t.Fatal(err)
	}
	limitedDriver.mu.Lock()
	limitedDriver.sessionProof = first
	limitedDriver.mu.Unlock()
	if err := limited.ServeOnce(ctx, serverConnFor(t, d, controller, serverRequest(d, now, "recover-cap-1", "recover-session", first.RouteRef))); err != nil {
		t.Fatal(err)
	}
	third := proofFor("binding-3", "native-3")
	limitedDriver.mu.Lock()
	limitedDriver.sessionProof = third
	limitedDriver.mu.Unlock()
	if err := limited.ServeOnce(ctx, serverConnFor(t, d, controller, serverRequest(d, now, "recover-cap-2", "recover-session", third.RouteRef))); !errors.Is(err, ErrReconcile) {
		t.Fatalf("recovery capacity accepted: %v", err)
	}
}

func TestServerClosedCancellationAndTerminalStateMatrix(t *testing.T) {
	s, driver, d, controller := serverFixture(t)
	ctx, cancel, now := serverContext(t)
	defer cancel()
	if err := s.Recover(ctx); err != nil {
		t.Fatal(err)
	}
	start := serverRequest(d, now, "request-start", "start", "")
	if err := s.ServeOnce(ctx, serverConnFor(t, d, controller, start)); err != nil {
		t.Fatal(err)
	}
	cancelQ := serverRequest(d, now, "request-cancel", "cancel", "runtime-session-1")
	if err := s.ServeOnce(ctx, serverConnFor(t, d, controller, cancelQ)); err != nil {
		t.Fatal(err)
	}
	driver.mu.Lock()
	calls := append([]mesh.Cancellation(nil), driver.cancels...)
	driver.mu.Unlock()
	if len(calls) != 1 || calls[0].Mode != mesh.CancellationUser || calls[0].RevisionRef != "revision-1" || calls[0].ReasonRef != "reason-1" {
		t.Fatalf("cancel lost bindings: %+v", calls)
	}
	changedCancel := cancelQ
	changedCancel.ReasonRef = "reason-2"
	if err := s.ServeOnce(ctx, serverConnFor(t, d, controller, changedCancel)); !errors.Is(err, ErrDenied) {
		t.Fatalf("same request id with changed cancellation reason err=%v", err)
	}
	driver.mu.Lock()
	calls = append([]mesh.Cancellation(nil), driver.cancels...)
	driver.mu.Unlock()
	if len(calls) != 1 {
		t.Fatal("changed cancellation replay reached runtime")
	}
	if err := s.ServeOnce(ctx, serverConnFor(t, d, controller, serverRequest(d, now, "request-send", "send", "runtime-session-1"))); !errors.Is(err, ErrDenied) {
		t.Fatalf("terminal send err=%v", err)
	}
	driver.mu.Lock()
	sends := driver.sends
	driver.mu.Unlock()
	if sends != 0 {
		t.Fatal("terminal session reached runtime send")
	}
	// Terminal observations remain available even after a user cancellation.
	driver.mu.Lock()
	driver.result = RuntimeResult{Status: "cancelled", OutputArtifactRef: "artifact-1", SchemaRef: "schema-1", ProvenanceDigest: "sha256:" + string(bytes.Repeat([]byte("a"), 64)), Classification: "L1"}
	driver.mu.Unlock()
	result := serverRequest(d, now, "request-result", "result", "runtime-session-1")
	if err := s.ServeOnce(ctx, serverConnFor(t, d, controller, result)); err != nil {
		t.Fatalf("terminal observation err=%v", err)
	}

	// Internal compensation is a separate exact mode and is only admitted for
	// a nonterminal state. It cannot be forged as a reason-only user cancel.
	s.mu.Lock()
	s.sessions["starting-session"] = serverSession{runtime: RuntimeSession{ID: "starting-session"}, runID: "run-2", attempt: "attempt-2", state: "starting"}
	s.mu.Unlock()
	comp := serverRequest(d, now, "request-comp", "cancel", "starting-session")
	comp.CancelMode, comp.RevisionRef, comp.ReasonRef = mesh.CancellationStartCompensation, "", "start_commit_failed"
	if err := s.ServeOnce(ctx, serverConnFor(t, d, controller, comp)); err != nil {
		t.Fatalf("compensation err=%v", err)
	}
	bad := comp
	bad.RequestID, bad.Nonce, bad.ReasonRef = "request-comp-bad", "request-comp-bad", "arbitrary"
	if err := s.ServeOnce(ctx, serverConnFor(t, d, controller, bad)); !errors.Is(err, ErrDenied) {
		t.Fatalf("arbitrary compensation err=%v", err)
	}
}

func TestServerPoisonsOnEveryMutatingDriverSentinel(t *testing.T) {
	for _, operation := range []string{"send", "steer", "cancel"} {
		for _, cause := range []error{ErrDenied, ErrInvalid, ErrReconcile} {
			t.Run(operation+"/"+cause.Error(), func(t *testing.T) {
				s, driver, d, controller := serverFixture(t)
				ctx, cancel, now := serverContext(t)
				defer cancel()
				if err := s.Recover(ctx); err != nil {
					t.Fatal(err)
				}
				if err := s.ServeOnce(ctx, serverConnFor(t, d, controller, serverRequest(d, now, "sentinel-start", "start", ""))); err != nil {
					t.Fatal(err)
				}
				driver.mu.Lock()
				switch operation {
				case "send":
					driver.sendErr = cause
				case "steer":
					driver.steerErr = cause
				default:
					driver.cancelErr = cause
				}
				driver.mu.Unlock()
				mutation := serverRequest(d, now, "sentinel-"+operation, operation, "runtime-session-1")
				if err := s.ServeOnce(ctx, serverConnFor(t, d, controller, mutation)); !errors.Is(err, ErrReconcile) {
					t.Fatalf("driver sentinel escaped uncertainty gate: %v", err)
				}
				driver.mu.Lock()
				calls := driver.sends + driver.steers + len(driver.cancels)
				driver.mu.Unlock()
				if calls != 1 {
					t.Fatalf("mutation was not invoked exactly once: %d", calls)
				}
				blocked := serverRequest(d, now, "sentinel-blocked", "status", "runtime-session-1")
				if err := s.ServeOnce(ctx, serverConnFor(t, d, controller, blocked)); !errors.Is(err, ErrReconcile) {
					t.Fatalf("poisoned server admitted next request: %v", err)
				}
				if err := s.Recover(ctx); err != nil {
					t.Fatalf("explicit recovery did not reopen gate: %v", err)
				}
				if err := s.ServeOnce(ctx, serverConnFor(t, d, controller, serverRequest(d, now, "sentinel-recovered", "status", "runtime-session-1"))); err != nil {
					t.Fatalf("recovered server remained closed: %v", err)
				}
			})
		}
	}
}

func TestServerSerializesPerSessionInputAndCancellation(t *testing.T) {
	startServer := func(t *testing.T) (*Server, *runtimeDriverFake, Descriptor, macoschannel.ReleasePin, context.Context, context.CancelFunc, time.Time) {
		t.Helper()
		s, driver, d, controller := serverFixture(t)
		ctx, cancel, now := serverContext(t)
		if err := s.Recover(ctx); err != nil {
			cancel()
			t.Fatal(err)
		}
		if err := s.ServeOnce(ctx, serverConnFor(t, d, controller, serverRequest(d, now, "gate-start", "start", ""))); err != nil {
			cancel()
			t.Fatal(err)
		}
		return s, driver, d, controller, ctx, cancel, now
	}
	waitEntered := func(t *testing.T, entered <-chan struct{}) {
		t.Helper()
		select {
		case <-entered:
		case <-time.After(2 * time.Second):
			t.Fatal("driver operation did not enter")
		}
	}

	t.Run("input first", func(t *testing.T) {
		s, driver, d, controller, ctx, cancel, now := startServer(t)
		defer cancel()
		driver.mu.Lock()
		driver.sendEntered, driver.sendRelease = make(chan struct{}), make(chan struct{})
		entered, release := driver.sendEntered, driver.sendRelease
		driver.mu.Unlock()
		sendDone := make(chan error, 1)
		cancelDone := make(chan error, 1)
		go func() {
			sendDone <- s.ServeOnce(ctx, serverConnFor(t, d, controller, serverRequest(d, now, "gate-send", "send", "runtime-session-1")))
		}()
		waitEntered(t, entered)
		go func() {
			cancelDone <- s.ServeOnce(ctx, serverConnFor(t, d, controller, serverRequest(d, now, "gate-cancel", "cancel", "runtime-session-1")))
		}()
		time.Sleep(20 * time.Millisecond)
		driver.mu.Lock()
		cancelCalls := len(driver.cancels)
		driver.mu.Unlock()
		if cancelCalls != 0 {
			t.Fatal("Cancel overtook an in-flight Send")
		}
		close(release)
		if err := <-sendDone; err != nil {
			t.Fatalf("ordered Send failed: %v", err)
		}
		if err := <-cancelDone; err != nil {
			t.Fatalf("ordered Cancel failed: %v", err)
		}
	})

	t.Run("cancel first", func(t *testing.T) {
		s, driver, d, controller, ctx, cancel, now := startServer(t)
		defer cancel()
		driver.mu.Lock()
		driver.cancelEntered, driver.cancelRelease = make(chan struct{}), make(chan struct{})
		entered, release := driver.cancelEntered, driver.cancelRelease
		driver.mu.Unlock()
		cancelDone := make(chan error, 1)
		sendDone := make(chan error, 1)
		go func() {
			cancelDone <- s.ServeOnce(ctx, serverConnFor(t, d, controller, serverRequest(d, now, "gate-cancel", "cancel", "runtime-session-1")))
		}()
		waitEntered(t, entered)
		go func() {
			sendDone <- s.ServeOnce(ctx, serverConnFor(t, d, controller, serverRequest(d, now, "gate-send", "send", "runtime-session-1")))
		}()
		time.Sleep(20 * time.Millisecond)
		driver.mu.Lock()
		sends := driver.sends
		driver.mu.Unlock()
		if sends != 0 {
			t.Fatal("Send overtook an in-flight Cancel")
		}
		close(release)
		if err := <-cancelDone; err != nil {
			t.Fatalf("ordered Cancel failed: %v", err)
		}
		if err := <-sendDone; !errors.Is(err, ErrDenied) {
			t.Fatalf("post-cancel Send was not denied: %v", err)
		}
		driver.mu.Lock()
		sends = driver.sends
		driver.mu.Unlock()
		if sends != 0 {
			t.Fatal("post-cancel Send reached driver")
		}
	})
}

func TestServerResponseFailureAfterMutationPoisonsUntilRecovery(t *testing.T) {
	for _, operation := range []string{"start", "send", "steer", "cancel"} {
		for _, failure := range []string{"seal", "write"} {
			t.Run(operation+"/"+failure, func(t *testing.T) {
				s, driver, d, controller := serverFixture(t)
				ctx, cancel, now := serverContext(t)
				defer cancel()
				if err := s.Recover(ctx); err != nil {
					t.Fatal(err)
				}
				if operation != "start" {
					if err := s.ServeOnce(ctx, serverConnFor(t, d, controller, serverRequest(d, now, "response-start", "start", ""))); err != nil {
						t.Fatal(err)
					}
				}
				session := "runtime-session-1"
				if operation == "start" {
					session = ""
				}
				q := serverRequest(d, now, "response-"+operation, operation, session)
				conn := serverConnFor(t, d, controller, q)
				if failure == "seal" {
					conn.sealErr = errors.New("response seal failed")
				} else {
					conn.writeErr = errors.New("response write failed")
				}
				if err := s.ServeOnce(ctx, conn); !errors.Is(err, ErrReconcile) {
					t.Fatalf("post-effect %s failure was not uncertain: %v", failure, err)
				}
				driver.mu.Lock()
				starts, controls := driver.starts, driver.sends+driver.steers+len(driver.cancels)
				driver.mu.Unlock()
				wantStarts, wantControls := 1, 1
				if operation == "start" {
					wantControls = 0
				}
				if starts != wantStarts || controls != wantControls {
					t.Fatalf("mutation count starts=%d controls=%d", starts, controls)
				}
				if err := s.ServeOnce(ctx, serverConnFor(t, d, controller, serverRequest(d, now, "response-blocked", "status", "runtime-session-1"))); !errors.Is(err, ErrReconcile) {
					t.Fatalf("post-effect response failure left server open: %v", err)
				}
				if err := s.Recover(ctx); err != nil {
					t.Fatal(err)
				}
				// The successful response was retained before the failed write; an
				// exact replay after explicit recovery returns it without another
				// native effect.
				if err := s.ServeOnce(ctx, serverConnFor(t, d, controller, q)); err != nil {
					t.Fatalf("exact recovered replay failed: %v", err)
				}
				driver.mu.Lock()
				gotStarts, gotControls := driver.starts, driver.sends+driver.steers+len(driver.cancels)
				driver.mu.Unlock()
				if gotStarts != starts || gotControls != controls {
					t.Fatalf("recovered replay duplicated effect: starts=%d/%d controls=%d/%d", starts, gotStarts, controls, gotControls)
				}
			})
		}
	}
}

func TestServerLostStartResponseReplaysExactACKWhilePoisoned(t *testing.T) {
	s, driver, d, controller := serverFixture(t)
	ctx, cancel, now := serverContext(t)
	defer cancel()
	if err := s.Recover(ctx); err != nil {
		t.Fatal(err)
	}
	q := serverRequest(d, now, "lost-start-ack", "start", "")
	lost := serverConnFor(t, d, controller, q)
	lost.writeErr = errors.New("connection lost after Start")
	if err := s.ServeOnce(ctx, lost); !errors.Is(err, ErrReconcile) {
		t.Fatalf("lost start response=%v", err)
	}
	driver.mu.Lock()
	starts := driver.starts
	driver.mu.Unlock()
	if starts != 1 {
		t.Fatalf("lost ACK duplicated Start before retry: %d", starts)
	}

	retry := serverConnFor(t, d, controller, q)
	if err := s.ServeOnce(ctx, retry); err != nil {
		t.Fatalf("exact retry was denied while poisoned: %v", err)
	}
	if got := serverResponse(t, retry); got.SessionID != "runtime-session-1" || got.RequestID != q.RequestID {
		t.Fatalf("exact retry response=%+v", got)
	}
	driver.mu.Lock()
	starts = driver.starts
	driver.mu.Unlock()
	if starts != 1 {
		t.Fatalf("exact retry dispatched another Start: %d", starts)
	}

	changed := q
	changed.OrderHash = "different-order-hash"
	if err := s.ServeOnce(ctx, serverConnFor(t, d, controller, changed)); !errors.Is(err, ErrDenied) {
		t.Fatalf("changed same-ID request was not denied: %v", err)
	}
	newID := q
	newID.RequestID, newID.Nonce = "lost-start-ack-new", "lost-start-ack-new"
	if err := s.ServeOnce(ctx, serverConnFor(t, d, controller, newID)); !errors.Is(err, ErrReconcile) {
		t.Fatalf("new request was admitted while poisoned: %v", err)
	}
}

func TestServerRefusesStartBeforeNativeEffectWhenIdentityTableIsFull(t *testing.T) {
	s, driver, d, controller := serverFixture(t)
	ctx, cancel, now := serverContext(t)
	defer cancel()
	if err := s.Recover(ctx); err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	for i := 0; i < maxServerSessions; i++ {
		id := fmt.Sprintf("full-binding-%03d", i)
		s.startBindings[id] = serverStartIdentity{requestID: fmt.Sprintf("full-request-%03d", i), digest: "sha256:" + strings.Repeat("a", 64)}
	}
	s.mu.Unlock()
	q := serverRequest(d, now, "bounded-start-request", "start", "")
	if err := s.ServeOnce(ctx, serverConnFor(t, d, controller, q)); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("full identity table admitted Start: %v", err)
	}
	driver.mu.Lock()
	starts := driver.starts
	driver.mu.Unlock()
	if starts != 0 {
		t.Fatalf("full identity table reached RuntimeDriver.Start: %d", starts)
	}
}

func TestServerReclaimsOnlyTerminalSessionAfterRecoveryWindow(t *testing.T) {
	s, driver, d, controller := serverFixture(t)
	clock := time.Now().UTC().Truncate(time.Second)
	ctx, cancel := context.WithDeadline(context.Background(), clock.Add(sessionRecoveryWindow+30*time.Second))
	defer cancel()
	s.now = func() time.Time { return clock }
	s.limit = 1
	if err := s.Recover(ctx); err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	s.sessions["retired-session"] = serverSession{runtime: RuntimeSession{ID: "retired-session"}, runID: "retired-run", attempt: "retired-attempt", state: "completed", terminalAt: clock, gate: &sync.Mutex{}}
	s.startBindings["retired-binding"] = serverStartIdentity{requestID: "retired-request", digest: "sha256:" + strings.Repeat("a", 64), sessionID: "retired-session"}
	s.mu.Unlock()

	blocked := serverRequest(d, clock, "before-window", "start", "")
	if err := s.ServeOnce(ctx, serverConnFor(t, d, controller, blocked)); err == nil {
		t.Fatal("terminal state was reclaimed before recovery window")
	}
	driver.mu.Lock()
	beforeStarts := driver.starts
	driver.mu.Unlock()
	if beforeStarts != 0 {
		t.Fatalf("full terminal table reached Start before recovery window: %d", beforeStarts)
	}
	clock = clock.Add(sessionRecoveryWindow + time.Second)
	allowed := serverRequest(d, clock, "after-window", "start", "")
	if err := s.ServeOnce(ctx, serverConnFor(t, d, controller, allowed)); err != nil {
		t.Fatalf("terminal session was not reclaimed after recovery window: %v", err)
	}
	driver.mu.Lock()
	starts := driver.starts
	driver.mu.Unlock()
	if starts != 1 {
		t.Fatalf("reclaimed slot did not admit exactly one new Start: %d", starts)
	}
	s.mu.Lock()
	_, retainedSession := s.sessions["retired-session"]
	_, retainedBinding := s.startBindings["retired-binding"]
	s.mu.Unlock()
	if retainedSession || retainedBinding {
		t.Fatal("terminal session identity survived its recovery window")
	}
}

func TestServerRecoveryClearsOnlyUnboundFailedStartReservations(t *testing.T) {
	s, driver, d, controller := serverFixture(t)
	ctx, cancel, now := serverContext(t)
	defer cancel()
	s.limit = 1
	driver.mu.Lock()
	driver.startErr = errors.New("runtime start failed before session")
	driver.mu.Unlock()
	if err := s.Recover(ctx); err != nil {
		t.Fatal(err)
	}
	failed := serverRequest(d, now, "failed-start", "start", "")
	if err := s.ServeOnce(ctx, serverConnFor(t, d, controller, failed)); !errors.Is(err, ErrReconcile) {
		t.Fatalf("failed Start did not fail-close: %v", err)
	}
	s.mu.Lock()
	identity, retained := s.startBindings[failed.BindingID]
	s.mu.Unlock()
	if !retained || identity.sessionID != "" {
		t.Fatalf("failed Start did not leave expected unbound reservation: %+v", identity)
	}
	driver.mu.Lock()
	driver.startErr = nil
	driver.mu.Unlock()
	if err := s.Recover(ctx); err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	_, retained = s.startBindings[failed.BindingID]
	s.mu.Unlock()
	if retained {
		t.Fatal("successful recovery retained unbound failed Start reservation")
	}
	next := serverRequest(d, now, "recovered-distinct-start", "start", "")
	next.OrderID, next.OrderHash, next.BindingID, next.BindingHash, next.RunID, next.AttemptID = "order-2", "order-hash-2", "binding-2", "binding-hash-2", "run-2", "attempt-2"
	if err := s.ServeOnce(ctx, serverConnFor(t, d, controller, next)); err != nil {
		t.Fatalf("recovery left unbound reservation at capacity: %v", err)
	}
	driver.mu.Lock()
	starts := driver.starts
	driver.mu.Unlock()
	if starts != 2 {
		t.Fatalf("recovery did not admit only the distinct post-failure Start: %d", starts)
	}
}

func TestServerRecoveryExcludesActiveAndNewEffects(t *testing.T) {
	s, driver, d, controller := serverFixture(t)
	ctx, cancel, now := serverContext(t)
	defer cancel()
	if err := s.Recover(ctx); err != nil {
		t.Fatal(err)
	}
	if err := s.ServeOnce(ctx, serverConnFor(t, d, controller, serverRequest(d, now, "lifecycle-start", "start", ""))); err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	s.sessions["runtime-session-2"] = serverSession{runtime: RuntimeSession{ID: "runtime-session-2"}, runID: "run-2", attempt: "attempt-2", state: "running", gate: &sync.Mutex{}}
	s.mu.Unlock()
	driver.mu.Lock()
	driver.sendErr = ErrDenied
	driver.sendEntered, driver.sendRelease = make(chan struct{}), make(chan struct{})
	sendEntered, sendRelease := driver.sendEntered, driver.sendRelease
	driver.recoverEntered, driver.recoverRelease = make(chan struct{}), make(chan struct{})
	recoverEntered, recoverRelease := driver.recoverEntered, driver.recoverRelease
	driver.mu.Unlock()
	firstDone := make(chan error, 1)
	go func() {
		firstDone <- s.ServeOnce(ctx, serverConnFor(t, d, controller, serverRequest(d, now, "lifecycle-send-1", "send", "runtime-session-1")))
	}()
	select {
	case <-sendEntered:
	case <-time.After(2 * time.Second):
		t.Fatal("first mutation did not enter driver")
	}
	recoverDone := make(chan error, 1)
	recoverLaunched := make(chan struct{})
	go func() {
		close(recoverLaunched)
		recoverDone <- s.Recover(ctx)
	}()
	<-recoverLaunched
	time.Sleep(20 * time.Millisecond) // allow the exclusive writer to queue
	select {
	case <-recoverEntered:
		t.Fatal("driver recovery overtook an active mutation")
	default:
	}
	secondDone := make(chan error, 1)
	go func() {
		secondDone <- s.ServeOnce(ctx, serverConnFor(t, d, controller, serverRequest(d, now, "lifecycle-send-2", "send", "runtime-session-2")))
	}()
	time.Sleep(20 * time.Millisecond)
	driver.mu.Lock()
	sends := driver.sends
	driver.mu.Unlock()
	if sends != 1 {
		t.Fatalf("new mutation crossed queued recovery: sends=%d", sends)
	}
	close(sendRelease)
	if err := <-firstDone; !errors.Is(err, ErrReconcile) {
		t.Fatalf("errored mutation was not uncertain: %v", err)
	}
	select {
	case <-recoverEntered:
	case <-time.After(2 * time.Second):
		t.Fatal("exclusive recovery did not start after active mutation drained")
	}
	driver.mu.Lock()
	driver.sendErr = nil
	driver.mu.Unlock()
	select {
	case err := <-secondDone:
		t.Fatalf("new mutation completed during driver recovery: %v", err)
	default:
	}
	close(recoverRelease)
	if err := <-recoverDone; err != nil {
		t.Fatalf("exclusive recovery failed: %v", err)
	}
	if err := <-secondDone; err != nil {
		t.Fatalf("new mutation did not resume after recovery: %v", err)
	}
}

func TestServerStateObservationsNeverReopenOrReplaceTerminal(t *testing.T) {
	startServer := func(t *testing.T) (*Server, *runtimeDriverFake, Descriptor, macoschannel.ReleasePin, context.Context, context.CancelFunc, time.Time) {
		t.Helper()
		s, driver, d, controller := serverFixture(t)
		ctx, cancel, now := serverContext(t)
		if err := s.Recover(ctx); err != nil {
			cancel()
			t.Fatal(err)
		}
		if err := s.ServeOnce(ctx, serverConnFor(t, d, controller, serverRequest(d, now, "start-state", "start", ""))); err != nil {
			cancel()
			t.Fatal(err)
		}
		return s, driver, d, controller, ctx, cancel, now
	}
	t.Run("terminal status cannot reopen", func(t *testing.T) {
		s, driver, d, controller, ctx, cancel, now := startServer(t)
		defer cancel()
		driver.mu.Lock()
		driver.status = RuntimeStatus{State: "completed", UsageSource: "attested"}
		driver.mu.Unlock()
		if err := s.ServeOnce(ctx, serverConnFor(t, d, controller, serverRequest(d, now, "status-completed", "status", "runtime-session-1"))); err != nil {
			t.Fatal(err)
		}
		driver.mu.Lock()
		driver.status = RuntimeStatus{State: "running", UsageSource: "provider"}
		driver.mu.Unlock()
		if err := s.ServeOnce(ctx, serverConnFor(t, d, controller, serverRequest(d, now, "status-stale-running", "status", "runtime-session-1"))); !errors.Is(err, ErrReconcile) {
			t.Fatalf("stale running status err=%v", err)
		}
		if err := s.ServeOnce(ctx, serverConnFor(t, d, controller, serverRequest(d, now, "send-after-terminal", "send", "runtime-session-1"))); !errors.Is(err, ErrReconcile) {
			t.Fatalf("terminal send was not denied: %v", err)
		}
		driver.mu.Lock()
		sends := driver.sends
		driver.mu.Unlock()
		if sends != 0 {
			t.Fatal("terminal session reached runtime send")
		}
	})
	t.Run("conflicting terminal result preserves cancellation", func(t *testing.T) {
		s, driver, d, controller, ctx, cancel, now := startServer(t)
		defer cancel()
		cancelQ := serverRequest(d, now, "cancel-state", "cancel", "runtime-session-1")
		if err := s.ServeOnce(ctx, serverConnFor(t, d, controller, cancelQ)); err != nil {
			t.Fatal(err)
		}
		driver.mu.Lock()
		driver.result = RuntimeResult{Status: "completed", OutputArtifactRef: "artifact-1", SchemaRef: "schema-1", ProvenanceDigest: "sha256:" + string(bytes.Repeat([]byte("a"), 64)), Classification: "L1"}
		driver.mu.Unlock()
		if err := s.ServeOnce(ctx, serverConnFor(t, d, controller, serverRequest(d, now, "conflicting-result", "result", "runtime-session-1"))); !errors.Is(err, ErrReconcile) {
			t.Fatalf("conflicting result err=%v", err)
		}
		s.mu.Lock()
		state := s.sessions["runtime-session-1"].state
		s.mu.Unlock()
		if state != "cancelled" {
			t.Fatalf("terminal state overwritten: %q", state)
		}
	})
	t.Run("post-start regression requires reconciliation", func(t *testing.T) {
		s, driver, d, controller, ctx, cancel, now := startServer(t)
		defer cancel()
		driver.mu.Lock()
		driver.status = RuntimeStatus{State: "starting", UsageSource: "provider"}
		driver.mu.Unlock()
		if err := s.ServeOnce(ctx, serverConnFor(t, d, controller, serverRequest(d, now, "status-regression", "status", "runtime-session-1"))); !errors.Is(err, ErrReconcile) {
			t.Fatalf("post-start regression err=%v", err)
		}
	})
}

func TestServerRecoveryProofAndNativeErrorFailClosed(t *testing.T) {
	s, driver, d, controller := serverFixture(t)
	ctx, cancel, now := serverContext(t)
	defer cancel()
	driver.mu.Lock()
	driver.proof.RequestIDRetention = false
	driver.mu.Unlock()
	if err := s.Recover(ctx); !errors.Is(err, ErrReconcile) {
		t.Fatalf("missing receipt proof err=%v", err)
	}
	driver.mu.Lock()
	driver.proof.RequestIDRetention = true
	driver.proof.BindingDigestRetention = false
	driver.mu.Unlock()
	if err := s.Recover(ctx); !errors.Is(err, ErrReconcile) {
		t.Fatalf("missing binding identity proof err=%v", err)
	}
	driver.mu.Lock()
	driver.proof.BindingDigestRetention = true
	driver.startErr = errors.New("native timeout")
	driver.mu.Unlock()
	if err := s.Recover(ctx); err != nil {
		t.Fatal(err)
	}
	q := serverRequest(d, now, "request-fails", "start", "")
	if err := s.ServeOnce(ctx, serverConnFor(t, d, controller, q)); !errors.Is(err, ErrReconcile) {
		t.Fatalf("native error err=%v", err)
	}
	if err := s.ServeOnce(ctx, serverConnFor(t, d, controller, serverRequest(d, now, "request-next", "start", ""))); !errors.Is(err, ErrReconcile) {
		t.Fatalf("poisoned server accepted request: %v", err)
	}
}

func TestServerConcurrentDuplicateStartDispatchesOnce(t *testing.T) {
	s, driver, d, controller := serverFixture(t)
	ctx, cancel, now := serverContext(t)
	defer cancel()
	if err := s.Recover(ctx); err != nil {
		t.Fatal(err)
	}
	driver.startEntered = make(chan struct{})
	driver.startRelease = make(chan struct{})
	q := serverRequest(d, now, "request-concurrent", "start", "")
	first := serverConnFor(t, d, controller, q)
	second := serverConnFor(t, d, controller, q)
	firstDone := make(chan error, 1)
	secondDone := make(chan error, 1)
	go func() { firstDone <- s.ServeOnce(ctx, first) }()
	select {
	case <-driver.startEntered:
	case <-time.After(2 * time.Second):
		t.Fatal("first request did not reach runtime")
	}
	go func() { secondDone <- s.ServeOnce(ctx, second) }()
	time.Sleep(20 * time.Millisecond)
	driver.mu.Lock()
	starts := driver.starts
	driver.mu.Unlock()
	if starts != 1 {
		t.Fatalf("duplicate request dispatched %d starts", starts)
	}
	close(driver.startRelease)
	for _, done := range []<-chan error{firstDone, secondDone} {
		select {
		case err := <-done:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("duplicate request did not complete")
		}
	}
	if serverResponse(t, first).SessionID != "runtime-session-1" || serverResponse(t, second).SessionID != "runtime-session-1" {
		t.Fatal("duplicate requests did not receive identical start response")
	}
}

func TestServerRejectsUntrustedEvidenceAndMalformedWireBeforeDriver(t *testing.T) {
	s, driver, d, controller := serverFixture(t)
	ctx, cancel, now := serverContext(t)
	defer cancel()
	if err := s.Recover(ctx); err != nil {
		t.Fatal(err)
	}
	q := serverRequest(d, now, "request-wire", "start", "")
	badEvidence := serverConnFor(t, d, controller, q)
	badEvidence.ev.Peer.GID++
	if err := s.ServeOnce(ctx, badEvidence); !errors.Is(err, ErrDenied) {
		t.Fatalf("foreign controller evidence err=%v", err)
	}
	// Canonical authenticated JSON with an unknown field is still rejected by
	// the closed decoder before any driver method can be reached.
	c := &serverTestConn{ev: serverEvidence(d, controller)}
	raw := []byte(`{"schema_version":"` + ProtocolV1 + `","operation":"start","unknown":true}`)
	tag, _ := c.Seal(frameBindingDomain, raw)
	wire, _ := canonical(sealedFrame{Payload: raw, Tag: tag})
	var framed bytes.Buffer
	if err := writeFrame(context.Background(), &framed, wire); err != nil {
		t.Fatal(err)
	}
	c.in = bytes.NewReader(framed.Bytes())
	if err := s.ServeOnce(ctx, c); !errors.Is(err, ErrDenied) {
		t.Fatalf("unknown field wire err=%v", err)
	}
	driver.mu.Lock()
	starts := driver.starts
	driver.mu.Unlock()
	if starts != 0 {
		t.Fatal("malformed or untrusted input reached native driver")
	}
	partial := serverConnFor(t, d, controller, q)
	partial.in = bytes.NewReader([]byte{0, 0, 0})
	if err := s.ServeOnce(ctx, partial); !errors.Is(err, ErrDenied) {
		t.Fatalf("partial frame err=%v", err)
	}
}
