package providertransport

// This file is the provider-side half of the descriptor-bound RPC seam.  It
// deliberately stops at a RuntimeDriver interface: a release-specific daemon
// must inject an attested official-runtime driver, rather than accepting a
// command line, environment, URL, or credential through this package.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"sync"
	"time"

	"openduck/internal/macoschannel"
	"openduck/internal/mesh"
)

const (
	frameBindingDomain = "providertransport.frame.v1"
	maxServerDeadline  = 30 * time.Second
	defaultReplayLimit = 256
	maxServerSessions  = 256
	// sessionRecoveryWindow bounds only volatile local routing state.  The
	// RuntimeDriver contract retains Start identity durably for longer; after a
	// local entry is retired a late request must recover through that driver,
	// never create a fresh native session from Controller memory.
	sessionRecoveryWindow = 15 * time.Minute
)

// RuntimeDriver is the only provider-specific boundary.  All values are
// Controller-generated opaque references or bounded result metadata; model
// payloads, credentials, command lines, environment, URLs and account state
// are not representable.  Recover must reconcile or quiesce any work left by a
// previous daemon instance before the server admits its first RPC.
type RuntimeDriver interface {
	// Recover must verify durable request-ID retention and reconcile or quiesce
	// every potentially in-flight native session. Returning a nil error without
	// this proof never opens the RPC gate after a daemon restart.
	Recover(context.Context) (RecoveryProof, error)
	// Start is durably idempotent by the exact
	// RequestID+RequestDigest+BindingID tuple. A production driver keeps both
	// the receipt and the one-to-one binding mapping across daemon restart for
	// at least the Controller retry/recovery window. Reusing a request ID with
	// changed input, or a binding ID with another request ID/digest, must fail
	// without starting native work. The Server's replay maps are only a bounded
	// same-process optimization and are not recovery evidence.
	Start(context.Context, RuntimeStart) (RuntimeSession, error)
	Send(context.Context, RuntimeSession, string) error
	Steer(context.Context, RuntimeSession, string) error
	Cancel(context.Context, RuntimeSession, mesh.Cancellation) error
	Status(context.Context, RuntimeSession) (RuntimeStatus, error)
	Wait(context.Context, RuntimeSession, time.Time) (RuntimeStatus, error)
	Result(context.Context, RuntimeSession, string) (RuntimeResult, error)
}

// PersistedSessionRecoveryDriver is deliberately separate from RuntimeDriver:
// recovery is a proof-only operation and must never be implemented by calling
// Start or by manufacturing a native handle. Drivers which do not expose this
// durable evidence keep controller recovery unavailable.
type PersistedSessionRecoveryDriver interface {
	RecoverSession(context.Context, string) (PersistedSessionProof, error)
}

const RecoveryProofV1 = "openduck-provider-runtime-recovery-proof.v1"

// RecoveryProof is an explicit driver assertion over its durable receipt,
// binding-digest retention and native-session recovery procedure. It is not
// provider evidence or readiness evidence; a missing/false field is a hard
// recovery denial.
type RecoveryProof struct {
	SchemaVersion, ReceiptStoreRevision                            string
	RequestIDRetention, BindingDigestRetention, InflightReconciled bool
}

func (p RecoveryProof) Validate() error {
	if p.SchemaVersion != RecoveryProofV1 || !id(p.ReceiptStoreRevision) || !p.RequestIDRetention || !p.BindingDigestRetention || !p.InflightReconciled {
		return ErrReconcile
	}
	return nil
}

// RuntimeStart binds a provider invocation to the Controller's already sealed
// order and endpoint binding. RequestDigest covers the canonical authenticated
// RPC request and is the driver's durable changed-input guard. The structure
// contains no prompt or capability material.
type RuntimeStart struct {
	RequestID, RequestDigest, ProfileID, ProfileRevision, MappingDigest, RuntimeDigest, ProtocolDigest string
	OrderID, OrderHash, BindingID, BindingHash, RunID, AttemptID                                       string
	Deadline                                                                                           time.Time
	Task                                                                                               mesh.TaskEnvelope
}

// RuntimeSession is a driver-owned opaque session identity.  It must be a
// bounded identifier; server state never derives it from native runtime text.
type RuntimeSession struct{ ID string }

// RuntimeStatus and RuntimeResult deliberately mirror the closed Controller
// contracts instead of exposing provider-native messages or usage records.
type RuntimeStatus struct{ State, UsageSource string }
type RuntimeResult struct {
	Status, OutputArtifactRef, SchemaRef, ProvenanceDigest, Classification string
}

// ServerConfig has no path, binary, account, credential, or listener fields.
// The privileged composition separately creates a macoschannel.Listener from
// already-open verified roots, then hands each accepted authenticated channel
// to ServeOnce.
type ServerConfig struct {
	Descriptor                   Descriptor
	Driver                       RuntimeDriver
	ControllerUID, ControllerGID uint32
	ControllerRelease            macoschannel.ReleasePin
	Now                          func() time.Time
	ReplayLimit                  int
}

// ServerConn is satisfied by macoschannel.Conn.  It intentionally does not
// expose a constructor, so callers still need the macOS channel authentication
// boundary to obtain a real connection.
type ServerConn interface {
	io.Reader
	io.Writer
	SetDeadline(time.Time) error
	Close() error
	Evidence() macoschannel.Evidence
	Seal(string, []byte) (string, error)
	Verify(string, []byte, string) error
}

// Server is a single-profile RPC endpoint.  It cannot serve after construction
// until Recover succeeds.  Any native driver error after dispatch poisons the
// endpoint and requires another explicit Recover, rather than guessing whether
// an external operation completed.
type Server struct {
	descriptor Descriptor
	driver     RuntimeDriver
	controller macoschannel.ReleasePin
	uid, gid   uint32
	now        func() time.Time
	limit      int
	lifecycle  sync.RWMutex

	mu            sync.Mutex
	recovered     bool
	poisoned      bool
	replays       map[string]serverReplay
	order         []string
	inflight      map[string]serverInflight
	startBindings map[string]serverStartIdentity
	sessions      map[string]serverSession
}

type serverReplay struct {
	digest string
	value  response
}
type serverInflight struct {
	digest string
	done   chan struct{}
}
type serverStartIdentity struct{ requestID, digest, sessionID string }
type serverSession struct {
	runtime    RuntimeSession
	routeRef   string
	runID      string
	attempt    string
	state      string
	terminalAt time.Time
	gate       *sync.Mutex
}

// nativeDispatchError marks an error observed only after a mutating driver
// method was invoked. Its cause may itself be ErrDenied/ErrInvalid/ErrReconcile,
// but those sentinels are no longer evidence that no provider effect happened.
type nativeDispatchError struct{ cause error }

func (e *nativeDispatchError) Error() string { return "provider runtime mutation outcome uncertain" }
func (e *nativeDispatchError) Unwrap() error { return e.cause }

func NewServer(c ServerConfig) (*Server, error) {
	if c.Descriptor.Validate() != nil || c.Driver == nil || c.ControllerUID == 0 || c.ControllerGID == 0 || !validRelease(c.ControllerRelease) {
		return nil, ErrInvalid
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	if c.ReplayLimit == 0 {
		c.ReplayLimit = defaultReplayLimit
	}
	if c.ReplayLimit < 1 || c.ReplayLimit > maxServerSessions {
		return nil, ErrInvalid
	}
	return &Server{descriptor: c.Descriptor, driver: c.Driver, controller: c.ControllerRelease, uid: c.ControllerUID, gid: c.ControllerGID, now: c.Now, limit: c.ReplayLimit, replays: map[string]serverReplay{}, inflight: map[string]serverInflight{}, startBindings: map[string]serverStartIdentity{}, sessions: map[string]serverSession{}}, nil
}

// Recover is an explicit boot gate.  A production driver uses it to reconcile
// its durable session/receipt state or terminate ambiguous native work.  The
// generic server never treats an empty in-memory map as proof that a restart is
// safe.
func (s *Server) Recover(ctx context.Context) error {
	if s == nil || ctx == nil || ctx.Err() != nil {
		return ErrInvalid
	}
	s.lifecycle.Lock()
	defer s.lifecycle.Unlock()
	s.mu.Lock()
	s.recovered = false
	s.poisoned = true
	s.mu.Unlock()
	proof, err := s.driver.Recover(ctx)
	if err != nil || proof.Validate() != nil {
		return ErrReconcile
	}
	s.mu.Lock()
	// A failed or structurally invalid Start may have reserved the local binding
	// before RuntimeDriver.Start returned, but it never produced a session that
	// this Server can route.  Recover holds the lifecycle writer lock and the
	// proof requires native inflight reconciliation, so only now is it safe to
	// discard those no-success local reservations.  Successful identities stay
	// until their terminal recovery window; the driver remains authoritative
	// across every restart for both same and changed requests.
	for bindingID, identity := range s.startBindings {
		if identity.sessionID == "" {
			delete(s.startBindings, bindingID)
		}
	}
	s.recovered, s.poisoned = true, false
	s.mu.Unlock()
	return nil
}

// ServeOnce processes exactly one RPC on an authenticated accepted channel.
// Listener ownership, accept loops and all filesystem/launchd setup remain in
// the macOS boundary composition; this function has no ambient listener or
// path fallback.
func (s *Server) ServeOnce(ctx context.Context, conn ServerConn) error {
	if s == nil || ctx == nil || conn == nil || ctx.Err() != nil || s.validateEvidence(conn.Evidence()) != nil {
		return ErrDenied
	}
	s.lifecycle.RLock()
	defer s.lifecycle.RUnlock()
	deadline, ok := ctx.Deadline()
	if !ok || !deadline.After(s.now().UTC()) || deadline.After(s.now().UTC().Add(maxServerDeadline)) || conn.SetDeadline(deadline) != nil {
		return ErrDenied
	}
	defer conn.SetDeadline(time.Time{})

	q, raw, err := readAuthenticatedRequest(ctx, conn)
	if err != nil || s.validateRequest(q, deadline) != nil {
		return ErrDenied
	}
	digest := requestDigest(raw)
	if digest == "" {
		return ErrDenied
	}
	if replay, wait, err := s.claim(q, digest); err != nil {
		return err
	} else if replay != nil {
		return s.writeResponse(ctx, conn, q.Operation, *replay)
	} else if wait != nil {
		select {
		case <-wait:
			s.mu.Lock()
			stored, found := s.replays[q.RequestID]
			s.mu.Unlock()
			if !found || stored.digest != digest {
				return ErrReconcile
			}
			return s.writeResponse(ctx, conn, q.Operation, stored.value)
		case <-ctx.Done():
			return ErrUnavailable
		}
	}

	out, dispatchErr := s.dispatch(ctx, q, digest)
	if dispatchErr != nil {
		s.finish(q.RequestID, digest, response{}, false)
		var nativeErr *nativeDispatchError
		if errors.As(dispatchErr, &nativeErr) {
			s.poison()
			return ErrReconcile
		}
		// A missing server-side session or a closed-contract request did not
		// reach a native runtime.  Do not let one stale Controller reference
		// poison every other profile request.  Any driver/I/O ambiguity does.
		if errors.Is(dispatchErr, ErrReconcile) || errors.Is(dispatchErr, ErrDenied) || errors.Is(dispatchErr, ErrInvalid) {
			return dispatchErr
		}
		s.poison()
		return ErrReconcile
	}
	s.finish(q.RequestID, digest, out, true)
	// The replay is stored before the response is written.  If this connection
	// dies, a same-ID same-digest retry obtains the exact original response.
	return s.writeResponse(ctx, conn, q.Operation, out)
}

func (s *Server) writeResponse(ctx context.Context, conn ServerConn, operation string, out response) error {
	if err := writeAuthenticatedResponse(ctx, conn, out); err != nil {
		if mutatingOperation(operation) {
			s.poison()
			return ErrReconcile
		}
		return err
	}
	return nil
}

func mutatingOperation(operation string) bool {
	return operation == "start" || operation == "send" || operation == "steer" || operation == "cancel"
}

func (s *Server) validateEvidence(e macoschannel.Evidence) error {
	d := s.descriptor
	if e.Channel != d.Channel || e.LocalRole != d.PeerIdentity || e.PeerRole != "controller" || e.Local.UID != d.PeerUID || e.Local.GID != d.PeerGID || e.Peer.UID != s.uid || e.Peer.GID != s.gid || e.KeyEpoch != d.KeyEpoch || e.LocalRelease != descriptorRelease(d) || e.PeerRelease != s.controller {
		return ErrDenied
	}
	return nil
}

func descriptorRelease(d Descriptor) macoschannel.ReleasePin {
	return macoschannel.ReleasePin{ReleaseID: d.ReleaseID, BinaryDigest: d.BinaryDigest, SocketDigest: d.SocketDigest, ManifestDigest: d.ManifestDigest}
}
func validRelease(p macoschannel.ReleasePin) bool {
	return id(p.ReleaseID) && bareDigest(p.BinaryDigest) && bareDigest(p.SocketDigest) && bareDigest(p.ManifestDigest)
}

func readAuthenticatedRequest(ctx context.Context, conn ServerConn) (request, []byte, error) {
	wire, err := readFrame(ctx, conn)
	if err != nil {
		return request{}, nil, err
	}
	var envelope sealedFrame
	if decodeCanonical(wire, &envelope) != nil || len(envelope.Payload) == 0 || len(envelope.Payload) > maxFrameBytes || envelope.Tag == "" || conn.Verify(frameBindingDomain, envelope.Payload, envelope.Tag) != nil {
		return request{}, nil, ErrDenied
	}
	var q request
	if decodeCanonical(envelope.Payload, &q) != nil || q.Validate() != nil {
		return request{}, nil, ErrInvalid
	}
	return q, append([]byte(nil), envelope.Payload...), nil
}

func writeAuthenticatedResponse(ctx context.Context, conn ServerConn, out response) error {
	if out.Validate() != nil {
		return ErrInvalid
	}
	payload, err := canonical(out)
	if err != nil {
		return ErrInvalid
	}
	tag, err := conn.Seal(frameBindingDomain, payload)
	if err != nil {
		return ErrDenied
	}
	wire, err := canonical(sealedFrame{Payload: payload, Tag: tag})
	if err != nil || len(wire) > maxFrameBytes {
		return ErrInvalid
	}
	return writeFrame(ctx, conn, wire)
}

func requestDigest(raw []byte) string {
	if len(raw) == 0 || len(raw) > maxFrameBytes {
		return ""
	}
	return providerDigest(raw)
}

func providerDigest(raw []byte) string {
	// Keep the same SHA-256 representation as descriptors and mappings without
	// allowing a native driver to supply or replace a digest.
	return "sha256:" + digestBytes(raw)
}

func (s *Server) validateRequest(q request, contextDeadline time.Time) error {
	now := s.now().UTC()
	d := s.descriptor
	if q.Validate() != nil || q.ProfileID != d.ProfileID || q.ProfileRevision != d.ProfileRevision || q.MappingDigest != d.MappingDigest || q.RuntimeDigest != d.RuntimeDigest || q.ProtocolDigest != d.ProtocolDigest || q.Audience != d.Audience || !q.Deadline.After(now) || q.Deadline.After(now.Add(maxServerDeadline)) || q.Deadline.After(contextDeadline) {
		return ErrDenied
	}
	return nil
}

func (s *Server) claim(q request, digest string) (*response, <-chan struct{}, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.recovered {
		return nil, nil, ErrReconcile
	}
	// A response write can fail after a native mutation and after finish has
	// durably retained this process's exact response.  Poison blocks every new
	// or changed effect, but it must not hide that immutable ACK from a same-ID,
	// same-digest retry: doing so would turn a safely idempotent Start retry into
	// a Controller-side uncertain orphan.  Replay lookup intentionally precedes
	// the poison gate; all identity checks remain exact.
	if replay, ok := s.replays[q.RequestID]; ok {
		if replay.digest != digest {
			return nil, nil, ErrDenied
		}
		copy := replay.value
		return &copy, nil, nil
	}
	if active, ok := s.inflight[q.RequestID]; ok {
		if active.digest != digest {
			return nil, nil, ErrDenied
		}
		// An in-flight same-ID request cannot create a second effect.  It is
		// safe to wait even while the server has been fail-closed; once it
		// settles the caller receives either its exact replay or reconciliation.
		return nil, active.done, nil
	}
	if s.poisoned {
		return nil, nil, ErrReconcile
	}
	s.reapTerminalLocked(s.now().UTC())
	if q.Operation == "start" {
		identity, found := s.startBindings[q.BindingID]
		if found && (identity.requestID != q.RequestID || identity.digest != digest) {
			return nil, nil, ErrDenied
		}
		if !found {
			// Reserve the complete non-replay Start identity before dispatch.  A
			// server cannot evict it safely: it is the local changed-binding guard
			// until the driver has provided a fresh recovery proof.  Refuse before
			// native work rather than letting session metadata grow unbounded.
			if len(s.startBindings) >= s.limit || len(s.sessions) >= s.limit {
				return nil, nil, ErrUnavailable
			}
			s.startBindings[q.BindingID] = serverStartIdentity{requestID: q.RequestID, digest: digest}
		}
	}
	s.inflight[q.RequestID] = serverInflight{digest: digest, done: make(chan struct{})}
	return nil, nil, nil
}

func (s *Server) finish(id, digest string, out response, success bool) {
	s.mu.Lock()
	active, found := s.inflight[id]
	if found {
		delete(s.inflight, id)
		if success {
			s.replays[id] = serverReplay{digest: digest, value: out}
			s.order = append(s.order, id)
			for len(s.order) > s.limit {
				delete(s.replays, s.order[0])
				s.order = s.order[1:]
			}
		}
		close(active.done)
	}
	s.mu.Unlock()
}

func (s *Server) poison() {
	s.mu.Lock()
	s.poisoned = true
	s.mu.Unlock()
}

func (s *Server) dispatch(ctx context.Context, q request, requestDigest string) (response, error) {
	base := response{SchemaVersion: ProtocolV1, Operation: q.Operation, RequestID: q.RequestID, ProfileID: q.ProfileID, ProfileRevision: q.ProfileRevision, MappingDigest: q.MappingDigest, RuntimeDigest: q.RuntimeDigest, ProtocolDigest: q.ProtocolDigest, Audience: q.Audience}
	s.mu.Lock()
	if !s.recovered || s.poisoned {
		s.mu.Unlock()
		return response{}, ErrReconcile
	}
	s.mu.Unlock()

	switch q.Operation {
	case "recover-session":
		driver, ok := s.driver.(PersistedSessionRecoveryDriver)
		if !ok {
			return response{}, ErrReconcile
		}
		proof, err := driver.RecoverSession(ctx, q.SessionID)
		if err != nil || proof.Validate() != nil || proof.RouteRef != q.SessionID || proof.ProfileID != s.descriptor.ProfileID || proof.ProfileRevision != s.descriptor.ProfileRevision || proof.MappingDigest != s.descriptor.MappingDigest || proof.RuntimeDigest != s.descriptor.RuntimeDigest || proof.ProtocolDigest != s.descriptor.ProtocolDigest {
			return response{}, ErrReconcile
		}
		s.mu.Lock()
		if len(s.sessions) >= s.limit {
			if _, exists := s.sessions[proof.NativeSessionID]; !exists {
				s.mu.Unlock()
				return response{}, ErrReconcile
			}
		}
		if _, exists := s.startBindings[proof.BindingID]; !exists && len(s.startBindings) >= s.limit {
			s.mu.Unlock()
			return response{}, ErrReconcile
		}
		for nativeID, session := range s.sessions {
			if session.routeRef == proof.RouteRef && nativeID != proof.NativeSessionID {
				s.mu.Unlock()
				return response{}, ErrReconcile
			}
		}
		if prior, exists := s.sessions[proof.NativeSessionID]; exists && (prior.routeRef != proof.RouteRef || prior.runID != proof.RunID || prior.attempt != proof.AttemptID || prior.state != "running") {
			s.mu.Unlock()
			return response{}, ErrReconcile
		}
		if prior, exists := s.startBindings[proof.BindingID]; exists && (prior.requestID != proof.RequestID || prior.digest != proof.RequestDigest || prior.sessionID != proof.NativeSessionID) {
			s.mu.Unlock()
			return response{}, ErrReconcile
		}
		s.sessions[proof.NativeSessionID] = serverSession{runtime: RuntimeSession{ID: proof.NativeSessionID}, routeRef: proof.RouteRef, runID: proof.RunID, attempt: proof.AttemptID, state: "running", gate: &sync.Mutex{}}
		s.startBindings[proof.BindingID] = serverStartIdentity{requestID: proof.RequestID, digest: proof.RequestDigest, sessionID: proof.NativeSessionID}
		s.mu.Unlock()
		base.Recovery = &proof
		return base, base.Validate()
	case "start":
		r, err := s.driver.Start(ctx, RuntimeStart{RequestID: q.RequestID, RequestDigest: requestDigest, ProfileID: q.ProfileID, ProfileRevision: q.ProfileRevision, MappingDigest: q.MappingDigest, RuntimeDigest: q.RuntimeDigest, ProtocolDigest: q.ProtocolDigest, OrderID: q.OrderID, OrderHash: q.OrderHash, BindingID: q.BindingID, BindingHash: q.BindingHash, RunID: q.RunID, AttemptID: q.AttemptID, Deadline: q.Deadline, Task: q.Task})
		if err != nil {
			return response{}, &nativeDispatchError{cause: err}
		}
		if !id(r.ID) {
			return response{}, &nativeDispatchError{cause: ErrInvalid}
		}
		s.mu.Lock()
		if prior, exists := s.sessions[r.ID]; exists && (prior.runID != q.RunID || prior.attempt != q.AttemptID) {
			s.mu.Unlock()
			return response{}, &nativeDispatchError{cause: ErrDenied}
		}
		routeRef := "ptv2-" + q.ProfileID + "-" + digestBytes([]byte(q.ProfileID+":"+q.BindingID+":"+q.BindingHash))
		s.sessions[r.ID] = serverSession{runtime: r, routeRef: routeRef, runID: q.RunID, attempt: q.AttemptID, state: "running", gate: &sync.Mutex{}}
		identity, bound := s.startBindings[q.BindingID]
		if !bound || identity.requestID != q.RequestID || identity.digest != requestDigest {
			s.mu.Unlock()
			return response{}, &nativeDispatchError{cause: ErrReconcile}
		}
		identity.sessionID = r.ID
		s.startBindings[q.BindingID] = identity
		s.mu.Unlock()
		base.SessionID, base.RunID, base.AttemptID = r.ID, q.RunID, q.AttemptID
		if err := base.Validate(); err != nil {
			return response{}, &nativeDispatchError{cause: err}
		}
		return base, nil
	case "send", "steer", "cancel", "status", "wait", "result", "collect":
		session, unlock, err := s.lockSession(q.SessionID)
		if err != nil {
			return response{}, err
		}
		defer unlock()
		switch q.Operation {
		case "send":
			if session.state != "running" {
				return response{}, ErrDenied
			}
			if err := s.driver.Send(ctx, session.runtime, q.InputRef); err != nil {
				s.poison()
				return response{}, &nativeDispatchError{cause: err}
			}
		case "steer":
			if session.state != "running" {
				return response{}, ErrDenied
			}
			if err := s.driver.Steer(ctx, session.runtime, q.InputRef); err != nil {
				s.poison()
				return response{}, &nativeDispatchError{cause: err}
			}
		case "cancel":
			cancellation := cancellationForRequest(q)
			if !cancellationAllowed(session.state, cancellation) {
				return response{}, ErrDenied
			}
			if err := s.driver.Cancel(ctx, session.runtime, cancellation); err != nil {
				s.poison()
				return response{}, &nativeDispatchError{cause: err}
			}
			s.updateState(q.SessionID, "cancelled")
		case "status", "wait":
			var status RuntimeStatus
			var err error
			if q.Operation == "status" {
				status, err = s.driver.Status(ctx, session.runtime)
			} else {
				status, err = s.driver.Wait(ctx, session.runtime, q.Deadline)
			}
			if err != nil || !state(status.State) || !usage(status.UsageSource) {
				return response{}, ErrUnavailable
			}
			if err := s.observeState(q.SessionID, status.State); err != nil {
				return response{}, err
			}
			base.State, base.UsageSource = status.State, status.UsageSource
		case "result", "collect":
			result, err := s.driver.Result(ctx, session.runtime, q.RevisionRef)
			if err != nil || !terminal(result.Status) || !id(result.OutputArtifactRef) || !id(result.SchemaRef) || !digest(result.ProvenanceDigest) || !classification(result.Classification) {
				return response{}, ErrUnavailable
			}
			if err := s.observeState(q.SessionID, result.Status); err != nil {
				return response{}, err
			}
			base.RunID, base.AttemptID, base.Status, base.OutputArtifactRef, base.SchemaRef, base.ProvenanceDigest, base.Classification = session.runID, session.attempt, result.Status, result.OutputArtifactRef, result.SchemaRef, result.ProvenanceDigest, result.Classification
		}
		return base, base.Validate()
	}
	return response{}, ErrInvalid
}

func (s *Server) lockSession(id string) (serverSession, func(), error) {
	s.mu.Lock()
	v, ok := s.sessions[id]
	if !ok {
		s.mu.Unlock()
		return serverSession{}, nil, ErrReconcile
	}
	if v.gate == nil {
		v.gate = &sync.Mutex{}
		s.sessions[id] = v
	}
	gate := v.gate
	s.mu.Unlock()

	gate.Lock()
	s.mu.Lock()
	v, ok = s.sessions[id]
	blocked := !s.recovered || s.poisoned
	s.mu.Unlock()
	if !ok || blocked {
		gate.Unlock()
		return serverSession{}, nil, ErrReconcile
	}
	return v, gate.Unlock, nil
}
func (s *Server) updateState(id, state string) {
	s.mu.Lock()
	if v, ok := s.sessions[id]; ok {
		v.state = state
		if serverTerminal(state) && v.terminalAt.IsZero() {
			v.terminalAt = s.now().UTC()
		}
		s.sessions[id] = v
	}
	s.mu.Unlock()
}

// observeState is deliberately monotone. A provider report may advance a
// running session to one terminal state, but it can never resurrect it or
// replace a terminal outcome. Such a report means the authenticated runtime
// and Controller session records disagree, so serving must pause for explicit
// reconciliation rather than re-enable control with a stale status response.
func (s *Server) observeState(id, next string) error {
	s.mu.Lock()
	v, ok := s.sessions[id]
	if !ok {
		s.mu.Unlock()
		return ErrReconcile
	}
	if serverTerminal(v.state) {
		if v.state == next {
			s.mu.Unlock()
			return nil
		}
		s.mu.Unlock()
		s.poison()
		return ErrReconcile
	}
	allowed := false
	switch v.state {
	case "starting":
		allowed = next == "starting" || next == "running" || serverTerminal(next)
	case "running":
		allowed = next == "running" || serverTerminal(next)
	}
	if !allowed {
		s.mu.Unlock()
		s.poison()
		return ErrReconcile
	}
	v.state = next
	if serverTerminal(next) && v.terminalAt.IsZero() {
		v.terminalAt = s.now().UTC()
	}
	s.sessions[id] = v
	s.mu.Unlock()
	return nil
}

func serverTerminal(state string) bool {
	return state == "completed" || state == "failed" || state == "cancelled" || state == "uncertain"
}

// reapTerminalLocked forgets only a local session whose terminal observation
// has survived the bounded recovery window.  It is called before a fresh
// Start is admitted, so reaching capacity fails closed until an old session is
// safely reclaimable.  Associated start replay/identity entries are removed
// together; the RuntimeDriver remains the durable idempotency authority.
func (s *Server) reapTerminalLocked(now time.Time) {
	if now.IsZero() {
		return
	}
	retired := make(map[string]bool)
	for id, session := range s.sessions {
		if serverTerminal(session.state) && !session.terminalAt.IsZero() && !now.Before(session.terminalAt.Add(sessionRecoveryWindow)) {
			delete(s.sessions, id)
			retired[id] = true
		}
	}
	if len(retired) == 0 {
		return
	}
	for bindingID, identity := range s.startBindings {
		if retired[identity.sessionID] {
			delete(s.startBindings, bindingID)
		}
	}
	if len(s.replays) == 0 {
		return
	}
	kept := s.order[:0]
	for _, requestID := range s.order {
		replay, ok := s.replays[requestID]
		if !ok {
			continue
		}
		if replay.value.Operation == "start" && retired[replay.value.SessionID] {
			delete(s.replays, requestID)
			continue
		}
		kept = append(kept, requestID)
	}
	s.order = kept
}

func cancellationAllowed(state string, cancellation mesh.Cancellation) bool {
	if cancellation.Validate() != nil {
		return false
	}
	switch cancellation.Mode {
	case mesh.CancellationUser:
		return state == "running"
	case mesh.CancellationStartCompensation, mesh.CancellationBatchCompensation:
		return state == "starting" || state == "running" || state == "uncertain"
	default:
		return false
	}
}

// digestBytes is intentionally tiny and local to this package.  It returns a
// lowercase hex SHA-256 without exposing the input in diagnostics.
func digestBytes(raw []byte) string {
	// Kept separate from providerbridge so the provider-side server owns no
	// registry or evidence dependency beyond the descriptor it was given.
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// The imports above intentionally avoid runtime/network packages.  Keep these
// compile-time assertions close to the seam for future compositions.
var _ ServerConn = (macoschannel.Conn)(nil)
