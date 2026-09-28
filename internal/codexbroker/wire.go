package codexbroker

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"sync"
	"time"
)

// frame is the broker wire envelope. Payloads are one of the typed structs in
// broker.go; there is no method or parameter escape hatch.
type wireFrame struct {
	SchemaVersion    string          `json:"schema_version"`
	Direction        string          `json:"direction"`
	Sequence         uint64          `json:"sequence"`
	RequestID        string          `json:"request_id"`
	Kind             string          `json:"kind"`
	OK               bool            `json:"ok"`
	ErrorCode        string          `json:"error_code,omitempty"`
	Payload          json.RawMessage `json:"payload,omitempty"`
	errorCodePresent bool
}

func writeFrame(w io.Writer, f wireFrame) error {
	if f.SchemaVersion != ProtocolV1 || (f.Direction != "request" && f.Direction != "response") || !opaque(f.RequestID) || f.Sequence == 0 || !allowedKind(f.Kind) || len(f.Payload) > MaxFrameBytes {
		return ErrProtocol
	}
	raw, err := json.Marshal(f)
	if err != nil || len(raw) > MaxFrameBytes {
		return ErrProtocol
	}
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(raw)))
	if _, err = w.Write(n[:]); err != nil {
		return err
	}
	_, err = w.Write(raw)
	return err
}

func readFrame(r *bufio.Reader) (wireFrame, error) {
	var n [4]byte
	if _, err := io.ReadFull(r, n[:]); err != nil {
		return wireFrame{}, err
	}
	if binary.BigEndian.Uint32(n[:]) > MaxFrameBytes {
		return wireFrame{}, ErrProtocol
	}
	raw := make([]byte, binary.BigEndian.Uint32(n[:]))
	if _, err := io.ReadFull(r, raw); err != nil {
		return wireFrame{}, err
	}
	var f wireFrame
	if strictUnmarshal(raw, &f) != nil || f.SchemaVersion != ProtocolV1 || (f.Direction != "request" && f.Direction != "response") || !opaque(f.RequestID) || f.Sequence == 0 || !allowedKind(f.Kind) || len(f.Payload) > MaxFrameBytes {
		return wireFrame{}, ErrProtocol
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil {
		return wireFrame{}, ErrProtocol
	}
	for _, name := range []string{"direction", "kind", "sequence", "request_id", "ok"} {
		if _, ok := fields[name]; !ok {
			return wireFrame{}, ErrProtocol
		}
	}
	if f.Direction == "request" || f.OK {
		payload, ok := fields["payload"]
		if !ok || string(payload) == "null" {
			return wireFrame{}, ErrProtocol
		}
	} else if _, ok := fields["payload"]; ok {
		return wireFrame{}, ErrProtocol
	}
	_, f.errorCodePresent = fields["error_code"]
	if f.errorCodePresent && string(fields["error_code"]) == "null" {
		return wireFrame{}, ErrProtocol
	}
	if err := validateWirePayload(f); err != nil {
		return wireFrame{}, err
	}
	return f, nil
}

func validateWirePayload(f wireFrame) error {
	if f.Direction == "request" {
		if f.OK || f.ErrorCode != "" || f.errorCodePresent {
			return ErrProtocol
		}
		switch f.Kind {
		case "attestation", "inventory", "close":
			return exactEmpty(f.Payload)
		case "login.start":
			var v LoginStart
			if strictUnmarshal(f.Payload, &v) != nil || v.Validate() != nil {
				return ErrProtocol
			}
			return nil
		case "login.completed":
			var v struct {
				LoginID string `json:"login_id"`
			}
			if strictUnmarshal(f.Payload, &v) != nil || !opaque(v.LoginID) {
				return ErrProtocol
			}
			return nil
		case "turn":
			var v Turn
			if strictUnmarshal(f.Payload, &v) != nil || v.Validate() != nil {
				return ErrProtocol
			}
			return nil
		case "cancel":
			var v Cancel
			if strictUnmarshal(f.Payload, &v) != nil || v.Validate() != nil {
				return ErrProtocol
			}
			return nil
		}
	}
	if f.OK {
		if f.ErrorCode != "" || f.errorCodePresent {
			return ErrProtocol
		}
		return validateResponsePayload(f.Kind, f.Payload)
	}
	if !validErrorCode(f.ErrorCode) || f.ErrorCode == "" || len(f.Payload) != 0 {
		return ErrProtocol
	}
	return nil
}
func exactEmpty(raw []byte) error {
	var v struct{}
	if string(raw) != "{}" || strictUnmarshal(raw, &v) != nil {
		return ErrProtocol
	}
	return nil
}

// strictUnmarshal rejects both unknown and duplicate keys. encoding/json by
// itself accepts duplicates (last value wins), which is unsafe at a boundary.
func strictUnmarshal(raw []byte, out any) error {
	// First walk a separate decoder to reject duplicate keys without mutating out.
	check := json.NewDecoder(bytes.NewReader(raw))
	if err := rejectDuplicateKeys(check); err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil {
		return err
	}
	var extra any
	if dec.Decode(&extra) != io.EOF {
		return ErrProtocol
	}
	return nil
}

func rejectDuplicateKeys(dec *json.Decoder) error {
	var walk func() error
	walk = func() error {
		t, err := dec.Token()
		if err != nil {
			return err
		}
		switch x := t.(type) {
		case json.Delim:
			if x == '{' {
				seen := map[string]struct{}{}
				for dec.More() {
					k, err := dec.Token()
					if err != nil {
						return err
					}
					ks, ok := k.(string)
					if !ok {
						return ErrProtocol
					}
					if _, ok := seen[ks]; ok {
						return ErrProtocol
					}
					seen[ks] = struct{}{}
					if err := walk(); err != nil {
						return err
					}
				}
				_, err = dec.Token()
				return err
			}
			if x == '[' {
				for dec.More() {
					if err := walk(); err != nil {
						return err
					}
				}
				_, err = dec.Token()
				return err
			}
		}
		return nil
	}
	if err := walk(); err != nil {
		return err
	}
	return nil
}

func allowedKind(k string) bool {
	switch k {
	case "attestation", "inventory", "login.start", "login.completed", "turn", "cancel", "close":
		return true
	}
	return false
}

type client struct {
	rw        io.ReadWriteCloser
	in        *bufio.Reader
	writeMu   sync.Mutex
	mu        sync.Mutex
	send      uint64
	recv      uint64
	closed    bool
	poison    error
	pending   map[string]chan response
	readDone  chan struct{}
	closeOnce sync.Once
	expected  BoundaryAttestation
	verifier  peerVerifier
	handshake bool
	runtime   *ExpectedRuntime
	channel   productionConn
}

func newClient(rw io.ReadWriteCloser) OwnerRuntimeClient {
	c := &client{rw: rw, in: bufio.NewReaderSize(rw, MaxFrameBytes+8), pending: map[string]chan response{}, readDone: make(chan struct{})}
	go c.reader()
	return c
}

type runtimePeerVerifier struct {
	conn     productionConn
	expected ExpectedRuntime
}

func (v runtimePeerVerifier) Verify(_ context.Context, a BoundaryAttestation) error {
	if v.conn == nil || !attestationMatchesRuntime(a, v.expected) || !v.expected.matchesClient(v.conn.Evidence()) {
		return ErrAttestation
	}
	canonical, err := attestationCanonical(a, v.expected.BindingDigest)
	if err != nil {
		return ErrAttestation
	}
	tag := strings.TrimPrefix(a.Signature, "sha256:")
	if tag == a.Signature {
		return ErrAttestation
	}
	return v.conn.Verify("codexbroker.attestation.v1", canonical, tag)
}

func attestationMatchesRuntime(a BoundaryAttestation, e ExpectedRuntime) bool {
	return a.RuntimeID == e.RuntimeID && a.RuntimeBinaryDigest == e.RuntimeBinaryDigest && a.PolicyDigest == e.PolicyDigest && a.PeerUID == e.PeerUID && a.PeerGID == e.PeerGID && a.Epoch == e.KeyEpoch && a.BrokerSocketDigest == e.BrokerSocketDigest && a.BrokerReleaseDigest == e.BrokerReleaseDigest && a.ExpectedEgressUID == e.ExpectedEgressUID && a.ExpectedEgressGID == e.ExpectedEgressGID && a.ExpectedEgressReleaseDigest == e.ExpectedEgressReleaseDigest && a.ExpectedEgressSocketDigest == e.ExpectedEgressSocketDigest && a.PeerID == e.Channel+":"+e.PeerRole
}
func newVerifiedClient(rw io.ReadWriteCloser, expected BoundaryAttestation, verifier peerVerifier) (OwnerRuntimeClient, error) {
	if expected.Validate() != nil || verifier == nil {
		return nil, ErrAttestation
	}
	c := &client{rw: rw, in: bufio.NewReaderSize(rw, MaxFrameBytes+8), pending: map[string]chan response{}, readDone: make(chan struct{}), expected: expected, verifier: verifier}
	go c.reader()
	return c, nil
}

type response struct {
	f   wireFrame
	err error
}

func (c *client) reader() {
	defer close(c.readDone)
	for {
		f, err := readFrame(c.in)
		if err != nil {
			c.fail(err)
			return
		}
		c.mu.Lock()
		if f.Sequence != c.recv+1 {
			c.mu.Unlock()
			c.fail(ErrOutOfOrder)
			return
		}
		c.recv = f.Sequence
		ch := c.pending[f.RequestID]
		delete(c.pending, f.RequestID)
		c.mu.Unlock()
		if f.Direction != "response" || ch == nil {
			c.fail(ErrProtocol)
			return
		}
		ch <- response{f: f}
	}
}
func (c *client) fail(err error) {
	c.mu.Lock()
	if !c.closed {
		c.closed = true
		c.poison = err
	}
	for id, ch := range c.pending {
		delete(c.pending, id)
		ch <- response{err: err}
	}
	c.mu.Unlock()
}
func (c *client) poisonConnection(err error) {
	c.fail(err)
	c.closeLocal()
}
func (c *client) closeLocal() {
	c.fail(ErrClosed)
	c.closeOnce.Do(func() { _ = c.rw.Close() })
	<-c.readDone
}
func (c *client) call(ctx context.Context, kind string, in any, out any) error {
	if kind != "attestation" {
		if err := c.ensureHandshake(ctx); err != nil {
			return err
		}
	}
	return c.callInternal(ctx, kind, in, out)
}
func (c *client) callInternal(ctx context.Context, kind string, in any, out any) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	cancelWatch := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			c.poisonConnection(ctx.Err())
		case <-cancelWatch:
		}
	}()
	defer close(cancelWatch)
	c.writeMu.Lock()
	c.mu.Lock()
	if c.closed {
		e := c.poison
		c.mu.Unlock()
		c.writeMu.Unlock()
		if e != nil {
			return e
		}
		return ErrClosed
	}
	c.send++
	seq := c.send
	id := "req_" + itoa(seq)
	ch := make(chan response, 1)
	c.pending[id] = ch
	c.mu.Unlock()
	payload, _ := json.Marshal(in)
	err := writeFrame(c.rw, wireFrame{SchemaVersion: ProtocolV1, Direction: "request", Sequence: seq, RequestID: id, Kind: kind, Payload: payload})
	c.writeMu.Unlock()
	if err != nil {
		c.mu.Lock()
		delete(c.pending, id)
		c.mu.Unlock()
		c.poisonConnection(err)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return err
	}
	var r response
	select {
	case r = <-ch:
	case <-ctx.Done():
		c.mu.Lock()
		delete(c.pending, id)
		c.mu.Unlock()
		c.poisonConnection(ctx.Err())
		return ctx.Err()
	}
	if r.err != nil {
		return r.err
	}
	f := r.f
	if f.RequestID != id || f.Kind != kind || f.Direction != "response" {
		c.poisonConnection(ErrProtocol)
		return ErrProtocol
	}
	if !f.OK {
		if f.ErrorCode == "cancelled" {
			return context.Canceled
		}
		return ErrProtocol
	}
	if out != nil && strictUnmarshal(f.Payload, out) != nil {
		return ErrProtocol
	}
	if err := validateResponsePayload(kind, f.Payload); err != nil {
		c.poisonConnection(err)
		return err
	}
	return nil
}

func validateResponsePayload(kind string, raw []byte) error {
	switch kind {
	case "attestation":
		var v BoundaryAttestation
		if strictUnmarshal(raw, &v) != nil || v.Validate() != nil {
			return ErrProtocol
		}
	case "inventory":
		if !requiredJSONKeys(raw, "schema_version", "account_state", "runtime_version", "runtime_digest", "model_only", "tools", "mcp", "plugins", "hooks") {
			return ErrProtocol
		}
		var v Inventory
		if strictUnmarshal(raw, &v) != nil || v.Validate() != nil {
			return ErrProtocol
		}
	case "login.start":
		var v LoginStarted
		if !nonEmptyStringFields(raw, "authorization_url", "user_code") || strictUnmarshal(raw, &v) != nil || v.Validate() != nil {
			return ErrProtocol
		}
	case "login.completed":
		if !requiredJSONKeys(raw, "login_id", "success") || !stringFields(raw, "error_code") {
			return ErrProtocol
		}
		var v LoginCompleted
		if strictUnmarshal(raw, &v) != nil || v.Validate() != nil {
			return ErrProtocol
		}
	case "turn":
		if !stringFields(raw, "answer", "error_code") {
			return ErrProtocol
		}
		var v TurnResult
		if strictUnmarshal(raw, &v) != nil || v.Validate() != nil {
			return ErrProtocol
		}
	case "cancel", "close":
		return exactEmpty(raw)
	default:
		return ErrProtocol
	}
	return nil
}

func requiredJSONKeys(raw []byte, keys ...string) bool {
	var m map[string]json.RawMessage
	if json.Unmarshal(raw, &m) != nil {
		return false
	}
	for _, k := range keys {
		v, ok := m[k]
		if !ok || string(v) == "null" {
			return false
		}
	}
	return true
}

func stringFields(raw []byte, keys ...string) bool {
	var m map[string]json.RawMessage
	if json.Unmarshal(raw, &m) != nil {
		return false
	}
	for _, k := range keys {
		v, ok := m[k]
		if ok && (string(v) == "null" || len(v) == 0 || v[0] != '"') {
			return false
		}
	}
	return true
}

func nonEmptyStringFields(raw []byte, keys ...string) bool {
	if !stringFields(raw, keys...) {
		return false
	}
	var m map[string]json.RawMessage
	if json.Unmarshal(raw, &m) != nil {
		return false
	}
	for _, k := range keys {
		if v, ok := m[k]; ok && string(v) == `""` {
			return false
		}
	}
	return true
}
func (c *client) ensureHandshake(ctx context.Context) error {
	if c.verifier == nil {
		return nil
	}
	var a BoundaryAttestation
	if err := c.callInternal(ctx, "attestation", struct{}{}, &a); err != nil {
		return err
	}
	if a.Validate() != nil || (c.runtime == nil && !sameAttestation(a, c.expected)) || (c.runtime != nil && !attestationMatchesRuntime(a, *c.runtime)) || c.verifier.Verify(ctx, a) != nil {
		c.poisonConnection(ErrAttestation)
		return ErrAttestation
	}
	c.mu.Lock()
	c.handshake = true
	c.mu.Unlock()
	return nil
}
func (c *client) Attestation(ctx context.Context) (BoundaryAttestation, error) {
	var o BoundaryAttestation
	err := c.call(ctx, "attestation", struct{}{}, &o)
	if err == nil && c.verifier != nil && (o.Validate() != nil || (c.runtime == nil && !sameAttestation(o, c.expected)) || (c.runtime != nil && !attestationMatchesRuntime(o, *c.runtime)) || c.verifier.Verify(ctx, o) != nil) {
		c.poisonConnection(ErrAttestation)
		return BoundaryAttestation{}, ErrAttestation
	}
	if err == nil && c.verifier != nil {
		c.mu.Lock()
		c.handshake = true
		c.mu.Unlock()
	}
	return o, err
}
func (c *client) Inventory(ctx context.Context) (Inventory, error) {
	var o Inventory
	err := c.call(ctx, "inventory", struct{}{}, &o)
	return o, err
}
func (c *client) LoginStart(ctx context.Context, i LoginStart) (LoginStarted, error) {
	var o LoginStarted
	err := c.call(ctx, "login.start", i, &o)
	return o, err
}
func (c *client) LoginCompleted(ctx context.Context, id string) (LoginCompleted, error) {
	var o LoginCompleted
	err := c.call(ctx, "login.completed", struct {
		LoginID string `json:"login_id"`
	}{id}, &o)
	return o, err
}
func (c *client) Turn(ctx context.Context, i Turn) (TurnResult, error) {
	var o TurnResult
	err := c.call(ctx, "turn", i, &o)
	return o, err
}
func (c *client) Cancel(ctx context.Context, i Cancel) error { return c.call(ctx, "cancel", i, nil) }
func (c *client) Close(ctx context.Context) error {
	// Graceful close is best-effort and bounded. The local transport shutdown
	// is independent of writeMu, so Close cannot wait behind a blocked writer.
	graceCtx, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
	defer cancel()
	result := make(chan error, 1)
	go func() { result <- c.call(graceCtx, "close", struct{}{}, nil) }()
	select {
	case err := <-result:
		c.closeLocal()
		return err
	case <-graceCtx.Done():
		c.poisonConnection(graceCtx.Err())
		<-result
		return graceCtx.Err()
	}
}

type server struct {
	broker       *Broker
	rw           io.ReadWriter
	in           *bufio.Reader
	recv, send   uint64
	loginPending string
	active       map[string]activeTurn
	// tombstones accept a cancel that wins the client write race. They are
	// exact (session, turn) pairs, bounded, and consumed when that Turn is
	// subsequently registered; they are never a wildcard cancellation API.
	tombstones map[string]cancelTombstone
	completed  map[string]completedTurn
	activeMu   sync.Mutex
	writeMu    sync.Mutex
	workers    sync.WaitGroup
}
type activeTurn struct {
	turnID string
	cancel context.CancelFunc
	done   chan struct{}
}
type cancelTombstone struct {
	turnID string
	at     time.Time
}
type completedTurn struct {
	turnID string
	at     time.Time
}

// A backend that ignores cancellation is isolated after the request deadline.
// Shutdown waits briefly for cooperative workers, then closes the transport;
// late results are buffered and discarded by their completed request.
const serverWorkerJoinTimeout = 250 * time.Millisecond
const (
	maxPreCancelTombstones = 32
	preCancelLifetime      = 2 * time.Second
	maxCompletedTurns      = 64
	completedTurnLifetime  = 5 * time.Second
)

func newServer(rw io.ReadWriter, backend backend, expected BoundaryAttestation, verifier peerVerifier) (*server, error) {
	b, err := newBroker(backend, expected, verifier)
	if err != nil {
		return nil, err
	}
	return &server{broker: b, rw: rw, in: bufio.NewReaderSize(rw, MaxFrameBytes+8), active: map[string]activeTurn{}, tombstones: map[string]cancelTombstone{}, completed: map[string]completedTurn{}}, nil
}

func serverForBroker(rw io.ReadWriter, b *Broker) *server {
	return &server{broker: b, rw: rw, in: bufio.NewReaderSize(rw, MaxFrameBytes+8), active: map[string]activeTurn{}, tombstones: map[string]cancelTombstone{}, completed: map[string]completedTurn{}}
}

func (s *server) pruneTombstonesLocked(now time.Time) {
	for session, tomb := range s.tombstones {
		if now.Sub(tomb.at) > preCancelLifetime {
			delete(s.tombstones, session)
		}
	}
}
func (s *server) pruneCompletedLocked(now time.Time) {
	for key, completed := range s.completed {
		if now.Sub(completed.at) > completedTurnLifetime {
			delete(s.completed, key)
		}
	}
}
func turnKey(session, turn string) string { return session + "\x00" + turn }
func (s *server) rememberCompletedLocked(session, turn string, now time.Time) {
	s.pruneCompletedLocked(now)
	key := turnKey(session, turn)
	if _, exists := s.completed[key]; !exists && len(s.completed) >= maxCompletedTurns {
		var oldest string
		var at time.Time
		for id, completed := range s.completed {
			if at.IsZero() || completed.at.Before(at) {
				oldest, at = id, completed.at
			}
		}
		delete(s.completed, oldest)
	}
	s.completed[key] = completedTurn{turnID: turn, at: now}
}

func (s *server) backendCall(ctx context.Context, fn func(context.Context) error) error {
	callCtx, cancel := context.WithTimeout(ctx, backendCallTimeout)
	defer cancel()
	s.workers.Add(1)
	result := make(chan error, 1)
	go func() {
		defer s.workers.Done()
		result <- fn(callCtx)
	}()
	select {
	case err := <-result:
		return err
	case <-callCtx.Done():
		return callCtx.Err()
	}
}

func backendValue[T any](s *server, ctx context.Context, fn func(context.Context) (T, error)) (T, error) {
	var zero T
	callCtx, cancel := context.WithTimeout(ctx, backendCallTimeout)
	defer cancel()
	s.workers.Add(1)
	result := make(chan struct {
		value T
		err   error
	}, 1)
	go func() {
		defer s.workers.Done()
		value, err := fn(callCtx)
		result <- struct {
			value T
			err   error
		}{value: value, err: err}
	}()
	select {
	case r := <-result:
		return r.value, r.err
	case <-callCtx.Done():
		return zero, callCtx.Err()
	}
}

func (s *server) serve(ctx context.Context) error {
	defer func() {
		// A poisoned transport must eventually terminate its broker-owned
		// child, but a malicious/context-ignoring backend must not hold the
		// server shutdown path hostage.
		go func() {
			closeCtx, cancel := context.WithTimeout(context.Background(), serverWorkerJoinTimeout)
			defer cancel()
			_ = s.broker.Close(closeCtx)
		}()
	}()
	stopCancel := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			if c, ok := s.rw.(io.Closer); ok {
				_ = c.Close()
			}
		case <-stopCancel:
		}
	}()
	defer func() {
		close(stopCancel)
		s.activeMu.Lock()
		active := make([]activeTurn, 0, len(s.active))
		for _, a := range s.active {
			a.cancel()
			active = append(active, a)
		}
		s.activeMu.Unlock()
		activeDeadline := time.NewTimer(serverWorkerJoinTimeout)
		for _, a := range active {
			select {
			case <-a.done:
			case <-activeDeadline.C:
			}
		}
		activeDeadline.Stop()
		workersDone := make(chan struct{})
		go func() {
			s.workers.Wait()
			close(workersDone)
		}()
		workerDeadline := time.NewTimer(serverWorkerJoinTimeout)
		select {
		case <-workersDone:
		case <-workerDeadline.C:
		}
		workerDeadline.Stop()
		if c, ok := s.rw.(io.Closer); ok {
			_ = c.Close()
		}
	}()
	for {
		f, e := readFrame(s.in)
		if e != nil {
			return e
		}
		if f.Direction != "request" {
			return ErrProtocol
		}
		if f.Sequence != s.recv+1 {
			return ErrOutOfOrder
		}
		s.recv = f.Sequence
		if f.Kind == "close" {
			err := s.backendCall(ctx, s.broker.Close)
			if e := s.respond(f, nil, err); e != nil {
				return e
			}
			return nil
		}
		var out any
		var err error
		switch f.Kind {
		case "attestation":
			out, err = backendValue(s, ctx, s.broker.Attestation)
		case "inventory":
			out, err = backendValue(s, ctx, s.broker.Inventory)
		case "login.start":
			var in LoginStart
			err = strictUnmarshal(f.Payload, &in)
			if err == nil {
				if s.loginPending != "" {
					err = ErrProtocol
				} else {
					out, err = backendValue(s, ctx, func(c context.Context) (LoginStarted, error) { return s.broker.LoginStart(c, in) })
				}
				if err == nil {
					s.loginPending = out.(LoginStarted).LoginID
				}
			}
		case "login.completed":
			var in struct {
				LoginID string `json:"login_id"`
			}
			err = strictUnmarshal(f.Payload, &in)
			if err == nil {
				if in.LoginID != s.loginPending {
					return s.respond(f, nil, ErrProtocol)
				}
				out, err = backendValue(s, ctx, func(c context.Context) (LoginCompleted, error) { return s.broker.LoginCompleted(c, in.LoginID) })
				if err == nil && out.(LoginCompleted).LoginID != in.LoginID {
					err = ErrProtocol
				}
				if err == nil {
					s.loginPending = ""
				}
			}
		case "turn":
			var in Turn
			err = strictUnmarshal(f.Payload, &in)
			if err == nil {
				s.activeMu.Lock()
				s.pruneTombstonesLocked(time.Now())
				s.pruneCompletedLocked(time.Now())
				tomb, cancelledBeforeStart := s.tombstones[in.SessionID]
				if cancelledBeforeStart {
					delete(s.tombstones, in.SessionID)
				}
				busy := len(s.active) != 0
				s.activeMu.Unlock()
				if cancelledBeforeStart {
					if tomb.turnID != in.TurnID {
						err = ErrProtocol
					} else {
						out = TurnResult{SessionID: in.SessionID, TurnID: in.TurnID, State: "cancelled", ErrorCode: "CANCELLED"}
					}
				} else if s.loginPending != "" || busy {
					err = ErrProtocol
				} else {
					turnCtx, cancel := context.WithCancel(ctx)
					s.activeMu.Lock()
					s.active[in.SessionID] = activeTurn{turnID: in.TurnID, cancel: cancel, done: make(chan struct{})}
					s.activeMu.Unlock()
					s.workers.Add(1)
					go func() { defer s.workers.Done(); s.runTurn(turnCtx, f, in) }()
					continue
				}
			}
		case "cancel":
			var in Cancel
			err = strictUnmarshal(f.Payload, &in)
			if err == nil {
				s.activeMu.Lock()
				now := time.Now()
				s.pruneTombstonesLocked(now)
				s.pruneCompletedLocked(now)
				active := s.active[in.SessionID]
				if active.cancel == nil {
					if _, completedExists := s.completed[turnKey(in.SessionID, in.TurnID)]; completedExists {
						// The matching turn already completed. Acknowledge the late
						// cancel as an idempotent no-op; do not create a tombstone
						// that could cancel a later turn in this session.
						s.activeMu.Unlock()
					} else {
						if prior, exists := s.tombstones[in.SessionID]; exists && prior.turnID != in.TurnID {
							err = ErrProtocol
						} else if !exists && len(s.tombstones) >= maxPreCancelTombstones {
							err = ErrProtocol
						} else {
							s.tombstones[in.SessionID] = cancelTombstone{turnID: in.TurnID, at: time.Now()}
						}
						s.activeMu.Unlock()
					}
				} else if active.turnID != in.TurnID {
					s.activeMu.Unlock()
					err = ErrProtocol
				} else {
					s.activeMu.Unlock()
					active.cancel()
					err = s.backendCall(ctx, func(c context.Context) error { return s.broker.Cancel(c, in) })
				}
			}
		default:
			err = ErrProtocol
		}
		if e := s.respond(f, out, err); e != nil {
			return e
		}
	}
}
func (s *server) runTurn(ctx context.Context, f wireFrame, in Turn) {
	out, err := s.broker.Turn(ctx, in)
	if err == nil && (out.SessionID != in.SessionID || out.TurnID != in.TurnID) {
		err = ErrProtocol
	}
	s.activeMu.Lock()
	a := s.active[in.SessionID]
	delete(s.active, in.SessionID)
	s.rememberCompletedLocked(in.SessionID, in.TurnID, time.Now())
	s.activeMu.Unlock()
	close(a.done)
	if e := s.respond(f, out, err); e != nil {
		if c, ok := s.rw.(io.Closer); ok {
			_ = c.Close()
		}
	}
}
func (s *server) respond(in wireFrame, out any, err error) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	s.send++
	var p json.RawMessage
	if out != nil && err == nil {
		p, _ = json.Marshal(out)
		if err == nil && validateResponsePayload(in.Kind, p) != nil {
			err = ErrProtocol
			p = nil
		}
	}
	if err == nil && (in.Kind == "cancel" || in.Kind == "close") && p == nil {
		p = []byte("{}")
	}
	code := ""
	if err != nil {
		code = "protocol"
		if errors.Is(err, context.Canceled) {
			code = "cancelled"
		}
	}
	return writeFrame(s.rw, wireFrame{SchemaVersion: ProtocolV1, Direction: "response", Sequence: s.send, RequestID: in.RequestID, Kind: in.Kind, OK: err == nil, ErrorCode: code, Payload: p})
}

func itoa(v uint64) string {
	const d = "0123456789"
	var b [20]byte
	i := len(b)
	for v > 0 {
		i--
		b[i] = d[v%10]
		v /= 10
	}
	return string(b[i:])
}
