package localpd

// This file contains the deliberately synthetic sidecar boundary for Qwen.
// It is a protocol, not an Ollama client: no network, process, or account is
// opened here.  Production construction remains impossible until the
// isolation attestation and monotonic Controller authority exist.

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

const (
	QwenProtocolV1       = "qwen-local-sidecar.v1"
	QwenModel            = "qwen3:8b"
	QwenNumCtx           = uint32(40960)
	QwenContextTokens    = uint32(32768)
	QwenThinkingMedium   = "medium"
	QwenNetworkNone      = "none"
	QwenToolsNone        = "none"
	maxQwenMessageBytes  = 1 << 20
	maxQwenOutputBytes   = 1 << 20
	qwenExchangeDeadline = 30 * time.Second
)

var (
	ErrQwenProtocol    = errors.New("invalid local-pd qwen protocol message")
	ErrQwenDisabled    = errors.New("synthetic qwen runtime disabled")
	ErrQwenReplay      = errors.New("local-pd qwen protocol replay")
	ErrQwenConfigDrift = errors.New("local-pd qwen configuration drift")
	ErrQwenUnavailable = errors.New("local-pd qwen runtime unavailable")
	ErrQwenOutputBound = errors.New("local-pd qwen output exceeds bound")
	ErrQwenThinkingMap = errors.New("local-pd qwen thinking mapping is not attested")
	ErrQwenAuth        = errors.New("local-pd qwen envelope authentication failed")
)

// QwenAuthenticator is supplied by the Controller. It authenticates the
// canonical envelope bytes, never payload text. A nil authenticator is not a
// valid production configuration.
type QwenAuthenticator interface {
	Sign([]byte) (string, error)
	Verify([]byte, string) bool
}

// QwenReplayStore is the durable CAS boundary. Implementations must persist
// only opaque keys and state; a pending key is treated as uncertain after a
// restart and cannot be retried.
type QwenReplayStore interface {
	Reserve(string) error
	Complete(string) error
}
type QwenReplayCheckpoint struct {
	Version     uint64
	StateDigest string
}
type QwenReplayCheckpointStore interface {
	LoadCheckpoint() (QwenReplayCheckpoint, error)
	CommitCheckpoint(uint64, QwenReplayCheckpoint) error
}
type memoryQwenReplayCheckpoint struct {
	mu sync.Mutex
	cp QwenReplayCheckpoint
}

func NewMemoryQwenReplayCheckpointStore() QwenReplayCheckpointStore {
	return &memoryQwenReplayCheckpoint{}
}
func (s *memoryQwenReplayCheckpoint) LoadCheckpoint() (QwenReplayCheckpoint, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cp, nil
}
func (s *memoryQwenReplayCheckpoint) CommitCheckpoint(e uint64, n QwenReplayCheckpoint) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cp.Version != e || n.Version != e+1 || !digestRE.MatchString(n.StateDigest) {
		return ErrQwenProtocol
	}
	s.cp = n
	return nil
}

type qwenReplayRecord struct {
	State     string    `json:"state"`
	UpdatedAt time.Time `json:"updated_at"`
}
type qwenReplayState struct {
	Version uint64                      `json:"version"`
	Records map[string]qwenReplayRecord `json:"records"`
}
type durableQwenReplayStore struct {
	mu         sync.Mutex
	root       *os.Root
	base       string
	lock       *os.File
	key        []byte
	checkpoint QwenReplayCheckpointStore
}

// NewTestQwenReplayStore is the only durable constructor available before
// DR-020. It is synthetic/test-only and requires an injected encryption key.
func NewTestQwenReplayStore(path string, key []byte, cps ...QwenReplayCheckpointStore) (QwenReplayStore, error) {
	if path == "" || !filepath.IsAbs(path) || len(key) != 32 || len(cps) != 1 || cps[0] == nil {
		return nil, ErrQwenProtocol
	}
	r, err := openTrustedPrivateRoot(filepath.Dir(filepath.Clean(path)))
	if err != nil {
		return nil, err
	}
	base := filepath.Base(filepath.Clean(path))
	lf, err := r.OpenFile(base+".lock", os.O_CREATE|os.O_RDWR|syscall.O_CLOEXEC, 0600)
	if err != nil {
		r.Close()
		return nil, err
	}
	if err = validatePrivateRegular(r, lf, base+".lock"); err != nil {
		lf.Close()
		r.Close()
		return nil, err
	}
	s := &durableQwenReplayStore{root: r, base: base, lock: lf, key: append([]byte(nil), key...), checkpoint: cps[0]}
	if err = s.withLock(func() error { _, e := s.load(); return e }); err != nil {
		s.Close()
		return nil, err
	}
	return s, nil
}
func (s *durableQwenReplayStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lock == nil {
		return nil
	}
	e := s.lock.Close()
	s.root.Close()
	s.lock = nil
	return e
}
func (s *durableQwenReplayStore) withLock(fn func() error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lock == nil {
		return ErrQwenProtocol
	}
	if e := syscall.Flock(int(s.lock.Fd()), syscall.LOCK_EX); e != nil {
		return e
	}
	defer syscall.Flock(int(s.lock.Fd()), syscall.LOCK_UN)
	return fn()
}
func (s *durableQwenReplayStore) seal(p []byte) ([]byte, error) {
	b, e := aes.NewCipher(s.key)
	if e != nil {
		return nil, e
	}
	g, e := cipher.NewGCM(b)
	if e != nil {
		return nil, e
	}
	n := make([]byte, g.NonceSize())
	if _, e = rand.Read(n); e != nil {
		return nil, e
	}
	return g.Seal(n, n, p, nil), nil
}
func (s *durableQwenReplayStore) open(p []byte) ([]byte, error) {
	b, e := aes.NewCipher(s.key)
	if e != nil {
		return nil, e
	}
	g, e := cipher.NewGCM(b)
	if e != nil || len(p) < g.NonceSize()+g.Overhead() {
		return nil, ErrQwenProtocol
	}
	x, e := g.Open(nil, p[:g.NonceSize()], p[g.NonceSize():], nil)
	if e != nil {
		return nil, ErrQwenProtocol
	}
	return x, nil
}
func (s *durableQwenReplayStore) load() (qwenReplayState, error) {
	fi, e := s.root.Lstat(s.base)
	if os.IsNotExist(e) {
		cp, e := s.checkpoint.LoadCheckpoint()
		if e != nil || cp.Version != 0 {
			return qwenReplayState{}, ErrQwenProtocol
		}
		return qwenReplayState{Version: 0, Records: map[string]qwenReplayRecord{}}, nil
	}
	if e != nil || fi.Mode()&os.ModeSymlink != 0 || !fi.Mode().IsRegular() {
		return qwenReplayState{}, ErrQwenProtocol
	}
	f, e := s.root.OpenFile(s.base, os.O_RDONLY|syscall.O_CLOEXEC, 0)
	if e != nil {
		return qwenReplayState{}, e
	}
	defer f.Close()
	enc, e := io.ReadAll(io.LimitReader(f, 4<<20+1))
	if e != nil || len(enc) > 4<<20 {
		return qwenReplayState{}, ErrQwenProtocol
	}
	plain, e := s.open(enc)
	if e != nil {
		return qwenReplayState{}, e
	}
	var st qwenReplayState
	if DecodeStrict(plain, &st) != nil || st.Records == nil || len(st.Records) > 4096 {
		return qwenReplayState{}, ErrQwenProtocol
	}
	now := time.Now().UTC()
	for k, v := range st.Records {
		if len(k) > 512 || v.State != "reserved" && v.State != "completed" || now.Sub(v.UpdatedAt) > 24*time.Hour {
			return qwenReplayState{}, ErrQwenProtocol
		}
	}
	d, _ := canonicalQwenDigest(st)
	cp, e := s.checkpoint.LoadCheckpoint()
	if e != nil || cp.Version != st.Version || cp.StateDigest != d {
		return qwenReplayState{}, ErrQwenProtocol
	}
	return st, nil
}
func (s *durableQwenReplayStore) save(st qwenReplayState) error {
	p, e := json.Marshal(st)
	if e != nil {
		return e
	}
	enc, e := s.seal(p)
	if e != nil {
		return e
	}
	rnd := make([]byte, 8)
	if _, e = rand.Read(rnd); e != nil {
		return e
	}
	tmp := "." + s.base + ".tmp-" + hex.EncodeToString(rnd)
	f, e := s.root.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_CLOEXEC, 0600)
	if e != nil {
		return e
	}
	ok := false
	defer func() {
		f.Close()
		if !ok {
			s.root.Remove(tmp)
		}
	}()
	if _, e = f.Write(enc); e != nil {
		return e
	}
	if e = f.Sync(); e != nil {
		return e
	}
	if e = f.Close(); e != nil {
		return e
	}
	if e = s.root.Rename(tmp, s.base); e != nil {
		return e
	}
	d, e := s.root.Open(".")
	if e != nil {
		return e
	}
	e = d.Sync()
	d.Close()
	if e != nil {
		return e
	}
	ok = true
	return nil
}
func (s *durableQwenReplayStore) Reserve(k string) error {
	return s.withLock(func() error {
		st, e := s.load()
		if e != nil {
			return e
		}
		if _, ok := st.Records[k]; ok {
			return ErrQwenReplay
		}
		if len(st.Records) >= 4096 {
			return ErrQwenReplay
		}
		st.Records[k] = qwenReplayRecord{"reserved", time.Now().UTC()}
		return s.commit(st)
	})
}
func (s *durableQwenReplayStore) Complete(k string) error {
	return s.withLock(func() error {
		st, e := s.load()
		if e != nil {
			return e
		}
		r, ok := st.Records[k]
		if !ok || r.State != "reserved" {
			return ErrQwenReplay
		}
		r.State = "completed"
		r.UpdatedAt = time.Now().UTC()
		st.Records[k] = r
		return s.commit(st)
	})
}
func (s *durableQwenReplayStore) commit(st qwenReplayState) error {
	e := st.Version
	st.Version++
	if err := s.save(st); err != nil {
		return err
	}
	d, _ := canonicalQwenDigest(st)
	return s.checkpoint.CommitCheckpoint(e, QwenReplayCheckpoint{Version: st.Version, StateDigest: d})
}

type memoryQwenReplayStore struct {
	mu     sync.Mutex
	states map[string]bool
}

func NewMemoryQwenReplayStore() QwenReplayStore {
	return &memoryQwenReplayStore{states: make(map[string]bool)}
}
func (s *memoryQwenReplayStore) Reserve(k string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.states[k]; ok {
		return ErrQwenReplay
	}
	s.states[k] = false
	return nil
}
func (s *memoryQwenReplayStore) Complete(k string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if done, ok := s.states[k]; !ok || done {
		return ErrQwenReplay
	}
	s.states[k] = true
	return nil
}

type QwenTestAuthenticator struct{ Token string }

func (a QwenTestAuthenticator) Sign(b []byte) (string, error) {
	if a.Token == "" {
		return "", ErrQwenAuth
	}
	d, _ := canonicalQwenDigest(struct {
		T string `json:"token"`
		B []byte `json:"bytes"`
	}{a.Token, b})
	return d, nil
}
func (a QwenTestAuthenticator) Verify(b []byte, sig string) bool {
	x, err := a.Sign(b)
	return err == nil && x == sig
}

// QwenProtocolConfig is the only supported local configuration.  Thinking is
// semantic; a provider-specific boolean is never silently inferred.
type QwenProtocolConfig struct {
	Model         string `json:"model"`
	NumCtx        uint32 `json:"num_ctx"`
	ContextTokens uint32 `json:"context_tokens"`
	Thinking      string `json:"thinking"`
	Tools         string `json:"tools"`
	Network       string `json:"network"`
	Fallback      string `json:"fallback"`
}

func DefaultQwenProtocolConfig() QwenProtocolConfig {
	return QwenProtocolConfig{QwenModel, QwenNumCtx, QwenContextTokens, QwenThinkingMedium, QwenToolsNone, QwenNetworkNone, "none"}
}
func (c QwenProtocolConfig) Validate() error {
	if c != DefaultQwenProtocolConfig() {
		return ErrQwenConfigDrift
	}
	return nil
}

// QwenThinkingMapping is an attested provider mapping.  Boolean think values
// are accepted only when this exact mapping is supplied; otherwise rejected.
type QwenThinkingMapping struct {
	Semantic            string `json:"semantic"`
	Boolean             bool   `json:"boolean"`
	Digest              string `json:"digest"`
	PairRuntimeDigest   string `json:"pair_runtime_digest"`
	PairConfigDigest    string `json:"pair_config_digest"`
	ControllerSignature string `json:"controller_signature"`
}

func (m QwenThinkingMapping) Validate(pair CurrentQwenPair, auth QwenAuthenticator) error {
	if m.Semantic != QwenThinkingMedium || !m.Boolean || m.PairRuntimeDigest != pair.RuntimeDigest || m.PairConfigDigest != pair.ConfigDigest || auth == nil {
		return ErrQwenThinkingMap
	}
	d, err := canonicalQwenDigest(struct {
		Semantic string `json:"semantic"`
		Boolean  bool   `json:"boolean"`
	}{m.Semantic, m.Boolean})
	if err != nil || d != m.Digest || !auth.Verify(mappingUnsigned(m), m.ControllerSignature) {
		return ErrQwenThinkingMap
	}
	return nil
}
func mappingUnsigned(m QwenThinkingMapping) []byte {
	b, _ := json.Marshal(struct {
		Semantic          string `json:"semantic"`
		Boolean           bool   `json:"boolean"`
		Digest            string `json:"digest"`
		PairRuntimeDigest string `json:"pair_runtime_digest"`
		PairConfigDigest  string `json:"pair_config_digest"`
	}{m.Semantic, m.Boolean, m.Digest, m.PairRuntimeDigest, m.PairConfigDigest})
	return b
}

type QwenHandshake struct {
	Version             string               `json:"version"`
	RuntimeID           string               `json:"runtime_id"`
	RuntimeDigest       string               `json:"runtime_digest"`
	Config              QwenProtocolConfig   `json:"config"`
	ConfigDigest        string               `json:"config_digest"`
	Pair                CurrentQwenPair      `json:"pair"`
	Mapping             *QwenThinkingMapping `json:"thinking_mapping,omitempty"`
	ControllerSignature string               `json:"controller_signature"`
}

func (h QwenHandshake) Validate(pair CurrentQwenPair, auth QwenAuthenticator) error {
	if h.Version != QwenProtocolV1 || h.RuntimeID == "" || h.Pair != pair || h.RuntimeDigest != pair.RuntimeDigest || h.ConfigDigest != pair.ConfigDigest {
		return ErrQwenProtocol
	}
	if h.Config.Validate() != nil {
		return ErrQwenConfigDrift
	}
	if h.Mapping != nil && h.Mapping.Validate(pair, auth) != nil {
		return ErrQwenThinkingMap
	}
	return nil
}

type qwenRequest struct {
	Version             string               `json:"version"`
	RequestID           string               `json:"request_id"`
	Nonce               string               `json:"nonce"`
	IssuedAt            time.Time            `json:"issued_at"`
	Deadline            time.Time            `json:"deadline"`
	Pair                CurrentQwenPair      `json:"pair"`
	Config              QwenProtocolConfig   `json:"config"`
	Payload             []byte               `json:"payload"`
	PayloadDigest       string               `json:"payload_digest"`
	Think               *bool                `json:"think,omitempty"`
	Mapping             *QwenThinkingMapping `json:"thinking_mapping,omitempty"`
	ControllerSignature string               `json:"controller_signature"`
}
type qwenResponse struct {
	Version             string          `json:"version"`
	RequestID           string          `json:"request_id"`
	Pair                CurrentQwenPair `json:"pair"`
	Output              []byte          `json:"output"`
	OutputDigest        string          `json:"output_digest"`
	ControllerSignature string          `json:"controller_signature"`
}

func handshakeUnsigned(h QwenHandshake) []byte {
	b, _ := json.Marshal(struct {
		Version       string               `json:"version"`
		RuntimeID     string               `json:"runtime_id"`
		RuntimeDigest string               `json:"runtime_digest"`
		Config        QwenProtocolConfig   `json:"config"`
		ConfigDigest  string               `json:"config_digest"`
		Pair          CurrentQwenPair      `json:"pair"`
		Mapping       *QwenThinkingMapping `json:"thinking_mapping,omitempty"`
	}{h.Version, h.RuntimeID, h.RuntimeDigest, h.Config, h.ConfigDigest, h.Pair, h.Mapping})
	return b
}
func requestUnsigned(r qwenRequest) []byte {
	b, _ := json.Marshal(struct {
		Version       string               `json:"version"`
		RequestID     string               `json:"request_id"`
		Nonce         string               `json:"nonce"`
		IssuedAt      time.Time            `json:"issued_at"`
		Deadline      time.Time            `json:"deadline"`
		Pair          CurrentQwenPair      `json:"pair"`
		Config        QwenProtocolConfig   `json:"config"`
		Payload       []byte               `json:"payload"`
		PayloadDigest string               `json:"payload_digest"`
		Think         *bool                `json:"think,omitempty"`
		Mapping       *QwenThinkingMapping `json:"thinking_mapping,omitempty"`
	}{r.Version, r.RequestID, r.Nonce, r.IssuedAt, r.Deadline, r.Pair, r.Config, r.Payload, r.PayloadDigest, r.Think, r.Mapping})
	return b
}
func responseUnsigned(r qwenResponse) []byte {
	b, _ := json.Marshal(struct {
		Version      string          `json:"version"`
		RequestID    string          `json:"request_id"`
		Pair         CurrentQwenPair `json:"pair"`
		Output       []byte          `json:"output"`
		OutputDigest string          `json:"output_digest"`
	}{r.Version, r.RequestID, r.Pair, r.Output, r.OutputDigest})
	return b
}

func canonicalQwenDigest(v any) (string, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(h[:]), nil
}
func validateQwenRequest(r qwenRequest, now time.Time, auth QwenAuthenticator) error {
	if r.Version != QwenProtocolV1 || r.RequestID == "" || r.Nonce == "" || r.Pair.RuntimeDigest == "" || r.Pair.ConfigDigest == "" || len(r.Payload) == 0 || len(r.Payload) > maxQwenMessageBytes || now.Before(r.IssuedAt) || !now.Before(r.Deadline) || r.Deadline.Sub(now) > qwenExchangeDeadline {
		return ErrQwenProtocol
	}
	if r.Config.Validate() != nil {
		return ErrQwenConfigDrift
	}
	d, err := canonicalQwenDigest(r.Payload)
	if err != nil || d != r.PayloadDigest {
		return ErrQwenProtocol
	}
	if r.Think != nil {
		if r.Mapping == nil || r.Mapping.Validate(r.Pair, auth) != nil {
			return ErrQwenThinkingMap
		}
		if *r.Think != r.Mapping.Boolean {
			return ErrQwenThinkingMap
		}
	}
	return nil
}

// QwenSidecar is intentionally narrow and carries no process or network
// capability. Implementations must return ErrQwenUnavailable on outage.
type QwenSidecar interface {
	Exchange(context.Context, QwenHandshake, qwenRequest) (qwenResponse, error)
}

type syntheticQwenSidecar struct {
	mu        sync.Mutex
	enabled   bool
	seen      map[string]struct{}
	fn        func([]byte) ([]byte, error)
	fnContext func(context.Context, []byte) ([]byte, error)
	auth      QwenAuthenticator
	store     QwenReplayStore
}

// NewSyntheticQwenSidecar returns a fake runtime. It is disabled by default;
// tests must opt in explicitly and provide a pure function.
func NewSyntheticQwenSidecar(enabled bool, fn func([]byte) ([]byte, error)) QwenSidecar {
	return &syntheticQwenSidecar{enabled: false}
}
func NewSyntheticQwenSidecarWithSecurity(enabled bool, fn func([]byte) ([]byte, error), auth QwenAuthenticator, store QwenReplayStore) QwenSidecar {
	return &syntheticQwenSidecar{enabled: false}
}
func NewSyntheticQwenSidecarContext(enabled bool, fn func(context.Context, []byte) ([]byte, error), auth QwenAuthenticator, store QwenReplayStore) QwenSidecar {
	return &syntheticQwenSidecar{enabled: enabled, fnContext: fn, auth: auth, store: store, seen: make(map[string]struct{})}
}
func (s *syntheticQwenSidecar) Exchange(ctx context.Context, h QwenHandshake, r qwenRequest) (qwenResponse, error) {
	if !s.enabled || s.fnContext == nil || s.auth == nil || s.store == nil {
		return qwenResponse{}, ErrQwenDisabled
	}
	if err := ctx.Err(); err != nil {
		return qwenResponse{}, err
	}
	if !s.auth.Verify(handshakeUnsigned(h), h.ControllerSignature) {
		return qwenResponse{}, ErrQwenAuth
	}
	if err := h.Validate(r.Pair, s.auth); err != nil {
		return qwenResponse{}, err
	}
	if err := validateQwenRequest(r, time.Now().UTC(), s.auth); err != nil {
		return qwenResponse{}, err
	}
	if !s.auth.Verify(requestUnsigned(r), r.ControllerSignature) {
		return qwenResponse{}, ErrQwenAuth
	}
	if r.Mapping != nil && (h.Mapping == nil || *r.Mapping != *h.Mapping) {
		return qwenResponse{}, ErrQwenThinkingMap
	}
	requestDigest, _ := canonicalQwenDigest(json.RawMessage(requestUnsigned(r)))
	fullKey, _ := canonicalQwenDigest(struct {
		Pair                            CurrentQwenPair
		Nonce, RequestID, RequestDigest string
	}{r.Pair, r.Nonce, r.RequestID, requestDigest})
	identityID, _ := canonicalQwenDigest(struct {
		Pair      CurrentQwenPair
		RequestID string
	}{r.Pair, r.RequestID})
	identityNonce, _ := canonicalQwenDigest(struct {
		Pair  CurrentQwenPair
		Nonce string
	}{r.Pair, r.Nonce})
	if err := s.store.Reserve("request-id:" + identityID); err != nil {
		return qwenResponse{}, err
	}
	if err := s.store.Reserve("nonce:" + identityNonce); err != nil {
		return qwenResponse{}, err
	}
	if err := s.store.Reserve("request:" + fullKey); err != nil {
		return qwenResponse{}, err
	}
	s.mu.Lock()
	if _, ok := s.seen[r.Nonce]; ok {
		s.mu.Unlock()
		return qwenResponse{}, ErrQwenReplay
	}
	s.seen[r.Nonce] = struct{}{}
	s.mu.Unlock()
	callCtx, cancel := context.WithDeadline(ctx, r.Deadline)
	defer cancel()
	out, err := s.fnContext(callCtx, append([]byte(nil), r.Payload...))
	if err != nil {
		return qwenResponse{}, ErrQwenUnavailable
	}
	if err := callCtx.Err(); err != nil {
		return qwenResponse{}, err
	}
	if len(out) > maxQwenOutputBytes {
		return qwenResponse{}, ErrQwenOutputBound
	}
	d, _ := canonicalQwenDigest(out)
	resp := qwenResponse{Version: QwenProtocolV1, RequestID: r.RequestID, Pair: r.Pair, Output: append([]byte(nil), out...), OutputDigest: d}
	resp.ControllerSignature, _ = s.auth.Sign(responseUnsigned(resp))
	if err := s.store.Complete("request:" + fullKey); err != nil {
		return qwenResponse{}, ErrQwenUnavailable
	}
	if err := s.store.Complete("request-id:" + identityID); err != nil {
		return qwenResponse{}, ErrQwenUnavailable
	}
	if err := s.store.Complete("nonce:" + identityNonce); err != nil {
		return qwenResponse{}, ErrQwenUnavailable
	}
	return resp, nil
}

// newSyntheticQwenTransport adapts the protocol to the existing sealed
// localPDTransport seam. It never logs or returns payload contents.
func newSyntheticQwenTransport(sidecar QwenSidecar, h QwenHandshake) localPDTransport {
	return &qwenTransport{sidecar: sidecar, handshake: h}
}
func newSyntheticQwenTransportWithSecurity(sidecar QwenSidecar, h QwenHandshake, auth QwenAuthenticator) localPDTransport {
	return &qwenTransport{sidecar: sidecar, handshake: h, auth: auth}
}

type qwenTransport struct {
	sidecar   QwenSidecar
	handshake QwenHandshake
	auth      QwenAuthenticator
}

func (t *qwenTransport) infer(ctx context.Context, in localInferenceRequest) ([]byte, error) {
	if t.sidecar == nil || t.auth == nil {
		return nil, ErrQwenProtocol
	}
	now := time.Now().UTC()
	id, err := qwenRandomID()
	if err != nil {
		return nil, ErrQwenUnavailable
	}
	nonce, err := qwenRandomID()
	if err != nil {
		return nil, ErrQwenUnavailable
	}
	r := qwenRequest{Version: QwenProtocolV1, RequestID: id, Nonce: nonce, IssuedAt: now, Deadline: now.Add(qwenExchangeDeadline), Pair: in.pair, Config: DefaultQwenProtocolConfig(), Payload: append([]byte(nil), in.payload...)}
	r.PayloadDigest, _ = canonicalQwenDigest(r.Payload)
	r.ControllerSignature, err = t.auth.Sign(requestUnsigned(r))
	if err != nil {
		return nil, ErrQwenAuth
	}
	resp, err := t.sidecar.Exchange(ctx, t.handshake, r)
	if err != nil {
		return nil, err
	}
	if resp.Version != QwenProtocolV1 || resp.RequestID != r.RequestID || resp.Pair != r.Pair || len(resp.Output) > maxQwenOutputBytes {
		return nil, ErrQwenProtocol
	}
	d, _ := canonicalQwenDigest(resp.Output)
	if d != resp.OutputDigest || !t.auth.Verify(responseUnsigned(resp), resp.ControllerSignature) {
		return nil, ErrQwenProtocol
	}
	return resp.Output, nil
}

func qwenRandomID() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
