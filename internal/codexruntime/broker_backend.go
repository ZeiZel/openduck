package codexruntime

// This file is the broker-owned production runtime adapter. The isolation
// seam is intentionally opaque: only this package can provide a real process
// and its independent model-only egress proof. The command therefore remains
// fail-closed until that composition exists.

import (
	"context"
	"errors"
	"io"
	"sync"
	"time"

	"openduck/internal/codexbroker"
	"openduck/internal/modelegress"
)

var (
	ErrRuntimeIsolationRequired = errors.New("production runtime isolation required")
	ErrRuntimeState             = errors.New("invalid production runtime state")
	ErrUncertainModelTurn       = errors.New("model turn outcome uncertain")
	ErrRuntimeShutdown          = errors.New("production runtime shutdown timed out")
)

// ProductionRuntimeProcess is deliberately not constructible by consumers:
// its lifecycle methods are package-private while the broker owns every
// process handle and joins it before a backend operation returns.
type ProductionRuntimeProcess interface {
	io.ReadWriter
	io.Closer
	terminate() error
	wait() error
}

// ProductionRuntimeIsolation is the only test/production composition seam.
// A real implementation must create the dedicated home and child under an
// independently enforced model-only egress sandbox before returning.
type ProductionRuntimeIsolation interface {
	start(context.Context) (ProductionRuntimeProcess, error)
	attestation(context.Context) (codexbroker.BoundaryAttestation, error)
}

// proxyGrantIsolation is deliberately narrower than ProductionRuntimeIsolation
// so historical synthetic fakes cannot accidentally become production-ready.
// A real runtime may start only after the runtime-channel grant has been
// verified and reduced to this one child-facing proxy URL.
type proxyGrantIsolation interface {
	proxyAddress(context.Context) (string, error)
}

type runtimeHandle struct {
	process ProductionRuntimeProcess
	once    sync.Once
	done    chan error
}

func newRuntimeHandle(p ProductionRuntimeProcess) *runtimeHandle {
	return &runtimeHandle{process: p, done: make(chan error, 1)}
}

func (h *runtimeHandle) stop() error {
	if h == nil || h.process == nil {
		return nil
	}
	h.once.Do(func() {
		go func() {
			_ = h.process.Close()
			_ = h.process.terminate()
			h.done <- h.process.wait()
		}()
	})
	select {
	case err := <-h.done:
		return err
	case <-time.After(productionShutdownTimeout):
		return ErrRuntimeShutdown
	}
}

type productionBackendState uint8

const (
	backendCold productionBackendState = iota
	backendReady
	backendLoginPending
	backendStopping
	backendClosed
)

// ProductionBackend owns the runtime process; no path, home, PID, stdio or
// generic RPC value is present in its public shape.
type ProductionBackend struct {
	mu         sync.Mutex
	isolation  ProductionRuntimeIsolation
	identity   codexbroker.ExpectedRuntimeIdentity
	model      string
	process    *runtimeHandle
	client     *Client
	loginID    string
	state      productionBackendState
	att        codexbroker.BoundaryAttestation
	attLoaded  bool
	opMu       sync.Mutex
	generation uint64
	poisoned   bool
}

// NewProductionBackend accepts only the opaque isolation seam. Passing nil is
// rejected, and the command's ordinary production composition intentionally
// has no way to bypass that gate.
func NewProductionBackend(identity codexbroker.ExpectedRuntimeIdentity, isolation ProductionRuntimeIsolation, model string) (*ProductionBackend, error) {
	if isolation == nil || identity.Validate() != nil || model == "" {
		return nil, ErrRuntimeIsolationRequired
	}
	return &ProductionBackend{isolation: isolation, identity: identity, model: model, state: backendCold}, nil
}

// productionEgressBinding remains a metadata-only test seam. Production
// startup no longer calls it or accepts a capability: only the broker owns
// that capability and the runtime sees a verified one-shot ProxyGrant.
func productionEgressBinding(identity codexbroker.ExpectedRuntimeIdentity) (modelegress.CapabilityBinding, error) {
	if identity.ExpectedEgressUID == 0 || identity.ExpectedEgressGID == 0 || !validDigestString(identity.ExpectedEgressReleaseDigest) || !validDigestString(identity.ExpectedEgressSocketDigest) || (identity.ExpectedEgressUID == identity.RuntimeUID && identity.ExpectedEgressGID == identity.RuntimeGID) {
		return modelegress.CapabilityBinding{}, ErrRuntimeIsolationRequired
	}
	return modelegress.CapabilityBinding{PolicyDigest: identity.PolicyDigest, ReleaseDigest: identity.ExpectedEgressReleaseDigest, SocketDigest: identity.ExpectedEgressSocketDigest, UID: identity.ExpectedEgressUID, GID: identity.ExpectedEgressGID, Epoch: identity.KeyEpoch}, nil
}

func (b *ProductionBackend) Attestation(ctx context.Context) (codexbroker.BoundaryAttestation, error) {
	if b == nil || b.isolation == nil {
		return codexbroker.BoundaryAttestation{}, ErrRuntimeIsolationRequired
	}
	a, err := b.isolation.attestation(ctx)
	if err != nil || !backendAttestationMatches(a, b.identity) {
		return codexbroker.BoundaryAttestation{}, codexbroker.ErrAttestation
	}
	b.mu.Lock()
	if b.state == backendClosed {
		b.mu.Unlock()
		return codexbroker.BoundaryAttestation{}, codexbroker.ErrClosed
	}
	b.att, b.attLoaded = a, true
	b.mu.Unlock()
	return a, nil
}

func backendAttestationMatches(a codexbroker.BoundaryAttestation, e codexbroker.ExpectedRuntimeIdentity) bool {
	return a.Validate() == nil && a.RuntimeID == e.RuntimeID && a.RuntimeBinaryDigest == e.RuntimeBinaryDigest && a.PolicyDigest == e.PolicyDigest && a.Epoch == e.KeyEpoch && a.BrokerSocketDigest == e.BrokerSocketDigest && a.BrokerReleaseDigest == e.BrokerReleaseDigest && a.ExpectedEgressUID == e.ExpectedEgressUID && a.ExpectedEgressGID == e.ExpectedEgressGID && a.ExpectedEgressReleaseDigest == e.ExpectedEgressReleaseDigest && a.ExpectedEgressSocketDigest == e.ExpectedEgressSocketDigest && a.PeerUID == e.PeerUID && a.PeerGID == e.PeerGID
}

func (b *ProductionBackend) ensureProcess(ctx context.Context) (*Client, *runtimeHandle, error) {
	b.mu.Lock()
	if b.state == backendClosed || b.poisoned || b.state == backendStopping {
		b.mu.Unlock()
		return nil, nil, codexbroker.ErrClosed
	}
	if b.client != nil && b.process != nil {
		c, h := b.client, b.process
		b.mu.Unlock()
		return c, h, nil
	}
	gen := b.generation
	b.mu.Unlock()
	grant, ok := b.isolation.(proxyGrantIsolation)
	if !ok {
		return nil, nil, ErrRuntimeIsolationRequired
	}
	proxyAddress, err := grant.proxyAddress(ctx)
	if err != nil || proxyAddress == "" {
		return nil, nil, ErrRuntimeIsolationRequired
	}
	p, err := b.isolation.start(ctx)
	if err != nil || p == nil {
		return nil, nil, ErrRuntimeIsolationRequired
	}
	c := NewClient(p)
	if err := c.Initialize(ctx, InitializeParams{ClientInfo: ClientInfo{Name: "openduck-codex-broker", Version: "0.1.0"}}); err != nil {
		if stopErr := newRuntimeHandle(p).stop(); stopErr != nil {
			b.mu.Lock()
			b.poisoned = true
			b.mu.Unlock()
		}
		return nil, nil, err
	}
	h := newRuntimeHandle(p)
	b.mu.Lock()
	if b.state == backendClosed || b.poisoned || b.client != nil || b.generation != gen {
		b.mu.Unlock()
		if stopErr := h.stop(); stopErr != nil {
			b.mu.Lock()
			b.poisoned = true
			b.mu.Unlock()
		}
		return nil, nil, codexbroker.ErrClosed
	}
	b.process, b.client, b.state = h, c, backendReady
	b.mu.Unlock()
	return c, h, nil
}

func (b *ProductionBackend) detachLocked() (*runtimeHandle, *Client) {
	p, c := b.process, b.client
	b.generation++
	b.process, b.client, b.loginID = nil, nil, ""
	if b.state != backendClosed {
		b.state = backendStopping
	}
	return p, c
}

func stopRuntime(h *runtimeHandle, c *Client) error {
	if c != nil {
		_ = c.Close()
	}
	return h.stop()
}

func (b *ProductionBackend) abortLocked() error {
	p, c := b.detachLocked()
	return stopRuntime(p, c)
}

func (b *ProductionBackend) abort() error {
	b.mu.Lock()
	if b.state == backendStopping && b.process == nil {
		b.mu.Unlock()
		return ErrRuntimeState
	}
	p, c := b.detachLocked()
	b.mu.Unlock()
	err := stopRuntime(p, c)
	b.mu.Lock()
	if errors.Is(err, ErrRuntimeShutdown) {
		b.poisoned = true
	} else if b.state == backendStopping {
		b.state = backendCold
	}
	b.mu.Unlock()
	return err
}

func (b *ProductionBackend) Inventory(ctx context.Context) (codexbroker.Inventory, error) {
	b.opMu.Lock()
	defer b.opMu.Unlock()
	c, _, err := b.ensureProcess(ctx)
	if err != nil {
		return codexbroker.Inventory{}, err
	}
	account, err := c.CallMetadata(ctx, "account/get", map[string]any{"refreshToken": false})
	if err != nil {
		return codexbroker.Inventory{}, errors.Join(err, b.abort())
	}
	config, err := c.CallMetadata(ctx, "config/read", map[string]any{"includeLayers": true})
	if err != nil || unsafeMetadata(config) {
		return codexbroker.Inventory{}, errors.Join(ErrUnsafeInventory, b.abort())
	}
	state := accountState(account)
	if state != "chatgpt" {
		return codexbroker.Inventory{}, errors.Join(ErrUnsafeInventory, b.abort())
	}
	i := codexbroker.Inventory{SchemaVersion: codexbroker.ProtocolV1, AccountState: state, RuntimeVersion: "broker-owned", RuntimeDigest: b.identity.RuntimeBinaryDigest, ModelOnly: true, Tools: []string{}, MCP: []string{}, Plugins: []string{}, Hooks: []string{}}
	return i, i.Validate()
}

func (b *ProductionBackend) LoginStart(ctx context.Context, in codexbroker.LoginStart) (codexbroker.LoginStarted, error) {
	b.opMu.Lock()
	defer b.opMu.Unlock()
	if in.Validate() != nil {
		return codexbroker.LoginStarted{}, codexbroker.ErrProtocol
	}
	c, _, err := b.ensureProcess(ctx)
	if err != nil {
		return codexbroker.LoginStarted{}, err
	}
	b.mu.Lock()
	if b.state == backendLoginPending {
		b.mu.Unlock()
		return codexbroker.LoginStarted{}, ErrRuntimeState
	}
	b.mu.Unlock()
	v, err := c.LoginStart(ctx, in.AccountType)
	if err != nil || v.LoginID == "" {
		stopErr := b.abort()
		return codexbroker.LoginStarted{}, errors.Join(err, stopErr)
	}
	b.mu.Lock()
	if b.state == backendClosed || b.client != c {
		b.mu.Unlock()
		return codexbroker.LoginStarted{}, codexbroker.ErrClosed
	}
	b.loginID, b.state = v.LoginID, backendLoginPending
	b.mu.Unlock()
	authURL := v.AuthURL
	if authURL == "" {
		authURL = v.VerificationURL
	}
	out := codexbroker.LoginStarted{LoginID: v.LoginID, AuthorizationURL: authURL, UserCode: v.UserCode}
	if err := out.Validate(); err != nil {
		return codexbroker.LoginStarted{}, errors.Join(err, b.abort())
	}
	return out, nil
}

func (b *ProductionBackend) LoginCompleted(ctx context.Context, id string) (codexbroker.LoginCompleted, error) {
	b.opMu.Lock()
	defer b.opMu.Unlock()
	b.mu.Lock()
	if b.state != backendLoginPending || id == "" || id != b.loginID || b.client == nil {
		b.mu.Unlock()
		return codexbroker.LoginCompleted{}, ErrRuntimeState
	}
	c := b.client
	b.mu.Unlock()
	err := c.WaitLoginCompleted(ctx, id)
	if err != nil {
		return codexbroker.LoginCompleted{LoginID: id, ErrorCode: "LOGIN_FAILED"}, errors.Join(err, b.abort())
	}
	account, err := c.CallMetadata(ctx, "account/get", map[string]any{"refreshToken": false})
	if err != nil || accountState(account) != "chatgpt" {
		return codexbroker.LoginCompleted{LoginID: id, ErrorCode: "LOGIN_FAILED"}, errors.Join(ErrUnsafeInventory, b.abort())
	}
	b.mu.Lock()
	if b.client != c || b.state == backendClosed {
		b.mu.Unlock()
		return codexbroker.LoginCompleted{}, codexbroker.ErrClosed
	}
	b.loginID, b.state = "", backendReady
	b.mu.Unlock()
	return codexbroker.LoginCompleted{LoginID: id, Success: true}, nil
}

func (b *ProductionBackend) Turn(ctx context.Context, in codexbroker.Turn) (codexbroker.TurnResult, error) {
	b.opMu.Lock()
	defer b.opMu.Unlock()
	b.mu.Lock()
	if in.Validate() != nil || b.state != backendReady {
		b.mu.Unlock()
		return codexbroker.TurnResult{}, codexbroker.ErrProtocol
	}
	b.mu.Unlock()
	c, h, err := b.ensureProcess(ctx)
	if err != nil {
		return codexbroker.TurnResult{}, err
	}
	stopCancellation := make(chan struct{})
	go func(p ProductionRuntimeProcess) {
		select {
		case <-ctx.Done():
			_ = p.Close()
			_ = p.terminate()
		case <-stopCancellation:
		}
	}(h.process)
	defer close(stopCancellation)
	details, err := c.StartThreadDetails(ctx, ThreadParams{Model: b.model, ApprovalPolicy: "never", Sandbox: "read-only"})
	if err != nil || len(details.InstructionSources) != 0 {
		return codexbroker.TurnResult{}, errors.Join(ErrUnsafeInventory, b.abort())
	}
	if err := c.StartTurn(ctx, TurnParams{ThreadID: details.ID, Prompt: in.Prompt, ApprovalPolicy: "never", Model: b.model}); err != nil {
		// The request may have reached the model. It is never retried.
		return codexbroker.TurnResult{}, errors.Join(ErrUncertainModelTurn, b.abort())
	}
	done, err := c.ReadAssistantCompleted(ctx, in.MaxOutputBytes)
	if err != nil {
		cleanupErr := b.abort()
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return codexbroker.TurnResult{}, errors.Join(err, cleanupErr)
		}
		return codexbroker.TurnResult{}, errors.Join(ErrUncertainModelTurn, cleanupErr)
	}
	if stopErr := b.abort(); stopErr != nil {
		return codexbroker.TurnResult{}, stopErr
	}
	r := codexbroker.TurnResult{SessionID: in.SessionID, TurnID: in.TurnID, State: "completed", Answer: done.Answer}
	return r, r.Validate()
}

func (b *ProductionBackend) Cancel(ctx context.Context, in codexbroker.Cancel) error {
	if in.Validate() != nil {
		return codexbroker.ErrProtocol
	}
	b.mu.Lock()
	if b.state == backendClosed || b.state == backendStopping {
		b.mu.Unlock()
		return ErrRuntimeState
	}
	if err := ctx.Err(); err != nil {
		b.mu.Unlock()
		return err
	}
	p, c := b.detachLocked()
	b.mu.Unlock()
	err := stopRuntime(p, c)
	if errors.Is(err, ErrRuntimeShutdown) {
		b.mu.Lock()
		b.poisoned = true
		b.mu.Unlock()
	} else if err == nil {
		b.mu.Lock()
		if b.state == backendStopping {
			b.state = backendCold
		}
		b.mu.Unlock()
	}
	return err
}

func (b *ProductionBackend) Close(ctx context.Context) error {
	b.mu.Lock()
	if b.state == backendClosed {
		b.mu.Unlock()
		return codexbroker.ErrClosed
	}
	if b.state == backendStopping {
		b.mu.Unlock()
		return ErrRuntimeState
	}
	p, c := b.detachLocked()
	b.state = backendClosed
	b.mu.Unlock()
	stopErr := stopRuntime(p, c)
	if stopErr != nil {
		b.mu.Lock()
		b.poisoned = true
		b.mu.Unlock()
		return stopErr
	}
	return ctx.Err()
}

var _ codexbroker.RuntimeBackend = (*ProductionBackend)(nil)

// Keep the lifecycle timeout visible at this boundary for later real
// isolation implementations; no operation may run forever during shutdown.
const productionShutdownTimeout = 2 * time.Second
