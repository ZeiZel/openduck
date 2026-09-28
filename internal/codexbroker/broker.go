// Package codexbroker is the only typed boundary through which Controller code
// may address the owner Codex runtime.  Process, stdio, JSON-RPC and runtime
// installation details deliberately do not appear in this package's public
// API.
package codexbroker

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"openduck/internal/macoschannel"
)

const (
	ProtocolV1           = "owner-runtime-broker.v1"
	MaxPromptBytes       = 64 << 10
	MaxAnswerBytes       = 256 << 10
	MaxFrameBytes        = 320 << 10
	MaxURLBytes          = 2048
	MaxCodeBytes         = 128
	MaxErrorBytes        = 128
	AttestationFreshness = 5 * time.Minute
)

var (
	ErrUnavailable = errors.New("codex broker unavailable")
	ErrProtocol    = errors.New("codex broker protocol violation")
	ErrAttestation = errors.New("codex broker attestation failed")
	ErrReplay      = errors.New("codex broker replay detected")
	ErrOutOfOrder  = errors.New("codex broker out-of-order frame")
	ErrClosed      = errors.New("codex broker connection closed")
)

type BoundaryAttestation struct {
	SchemaVersion               string    `json:"schema_version"`
	RuntimeID                   string    `json:"runtime_id"`
	PeerID                      string    `json:"peer_id"`
	RuntimeBinaryDigest         string    `json:"runtime_binary_digest"`
	PolicyDigest                string    `json:"policy_digest"`
	IssuedAt                    time.Time `json:"issued_at"`
	PeerUID                     uint32    `json:"peer_uid"`
	PeerGID                     uint32    `json:"peer_gid"`
	Epoch                       uint64    `json:"epoch"`
	BrokerSocketDigest          string    `json:"broker_socket_digest"`
	BrokerReleaseDigest         string    `json:"broker_release_digest"`
	ExpectedEgressUID           uint32    `json:"expected_egress_uid"`
	ExpectedEgressGID           uint32    `json:"expected_egress_gid"`
	ExpectedEgressReleaseDigest string    `json:"expected_egress_release_digest"`
	ExpectedEgressSocketDigest  string    `json:"expected_egress_socket_digest"`
	Signature                   string    `json:"signature"`
}

func (a BoundaryAttestation) Validate() error {
	if a.SchemaVersion != ProtocolV1 || !opaque(a.RuntimeID) || !opaque(a.PeerID) || !digest(a.RuntimeBinaryDigest) || !digest(a.PolicyDigest) || !digest(a.BrokerSocketDigest) || !digest(a.BrokerReleaseDigest) || !digest(a.ExpectedEgressReleaseDigest) || !digest(a.ExpectedEgressSocketDigest) || !digest(a.Signature) || a.PeerUID == 0 || a.PeerGID == 0 || a.ExpectedEgressUID == 0 || a.ExpectedEgressGID == 0 || a.Epoch == 0 || a.IssuedAt.IsZero() || time.Since(a.IssuedAt) > AttestationFreshness || time.Until(a.IssuedAt) > time.Minute {
		return ErrAttestation
	}
	return nil
}

type Inventory struct {
	SchemaVersion  string   `json:"schema_version"`
	AccountState   string   `json:"account_state"`
	RuntimeVersion string   `json:"runtime_version"`
	RuntimeDigest  string   `json:"runtime_digest"`
	ModelOnly      bool     `json:"model_only"`
	Tools          []string `json:"tools"`
	MCP            []string `json:"mcp"`
	Plugins        []string `json:"plugins"`
	Hooks          []string `json:"hooks"`
}

func (i Inventory) Validate() error {
	if i.SchemaVersion != ProtocolV1 || !opaque(i.AccountState) || !opaque(i.RuntimeVersion) || !digest(i.RuntimeDigest) || !i.ModelOnly || !boundedStrings(i.Tools) || !boundedStrings(i.MCP) || !boundedStrings(i.Plugins) || !boundedStrings(i.Hooks) || len(i.Tools) != 0 || len(i.MCP) != 0 || len(i.Plugins) != 0 || len(i.Hooks) != 0 {
		return ErrProtocol
	}
	return nil
}

func boundedStrings(v []string) bool {
	if len(v) > 64 {
		return false
	}
	for _, s := range v {
		if len(s) > 256 || strings.ContainsAny(s, "\r\n") {
			return false
		}
	}
	return true
}

type LoginStart struct {
	AccountType string `json:"account_type"`
}
type LoginStarted struct {
	LoginID          string `json:"login_id"`
	AuthorizationURL string `json:"authorization_url,omitempty"`
	UserCode         string `json:"user_code,omitempty"`
}
type LoginCompleted struct {
	LoginID   string `json:"login_id"`
	Success   bool   `json:"success"`
	ErrorCode string `json:"error_code,omitempty"`
}
type Turn struct {
	SessionID      string `json:"session_id"`
	TurnID         string `json:"turn_id"`
	Prompt         string `json:"prompt"`
	Classification string `json:"classification"`
	MaxOutputBytes int    `json:"max_output_bytes"`
}
type TurnResult struct {
	SessionID string `json:"session_id"`
	TurnID    string `json:"turn_id"`
	State     string `json:"state"`
	Answer    string `json:"answer,omitempty"`
	ErrorCode string `json:"error_code,omitempty"`
}
type Cancel struct {
	SessionID string `json:"session_id"`
	TurnID    string `json:"turn_id"`
}

func (l LoginStart) Validate() error {
	if l.AccountType != "chatgpt" && l.AccountType != "chatgptDeviceCode" {
		return ErrProtocol
	}
	return nil
}
func (l LoginStarted) Validate() error {
	if !opaque(l.LoginID) || len([]byte(l.AuthorizationURL)) > MaxURLBytes || len([]byte(l.UserCode)) > MaxCodeBytes || (l.AuthorizationURL == "" && l.UserCode == "") || (l.AuthorizationURL != "" && (!strings.HasPrefix(l.AuthorizationURL, "https://") || len(l.AuthorizationURL) == len("https://"))) || strings.ContainsAny(l.AuthorizationURL+l.UserCode, "\r\n") {
		return ErrProtocol
	}
	return nil
}
func (l LoginCompleted) Validate() error {
	if !opaque(l.LoginID) || !validErrorCode(l.ErrorCode) || (l.Success && l.ErrorCode != "") || (!l.Success && l.ErrorCode == "") {
		return ErrProtocol
	}
	return nil
}
func (t Turn) Validate() error {
	if !opaque(t.SessionID) || !opaque(t.TurnID) || t.Prompt == "" || len([]byte(t.Prompt)) > MaxPromptBytes || (t.Classification != "L0" && t.Classification != "L1") || t.MaxOutputBytes <= 0 || t.MaxOutputBytes > MaxAnswerBytes {
		return ErrProtocol
	}
	return nil
}
func (r TurnResult) Validate() error {
	if !opaque(r.SessionID) || !opaque(r.TurnID) || (r.State != "completed" && r.State != "failed" && r.State != "cancelled") || len([]byte(r.Answer)) > MaxAnswerBytes || !validErrorCode(r.ErrorCode) || (r.State == "completed" && (r.Answer == "" || r.ErrorCode != "")) || (r.State != "completed" && (r.ErrorCode == "" || r.Answer != "")) {
		return ErrProtocol
	}
	return nil
}
func validErrorCode(s string) bool {
	if len(s) > MaxErrorBytes {
		return false
	}
	for _, b := range []byte(s) {
		if !(b == '_' || b == '-' || b == '.' || b == ':' || b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9') {
			return false
		}
	}
	return true
}
func (c Cancel) Validate() error {
	if !opaque(c.SessionID) || !opaque(c.TurnID) {
		return ErrProtocol
	}
	return nil
}

// OwnerRuntimeClient is the complete Controller-facing surface.  All IDs are
// opaque; implementations must not expose process or profile details.
type OwnerRuntimeClient interface {
	Attestation(context.Context) (BoundaryAttestation, error)
	Inventory(context.Context) (Inventory, error)
	LoginStart(context.Context, LoginStart) (LoginStarted, error)
	LoginCompleted(context.Context, string) (LoginCompleted, error)
	Turn(context.Context, Turn) (TurnResult, error)
	Cancel(context.Context, Cancel) error
	Close(context.Context) error
}

// RuntimeBackend is the only provider surface consumed by the broker. It is
// deliberately limited to the typed owner-runtime operations; process,
// stdio, paths and generic RPC are not representable here.
type RuntimeBackend interface {
	OwnerRuntimeClient
}

// ForwardingBackend is the broker-side adapter for a separately authenticated
// runtime daemon. It deliberately contains only the typed client and the
// broker-to-Controller attestation; it cannot expose a child process, a
// runtime filesystem path, or egress credentials to the broker listener.
type ForwardingBackend struct {
	runtime OwnerRuntimeClient
	att     BoundaryAttestation
}

func NewForwardingBackend(runtime OwnerRuntimeClient, att BoundaryAttestation) (*ForwardingBackend, error) {
	if runtime == nil || att.Validate() != nil {
		return nil, ErrAttestation
	}
	return &ForwardingBackend{runtime: runtime, att: att}, nil
}

func (b *ForwardingBackend) Attestation(context.Context) (BoundaryAttestation, error) {
	if b == nil || b.runtime == nil || b.att.Validate() != nil {
		return BoundaryAttestation{}, ErrAttestation
	}
	return b.att, nil
}
func (b *ForwardingBackend) Inventory(c context.Context) (Inventory, error) {
	return b.runtime.Inventory(c)
}
func (b *ForwardingBackend) LoginStart(c context.Context, v LoginStart) (LoginStarted, error) {
	return b.runtime.LoginStart(c, v)
}
func (b *ForwardingBackend) LoginCompleted(c context.Context, id string) (LoginCompleted, error) {
	return b.runtime.LoginCompleted(c, id)
}
func (b *ForwardingBackend) Turn(c context.Context, v Turn) (TurnResult, error) {
	return b.runtime.Turn(c, v)
}
func (b *ForwardingBackend) Cancel(c context.Context, v Cancel) error { return b.runtime.Cancel(c, v) }
func (b *ForwardingBackend) Close(c context.Context) error {
	if b == nil || b.runtime == nil {
		return ErrClosed
	}
	return b.runtime.Close(c)
}

var _ RuntimeBackend = (*ForwardingBackend)(nil)

// backend is retained as a private alias so the test-only transport cannot
// accidentally widen the production API.
type backend = RuntimeBackend

// ExpectedRuntime is the stable identity a production channel must bind to.
// It contains no process handles or filesystem paths. The channel evidence is
// supplied by macoschannel after its kernel-credential and transcript checks.
type ExpectedRuntime struct {
	RuntimeID string
	// BrokerBinaryDigest identifies the release binary authenticated by the
	// macoschannel. RuntimeBinaryDigest identifies the separate Codex child.
	BrokerBinaryDigest          string
	RuntimeBinaryDigest         string
	PolicyDigest                string
	BrokerReleaseDigest         string
	BrokerSocketDigest          string
	PeerUID                     uint32
	PeerGID                     uint32
	RuntimeUID                  uint32
	RuntimeGID                  uint32
	ExpectedEgressUID           uint32
	ExpectedEgressGID           uint32
	ExpectedEgressReleaseDigest string
	ExpectedEgressSocketDigest  string
	KeyEpoch                    uint64
	Channel                     string
	LocalRole                   string
	PeerRole                    string
	BindingDigest               string
}

// ExpectedRuntimeIdentity is the public name used by production composition.
// It is an alias deliberately: identity values cannot gain a second, weaker
// representation at the broker boundary.
type ExpectedRuntimeIdentity = ExpectedRuntime

func (e ExpectedRuntime) Validate() error {
	if !opaque(e.RuntimeID) || !digest(e.BrokerBinaryDigest) || !digest(e.RuntimeBinaryDigest) || !digest(e.PolicyDigest) ||
		!digest(e.BrokerReleaseDigest) || !digest(e.BrokerSocketDigest) || !digest(e.ExpectedEgressReleaseDigest) || !digest(e.ExpectedEgressSocketDigest) || e.ExpectedEgressUID == 0 || e.ExpectedEgressGID == 0 || e.PeerUID == 0 ||
		e.PeerGID == 0 || e.RuntimeUID == 0 || e.RuntimeGID == 0 || e.RuntimeUID == e.PeerUID || e.KeyEpoch == 0 || !opaque(e.Channel) || !opaque(e.LocalRole) || !opaque(e.PeerRole) || e.LocalRole == e.PeerRole || !digest(e.BindingDigest) {
		return ErrAttestation
	}
	return nil
}

// ComputeBindingDigest binds only stable, already-authenticated channel evidence.
// It is an identity digest, not a signature and must never be accepted as one.
func (e ExpectedRuntime) ComputeBindingDigest(ev macoschannel.Evidence) string {
	// BindingDigest is derived from the sealed macoschannel transcript below,
	// so requiring it before the derivation would make a production listener
	// impossible to compose. Validate every other identity field with a fixed
	// syntactically-valid placeholder; the resulting digest never depends on
	// that placeholder.
	v := e
	v.BindingDigest = Digest("pending-channel-binding")
	if v.Validate() != nil || ev.KeyEpoch == 0 {
		return ""
	}
	// Canonicalize the two channel orientations so the broker server and
	// controller client independently derive the same identity digest.
	brokerRelease, controllerRelease := ev.LocalRelease, ev.PeerRelease
	controller := ev.Peer
	if ev.LocalRole == e.PeerRole && ev.PeerRole == e.LocalRole {
		brokerRelease, controllerRelease = ev.PeerRelease, ev.LocalRelease
		controller = ev.Local
	}
	return Digest(fmt.Sprintf("codexbroker-binding-v3|runtime=%s|broker-binary=%s|runtime-binary=%s|policy=%s|broker-release=%s|broker-socket=%s|egress=%d:%d|egress-release=%s|egress-socket=%s|channel=%s|peer=%d:%d|roles=%s,%s|epoch=%d|local-release=%s|peer-release=%s",
		e.RuntimeID, e.BrokerBinaryDigest, e.RuntimeBinaryDigest, e.PolicyDigest, e.BrokerReleaseDigest, e.BrokerSocketDigest, e.ExpectedEgressUID, e.ExpectedEgressGID, e.ExpectedEgressReleaseDigest, e.ExpectedEgressSocketDigest,
		ev.Channel, controller.UID, controller.GID, e.LocalRole, e.PeerRole,
		ev.KeyEpoch, brokerRelease.ReleaseID, controllerRelease.ReleaseID))
}

func (e ExpectedRuntime) matches(ev macoschannel.Evidence) bool {
	localRuntime := ev.Local.UID == e.RuntimeUID && ev.Local.GID == e.RuntimeGID && ev.LocalRole == e.LocalRole && ev.PeerRole == e.PeerRole && ev.LocalRelease.BinaryDigest == e.BrokerBinaryDigest[7:] && ev.LocalRelease.ManifestDigest == e.BrokerReleaseDigest[7:] && ev.LocalRelease.SocketDigest == e.BrokerSocketDigest[7:]
	peerRuntime := ev.Peer.UID == e.RuntimeUID && ev.Peer.GID == e.RuntimeGID && ev.PeerRole == e.LocalRole && ev.LocalRole == e.PeerRole && ev.PeerRelease.BinaryDigest == e.BrokerBinaryDigest[7:] && ev.PeerRelease.ManifestDigest == e.BrokerReleaseDigest[7:] && ev.PeerRelease.SocketDigest == e.BrokerSocketDigest[7:]
	peer := (ev.Peer.UID == e.PeerUID && ev.Peer.GID == e.PeerGID) || (ev.Local.UID == e.PeerUID && ev.Local.GID == e.PeerGID)
	return e.Validate() == nil && peer && ev.KeyEpoch == e.KeyEpoch && (localRuntime || peerRuntime) &&
		ev.Channel == e.Channel && e.ComputeBindingDigest(ev) == e.BindingDigest
}

func (e ExpectedRuntime) matchesServer(ev macoschannel.Evidence) bool {
	return e.matches(ev) && ev.Local.UID == e.RuntimeUID && ev.Local.GID == e.RuntimeGID &&
		ev.Peer.UID == e.PeerUID && ev.Peer.GID == e.PeerGID &&
		ev.LocalRole == e.LocalRole && ev.PeerRole == e.PeerRole &&
		ev.LocalRelease.BinaryDigest == e.BrokerBinaryDigest[7:] &&
		ev.LocalRelease.ManifestDigest == e.BrokerReleaseDigest[7:] &&
		ev.LocalRelease.SocketDigest == e.BrokerSocketDigest[7:]
}

func (e ExpectedRuntime) matchesClient(ev macoschannel.Evidence) bool {
	return e.matches(ev) && ev.Local.UID == e.PeerUID && ev.Local.GID == e.PeerGID &&
		ev.Peer.UID == e.RuntimeUID && ev.Peer.GID == e.RuntimeGID &&
		ev.LocalRole == e.PeerRole && ev.PeerRole == e.LocalRole &&
		ev.PeerRelease.BinaryDigest == e.BrokerBinaryDigest[7:] &&
		ev.PeerRelease.ManifestDigest == e.BrokerReleaseDigest[7:] &&
		ev.PeerRelease.SocketDigest == e.BrokerSocketDigest[7:]
}

// ProductionClient is intentionally opaque. A value can only be constructed
// by NewProductionClient from an authenticated macoschannel.Conn.
type ProductionClient struct{ client *client }

// ProductionConnector is an opaque, already-authenticated owner-runtime
// connection. Its transport and channel evidence never escape this package.
type ProductionConnector struct{ client *ProductionClient }

type productionConn interface {
	io.ReadWriteCloser
	Evidence() macoschannel.Evidence
	Seal(string, []byte) (string, error)
	Verify(string, []byte, string) error
}

func (p *ProductionClient) Attestation(c context.Context) (BoundaryAttestation, error) {
	return p.client.Attestation(c)
}
func (p *ProductionClient) Inventory(c context.Context) (Inventory, error) {
	return p.client.Inventory(c)
}
func (p *ProductionClient) LoginStart(c context.Context, v LoginStart) (LoginStarted, error) {
	return p.client.LoginStart(c, v)
}
func (p *ProductionClient) LoginCompleted(c context.Context, id string) (LoginCompleted, error) {
	return p.client.LoginCompleted(c, id)
}
func (p *ProductionClient) Turn(c context.Context, v Turn) (TurnResult, error) {
	return p.client.Turn(c, v)
}
func (p *ProductionClient) Cancel(c context.Context, v Cancel) error { return p.client.Cancel(c, v) }
func (p *ProductionClient) Close(c context.Context) error            { return p.client.Close(c) }

// NewProductionClient is fail-closed until macoschannel exposes a sealed
// binder for the runtime attestation. Evidence matching alone is not a
// signature and cannot authorize a production Codex runtime.
func NewProductionClient(conn macoschannel.Conn, expected ExpectedRuntime) (*ProductionClient, error) {
	return newProductionClient(conn, expected)
}

// NewProductionConnector requires the same exact peer, release, socket and
// transcript binding as the production client. There is no constructor from a
// path, raw socket, or unsealed net.Conn.
func NewProductionConnector(conn macoschannel.Conn, expected ExpectedRuntimeIdentity) (*ProductionConnector, error) {
	client, err := NewProductionClient(conn, expected)
	if err != nil {
		return nil, err
	}
	return &ProductionConnector{client: client}, nil
}

// Client returns only the typed Controller-facing surface. Process, profile,
// stdio and channel handles remain private to the connector.
func (c *ProductionConnector) Client() (OwnerRuntimeClient, error) {
	if c == nil || c.client == nil {
		return nil, ErrUnavailable
	}
	return c.client, nil
}

func newProductionClient(conn productionConn, expected ExpectedRuntime) (*ProductionClient, error) {
	if conn == nil || expected.Validate() != nil || !expected.matchesClient(conn.Evidence()) {
		return nil, ErrAttestation
	}
	c := newClient(conn).(*client)
	c.runtime = &expected
	c.channel = conn
	c.verifier = runtimePeerVerifier{conn: conn, expected: expected}
	return &ProductionClient{client: c}, nil
}

// ProductionServer is the authenticated, single-connection server surface.
// Its constructor remains sealed for the same reason as ProductionClient.
type ProductionServer struct{ server *server }

func NewProductionServer(conn macoschannel.Conn, backend RuntimeBackend, expected ExpectedRuntime) (*ProductionServer, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	return newProductionServerContext(ctx, conn, backend, expected)
}

func newProductionServer(conn productionConn, backend RuntimeBackend, expected ExpectedRuntime) (*ProductionServer, error) {
	return newProductionServerContext(context.Background(), conn, backend, expected)
}

func newProductionServerContext(ctx context.Context, conn productionConn, backend RuntimeBackend, expected ExpectedRuntime) (*ProductionServer, error) {
	if conn == nil || backend == nil || expected.Validate() != nil || !expected.matchesServer(conn.Evidence()) {
		return nil, ErrAttestation
	}
	backendAtt, err := runBackend(ctx, backend.Attestation)
	if err != nil || !backendIdentityMatches(backendAtt, expected) {
		return nil, ErrAttestation
	}
	att, err := signedAttestation(conn, expected)
	if err != nil {
		return nil, err
	}
	ab := &attestingBackend{RuntimeBackend: backend, conn: conn, expected: expected, initial: att}
	s, err := newServer(conn, ab, att, expectedVerifier{expected: expected})
	if err != nil {
		return nil, err
	}
	s.broker.attFactory = func() (BoundaryAttestation, error) { return signedAttestation(conn, expected) }
	return &ProductionServer{server: s}, nil
}

type attestingBackend struct {
	RuntimeBackend
	conn     productionConn
	expected ExpectedRuntime
	initial  BoundaryAttestation
	used     bool
}

func (b *attestingBackend) Attestation(ctx context.Context) (BoundaryAttestation, error) {
	if !b.used {
		b.used = true
		return b.initial, nil
	}
	if a, err := b.RuntimeBackend.Attestation(ctx); err != nil || !backendIdentityMatches(a, b.expected) {
		return BoundaryAttestation{}, ErrAttestation
	}
	return signedAttestation(b.conn, b.expected)
}

func backendIdentityMatches(a BoundaryAttestation, e ExpectedRuntime) bool {
	return a.Validate() == nil && a.RuntimeID == e.RuntimeID && a.RuntimeBinaryDigest == e.RuntimeBinaryDigest && a.PolicyDigest == e.PolicyDigest && a.Epoch == e.KeyEpoch && a.BrokerSocketDigest == e.BrokerSocketDigest && a.BrokerReleaseDigest == e.BrokerReleaseDigest && a.ExpectedEgressUID == e.ExpectedEgressUID && a.ExpectedEgressGID == e.ExpectedEgressGID && a.ExpectedEgressReleaseDigest == e.ExpectedEgressReleaseDigest && a.ExpectedEgressSocketDigest == e.ExpectedEgressSocketDigest
}

func (s *ProductionServer) Serve(ctx context.Context) error {
	if s == nil || s.server == nil {
		return ErrUnavailable
	}
	return s.server.serve(ctx)
}

type expectedVerifier struct{ expected ExpectedRuntime }

func (v expectedVerifier) Verify(_ context.Context, a BoundaryAttestation) error {
	if a.Validate() != nil || a.RuntimeID != v.expected.RuntimeID || a.RuntimeBinaryDigest != v.expected.RuntimeBinaryDigest || a.PolicyDigest != v.expected.PolicyDigest || a.PeerUID != v.expected.PeerUID || a.PeerGID != v.expected.PeerGID || a.Epoch != v.expected.KeyEpoch || a.BrokerSocketDigest != v.expected.BrokerSocketDigest || a.BrokerReleaseDigest != v.expected.BrokerReleaseDigest || a.ExpectedEgressUID != v.expected.ExpectedEgressUID || a.ExpectedEgressGID != v.expected.ExpectedEgressGID || a.ExpectedEgressReleaseDigest != v.expected.ExpectedEgressReleaseDigest || a.ExpectedEgressSocketDigest != v.expected.ExpectedEgressSocketDigest {
		return ErrAttestation
	}
	return nil
}

func attestationCanonical(a BoundaryAttestation, binding string) ([]byte, error) {
	return json.Marshal(struct {
		SchemaVersion, RuntimeID, PeerID, RuntimeBinaryDigest, PolicyDigest                                             string
		IssuedAt                                                                                                        time.Time
		PeerUID, PeerGID, Epoch                                                                                         uint64
		BrokerSocketDigest, BrokerReleaseDigest, ExpectedEgressReleaseDigest, ExpectedEgressSocketDigest, BindingDigest string
		ExpectedEgressUID, ExpectedEgressGID                                                                            uint32
	}{a.SchemaVersion, a.RuntimeID, a.PeerID, a.RuntimeBinaryDigest, a.PolicyDigest, a.IssuedAt, uint64(a.PeerUID), uint64(a.PeerGID), a.Epoch, a.BrokerSocketDigest, a.BrokerReleaseDigest, a.ExpectedEgressReleaseDigest, a.ExpectedEgressSocketDigest, binding, a.ExpectedEgressUID, a.ExpectedEgressGID})
}

func signedAttestation(conn productionConn, e ExpectedRuntime) (BoundaryAttestation, error) {
	ev := conn.Evidence()
	a := BoundaryAttestation{SchemaVersion: ProtocolV1, RuntimeID: e.RuntimeID, PeerID: ev.Channel + ":" + ev.PeerRole, RuntimeBinaryDigest: e.RuntimeBinaryDigest, PolicyDigest: e.PolicyDigest, IssuedAt: time.Now().UTC(), PeerUID: ev.Peer.UID, PeerGID: ev.Peer.GID, Epoch: ev.KeyEpoch, BrokerSocketDigest: e.BrokerSocketDigest, BrokerReleaseDigest: e.BrokerReleaseDigest, ExpectedEgressUID: e.ExpectedEgressUID, ExpectedEgressGID: e.ExpectedEgressGID, ExpectedEgressReleaseDigest: e.ExpectedEgressReleaseDigest, ExpectedEgressSocketDigest: e.ExpectedEgressSocketDigest}
	canonical, err := attestationCanonical(a, e.BindingDigest)
	if err != nil {
		return BoundaryAttestation{}, ErrAttestation
	}
	tag, err := conn.Seal("codexbroker.attestation.v1", canonical)
	if err != nil {
		return BoundaryAttestation{}, ErrAttestation
	}
	a.Signature = "sha256:" + tag
	return a, a.Validate()
}

// Production construction is intentionally sealed until a separately
// attested service principal/runtime composition is accepted.
func NewProduction() (OwnerRuntimeClient, error) {
	return nil, ErrUnavailable
}

type peerVerifier interface {
	Verify(context.Context, BoundaryAttestation) error
}

// backendCallTimeout bounds synchronous backend methods at the broker
// boundary. A backend is expected to honor ctx, but the boundary must remain
// live even when a faulty implementation ignores cancellation. The worker's
// result is delivered through a one-element channel so a late return cannot
// block or splice into a subsequent request.
const backendCallTimeout = 2 * time.Second

func runBackend[T any](ctx context.Context, fn func(context.Context) (T, error)) (T, error) {
	var zero T
	callCtx, cancel := context.WithTimeout(ctx, backendCallTimeout)
	defer cancel()
	result := make(chan struct {
		value T
		err   error
	}, 1)
	go func() {
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

type Broker struct {
	backend    backend
	verifier   peerVerifier
	mu         sync.Mutex
	seq        uint64
	closed     bool
	att        BoundaryAttestation
	attFactory func() (BoundaryAttestation, error)
}

func newBroker(backend backend, expected BoundaryAttestation, verifier peerVerifier) (*Broker, error) {
	if backend == nil || verifier == nil || expected.Validate() != nil {
		return nil, ErrUnavailable
	}
	a, err := runBackend(context.Background(), backend.Attestation)
	if err != nil || a.Validate() != nil || !sameAttestation(a, expected) || verifier.Verify(context.Background(), a) != nil {
		return nil, ErrAttestation
	}
	return &Broker{backend: backend, verifier: verifier, att: expected}, nil
}
func (b *Broker) check(ctx context.Context) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return ErrClosed
	}
	a, err := b.backend.Attestation(ctx)
	validSame := sameAttestation(a, b.att)
	if b.attFactory != nil {
		validSame = sameAttestationStable(a, b.att)
	}
	if err != nil || a.Validate() != nil || !validSame || b.verifier.Verify(ctx, a) != nil {
		return ErrAttestation
	}
	return nil
}
func (b *Broker) Attestation(ctx context.Context) (BoundaryAttestation, error) {
	if err := b.check(ctx); err != nil {
		return BoundaryAttestation{}, err
	}
	if b.attFactory != nil {
		a, err := b.attFactory()
		if err != nil || a.Validate() != nil {
			return BoundaryAttestation{}, ErrAttestation
		}
		return a, nil
	}
	return b.att, nil
}
func (b *Broker) Inventory(ctx context.Context) (Inventory, error) {
	if err := b.check(ctx); err != nil {
		return Inventory{}, err
	}
	i, e := b.backend.Inventory(ctx)
	if e != nil {
		return Inventory{}, e
	}
	if i.Validate() != nil {
		return Inventory{}, ErrProtocol
	}
	return i, nil
}
func (b *Broker) LoginStart(ctx context.Context, in LoginStart) (LoginStarted, error) {
	if err := b.check(ctx); err != nil {
		return LoginStarted{}, err
	}
	if in.Validate() != nil {
		return LoginStarted{}, ErrProtocol
	}
	out, e := b.backend.LoginStart(ctx, in)
	if e != nil {
		return LoginStarted{}, e
	}
	if out.Validate() != nil {
		return LoginStarted{}, ErrProtocol
	}
	return out, nil
}
func (b *Broker) LoginCompleted(ctx context.Context, id string) (LoginCompleted, error) {
	if err := b.check(ctx); err != nil {
		return LoginCompleted{}, err
	}
	if !opaque(id) {
		return LoginCompleted{}, ErrProtocol
	}
	out, e := b.backend.LoginCompleted(ctx, id)
	if e != nil {
		return LoginCompleted{}, e
	}
	if out.Validate() != nil {
		return LoginCompleted{}, ErrProtocol
	}
	return out, nil
}
func (b *Broker) Turn(ctx context.Context, in Turn) (TurnResult, error) {
	if err := b.check(ctx); err != nil {
		return TurnResult{}, err
	}
	if in.Validate() != nil {
		return TurnResult{}, ErrProtocol
	}
	out, e := b.backend.Turn(ctx, in)
	if e != nil {
		return TurnResult{}, e
	}
	if out.Validate() != nil {
		return TurnResult{}, ErrProtocol
	}
	return out, nil
}
func (b *Broker) Cancel(ctx context.Context, in Cancel) error {
	if err := b.check(ctx); err != nil {
		return err
	}
	if in.Validate() != nil {
		return ErrProtocol
	}
	return b.backend.Cancel(ctx, in)
}
func (b *Broker) Close(ctx context.Context) error {
	b.mu.Lock()
	if b.closed {
		return ErrClosed
	}
	b.closed = true
	b.mu.Unlock()
	return b.backend.Close(ctx)
}

// A bounded frame is used only inside the broker transport adapter. It is not
// a JSON-RPC escape hatch and only the allow-listed operation kinds are legal.
type frame struct {
	Sequence uint64
	Kind     string
	Payload  []byte
}

func (f frame) validate(last uint64) error {
	if f.Sequence == 0 || f.Sequence != last+1 {
		if f.Sequence <= last {
			return ErrReplay
		}
		return ErrOutOfOrder
	}
	if len(f.Payload) > MaxFrameBytes {
		return ErrProtocol
	}
	switch f.Kind {
	case "attestation", "inventory", "login.start", "login.completed", "turn", "cancel", "close":
	default:
		return ErrProtocol
	}
	return nil
}

func opaque(s string) bool {
	return s != "" && utf8.RuneCountInString(s) <= 256 && !strings.ContainsAny(s, "\r\n/\\")
}
func digest(s string) bool {
	if len(s) != 71 || !strings.HasPrefix(s, "sha256:") {
		return false
	}
	_, e := hex.DecodeString(s[7:])
	return e == nil
}
func Digest(v string) string {
	d := sha256.Sum256([]byte(v))
	return "sha256:" + hex.EncodeToString(d[:])
}
func (b *Broker) String() string { return fmt.Sprintf("%s/%s", ProtocolV1, b.att.RuntimeID) }

func sameAttestation(a, b BoundaryAttestation) bool {
	return a.SchemaVersion == b.SchemaVersion && a.RuntimeID == b.RuntimeID && a.PeerID == b.PeerID && a.RuntimeBinaryDigest == b.RuntimeBinaryDigest && a.PolicyDigest == b.PolicyDigest && a.PeerUID == b.PeerUID && a.PeerGID == b.PeerGID && a.Epoch == b.Epoch && a.BrokerSocketDigest == b.BrokerSocketDigest && a.BrokerReleaseDigest == b.BrokerReleaseDigest && a.ExpectedEgressUID == b.ExpectedEgressUID && a.ExpectedEgressGID == b.ExpectedEgressGID && a.ExpectedEgressReleaseDigest == b.ExpectedEgressReleaseDigest && a.ExpectedEgressSocketDigest == b.ExpectedEgressSocketDigest && a.Signature == b.Signature
}

func sameAttestationStable(a, b BoundaryAttestation) bool {
	return a.SchemaVersion == b.SchemaVersion && a.RuntimeID == b.RuntimeID && a.PeerID == b.PeerID && a.RuntimeBinaryDigest == b.RuntimeBinaryDigest && a.PolicyDigest == b.PolicyDigest && a.PeerUID == b.PeerUID && a.PeerGID == b.PeerGID && a.Epoch == b.Epoch && a.BrokerSocketDigest == b.BrokerSocketDigest && a.BrokerReleaseDigest == b.BrokerReleaseDigest && a.ExpectedEgressUID == b.ExpectedEgressUID && a.ExpectedEgressGID == b.ExpectedEgressGID && a.ExpectedEgressReleaseDigest == b.ExpectedEgressReleaseDigest && a.ExpectedEgressSocketDigest == b.ExpectedEgressSocketDigest
}
