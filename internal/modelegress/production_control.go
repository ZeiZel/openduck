package modelegress

// Production control is the narrow authenticated seam between the model-only
// egress service and its broker.  It deliberately carries no proxy address,
// credentials, or arbitrary command: the only useful result is a capability
// bound to the exact authenticated channel and release policy.

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"

	"openduck/internal/macoschannel"
)

var (
	ErrControlUnavailable = errors.New("model egress control unavailable")
	ErrControlProtocol    = errors.New("model egress control protocol violation")
)

const controlProtocolV1 = "model-egress-control.v1"

// ControlExpectation is an immutable comparison target.  It is not a
// capability and cannot be used to bypass macoschannel authentication.
type ControlExpectation struct {
	Policy       Policy
	Channel      string
	LocalRole    string
	PeerRole     string
	LocalUID     uint32
	LocalGID     uint32
	PeerUID      uint32
	PeerGID      uint32
	LocalRelease macoschannel.ReleasePin
	PeerRelease  macoschannel.ReleasePin
	Epoch        uint64
	ProxyAddress string
}

func (e ControlExpectation) Validate() error {
	if e.Policy.Validate() != nil || e.Channel == "" || e.LocalRole == "" || e.PeerRole == "" || e.LocalRole == e.PeerRole || e.LocalUID == 0 || e.LocalGID == 0 || e.PeerUID == 0 || e.PeerGID == 0 || e.LocalUID != e.Policy.ProxyUID || e.LocalGID != e.Policy.ProxyGID || e.Epoch == 0 || e.Policy.Epoch != e.Epoch || e.LocalUID == e.PeerUID {
		return ErrControlUnavailable
	}
	return nil
}

func releaseDigest(pin macoschannel.ReleasePin, manifest bool) string {
	if manifest {
		return "sha256:" + pin.ManifestDigest
	}
	return "sha256:" + pin.SocketDigest
}

func (e ControlExpectation) verify(conn macoschannel.Conn) error {
	if conn == nil || e.Validate() != nil {
		return ErrControlUnavailable
	}
	ev := conn.Evidence()
	if ev.Channel != e.Channel || ev.LocalRole != e.LocalRole || ev.PeerRole != e.PeerRole || ev.KeyEpoch != e.Epoch || ev.Local.UID != e.LocalUID || ev.Local.GID != e.LocalGID || ev.Peer.UID != e.PeerUID || ev.Peer.GID != e.PeerGID || ev.LocalRelease != e.LocalRelease || ev.PeerRelease != e.PeerRelease {
		return ErrControlUnavailable
	}
	if e.Policy.ReleaseDigest != releaseDigest(e.LocalRelease, true) || e.Policy.SocketDigest != releaseDigest(e.LocalRelease, false) {
		return ErrControlUnavailable
	}
	return nil
}

type controlFrame struct {
	Version   string             `json:"version"`
	Kind      string             `json:"kind"`
	Nonce     string             `json:"nonce,omitempty"`
	SessionID string             `json:"session_id,omitempty"`
	Receipt   *CapabilityReceipt `json:"receipt,omitempty"`
}

// CapabilityReceipt is the only value crossing the egress/broker process
// boundary. Tag is a macoschannel transcript MAC; the receipt is fresh and
// channel-bound, so an in-memory capability is never shared between daemons.
type CapabilityReceipt struct {
	Version       string    `json:"version"`
	Channel       string    `json:"channel"`
	PolicyDigest  string    `json:"policy_digest"`
	ReleaseDigest string    `json:"release_digest"`
	SocketDigest  string    `json:"socket_digest"`
	ProxyAddress  string    `json:"proxy_address"`
	EgressUID     uint32    `json:"egress_uid"`
	EgressGID     uint32    `json:"egress_gid"`
	BrokerUID     uint32    `json:"broker_uid"`
	BrokerGID     uint32    `json:"broker_gid"`
	Epoch         uint64    `json:"epoch"`
	IssuedAt      time.Time `json:"issued_at"`
	Nonce         string    `json:"nonce"`
	SessionID     string    `json:"session_id"`
	ProxyToken    string    `json:"proxy_token"`
	Tag           string    `json:"tag"`
}

func (r CapabilityReceipt) canonical() ([]byte, error) {
	return json.Marshal(struct {
		Version, Channel, PolicyDigest, ReleaseDigest, SocketDigest, ProxyAddress string
		EgressUID, EgressGID, BrokerUID, BrokerGID                                uint32
		Epoch                                                                     uint64
		IssuedAt                                                                  time.Time
		Nonce, SessionID, ProxyToken                                              string
	}{r.Version, r.Channel, r.PolicyDigest, r.ReleaseDigest, r.SocketDigest, r.ProxyAddress, r.EgressUID, r.EgressGID, r.BrokerUID, r.BrokerGID, r.Epoch, r.IssuedAt, r.Nonce, r.SessionID, r.ProxyToken})
}

func (r CapabilityReceipt) validateFresh(now time.Time) error {
	if r.Version != controlProtocolV1 || r.Channel == "" || r.PolicyDigest == "" || r.ReleaseDigest == "" || r.SocketDigest == "" || r.ProxyAddress == "" || r.EgressUID == 0 || r.EgressGID == 0 || r.BrokerUID == 0 || r.BrokerGID == 0 || r.Epoch == 0 || r.Nonce == "" || r.SessionID == "" || len(r.SessionID) > 256 || !validProxyToken(r.ProxyToken) || r.Tag == "" || now.Sub(r.IssuedAt) > 30*time.Second || r.IssuedAt.Sub(now) > time.Minute {
		return ErrControlProtocol
	}
	return nil
}

func writeControl(w io.Writer, f controlFrame) error {
	if !validControlFrame(f) {
		return ErrControlProtocol
	}
	b, err := json.Marshal(f)
	if err != nil || len(b) > 1024 {
		return ErrControlProtocol
	}
	b = append(b, '\n')
	_, err = w.Write(b)
	return err
}

func readControl(r *bufio.Reader) (controlFrame, error) {
	b, err := r.ReadBytes('\n')
	if err != nil || len(b) > 1024 {
		return controlFrame{}, ErrControlProtocol
	}
	var f controlFrame
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if dec.Decode(&f) != nil || !validControlFrame(f) {
		return controlFrame{}, ErrControlProtocol
	}
	return f, nil
}

func validControlFrame(f controlFrame) bool {
	if f.Version != controlProtocolV1 || (f.Kind != "ready" && f.Kind != "probe" && f.Kind != "revoke" && f.Kind != "revoked") {
		return false
	}
	if (f.Kind == "probe" || f.Kind == "revoke") && (f.Nonce == "" || f.SessionID == "" || len(f.SessionID) > 256) {
		return false
	}
	return (f.Kind != "ready" || f.Receipt != nil) && (f.Kind != "revoked" || f.SessionID != "")
}

// AuthenticatedControlServer owns the egress capability.  The capability is
// issued only after exact kernel peer, channel, release, policy and epoch
// evidence has been checked.
type AuthenticatedControlServer struct {
	conn     macoschannel.Conn
	cap      ProductionCapability
	expected ControlExpectation
}

func NewAuthenticatedControlServer(conn macoschannel.Conn, expected ControlExpectation) (*AuthenticatedControlServer, error) {
	if err := expected.verify(conn); err != nil {
		return nil, err
	}
	token, err := newProxyToken()
	if err != nil {
		return nil, err
	}
	cap, err := issueCapabilityWithToken(expected.Policy, token)
	if err != nil {
		return nil, err
	}
	return &AuthenticatedControlServer{conn: conn, cap: cap, expected: expected}, nil
}

func mustPolicyDigest(p Policy) string { d, _ := p.Digest(); return d }

func (s *AuthenticatedControlServer) Capability() ProductionCapability {
	if s == nil {
		return nil
	}
	return s.cap
}

func (s *AuthenticatedControlServer) Serve(ctx context.Context) error {
	return s.serve(ctx, nil)
}

// ServeWithRegistry is the production control path. It publishes a capability
// only under the caller-provided exact runtime session id, and accepts an
// authenticated revoke for that same id.
func (s *AuthenticatedControlServer) ServeWithRegistry(ctx context.Context, registry *CapabilityRegistry) error {
	if registry == nil {
		return ErrControlUnavailable
	}
	return s.serve(ctx, registry)
}

func (s *AuthenticatedControlServer) serve(ctx context.Context, registry *CapabilityRegistry) error {
	if s == nil || s.conn == nil || s.cap == nil {
		return ErrControlUnavailable
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := s.conn.SetReadDeadline(deadline(ctx)); err != nil {
		return err
	}
	f, err := readControl(bufio.NewReader(s.conn))
	if err != nil {
		return err
	}
	if f.Kind == "revoke" {
		if registry == nil {
			return ErrControlProtocol
		}
		registry.RemoveSession(f.SessionID)
		return writeControl(s.conn, controlFrame{Version: controlProtocolV1, Kind: "revoked", SessionID: f.SessionID})
	}
	if f.Kind != "probe" {
		return ErrControlProtocol
	}
	if f.Nonce == "" {
		return ErrControlProtocol
	}
	cap := s.cap
	if registry != nil {
		cap, err = registry.Register(f.SessionID, s.cap, time.Now().UTC())
		if err != nil {
			return err
		}
	}
	token, err := proxyToken(cap)
	if err != nil {
		return err
	}
	r := CapabilityReceipt{Version: controlProtocolV1, Channel: s.expected.Channel, PolicyDigest: mustPolicyDigest(s.expected.Policy), ReleaseDigest: s.expected.Policy.ReleaseDigest, SocketDigest: s.expected.Policy.SocketDigest, ProxyAddress: s.expected.ProxyAddress, EgressUID: s.expected.LocalUID, EgressGID: s.expected.LocalGID, BrokerUID: s.expected.PeerUID, BrokerGID: s.expected.PeerGID, Epoch: s.expected.Epoch, IssuedAt: time.Now().UTC(), Nonce: f.Nonce, SessionID: f.SessionID, ProxyToken: token}
	canonical, err := r.canonical()
	if err != nil {
		return err
	}
	r.Tag, err = s.conn.Seal("modelegress.receipt.v1", canonical)
	if err != nil {
		return err
	}
	return writeControl(s.conn, controlFrame{Version: controlProtocolV1, Kind: "ready", Receipt: &r})
}

// AuthenticatedControlClient is a receipt-only peer.  It cannot mint or
// receive the server's capability, preserving the one-way authority boundary.
type AuthenticatedControlClient struct{ conn macoschannel.Conn }

func NewAuthenticatedControlClient(conn macoschannel.Conn, expected ControlExpectation) (*AuthenticatedControlClient, error) {
	if err := expected.verify(conn); err != nil {
		return nil, err
	}
	return &AuthenticatedControlClient{conn: conn}, nil
}

// NewAuthenticatedControlClientForPeer is the broker-side constructor. The
// expectation describes the egress server's local identity; the authenticated
// connection necessarily presents the reverse local/peer orientation.
func NewAuthenticatedControlClientForPeer(conn macoschannel.Conn, serverExpected ControlExpectation) (*AuthenticatedControlClient, error) {
	if conn == nil || serverExpected.Validate() != nil {
		return nil, ErrControlUnavailable
	}
	ev := conn.Evidence()
	if ev.Channel != serverExpected.Channel || ev.LocalRole != serverExpected.PeerRole || ev.PeerRole != serverExpected.LocalRole || ev.KeyEpoch != serverExpected.Epoch || ev.Local.UID != serverExpected.PeerUID || ev.Local.GID != serverExpected.PeerGID || ev.Peer.UID != serverExpected.LocalUID || ev.Peer.GID != serverExpected.LocalGID || ev.LocalRelease != serverExpected.PeerRelease || ev.PeerRelease != serverExpected.LocalRelease {
		return nil, ErrControlUnavailable
	}
	return &AuthenticatedControlClient{conn: conn}, nil
}

func (c *AuthenticatedControlClient) Probe(ctx context.Context) error {
	if c == nil || c.conn == nil {
		return ErrControlUnavailable
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := c.conn.SetDeadline(deadline(ctx)); err != nil {
		return err
	}
	challenge := make([]byte, 16)
	if _, err := rand.Read(challenge); err != nil {
		return err
	}
	challengeText := hex.EncodeToString(challenge)
	if err := writeControl(c.conn, controlFrame{Version: controlProtocolV1, Kind: "probe", Nonce: challengeText, SessionID: challengeText}); err != nil {
		return err
	}
	f, err := readControl(bufio.NewReader(c.conn))
	if err != nil || f.Kind != "ready" {
		return ErrControlProtocol
	}
	return nil
}

// ProbeCapability verifies the receipt MAC on this authenticated peer and
// mints a broker-local capability only after all receipt/evidence fields match.
func (c *AuthenticatedControlClient) ProbeCapability(ctx context.Context, policy Policy, serverExpected ControlExpectation) (ProductionCapability, error) {
	challenge := make([]byte, 16)
	if _, err := rand.Read(challenge); err != nil {
		return nil, err
	}
	return c.ProbeCapabilityForSession(ctx, policy, serverExpected, hex.EncodeToString(challenge))
}

// ProbeCapabilityForSession renews only one exact broker-runtime session.
func (c *AuthenticatedControlClient) ProbeCapabilityForSession(ctx context.Context, policy Policy, serverExpected ControlExpectation, sessionID string) (ProductionCapability, error) {
	if c == nil || c.conn == nil || policy.Validate() != nil || serverExpected.Validate() != nil || sessionID == "" || len(sessionID) > 256 {
		return nil, ErrControlUnavailable
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := c.conn.SetDeadline(deadline(ctx)); err != nil {
		return nil, err
	}
	challenge := make([]byte, 16)
	if _, err := rand.Read(challenge); err != nil {
		return nil, err
	}
	challengeText := hex.EncodeToString(challenge)
	if err := writeControl(c.conn, controlFrame{Version: controlProtocolV1, Kind: "probe", Nonce: challengeText, SessionID: sessionID}); err != nil {
		return nil, err
	}
	f, err := readControl(bufio.NewReader(c.conn))
	if err != nil || f.Kind != "ready" || f.Receipt == nil {
		return nil, ErrControlProtocol
	}
	r := *f.Receipt
	if r.Nonce != challengeText || r.SessionID != sessionID {
		return nil, ErrControlProtocol
	}
	now := time.Now().UTC()
	if r.validateFresh(now) != nil || r.PolicyDigest != mustPolicyDigest(policy) || r.ReleaseDigest != policy.ReleaseDigest || r.SocketDigest != policy.SocketDigest || r.ProxyAddress != serverExpected.ProxyAddress || r.Channel != serverExpected.Channel || r.EgressUID != serverExpected.LocalUID || r.EgressGID != serverExpected.LocalGID || r.BrokerUID != serverExpected.PeerUID || r.BrokerGID != serverExpected.PeerGID || r.Epoch != serverExpected.Epoch {
		return nil, ErrControlUnavailable
	}
	ev := c.conn.Evidence()
	if ev.Channel != r.Channel || ev.Peer.UID != r.EgressUID || ev.Peer.GID != r.EgressGID || ev.Local.UID != r.BrokerUID || ev.Local.GID != r.BrokerGID || ev.KeyEpoch != r.Epoch {
		return nil, ErrControlUnavailable
	}
	canonical, err := r.canonical()
	if err != nil || c.conn.Verify("modelegress.receipt.v1", canonical, r.Tag) != nil {
		return nil, ErrControlUnavailable
	}
	return issueCapabilityWithToken(policy, r.ProxyToken)
}

func (c *AuthenticatedControlClient) RevokeSession(ctx context.Context, sessionID string) error {
	if c == nil || c.conn == nil || sessionID == "" || len(sessionID) > 256 {
		return ErrControlUnavailable
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := c.conn.SetDeadline(deadline(ctx)); err != nil {
		return err
	}
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	if err := writeControl(c.conn, controlFrame{Version: controlProtocolV1, Kind: "revoke", Nonce: hex.EncodeToString(nonce), SessionID: sessionID}); err != nil {
		return err
	}
	f, err := readControl(bufio.NewReader(c.conn))
	if err != nil || f.Kind != "revoked" || f.SessionID != sessionID {
		return ErrControlProtocol
	}
	return nil
}

func deadline(ctx context.Context) (d time.Time) {
	if d, ok := ctx.Deadline(); ok {
		return d
	}
	return time.Now().Add(10 * time.Second)
}
