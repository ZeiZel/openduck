// Package codexruntimewire owns the one-way broker-to-runtime grant preface.
//
// The preface is deliberately sent before the typed Codex broker protocol. It
// carries the sole child-facing egress credential, sealed to the authenticated
// runtime channel.  The runtime can verify and consume it but cannot issue or
// renew it: there is no constructor from a token or a capability in this
// package.
package codexruntimewire

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"strings"
	"time"

	"openduck/internal/macoschannel"
	"openduck/internal/modelegress"
)

const (
	ProtocolV1   = "openduck.broker-runtime.v1"
	grantDomain  = "openduck.broker-runtime.proxy-grant.v1"
	maxGrantSize = 4096
	grantTTL     = 25 * time.Second
)

var ErrGrant = errors.New("invalid broker runtime proxy grant")

// ProxyGrant is intentionally short-lived, exact-channel-bound and
// non-renewable. ProxyURL is the only secret-bearing value and is never
// returned by this package after it has been written to the authenticated
// runtime connection.
type ProxyGrant struct {
	Version       string    `json:"version"`
	Channel       string    `json:"channel"`
	BindingDigest string    `json:"binding_digest"`
	BrokerUID     uint32    `json:"broker_uid"`
	BrokerGID     uint32    `json:"broker_gid"`
	RuntimeUID    uint32    `json:"runtime_uid"`
	RuntimeGID    uint32    `json:"runtime_gid"`
	IssuedAt      time.Time `json:"issued_at"`
	ExpiresAt     time.Time `json:"expires_at"`
	ProxyURL      string    `json:"proxy_url"`
	Tag           string    `json:"tag"`
}

func digest(v string) bool {
	if len(v) != 71 || !strings.HasPrefix(v, "sha256:") {
		return false
	}
	_, err := hex.DecodeString(v[7:])
	return err == nil
}

func validProxyURL(v string) bool {
	u, err := url.Parse(v)
	if err != nil || u.Scheme != "http" || u.Host != "127.0.0.1:8790" || u.User == nil || u.User.Username() != "openduck" {
		return false
	}
	p, ok := u.User.Password()
	return ok && len(p) == 64 && !strings.ContainsAny(v, "\r\n")
}

func (g ProxyGrant) canonical() ([]byte, error) {
	if g.Version != ProtocolV1 || g.Channel == "" || !digest(g.BindingDigest) || g.BrokerUID == 0 || g.BrokerGID == 0 || g.RuntimeUID == 0 || g.RuntimeGID == 0 || g.BrokerUID == g.RuntimeUID || g.IssuedAt.IsZero() || g.ExpiresAt.IsZero() || !g.ExpiresAt.After(g.IssuedAt) || g.ExpiresAt.Sub(g.IssuedAt) > grantTTL || !validProxyURL(g.ProxyURL) {
		return nil, ErrGrant
	}
	return json.Marshal(struct {
		Version, Channel, BindingDigest string
		BrokerUID, BrokerGID            uint32
		RuntimeUID, RuntimeGID          uint32
		IssuedAt, ExpiresAt             time.Time
		ProxyURL                        string
	}{g.Version, g.Channel, g.BindingDigest, g.BrokerUID, g.BrokerGID, g.RuntimeUID, g.RuntimeGID, g.IssuedAt.UTC(), g.ExpiresAt.UTC(), g.ProxyURL})
}

func (g ProxyGrant) validate(now time.Time, ev macoschannel.Evidence, localRuntime bool) error {
	if _, err := g.canonical(); err != nil || g.Tag == "" || now.Before(g.IssuedAt.Add(-time.Minute)) || !now.Before(g.ExpiresAt) {
		return ErrGrant
	}
	if ev.Channel != g.Channel || ev.BindingDigest != g.BindingDigest {
		return ErrGrant
	}
	if localRuntime {
		if ev.Local.UID != g.RuntimeUID || ev.Local.GID != g.RuntimeGID || ev.Peer.UID != g.BrokerUID || ev.Peer.GID != g.BrokerGID {
			return ErrGrant
		}
	} else if ev.Local.UID != g.BrokerUID || ev.Local.GID != g.BrokerGID || ev.Peer.UID != g.RuntimeUID || ev.Peer.GID != g.RuntimeGID {
		return ErrGrant
	}
	return nil
}

// Issue obtains the proxy token only from the broker-owned opaque capability,
// binds it to the exact authenticated connection, and seals it for the
// runtime. Neither runtime code nor callers can construct an equivalent grant.
func Issue(conn macoschannel.Conn, cap modelegress.ProductionCapability, brokerUID, brokerGID, runtimeUID, runtimeGID uint32, now time.Time) (ProxyGrant, error) {
	if conn == nil || cap == nil || brokerUID == 0 || brokerGID == 0 || runtimeUID == 0 || runtimeGID == 0 || brokerUID == runtimeUID {
		return ProxyGrant{}, ErrGrant
	}
	ev := conn.Evidence()
	if ev.Local.UID != brokerUID || ev.Local.GID != brokerGID || ev.Peer.UID != runtimeUID || ev.Peer.GID != runtimeGID || ev.Channel == "" || !digest(ev.BindingDigest) {
		return ProxyGrant{}, ErrGrant
	}
	proxyURL, err := modelegress.ProxyURL(cap, "127.0.0.1:8790")
	if err != nil {
		return ProxyGrant{}, ErrGrant
	}
	g := ProxyGrant{Version: ProtocolV1, Channel: ev.Channel, BindingDigest: ev.BindingDigest, BrokerUID: brokerUID, BrokerGID: brokerGID, RuntimeUID: runtimeUID, RuntimeGID: runtimeGID, IssuedAt: now.UTC(), ExpiresAt: now.UTC().Add(grantTTL), ProxyURL: proxyURL}
	b, err := g.canonical()
	if err != nil {
		return ProxyGrant{}, err
	}
	g.Tag, err = conn.Seal(grantDomain, b)
	if err != nil {
		return ProxyGrant{}, ErrGrant
	}
	return g, nil
}

// WriteGrant is one-shot. A second grant would be renewal authority, so the
// runtime service rejects it by consuming exactly one preface per connection.
func WriteGrant(ctx context.Context, conn macoschannel.Conn, g ProxyGrant) error {
	if conn == nil || ctx == nil || g.validate(time.Now().UTC(), conn.Evidence(), false) != nil {
		return ErrGrant
	}
	b, err := json.Marshal(g)
	if err != nil || len(b) > maxGrantSize {
		return ErrGrant
	}
	if err = conn.SetWriteDeadline(deadline(ctx)); err != nil {
		return err
	}
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(b)))
	if _, err = conn.Write(n[:]); err != nil {
		return err
	}
	_, err = conn.Write(b)
	return err
}

// ReadGrant verifies the broker-origin MAC and exact kernel/channel identity.
// It does not expose a mint/renew operation to the runtime.
func ReadGrant(ctx context.Context, conn macoschannel.Conn) (ProxyGrant, error) {
	if conn == nil || ctx == nil {
		return ProxyGrant{}, ErrGrant
	}
	if err := conn.SetReadDeadline(deadline(ctx)); err != nil {
		return ProxyGrant{}, err
	}
	r := bufio.NewReaderSize(conn, maxGrantSize+4)
	var n [4]byte
	if _, err := io.ReadFull(r, n[:]); err != nil || binary.BigEndian.Uint32(n[:]) == 0 || binary.BigEndian.Uint32(n[:]) > maxGrantSize {
		return ProxyGrant{}, ErrGrant
	}
	b := make([]byte, binary.BigEndian.Uint32(n[:]))
	if _, err := io.ReadFull(r, b); err != nil {
		return ProxyGrant{}, ErrGrant
	}
	var g ProxyGrant
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if dec.Decode(&g) != nil || dec.Decode(&struct{}{}) != io.EOF || g.validate(time.Now().UTC(), conn.Evidence(), true) != nil {
		return ProxyGrant{}, ErrGrant
	}
	canonical, err := g.canonical()
	if err != nil || conn.Verify(grantDomain, canonical, g.Tag) != nil {
		return ProxyGrant{}, ErrGrant
	}
	return g, nil
}

func deadline(ctx context.Context) time.Time {
	if d, ok := ctx.Deadline(); ok {
		return d
	}
	return time.Now().Add(5 * time.Second)
}

// BindingDigest is useful to deployment composition without leaking a proxy
// grant. It accepts no mutable channel metadata.
func BindingDigest(ev macoschannel.Evidence) string {
	if ev.Channel == "" || ev.BindingDigest == "" {
		return ""
	}
	s := sha256.Sum256([]byte(ev.Channel + "|" + ev.BindingDigest))
	return "sha256:" + hex.EncodeToString(s[:])
}
