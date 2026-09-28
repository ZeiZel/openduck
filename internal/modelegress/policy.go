package modelegress

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"regexp"
	"sort"
	"strings"
)

const PolicyVersion = "model-egress.v1"

var (
	ErrInvalidPolicy = errors.New("invalid model egress policy")
	ErrDenied        = errors.New("model egress denied")
	ErrNoCapability  = errors.New("production egress capability unavailable")
	ErrOSEnforcement = errors.New("model egress OS enforcement required")
)

type Policy struct {
	Version       string   `json:"version"`
	AllowedHosts  []string `json:"allowed_hosts"`
	Port          uint16   `json:"port"`
	ProxyUID      uint32   `json:"proxy_uid"`
	ProxyGID      uint32   `json:"proxy_gid"`
	ReleaseDigest string   `json:"release_digest"`
	SocketDigest  string   `json:"socket_digest"`
	Epoch         uint64   `json:"epoch"`
}

type canonicalPolicy struct {
	Version string   `json:"version"`
	Hosts   []string `json:"allowed_hosts"`
	Port    uint16   `json:"port"`
	UID     uint32   `json:"proxy_uid"`
	GID     uint32   `json:"proxy_gid"`
	Release string   `json:"release_digest"`
	Socket  string   `json:"socket_digest"`
	Epoch   uint64   `json:"epoch"`
}

var fqdnLabel = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

func NewPolicy(hosts []string, uid, gid uint32, releaseDigest, socketDigest string, epoch uint64) (Policy, error) {
	if len(hosts) == 0 || uid == 0 || gid == 0 || epoch == 0 || !validDigest(releaseDigest) || !validDigest(socketDigest) {
		return Policy{}, ErrInvalidPolicy
	}
	copyHosts := append([]string(nil), hosts...)
	for i, host := range copyHosts {
		if !validFQDN(host) {
			return Policy{}, fmt.Errorf("%w: host %q", ErrInvalidPolicy, host)
		}
		copyHosts[i] = strings.ToLower(host)
	}
	sort.Strings(copyHosts)
	for i := 1; i < len(copyHosts); i++ {
		if copyHosts[i] == copyHosts[i-1] {
			return Policy{}, fmt.Errorf("%w: duplicate host", ErrInvalidPolicy)
		}
	}
	return Policy{Version: PolicyVersion, AllowedHosts: copyHosts, Port: 443, ProxyUID: uid, ProxyGID: gid, ReleaseDigest: releaseDigest, SocketDigest: socketDigest, Epoch: epoch}, nil
}

func (p Policy) Validate() error {
	if p.Version != PolicyVersion || p.Port != 443 || p.ProxyUID == 0 || p.ProxyGID == 0 || p.Epoch == 0 || len(p.AllowedHosts) == 0 || !validDigest(p.ReleaseDigest) || !validDigest(p.SocketDigest) {
		return ErrInvalidPolicy
	}
	prev := ""
	for _, h := range p.AllowedHosts {
		if !validFQDN(h) || h <= prev {
			return ErrInvalidPolicy
		}
		prev = h
	}
	return nil
}

func (p Policy) Canonical() ([]byte, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(canonicalPolicy{PolicyVersion, append([]string(nil), p.AllowedHosts...), 443, p.ProxyUID, p.ProxyGID, p.ReleaseDigest, p.SocketDigest, p.Epoch})
}

func (p Policy) Digest() (string, error) {
	b, err := p.Canonical()
	if err != nil {
		return "", err
	}
	s := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(s[:]), nil
}

func validDigest(s string) bool {
	if len(s) != 71 || !strings.HasPrefix(s, "sha256:") {
		return false
	}
	_, err := hex.DecodeString(s[7:])
	return err == nil
}

func validFQDN(s string) bool {
	if len(s) < 1 || len(s) > 253 || s != strings.ToLower(s) || strings.HasSuffix(s, ".") || net.ParseIP(s) != nil {
		return false
	}
	for _, l := range strings.Split(s, ".") {
		if len(l) > 63 || !fqdnLabel.MatchString(l) {
			return false
		}
	}
	return strings.Contains(s, ".")
}

func allowedHost(p Policy, host string) bool {
	host = strings.ToLower(host)
	for _, h := range p.AllowedHosts {
		if host == h {
			return true
		}
	}
	return false
}

// ProductionCapability is intentionally sealed. No value can be constructed by
// decoding policy metadata; only the authenticated composition package can issue it.
type ProductionCapability interface{ productionCapability() }
type capability struct {
	productionCapabilityMarker                struct{}
	policyDigest, releaseDigest, socketDigest string
	uid, gid                                  uint32
	epoch                                     uint64
	proxyToken                                string
}

func (capability) productionCapability() {}
func issueCapability(p Policy) (ProductionCapability, error) {
	return issueCapabilityWithToken(p, "")
}
func issueCapabilityWithToken(p Policy, token string) (ProductionCapability, error) {
	d, err := p.Digest()
	if err != nil {
		return nil, err
	}
	if token != "" && !validProxyToken(token) {
		return nil, ErrNoCapability
	}
	return capability{policyDigest: d, releaseDigest: p.ReleaseDigest, socketDigest: p.SocketDigest, uid: p.ProxyUID, gid: p.ProxyGID, epoch: p.Epoch, proxyToken: token}, nil
}
func verifyCapability(p Policy, c ProductionCapability) error {
	x, ok := c.(capability)
	if !ok {
		return ErrNoCapability
	}
	d, err := p.Digest()
	if err != nil || x.policyDigest != d || x.releaseDigest != p.ReleaseDigest || x.socketDigest != p.SocketDigest || x.uid != p.ProxyUID || x.gid != p.ProxyGID || x.epoch != p.Epoch {
		return ErrNoCapability
	}
	return nil
}

func newProxyToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
func validProxyToken(s string) bool {
	if len(s) != 64 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}
func proxyToken(c ProductionCapability) (string, error) {
	x, ok := c.(capability)
	if !ok || !validProxyToken(x.proxyToken) {
		return "", ErrNoCapability
	}
	return x.proxyToken, nil
}

// CapabilityBinding is metadata supplied by an authenticated runtime
// composition. It is only a comparison target; it cannot mint a capability.
type CapabilityBinding struct {
	PolicyDigest, ReleaseDigest, SocketDigest string
	UID, GID                                  uint32
	Epoch                                     uint64
}

func VerifyCapabilityBinding(b CapabilityBinding, c ProductionCapability) error {
	x, ok := c.(capability)
	if !ok || b.PolicyDigest == "" || x.policyDigest != b.PolicyDigest || x.releaseDigest != b.ReleaseDigest || x.socketDigest != b.SocketDigest || x.uid != b.UID || x.gid != b.GID || x.epoch != b.Epoch {
		return ErrNoCapability
	}
	return nil
}
