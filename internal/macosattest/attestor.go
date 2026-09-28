// Package macosattest verifies privileged, kernel-derived provider runtime
// observations. It never treats a pathname or the contents of an inactive
// installed file as evidence about a running process.
package macosattest

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"openduck/internal/macoschannel"
	"openduck/internal/readiness"
)

var ErrUnavailable = errors.New("provider runtime attestation unavailable")

type Process struct {
	PID                 int
	ParentPID           int
	StartSec, StartUsec int64
	UID, GID            uint32
	CDHash              [20]byte
}

// VerifyAuthenticated accepts only macoschannel.Conn, a sealed interface that
// can be constructed only after LOCAL_PEERCRED and transcript authentication.
func VerifyAuthenticated(b Binding, conn macoschannel.Conn) (readiness.LiveProvider, error) {
	if conn == nil {
		return readiness.LiveProvider{}, ErrUnavailable
	}
	ev := conn.Evidence()
	b.Peer = Peer{UID: ev.Peer.UID, GID: ev.Peer.GID, Authenticated: ev.BindingDigest != ""}
	return Verify(b)
}

func (p Process) StartIdentity() string {
	return fmt.Sprintf("darwin-start:%d:%d:%d", p.PID, p.StartSec, p.StartUsec)
}
func (p Process) ImageIdentity() string {
	sum := sha256.Sum256(append([]byte("darwin-cdhash-v1\x00"), p.CDHash[:]...))
	return "sha256:" + hex.EncodeToString(sum[:])
}

type Peer struct {
	UID, GID      uint32
	Authenticated bool
}

type Binding struct {
	Provider, JobLabel                        string
	Before, After                             Process
	Peer                                      Peer
	ExpectedUID, ExpectedGID, ExpectedPeerGID uint32
	Evidence                                  readiness.ProviderEvidence
}

// Verify requires two kernel samples surrounding the launchd lookup. Equality
// of PID and kernel start time defeats PID reuse/restart; equality of CDHash
// defeats pathname substitution. Peer credentials must come from
// LOCAL_PEERCRED on the authenticated controller connection.
func Verify(b Binding) (readiness.LiveProvider, error) {
	if b.Provider == "" || b.JobLabel == "" || b.Before.PID <= 0 || b.Before != b.After || b.Before.UID != b.ExpectedUID || b.Before.GID != b.ExpectedGID || !b.Peer.Authenticated || b.Peer.GID != b.ExpectedPeerGID || b.Evidence.Provider != b.Provider || b.Evidence.JobLabel != b.JobLabel || b.Evidence.PID != b.Before.PID || b.Evidence.StartIdentity != b.Before.StartIdentity() || b.Evidence.ExecutingImageIdentity != b.Before.ImageIdentity() {
		return readiness.LiveProvider{}, ErrUnavailable
	}
	return readiness.LiveProvider{Provider: b.Provider, JobLabel: b.JobLabel, PID: b.Before.PID, Running: true, StartIdentity: b.Before.StartIdentity(), ExecutingImageIdentity: b.Before.ImageIdentity(), ServiceUser: b.Evidence.ServiceUser, ServiceGroup: b.Evidence.ServiceGroup, ChannelPeerGroup: b.Evidence.ChannelPeerGroup, ChannelPeerAuthenticated: true}, nil
}
