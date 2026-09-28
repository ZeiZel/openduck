package macosattest

import (
	"context"
	"net"
	"openduck/internal/nativemcp"
	"sync"
	"time"
)

type HostRegistration struct {
	Provider, PeerID, SessionID, ChannelID, ProfileID, RevisionID string
	Host                                                          Process
	ShimImageIdentity                                             string
	ShimUID, ShimGID                                              uint32
	ExpiresAt                                                     time.Time
}
type HostRegistry struct {
	mu       sync.RWMutex
	byHost   map[int]HostRegistration
	attested map[string]attestedShim
	now      func() time.Time
}

func NewHostRegistry(now func() time.Time) *HostRegistry {
	return &HostRegistry{byHost: map[int]HostRegistration{}, attested: map[string]attestedShim{}, now: now}
}
func (r *HostRegistry) Register(v HostRegistration) error {
	if r == nil || v.Provider == "" || v.PeerID == "" || v.SessionID == "" || v.ChannelID == "" || v.ProfileID == "" || v.RevisionID == "" || v.Host.PID <= 0 || v.ShimImageIdentity == "" || v.ExpiresAt.IsZero() {
		return ErrUnavailable
	}
	now, err := SampleProcess(v.Host.PID)
	if err != nil || now != v.Host {
		return ErrUnavailable
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.byHost[v.Host.PID]; exists {
		return ErrUnavailable
	}
	r.byHost[v.Host.PID] = v
	return nil
}
func (r *HostRegistry) Revoke(pid int) {
	if r != nil {
		r.mu.Lock()
		if v, ok := r.byHost[pid]; ok {
			delete(r.attested, v.Provider+"\x00"+v.PeerID)
		}
		delete(r.byHost, pid)
		r.mu.Unlock()
	}
}
func (r *HostRegistry) PeerFor(_ context.Context, conn net.Conn) (nativemcp.PeerIdentity, error) {
	if r == nil || conn == nil {
		return nativemcp.PeerIdentity{}, ErrUnavailable
	}
	shim, err := socketPeer(conn)
	if err != nil || shim.ParentPID <= 0 {
		return nativemcp.PeerIdentity{}, ErrUnavailable
	}
	r.mu.RLock()
	reg, ok := r.byHost[shim.ParentPID]
	r.mu.RUnlock()
	now := time.Now().UTC()
	if r.now != nil {
		now = r.now().UTC()
	}
	host, hostErr := SampleProcess(shim.ParentPID)
	if !ok || hostErr != nil || host != reg.Host || !now.Before(reg.ExpiresAt) || shim.UID != reg.ShimUID || shim.GID != reg.ShimGID || shim.ImageIdentity() != reg.ShimImageIdentity {
		return nativemcp.PeerIdentity{}, ErrUnavailable
	}
	r.mu.Lock()
	r.attested[reg.Provider+"\x00"+reg.PeerID] = attestedShim{registration: reg, shim: shim}
	r.mu.Unlock()
	return nativemcp.PeerIdentity{Provider: reg.Provider, PeerID: reg.PeerID}, nil
}

type attestedShim struct {
	registration HostRegistration
	shim         Process
}

type NativeSessionIdentity struct{ Provider, PeerID, ProfileID, SessionID, ChannelID, RevisionID string }

// RegistrationFor exposes no process metadata or authority. It returns only
// bounded lookup identity after revalidating the already-attested live shim,
// host start identity and expiry; Controller must still derive the contract
// from its durable association/endpoint/revision stores.
func (r *HostRegistry) RegistrationFor(peer nativemcp.PeerIdentity) (NativeSessionIdentity, error) {
	if r == nil {
		return NativeSessionIdentity{}, ErrUnavailable
	}
	r.mu.RLock()
	observed, ok := r.attested[peer.Provider+"\x00"+peer.PeerID]
	r.mu.RUnlock()
	now := time.Now().UTC()
	if r.now != nil {
		now = r.now().UTC()
	}
	host, hostErr := SampleProcess(observed.registration.Host.PID)
	shim, shimErr := SampleProcess(observed.shim.PID)
	if !ok || hostErr != nil || shimErr != nil || host != observed.registration.Host || shim != observed.shim || shim.ParentPID != host.PID || !now.Before(observed.registration.ExpiresAt) {
		return NativeSessionIdentity{}, ErrUnavailable
	}
	v := observed.registration
	return NativeSessionIdentity{Provider: v.Provider, PeerID: v.PeerID, ProfileID: v.ProfileID, SessionID: v.SessionID, ChannelID: v.ChannelID, RevisionID: v.RevisionID}, nil
}

func (r *HostRegistry) VerifyNativeMCPPeer(_ context.Context, contract nativemcp.SessionContract, peer nativemcp.PeerIdentity) error {
	if r == nil {
		return ErrUnavailable
	}
	r.mu.RLock()
	observed, ok := r.attested[peer.Provider+"\x00"+peer.PeerID]
	r.mu.RUnlock()
	now := time.Now().UTC()
	if r.now != nil {
		now = r.now().UTC()
	}
	host, hostErr := SampleProcess(observed.registration.Host.PID)
	shim, shimErr := SampleProcess(observed.shim.PID)
	if !ok || hostErr != nil || shimErr != nil || host != observed.registration.Host || shim != observed.shim || shim.ParentPID != host.PID || !now.Before(observed.registration.ExpiresAt) || contract.Provider != observed.registration.Provider || contract.PeerID != observed.registration.PeerID || contract.UISessionID != observed.registration.SessionID || contract.ProfileID != observed.registration.ProfileID || contract.RevisionID != observed.registration.RevisionID {
		return ErrUnavailable
	}
	return nil
}

var _ nativemcp.ProcessAttestor = (*HostRegistry)(nil)
