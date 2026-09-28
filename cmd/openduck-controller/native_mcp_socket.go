package main

import (
	"context"
	"time"

	"openduck/internal/macosattest"
	"openduck/internal/nativemcp"
)

// nativeMCPSessionResolver is Controller-only composition for the root-owned
// Unix listener. The shim supplies neither session values nor a capability:
// HostRegistry returns a bounded identity only after LOCAL_PEERCRED and process
// lineage attestation; all remaining binding is reread from durable state.
type nativeMCPSessionResolver struct {
	app      *meshApplication
	registry *macosattest.HostRegistry
	backend  *nativemcp.ControllerBackend
}

func (r nativeMCPSessionResolver) ResolveNativeMCPSession(ctx context.Context, peer nativemcp.PeerIdentity) (nativemcp.SessionContract, nativemcp.AttestedBackend, nativemcp.ProcessAttestor, error) {
	if r.app == nil || r.app.coordinator == nil || r.app.revisions == nil || r.registry == nil || r.backend == nil {
		return nativemcp.SessionContract{}, nil, nil, nativemcp.ErrUnauthorized
	}
	identity, err := r.registry.RegistrationFor(peer)
	if err != nil || identity.Provider != peer.Provider || identity.PeerID != peer.PeerID {
		return nativemcp.SessionContract{}, nil, nil, nativemcp.ErrUnauthorized
	}
	contract, err := nativemcp.NewControllerContract(ctx, r.app.coordinator, r.app.revisions, identity.Provider, identity.ProfileID, identity.SessionID, identity.ChannelID, time.Now().UTC())
	if err != nil || contract.RevisionID != identity.RevisionID || contract.PeerID != identity.PeerID {
		return nativemcp.SessionContract{}, nil, nil, nativemcp.ErrUnauthorized
	}
	return contract, r.backend, r.registry, nil
}

// newNativeMCPSocketServer is not exposed to HTTP/UI. Production wiring may
// listen only after the installer creates the fixed root-owned socket boundary;
// until then this pure composition function cannot make a native registration
// operational.
func newNativeMCPSocketServer(app *meshApplication, registry *macosattest.HostRegistry) (*nativemcp.SocketServer, error) {
	if app == nil || app.coordinator == nil || app.revisions == nil || registry == nil {
		return nil, nativemcp.ErrUnauthorized
	}
	backend := &nativemcp.ControllerBackend{Coordinator: app.coordinator, Revisions: app.revisions}
	resolver := nativeMCPSessionResolver{app: app, registry: registry, backend: backend}
	return &nativemcp.SocketServer{Peers: registry, Resolver: resolver}, nil
}
