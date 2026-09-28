package nativemcp

import (
	"context"
	"time"

	"openduck/internal/mesh"
	"openduck/internal/providerrevision"
)

// NewControllerContract derives the complete immutable native session only
// from Controller state after the socket peer has been attested. Its arguments
// are registration identity, never an endpoint, peer, expiry, capability, or
// provider route supplied by the shim.
func NewControllerContract(ctx context.Context, coordinator *mesh.Coordinator, revisions *providerrevision.Service, provider, profileID, uiSessionID, uiChannelID string, now time.Time) (SessionContract, error) {
	if coordinator == nil || revisions == nil || now.IsZero() || !nativeProvider(provider) || !idRE.MatchString(profileID) || !idRE.MatchString(uiSessionID) || !idRE.MatchString(uiChannelID) {
		return SessionContract{}, ErrUnauthorized
	}
	a, err := revisions.Association(ctx, uiSessionID, uiChannelID)
	if err != nil {
		return SessionContract{}, ErrUnauthorized
	}
	registry, installed, err := revisions.Registry(ctx)
	if err != nil || installed.Bundle.RevisionID != a.RevisionID {
		return SessionContract{}, ErrUnauthorized
	}
	p, err := registry.Lookup(ctx, profileID, now.UTC())
	if err != nil || string(p.Provider) != provider {
		return SessionContract{}, ErrUnauthorized
	}
	b, err := coordinator.EndpointBinding(ctx, a.EndpointID)
	if err != nil || b.Audience != "ui" || b.RootRunID != a.RootRunID || b.RunID != a.RunID || b.SessionID != a.MeshSessionID || b.AttemptID != a.AttemptID || b.PeerID != a.PeerID || b.Generation != a.EndpointGeneration || !b.ExpiresAt.Equal(a.ExpiresAt) {
		return SessionContract{}, ErrUnauthorized
	}
	contract := SessionContract{SchemaVersion: SessionContractV1, Provider: provider, ProfileID: profileID, RevisionID: a.RevisionID, UISessionID: a.SessionID, UIChannelID: a.ChannelID, RootRunID: a.RootRunID, RunID: a.RunID, MeshSessionID: a.MeshSessionID, AttemptID: a.AttemptID, EndpointID: a.EndpointID, PeerID: a.PeerID, Generation: a.EndpointGeneration, ExpiresAt: a.ExpiresAt}
	if contract.Validate(now.UTC()) != nil {
		return SessionContract{}, ErrUnauthorized
	}
	return contract, nil
}
