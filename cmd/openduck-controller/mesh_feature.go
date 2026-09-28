package main

import (
	"context"
	"openduck/internal/mesh"
	"openduck/internal/providerbridge"
	"time"
)

// newDisabledMeshCoordinator is an explicit composition seam until a durable
// mesh repository and verified provider registry are provisioned. Its empty
// directory and nil starter make every spawn fail closed; it cannot create a
// provider session, reach a provider, or expose a capability endpoint.
func newDisabledMeshCoordinator(repo mesh.Repository, registry *providerbridge.Registry) (*mesh.Coordinator, error) {
	directory, err := newProviderMeshDirectory(registry, disabledMeshLimits())
	if err != nil {
		return nil, err
	}
	endpoints, err := mesh.NewPersistentEndpointAuthorizer(repo)
	if err != nil {
		return nil, err
	}
	return mesh.NewCoordinator(mesh.CoordinatorOptions{
		Repository:    repo,
		Directory:     directory,
		Starter:       noAdapterRouter{},
		Sessions:      noAdapterRouter{},
		Endpoints:     endpoints,
		PolicyVersion: "mesh-disabled.v1",
	})
}

// providerMeshDirectory is deliberately in the composition package: mesh owns
// the consumer interface while providerbridge remains metadata-only and cannot
// import Controller authority types.
type providerMeshDirectory struct {
	registry *providerbridge.Registry
	limits   mesh.ExecutionLimits
	now      func() time.Time
}

func newProviderMeshDirectory(registry *providerbridge.Registry, limits mesh.ExecutionLimits) (*providerMeshDirectory, error) {
	if registry == nil || limits.Validate() != nil {
		return nil, mesh.ErrInvalidContract
	}
	return &providerMeshDirectory{registry: registry, limits: limits, now: time.Now}, nil
}
func (d *providerMeshDirectory) Lookup(ctx context.Context, id string) (mesh.Profile, error) {
	r, err := d.registry.Resolve(ctx, id, d.now().UTC())
	if err != nil {
		return mesh.Profile{}, err
	}
	l := r.Limits
	limits := mesh.ExecutionLimits{SchemaVersion: mesh.ExecutionLimitsV1, MaxDepth: l.MaxDepth, MaxChildrenPerParent: l.MaxChildrenPerParent, MaxConcurrentRuns: l.MaxConcurrentRuns, MaxInputTokens: l.MaxInputTokens, MaxOutputTokens: l.MaxOutputTokens, MaxWallMS: l.MaxWallMS, MaxAttempts: l.MaxAttempts, MaxResultBytes: l.MaxResultBytes, Cost: mesh.CostLimit{Kind: l.Cost.Kind, Currency: l.Cost.Currency, MinorUnitExponent: l.Cost.MinorUnitExponent, MaxMinorUnits: l.Cost.MaxMinorUnits, Unit: l.Cost.Unit, MaxQuantity: l.Cost.MaxQuantity}}
	tools := make([]string, 0, len(r.Mapping.Operations))
	if r.MappingVerified {
		for _, operation := range r.Mapping.Operations {
			tools = append(tools, operation.Operation)
		}
	}
	p := r.Profile
	return mesh.Profile{ID: p.ID, Provider: string(p.Provider), Model: p.Model, Status: string(p.Status), AccountHandleRef: p.AccountRef, LocalOnly: p.LocalOnly, MeshSpawn: r.MeshSpawnEnabled(), Limits: limits, MappingVerified: r.MappingVerified, EvidenceCurrent: r.EvidenceCurrent, Supported: mesh.CapabilityEnvelope{Tools: tools}}, nil
}
func (d *providerMeshDirectory) List(ctx context.Context) ([]mesh.Profile, error) {
	declared := d.registry.Profiles(ctx)
	out := make([]mesh.Profile, 0, len(declared))
	for _, p := range declared {
		v, err := d.Lookup(ctx, p.ID)
		if err != nil {
			continue
		}
		out = append(out, v)
	}
	return out, nil
}
func disabledMeshLimits() mesh.ExecutionLimits {
	return mesh.ExecutionLimits{SchemaVersion: mesh.ExecutionLimitsV1, MaxDepth: 1, MaxChildrenPerParent: 1, MaxConcurrentRuns: 1, MaxInputTokens: 1, MaxOutputTokens: 1, MaxWallMS: 1, MaxAttempts: 1, MaxResultBytes: 1, Cost: mesh.CostLimit{Kind: "non_monetary", Unit: "token", MaxQuantity: 1}}
}
