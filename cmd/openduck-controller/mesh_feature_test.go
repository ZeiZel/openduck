package main

import (
	"context"
	"encoding/json"
	"errors"
	"openduck/internal/mesh"
	"openduck/internal/meshui"
	"openduck/internal/providerbridge"
	"strings"
	"testing"
)

func TestDisabledMeshCompositionFailsClosed(t *testing.T) {
	registry, err := providerbridge.NewRegistry(nil, nil, nil, nil, providerbridge.TrustRegistry{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	c, err := newDisabledMeshCoordinator(mesh.NewMemoryRepository(), registry)
	if err != nil {
		t.Fatal(err)
	}
	b, err := c.RegisterRoot(context.Background(), "root-test", "session-test", "attempt-test", "peer-test", "L1", "workspace-test")
	if err != nil {
		t.Fatal(err)
	}
	p := mesh.SpawnProposal{SchemaVersion: mesh.SpawnProposalV1, ClientNonce: "nonce-test", Objective: "test", PreferredProfile: "not-configured", RequestedRole: "worker", OutputSchemaRef: "result-v1", RequestedLimits: mesh.ExecutionLimits{SchemaVersion: mesh.ExecutionLimitsV1, MaxDepth: 1, MaxChildrenPerParent: 1, MaxConcurrentRuns: 1, MaxInputTokens: 1, MaxOutputTokens: 1, MaxWallMS: 1, MaxAttempts: 1, MaxResultBytes: 1, Cost: mesh.CostLimit{Kind: "non_monetary", Unit: "token", MaxQuantity: 1}}}
	_, err = c.ProposeSpawn(context.Background(), mesh.ProposalRequest{Endpoint: mesh.EndpointRequest{EndpointID: b.EndpointID, PeerID: b.PeerID, Audience: "mesh", Nonce: "call-test", MessageDigest: "sha256:bad"}, Proposal: p})
	if !errors.Is(err, mesh.ErrUnauthorized) {
		t.Fatalf("composition unexpectedly admitted spawn: %v", err)
	}
}

func TestResultEnvelopeUsesExactOutputArtifactReference(t *testing.T) {
	digest := "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	response := meshui.MeshUIResponse{SchemaVersion: meshui.ResponseSchema, Kind: "mesh-result", Result: &meshui.ResultEnvelopeOutput{RunID: "run-1", AttemptID: "attempt-1", Status: "completed", OutputArtifactRef: "artifact-1", SchemaRef: "result-v1", ProvenanceDigest: digest, Classification: "L1"}}
	if err := response.Validate("mesh-result"); err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(response)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"output_artifact_ref":"artifact-1"`) || strings.Contains(string(b), `"artifact_ref"`) {
		t.Fatalf("unexpected result envelope wire shape: %s", b)
	}
}
