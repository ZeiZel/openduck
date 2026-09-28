package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"openduck/internal/providerrevision"
)

func TestUIBindSigningRequestIsExactAndImmutable(t *testing.T) {
	ctx := context.Background()
	fixture := newMeshApplicationFixture(t)
	state, err := fixture.repo.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	active, err := fixture.service.Active(ctx)
	if err != nil {
		t.Fatal(err)
	}
	registration := providerrevision.UIRegistration{
		RequestNonce:       "registration-nonce-1",
		RequestDigest:      meshDigest("registration-request-1"),
		SessionID:          fixture.principal.SessionID,
		ChannelID:          fixture.principal.ChannelID,
		RootRunID:          fixture.binding.RootRunID,
		RunID:              fixture.binding.RunID,
		MeshSessionID:      fixture.binding.SessionID,
		AttemptID:          fixture.binding.AttemptID,
		PeerID:             fixture.binding.PeerID,
		EndpointID:         fixture.binding.EndpointID,
		EndpointGeneration: fixture.binding.Generation,
		RevisionID:         active.Bundle.RevisionID,
		ExpiresAt:          fixture.binding.ExpiresAt,
	}
	next := meshApplicationCloneRevisionSnapshot(state)
	next.Registrations[fixture.principal.SessionID+":"+fixture.principal.ChannelID] = registration
	if err = fixture.repo.CompareAndSwap(ctx, state, next); err != nil {
		t.Fatal(err)
	}

	request, err := uiBindSigningRequestFor(ctx, fixture.service, registration)
	if err != nil {
		t.Fatal(err)
	}
	if request.RegistrationNonce != registration.RequestNonce || request.RegistrationDigest != registration.RequestDigest || request.BaseCurrentRevision != registration.RevisionID || request.RootRunID != registration.RootRunID || request.RunID != registration.RunID || request.MeshSessionID != registration.MeshSessionID || request.AttemptID != registration.AttemptID || request.PeerID != registration.PeerID || request.EndpointID != registration.EndpointID || request.EndpointGeneration != registration.EndpointGeneration || request.EndpointExpiresAt == "" {
		t.Fatalf("inexact signing request: %+v", request)
	}

	stateDir := t.TempDir()
	root, err := os.OpenRoot(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err = publishUIBindSigningRequest(root, request); err != nil {
		t.Fatal(err)
	}
	leaf, err := uiBindSigningRequestLeaf(registration)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(stateDir, leaf))
	if err != nil {
		t.Fatal(err)
	}
	var decoded uiBindSigningRequest
	if err = json.Unmarshal(raw, &decoded); err != nil || decoded != request {
		t.Fatalf("published request=%+v err=%v", decoded, err)
	}
	if err = publishUIBindSigningRequest(root, request); err != nil {
		t.Fatalf("idempotent publication=%v", err)
	}
	if err = os.WriteFile(filepath.Join(stateDir, leaf), []byte("tampered"), 0600); err != nil {
		t.Fatal(err)
	}
	if err = publishUIBindSigningRequest(root, request); err == nil {
		t.Fatal("tampered signing request was accepted")
	}
}
