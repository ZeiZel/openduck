package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"time"

	"openduck/internal/providerrevision"
)

const uiBindSigningRequestV1 = "openduck-ui-bind-signing-request.v1"

// uiBindSigningRequest is an unprivileged outbox artifact. It contains the
// exact dynamically minted UI endpoint but never a private key, bearer, mesh
// endpoint, provider handle, or a signed lifecycle operation. The external
// owner signer must turn this immutable request into a fresh signed ui-bind
// envelope and place that envelope into the separately verified lifecycle
// inbox.
type uiBindSigningRequest struct {
	SchemaVersion       string `json:"schema_version"`
	RegistrationNonce   string `json:"registration_nonce"`
	RegistrationDigest  string `json:"registration_digest"`
	RevisionID          string `json:"revision_id"`
	BundleDigest        string `json:"bundle_digest"`
	TrustDigest         string `json:"trust_digest"`
	BaseVersion         uint64 `json:"base_version"`
	BaseCurrentRevision string `json:"base_current_revision"`
	SessionID           string `json:"session_id"`
	ChannelID           string `json:"channel_id"`
	RootRunID           string `json:"root_run_id"`
	RunID               string `json:"run_id"`
	MeshSessionID       string `json:"mesh_session_id"`
	AttemptID           string `json:"attempt_id"`
	PeerID              string `json:"peer_id"`
	EndpointID          string `json:"endpoint_id"`
	EndpointGeneration  uint64 `json:"endpoint_generation"`
	EndpointExpiresAt   string `json:"endpoint_expires_at"`
}

func uiBindSigningRequestFor(ctx context.Context, service *providerrevision.Service, registration providerrevision.UIRegistration) (uiBindSigningRequest, error) {
	if service == nil || registration.RequestNonce == "" || registration.RequestDigest == "" || registration.EndpointID == "" || registration.EndpointGeneration == 0 || registration.ExpiresAt.IsZero() {
		return uiBindSigningRequest{}, errors.New("ui registration unavailable")
	}
	installed, err := service.Active(ctx)
	if err != nil || installed.Bundle.RevisionID != registration.RevisionID {
		return uiBindSigningRequest{}, errors.New("ui registration unavailable")
	}
	// Registration is committed by ui-register, so the bind must fence the
	// current durable version returned by the repository, not a caller choice.
	pending, baseVersion, err := service.RegistrationForBinding(ctx, registration.SessionID, registration.ChannelID)
	if err != nil || pending != registration {
		return uiBindSigningRequest{}, errors.New("ui registration unavailable")
	}
	// A later mutation invalidates this request at ui-bind apply time; it can
	// never bind an endpoint under a changed trust revision.
	return uiBindSigningRequest{SchemaVersion: uiBindSigningRequestV1, RegistrationNonce: registration.RequestNonce, RegistrationDigest: registration.RequestDigest, RevisionID: installed.Bundle.RevisionID, BundleDigest: installed.Bundle.Digest, TrustDigest: installed.Bundle.TrustBundleDigest, BaseVersion: baseVersion, BaseCurrentRevision: installed.Bundle.RevisionID, SessionID: registration.SessionID, ChannelID: registration.ChannelID, RootRunID: registration.RootRunID, RunID: registration.RunID, MeshSessionID: registration.MeshSessionID, AttemptID: registration.AttemptID, PeerID: registration.PeerID, EndpointID: registration.EndpointID, EndpointGeneration: registration.EndpointGeneration, EndpointExpiresAt: registration.ExpiresAt.UTC().Format(time.RFC3339Nano)}, nil
}

func uiBindSigningRequestLeaf(registration providerrevision.UIRegistration) (string, error) {
	if registration.RequestNonce == "" || filepath.Base(registration.RequestNonce) != registration.RequestNonce {
		return "", errors.New("ui registration unavailable")
	}
	return "ui-bind-request." + registration.RequestNonce + ".json", nil
}

func publishUIBindSigningRequest(root *os.Root, request uiBindSigningRequest) error {
	if root == nil || request.SchemaVersion != uiBindSigningRequestV1 || request.RegistrationNonce == "" || request.RegistrationDigest == "" || request.RevisionID == "" || request.BundleDigest == "" || request.TrustDigest == "" || request.BaseCurrentRevision != request.RevisionID || request.SessionID == "" || request.ChannelID == "" || request.RootRunID == "" || request.RunID != request.RootRunID || request.MeshSessionID == "" || request.AttemptID == "" || request.PeerID == "" || request.EndpointID == "" || request.EndpointGeneration == 0 || request.EndpointExpiresAt == "" {
		return errors.New("ui registration unavailable")
	}
	leaf, err := uiBindSigningRequestLeaf(providerrevision.UIRegistration{RequestNonce: request.RegistrationNonce})
	if err != nil {
		return err
	}
	raw, err := json.Marshal(request)
	if err != nil || len(raw) == 0 || len(raw) > 8192 {
		return errors.New("ui registration unavailable")
	}
	if info, statErr := root.Lstat(leaf); statErr == nil {
		if !info.Mode().IsRegular() || info.Mode()&^0600 != 0 || info.Size() != int64(len(raw)) {
			return errors.New("ui registration unavailable")
		}
		f, openErr := root.Open(leaf)
		if openErr != nil {
			return errors.New("ui registration unavailable")
		}
		present, readErr := io.ReadAll(io.LimitReader(f, 8193))
		closeErr := f.Close()
		if readErr != nil || closeErr != nil || !bytes.Equal(present, raw) {
			return errors.New("ui registration unavailable")
		}
		return nil
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return errors.New("ui registration unavailable")
	}
	temporary := "." + leaf + ".tmp"
	f, err := root.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return errors.New("ui registration unavailable")
	}
	_, writeErr := f.Write(raw)
	syncErr := f.Sync()
	closeErr := f.Close()
	if writeErr != nil || syncErr != nil || closeErr != nil {
		_ = root.Remove(temporary)
		return errors.New("ui registration unavailable")
	}
	if err = root.Rename(temporary, leaf); err != nil {
		_ = root.Remove(temporary)
		return errors.New("ui registration unavailable")
	}
	return nil
}
