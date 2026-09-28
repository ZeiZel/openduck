package nativeconfirm

import (
	"context"
	"encoding/json"
	"sync"

	"openduck/internal/harness"
	"openduck/internal/ownerauth"
)

// OwnerAuthAdapter is the only bridge from the generic two-phase Runner to
// the pinned native helper process. The ownerauth.Session and its pipe remain
// private; no process handle or helper proof can be returned to a plugin.
type OwnerAuthAdapter struct {
	config    ownerauth.Config
	mu        sync.Mutex
	session   ownerauth.Session
	sessionID string
}

func NewOwnerAuthAdapter(config ownerauth.Config) *OwnerAuthAdapter {
	return &OwnerAuthAdapter{config: config}
}

func (a *OwnerAuthAdapter) Render(ctx context.Context, req RenderRequest) (RenderAck, error) {
	a.mu.Lock()
	if a.session != nil {
		a.mu.Unlock()
		return RenderAck{}, ErrBusy
	}
	digest, err := ownerauthDigest(req.DestinationSummary)
	if err != nil {
		a.mu.Unlock()
		return RenderAck{}, ErrRunner
	}
	displayInstance := req.Challenge.DisplayInstanceID
	if displayInstance == "" {
		displayInstance = "native-pending-" + req.SessionID
	}
	dossier := ownerauth.Dossier{SessionID: req.SessionID, DisplayInstance: displayInstance, ActionType: "owner.confirm", Title: "OpenDuck confirmation", PreviewText: string(req.PreviewBytes), Destination: string(req.DestinationSummary), Risk: "owner-confirmation", ExpiresAt: req.Challenge.ExpiresAt.UTC().Format("2006-01-02T15:04:05.999999999Z07:00"), PreviewDigest: req.PreviewDigest, DestinationDigest: digest}
	s, err := a.config.Start(ctx, dossier)
	if err != nil {
		a.mu.Unlock()
		return RenderAck{}, err
	}
	a.session, a.sessionID = s, req.SessionID
	a.mu.Unlock()
	ack, err := s.Render(ctx)
	if err != nil {
		a.clear(s)
		return RenderAck{}, err
	}
	return RenderAck{SessionID: ack.SessionID, DisplayNonce: ack.DisplayNonce, PreviewDigest: ack.PreviewDigest, DestinationDigest: ack.DestinationDigest}, nil
}

func (a *OwnerAuthAdapter) Authenticate(ctx context.Context, req AuthenticateRequest) (AuthResult, error) {
	a.mu.Lock()
	s := a.session
	if s == nil || a.sessionID != req.SessionID {
		a.mu.Unlock()
		return AuthResult{}, ErrRunner
	}
	a.mu.Unlock()
	b, err := json.Marshal(req.Challenge)
	if err != nil {
		a.clear(s)
		return AuthResult{}, ErrRunner
	}
	r, err := s.Authenticate(ctx, string(b))
	a.clear(s)
	if err != nil {
		return AuthResult{}, err
	}
	return AuthResult{SessionID: r.SessionID, Decision: r.Decision, Approver: r.Approver, ProofRef: r.ProofRef}, nil
}

func (a *OwnerAuthAdapter) Cancel(_ context.Context, sessionID string) {
	a.mu.Lock()
	s := a.session
	if s == nil || (sessionID != "" && a.sessionID != sessionID) {
		a.mu.Unlock()
		return
	}
	a.session, a.sessionID = nil, ""
	a.mu.Unlock()
	s.Cancel()
}

func (a *OwnerAuthAdapter) clear(s ownerauth.Session) {
	a.mu.Lock()
	if a.session == s {
		a.session, a.sessionID = nil, ""
	}
	a.mu.Unlock()
	if s != nil {
		s.Cancel()
	}
}

func ownerauthDigest(v []byte) (string, error) {
	var value any
	if err := json.Unmarshal(v, &value); err != nil {
		return "", err
	}
	// ownerauth accepts the harness's sha256:<hex> form.
	return harness.SHA256(value)
}
