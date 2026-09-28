package ownerauth

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync"
	"time"
)

// Start launches one pinned helper and keeps its private pipe for the two
// protocol phases. The returned handle never leaves the native adapter.
func (c Config) Start(ctx context.Context, d Dossier) (Session, error) {
	if err := c.validate(); err != nil || !validDossier(d) {
		return nil, ErrProtocol
	}
	verified, err := openVerifiedExecutable(c.Path, c.SHA256)
	if err != nil {
		return nil, err
	}
	timeout := c.Timeout
	if timeout <= 0 || timeout > 5*time.Minute {
		timeout = 90 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	cmd := exec.CommandContext(ctx, verified.path)
	cmd.Args = []string{verified.path}
	cmd.ExtraFiles = []*os.File{verified.file}
	cmd.Dir = "/"
	cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=/var/empty", "LANG=C"}
	in, err := cmd.StdinPipe()
	if err != nil {
		cancel()
		verified.file.Close()
		verified.cleanup()
		return nil, err
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		in.Close()
		verified.file.Close()
		verified.cleanup()
		return nil, err
	}
	cmd.Stderr = io.Discard
	if err := cmd.Start(); err != nil {
		cancel()
		in.Close()
		verified.file.Close()
		verified.cleanup()
		return nil, err
	}
	return &SessionRunner{cfg: c, dossier: d, ctx: ctx, cancel: cancel, cmd: cmd, in: in, reader: bufio.NewReaderSize(out, maxLine+1), verified: verified}, nil
}

func validDossier(d Dossier) bool {
	return d.SessionID != "" && d.DisplayInstance != "" && d.ActionType != "" && d.Title != "" &&
		len(d.PreviewText) > 0 && len(d.PreviewText) <= maxText && len(d.ActionType) <= maxField &&
		len(d.Title) <= maxField && d.Destination != "" && len(d.Destination) <= maxField && d.Risk != "" &&
		len(d.Risk) <= maxField && d.ExpiresAt != "" && len(d.ExpiresAt) <= maxField &&
		validDigest(d.PreviewDigest) && validDigest(d.DestinationDigest)
}

type SessionRunner struct {
	mu       sync.Mutex
	cfg      Config
	dossier  Dossier
	ctx      context.Context
	cancel   context.CancelFunc
	cmd      *exec.Cmd
	in       io.WriteCloser
	reader   *bufio.Reader
	verified *verifiedExecutable
	phase    uint8 // 0=new, 1=rendered, 2=finished, 3=cancelled
	waitOnce sync.Once
	waitErr  error
}

func (s *SessionRunner) Render(ctx context.Context) (RenderAck, error) {
	s.mu.Lock()
	if s.phase != 0 {
		s.mu.Unlock()
		return RenderAck{}, ErrProtocol
	}
	s.phase = 1
	s.mu.Unlock()
	stop := watchContext(ctx, s)
	defer close(stop)
	if err := ctx.Err(); err != nil {
		s.Cancel()
		return RenderAck{}, err
	}
	enc := json.NewEncoder(s.in)
	if err := enc.Encode(map[string]any{"type": "preview", "session_id": s.dossier.SessionID, "display_instance_id": s.dossier.DisplayInstance, "action_type": s.dossier.ActionType, "title": s.dossier.Title, "text": s.dossier.PreviewText, "destination": s.dossier.Destination, "risk": s.dossier.Risk, "expires_at": s.dossier.ExpiresAt, "preview_digest": s.dossier.PreviewDigest, "destination_digest": s.dossier.DestinationDigest}); err != nil {
		s.Cancel()
		return RenderAck{}, ErrProtocol
	}
	line, err := boundedLine(s.reader)
	if err != nil {
		s.Cancel()
		return RenderAck{}, ErrProtocol
	}
	var ack RenderAck
	var wire struct {
		Type              string `json:"type"`
		SessionID         string `json:"session_id"`
		DisplayInstance   string `json:"display_instance_id"`
		DisplayNonce      string `json:"display_nonce"`
		PreviewDigest     string `json:"preview_digest"`
		DestinationDigest string `json:"destination_digest"`
	}
	if json.Unmarshal(line, &wire) != nil || wire.Type != "rendered" || wire.SessionID != s.dossier.SessionID || wire.DisplayInstance != s.dossier.DisplayInstance || wire.DisplayNonce == "" || wire.PreviewDigest != s.dossier.PreviewDigest || wire.DestinationDigest != s.dossier.DestinationDigest {
		s.Cancel()
		return RenderAck{}, fmt.Errorf("%w: rendered mismatch", ErrProtocol)
	}
	ack = RenderAck{SessionID: wire.SessionID, DisplayNonce: wire.DisplayNonce, PreviewDigest: wire.PreviewDigest, DestinationDigest: wire.DestinationDigest}
	return ack, nil
}

func (s *SessionRunner) Authenticate(ctx context.Context, challenge string) (Result, error) {
	s.mu.Lock()
	if s.phase != 1 {
		s.mu.Unlock()
		return Result{}, ErrProtocol
	}
	s.mu.Unlock()
	stop := watchContext(ctx, s)
	defer close(stop)
	if challenge == "" {
		s.Cancel()
		return Result{}, ErrProtocol
	}
	if err := json.NewEncoder(s.in).Encode(map[string]any{"type": "challenge", "session_id": s.dossier.SessionID, "challenge": challenge}); err != nil {
		s.Cancel()
		return Result{}, ErrProtocol
	}
	line, err := boundedLine(s.reader)
	if err != nil {
		s.Cancel()
		return Result{}, ErrProtocol
	}
	var wire struct {
		Type   string `json:"type"`
		Result Result `json:"result"`
	}
	if json.Unmarshal(line, &wire) != nil || wire.Type != "decision" {
		s.Cancel()
		return Result{}, ErrProtocol
	}
	r := wire.Result
	if r.SessionID != s.dossier.SessionID || r.DisplayInstance != s.dossier.DisplayInstance || r.Challenge != challenge || (r.Decision != "approve" && r.Decision != "reject") || r.Timestamp.IsZero() {
		s.Cancel()
		return Result{}, ErrProtocol
	}
	if s.cfg.Authority == nil {
		s.Cancel()
		return Result{}, ErrProtocol
	}
	approver, proof, err := s.cfg.Authority.Authorize(ctx, r.SessionID, r.Decision)
	if err != nil || approver == "" || proof == "" {
		s.Cancel()
		if err != nil {
			return Result{}, err
		}
		return Result{}, ErrProtocol
	}
	r.Approver = approver
	r.ProofRef = proof
	if err := s.waitProcess(); err != nil && s.ctx.Err() == nil {
		s.Cancel()
		return Result{}, ErrProtocol
	}
	s.mu.Lock()
	s.phase = 2
	s.mu.Unlock()
	s.closeResources()
	return r, nil
}

func watchContext(ctx context.Context, s *SessionRunner) chan struct{} {
	stop := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			s.Cancel()
		case <-stop:
		}
	}()
	return stop
}

func (s *SessionRunner) Cancel() {
	s.mu.Lock()
	if s.phase == 3 || s.phase == 2 {
		s.mu.Unlock()
		return
	}
	s.phase = 3
	s.mu.Unlock()
	s.cancel()
	_ = s.in.Close()
	if s.cmd.Process != nil {
		_ = s.cmd.Process.Kill()
	}
	_ = s.waitProcess()
	s.closeResources()
}

func (s *SessionRunner) waitProcess() error {
	s.waitOnce.Do(func() { s.waitErr = s.cmd.Wait() })
	return s.waitErr
}

func (s *SessionRunner) closeResources() {
	_ = s.in.Close()
	_ = s.verified.file.Close()
	s.verified.cleanup()
	s.cancel()
}

type staticAuthority string

func (a staticAuthority) Authorize(context.Context, string, string) (string, string, error) {
	return "legacy", string(a), nil
}
