package ownerauth

import (
	"context"
	"errors"
	"testing"
	"time"
)

type testAuthority struct{ calls int }

func (a *testAuthority) Authorize(context.Context, string, string) (string, string, error) {
	a.calls++
	return "owner", "controller-proof-1", nil
}

func sessionDossier() Dossier {
	return Dossier{SessionID: "s1", DisplayInstance: "d1", ActionType: "reply.send", Title: "Confirm", PreviewText: "safe", Destination: `{"channel":"native"}`, Risk: "L1", ExpiresAt: "2026-08-13T00:00:00Z", PreviewDigest: stringsRepeat("a", 64), DestinationDigest: stringsRepeat("b", 64)}
}

func TestSessionRunnerTwoPhaseAndAuthorityProof(t *testing.T) {
	p, hash := helper(t, `read line; printf '%s\n' '{"type":"rendered","session_id":"s1","display_instance_id":"d1","display_nonce":"n1","preview_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","destination_digest":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}'; read line; printf '%s\n' '{"type":"decision","result":{"decision":"approve","challenge":"final","session_id":"s1","display_instance_id":"d1","timestamp":"2026-08-13T00:00:00Z"}}'`)
	a := &testAuthority{}
	s, err := (Config{Path: p, SHA256: hash, Timeout: 3 * time.Second, Authority: a}).Start(context.Background(), sessionDossier())
	if err != nil {
		t.Fatal(err)
	}
	ack, err := s.Render(context.Background())
	if err != nil || ack.DisplayNonce != "n1" {
		t.Fatalf("ack=%+v err=%v", ack, err)
	}
	r, err := s.Authenticate(context.Background(), "final")
	if err != nil || r.Decision != "approve" || r.Approver != "owner" || r.ProofRef != "controller-proof-1" || a.calls != 1 {
		t.Fatalf("result=%+v err=%v calls=%d", r, err, a.calls)
	}
}

func TestSessionRunnerCancelAndTimeout(t *testing.T) {
	p, hash := helper(t, `read line; sleep 5`)
	s, err := (Config{Path: p, SHA256: hash, Timeout: time.Second}).Start(context.Background(), sessionDossier())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := s.Render(ctx); err == nil {
		t.Fatal("expected cancellation")
	}
	s.Cancel()
	if _, err := s.Render(context.Background()); !errors.Is(err, ErrProtocol) {
		t.Fatalf("second render err=%v", err)
	}
}

func TestSessionRunnerRejectsMismatchedAck(t *testing.T) {
	p, hash := helper(t, `read line; printf '%s\n' '{"type":"rendered","session_id":"s1","display_instance_id":"d1","display_nonce":"n1","preview_digest":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","destination_digest":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}'`)
	s, err := (Config{Path: p, SHA256: hash, Timeout: time.Second}).Start(context.Background(), sessionDossier())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Render(context.Background()); err == nil {
		t.Fatal("expected mismatch")
	}
}
