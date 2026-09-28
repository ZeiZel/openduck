package nativeconfirm

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"openduck/internal/harness"
)

type fakeController struct {
	mu            sync.Mutex
	task          harness.TaskRecord
	session       harness.NativeCallbackSession
	issued        harness.TaskRecord
	receipt       harness.InteractionRenderReceipt
	challenge     harness.DecisionChallenge
	decision      harness.OwnerDecisionEvent
	ackErr        error
	decisionErr   error
	issueCount    int
	ackCount      int
	decisionCount int
}

func (f *fakeController) Task(context.Context, string) (harness.TaskRecord, error) {
	return f.task, nil
}
func (f *fakeController) IssueNativeCallbackSession(context.Context, string, uint64, time.Duration) (harness.TaskRecord, harness.NativeCallbackSession, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.issueCount++
	return f.issued, f.session, nil
}
func (f *fakeController) AcknowledgeNativeRendered(_ context.Context, _ string, _ uint64, _ harness.NativeCallbackSession, nonce, digest string) (harness.TaskRecord, harness.InteractionRenderReceipt, harness.DecisionChallenge, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ackCount++
	if f.ackErr != nil {
		return harness.TaskRecord{}, harness.InteractionRenderReceipt{}, harness.DecisionChallenge{}, f.ackErr
	}
	f.challenge.DisplayNonce = nonce
	f.challenge.PreviewDigest = digest
	return f.issued, f.receipt, f.challenge, nil
}
func (f *fakeController) RecordNativeAuthenticatedDecision(_ context.Context, _ string, _ uint64, _ harness.NativeCallbackSession, decision, approver, proof string) (harness.TaskRecord, harness.OwnerDecisionEvent, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.decisionCount++
	if f.decisionErr != nil {
		return harness.TaskRecord{}, harness.OwnerDecisionEvent{}, f.decisionErr
	}
	f.decision.Decision, f.decision.ApproverID, f.decision.RecentAuthProofRef = decision, approver, proof
	return f.task, f.decision, nil
}

type fakeRunner struct {
	mu          sync.Mutex
	render      RenderAck
	auth        AuthResult
	renderErr   error
	authErr     error
	renderReq   RenderRequest
	authReq     AuthenticateRequest
	renderBlock <-chan struct{}
	cancelCount int
}

func (r *fakeRunner) Render(ctx context.Context, req RenderRequest) (RenderAck, error) {
	r.mu.Lock()
	r.renderReq = req
	r.mu.Unlock()
	if r.renderBlock != nil {
		select {
		case <-r.renderBlock:
		case <-ctx.Done():
			return RenderAck{}, ctx.Err()
		}
	}
	return r.render, r.renderErr
}
func (r *fakeRunner) Authenticate(_ context.Context, req AuthenticateRequest) (AuthResult, error) {
	r.mu.Lock()
	r.authReq = req
	r.mu.Unlock()
	return r.auth, r.authErr
}
func (r *fakeRunner) Cancel(context.Context, string) { r.mu.Lock(); r.cancelCount++; r.mu.Unlock() }

func nativeFixture(t *testing.T) (*fakeController, *fakeRunner, string) {
	t.Helper()
	payload := json.RawMessage(`{"body":"safe"}`)
	destination := json.RawMessage(`{"channel":"native"}`)
	payloadHash, _ := harness.SHA256(payload)
	destinationHash, _ := harness.SHA256(destination)
	reconcileHash, _ := harness.SHA256("reconcile")
	specHash, _ := harness.SHA256("spec")
	a := harness.ActionProposal{ActionID: "action-1", TaskID: "task-1", SpecHash: specHash, ActionType: "reply.send", Principal: "controller", CanonicalPayload: payload, PayloadHash: payloadHash, DestinationDescriptor: destination, DestinationHash: destinationHash, ReconciliationPolicyDigest: reconcileHash, Effects: []string{"synthetic"}, RiskClass: "L1", RequiredCapability: "reply.send", ApprovalMode: "owner", ExpiresAt: time.Now().Add(time.Minute).UTC(), PolicyVersion: "p1"}
	preview, digest, err := harness.RenderPreview(a, "render.v1")
	if err != nil {
		t.Fatal(err)
	}
	challenge := harness.DecisionChallenge{SessionID: "session-1", PreviewDigest: digest}
	fc := &fakeController{task: harness.TaskRecord{ID: "task-1", Version: 7, Action: &a, Envelope: &harness.OwnerInteractionEnvelope{PreviewDigest: digest}, DeliveryBinding: &harness.InteractionDeliveryBinding{RenderingVersion: "render.v1"}}, issued: harness.TaskRecord{ID: "task-1", Version: 8}, session: harness.NativeCallbackSession{SessionID: "session-1", Challenge: challenge}, receipt: harness.InteractionRenderReceipt{ReceiptDigest: "sha256:" + "1"}, challenge: challenge, decision: harness.OwnerDecisionEvent{DecisionEventID: "event-1"}}
	destinationDigest, _ := harness.SHA256(json.RawMessage(`{"channel":"native"}`))
	fr := &fakeRunner{render: RenderAck{SessionID: "session-1", DisplayNonce: "display-nonce", PreviewDigest: digest, DestinationDigest: destinationDigest}, auth: AuthResult{SessionID: "session-1", Decision: "approve", Approver: "owner", ProofRef: "proof"}}
	_ = preview
	return fc, fr, digest
}

func TestConfirmSplicesControllerPreviewAndTwoPhaseChallenge(t *testing.T) {
	fc, fr, digest := nativeFixture(t)
	c, err := New(fc, fr, Config{TTL: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	got, err := c.Confirm(context.Background(), "task-1", 7)
	if err != nil || got.Event.Decision != "approve" {
		t.Fatalf("result=%+v err=%v", got, err)
	}
	if string(fr.renderReq.PreviewBytes) == "" || fr.renderReq.PreviewDigest != digest || string(fr.renderReq.DestinationSummary) != `{"channel":"native"}` {
		t.Fatalf("runner did not receive canonical preview: %+v", fr.renderReq)
	}
	if fr.authReq.Challenge.DisplayNonce != "display-nonce" || fr.authReq.Challenge.PreviewDigest != digest {
		t.Fatalf("runner did not receive final authoritative challenge: %+v", fr.authReq)
	}
}

func TestConfirmRejectsWrongDigestAndNeverDecides(t *testing.T) {
	fc, fr, digest := nativeFixture(t)
	fr.render.PreviewDigest = "sha256:" + "0"
	c, _ := New(fc, fr, Config{})
	if _, err := c.Confirm(context.Background(), "task-1", 7); !errors.Is(err, ErrRunner) {
		t.Fatalf("err=%v", err)
	}
	if fc.decisionCount != 0 || digest == fr.render.PreviewDigest {
		t.Fatal("wrong digest reached decision path")
	}
}

func TestConfirmRejectsWrongDestinationDigest(t *testing.T) {
	fc, fr, _ := nativeFixture(t)
	fr.render.DestinationDigest = "sha256:" + strings.Repeat("0", 64)
	c, _ := New(fc, fr, Config{})
	if _, err := c.Confirm(context.Background(), "task-1", 7); !errors.Is(err, ErrRunner) {
		t.Fatalf("err=%v", err)
	}
	if fc.decisionCount != 0 {
		t.Fatal("destination mismatch reached decision path")
	}
}

func TestConfirmSingleFlightAndTimeout(t *testing.T) {
	fc, fr, _ := nativeFixture(t)
	block := make(chan struct{})
	fr.renderBlock = block
	c, _ := New(fc, fr, Config{TTL: 20 * time.Millisecond})
	ctx := context.Background()
	done := make(chan error, 1)
	go func() { _, err := c.Confirm(ctx, "task-1", 7); done <- err }()
	time.Sleep(time.Millisecond)
	if _, err := c.Confirm(ctx, "task-1", 7); !errors.Is(err, ErrBusy) {
		t.Fatalf("concurrent confirmation err=%v", err)
	}
	if err := <-done; !errors.Is(err, ErrRunner) {
		t.Fatalf("timeout err=%v", err)
	}
}

func TestConfirmControllerRejectsReplay(t *testing.T) {
	fc, fr, _ := nativeFixture(t)
	fc.ackErr = harness.ErrDecisionDenied
	c, _ := New(fc, fr, Config{})
	if _, err := c.Confirm(context.Background(), "task-1", 7); !errors.Is(err, harness.ErrDecisionDenied) {
		t.Fatalf("replay/invalid session err=%v", err)
	}
	if fc.decisionCount != 0 {
		t.Fatal("decision recorded after controller rejection")
	}
}
