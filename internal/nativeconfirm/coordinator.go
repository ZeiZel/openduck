// Package nativeconfirm coordinates the native, owner-authenticated confirmation path.
//
// The coordinator is intentionally an in-process adapter. It accepts only a task id and
// an expected task version, derives every preview field from the Controller, and never
// exposes the Controller's opaque callback handle to a runner or a UI.
package nativeconfirm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"openduck/internal/harness"
)

const DefaultTTL = 60 * time.Second

var (
	ErrBusy    = errors.New("native confirmation already in progress")
	ErrInvalid = errors.New("invalid native confirmation request")
	ErrRunner  = errors.New("native confirmation runner rejected request")
)

// Controller is the narrow native callback surface. The coordinator does not need
// repository access or any effect executor.
type Controller interface {
	Task(context.Context, string) (harness.TaskRecord, error)
	IssueNativeCallbackSession(context.Context, string, uint64, time.Duration) (harness.TaskRecord, harness.NativeCallbackSession, error)
	AcknowledgeNativeRendered(context.Context, string, uint64, harness.NativeCallbackSession, string, string) (harness.TaskRecord, harness.InteractionRenderReceipt, harness.DecisionChallenge, error)
	RecordNativeAuthenticatedDecision(context.Context, string, uint64, harness.NativeCallbackSession, string, string, string) (harness.TaskRecord, harness.OwnerDecisionEvent, error)
}

// RenderRequest contains the exact bytes and server-issued challenge to display.
// DestinationSummary is canonical JSON and is informational only; the Controller
// remains authoritative for the eventual decision event.
type RenderRequest struct {
	TaskID             string
	SessionID          string
	PreviewBytes       []byte
	PreviewDigest      string
	DestinationSummary []byte
	Challenge          harness.DecisionChallenge
}

type RenderAck struct {
	SessionID         string
	DisplayNonce      string
	PreviewDigest     string
	DestinationDigest string
}

type AuthenticateRequest struct {
	TaskID    string
	SessionID string
	Challenge harness.DecisionChallenge
}

type AuthResult struct {
	SessionID string
	Decision  string
	Approver  string
	ProofRef  string
}

// Runner is a two-phase native helper. Render must return only what the helper
// observed; Authenticate receives the final challenge after the Controller has
// persisted the authoritative render receipt.
type Runner interface {
	Render(context.Context, RenderRequest) (RenderAck, error)
	Authenticate(context.Context, AuthenticateRequest) (AuthResult, error)
	Cancel(context.Context, string)
}

type Config struct {
	TTL time.Duration
}

type Coordinator struct {
	controller Controller
	runner     Runner
	ttl        time.Duration
	mu         sync.Mutex
	active     bool
}

func New(controller Controller, runner Runner, cfg Config) (*Coordinator, error) {
	if controller == nil || runner == nil {
		return nil, ErrInvalid
	}
	if cfg.TTL == 0 {
		cfg.TTL = DefaultTTL
	}
	if cfg.TTL <= 0 || cfg.TTL > DefaultTTL {
		return nil, fmt.Errorf("%w: ttl must be between 1ns and 60s", ErrInvalid)
	}
	return &Coordinator{controller: controller, runner: runner, ttl: cfg.TTL}, nil
}

type Result struct {
	Task  harness.TaskRecord
	Event harness.OwnerDecisionEvent
}

// Confirm runs one complete native confirmation. The caller supplies no preview,
// destination, hash, handle, or decision authority.
func (c *Coordinator) Confirm(ctx context.Context, taskID string, version uint64) (Result, error) {
	if taskID == "" || version == 0 {
		return Result{}, ErrInvalid
	}
	c.mu.Lock()
	if c.active {
		c.mu.Unlock()
		return Result{}, ErrBusy
	}
	c.active = true
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		c.active = false
		c.mu.Unlock()
	}()

	ctx, cancel := context.WithTimeout(ctx, c.ttl)
	defer cancel()
	started, err := c.controller.Task(ctx, taskID)
	if err != nil || started.Version != version || started.Action == nil || started.Envelope == nil || started.DeliveryBinding == nil {
		if err == nil {
			err = harness.ErrBindingMismatch
		}
		return Result{}, err
	}
	preview, digest, err := harness.RenderPreview(*started.Action, started.DeliveryBinding.RenderingVersion)
	if err != nil || digest != started.Envelope.PreviewDigest {
		if err == nil {
			err = harness.ErrBindingMismatch
		}
		return Result{}, err
	}
	destination, err := canonicalDestination(started.Action.DestinationDescriptor)
	if err != nil {
		return Result{}, err
	}

	issued, session, err := c.controller.IssueNativeCallbackSession(ctx, taskID, version, c.ttl)
	if err != nil {
		return Result{}, err
	}
	defer func() { c.runner.Cancel(context.Background(), session.SessionID) }()
	ack, err := c.runner.Render(ctx, RenderRequest{TaskID: taskID, SessionID: session.SessionID, PreviewBytes: append([]byte(nil), preview...), PreviewDigest: digest, DestinationSummary: destination, Challenge: session.Challenge})
	if err != nil {
		return Result{}, fmt.Errorf("%w: render: %v", ErrRunner, err)
	}
	destinationDigest, err := harness.SHA256(json.RawMessage(destination))
	if err != nil {
		return Result{}, err
	}
	if ack.SessionID != session.SessionID || ack.DisplayNonce == "" || ack.PreviewDigest != digest || ack.DestinationDigest != destinationDigest {
		return Result{}, fmt.Errorf("%w: render acknowledgement mismatch", ErrRunner)
	}
	rendered, receipt, finalChallenge, err := c.controller.AcknowledgeNativeRendered(ctx, taskID, issued.Version, session, ack.DisplayNonce, ack.PreviewDigest)
	if err != nil {
		return Result{}, err
	}
	result, err := c.runner.Authenticate(ctx, AuthenticateRequest{TaskID: taskID, SessionID: session.SessionID, Challenge: finalChallenge})
	if err != nil {
		return Result{}, fmt.Errorf("%w: authenticate: %v", ErrRunner, err)
	}
	if result.SessionID != session.SessionID || (result.Decision != "approve" && result.Decision != "reject") || result.Approver == "" || result.ProofRef == "" || receipt.ReceiptDigest == "" {
		return Result{}, fmt.Errorf("%w: authentication result mismatch", ErrRunner)
	}
	committed, event, err := c.controller.RecordNativeAuthenticatedDecision(ctx, taskID, rendered.Version, session, result.Decision, result.Approver, result.ProofRef)
	if err != nil {
		return Result{}, err
	}
	return Result{Task: committed, Event: event}, nil
}

func canonicalDestination(raw json.RawMessage) ([]byte, error) {
	var v any
	if len(raw) == 0 || json.Unmarshal(raw, &v) != nil {
		return nil, harness.ErrInvalidContract
	}
	return harness.CanonicalJSON(v)
}
