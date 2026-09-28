package codexruntime

import (
	"context"
	"errors"
	"sync"
	"time"
)

// ChatRunService owns the asynchronous lifecycle exposed to Command Center.
// The encrypted ledger is authoritative for lifecycle state; answers remain in
// volatile memory so a restart can never fabricate a completed transcript.
type ChatRunService struct {
	canary  *OwnerCanary
	ledger  *ChatRunLedger
	mu      sync.Mutex
	runs    map[string]context.CancelFunc
	answers map[string]AssistantTurnResult
	closing bool
	wg      sync.WaitGroup
}

func NewChatRunService(canary *OwnerCanary, ledger *ChatRunLedger) (*ChatRunService, error) {
	if canary == nil || ledger == nil || ledger.checkpoint == nil {
		return nil, ErrUnsafeRuntime
	}
	return &ChatRunService{canary: canary, ledger: ledger, runs: map[string]context.CancelFunc{}, answers: map[string]AssistantTurnResult{}}, nil
}

func (s *ChatRunService) Start(ctx context.Context, order GeneralChatOrder) (AssistantTurnResult, error) {
	if s == nil {
		return AssistantTurnResult{}, ErrChatRejected
	}
	if err := order.Validate(); err != nil {
		return AssistantTurnResult{}, err
	}
	s.mu.Lock()
	closing := s.closing
	s.mu.Unlock()
	if closing {
		return AssistantTurnResult{}, ErrRuntimeShutdown
	}
	// Spend no durable state until the one-use owner grant, process gate, PD
	// scan and broker inventory have all passed exactly once.
	inv, err := s.canary.Preflight(ctx, order)
	if err != nil {
		return AssistantTurnResult{}, err
	}
	now := time.Now().UTC()
	// Serialize the close gate with Begin, running transition and run
	// registration. Close cannot observe a half-created durable run.
	s.mu.Lock()
	if s.closing {
		s.mu.Unlock()
		return AssistantTurnResult{}, ErrRuntimeShutdown
	}
	r, err := s.ledger.Begin(order.ChatID, order.ChatID+":"+order.Prompt, now)
	if err != nil {
		s.mu.Unlock()
		return AssistantTurnResult{}, err
	}
	if r.State != "pending" {
		s.mu.Unlock()
		return s.result(r)
	}
	if _, err := s.ledger.Transition(r.RunID, r.Version, "running", "", "", now); err != nil {
		s.mu.Unlock()
		return AssistantTurnResult{}, err
	}
	runCtx, cancel := context.WithCancel(context.Background())
	if old := s.runs[r.RunID]; old != nil {
		cancel()
		s.mu.Unlock()
		return s.Get(ctx, r.RunID)
	}
	s.runs[r.RunID] = cancel
	s.wg.Add(1)
	s.mu.Unlock()
	go func() { defer s.wg.Done(); s.runAuthorized(runCtx, r.RunID, order, now, inv) }()
	return AssistantTurnResult{SchemaVersion: AssistantTurnResultV1, ChatID: r.RunID, State: "running", StartedAt: now}, nil
}

func (s *ChatRunService) runAuthorized(ctx context.Context, runID string, order GeneralChatOrder, started time.Time, inv RuntimeInventory) {
	result, err := s.canary.runAuthorized(ctx, order, inv)
	s.finish(runID, order, started, result, err)
}

func (s *ChatRunService) run(ctx context.Context, runID string, order GeneralChatOrder, started time.Time) {
	result, err := s.canary.Run(ctx, order)
	s.finish(runID, order, started, result, err)
}

func (s *ChatRunService) finish(runID string, order GeneralChatOrder, started time.Time, result AssistantTurnResult, err error) {
	defer func() { s.mu.Lock(); delete(s.runs, runID); s.mu.Unlock() }()
	next, code, digest := "completed", "", ""
	if err != nil {
		next, code = "failed", "RUNTIME_FAILED"
		if errors.Is(err, context.Canceled) {
			next, code = "cancelled", "CANCELLED"
		}
		if errors.Is(err, ErrLocalPDUnavailable) {
			next, code = "failed", "LOCAL_PD_UNAVAILABLE"
		}
	} else if result.Validate() != nil || result.State != "completed" {
		next, code = "uncertain", "INVALID_RESULT"
	} else {
		digest = ChatAnswerDigest(result.Answer)
	}
	r, getErr := s.ledger.Get(runID)
	if getErr != nil {
		return
	}
	updated, transitionErr := s.ledger.Transition(runID, r.Version, next, digest, code, time.Now().UTC())
	if transitionErr != nil {
		return
	} // cancel/race won; never publish an answer
	if next == "completed" {
		// Publishing is strictly after the encrypted terminal persistence and
		// external checkpoint. A persistence failure therefore cannot leak it.
		result.ChatID, result.StartedAt, result.CompletedAt = runID, started, time.Now().UTC()
		s.mu.Lock()
		s.answers[runID] = result
		s.mu.Unlock()
		return
	}
	_ = updated
}

func (s *ChatRunService) Get(_ context.Context, runID string) (AssistantTurnResult, error) {
	r, err := s.ledger.Get(runID)
	if err != nil {
		return AssistantTurnResult{}, err
	}
	return s.result(r)
}
func (s *ChatRunService) result(r ChatRunRecord) (AssistantTurnResult, error) {
	base := AssistantTurnResult{SchemaVersion: AssistantTurnResultV1, ChatID: r.RunID, StartedAt: r.UpdatedAt}
	if r.PendingToken != "" {
		base.State, base.ErrorCode, base.CompletedAt = "failed", "UNCERTAIN_CHECKPOINT", r.UpdatedAt
		return base, nil
	}
	switch r.State {
	case "pending", "running":
		base.State = r.State
	case "completed":
		s.mu.Lock()
		answer, ok := s.answers[r.RunID]
		s.mu.Unlock()
		if !ok || answer.Answer == "" { // restart: answer was intentionally not retained
			base.State, base.ErrorCode, base.CompletedAt = "failed", "UNCERTAIN_RESTART", r.UpdatedAt
			return base, nil
		}
		return answer, nil
	case "cancelled", "failed", "uncertain":
		base.State, base.ErrorCode, base.CompletedAt = "failed", r.ErrorCode, r.UpdatedAt
		if r.State == "cancelled" {
			base.State = "cancelled"
		}
		if base.ErrorCode == "" {
			base.ErrorCode = "UNCERTAIN"
		}
	default:
		return AssistantTurnResult{}, ErrRunCAS
	}
	return base, nil
}
func (s *ChatRunService) Cancel(_ context.Context, runID string) error {
	s.mu.Lock()
	cancel := s.runs[runID]
	s.mu.Unlock()
	if cancel == nil {
		return ErrRunCAS
	}
	r, err := s.ledger.Get(runID)
	if err != nil {
		return err
	}
	if _, err := s.ledger.Transition(runID, r.Version, "cancelled", "", "CANCELLED", time.Now().UTC()); err != nil {
		return err
	}
	cancel()
	return nil
}

// Close prevents new runs, cancels active turns and joins all worker
// goroutines before returning. It is idempotent and safe during HTTP shutdown.
func (s *ChatRunService) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	if !s.closing {
		s.closing = true
		for _, cancel := range s.runs {
			cancel()
		}
	}
	s.mu.Unlock()
	done := make(chan struct{})
	go func() { s.wg.Wait(); close(done) }()
	select {
	case <-done:
		return nil
	case <-time.After(5 * time.Second):
		return ErrRuntimeShutdown
	}
}
