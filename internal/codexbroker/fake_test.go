package codexbroker

import (
	"context"
	"sync"
	"time"
)

// Fake is provider-free and deterministic. It is intended for contract tests
// and local UI development; it cannot launch a runtime or perform login.
type fake struct {
	mu               sync.Mutex
	AttestationValue BoundaryAttestation
	InventoryValue   Inventory
	Answer           string
	Login            LoginStarted
	Calls            []string
	Closed           bool
	Revoked          bool
	Delay            time.Duration
	TurnEntered      chan struct{}
	turnOnce         sync.Once
}

func (f *fake) wait(ctx context.Context) error {
	f.mu.Lock()
	d := f.Delay
	f.mu.Unlock()
	if d <= 0 {
		return nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

func (f *fake) Attestation(context.Context) (BoundaryAttestation, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.Revoked {
		return BoundaryAttestation{}, ErrAttestation
	}
	return f.AttestationValue, nil
}
func (f *fake) Inventory(ctx context.Context) (Inventory, error) {
	if err := f.wait(ctx); err != nil {
		return Inventory{}, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.Revoked {
		return Inventory{}, ErrAttestation
	}
	f.Calls = append(f.Calls, "inventory")
	return f.InventoryValue, nil
}
func (f *fake) LoginStart(ctx context.Context, in LoginStart) (LoginStarted, error) {
	if err := f.wait(ctx); err != nil {
		return LoginStarted{}, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.Revoked {
		return LoginStarted{}, ErrAttestation
	}
	if in.Validate() != nil {
		return LoginStarted{}, ErrProtocol
	}
	f.Calls = append(f.Calls, "login.start")
	if f.Login.LoginID == "" {
		f.Login = LoginStarted{LoginID: "login_1", AuthorizationURL: "https://login.invalid/fixture"}
	}
	return f.Login, nil
}
func (f *fake) LoginCompleted(ctx context.Context, id string) (LoginCompleted, error) {
	if err := f.wait(ctx); err != nil {
		return LoginCompleted{}, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.Revoked {
		return LoginCompleted{}, ErrAttestation
	}
	f.Calls = append(f.Calls, "login.completed")
	return LoginCompleted{LoginID: id, Success: true}, nil
}
func (f *fake) Turn(ctx context.Context, in Turn) (TurnResult, error) {
	if f.TurnEntered != nil {
		f.turnOnce.Do(func() { close(f.TurnEntered) })
	}
	if err := f.wait(ctx); err != nil {
		return TurnResult{}, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.Revoked {
		return TurnResult{}, ErrAttestation
	}
	f.Calls = append(f.Calls, "turn")
	answer := f.Answer
	if answer == "" {
		answer = "fixture"
	}
	return TurnResult{SessionID: in.SessionID, TurnID: in.TurnID, State: "completed", Answer: answer}, nil
}
func (f *fake) Cancel(_ context.Context, in Cancel) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.Revoked {
		return ErrAttestation
	}
	if in.Validate() != nil {
		return ErrProtocol
	}
	f.Calls = append(f.Calls, "cancel")
	return nil
}
func (f *fake) Close(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.Closed {
		return ErrClosed
	}
	f.Closed = true
	f.Calls = append(f.Calls, "close")
	return nil
}
