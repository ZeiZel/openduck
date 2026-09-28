package codexruntime

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"time"

	"openduck/internal/codexbroker"
)

// BrokerChatTransport adapts the Controller-facing typed broker to the
// existing owner-chat lifecycle. It deliberately has no process, profile, or
// app-server configuration fields.
type BrokerChatTransport struct {
	runtime codexbroker.OwnerRuntimeClient
}

func opaqueRandomID(prefix string) (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", ErrChatRejected
	}
	return prefix + hex.EncodeToString(b), nil
}

// newBrokerChatTransport is intentionally package-private. Production callers
// must obtain the client from the attested broker composition; an arbitrary
// OwnerRuntimeClient cannot be injected through a public constructor.
func newBrokerChatTransport(runtime codexbroker.OwnerRuntimeClient) (BrokerChatTransport, error) {
	if runtime == nil {
		return BrokerChatTransport{}, ErrUnsafeInventory
	}
	return BrokerChatTransport{runtime: runtime}, nil
}

// NewBrokerChatTransportForProduction accepts only the typed broker surface;
// process/profile/stdio details remain unreachable from Controller code.
func NewBrokerChatTransportForProduction(runtime codexbroker.OwnerRuntimeClient) (BrokerChatTransport, error) {
	return newBrokerChatTransport(runtime)
}

func (t BrokerChatTransport) Inventory(ctx context.Context) (RuntimeInventory, error) {
	if t.runtime == nil {
		return RuntimeInventory{}, ErrUnsafeInventory
	}
	i, err := t.runtime.Inventory(ctx)
	if err != nil {
		return RuntimeInventory{}, err
	}
	return RuntimeInventory{SchemaVersion: RuntimeInventoryV1, AccountState: i.AccountState, ExecutableVersion: i.RuntimeVersion, ExecutableDigest: i.RuntimeDigest, ModelNetworkOnly: i.ModelOnly}, nil
}

func (t BrokerChatTransport) Turn(ctx context.Context, o GeneralChatOrder) (AssistantTurnResult, error) {
	if t.runtime == nil || o.Validate() != nil {
		return AssistantTurnResult{}, ErrChatRejected
	}
	sessionID, err := opaqueRandomID("session_")
	if err != nil {
		return AssistantTurnResult{}, err
	}
	turnID, err := opaqueRandomID("turn_")
	if err != nil {
		return AssistantTurnResult{}, err
	}
	turn := codexbroker.Turn{SessionID: sessionID, TurnID: turnID, Prompt: o.Prompt, Classification: o.Classification, MaxOutputBytes: o.MaxOutputBytes}
	type response struct {
		result codexbroker.TurnResult
		err    error
	}
	resultCh := make(chan response, 1)
	go func() {
		r, err := t.runtime.Turn(ctx, turn)
		resultCh <- response{result: r, err: err}
	}()
	var r codexbroker.TurnResult
	select {
	case out := <-resultCh:
		r, err = out.result, out.err
	case <-ctx.Done():
		// Cancellation is a typed broker operation. The opaque session/turn
		// identifiers are the only values crossing this boundary; no raw RPC
		// or process handle is exposed to the Controller.
		cancelCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		cancelErr := t.runtime.Cancel(cancelCtx, codexbroker.Cancel{SessionID: sessionID, TurnID: turnID})
		cancel()
		if cancelErr != nil {
			return AssistantTurnResult{}, cancelErr
		}
		return AssistantTurnResult{SchemaVersion: AssistantTurnResultV1, ChatID: o.ChatID, ThreadID: o.ThreadID, TurnID: turnID, State: "cancelled", ErrorCode: "CANCELLED"}, context.Canceled
	}
	if err != nil {
		return AssistantTurnResult{}, err
	}
	state := r.State
	if state == "cancelled" {
		state = "cancelled"
	}
	if r.SessionID != sessionID || r.TurnID != turnID {
		return AssistantTurnResult{}, ErrChatRejected
	}
	return AssistantTurnResult{SchemaVersion: AssistantTurnResultV1, ChatID: o.ChatID, ThreadID: o.ThreadID, TurnID: r.TurnID, State: state, Answer: r.Answer, ErrorCode: r.ErrorCode}, nil
}
