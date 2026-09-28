package codexruntime

import (
	"context"
	"errors"
	"testing"
	"time"
)

type allowChatAuth struct{}

func (allowChatAuth) Authorize(context.Context) error { return nil }

type allowChatGate struct{}

func (allowChatGate) Check(context.Context) error { return nil }

func chatOrder(t *testing.T, prompt string) GeneralChatOrder {
	t.Helper()
	return GeneralChatOrder{SchemaVersion: GeneralChatOrderV1, ChatID: "chat-1", Prompt: prompt, WorkspaceRoots: []string{}, Classification: "L0", MaxOutputBytes: 1024, ApprovalPolicy: "never", ReadOnly: true, ToolsDisabled: true, NetworkMode: "model_only"}
}

func safeInventory() RuntimeInventory {
	return RuntimeInventory{SchemaVersion: RuntimeInventoryV1, AccountState: "authenticated_owner", ExecutableVersion: "codex-test", ExecutableDigest: "sha256:test", ModelNetworkOnly: true}
}

func TestOwnerCanaryRunsExactlyOneBoundedTurn(t *testing.T) {
	transport := &FakeChatTransport{InventoryValue: safeInventory(), Result: AssistantTurnResult{State: "completed", Answer: "OK"}}
	home := t.TempDir()
	canary, err := NewOwnerCanary(home, transport, allowChatAuth{}, allowChatGate{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	result, err := canary.Run(context.Background(), chatOrder(t, "Reply exactly OPENDUCK_CHAT_CANARY_OK"))
	if err != nil || result.State != "completed" || result.Answer != "OK" || transport.Calls != 1 {
		t.Fatalf("result=%+v err=%v calls=%d", result, err, transport.Calls)
	}
}

func TestOwnerCanaryPDNeverCallsCloud(t *testing.T) {
	transport := &FakeChatTransport{InventoryValue: safeInventory(), Result: AssistantTurnResult{State: "completed", Answer: "should-not"}}
	canary, _ := NewOwnerCanary(t.TempDir(), transport, allowChatAuth{}, allowChatGate{}, nil)
	order := chatOrder(t, "Это ПД\r\nсекрет")
	_, err := canary.Run(context.Background(), order)
	if !errors.Is(err, ErrLocalPDUnavailable) || transport.Calls != 0 {
		t.Fatalf("err=%v calls=%d", err, transport.Calls)
	}
}

func TestOwnerCanaryConfusableAndStructuredDataFailClosed(t *testing.T) {
	for _, prompt := range []string{"Это\u00a0ПД", "contact alice@example.com"} {
		transport := &FakeChatTransport{InventoryValue: safeInventory(), Result: AssistantTurnResult{State: "completed", Answer: "bad"}}
		canary, _ := NewOwnerCanary(t.TempDir(), transport, allowChatAuth{}, allowChatGate{}, nil)
		_, err := canary.Run(context.Background(), chatOrder(t, prompt))
		if !errors.Is(err, ErrLocalPDUnavailable) || transport.Calls != 0 {
			t.Fatalf("prompt=%q err=%v calls=%d", prompt, err, transport.Calls)
		}
	}
}

func TestOwnerCanaryRejectsUnsafeInventory(t *testing.T) {
	inv := safeInventory()
	inv.ToolInventory = []string{"shell"}
	transport := &FakeChatTransport{InventoryValue: inv, Result: AssistantTurnResult{State: "completed", Answer: "bad"}}
	canary, _ := NewOwnerCanary(t.TempDir(), transport, allowChatAuth{}, allowChatGate{}, nil)
	if _, err := canary.Run(context.Background(), chatOrder(t, "hello")); !errors.Is(err, ErrUnsafeInventory) {
		t.Fatalf("err=%v", err)
	}
}

func TestOwnerCanaryAsyncStatesAndCancellation(t *testing.T) {
	transport := &FakeChatTransport{InventoryValue: safeInventory(), Result: AssistantTurnResult{State: "completed", Answer: "OK"}}
	canary, _ := NewOwnerCanary(t.TempDir(), transport, allowChatAuth{}, allowChatGate{}, nil)
	states := []string{}
	for result := range canary.Start(context.Background(), chatOrder(t, "hello")) {
		states = append(states, result.State)
	}
	if len(states) != 3 || states[0] != "pending" || states[1] != "running" || states[2] != "completed" {
		t.Fatalf("states=%v", states)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := canary.Run(ctx, chatOrder(t, "hello")); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel err=%v", err)
	}
	_ = time.Now()
}
