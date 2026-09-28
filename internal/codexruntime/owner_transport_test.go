package codexruntime

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestBoundSealedStartupCapabilityBindsOrderAndConsumes(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	order := GeneralChatOrder{SchemaVersion: GeneralChatOrderV1, ChatID: "chat-1", Prompt: "hello", Classification: "L0", MaxOutputBytes: 1024, ApprovalPolicy: "never", ReadOnly: true, ToolsDisabled: true, NetworkMode: "model_only", WorkspaceRoots: []string{}}
	digest, err := GeneralChatOrderDigest(order)
	if err != nil {
		t.Fatal(err)
	}
	expires := time.Now().UTC().Add(time.Minute).Format(time.RFC3339Nano)
	signature := ed25519.Sign(private, []byte("openduck-owner-canary-capability.v1\nowner-chat-canary\n"+expires+"\n"+digest+"\n"+order.ChatID))
	raw, _ := json.Marshal(sealedCapability{Version: "openduck-owner-canary-capability.v1", Purpose: "owner-chat-canary", Expires: expires, OrderDigest: digest, SessionID: order.ChatID, MAC: hex.EncodeToString(signature)})
	path := filepath.Join(t.TempDir(), "capability")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	auth, err := NewBoundSealedStartupCapability(public, path, time.Now().UTC(), digest, order.ChatID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := GeneralChatOrderDigest(GeneralChatOrder{SchemaVersion: GeneralChatOrderV1, ChatID: "wrong", Prompt: "hello", Classification: "L0", MaxOutputBytes: 1024, ApprovalPolicy: "never", ReadOnly: true, ToolsDisabled: true, NetworkMode: "model_only", WorkspaceRoots: []string{}}); err != nil {
		t.Fatal(err)
	}
	if _, err := NewBoundSealedStartupCapability(public, path, time.Now().UTC(), "sha256:"+strings.Repeat("a", 64), order.ChatID); err == nil {
		t.Fatal("wrong order digest accepted")
	}
	if err := auth.Authorize(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := auth.Authorize(context.Background()); err == nil {
		t.Fatal("sealed capability reused")
	}
}

type observerFixture struct{}

func (observerFixture) Observe(context.Context, string, string) (string, string, error) {
	return "node-1/codex-1", "sha256:" + strings.Repeat("a", 64), nil
}

type starterFixture struct{ process *scriptedProcess }
type sandboxFixture struct{}

func (sandboxFixture) Prepare(context.Context, string, string) error { return nil }

type countingObserver struct{ n int }

func (o *countingObserver) Observe(context.Context, string, string) (string, string, error) {
	o.n++
	return "fixture", "sha256:" + strings.Repeat("a", 64), nil
}

func (s starterFixture) Start(_ context.Context, l Launch) (Process, error) {
	if l.Home == "" || l.Worktree == "" {
		return nil, ErrUnsafeRuntime
	}
	return s.process, nil
}

func TestOwnerTransportUsesOwnerHomeWithoutReadingItAndBuildsObservedInventory(t *testing.T) {
	ownerHome := filepath.Join(t.TempDir(), "codex-home")
	p := &scriptedProcess{pid: 88, scripted: scripted{responses: []string{
		response(1, `{}`),
		response(2, `{"account":{"type":"chatgpt"}}`),
		response(3, `{"config":{"approval_policy":"never","tools":[]}}`),
		response(4, `{"instructions":[]}`),
	}}}
	transport, err := NewOwnerHomeCodexTransport(OwnerCodexConfig{Binary: "/opt/codex.js", Interpreter: "/opt/node", OwnerHome: ownerHome, Starter: starterFixture{process: p}, Authenticator: allowChatAuth{}, ProcessGate: allowChatGate{}, Observer: observerFixture{}, Sandbox: sandboxFixture{}})
	if err != nil {
		t.Fatal(err)
	}
	inv, err := transport.Inventory(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if inv.AccountState != "chatgpt" || !inv.ModelNetworkOnly || len(inv.ToolInventory) != 0 || inv.ExecutableVersion == "" {
		t.Fatalf("inventory=%+v", inv)
	}
	if !strings.Contains(strings.Join(p.writes, ""), `"method":"account/get"`) || strings.Contains(strings.Join(p.writes, ""), "auth.json") {
		t.Fatalf("writes=%s", strings.Join(p.writes, ""))
	}
	_ = transport.Close()
}

func TestLoginStartColdLaunchUsesVerifiedStart(t *testing.T) {
	o := &countingObserver{}
	p := &scriptedProcess{scripted: scripted{responses: []string{response(1, `{}`), response(2, `{"loginId":"login-1","authUrl":"https://example.invalid"}`)}}}
	tx, err := NewOwnerHomeCodexTransport(OwnerCodexConfig{Binary: "/opt/codex.js", Interpreter: "/opt/node", OwnerHome: filepath.Join(t.TempDir(), "home"), Starter: starterFixture{process: p}, Authenticator: allowChatAuth{}, ProcessGate: allowChatGate{}, Observer: o, Sandbox: sandboxFixture{}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.LoginStart(context.Background(), "chatgpt"); err != nil {
		t.Fatal(err)
	}
	if o.n != 2 {
		t.Fatalf("expected pre/post observation, got %d", o.n)
	}
}
