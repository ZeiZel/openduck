package codexruntime

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

var (
	ErrOwnerAuthorization = errors.New("owner authorization required")
	ErrProcessGate        = errors.New("unsafe local runtime process state")
)

// OwnerAuthenticator is the sole authority for enabling this canary. A
// loopback HTTP session or browser origin is not an authenticator.
type OwnerAuthenticator interface{ Authorize(context.Context) error }
type ProcessGate interface{ Check(context.Context) error }
type ExecutableObserver interface {
	Observe(context.Context, string, string) (version, digest string, err error)
}

type OwnerCodexConfig struct {
	Binary        string
	Interpreter   string
	OwnerHome     string
	Starter       Starter
	Authenticator OwnerAuthenticator
	ProcessGate   ProcessGate
	Observer      ExecutableObserver
	// Sandbox must independently confine the child to Worktree before launch;
	// app-server 0.142.3 itself has no restricted-root turn policy.
	Sandbox OwnerProcessSandbox
}
type OwnerProcessSandbox interface {
	Prepare(context.Context, string, string) error
}

type OwnerHomeCodexTransport struct {
	cfg       OwnerCodexConfig
	process   Process
	client    *Client
	threadID  string
	worktree  string
	inventory RuntimeInventory
	mu        sync.Mutex
	closed    bool
	loginID   string
}

func NewDedicatedCodexHome(cfg OwnerCodexConfig) (*OwnerHomeCodexTransport, error) {
	if cfg.OwnerHome == "" || !filepath.IsAbs(cfg.OwnerHome) || filepath.Clean(cfg.OwnerHome) != cfg.OwnerHome || cfg.OwnerHome == string(filepath.Separator) {
		return nil, ErrUnsafeRuntime
	}
	if err := ensureDedicatedHome(cfg.OwnerHome); err != nil {
		return nil, err
	}
	return NewOwnerHomeCodexTransport(cfg)
}

// PrepareDedicatedOwnerHome is the only production home constructor. It
// creates a fixed child under an explicit private OpenDuck state root, writes
// the deny-all config before a process starts, and pins its digest in a small
// authority marker. Existing ambient ~/.codex is never accepted.
func PrepareDedicatedOwnerHome(stateRoot string) (string, error) {
	if stateRoot == "" || !filepath.IsAbs(stateRoot) || filepath.Clean(stateRoot) != stateRoot || filepath.Base(stateRoot) == ".codex" {
		return "", ErrUnsafeRuntime
	}
	root, err := os.Lstat(stateRoot)
	if err != nil || root.Mode()&os.ModeSymlink != 0 || !root.IsDir() || root.Mode().Perm() != 0700 || !ownedByCurrentUser(root) {
		return "", ErrUnsafeRuntime
	}
	home := filepath.Join(stateRoot, ownerHomeName)
	if filepath.Clean(home) == filepath.Join(os.Getenv("HOME"), ".codex") {
		return "", ErrUnsafeRuntime
	}
	if err := ensureDedicatedHome(home); err != nil {
		return "", err
	}
	return home, pinDedicatedHome(home)
}

func ensureDedicatedHome(path string) error {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		if err := os.MkdirAll(path, 0700); err != nil {
			return ErrUnsafeRuntime
		}
		info, err = os.Lstat(path)
	}
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm() != 0700 || !ownedByCurrentUser(info) {
		return ErrUnsafeRuntime
	}
	return nil
}

const ownerConfig = "approval_policy = \"never\"\nsandbox_mode = \"read-only\"\nnetwork_access = true\n# OpenDuck owner-chat canary: no plugins, MCP, apps, hooks, web, or multi-agent.\n"

type homeAuthority struct {
	Version      string `json:"version"`
	ConfigDigest string `json:"config_digest"`
}

func pinDedicatedHome(home string) error {
	config := filepath.Join(home, "config.toml")
	marker := filepath.Join(home, ".openduck-owner-home.json")
	for _, forbidden := range []string{"plugins", "mcp", "hooks", "apps", "config.json", ".mcp.json", ".codex"} {
		if _, err := os.Lstat(filepath.Join(home, forbidden)); err == nil {
			return ErrUnsafeRuntime
		} else if !os.IsNotExist(err) {
			return ErrUnsafeRuntime
		}
	}
	digest := sha256.Sum256([]byte(ownerConfig))
	want := "sha256:" + hex.EncodeToString(digest[:])
	ci, cerr := os.Lstat(config)
	mi, merr := os.Lstat(marker)
	if os.IsNotExist(cerr) && os.IsNotExist(merr) {
		if err := os.WriteFile(config, []byte(ownerConfig), 0600); err != nil {
			return ErrUnsafeRuntime
		}
		raw, _ := json.Marshal(homeAuthority{Version: "openduck-owner-home.v1", ConfigDigest: want})
		if err := os.WriteFile(marker, raw, 0600); err != nil {
			return ErrUnsafeRuntime
		}
		return nil
	}
	if cerr != nil || merr != nil || ci.Mode()&os.ModeSymlink != 0 || mi.Mode()&os.ModeSymlink != 0 || !ci.Mode().IsRegular() || !mi.Mode().IsRegular() || ci.Mode().Perm() != 0600 || mi.Mode().Perm() != 0600 || !ownedByCurrentUser(ci) || !ownedByCurrentUser(mi) {
		return ErrUnsafeRuntime
	}
	raw, err := os.ReadFile(config)
	if err != nil || string(raw) != ownerConfig {
		return ErrUnsafeRuntime
	}
	raw, err = os.ReadFile(marker)
	if err != nil {
		return ErrUnsafeRuntime
	}
	var got homeAuthority
	if json.Unmarshal(raw, &got) != nil || got.Version != "openduck-owner-home.v1" || got.ConfigDigest != want {
		return ErrUnsafeRuntime
	}
	return nil
}

// NewOwnerHomeCodexTransport only validates path shape. It never opens or
// copies CODEX_HOME and never reads auth.json or any other credential store.
func NewOwnerHomeCodexTransport(cfg OwnerCodexConfig) (*OwnerHomeCodexTransport, error) {
	if cfg.Binary == "" || !filepath.IsAbs(cfg.Binary) || filepath.Clean(cfg.Binary) != cfg.Binary || cfg.OwnerHome == "" || !filepath.IsAbs(cfg.OwnerHome) || filepath.Clean(cfg.OwnerHome) != cfg.OwnerHome || cfg.OwnerHome == string(filepath.Separator) || cfg.Authenticator == nil || cfg.ProcessGate == nil || cfg.Observer == nil || cfg.Sandbox == nil {
		return nil, ErrUnsafeRuntime
	}
	if cfg.Interpreter != "" && (!filepath.IsAbs(cfg.Interpreter) || filepath.Clean(cfg.Interpreter) != cfg.Interpreter) {
		return nil, ErrUnsafeRuntime
	}
	if cfg.Starter == nil {
		cfg.Starter = execStarter{}
	}
	if err := ensureDedicatedHome(cfg.OwnerHome); err != nil {
		return nil, err
	}
	if err := pinDedicatedHome(cfg.OwnerHome); err != nil {
		return nil, err
	}
	return &OwnerHomeCodexTransport{cfg: cfg}, nil
}

// startVerifiedLocked is the sole app-server launch path. It verifies both
// executable components before and after sandbox preparation, before Starter
// receives control.
func (t *OwnerHomeCodexTransport) startVerifiedLocked(ctx context.Context) (string, string, error) {
	version, digest, err := t.cfg.Observer.Observe(ctx, t.cfg.Binary, t.cfg.Interpreter)
	if err != nil || version == "" || !validDigestString(digest) {
		return "", "", ErrUnsafeInventory
	}
	worktree, err := os.MkdirTemp("", "openduck-chat-cwd-")
	if err != nil {
		return "", "", err
	}
	if err := t.cfg.Sandbox.Prepare(ctx, worktree, t.cfg.OwnerHome); err != nil {
		_ = os.RemoveAll(worktree)
		return "", "", ErrUnsafeRuntime
	}
	version2, digest2, err := t.cfg.Observer.Observe(ctx, t.cfg.Binary, t.cfg.Interpreter)
	if err != nil || version2 != version || digest2 != digest {
		_ = os.RemoveAll(worktree)
		return "", "", ErrUnsafeRuntime
	}
	p, err := t.cfg.Starter.Start(ctx, Launch{Binary: t.cfg.Binary, Interpreter: t.cfg.Interpreter, Home: t.cfg.OwnerHome, Worktree: worktree})
	if err != nil {
		_ = os.RemoveAll(worktree)
		return "", "", err
	}
	t.process, t.client, t.worktree = p, NewClient(p), worktree
	if err := t.client.Initialize(ctx, InitializeParams{ClientInfo: ClientInfo{Name: "openduck-owner-chat", Version: "0.1.0"}}); err != nil {
		t.closeLocked()
		return "", "", err
	}
	return version, digest, nil
}

func (t *OwnerHomeCodexTransport) Inventory(ctx context.Context) (RuntimeInventory, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return RuntimeInventory{}, ErrProcessGate
	}
	if err := t.cfg.ProcessGate.Check(ctx); err != nil {
		return RuntimeInventory{}, ErrProcessGate
	}
	if t.client != nil {
		return t.inventory, nil
	}
	version, digest, err := t.startVerifiedLocked(ctx)
	if err != nil {
		return RuntimeInventory{}, err
	}
	account, err := t.client.CallMetadata(ctx, "account/get", map[string]any{"refreshToken": false})
	if err != nil {
		t.closeLocked()
		return RuntimeInventory{}, err
	}
	config, err := t.client.CallMetadata(ctx, "config/read", map[string]any{"cwd": t.worktree, "includeLayers": true})
	if err != nil {
		t.closeLocked()
		return RuntimeInventory{}, err
	}
	if unsafeMetadata(config) {
		t.closeLocked()
		return RuntimeInventory{}, ErrUnsafeInventory
	}
	state := accountState(account)
	if state != "chatgpt" {
		t.closeLocked()
		return RuntimeInventory{}, ErrUnsafeInventory
	}
	t.inventory = RuntimeInventory{SchemaVersion: RuntimeInventoryV1, AccountState: state, InstructionSources: []string{}, ExecutableVersion: version, ExecutableDigest: digest, ModelNetworkOnly: true}
	if err := t.inventory.Validate(); err != nil {
		t.closeLocked()
		return RuntimeInventory{}, err
	}
	return t.inventory, nil
}

func (t *OwnerHomeCodexTransport) LoginStart(ctx context.Context, accountType string) (LoginStartResult, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return LoginStartResult{}, ErrProcessGate
	}
	if err := t.cfg.Authenticator.Authorize(ctx); err != nil {
		return LoginStartResult{}, ErrOwnerAuthorization
	}
	if err := t.cfg.ProcessGate.Check(ctx); err != nil {
		return LoginStartResult{}, ErrProcessGate
	}
	if t.client == nil {
		if _, _, err := t.startVerifiedLocked(ctx); err != nil {
			return LoginStartResult{}, err
		}
	}
	login, err := t.client.LoginStart(ctx, accountType)
	if err == nil {
		t.loginID = login.LoginID
	}
	return login, err
}

func (t *OwnerHomeCodexTransport) LoginCompleted(ctx context.Context, loginID string) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed || t.client == nil || loginID == "" || loginID != t.loginID {
		return ErrOwnerAuthorization
	}
	if err := t.cfg.ProcessGate.Check(ctx); err != nil {
		return ErrProcessGate
	}
	if err := t.client.WaitLoginCompleted(ctx, loginID); err != nil {
		return err
	}
	raw, err := t.client.CallMetadata(ctx, "account/get", map[string]any{"refreshToken": false})
	if err != nil {
		return err
	}
	if accountState(raw) != "chatgpt" {
		return ErrOwnerAuthorization
	}
	t.loginID = "" // notification capability is single-use
	return nil
}

func (t *OwnerHomeCodexTransport) Turn(ctx context.Context, order GeneralChatOrder) (AssistantTurnResult, error) {
	if err := order.Validate(); err != nil {
		return AssistantTurnResult{}, err
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.client == nil || t.process == nil || t.closed {
		return AssistantTurnResult{}, ErrUnsafeInventory
	}
	if t.threadID == "" {
		details, err := t.client.StartThreadDetails(ctx, ThreadParams{CWD: t.worktree, Model: order.Model, ApprovalPolicy: "never", Sandbox: "read-only"})
		if err != nil {
			return AssistantTurnResult{}, err
		}
		if len(details.InstructionSources) != 0 {
			return AssistantTurnResult{}, ErrUnsafeInventory
		}
		t.threadID = details.ID
	}
	started := time.Now().UTC()
	// The app-server schema cannot express restricted roots in this version.
	// A production launch therefore requires the independent OS sandbox wrapper;
	// without it construction fails closed before a model turn.
	if err := t.client.StartTurn(ctx, TurnParams{ThreadID: t.threadID, Prompt: order.Prompt, ApprovalPolicy: "never", CWD: t.worktree}); err != nil {
		return AssistantTurnResult{}, err
	}
	doneSignal := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = t.client.Close()
			_ = t.process.Terminate()
		case <-doneSignal:
		}
	}()
	done, err := t.client.ReadAssistantCompleted(ctx, order.MaxOutputBytes)
	close(doneSignal)
	if err != nil {
		return AssistantTurnResult{}, err
	}
	if done.ThreadID != t.threadID {
		return AssistantTurnResult{}, ErrProtocol
	}
	return AssistantTurnResult{SchemaVersion: AssistantTurnResultV1, ChatID: order.ChatID, ThreadID: done.ThreadID, TurnID: done.TurnID, State: "completed", Answer: done.Answer, StartedAt: started, CompletedAt: time.Now().UTC()}, nil
}

func validDigestString(v string) bool { return len(v) == 71 && strings.HasPrefix(v, "sha256:") }
func accountState(raw json.RawMessage) string {
	var v map[string]any
	if json.Unmarshal(raw, &v) != nil {
		return ""
	}
	if account, ok := v["account"].(map[string]any); ok {
		if typ, ok := account["type"].(string); ok {
			return typ
		}
	}
	if s, ok := v["status"].(string); ok && s != "" {
		return s
	}
	return ""
}
func unsafeMetadata(raw json.RawMessage) bool {
	var v any
	if json.Unmarshal(raw, &v) != nil {
		return true
	}
	return hasUnsafeMetadata(v)
}
func hasUnsafeMetadata(v any) bool {
	switch x := v.(type) {
	case map[string]any:
		for k, value := range x {
			lower := strings.ToLower(k)
			if lower == "tools" || lower == "mcp" || lower == "mcpservers" || lower == "apps" || lower == "plugins" || lower == "hooks" || lower == "web" || lower == "multiagent" {
				switch y := value.(type) {
				case nil:
				case bool:
					if y {
						return true
					}
				case string:
					if y != "" {
						return true
					}
				case []any:
					if len(y) > 0 {
						return true
					}
				case map[string]any:
					if len(y) > 0 {
						return true
					}
				default:
					return true
				}
			}
			if hasUnsafeMetadata(value) {
				return true
			}
		}
	case []any:
		for _, value := range x {
			if hasUnsafeMetadata(value) {
				return true
			}
		}
	}
	return false
}
func (t *OwnerHomeCodexTransport) closeLocked() {
	if t.closed {
		return
	}
	t.closed = true
	if t.process != nil {
		_ = t.process.Terminate()
		_ = t.process.Wait()
	}
	if t.worktree != "" {
		_ = os.RemoveAll(t.worktree)
	}
	t.client = nil
}
func (t *OwnerHomeCodexTransport) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.closeLocked()
	return nil
}

var _ io.Closer = (*OwnerHomeCodexTransport)(nil)
