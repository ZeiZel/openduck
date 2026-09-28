package codexruntime

// Chat canary is deliberately separate from the worker protocol. A general
// chat is an owner-only, read-only conversation and must never be accepted as
// a WorkOrder or produce WorkerResult evidence.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"openduck/internal/localpd"
)

const (
	GeneralChatOrderV1    = "general-chat-order.v1"
	AssistantTurnResultV1 = "assistant-turn-result.v1"
	RuntimeInventoryV1    = "codex-runtime-inventory.v1"
	MaxChatPromptBytes    = 64 << 10
	MaxAssistantBytes     = 256 << 10
	MaxWorkspaceRoots     = 32
)

var (
	ErrChatRejected                  = errors.New("general chat rejected")
	ErrLocalPDUnavailable            = errors.New("local PD unavailable")
	ErrUnsafeInventory               = errors.New("unsafe Codex runtime inventory")
	ErrWorkspaceExecutionUnavailable = errors.New("workspace execution unavailable")
	ErrApprovalRequired              = errors.New("owner approval required")
)

type ApprovalRequiredError struct {
	RequestID   string
	OrderDigest string
	ExpiresAt   time.Time
}

func (e ApprovalRequiredError) Error() string { return "owner approval required" }
func (e ApprovalRequiredError) Unwrap() error { return ErrApprovalRequired }

type approvalRequestContextKey struct{}

// WithApprovalRequestID carries the stable owner-approval attempt selected by
// the UI. It is transport metadata, never part of the signed chat order.
func WithApprovalRequestID(ctx context.Context, requestID string) context.Context {
	return context.WithValue(ctx, approvalRequestContextKey{}, requestID)
}
func ApprovalRequestID(ctx context.Context) string {
	requestID, _ := ctx.Value(approvalRequestContextKey{}).(string)
	return requestID
}

type GeneralChatOrder struct {
	SchemaVersion  string   `json:"schema_version"`
	ChatID         string   `json:"chat_id"`
	ThreadID       string   `json:"thread_id,omitempty"`
	Prompt         string   `json:"prompt"`
	WorkspaceRoots []string `json:"workspace_roots"`
	Classification string   `json:"classification"`
	Model          string   `json:"model,omitempty"`
	MaxOutputBytes int      `json:"max_output_bytes"`
	ApprovalPolicy string   `json:"approval_policy"`
	ReadOnly       bool     `json:"read_only"`
	ToolsDisabled  bool     `json:"tools_disabled"`
	NetworkMode    string   `json:"network_mode"`
}

func (o GeneralChatOrder) Validate() error {
	if o.SchemaVersion != GeneralChatOrderV1 || o.ChatID == "" || o.Prompt == "" || len([]byte(o.Prompt)) > MaxChatPromptBytes || o.Classification != "L0" && o.Classification != "L1" || o.ApprovalPolicy != "never" || !o.ReadOnly || !o.ToolsDisabled || o.NetworkMode != "model_only" || o.MaxOutputBytes <= 0 || o.MaxOutputBytes > MaxAssistantBytes {
		return ErrChatRejected
	}
	if len(o.ChatID) > 256 || strings.ContainsAny(o.ChatID, "\r\n") || strings.ContainsAny(o.ThreadID, "\r\n") || len(o.WorkspaceRoots) > MaxWorkspaceRoots {
		return ErrChatRejected
	}
	if len(o.WorkspaceRoots) != 0 {
		// Raw paths are never forwarded to the broker. Until an authenticated
		// workspace-group capability is attached to this order, execution is
		// explicitly unavailable rather than silently dropping the roots.
		return ErrWorkspaceExecutionUnavailable
	}
	for _, root := range o.WorkspaceRoots {
		if root == "" || !filepath.IsAbs(root) || filepath.Clean(root) != root || root == string(filepath.Separator) {
			return ErrChatRejected
		}
	}
	return nil
}

type AssistantTurnResult struct {
	SchemaVersion string    `json:"schema_version"`
	ChatID        string    `json:"chat_id"`
	ThreadID      string    `json:"thread_id,omitempty"`
	TurnID        string    `json:"turn_id,omitempty"`
	State         string    `json:"state"`
	Answer        string    `json:"answer,omitempty"`
	ErrorCode     string    `json:"error_code,omitempty"`
	StartedAt     time.Time `json:"started_at"`
	CompletedAt   time.Time `json:"completed_at,omitempty"`
}

func (r AssistantTurnResult) Validate() error {
	if r.SchemaVersion != AssistantTurnResultV1 || r.ChatID == "" || r.State == "" || len([]byte(r.Answer)) > MaxAssistantBytes {
		return ErrChatRejected
	}
	switch r.State {
	case "pending", "running":
		if r.Answer != "" || r.ErrorCode != "" {
			return ErrChatRejected
		}
	case "completed":
		if r.Answer == "" || r.ErrorCode != "" {
			return ErrChatRejected
		}
	case "failed", "cancelled":
		if r.Answer != "" || r.ErrorCode == "" {
			return ErrChatRejected
		}
	default:
		return ErrChatRejected
	}
	return nil
}

// RuntimeInventory is observation-only metadata. It must never contain an
// auth path's contents, token, cookie, prompt, or transcript.
type RuntimeInventory struct {
	SchemaVersion      string   `json:"schema_version"`
	AccountState       string   `json:"account_state"`
	InstructionSources []string `json:"instruction_sources"`
	ToolInventory      []string `json:"tool_inventory"`
	MCPInventory       []string `json:"mcp_inventory"`
	AppInventory       []string `json:"app_inventory"`
	PluginInventory    []string `json:"plugin_inventory"`
	HookInventory      []string `json:"hook_inventory"`
	WebEnabled         bool     `json:"web_enabled"`
	MultiAgentEnabled  bool     `json:"multi_agent_enabled"`
	ExecutableVersion  string   `json:"executable_version"`
	ExecutableDigest   string   `json:"executable_digest"`
	ModelNetworkOnly   bool     `json:"model_network_only"`
}

func (i RuntimeInventory) Validate() error {
	if i.SchemaVersion != RuntimeInventoryV1 || i.AccountState == "" || i.ExecutableVersion == "" || i.ExecutableDigest == "" || !i.ModelNetworkOnly || i.WebEnabled || i.MultiAgentEnabled || len(i.ToolInventory) != 0 || len(i.MCPInventory) != 0 || len(i.AppInventory) != 0 || len(i.PluginInventory) != 0 || len(i.HookInventory) != 0 {
		return ErrUnsafeInventory
	}
	return nil
}

type ChatTransport interface {
	Inventory(context.Context) (RuntimeInventory, error)
	Turn(context.Context, GeneralChatOrder) (AssistantTurnResult, error)
}

type OwnerCanary struct {
	transport   ChatTransport
	ownerHome   string
	authorizer  OwnerAuthenticator
	processGate ProcessGate
	ledger      *ChatRunLedger
}

// BoundOwnerAuthenticator can bind the one-use owner grant to the exact
// immutable order being started. Plain OwnerAuthenticator remains supported
// for synthetic tests and non-production callers.
type BoundOwnerAuthenticator interface {
	AuthorizeOrder(context.Context, GeneralChatOrder) error
}

func GeneralChatOrderDigest(order GeneralChatOrder) (string, error) {
	raw, err := json.Marshal(order)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// NewOwnerCanary refuses an absent or broad CODEX_HOME. It does not inspect
// the directory, read auth.json, copy it, or include it in logs/attestations.
func NewOwnerCanary(ownerHome string, transport ChatTransport, authorizer OwnerAuthenticator, processGate ProcessGate, ledger *ChatRunLedger) (*OwnerCanary, error) {
	if transport == nil || authorizer == nil || processGate == nil || ownerHome == "" || !filepath.IsAbs(ownerHome) || filepath.Clean(ownerHome) != ownerHome || ownerHome == string(filepath.Separator) {
		return nil, ErrUnsafeInventory
	}
	return &OwnerCanary{transport: transport, ownerHome: ownerHome, authorizer: authorizer, processGate: processGate, ledger: ledger}, nil
}

// NewBoundOwnerCanary is the production constructor. The broker owns runtime
// process/profile details, so Controller receives no filesystem home or binary
// path at this boundary.
func NewBoundOwnerCanary(transport ChatTransport, authorizer OwnerAuthenticator, processGate ProcessGate, ledger *ChatRunLedger) (*OwnerCanary, error) {
	if transport == nil || authorizer == nil || processGate == nil {
		return nil, ErrUnsafeInventory
	}
	return &OwnerCanary{transport: transport, authorizer: authorizer, processGate: processGate, ledger: ledger}, nil
}

func (c *OwnerCanary) Run(ctx context.Context, order GeneralChatOrder) (AssistantTurnResult, error) {
	if c == nil || c.transport == nil {
		return AssistantTurnResult{}, ErrChatRejected
	}
	if err := order.Validate(); err != nil {
		return AssistantTurnResult{}, err
	}
	inv, err := c.Preflight(ctx, order)
	if err != nil {
		return AssistantTurnResult{}, err
	}
	return c.runAuthorized(ctx, order, inv)
}

// Preflight consumes the owner start grant exactly once and performs all
// local-PD and runtime checks before any durable chat ledger operation.
func (c *OwnerCanary) Preflight(ctx context.Context, order GeneralChatOrder) (RuntimeInventory, error) {
	if c == nil || c.transport == nil {
		return RuntimeInventory{}, ErrChatRejected
	}
	if err := order.Validate(); err != nil {
		return RuntimeInventory{}, err
	}
	var authErr error
	if bound, ok := c.authorizer.(BoundOwnerAuthenticator); ok {
		authErr = bound.AuthorizeOrder(ctx, order)
	} else {
		authErr = c.authorizer.Authorize(ctx)
	}
	if authErr != nil {
		if errors.Is(authErr, ErrApprovalRequired) {
			return RuntimeInventory{}, authErr
		}
		return RuntimeInventory{}, ErrOwnerAuthorization
	}
	if err := c.processGate.Check(ctx); err != nil {
		return RuntimeInventory{}, ErrProcessGate
	}
	if err := detectChatPrivacy(order); err != nil {
		return RuntimeInventory{}, err
	}
	inv, err := c.transport.Inventory(ctx)
	if err != nil || inv.Validate() != nil {
		return RuntimeInventory{}, ErrUnsafeInventory
	}
	return inv, nil
}

func (c *OwnerCanary) runAuthorized(ctx context.Context, order GeneralChatOrder, _ RuntimeInventory) (AssistantTurnResult, error) {
	if c == nil || c.transport == nil {
		return AssistantTurnResult{}, ErrChatRejected
	}
	if err := order.Validate(); err != nil {
		return AssistantTurnResult{}, err
	}
	var run ChatRunRecord
	var err error
	if c.ledger != nil {
		run, err = c.ledger.Begin(order.ChatID, order.ChatID+":"+order.Prompt, time.Now().UTC())
		if err != nil {
			return AssistantTurnResult{}, err
		}
		if _, err = c.ledger.Transition(run.RunID, run.Version, "running", "", "", time.Now().UTC()); err != nil {
			return AssistantTurnResult{}, err
		}
	}
	result, err := c.transport.Turn(ctx, order)
	if err != nil {
		if c.ledger != nil {
			_, _ = c.ledger.Transition(run.RunID, 2, "failed", "", "RUNTIME_FAILED", time.Now().UTC())
		}
		return AssistantTurnResult{}, err
	}
	if result.ChatID != order.ChatID || result.Validate() != nil {
		if c.ledger != nil {
			_, _ = c.ledger.Transition(run.RunID, 2, "uncertain", "", "INVALID_RESULT", time.Now().UTC())
		}
		return AssistantTurnResult{}, ErrChatRejected
	}
	if result.State == "completed" {
		if err := postscanAssistantAnswer(order, result.Answer); err != nil {
			if c.ledger != nil {
				_, _ = c.ledger.Transition(run.RunID, 2, "failed", "", "LOCAL_PD_UNAVAILABLE", time.Now().UTC())
			}
			return AssistantTurnResult{SchemaVersion: AssistantTurnResultV1, ChatID: order.ChatID, State: "failed", ErrorCode: "LOCAL_PD_UNAVAILABLE", StartedAt: result.StartedAt, CompletedAt: time.Now().UTC()}, ErrLocalPDUnavailable
		}
	}
	if c.ledger != nil {
		_, _ = c.ledger.Transition(run.RunID, 2, "completed", ChatAnswerDigest(result.Answer), "", time.Now().UTC())
	}
	return result, nil
}

func (c *OwnerCanary) Start(ctx context.Context, order GeneralChatOrder) <-chan AssistantTurnResult {
	out := make(chan AssistantTurnResult, 4)
	go func() {
		defer close(out)
		started := time.Now().UTC()
		pending := AssistantTurnResult{SchemaVersion: AssistantTurnResultV1, ChatID: order.ChatID, State: "pending", StartedAt: started}
		out <- pending
		if order.Validate() != nil {
			out <- AssistantTurnResult{SchemaVersion: AssistantTurnResultV1, ChatID: order.ChatID, State: "failed", ErrorCode: "INVALID_ORDER", StartedAt: started, CompletedAt: time.Now().UTC()}
			return
		}
		out <- AssistantTurnResult{SchemaVersion: AssistantTurnResultV1, ChatID: order.ChatID, State: "running", StartedAt: started}
		result, err := c.Run(ctx, order)
		if err != nil {
			code := "RUNTIME_FAILED"
			if errors.Is(err, ErrLocalPDUnavailable) {
				code = "LOCAL_PD_UNAVAILABLE"
			}
			if errors.Is(err, context.Canceled) {
				code = "CANCELLED"
			}
			out <- AssistantTurnResult{SchemaVersion: AssistantTurnResultV1, ChatID: order.ChatID, State: func() string {
				if code == "CANCELLED" {
					return "cancelled"
				}
				return "failed"
			}(), ErrorCode: code, StartedAt: started, CompletedAt: time.Now().UTC()}
			return
		}
		out <- result
	}()
	return out
}

func detectChatPrivacy(o GeneralChatOrder) error {
	content := []byte(o.Prompt)
	if bytes := len(content); bytes == 0 {
		return ErrLocalPDUnavailable
	}
	event := localpd.SourceEvent{ConversationID: o.ChatID, Revision: 1, SourceSequence: 1, IngestOrdinal: 1, ScannedThrough: 1, Complete: true, Content: content}
	d, err := localpd.Detect(event)
	if err != nil || d.Mode != localpd.ModeNormal || d.Class == localpd.ClassL2 || d.Class == localpd.ClassL3 {
		return ErrLocalPDUnavailable
	}
	return nil
}

func postscanAssistantAnswer(o GeneralChatOrder, answer string) error {
	if answer == "" || len([]byte(answer)) > o.MaxOutputBytes {
		return ErrLocalPDUnavailable
	}
	event := localpd.SourceEvent{ConversationID: o.ChatID + ":assistant", Revision: 1, SourceSequence: 1, IngestOrdinal: 1, ScannedThrough: 1, Complete: true, Content: []byte(answer)}
	d, err := localpd.Detect(event)
	if err != nil || d.Mode != localpd.ModeNormal || d.Class == localpd.ClassL2 || d.Class == localpd.ClassL3 {
		return ErrLocalPDUnavailable
	}
	return nil
}

// FakeChatTransport is a deterministic test seam and intentionally cannot
// perform network, tool, or filesystem operations.
type FakeChatTransport struct {
	InventoryValue RuntimeInventory
	Result         AssistantTurnResult
	Calls          int
	mu             sync.Mutex
}

func (f *FakeChatTransport) Inventory(context.Context) (RuntimeInventory, error) {
	return f.InventoryValue, nil
}
func (f *FakeChatTransport) Turn(ctx context.Context, o GeneralChatOrder) (AssistantTurnResult, error) {
	f.mu.Lock()
	f.Calls++
	f.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return AssistantTurnResult{}, err
	}
	r := f.Result
	r.ChatID = o.ChatID
	if r.SchemaVersion == "" {
		r.SchemaVersion = AssistantTurnResultV1
	}
	if r.State == "" {
		r.State = "completed"
	}
	if r.StartedAt.IsZero() {
		r.StartedAt = time.Now().UTC()
	}
	if r.CompletedAt.IsZero() {
		r.CompletedAt = time.Now().UTC()
	}
	return r, nil
}
