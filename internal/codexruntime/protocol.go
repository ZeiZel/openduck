package codexruntime

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"openduck/internal/harness"
	"strings"
)

const maxLineBytes = 256 << 10

var (
	ErrProtocol          = errors.New("codex runtime protocol violation")
	ErrApprovalRequested = errors.New("worker requested approval")
	ErrOutOfOrder        = errors.New("codex runtime event out of order")
)

type Request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      uint64          `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}
type Response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      uint64          `json:"id,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *RPCError       `json:"error,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
}
type RPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}
type InitializeParams struct {
	// ProtocolVersion and ProfileDigest are local binding metadata and are not
	// sent to Codex; app-server requires clientInfo instead.
	ProtocolVersion string     `json:"-"`
	ProfileDigest   string     `json:"-"`
	ClientInfo      ClientInfo `json:"clientInfo"`
}
type ClientInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}
type ThreadParams struct {
	ThreadID        string `json:"-"`
	WorkOrderDigest string `json:"-"`
	CWD             string `json:"cwd,omitempty"`
	Model           string `json:"model,omitempty"`
	ApprovalPolicy  string `json:"approvalPolicy,omitempty"`
	Sandbox         string `json:"sandbox,omitempty"`
}
type TurnParams struct {
	ThreadID        string      `json:"-"`
	WorkOrderDigest string      `json:"-"`
	Prompt          string      `json:"-"`
	Input           []UserInput `json:"input"`
	OutputSchema    any         `json:"outputSchema,omitempty"`
	SandboxPolicy   any         `json:"sandboxPolicy,omitempty"`
	ApprovalPolicy  string      `json:"approvalPolicy,omitempty"`
	CWD             string      `json:"cwd,omitempty"`
	Model           string      `json:"model,omitempty"`
}
type UserInput struct {
	Type string `json:"type"`
	Text string `json:"text,omitempty"`
}
type Completed struct {
	ThreadID     string               `json:"threadId"`
	TurnID       string               `json:"-"`
	Result       json.RawMessage      `json:"turn"`
	WorkerResult harness.WorkerResult `json:"-"`
}

type AssistantCompleted struct{ ThreadID, TurnID, Answer string }
type LoginStartResult struct {
	AuthURL         string `json:"authUrl,omitempty"`
	VerificationURL string `json:"verificationUrl,omitempty"`
	UserCode        string `json:"userCode,omitempty"`
	LoginID         string `json:"loginId,omitempty"`
}

func (c *Client) LoginStart(ctx context.Context, accountType string) (LoginStartResult, error) {
	if accountType != "chatgpt" && accountType != "chatgptDeviceCode" {
		return LoginStartResult{}, ErrProtocol
	}
	raw, err := c.call(ctx, "account/login/start", map[string]any{"type": accountType})
	if err != nil {
		return LoginStartResult{}, err
	}
	var out LoginStartResult
	if json.Unmarshal(raw, &out) != nil || (out.AuthURL == "" && out.VerificationURL == "" && out.UserCode == "") {
		return LoginStartResult{}, ErrProtocol
	}
	return out, nil
}

// WaitLoginCompleted consumes the server notification emitted for the login
// session. It is deliberately not an RPC request in app-server v2.
func (c *Client) WaitLoginCompleted(ctx context.Context, loginID string) error {
	if loginID == "" {
		return ErrProtocol
	}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		line, err := c.readLine()
		if err != nil {
			return err
		}
		var n struct {
			Method string `json:"method"`
			Params struct {
				Success bool   `json:"success"`
				Error   any    `json:"error"`
				LoginID string `json:"loginId"`
			} `json:"params"`
		}
		if json.Unmarshal(line, &n) != nil {
			return ErrProtocol
		}
		if n.Method != "account/login/completed" {
			continue
		}
		if n.Params.LoginID != loginID || !n.Params.Success || n.Params.Error != nil {
			return ErrProtocol
		}
		return nil
	}
}

type Client struct {
	rw            io.ReadWriter
	in            *bufio.Reader
	next          uint64
	initialized   bool
	threadStarted bool
	turnStarted   bool
	threadID      string
	turnID        string
}

func NewClient(rw io.ReadWriter) *Client {
	return &Client{rw: rw, in: bufio.NewReaderSize(rw, maxLineBytes)}
}

// CallMetadata is intentionally limited to read-only app-server metadata
// methods. It is not a general RPC escape hatch for chat or worker callers.
func (c *Client) CallMetadata(ctx context.Context, method string, params any) (json.RawMessage, error) {
	switch method {
	case "account/get", "config/read":
		return c.call(ctx, method, params)
	default:
		return nil, ErrProtocol
	}
}

// Close allows a supervising launcher to interrupt a blocked read. The
// protocol itself cannot make arbitrary io.ReadWriter implementations
// cancelable; production transports must therefore also implement io.Closer.
func (c *Client) Close() error {
	if closer, ok := c.rw.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}
func (c *Client) call(ctx context.Context, method string, params any) (json.RawMessage, error) {
	if ctx == nil {
		return nil, ErrProtocol
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if method == "approval/request" || method == "item/commandExecution/requestApproval" || method == "exec/approval_required" {
		return nil, ErrApprovalRequested
	}
	c.next++
	p, e := json.Marshal(params)
	if e != nil {
		return nil, e
	}
	req := Request{JSONRPC: "2.0", ID: c.next, Method: method, Params: p}
	b, e := json.Marshal(req)
	if e != nil {
		return nil, e
	}
	b = append(b, '\n')
	if _, e = c.rw.Write(b); e != nil {
		return nil, e
	}
	for {
		line, e := c.readLine()
		if e != nil {
			return nil, fmt.Errorf("%w: read response", ErrProtocol)
		}
		var msg map[string]json.RawMessage
		if e = json.Unmarshal(line, &msg); e != nil {
			return nil, fmt.Errorf("%w: response", ErrProtocol)
		}
		if methodRaw, ok := msg["method"]; ok {
			var name string
			_ = json.Unmarshal(methodRaw, &name)
			if name == "approval/request" || name == "item/commandExecution/requestApproval" || name == "exec/approval_required" || name == "item/fileChange/requestApproval" {
				return nil, ErrApprovalRequested
			}
			// Server requests must be answered so the stream cannot deadlock. No
			// request is permitted by this client, therefore fail closed.
			if id, ok := msg["id"]; ok {
				c.writeError(id, -32601, "unsupported server request")
			}
			continue
		}
		id, ok := msg["id"]
		if !ok {
			continue
		}
		var got uint64
		if json.Unmarshal(id, &got) != nil || got != req.ID {
			return nil, fmt.Errorf("%w: response id", ErrProtocol)
		}
		if eraw, ok := msg["error"]; ok && string(eraw) != "null" {
			return nil, fmt.Errorf("%w: response error", ErrProtocol)
		}
		result, ok := msg["result"]
		if !ok {
			return nil, fmt.Errorf("%w: response result", ErrProtocol)
		}
		return result, nil
	}
}

func (c *Client) writeError(id json.RawMessage, code int, message string) {
	b, _ := json.Marshal(map[string]any{"id": id, "error": map[string]any{"code": code, "message": message}})
	b = append(b, '\n')
	_, _ = c.rw.Write(b)
}

func (c *Client) readLine() ([]byte, error) {
	var line []byte
	for {
		part, e := c.in.ReadSlice('\n')
		line = append(line, part...)
		if len(line) > maxLineBytes {
			return nil, ErrProtocol
		}
		if e == nil {
			return line, nil
		}
		if !errors.Is(e, bufio.ErrBufferFull) {
			return nil, e
		}
	}
}
func bytesReader(b []byte) *byteReader { return &byteReader{b: b} }

type byteReader struct{ b []byte }

func (r *byteReader) Read(p []byte) (int, error) {
	if len(r.b) == 0 {
		return 0, io.EOF
	}
	n := copy(p, r.b)
	r.b = r.b[n:]
	return n, nil
}
func (c *Client) Initialize(ctx context.Context, p InitializeParams) error {
	if c.initialized {
		return ErrOutOfOrder
	}
	if p.ClientInfo.Name == "" {
		p.ClientInfo.Name = "openduck"
	}
	if p.ClientInfo.Version == "" {
		p.ClientInfo.Version = "0.1.0"
	}
	if _, e := c.call(ctx, "initialize", struct {
		ClientInfo ClientInfo `json:"clientInfo"`
	}{p.ClientInfo}); e != nil {
		return e
	}
	if _, e := c.rw.Write([]byte(`{"method":"initialized","params":{}}
`)); e != nil {
		return e
	}
	c.initialized = true
	return nil
}
func (c *Client) StartThread(ctx context.Context, p ThreadParams) (string, error) {
	details, err := c.StartThreadDetails(ctx, p)
	return details.ID, err
}

type ThreadDetails struct {
	ID                 string
	InstructionSources []string
}

func (c *Client) StartThreadDetails(ctx context.Context, p ThreadParams) (ThreadDetails, error) {
	if !c.initialized || c.threadStarted {
		return ThreadDetails{}, ErrOutOfOrder
	}
	if p.ApprovalPolicy == "" {
		p.ApprovalPolicy = "never"
	}
	b, e := c.call(ctx, "thread/start", struct {
		CWD            string `json:"cwd,omitempty"`
		Model          string `json:"model,omitempty"`
		ApprovalPolicy string `json:"approvalPolicy,omitempty"`
		Sandbox        string `json:"sandbox,omitempty"`
	}{p.CWD, p.Model, p.ApprovalPolicy, p.Sandbox})
	if e != nil {
		return ThreadDetails{}, e
	}
	var v struct {
		Thread struct {
			ID                 string   `json:"id"`
			InstructionSources []string `json:"instructionSources"`
		} `json:"thread"`
		InstructionSources []string `json:"instructionSources"`
	}
	if json.Unmarshal(b, &v) != nil || v.Thread.ID == "" {
		return ThreadDetails{}, ErrProtocol
	}
	c.threadStarted = true
	c.threadID = v.Thread.ID
	sources := v.InstructionSources
	if sources == nil {
		sources = v.Thread.InstructionSources
	} // compatibility fixture only
	return ThreadDetails{ID: v.Thread.ID, InstructionSources: append([]string(nil), sources...)}, nil
}
func (c *Client) ResumeThread(ctx context.Context, p ThreadParams) error {
	if !c.initialized || c.threadStarted {
		return ErrOutOfOrder
	}
	if _, e := c.call(ctx, "thread/resume", struct {
		ThreadID string `json:"threadId"`
	}{p.ThreadID}); e != nil {
		return e
	}
	c.threadStarted = true
	return nil
}
func (c *Client) StartTurn(ctx context.Context, p TurnParams) error {
	if !c.threadStarted || c.turnStarted {
		return ErrOutOfOrder
	}
	input := p.Input
	if len(input) == 0 && p.Prompt != "" {
		input = []UserInput{{Type: "text", Text: p.Prompt}}
	}
	if p.ApprovalPolicy == "" {
		p.ApprovalPolicy = "never"
	}
	b, e := c.call(ctx, "turn/start", struct {
		ThreadID       string      `json:"threadId"`
		Input          []UserInput `json:"input"`
		OutputSchema   any         `json:"outputSchema,omitempty"`
		SandboxPolicy  any         `json:"sandboxPolicy,omitempty"`
		ApprovalPolicy string      `json:"approvalPolicy,omitempty"`
		CWD            string      `json:"cwd,omitempty"`
		Model          string      `json:"model,omitempty"`
	}{p.ThreadID, input, p.OutputSchema, p.SandboxPolicy, p.ApprovalPolicy, p.CWD, p.Model})
	if e != nil {
		return e
	}
	var result struct {
		Turn struct {
			ID string `json:"id"`
		} `json:"turn"`
	}
	if json.Unmarshal(b, &result) != nil || result.Turn.ID == "" {
		return ErrProtocol
	}
	c.turnID = result.Turn.ID
	c.turnStarted = true
	return nil
}
func (c *Client) ReadCompleted(ctx context.Context) (Completed, error) {
	if !c.turnStarted {
		return Completed{}, ErrOutOfOrder
	}
	var worker harness.WorkerResult
	gotWorker := false
	for {
		line, e := c.readLine()
		if e != nil {
			return Completed{}, e
		}
		var r struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
			Params json.RawMessage `json:"params"`
		}
		if e = json.Unmarshal(line, &r); e != nil {
			return Completed{}, ErrProtocol
		}
		if r.Method == "approval/request" || r.Method == "item/commandExecution/requestApproval" || r.Method == "item/fileChange/requestApproval" || r.Method == "exec/approval_required" {
			return Completed{}, ErrApprovalRequested
		}
		if r.Method != "" && len(r.ID) > 0 {
			c.writeError(r.ID, -32601, "unsupported server request")
			continue
		}
		if r.Method != "turn/completed" {
			if r.Method == "item/completed" {
				var item struct {
					Item struct {
						Type string `json:"type"`
						Text string `json:"text"`
					} `json:"item"`
				}
				if json.Unmarshal(r.Params, &item) != nil || item.Item.Type != "agentMessage" || item.Item.Text == "" || gotWorker {
					return Completed{}, ErrProtocol
				}
				if json.Unmarshal([]byte(item.Item.Text), &worker) != nil || worker.Validate() != nil {
					return Completed{}, ErrProtocol
				}
				gotWorker = true
			}
			continue
		}
		var p struct {
			ThreadID string `json:"threadId"`
			Turn     struct {
				ID     string `json:"id"`
				Status string `json:"status"`
			} `json:"turn"`
		}
		if json.Unmarshal(r.Params, &p) != nil || p.ThreadID == "" || p.Turn.ID == "" || p.Turn.Status != "completed" {
			return Completed{}, ErrProtocol
		}
		if c.threadID != "" && p.ThreadID != c.threadID || c.turnID != "" && p.Turn.ID != c.turnID {
			return Completed{}, harness.ErrBindingMismatch
		}
		if !gotWorker {
			return Completed{}, ErrProtocol
		}
		turn, _ := json.Marshal(p.Turn)
		return Completed{ThreadID: p.ThreadID, TurnID: p.Turn.ID, Result: turn, WorkerResult: worker}, nil
	}
}

// ReadAssistantCompleted accepts harmless progress notifications but exactly
// one agentMessage. Any tool/process/file/MCP/server request is a hard fail.
func (c *Client) ReadAssistantCompleted(ctx context.Context, maxBytes int) (AssistantCompleted, error) {
	if !c.turnStarted || maxBytes <= 0 || maxBytes > MaxAssistantBytes {
		return AssistantCompleted{}, ErrOutOfOrder
	}
	var answer string
	for {
		line, err := c.readLine()
		if err != nil {
			return AssistantCompleted{}, err
		}
		var r struct {
			Method string          `json:"method"`
			Params json.RawMessage `json:"params"`
			ID     json.RawMessage `json:"id"`
		}
		if json.Unmarshal(line, &r) != nil {
			return AssistantCompleted{}, ErrProtocol
		}
		if r.Method == "" && len(r.ID) > 0 {
			return AssistantCompleted{}, ErrProtocol
		}
		if r.Method == "approval/request" || r.Method == "item/commandExecution/requestApproval" || r.Method == "item/fileChange/requestApproval" || r.Method == "exec/approval_required" {
			return AssistantCompleted{}, ErrApprovalRequested
		}
		lower := strings.ToLower(r.Method)
		for _, forbidden := range []string{"tool", "command", "filechange", "mcp", "server/request", "process"} {
			if strings.Contains(lower, forbidden) {
				return AssistantCompleted{}, ErrProtocol
			}
		}
		if r.Method == "item/completed" {
			var item struct {
				Item struct {
					Type string `json:"type"`
					Text string `json:"text"`
				} `json:"item"`
			}
			if json.Unmarshal(r.Params, &item) != nil || item.Item.Type != "agentMessage" || item.Item.Text == "" || answer != "" || len([]byte(item.Item.Text)) > maxBytes {
				return AssistantCompleted{}, ErrProtocol
			}
			answer = item.Item.Text
			continue
		}
		if r.Method != "turn/completed" {
			continue
		}
		var p struct {
			ThreadID string `json:"threadId"`
			Turn     struct {
				ID     string `json:"id"`
				Status string `json:"status"`
			} `json:"turn"`
		}
		if json.Unmarshal(r.Params, &p) != nil || p.ThreadID == "" || p.Turn.ID == "" || p.Turn.Status != "completed" || answer == "" {
			return AssistantCompleted{}, ErrProtocol
		}
		if c.threadID != "" && p.ThreadID != c.threadID || c.turnID != "" && p.Turn.ID != c.turnID {
			return AssistantCompleted{}, harness.ErrBindingMismatch
		}
		return AssistantCompleted{ThreadID: p.ThreadID, TurnID: p.Turn.ID, Answer: answer}, nil
	}
}
