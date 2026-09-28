// Package nativemcp implements the Controller-owned stdio MCP surface used by
// native subscription hosts.  It deliberately contains no provider client,
// endpoint dialer, credential loader, or ambient mesh request constructor.
package nativemcp

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"regexp"
	"sort"
	"strings"
	"time"

	"openduck/internal/mesh"
)

const (
	ProtocolVersion   = "2025-11-25" // https://modelcontextprotocol.io/specification/2025-11-25
	SessionContractV1 = "openduck-native-mcp-session.v1"
	maxMessageBytes   = 64 << 10
)

var (
	ErrUnauthorized = errors.New("native mcp unauthorized")
	ErrInvalid      = errors.New("native mcp invalid request")
	childOperations = []string{"spawn", "spawnBatch", "send", "steer", "wait", "collect", "cancel", "list", "status", "result", "listProfiles"}
	idRE            = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,127}$`)
)

// SessionContract is Controller-produced, immutable session metadata.  It is
// intentionally not an endpoint credential: Backend must compare all fields
// against durable Controller state and a platform-attested process identity.
type SessionContract struct {
	SchemaVersion string    `json:"schema_version"`
	Provider      string    `json:"provider"`
	ProfileID     string    `json:"profile_id"`
	RevisionID    string    `json:"revision_id"`
	UISessionID   string    `json:"ui_session_id"`
	UIChannelID   string    `json:"ui_channel_id"`
	RootRunID     string    `json:"root_run_id"`
	RunID         string    `json:"run_id"`
	MeshSessionID string    `json:"mesh_session_id"`
	AttemptID     string    `json:"attempt_id"`
	EndpointID    string    `json:"endpoint_id"`
	PeerID        string    `json:"peer_id"`
	Generation    uint64    `json:"generation"`
	ExpiresAt     time.Time `json:"expires_at"`
}

func (c SessionContract) Validate(now time.Time) error {
	if c.SchemaVersion != SessionContractV1 || !nativeProvider(c.Provider) || c.Generation == 0 || !c.ExpiresAt.After(now) {
		return ErrUnauthorized
	}
	for _, v := range []string{c.Provider, c.ProfileID, c.RevisionID, c.UISessionID, c.UIChannelID, c.RootRunID, c.RunID, c.MeshSessionID, c.AttemptID, c.EndpointID, c.PeerID} {
		if !idRE.MatchString(v) {
			return ErrUnauthorized
		}
	}
	if c.RootRunID != c.RunID {
		return ErrUnauthorized
	}
	return nil
}

func nativeProvider(provider string) bool {
	return provider == "codex" || provider == "claude" || provider == "qwen" || provider == "kimi"
}

// PeerIdentity is returned by a platform attestor owned by Controller.  The
// stdio process must never accept it from MCP params, environment, or a file.
type PeerIdentity struct {
	Provider string
	PeerID   string
}

type PeerSource interface {
	Current(context.Context) (PeerIdentity, error)
}

// Backend is the only authority seam.  Its implementation rechecks the
// current association, revision, endpoint generation, expiry/revocation and
// process attestation, then performs the typed child operation through the
// Controller's private mesh capability.  Request never contains an endpoint,
// audience, nonce, provider credential, URL, or arbitrary method name.
type Backend interface {
	Authorize(context.Context, SessionContract, PeerIdentity) error
	Invoke(context.Context, SessionContract, PeerIdentity, string, json.RawMessage) (json.RawMessage, error)
}

type Server struct {
	Contract SessionContract
	Peers    PeerSource
	Backend  Backend
	Now      func() time.Time
	// FirstFrameTimeout bounds a client which connects but never sends a
	// complete MCP frame. IdleTimeout applies independently to every later
	// frame and WriteTimeout bounds backpressure from a host which stopped
	// consuming stdout. Zero values select the fail-closed production defaults.
	FirstFrameTimeout time.Duration
	IdleTimeout       time.Duration
	WriteTimeout      time.Duration
}

const (
	defaultFirstFrameTimeout = 5 * time.Second
	defaultIdleTimeout       = 30 * time.Second
	defaultWriteTimeout      = 5 * time.Second
)

func (s Server) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}

func (s Server) valid() error {
	if s.Peers == nil || s.Backend == nil || s.Contract.Validate(s.now()) != nil {
		return ErrUnauthorized
	}
	return nil
}

// Serve implements the standard newline-delimited stdio transport. stdout is
// reserved exclusively for valid JSON-RPC messages; callers may use stderr for
// bounded operational diagnostics.
func (s Server) Serve(ctx context.Context, in io.Reader, out io.Writer) error {
	if ctx == nil || s.valid() != nil {
		return ErrUnauthorized
	}
	reader := bufio.NewReaderSize(io.LimitReader(in, 8<<20), maxMessageBytes+1)
	enc := json.NewEncoder(out)
	initialized := false
	first := true
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		readTimeout := s.IdleTimeout
		if first {
			readTimeout = s.FirstFrameTimeout
		}
		if readTimeout <= 0 {
			if first {
				readTimeout = defaultFirstFrameTimeout
			} else {
				readTimeout = defaultIdleTimeout
			}
		}
		if deadline, ok := in.(interface{ SetReadDeadline(time.Time) error }); ok {
			if err := deadline.SetReadDeadline(time.Now().Add(readTimeout)); err != nil {
				return nil
			}
		}
		frame, readErr := reader.ReadSlice('\n')
		if readErr != nil {
			if len(frame) == 0 {
				if timeout, ok := readErr.(net.Error); !ok || !timeout.Timeout() {
					return nil
				}
			}
			return ErrInvalid
		}
		if len(frame) > maxMessageBytes {
			return ErrInvalid
		}
		first = false
		var request rpcRequest
		if err := decodeExact(frame[:len(frame)-1], &request); err != nil || request.JSONRPC != "2.0" || request.Method == "" {
			if err := s.setWriteDeadline(out); err != nil {
				return ErrInvalid
			}
			if err := enc.Encode(rpcError{JSONRPC: "2.0", ID: nil, Error: rpcFault{Code: -32600, Message: "invalid request"}}); err != nil {
				return err
			}
			continue
		}
		// Notifications do not have an id and therefore do not receive a reply.
		if request.ID == nil {
			if request.Method == "notifications/initialized" {
				initialized = true
			}
			continue
		}
		result, fault, next := s.handle(ctx, initialized, request)
		initialized = initialized || next
		var err error
		if fault != nil {
			if deadlineErr := s.setWriteDeadline(out); deadlineErr != nil {
				return ErrInvalid
			}
			err = enc.Encode(rpcError{JSONRPC: "2.0", ID: request.ID, Error: *fault})
		} else {
			if deadlineErr := s.setWriteDeadline(out); deadlineErr != nil {
				return ErrInvalid
			}
			err = enc.Encode(rpcResult{JSONRPC: "2.0", ID: request.ID, Result: result})
		}
		if err != nil {
			return err
		}
	}
}

func (s Server) setWriteDeadline(out io.Writer) error {
	deadline, ok := out.(interface{ SetWriteDeadline(time.Time) error })
	if !ok {
		return nil
	}
	timeout := s.WriteTimeout
	if timeout <= 0 {
		timeout = defaultWriteTimeout
	}
	return deadline.SetWriteDeadline(time.Now().Add(timeout))
}

func (s Server) peer(ctx context.Context) (PeerIdentity, error) {
	p, err := s.Peers.Current(ctx)
	if err != nil || p.Provider != s.Contract.Provider || p.PeerID != s.Contract.PeerID || !idRE.MatchString(p.PeerID) {
		return PeerIdentity{}, ErrUnauthorized
	}
	if err = s.Backend.Authorize(ctx, s.Contract, p); err != nil {
		return PeerIdentity{}, ErrUnauthorized
	}
	return p, nil
}

func (s Server) handle(ctx context.Context, initialized bool, request rpcRequest) (any, *rpcFault, bool) {
	switch request.Method {
	case "initialize":
		if initialized || !validInitialize(request.Params) {
			return nil, invalidParams(), false
		}
		if _, err := s.peer(ctx); err != nil {
			return nil, unavailable(), false
		}
		return map[string]any{"protocolVersion": ProtocolVersion, "capabilities": map[string]any{"tools": map[string]any{"listChanged": false}}, "serverInfo": map[string]string{"name": "openduck-native-mcp", "version": "v1"}}, nil, true
	case "ping":
		if !initialized {
			return nil, unavailable(), false
		}
		if _, err := s.peer(ctx); err != nil {
			return nil, unavailable(), false
		}
		return map[string]any{}, nil, false
	case "tools/list":
		if !initialized {
			return nil, unavailable(), false
		}
		if !emptyOrCursor(request.Params) {
			return nil, invalidParams(), false
		}
		if _, err := s.peer(ctx); err != nil {
			return nil, unavailable(), false
		}
		return map[string]any{"tools": tools()}, nil, false
	case "tools/call":
		if !initialized {
			return nil, unavailable(), false
		}
		name, args, err := callParams(request.Params)
		if err != nil {
			return nil, invalidParams(), false
		}
		operation, ok := toolOperation(name)
		if !ok {
			return nil, &rpcFault{Code: -32601, Message: "method not found"}, false
		}
		args, err = validateOperationArguments(operation, args)
		if err != nil {
			return nil, toolFailure("invalid arguments"), false
		}
		peer, err := s.peer(ctx)
		if err != nil {
			return nil, toolFailure("controller authorization unavailable"), false
		}
		response, err := s.Backend.Invoke(ctx, s.Contract, peer, operation, args)
		if err != nil {
			return nil, toolFailure("controller operation unavailable"), false
		}
		var structured any
		if decodeExact(response, &structured) != nil {
			return nil, toolFailure("controller operation unavailable"), false
		}
		return map[string]any{"content": []map[string]string{{"type": "text", "text": string(response)}}, "structuredContent": structured, "isError": false}, nil, false
	default:
		return nil, &rpcFault{Code: -32601, Message: "method not found"}, false
	}
}

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}
type rpcFault struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}
type rpcError struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Error   rpcFault        `json:"error"`
}
type rpcResult struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result"`
}

func unavailable() *rpcFault {
	return &rpcFault{Code: -32001, Message: "controller authorization unavailable"}
}
func invalidParams() *rpcFault             { return &rpcFault{Code: -32602, Message: "invalid params"} }
func toolFailure(message string) *rpcFault { return &rpcFault{Code: -32002, Message: message} }

func decodeExact(raw []byte, output any) error {
	d := json.NewDecoder(strings.NewReader(string(raw)))
	d.DisallowUnknownFields()
	if err := d.Decode(output); err != nil {
		return err
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return ErrInvalid
	}
	return nil
}
func validInitialize(raw json.RawMessage) bool {
	var v struct {
		ProtocolVersion string         `json:"protocolVersion"`
		Capabilities    map[string]any `json:"capabilities"`
		ClientInfo      struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"clientInfo"`
	}
	return decodeExact(raw, &v) == nil && v.ProtocolVersion == ProtocolVersion && v.ClientInfo.Name != "" && v.ClientInfo.Version != ""
}
func emptyOrCursor(raw json.RawMessage) bool {
	if len(raw) == 0 || string(raw) == "null" {
		return true
	}
	var p struct {
		Cursor string `json:"cursor"`
	}
	return decodeExact(raw, &p) == nil && p.Cursor == ""
}
func callParams(raw json.RawMessage) (string, json.RawMessage, error) {
	var p struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if decodeExact(raw, &p) != nil || p.Name == "" || len(p.Arguments) == 0 {
		return "", nil, ErrInvalid
	}
	return p.Name, p.Arguments, nil
}
func toolOperation(name string) (string, bool) {
	const prefix = "openduck_mesh_"
	if !strings.HasPrefix(name, prefix) {
		return "", false
	}
	op := strings.TrimPrefix(name, prefix)
	for _, v := range childOperations {
		if v == op {
			return op, true
		}
	}
	return "", false
}
func tools() []map[string]any {
	out := make([]map[string]any, 0, len(childOperations))
	for _, operation := range childOperations {
		out = append(out, map[string]any{"name": "openduck_mesh_" + operation, "description": "Controller-authorized OpenDuck child-session " + operation + " operation.", "inputSchema": operationSchema(operation)})
	}
	return out
}
func operationSchema(operation string) map[string]any { // strict runtime validation below is authoritative; schema is host guidance.
	properties := map[string]any{}
	required := []string{}
	switch operation {
	case "spawn":
		return map[string]any{"type": "object", "additionalProperties": false}
	case "spawnBatch":
		properties["proposals"] = map[string]any{"type": "array"}
		required = []string{"proposals"}
	case "send", "steer":
		properties["run_id"] = map[string]any{"type": "string"}
		properties["input_ref"] = map[string]any{"type": "string"}
		required = []string{"run_id", "input_ref"}
	case "cancel":
		properties["run_id"] = map[string]any{"type": "string"}
		properties["revision_ref"] = map[string]any{"type": "string"}
		properties["reason_ref"] = map[string]any{"type": "string"}
		required = []string{"run_id", "revision_ref", "reason_ref"}
	case "list":
		properties["root_id"] = map[string]any{"type": "string"}
		properties["revision_ref"] = map[string]any{"type": "string"}
		required = []string{"root_id", "revision_ref"}
	case "listProfiles":
		properties["revision_ref"] = map[string]any{"type": "string"}
		required = []string{"revision_ref"}
	default:
		properties["run_id"] = map[string]any{"type": "string"}
		properties["revision_ref"] = map[string]any{"type": "string"}
		required = []string{"run_id", "revision_ref"}
	}
	return map[string]any{"type": "object", "additionalProperties": false, "properties": properties, "required": required}
}

func validateOperationArguments(operation string, raw json.RawMessage) (json.RawMessage, error) {
	if len(raw) == 0 || len(raw) > maxMessageBytes {
		return nil, ErrInvalid
	}
	if operation == "spawn" {
		if _, err := mesh.DecodeSpawnProposal(raw); err != nil {
			return nil, ErrInvalid
		}
		return append(json.RawMessage(nil), raw...), nil
	}
	if operation == "spawnBatch" {
		var v struct {
			Proposals []json.RawMessage `json:"proposals"`
		}
		if decodeExact(raw, &v) != nil || len(v.Proposals) == 0 || len(v.Proposals) > 16 {
			return nil, ErrInvalid
		}
		for _, p := range v.Proposals {
			if _, err := mesh.DecodeSpawnProposal(p); err != nil {
				return nil, ErrInvalid
			}
		}
		return canonicalRaw(raw)
	}
	fields := map[string][]string{"send": {"run_id", "input_ref"}, "steer": {"run_id", "input_ref"}, "cancel": {"run_id", "revision_ref", "reason_ref"}, "list": {"root_id", "revision_ref"}, "listProfiles": {"revision_ref"}, "wait": {"run_id", "revision_ref"}, "collect": {"run_id", "revision_ref"}, "status": {"run_id", "revision_ref"}, "result": {"run_id", "revision_ref"}}
	want, ok := fields[operation]
	if !ok {
		return nil, ErrInvalid
	}
	var values map[string]string
	if decodeExact(raw, &values) != nil || len(values) != len(want) {
		return nil, ErrInvalid
	}
	for _, key := range want {
		if !idRE.MatchString(values[key]) {
			return nil, ErrInvalid
		}
	}
	for key := range values {
		found := false
		for _, expected := range want {
			if key == expected {
				found = true
			}
		}
		if !found {
			return nil, ErrInvalid
		}
	}
	return canonicalRaw(raw)
}
func canonicalRaw(raw json.RawMessage) (json.RawMessage, error) {
	var v any
	if decodeExact(raw, &v) != nil {
		return nil, ErrInvalid
	}
	out, err := json.Marshal(v)
	if err != nil {
		return nil, ErrInvalid
	}
	return out, nil
}

// ContractDigest is a stable public binding reference for registration
// metadata. It is not a secret or authorization substitute.
func ContractDigest(c SessionContract) string {
	raw, _ := json.Marshal(c)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
func ChildOperations() []string       { return append([]string(nil), childOperations...) }
func SortedChildOperations() []string { out := ChildOperations(); sort.Strings(out); return out }
func (c SessionContract) String() string {
	return fmt.Sprintf("%s/%s/%s", c.Provider, c.ProfileID, c.EndpointID)
}
