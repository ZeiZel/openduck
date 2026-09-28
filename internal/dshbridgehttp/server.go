// Package dshbridgehttp exposes only the authenticated local Command Center
// read/admission boundary. It has no provider, model, MCP, or effector access.
package dshbridgehttp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"

	"openduck/internal/codexruntime"
	"openduck/internal/dshbridge"
	"openduck/internal/meshui"
)

type Server struct {
	Bridge *dshbridge.Bridge
	Host   string
	Origin string
	// ProjectionSigner is an optional trusted local signer used by synthetic
	// composition to bind the canonical read payload before verification.
	ProjectionSigner func(route string, canonicalPayload []byte, projection dshbridge.SafeProjection) string
	// ChatRunner is optional and is only wired by an owner-only composition.
	// It receives a typed GeneralChatOrder and returns a typed bounded result.
	ChatRunner func(context.Context, codexruntime.GeneralChatOrder) (codexruntime.AssistantTurnResult, error)
	// ChatAuthorizer is independent of UI bearer/bootstrap authentication.
	// Without it, a loopback browser session cannot start a model turn.
	ChatAuthorizer func(context.Context) error
	ChatRuns       ChatRunService
	PluginReads    dshbridge.PluginReadProvider
	// MeshUI is an optional Controller UI projection. Authentication is always
	// performed by Bridge.Sessions above; MeshUI owns no HTTP session authority.
	MeshUI *meshui.Service
}

type ChatRunService interface {
	Start(context.Context, codexruntime.GeneralChatOrder) (codexruntime.AssistantTurnResult, error)
	Get(context.Context, string) (codexruntime.AssistantTurnResult, error)
	Cancel(context.Context, string) error
}

const maxReadModelBytes = 256 << 10

var projectionProofPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

func (s *Server) Handler() http.Handler {
	if s.Bridge != nil && s.Bridge.Sessions != nil {
		// Config is intentionally supplied to the SessionStore; these fields only
		// prevent a miswired HTTP adapter from accepting a different authority.
	}
	return http.HandlerFunc(s.serve)
}

func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	s.securityHeaders(w)
	if !s.peerLoopback(r) {
		http.Error(w, "peer rejected", http.StatusForbidden)
		return
	}
	if s.Bridge == nil || s.Bridge.Sessions == nil || !s.Bridge.Sessions.Matches(s.Origin, s.Host) {
		http.Error(w, "controller unavailable", http.StatusServiceUnavailable)
		return
	}
	if r.Method == http.MethodOptions {
		s.options(w, r)
		return
	}
	if r.Host != s.Host || r.Header.Get("Origin") != s.Origin {
		http.Error(w, "origin or host rejected", http.StatusForbidden)
		return
	}
	if r.URL.Path == "/v1/ui/bootstrap" {
		s.bootstrap(w, r)
		return
	}
	principal, err := s.authorize(r)
	if err != nil {
		writeAuthError(w, err)
		return
	}
	// Authorization is the only bearer-handling boundary. Downstream mesh/UI
	// components receive an opaque principal, never the bearer or a token hash.
	r = r.WithContext(dshbridge.WithUIPrincipal(r.Context(), principal))
	if s.MeshUI != nil && (r.URL.Path == "/v1/plugin-reads/mesh" || strings.HasPrefix(r.URL.Path, "/v1/plugin-proposals/")) {
		s.meshUI(w, r)
		return
	}
	// Chat run paths must precede generic GET read projection routing.
	if strings.HasPrefix(r.URL.Path, "/v1/chat/runs/") && s.ChatRuns != nil {
		s.chatRun(w, r)
		return
	}
	if r.URL.Path == "/v1/chat/runs" && r.Method == http.MethodPost && s.ChatRuns != nil {
		s.chatRunStart(w, r)
		return
	}
	if r.Method == http.MethodGet {
		if s.PluginReads != nil && strings.HasPrefix(r.URL.Path, "/v1/plugin-reads/") {
			s.pluginRead(w, r)
			return
		}
		s.read(w, r)
		return
	}
	if r.URL.Path == "/v1/composer" && r.Method == http.MethodPost {
		s.compose(w, r)
		return
	}
	if r.URL.Path == "/v1/chat" && r.Method == http.MethodPost {
		s.chat(w, r)
		return
	}
	w.Header().Set("Allow", "GET")
	if r.URL.Path == "/v1/composer" {
		w.Header().Set("Allow", "POST, OPTIONS")
	}
	if r.URL.Path == "/v1/chat" {
		w.Header().Set("Allow", "POST, OPTIONS")
	}
	http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
}

func (s *Server) chat(w http.ResponseWriter, r *http.Request) {
	if s.ChatRunner == nil {
		http.Error(w, "chat unavailable", http.StatusServiceUnavailable)
		return
	}
	if s.ChatAuthorizer == nil {
		http.Error(w, "owner authorization required", http.StatusForbidden)
		return
	}
	if err := s.ChatAuthorizer(r.Context()); err != nil {
		if errors.Is(err, codexruntime.ErrApprovalRequired) {
			writeApprovalRequired(w, err)
			return
		}
		http.Error(w, "owner authorization required", http.StatusForbidden)
		return
	}
	if r.Header.Get("Content-Type") != "application/json" {
		http.Error(w, "content type rejected", http.StatusUnsupportedMediaType)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, codexruntime.MaxChatPromptBytes+4096)
	var order codexruntime.GeneralChatOrder
	if err := decodeStrict(r, &order); err != nil {
		http.Error(w, "chat order rejected", http.StatusBadRequest)
		return
	}
	if err := order.Validate(); err != nil {
		if errors.Is(err, codexruntime.ErrWorkspaceExecutionUnavailable) {
			http.Error(w, "WORKSPACE_EXECUTION_UNAVAILABLE", http.StatusConflict)
		} else {
			http.Error(w, "chat order rejected", http.StatusBadRequest)
		}
		return
	}
	result, err := s.ChatRunner(r.Context(), order)
	if err != nil {
		if errors.Is(err, codexruntime.ErrLocalPDUnavailable) {
			writeJSON(w, http.StatusConflict, result)
			return
		}
		if errors.Is(err, context.Canceled) {
			writeJSON(w, http.StatusRequestTimeout, result)
			return
		}
		http.Error(w, "chat unavailable", http.StatusServiceUnavailable)
		return
	}
	if result.Validate() != nil {
		http.Error(w, "chat result rejected", http.StatusBadGateway)
		return
	}
	s.cors(w)
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) authorizeChat(w http.ResponseWriter, r *http.Request) bool {
	if s.ChatAuthorizer == nil || s.ChatAuthorizer(r.Context()) != nil {
		http.Error(w, "owner authorization required", http.StatusForbidden)
		return false
	}
	return true
}
func (s *Server) chatRunStart(w http.ResponseWriter, r *http.Request) {
	// The ChatRunService owns the one-use owner grant and performs it before
	// ledger.Begin. A separate HTTP authorizer here would consume that grant
	// twice. Legacy synchronous ChatRunner mode still requires the authorizer.
	if s.ChatAuthorizer != nil && s.ChatRuns == nil && !s.authorizeChat(w, r) {
		return
	}
	if r.Header.Get("Content-Type") != "application/json" {
		http.Error(w, "content type rejected", http.StatusUnsupportedMediaType)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, codexruntime.MaxChatPromptBytes+4096)
	var order codexruntime.GeneralChatOrder
	if err := decodeStrict(r, &order); err != nil {
		http.Error(w, "chat order rejected", http.StatusBadRequest)
		return
	}
	if err := order.Validate(); err != nil {
		if errors.Is(err, codexruntime.ErrWorkspaceExecutionUnavailable) {
			http.Error(w, "WORKSPACE_EXECUTION_UNAVAILABLE", http.StatusConflict)
		} else {
			http.Error(w, "chat order rejected", http.StatusBadRequest)
		}
		return
	}
	ctx := r.Context()
	if requestID := r.Header.Get("X-Owner-Approval-Request-ID"); requestID != "" {
		ctx = codexruntime.WithApprovalRequestID(ctx, requestID)
	}
	result, err := s.ChatRuns.Start(ctx, order)
	if err != nil {
		if errors.Is(err, codexruntime.ErrApprovalRequired) {
			writeApprovalRequired(w, err)
			return
		}
		http.Error(w, "chat unavailable", http.StatusServiceUnavailable)
		return
	}
	if result.Validate() != nil {
		http.Error(w, "chat result rejected", http.StatusBadGateway)
		return
	}
	s.cors(w)
	writeJSON(w, http.StatusAccepted, result)
}

func writeApprovalRequired(w http.ResponseWriter, err error) {
	body := struct {
		SchemaVersion string `json:"schema_version"`
		ErrorCode     string `json:"error_code"`
		RequestID     string `json:"request_id"`
		OrderDigest   string `json:"order_digest"`
		ExpiresAt     string `json:"expires_at"`
	}{SchemaVersion: "owner-approval-required.v1", ErrorCode: "OWNER_APPROVAL_REQUIRED"}
	var approval codexruntime.ApprovalRequiredError
	if errors.As(err, &approval) {
		body.RequestID = approval.RequestID
		body.OrderDigest = approval.OrderDigest
		body.ExpiresAt = approval.ExpiresAt.UTC().Format(time.RFC3339Nano)
	}
	writeJSON(w, http.StatusPreconditionRequired, body)
}
func (s *Server) chatRun(w http.ResponseWriter, r *http.Request) {
	// GET and DELETE are lifecycle reads/cancellation and never spend a start
	// grant. POST authorization is performed by ChatRunService.Start.
	if r.Method == http.MethodPost && s.ChatAuthorizer != nil && s.ChatRuns == nil && !s.authorizeChat(w, r) {
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/v1/chat/runs/")
	if id == "" || strings.Contains(id, "/") {
		http.NotFound(w, r)
		return
	}
	switch r.Method {
	case http.MethodGet:
		result, err := s.ChatRuns.Get(r.Context(), id)
		if err != nil {
			http.Error(w, "chat run unavailable", http.StatusNotFound)
			return
		}
		if result.Validate() != nil {
			http.Error(w, "chat result rejected", http.StatusBadGateway)
			return
		}
		s.cors(w)
		writeJSON(w, http.StatusOK, result)
	case http.MethodDelete:
		if err := s.ChatRuns.Cancel(r.Context(), id); err != nil {
			http.Error(w, "chat run unavailable", http.StatusNotFound)
			return
		}
		s.cors(w)
		writeJSON(w, http.StatusAccepted, map[string]string{"state": "cancelled"})
	default:
		w.Header().Set("Allow", "GET, DELETE, OPTIONS")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) securityHeaders(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store, max-age=0")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
	w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()")
}

func (s *Server) options(w http.ResponseWriter, r *http.Request) {
	if r.Host != s.Host || r.Header.Get("Origin") != s.Origin {
		http.Error(w, "origin or host rejected", http.StatusForbidden)
		return
	}
	meshRead := s.MeshUI != nil && r.URL.Path == "/v1/plugin-reads/mesh"
	meshProposal := s.MeshUI != nil && meshProposalKinds[strings.TrimPrefix(r.URL.Path, "/v1/plugin-proposals/")] && !strings.Contains(strings.TrimPrefix(r.URL.Path, "/v1/plugin-proposals/"), "/")
	if (strings.HasPrefix(r.URL.Path, "/v1/plugin-reads/") && (!isPluginReadPath(r.URL.Path) && !meshRead || r.URL.RawQuery != "")) || (strings.HasPrefix(r.URL.Path, "/v1/plugin-proposals/") && (!meshProposal || r.URL.RawQuery != "")) {
		http.Error(w, "plugin route rejected", http.StatusBadRequest)
		return
	}
	w.Header().Set("Access-Control-Allow-Origin", s.Origin)
	methods := "GET, POST, OPTIONS"
	if (isPluginReadPath(r.URL.Path) || meshRead) && r.URL.RawQuery == "" {
		methods = "GET, OPTIONS"
	}
	w.Header().Set("Access-Control-Allow-Methods", methods)
	w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, X-UI-Nonce, X-UI-Request-Nonce, X-Owner-Approval-Request-ID, Access-Control-Request-Private-Network")
	w.Header().Set("Access-Control-Allow-Credentials", "false")
	if r.Header.Get("Access-Control-Request-Private-Network") == "true" {
		w.Header().Set("Access-Control-Allow-Private-Network", "true")
	}
	w.Header().Set("Vary", "Origin")
	w.WriteHeader(http.StatusNoContent)
}

func isPluginReadPath(path string) bool {
	switch path {
	case "/v1/plugin-reads/beads/project-graph", "/v1/plugin-reads/beads/global-metadata", "/v1/plugin-reads/workspace-groups":
		return true
	}
	return false
}

func (s *Server) bootstrap(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST, OPTIONS")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if r.Header.Get("Content-Type") != "application/json" {
		http.Error(w, "content type rejected", http.StatusUnsupportedMediaType)
		return
	}
	if s.Bridge == nil || s.Bridge.Sessions == nil {
		http.Error(w, "controller unavailable", http.StatusServiceUnavailable)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	var req struct {
		ClientNonce string `json:"client_nonce"`
	}
	if err := decodeStrict(r, &req); err != nil {
		http.Error(w, "invalid bootstrap", http.StatusBadRequest)
		return
	}
	session, err := s.Bridge.Sessions.Issue(req.ClientNonce)
	if err != nil {
		http.Error(w, "invalid bootstrap", http.StatusBadRequest)
		return
	}
	s.cors(w)
	writeJSON(w, http.StatusOK, session)
}

func (s *Server) authorize(r *http.Request) (dshbridge.UIPrincipal, error) {
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		return dshbridge.UIPrincipal{}, dshbridge.ErrUnauthorized
	}
	return s.Bridge.Sessions.AuthorizePrincipal(strings.TrimPrefix(auth, "Bearer "), r.Header.Get("X-UI-Nonce"), r.Header.Get("X-UI-Request-Nonce"), r.Header.Get("Origin"), r.Host)
}

func (s *Server) read(w http.ResponseWriter, r *http.Request) {
	route := strings.TrimPrefix(r.URL.Path, "/v1/read/")
	if route == r.URL.Path || route == "" || strings.Contains(route, "/") {
		http.NotFound(w, r)
		return
	}
	model, err := s.Bridge.Read(r.Context(), route)
	if err != nil {
		s.domainError(w, err)
		return
	}
	snapshot := normalizeRead(model)
	body, err := buildReadJSON(snapshot, s.Bridge.ProjectionVerifier, s.ProjectionSigner)
	if err != nil {
		s.domainError(w, err)
		return
	}
	s.cors(w)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

func (s *Server) compose(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Content-Type") != "application/octet-stream" {
		http.Error(w, "content type rejected", http.StatusUnsupportedMediaType)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, dshbridge.MaxComposerBytes)
	payload, err := io.ReadAll(r.Body)
	if err != nil || len(payload) == 0 || len(payload) > dshbridge.MaxComposerBytes {
		http.Error(w, "payload rejected", http.StatusRequestEntityTooLarge)
		return
	}
	result, err := s.Bridge.Compose(r.Context(), payload)
	if err != nil {
		s.domainError(w, err)
		return
	}
	s.cors(w)
	writeJSON(w, http.StatusAccepted, result)
}

func (s *Server) cors(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Origin", s.Origin)
	w.Header().Set("Access-Control-Allow-Credentials", "false")
	w.Header().Set("Vary", "Origin")
}
func (s *Server) domainError(w http.ResponseWriter, err error) {
	if errors.Is(err, dshbridge.ErrLocalPDUnavailable) {
		http.Error(w, "LOCAL_PD_UNAVAILABLE", http.StatusConflict)
		return
	}
	if errors.Is(err, dshbridge.ErrUnavailable) {
		http.Error(w, "controller unavailable", http.StatusServiceUnavailable)
		return
	}
	if errors.Is(err, dshbridge.ErrInvalidRequest) || errors.Is(err, dshbridge.ErrUnsupportedClass) {
		http.Error(w, "request rejected", http.StatusBadRequest)
		return
	}
	http.Error(w, "controller request failed", http.StatusBadGateway)
}
func writeAuthError(w http.ResponseWriter, err error) {
	status := http.StatusUnauthorized
	if errors.Is(err, dshbridge.ErrExpired) || errors.Is(err, dshbridge.ErrReplay) {
		status = http.StatusForbidden
	}
	http.Error(w, "ui channel rejected", status)
}
func decodeStrict(r *http.Request, out any) error {
	raw, err := io.ReadAll(r.Body)
	if err != nil || len(raw) == 0 || len(raw) > 4096 {
		return errors.New("invalid body")
	}
	if err := validateJSON(raw); err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil {
		return err
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return errors.New("trailing data")
	}
	return nil
}

func validateJSON(raw []byte) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := walkJSON(dec); err != nil {
		return err
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return errors.New("trailing json")
	}
	return nil
}
func walkJSON(dec *json.Decoder) error {
	t, err := dec.Token()
	if err != nil {
		return err
	}
	if t == nil {
		return errors.New("null is not allowed")
	}
	if d, ok := t.(json.Delim); ok {
		switch d {
		case '{':
			seen := map[string]struct{}{}
			for dec.More() {
				token, tokenErr := dec.Token()
				if tokenErr != nil {
					return tokenErr
				}
				key, ok := token.(string)
				if !ok {
					return errors.New("invalid object key")
				}
				if _, exists := seen[key]; exists {
					return errors.New("duplicate key")
				}
				seen[key] = struct{}{}
				if err := walkJSON(dec); err != nil {
					return err
				}
			}
			_, err = dec.Token()
		case '[':
			for dec.More() {
				if err := walkJSON(dec); err != nil {
					return err
				}
			}
			_, err = dec.Token()
		}
	}
	return err
}

type inboxEnvelope struct {
	SchemaVersion string                   `json:"schema_version"`
	Route         string                   `json:"route"`
	Data          dshbridge.InboxReadModel `json:"data"`
}
type calendarEnvelope struct {
	SchemaVersion string                      `json:"schema_version"`
	Route         string                      `json:"route"`
	Data          dshbridge.CalendarReadModel `json:"data"`
}
type graphEnvelope struct {
	SchemaVersion string                       `json:"schema_version"`
	Route         string                       `json:"route"`
	Data          dshbridge.WorkGraphReadModel `json:"data"`
}
type tasksEnvelope struct {
	SchemaVersion string                   `json:"schema_version"`
	Route         string                   `json:"route"`
	Data          dshbridge.TasksReadModel `json:"data"`
}
type timeEnvelope struct {
	SchemaVersion string                  `json:"schema_version"`
	Route         string                  `json:"route"`
	Data          dshbridge.TimeReadModel `json:"data"`
}
type reviewsEnvelope struct {
	SchemaVersion string                     `json:"schema_version"`
	Route         string                     `json:"route"`
	Data          dshbridge.ReviewsReadModel `json:"data"`
}
type memoryEnvelope struct {
	SchemaVersion string                            `json:"schema_version"`
	Route         string                            `json:"route"`
	Data          dshbridge.MemoryMetadataReadModel `json:"data"`
}
type healthEnvelope struct {
	SchemaVersion string                    `json:"schema_version"`
	Route         string                    `json:"route"`
	Data          dshbridge.HealthReadModel `json:"data"`
}

func buildReadJSON(m dshbridge.ReadResult, verifier dshbridge.ProjectionVerifier, signer func(string, []byte, dshbridge.SafeProjection) string) ([]byte, error) {
	if signer != nil {
		projection, canonical, err := canonicalProjection(m)
		if err != nil {
			return nil, err
		}
		proof := signer(m.Route, canonical, projection)
		switch m.Route {
		case "inbox":
			m.Inbox.Projection.Proof = proof
		case "calendar":
			m.Calendar.Projection.Proof = proof
		case "workgraph":
			m.WorkGraph.Projection.Proof = proof
		case "tasks":
			m.Tasks.Projection.Proof = proof
		case "time":
			m.Time.Projection.Proof = proof
		case "reviews":
			m.Reviews.Projection.Proof = proof
		case "memory-metadata":
			m.MemoryMetadata.Projection.Proof = proof
		case "health":
			m.Health.Projection.Proof = proof
		}
	}
	if err := validateRead(m, verifier); err != nil {
		return nil, err
	}
	var v any
	switch m.Route {
	case "inbox":
		v = inboxEnvelope{dshbridge.ReadModelV1, m.Route, *m.Inbox}
	case "calendar":
		v = calendarEnvelope{dshbridge.ReadModelV1, m.Route, *m.Calendar}
	case "workgraph":
		v = graphEnvelope{dshbridge.ReadModelV1, m.Route, *m.WorkGraph}
	case "tasks":
		v = tasksEnvelope{dshbridge.ReadModelV1, m.Route, *m.Tasks}
	case "time":
		v = timeEnvelope{dshbridge.ReadModelV1, m.Route, *m.Time}
	case "reviews":
		v = reviewsEnvelope{dshbridge.ReadModelV1, m.Route, *m.Reviews}
	case "memory-metadata":
		v = memoryEnvelope{dshbridge.ReadModelV1, m.Route, *m.MemoryMetadata}
	case "health":
		v = healthEnvelope{dshbridge.ReadModelV1, m.Route, *m.Health}
	default:
		return nil, dshbridge.ErrInvalidRequest
	}
	body, err := json.Marshal(v)
	if err != nil || len(body) > maxReadModelBytes {
		return nil, dshbridge.ErrInvalidRequest
	}
	return append(body, '\n'), nil
}

func normalizeRead(m dshbridge.ReadResult) dshbridge.ReadResult {
	if m.Inbox != nil {
		x := *m.Inbox
		x.Items = append([]dshbridge.InboxItem(nil), m.Inbox.Items...)
		if x.Items == nil {
			x.Items = []dshbridge.InboxItem{}
		}
		m.Inbox = &x
	}
	if m.Calendar != nil {
		x := *m.Calendar
		x.Items = append([]dshbridge.CalendarItem(nil), m.Calendar.Items...)
		if x.Items == nil {
			x.Items = []dshbridge.CalendarItem{}
		}
		m.Calendar = &x
	}
	if m.WorkGraph != nil {
		x := *m.WorkGraph
		x.Nodes = append([]dshbridge.WorkGraphNode(nil), m.WorkGraph.Nodes...)
		x.Edges = append([]dshbridge.WorkGraphEdge(nil), m.WorkGraph.Edges...)
		if x.Nodes == nil {
			x.Nodes = []dshbridge.WorkGraphNode{}
		}
		if x.Edges == nil {
			x.Edges = []dshbridge.WorkGraphEdge{}
		}
		m.WorkGraph = &x
	}
	if m.Tasks != nil {
		x := *m.Tasks
		x.Items = append([]dshbridge.TaskItem(nil), m.Tasks.Items...)
		if x.Items == nil {
			x.Items = []dshbridge.TaskItem{}
		}
		m.Tasks = &x
	}
	if m.Reviews != nil {
		x := *m.Reviews
		x.Items = append([]dshbridge.ReviewItem(nil), m.Reviews.Items...)
		if x.Items == nil {
			x.Items = []dshbridge.ReviewItem{}
		}
		m.Reviews = &x
	}
	if m.MemoryMetadata != nil {
		x := *m.MemoryMetadata
		x.Items = append([]dshbridge.MemoryMetadata(nil), m.MemoryMetadata.Items...)
		if x.Items == nil {
			x.Items = []dshbridge.MemoryMetadata{}
		}
		m.MemoryMetadata = &x
	}
	return m
}

func validateRead(m dshbridge.ReadResult, verifier dshbridge.ProjectionVerifier) error {
	if m.Route == "" {
		return dshbridge.ErrInvalidRequest
	}
	count := 0
	if m.Inbox != nil {
		if m.Inbox.SchemaVersion != dshbridge.ReadModelV1 || !validProjection(m.Inbox.Projection) {
			return dshbridge.ErrInvalidRequest
		}
		count++
	}
	if m.Calendar != nil {
		if m.Calendar.SchemaVersion != dshbridge.ReadModelV1 || !validProjection(m.Calendar.Projection) {
			return dshbridge.ErrInvalidRequest
		}
		count++
	}
	if m.WorkGraph != nil {
		if m.WorkGraph.SchemaVersion != dshbridge.ReadModelV1 || !validProjection(m.WorkGraph.Projection) || !safeText(m.WorkGraph.GraphID, 256) || !safeText(m.WorkGraph.BaselineVersion, 256) {
			return dshbridge.ErrInvalidRequest
		}
		count++
	}
	if m.Tasks != nil {
		if m.Tasks.SchemaVersion != dshbridge.ReadModelV1 || !validProjection(m.Tasks.Projection) {
			return dshbridge.ErrInvalidRequest
		}
		count++
	}
	if m.Time != nil {
		if m.Time.SchemaVersion != dshbridge.ReadModelV1 || !validProjection(m.Time.Projection) || !safeText(m.Time.ActiveTaskID, 256) || m.Time.PlannedSeconds < 0 || m.Time.SpentSeconds < 0 {
			return dshbridge.ErrInvalidRequest
		}
		count++
	}
	if m.Reviews != nil {
		if m.Reviews.SchemaVersion != dshbridge.ReadModelV1 || !validProjection(m.Reviews.Projection) {
			return dshbridge.ErrInvalidRequest
		}
		count++
	}
	if m.MemoryMetadata != nil {
		if m.MemoryMetadata.SchemaVersion != dshbridge.ReadModelV1 || !validProjection(m.MemoryMetadata.Projection) {
			return dshbridge.ErrInvalidRequest
		}
		count++
	}
	if m.Health != nil {
		if m.Health.SchemaVersion != dshbridge.ReadModelV1 || !validProjection(m.Health.Projection) || !safeText(m.Health.Status, 128) {
			return dshbridge.ErrInvalidRequest
		}
		count++
	}
	if count != 1 {
		return dshbridge.ErrInvalidRequest
	}
	if (m.Route == "inbox") != (m.Inbox != nil) || (m.Route == "calendar") != (m.Calendar != nil) || (m.Route == "workgraph") != (m.WorkGraph != nil) || (m.Route == "tasks") != (m.Tasks != nil) || (m.Route == "time") != (m.Time != nil) || (m.Route == "reviews") != (m.Reviews != nil) || (m.Route == "memory-metadata") != (m.MemoryMetadata != nil) || (m.Route == "health") != (m.Health != nil) {
		return dshbridge.ErrInvalidRequest
	}
	if verifier == nil {
		return dshbridge.ErrInvalidRequest
	}
	projection, canonical, err := canonicalProjection(m)
	if err != nil || verifier.Verify(m.Route, canonical, projection, time.Now().UTC()) != nil {
		return dshbridge.ErrInvalidRequest
	}
	if m.Inbox != nil {
		if len(m.Inbox.Items) > 256 {
			return dshbridge.ErrInvalidRequest
		}
		for _, x := range m.Inbox.Items {
			// General Command Center projections are metadata-only for safe
			// classes. PD content never enters this channel, even as a digest.
			if x.Classification != dshbridge.ClassL0 && x.Classification != dshbridge.ClassL1 {
				return dshbridge.ErrInvalidRequest
			}
			if !safeText(x.ID, 256) || !safeText(x.Summary, 4096) || !safeText(x.Source, 256) {
				return dshbridge.ErrInvalidRequest
			}
		}
	}
	if m.Calendar != nil {
		if len(m.Calendar.Items) > 256 {
			return dshbridge.ErrInvalidRequest
		}
		for _, x := range m.Calendar.Items {
			if !safeText(x.ID, 256) || !safeText(x.Title, 4096) || !safeText(x.Timezone, 128) || !safeText(x.Status, 128) {
				return dshbridge.ErrInvalidRequest
			}
		}
	}
	if m.WorkGraph != nil {
		if len(m.WorkGraph.Nodes) > 512 || len(m.WorkGraph.Edges) > 1024 {
			return dshbridge.ErrInvalidRequest
		}
		for _, x := range m.WorkGraph.Nodes {
			if !safeText(x.ID, 256) || !safeText(x.Title, 4096) || !safeText(x.Status, 128) {
				return dshbridge.ErrInvalidRequest
			}
		}
		for _, x := range m.WorkGraph.Edges {
			if !safeText(x.From, 256) || !safeText(x.To, 256) || !safeText(x.Kind, 128) {
				return dshbridge.ErrInvalidRequest
			}
		}
	}
	if m.Tasks != nil {
		if len(m.Tasks.Items) > 512 {
			return dshbridge.ErrInvalidRequest
		}
		for _, x := range m.Tasks.Items {
			if !safeText(x.ID, 256) || !safeText(x.Title, 4096) || !safeText(x.Status, 128) || !safeText(x.Source, 256) {
				return dshbridge.ErrInvalidRequest
			}
		}
	}
	if m.Reviews != nil {
		if len(m.Reviews.Items) > 256 {
			return dshbridge.ErrInvalidRequest
		}
		for _, x := range m.Reviews.Items {
			if !safeText(x.ID, 256) || !safeText(x.TargetID, 256) || !safeText(x.Status, 128) {
				return dshbridge.ErrInvalidRequest
			}
		}
	}
	if m.MemoryMetadata != nil {
		if len(m.MemoryMetadata.Items) > 256 {
			return dshbridge.ErrInvalidRequest
		}
		for _, x := range m.MemoryMetadata.Items {
			if !safeText(x.ID, 256) || !safeText(x.Scope, 128) || !safeText(x.Sensitivity, 128) || !safeText(x.Status, 128) {
				return dshbridge.ErrInvalidRequest
			}
		}
	}
	b, err := json.Marshal(m)
	if err != nil || len(b) > maxReadModelBytes {
		return dshbridge.ErrInvalidRequest
	}
	return nil
}

func canonicalProjection(m dshbridge.ReadResult) (dshbridge.SafeProjection, []byte, error) {
	var projection dshbridge.SafeProjection
	var payload any
	switch m.Route {
	case "inbox":
		x := *m.Inbox
		projection = x.Projection
		x.Projection.Proof = ""
		payload = x
	case "calendar":
		x := *m.Calendar
		projection = x.Projection
		x.Projection.Proof = ""
		payload = x
	case "workgraph":
		x := *m.WorkGraph
		projection = x.Projection
		x.Projection.Proof = ""
		payload = x
	case "tasks":
		x := *m.Tasks
		projection = x.Projection
		x.Projection.Proof = ""
		payload = x
	case "time":
		x := *m.Time
		projection = x.Projection
		x.Projection.Proof = ""
		payload = x
	case "reviews":
		x := *m.Reviews
		projection = x.Projection
		x.Projection.Proof = ""
		payload = x
	case "memory-metadata":
		x := *m.MemoryMetadata
		projection = x.Projection
		x.Projection.Proof = ""
		payload = x
	case "health":
		x := *m.Health
		projection = x.Projection
		x.Projection.Proof = ""
		payload = x
	default:
		return projection, nil, dshbridge.ErrInvalidRequest
	}
	b, err := json.Marshal(payload)
	return projection, b, err
}
func safeText(value string, max int) bool {
	if len(value) > max {
		return false
	}
	lower := strings.ToLower(value)
	for _, marker := range []string{"sentinel", "qwen", "raw_pd", "raw pd", "localpd"} {
		if strings.Contains(lower, marker) {
			return false
		}
	}
	return true
}
func validProjection(p dshbridge.SafeProjection) bool {
	return (p.Classification == dshbridge.ClassL0 || p.Classification == dshbridge.ClassL1) && safeText(p.Provenance, 256) && projectionProofPattern.MatchString(p.Proof)
}
func (s *Server) peerLoopback(r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	return host == "localhost" || (net.ParseIP(host) != nil && net.ParseIP(host).IsLoopback())
}
func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
