package harnesshttp

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"openduck/internal/harness"
	"regexp"
	"strings"
	"sync"
)

const (
	callbackOriginPath   = "/v1/controller/callback/origin"
	originProbePath      = "/v1/controller/origin-probe"
	callbackRenderPath   = "/v1/controller/callback/render"
	callbackDecisionPath = "/v1/controller/callback/decision"
	maxCallbackBody      = 16 << 10
)

// CallbackConfig deliberately defaults to disabled. Origin is an exact browser
// origin (scheme://host[:port]); Host is an exact HTTP Host header value.
type CallbackConfig struct {
	Enabled            bool
	Origin             string
	Host               string
	OriginProbeEnabled bool
}

// OwnerAuthenticator is the trust boundary for browser assertions. The HTTP
// transport does not parse, verify, or persist assertions; a deployment must
// inject an implementation backed by an attested authenticator.
type OwnerAuthenticator interface {
	Authenticate(context.Context, string) (identity string, proofRef string, err error)
}

type CallbackController interface {
	RenderCallbackSession(context.Context, string, uint64, string) (harness.TaskRecord, harness.InteractionRenderReceipt, harness.DecisionChallenge, error)
	RecordAuthenticatedCallback(context.Context, string, uint64, string, string, string) (harness.TaskRecord, harness.OwnerDecisionEvent, error)
}

type callbackTransport struct {
	server *Server
	mu     sync.Mutex
	probed bool
}

var probeTokenPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{32,128}$`)

type originProbeRequest struct{}
type originProbeResponse struct {
	SchemaVersion   string `json:"schema_version"`
	CallbackEnabled bool   `json:"callback_enabled"`
	ObservedOrigin  string `json:"observed_origin"`
	OriginTrust     string `json:"origin_trust"`
	OneTime         bool   `json:"one_time"`
}

type renderCallbackRequest struct {
	TaskID    string `json:"task_id"`
	Version   uint64 `json:"version"`
	SessionID string `json:"session_id"`
}

type decisionCallbackRequest struct {
	TaskID    string `json:"task_id"`
	Version   uint64 `json:"version"`
	SessionID string `json:"session_id"`
	Handle    string `json:"handle"`
	Decision  string `json:"decision"`
	Assertion string `json:"assertion"`
}

func (t *callbackTransport) serve(w http.ResponseWriter, r *http.Request) {
	if !t.server.callback.Enabled {
		http.NotFound(w, r)
		return
	}
	if r.Host != t.server.callback.Host {
		http.Error(w, "host not allowed", http.StatusForbidden)
		return
	}
	if !t.authorizeOrigin(w, r) {
		return
	}
	switch r.URL.Path {
	case callbackOriginPath:
		if r.Method == http.MethodOptions {
			t.options(w)
			return
		}
		if r.Method != http.MethodPost {
			methodPOST(w, r)
			return
		}
		t.origin(w, r)
	case callbackRenderPath:
		if r.Method == http.MethodOptions {
			t.options(w)
			return
		}
		if r.Method != http.MethodPost {
			methodPOST(w, r)
			return
		}
		t.render(w, r)
	case callbackDecisionPath:
		if r.Method == http.MethodOptions {
			t.options(w)
			return
		}
		if r.Method != http.MethodPost {
			methodPOST(w, r)
			return
		}
		t.decision(w, r)
	default:
		http.NotFound(w, r)
	}
}

// serveOriginProbe is intentionally separate from authenticated callbacks. It
// accepts only a short-lived, high-entropy UI probe token and returns metadata;
// it never creates a session, verifies an owner, or authorizes an action.
func (t *callbackTransport) serveOriginProbe(w http.ResponseWriter, r *http.Request) {
	if !t.server.callback.OriginProbeEnabled || r.Host != "127.0.0.1:8788" {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodOptions {
		w.Header().Set("Allow", "GET, OPTIONS")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	origin := r.Header.Get("Origin")
	if !validObservedOrigin(origin) {
		http.Error(w, "origin required", http.StatusForbidden)
		return
	}
	w.Header().Set("Access-Control-Allow-Origin", origin)
	w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "X-OpenDuck-UI-Probe")
	w.Header().Set("Access-Control-Allow-Credentials", "false")
	w.Header().Set("Access-Control-Allow-Private-Network", "true")
	w.Header().Set("Vary", "Origin")
	w.Header().Set("Cache-Control", "no-store")
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	token := r.Header.Get("X-OpenDuck-UI-Probe")
	if !probeTokenPattern.MatchString(token) {
		http.Error(w, "probe rejected", http.StatusForbidden)
		return
	}
	t.mu.Lock()
	if t.probed {
		t.mu.Unlock()
		http.Error(w, "probe already used", http.StatusConflict)
		return
	}
	t.probed = true
	t.mu.Unlock()
	writeJSON(w, http.StatusOK, originProbeResponse{SchemaVersion: "origin-probe.v1", CallbackEnabled: t.server.callback.Enabled, ObservedOrigin: origin, OriginTrust: "untrusted", OneTime: true})
}

func (t *callbackTransport) authorizeOrigin(w http.ResponseWriter, r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" || origin == "null" || origin != t.server.callback.Origin {
		http.Error(w, "origin not allowed", http.StatusForbidden)
		return false
	}
	w.Header().Set("Access-Control-Allow-Origin", t.server.callback.Origin)
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-P2P-Private-Network, X-Owner-Assertion")
	w.Header().Set("Access-Control-Allow-Private-Network", "true")
	w.Header().Set("Vary", "Origin")
	return true
}

func (t *callbackTransport) options(w http.ResponseWriter) {
	w.Header().Set("Content-Length", "0")
	w.WriteHeader(http.StatusNoContent)
}

func (t *callbackTransport) origin(w http.ResponseWriter, r *http.Request) {
	var req originProbeRequest
	if !decodeCallbackJSON(w, r, &req) {
		return
	}
	t.mu.Lock()
	if t.probed {
		t.mu.Unlock()
		http.Error(w, "probe already used", http.StatusConflict)
		return
	}
	t.probed = true
	t.mu.Unlock()
	writeJSON(w, http.StatusOK, originProbeResponse{SchemaVersion: "callback-origin-probe.v1", CallbackEnabled: true, ObservedOrigin: t.server.callback.Origin, OriginTrust: "configured", OneTime: true})
}

func (t *callbackTransport) render(w http.ResponseWriter, r *http.Request) {
	var req renderCallbackRequest
	if !decodeCallbackJSON(w, r, &req) || req.TaskID == "" || req.SessionID == "" || req.Version == 0 {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	if t.server.CallbackController == nil {
		http.Error(w, "callback unavailable", http.StatusServiceUnavailable)
		return
	}
	_, receipt, challenge, err := t.server.CallbackController.RenderCallbackSession(r.Context(), req.TaskID, req.Version, req.SessionID)
	if err != nil {
		http.Error(w, "callback denied", http.StatusForbidden)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"schema_version": "callback-render.v1", "receipt": receipt, "challenge": challenge})
}

func (t *callbackTransport) decision(w http.ResponseWriter, r *http.Request) {
	var req decisionCallbackRequest
	if !decodeCallbackJSON(w, r, &req) || req.TaskID == "" || req.SessionID == "" || req.Handle == "" || req.Assertion == "" || req.Version == 0 || (req.Decision != "approve" && req.Decision != "reject") {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	if t.server.OwnerAuthenticator == nil || t.server.CallbackController == nil {
		http.Error(w, "callback unavailable", http.StatusServiceUnavailable)
		return
	}
	if _, _, err := t.server.OwnerAuthenticator.Authenticate(r.Context(), req.Assertion); err != nil {
		http.Error(w, "authentication denied", http.StatusForbidden)
		return
	}
	_, event, err := t.server.CallbackController.RecordAuthenticatedCallback(r.Context(), req.TaskID, req.Version, req.SessionID, req.Handle, req.Decision)
	if err != nil {
		http.Error(w, "callback denied", http.StatusForbidden)
		return
	}
	// The controller, not the request, constructs the authoritative event.
	writeJSON(w, http.StatusOK, map[string]any{"schema_version": "callback-decision.v1", "decision_event_id": event.DecisionEventID, "decision": event.Decision})
}

func decodeCallbackJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	if r.Header.Get("Content-Type") != "application/json" {
		http.Error(w, "content type required", http.StatusUnsupportedMediaType)
		return false
	}
	dec := json.NewDecoder(io.LimitReader(r.Body, maxCallbackBody+1))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return false
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		http.Error(w, "one json value required", http.StatusBadRequest)
		return false
	}
	return true
}

func methodPOST(w http.ResponseWriter, r *http.Request) bool {
	if r.Method == http.MethodPost {
		return true
	}
	w.Header().Set("Allow", http.MethodPost+", "+http.MethodOptions)
	http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	return false
}

func validateCallbackConfig(c CallbackConfig) error {
	if c.OriginProbeEnabled && c.Host != "127.0.0.1:8788" {
		return errors.New("origin probe requires 127.0.0.1:8788 host")
	}
	if !c.Enabled {
		if c.Origin != "" {
			return errors.New("disabled callback cannot configure origin")
		}
		return nil
	}
	u, err := url.Parse(c.Origin)
	if c.Origin == "" || c.Origin == "null" || strings.ContainsAny(c.Origin, " \t\r\n") || c.Host == "" || err != nil || u.Scheme == "" || u.Host == "" || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.User != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return errors.New("enabled callback requires exact origin and host")
	}
	return nil
}

// validObservedOrigin validates a browser Origin syntax without granting it
// trust. The exact value is echoed solely for CORS discovery diagnostics.
func validObservedOrigin(origin string) bool {
	if origin == "" || origin == "null" || strings.ContainsAny(origin, " \t\r\n") {
		return false
	}
	u, err := url.Parse(origin)
	return err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host != "" && u.Path == "" && u.RawQuery == "" && u.Fragment == "" && u.User == nil
}
