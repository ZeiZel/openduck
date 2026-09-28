package harnesshttp

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"openduck/internal/harness"
	"strings"
	"testing"
)

type callbackController struct{}

func (callbackController) RenderCallbackSession(context.Context, string, uint64, string) (harness.TaskRecord, harness.InteractionRenderReceipt, harness.DecisionChallenge, error) {
	return harness.TaskRecord{}, harness.InteractionRenderReceipt{ReceiptDigest: "receipt"}, harness.DecisionChallenge{ChallengeDigest: "challenge"}, nil
}
func (callbackController) RecordAuthenticatedCallback(context.Context, string, uint64, string, string, string) (harness.TaskRecord, harness.OwnerDecisionEvent, error) {
	return harness.TaskRecord{}, harness.OwnerDecisionEvent{DecisionEventID: "event", Decision: "approve"}, nil
}

type callbackAuthenticator struct{}

func (callbackAuthenticator) Authenticate(context.Context, string) (string, string, error) {
	return "owner", "proof", nil
}

type snapshotter struct {
	snap harness.ControllerSnapshot
	err  error
}

func (s snapshotter) Snapshot(context.Context) (harness.ControllerSnapshot, error) {
	return s.snap, s.err
}

func TestStatusGETAndMethodBoundaries(t *testing.T) {
	c := snapshotter{snap: harness.ControllerSnapshot{Tasks: map[string]harness.TaskRecord{"a": {ID: "a", State: harness.Observed}}}}
	h := (&Server{Controller: c}).Handler()
	r := httptest.NewRequest(http.MethodGet, "/v1/controller/status", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status code = %d", w.Code)
	}
	if got := w.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("content type = %q", got)
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/v1/controller/status", nil))
	if w.Code != http.StatusMethodNotAllowed || w.Header().Get("Allow") != "GET" {
		t.Fatalf("POST status: %d allow=%q", w.Code, w.Header().Get("Allow"))
	}
}

func TestTasksExposeOnlyBoundedProjection(t *testing.T) {
	c := snapshotter{snap: harness.ControllerSnapshot{Tasks: map[string]harness.TaskRecord{
		"z": {ID: "z", State: harness.WorkRunning, Version: 7, WorkOrder: &harness.WorkOrder{}, Evidence: &harness.EvidenceBundle{}, Decisions: map[string]harness.ApprovalRecord{"d": {DecisionEventID: "d"}}},
		"a": {ID: "a", State: harness.SignalReady, Version: 2},
	}}}
	w := httptest.NewRecorder()
	(&Server{Controller: c}).Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/v1/controller/tasks", nil))
	if w.Code != http.StatusOK || strings.Contains(w.Body.String(), `"work_order":`) || strings.Contains(w.Body.String(), "decision_event_id") {
		t.Fatalf("unsafe task projection: code=%d body=%s", w.Code, w.Body.String())
	}
	var got TaskList
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil || got.SchemaVersion != "controller-task-list.v1" || len(got.Tasks) != 2 || got.Tasks[0].ID != "a" || got.Tasks[1].ID != "z" || got.Tasks[1].DecisionCount != 1 {
		t.Fatalf("task list: err=%v value=%+v", err, got)
	}
	w = httptest.NewRecorder()
	(&Server{Controller: c}).Handler().ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/v1/controller/tasks", nil))
	if w.Code != http.StatusMethodNotAllowed || w.Header().Get("Allow") != "GET" {
		t.Fatalf("method boundary: %d", w.Code)
	}
}

func TestReadyFailsClosedOnPoison(t *testing.T) {
	h := (&Server{Controller: snapshotter{err: errors.Join(harness.ErrControllerPoisoned, errors.New("internal"))}}).Handler()
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("ready code = %d", w.Code)
	}
}

func callbackServer(t *testing.T) http.Handler {
	t.Helper()
	s := &Server{Controller: snapshotter{snap: harness.ControllerSnapshot{Tasks: map[string]harness.TaskRecord{}}}, CallbackController: callbackController{}, OwnerAuthenticator: callbackAuthenticator{}}
	if err := s.ConfigureCallback(CallbackConfig{Enabled: true, Origin: "https://codex.test", Host: "127.0.0.1:8788", OriginProbeEnabled: true}); err != nil {
		t.Fatal(err)
	}
	return s.Handler()
}

func callbackRequest(method, path, host, origin, body string) *http.Request {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.Host = host
	if origin != "" {
		r.Header.Set("Origin", origin)
	}
	if method == http.MethodPost {
		r.Header.Set("Content-Type", "application/json")
	}
	return r
}

func TestCallbackDisabledByDefault(t *testing.T) {
	w := httptest.NewRecorder()
	(&Server{}).Handler().ServeHTTP(w, callbackRequest(http.MethodPost, callbackOriginPath, "127.0.0.1:8788", "https://codex.test", `{}`))
	if w.Code != http.StatusNotFound {
		t.Fatalf("disabled status = %d", w.Code)
	}
}

func TestCallbackOriginAndHostBoundaries(t *testing.T) {
	h := callbackServer(t)
	for _, tc := range []struct {
		name, host, origin string
		want               int
	}{
		{"wrong host", "localhost:8788", "https://codex.test", http.StatusForbidden},
		{"wrong origin", "127.0.0.1:8788", "https://other.test", http.StatusForbidden},
		{"null origin", "127.0.0.1:8788", "null", http.StatusForbidden},
	} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, callbackRequest(http.MethodPost, callbackOriginPath, tc.host, tc.origin, `{}`))
		if w.Code != tc.want {
			t.Errorf("%s: code=%d", tc.name, w.Code)
		}
	}
}

func TestCallbackOriginProbeOneTimeAndPreflight(t *testing.T) {
	h := callbackServer(t)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, callbackRequest(http.MethodOptions, callbackRenderPath, "127.0.0.1:8788", "https://codex.test", ""))
	if w.Code != http.StatusNoContent || w.Header().Get("Access-Control-Allow-Credentials") != "" || w.Header().Get("Access-Control-Allow-Private-Network") != "true" {
		t.Fatalf("preflight: code=%d headers=%v", w.Code, w.Header())
	}
	for i := 0; i < 2; i++ {
		w = httptest.NewRecorder()
		h.ServeHTTP(w, callbackRequest(http.MethodPost, callbackOriginPath, "127.0.0.1:8788", "https://codex.test", `{}`))
		want := http.StatusOK
		if i == 1 {
			want = http.StatusConflict
		}
		if w.Code != want {
			t.Fatalf("probe %d: code=%d", i, w.Code)
		}
		if i == 0 {
			var got originProbeResponse
			if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil || !got.OneTime || !got.CallbackEnabled {
				t.Fatalf("probe response: %v %#v", err, got)
			}
		}
	}
}

func TestNonAuthoritativeUIOriginProbe(t *testing.T) {
	h := callbackServer(t)
	r := callbackRequest(http.MethodGet, originProbePath, "127.0.0.1:8788", "https://ui.example", "")
	r.Header.Set("X-OpenDuck-UI-Probe", strings.Repeat("a", 32))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("probe: code=%d cache=%q", w.Code, w.Header().Get("Cache-Control"))
	}
}

func TestOriginProbeIndependentAndCORSDiscovery(t *testing.T) {
	s := &Server{}
	if err := s.ConfigureCallback(CallbackConfig{Host: "127.0.0.1:8788", OriginProbeEnabled: true}); err != nil {
		t.Fatal(err)
	}
	h := s.Handler()
	r := callbackRequest(http.MethodOptions, originProbePath, "127.0.0.1:8788", "https://ui.example", "")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusNoContent || w.Header().Get("Access-Control-Allow-Origin") != "https://ui.example" || w.Header().Get("Access-Control-Allow-Methods") != "GET, OPTIONS" || w.Header().Get("Access-Control-Allow-Credentials") != "false" || w.Header().Get("Access-Control-Allow-Private-Network") != "true" || w.Header().Get("Vary") != "Origin" || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("probe preflight: code=%d headers=%v", w.Code, w.Header())
	}
	r = callbackRequest(http.MethodGet, originProbePath, "127.0.0.1:8788", "https://ui.example", "")
	r.Header.Set("X-OpenDuck-UI-Probe", strings.Repeat("b", 32))
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("probe get code=%d body=%s", w.Code, w.Body.String())
	}
	var got originProbeResponse
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil || got.CallbackEnabled || got.ObservedOrigin != "https://ui.example" || got.OriginTrust != "untrusted" {
		t.Fatalf("probe response: err=%v value=%#v", err, got)
	}
	for _, origin := range []string{"", "null", "javascript:alert(1)", "https://ui.example/path"} {
		r := callbackRequest(http.MethodOptions, originProbePath, "127.0.0.1:8788", origin, "")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != http.StatusForbidden {
			t.Errorf("invalid origin %q code=%d", origin, w.Code)
		}
	}
}

func TestOriginProbeDisabledDoesNotExposeCallbacks(t *testing.T) {
	s := &Server{}
	if err := s.ConfigureCallback(CallbackConfig{Host: "127.0.0.1:8788"}); err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, callbackRequest(http.MethodGet, originProbePath, "127.0.0.1:8788", "https://ui.example", ""))
	if w.Code != http.StatusNotFound {
		t.Fatalf("disabled probe code=%d", w.Code)
	}
}

func TestCallbackStrictJSONAndDecisionAssertion(t *testing.T) {
	h := callbackServer(t)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, callbackRequest(http.MethodPost, callbackRenderPath, "127.0.0.1:8788", "https://codex.test", `{"task_id":"t","version":1,"session_id":"s","extra":1}`))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("unknown field code=%d", w.Code)
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, callbackRequest(http.MethodPost, callbackDecisionPath, "127.0.0.1:8788", "https://codex.test", `{"task_id":"t","version":1,"session_id":"s","handle":"h","decision":"approve","assertion":"a","identity":"forged"}`))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("authoritative field code=%d", w.Code)
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, callbackRequest(http.MethodPost, callbackDecisionPath, "127.0.0.1:8788", "https://codex.test", `{"task_id":"t","version":1,"session_id":"s","handle":"h","decision":"approve","assertion":"a"}`))
	if w.Code != http.StatusOK {
		t.Fatalf("decision code=%d body=%s", w.Code, w.Body.String())
	}
}
