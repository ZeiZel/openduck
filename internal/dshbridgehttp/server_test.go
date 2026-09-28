package dshbridgehttp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"openduck/internal/codexruntime"
	"openduck/internal/dshbridge"
)

type fakeModels struct{}

var testProjection = dshbridge.SafeProjection{Classification: dshbridge.ClassL1, Provenance: "controller:synthetic", Proof: "sha256:0000000000000000000000000000000000000000000000000000000000000000", Version: 1, ExpiresAt: time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC)}

type fixtureVerifier struct{}

func (fixtureVerifier) Verify(_ string, payload []byte, p dshbridge.SafeProjection, now time.Time) error {
	if len(payload) == 0 || p.Version == 0 || !p.ExpiresAt.After(now) || len(p.Proof) != 71 {
		return fmt.Errorf("invalid projection attestation")
	}
	return nil
}

type chatAuthFixture struct{}

func (chatAuthFixture) Authorize(context.Context) error { return nil }

type rejectingChatAuthFixture struct{}

func (rejectingChatAuthFixture) Authorize(context.Context) error {
	return codexruntime.ErrOwnerAuthorization
}

type chatGateFixture struct{}

func (chatGateFixture) Check(context.Context) error { return nil }

type approvalRequiredRuns struct{}

func (approvalRequiredRuns) Start(context.Context, codexruntime.GeneralChatOrder) (codexruntime.AssistantTurnResult, error) {
	return codexruntime.AssistantTurnResult{}, codexruntime.ApprovalRequiredError{RequestID: "0123456789abcdef0123456789abcdef", OrderDigest: "sha256:" + strings.Repeat("a", 64), ExpiresAt: time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC)}
}
func (approvalRequiredRuns) Get(context.Context, string) (codexruntime.AssistantTurnResult, error) {
	return codexruntime.AssistantTurnResult{}, errors.New("not implemented")
}
func (approvalRequiredRuns) Cancel(context.Context, string) error {
	return errors.New("not implemented")
}

func TestChatRunApprovalRequiredHasExact428Contract(t *testing.T) {
	h, session := testHandler(t)
	_ = h
	store, err := dshbridge.NewSessionStore(dshbridge.Config{Origin: session.Origin, Host: session.Host})
	if err != nil {
		t.Fatal(err)
	}
	issued, err := store.Issue("approval-contract")
	if err != nil {
		t.Fatal(err)
	}
	h = (&Server{Bridge: &dshbridge.Bridge{Sessions: store, Models: fakeModels{}, Classifier: fakeClassifier{}, Authority: fakeAuthority{}, ProjectionVerifier: fixtureVerifier{}}, Origin: issued.Origin, Host: issued.Host, ChatRuns: approvalRequiredRuns{}}).Handler()
	body := `{"schema_version":"general-chat-order.v1","chat_id":"approval","prompt":"hello","workspace_roots":[],"classification":"L0","max_output_bytes":1024,"approval_policy":"never","read_only":true,"tools_disabled":true,"network_mode":"model_only"}`
	r := request(http.MethodPost, "/v1/chat/runs", body, issued, "approval-start")
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusPreconditionRequired {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	var got map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if len(got) != 5 || got["schema_version"] != "owner-approval-required.v1" || got["error_code"] != "OWNER_APPROVAL_REQUIRED" || got["request_id"] == "" || got["order_digest"] == "" || got["expires_at"] == "" {
		t.Fatalf("contract=%v", got)
	}
}

// This crosses the real HTTP parser/routes, async service/ledger, and a
// provider-free transport. No live login or model process is involved.
func TestChatRunHTTPE2EWithFakeTransport(t *testing.T) {
	store, err := dshbridge.NewSessionStore(dshbridge.Config{Origin: "http://127.0.0.1:3000", Host: "127.0.0.1:8788"})
	if err != nil {
		t.Fatal(err)
	}
	session, err := store.Issue("chat-e2e")
	if err != nil {
		t.Fatal(err)
	}
	inv := codexruntime.RuntimeInventory{SchemaVersion: codexruntime.RuntimeInventoryV1, AccountState: "chatgpt", ExecutableVersion: "fixture", ExecutableDigest: "sha256:0000000000000000000000000000000000000000000000000000000000000000", ModelNetworkOnly: true}
	canary, err := codexruntime.NewOwnerCanary(t.TempDir(), &codexruntime.FakeChatTransport{InventoryValue: inv, Result: codexruntime.AssistantTurnResult{State: "completed", Answer: "fixture answer"}}, chatAuthFixture{}, chatGateFixture{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	ledger, err := codexruntime.NewEncryptedChatRunLedgerWithCheckpoint(t.TempDir()+"/chat.enc", []byte("01234567890123456789012345678901"), codexruntime.NewMemoryChatCheckpoint())
	if err != nil {
		t.Fatal(err)
	}
	runs, err := codexruntime.NewChatRunService(canary, ledger)
	if err != nil {
		t.Fatal(err)
	}
	h := (&Server{Bridge: &dshbridge.Bridge{Sessions: store, Models: fakeModels{}, Classifier: fakeClassifier{}, Authority: fakeAuthority{}, ProjectionVerifier: fixtureVerifier{}}, Origin: session.Origin, Host: session.Host, ChatRuns: runs, ChatAuthorizer: func(context.Context) error { return nil }}).Handler()
	body := `{"schema_version":"general-chat-order.v1","chat_id":"http-chat","prompt":"hello","workspace_roots":[],"classification":"L0","max_output_bytes":1024,"approval_policy":"never","read_only":true,"tools_disabled":true,"network_mode":"model_only"}`
	r := request(http.MethodPost, "/v1/chat/runs", body, session, "chat-start")
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusAccepted {
		t.Fatalf("start %d %s", w.Code, w.Body.String())
	}
	var started codexruntime.AssistantTurnResult
	if err := json.Unmarshal(w.Body.Bytes(), &started); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 40; i++ {
		r = request(http.MethodGet, "/v1/chat/runs/"+started.ChatID, "", session, fmt.Sprintf("chat-get-%d", i))
		w = httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != http.StatusOK {
			t.Fatalf("get %d %s", w.Code, w.Body.String())
		}
		var got codexruntime.AssistantTurnResult
		_ = json.Unmarshal(w.Body.Bytes(), &got)
		if got.State == "completed" {
			if got.Answer != "fixture answer" {
				t.Fatalf("answer=%q", got.Answer)
			}
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("chat did not complete")
}

func TestChatRunHTTPRejectsAnonymousOwnerStartBeforeLedger(t *testing.T) {
	store, err := dshbridge.NewSessionStore(dshbridge.Config{Origin: "http://127.0.0.1:3000", Host: "127.0.0.1:8788"})
	if err != nil {
		t.Fatal(err)
	}
	session, err := store.Issue("anonymous-bootstrap")
	if err != nil {
		t.Fatal(err)
	}
	inv := codexruntime.RuntimeInventory{SchemaVersion: codexruntime.RuntimeInventoryV1, AccountState: "chatgpt", ExecutableVersion: "fixture", ExecutableDigest: "sha256:" + strings.Repeat("0", 64), ModelNetworkOnly: true}
	canary, err := codexruntime.NewOwnerCanary(t.TempDir(), &codexruntime.FakeChatTransport{InventoryValue: inv}, rejectingChatAuthFixture{}, chatGateFixture{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	ledger, err := codexruntime.NewEncryptedChatRunLedgerWithCheckpoint(t.TempDir()+"/chat.enc", []byte("01234567890123456789012345678901"), codexruntime.NewMemoryChatCheckpoint())
	if err != nil {
		t.Fatal(err)
	}
	runs, err := codexruntime.NewChatRunService(canary, ledger)
	if err != nil {
		t.Fatal(err)
	}
	h := (&Server{Bridge: &dshbridge.Bridge{Sessions: store, Models: fakeModels{}, Classifier: fakeClassifier{}, Authority: fakeAuthority{}, ProjectionVerifier: fixtureVerifier{}}, Origin: session.Origin, Host: session.Host, ChatRuns: runs}).Handler()
	body := `{"schema_version":"general-chat-order.v1","chat_id":"anonymous","prompt":"hello","workspace_roots":[],"classification":"L0","max_output_bytes":1024,"approval_policy":"never","read_only":true,"tools_disabled":true,"network_mode":"model_only"}`
	r := request(http.MethodPost, "/v1/chat/runs", body, session, "anonymous-start")
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("anonymous start status=%d body=%s", w.Code, w.Body.String())
	}
	if _, err := ledger.Get("anonymous"); err == nil {
		t.Fatal("anonymous owner grant created a durable run")
	}
}

func (fakeModels) ReadInbox(context.Context) (dshbridge.InboxReadModel, error) {
	return dshbridge.InboxReadModel{SchemaVersion: dshbridge.ReadModelV1, Projection: testProjection, GeneratedAt: time.Unix(1, 0).UTC()}, nil
}
func (fakeModels) ReadCalendar(context.Context) (dshbridge.CalendarReadModel, error) {
	return dshbridge.CalendarReadModel{SchemaVersion: dshbridge.ReadModelV1, Projection: testProjection, GeneratedAt: time.Unix(1, 0).UTC()}, nil
}
func (fakeModels) ReadWorkGraph(context.Context) (dshbridge.WorkGraphReadModel, error) {
	return dshbridge.WorkGraphReadModel{SchemaVersion: dshbridge.ReadModelV1, Projection: testProjection, GeneratedAt: time.Unix(1, 0).UTC()}, nil
}
func (fakeModels) ReadTasks(context.Context) (dshbridge.TasksReadModel, error) {
	return dshbridge.TasksReadModel{SchemaVersion: dshbridge.ReadModelV1, Projection: testProjection, GeneratedAt: time.Unix(1, 0).UTC()}, nil
}
func (fakeModels) ReadTime(context.Context) (dshbridge.TimeReadModel, error) {
	return dshbridge.TimeReadModel{SchemaVersion: dshbridge.ReadModelV1, Projection: testProjection, GeneratedAt: time.Unix(1, 0).UTC()}, nil
}
func (fakeModels) ReadReviews(context.Context) (dshbridge.ReviewsReadModel, error) {
	return dshbridge.ReviewsReadModel{SchemaVersion: dshbridge.ReadModelV1, Projection: testProjection, GeneratedAt: time.Unix(1, 0).UTC()}, nil
}
func (fakeModels) ReadMemoryMetadata(context.Context) (dshbridge.MemoryMetadataReadModel, error) {
	return dshbridge.MemoryMetadataReadModel{SchemaVersion: dshbridge.ReadModelV1, Projection: testProjection, GeneratedAt: time.Unix(1, 0).UTC()}, nil
}
func (fakeModels) ReadHealth(context.Context) (dshbridge.HealthReadModel, error) {
	return dshbridge.HealthReadModel{SchemaVersion: dshbridge.ReadModelV1, Projection: testProjection, Status: "ok", ControllerAvailable: true}, nil
}

type sentinelModels struct{ fakeModels }

func (sentinelModels) ReadInbox(context.Context) (dshbridge.InboxReadModel, error) {
	return dshbridge.InboxReadModel{SchemaVersion: dshbridge.ReadModelV1, Projection: testProjection, Items: []dshbridge.InboxItem{{ID: "x", Summary: "private-sentinel", Source: "test", Classification: dshbridge.ClassL1, UpdatedAt: time.Unix(1, 0).UTC()}}, GeneratedAt: time.Unix(1, 0).UTC()}, nil
}

type fakeClassifier struct{}

func (fakeClassifier) Classify([]byte) (dshbridge.PrivacyClass, error) { return dshbridge.ClassL1, nil }

type fakeAuthority struct{}

func (fakeAuthority) AdmitCloud(context.Context, []byte) (dshbridge.CloudAdmission, error) {
	return dshbridge.CloudAdmission{ID: "adm_12345678", Status: "pending"}, nil
}
func (fakeAuthority) DispatchLocalPD(context.Context, []byte) (dshbridge.LocalPDAdmission, error) {
	return dshbridge.LocalPDAdmission{Handle: "local-1", Status: "queued"}, nil
}

func testHandler(t *testing.T) (http.Handler, dshbridge.UIChannelSession) {
	t.Helper()
	store, err := dshbridge.NewSessionStore(dshbridge.Config{Origin: "http://127.0.0.1:3000", Host: "127.0.0.1:8788"})
	if err != nil {
		t.Fatal(err)
	}
	b := &dshbridge.Bridge{Sessions: store, Models: fakeModels{}, Classifier: fakeClassifier{}, Authority: fakeAuthority{}, ProjectionVerifier: fixtureVerifier{}}
	session, err := store.Issue("client")
	if err != nil {
		t.Fatal(err)
	}
	return (&Server{Bridge: b, Origin: "http://127.0.0.1:3000", Host: "127.0.0.1:8788"}).Handler(), session
}

func request(method, path string, body string, session dshbridge.UIChannelSession, requestNonce string) *http.Request {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.RemoteAddr = "127.0.0.1:45678"
	r.Host = session.Host
	r.Header.Set("Origin", session.Origin)
	if path != "/v1/ui/bootstrap" {
		r.Header.Set("Authorization", "Bearer "+session.Token)
		r.Header.Set("X-UI-Nonce", session.ClientNonce)
		r.Header.Set("X-UI-Request-Nonce", requestNonce)
	}
	return r
}

func TestReadModelRequiresAuthenticatedNoStoreChannel(t *testing.T) {
	h, session := testHandler(t)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, request(http.MethodGet, "/v1/read/inbox", "", session, "r1"))
	if w.Code != http.StatusOK || w.Header().Get("Cache-Control") == "" || w.Header().Get("Access-Control-Allow-Credentials") != "false" {
		t.Fatalf("read: code=%d headers=%v", w.Code, w.Header())
	}
	var model struct {
		Route string                   `json:"route"`
		Data  dshbridge.InboxReadModel `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &model); err != nil || model.Route != "inbox" || model.Data.SchemaVersion != dshbridge.ReadModelV1 {
		t.Fatalf("model: %v %#v", err, model)
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, request(http.MethodGet, "/v1/read/inbox", "", session, "r1"))
	if w.Code != http.StatusForbidden {
		t.Fatalf("replayed request code=%d", w.Code)
	}
}

func TestComposerStrictContentTypeAndOpaqueResponse(t *testing.T) {
	h, session := testHandler(t)
	r := request(http.MethodPost, "/v1/composer", "safe-sentinel", session, "compose-1")
	r.Header.Set("Content-Type", "application/octet-stream")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusAccepted || strings.Contains(w.Body.String(), "safe-sentinel") || !strings.Contains(w.Body.String(), "adm_12345678") {
		t.Fatalf("compose response: %d %s", w.Code, w.Body.String())
	}
	r = request(http.MethodPost, "/v1/composer", "x", session, "compose-2")
	r.Header.Set("Content-Type", "text/plain")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("content type code=%d", w.Code)
	}
}

func TestOriginHostAndControllerDownFailClosed(t *testing.T) {
	h, session := testHandler(t)
	r := request(http.MethodGet, "/v1/read/health", "", session, "r1")
	r.Host = "localhost:8788"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("wrong host code=%d", w.Code)
	}
	w = httptest.NewRecorder()
	(&Server{Origin: session.Origin, Host: session.Host}).Handler().ServeHTTP(w, request(http.MethodGet, "/v1/read/health", "", session, "r2"))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("down code=%d", w.Code)
	}
}

func TestBootstrapRejectsMismatchPeerNullAndDuplicateJSON(t *testing.T) {
	h, session := testHandler(t)
	for _, body := range []string{`{"client_nonce":"x","client_nonce":"y"}`, `{"client_nonce":null}`} {
		r := httptest.NewRequest(http.MethodPost, "/v1/ui/bootstrap", strings.NewReader(body))
		r.RemoteAddr = "127.0.0.1:5000"
		r.Host = session.Host
		r.Header.Set("Origin", session.Origin)
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("invalid bootstrap code=%d", w.Code)
		}
	}
	r := httptest.NewRequest(http.MethodPost, "/v1/ui/bootstrap", strings.NewReader(`{"client_nonce":"x"}`))
	r.RemoteAddr = "192.0.2.1:5000"
	r.Host = session.Host
	r.Header.Set("Origin", session.Origin)
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("non-loopback peer code=%d", w.Code)
	}
	r = httptest.NewRequest(http.MethodPost, "/v1/ui/bootstrap", strings.NewReader(`{"client_nonce":"x"}`))
	r.RemoteAddr = "127.0.0.1:5000"
	r.Host = "localhost:8788"
	r.Header.Set("Origin", session.Origin)
	r.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("wrong bootstrap host code=%d", w.Code)
	}
}

func TestPNAHeaderOnlyWhenRequested(t *testing.T) {
	h, session := testHandler(t)
	for _, want := range []string{"", "true"} {
		r := httptest.NewRequest(http.MethodOptions, "/v1/read/health", nil)
		r.RemoteAddr = "127.0.0.1:5000"
		r.Host = session.Host
		r.Header.Set("Origin", session.Origin)
		if want != "" {
			r.Header.Set("Access-Control-Request-Private-Network", want)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != http.StatusNoContent || w.Header().Get("Access-Control-Allow-Private-Network") != want {
			t.Fatalf("PNA want=%q got=%q code=%d", want, w.Header().Get("Access-Control-Allow-Private-Network"), w.Code)
		}
	}
}

func TestReadModelSentinelAndOversizeFailClosed(t *testing.T) {
	store, err := dshbridge.NewSessionStore(dshbridge.Config{Origin: "http://127.0.0.1:3000", Host: "127.0.0.1:8788"})
	if err != nil {
		t.Fatal(err)
	}
	session, err := store.Issue("sentinel-client")
	if err != nil {
		t.Fatal(err)
	}
	b := &dshbridge.Bridge{Sessions: store, Models: sentinelModels{}, ProjectionVerifier: fixtureVerifier{}}
	h := (&Server{Bridge: b, Origin: session.Origin, Host: session.Host}).Handler()
	r := request(http.MethodGet, "/v1/read/inbox", "", session, "sentinel-read")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("sentinel read code=%d", w.Code)
	}
}

type pdInboxModels struct{ fakeModels }

func (pdInboxModels) ReadInbox(context.Context) (dshbridge.InboxReadModel, error) {
	return dshbridge.InboxReadModel{SchemaVersion: dshbridge.ReadModelV1, Projection: testProjection, Items: []dshbridge.InboxItem{{ID: "x", Summary: "redacted", Source: "source-ref", Classification: dshbridge.ClassL2, UpdatedAt: time.Unix(1, 0).UTC()}}, GeneratedAt: time.Unix(1, 0).UTC()}, nil
}

func TestPDInboxNeverReachesGeneralUI(t *testing.T) {
	store, err := dshbridge.NewSessionStore(dshbridge.Config{Origin: "http://127.0.0.1:3000", Host: "127.0.0.1:8788"})
	if err != nil {
		t.Fatal(err)
	}
	session, err := store.Issue("pd-client")
	if err != nil {
		t.Fatal(err)
	}
	h := (&Server{Bridge: &dshbridge.Bridge{Sessions: store, Models: pdInboxModels{}, ProjectionVerifier: fixtureVerifier{}}, Origin: session.Origin, Host: session.Host}).Handler()
	r := request(http.MethodGet, "/v1/read/inbox", "", session, "pd-read")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("PD inbox was exposed: code=%d body=%s", w.Code, w.Body.String())
	}
}

type unprovenModels struct{ fakeModels }

func (unprovenModels) ReadCalendar(context.Context) (dshbridge.CalendarReadModel, error) {
	return dshbridge.CalendarReadModel{SchemaVersion: dshbridge.ReadModelV1, Items: []dshbridge.CalendarItem{}, GeneratedAt: time.Unix(1, 0).UTC()}, nil
}
func TestEveryRouteRequiresSafeProjectionProof(t *testing.T) {
	store, err := dshbridge.NewSessionStore(dshbridge.Config{Origin: "http://127.0.0.1:3000", Host: "127.0.0.1:8788"})
	if err != nil {
		t.Fatal(err)
	}
	session, err := store.Issue("unproven-client")
	if err != nil {
		t.Fatal(err)
	}
	h := (&Server{Bridge: &dshbridge.Bridge{Sessions: store, Models: unprovenModels{}}, Origin: session.Origin, Host: session.Host}).Handler()
	r := request(http.MethodGet, "/v1/read/calendar", "", session, "unproven-read")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("unproven projection code=%d", w.Code)
	}
}

type rejectingVerifier struct{}

func (rejectingVerifier) Verify(string, []byte, dshbridge.SafeProjection, time.Time) error {
	return fmt.Errorf("forged or altered attestation")
}
func TestForgedAttestationRejectedAcrossEveryRoute(t *testing.T) {
	_, session := testHandler(t)
	// Replace the injected verifier with a fail-closed verifier: every route
	// must require a trusted attestation, not just a proof-shaped string.
	store, err := dshbridge.NewSessionStore(dshbridge.Config{Origin: session.Origin, Host: session.Host})
	if err != nil {
		t.Fatal(err)
	}
	fresh, err := store.Issue("forged-client")
	if err != nil {
		t.Fatal(err)
	}
	server := (&Server{Bridge: &dshbridge.Bridge{Sessions: store, Models: fakeModels{}, ProjectionVerifier: rejectingVerifier{}}, Origin: fresh.Origin, Host: fresh.Host}).Handler()
	for i, route := range []string{"inbox", "calendar", "workgraph", "tasks", "time", "reviews", "memory-metadata", "health"} {
		r := request(http.MethodGet, "/v1/read/"+route, "", fresh, fmt.Sprintf("forged-%d", i))
		w := httptest.NewRecorder()
		server.ServeHTTP(w, r)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("route=%s forged proof code=%d", route, w.Code)
		}
	}
}

type mutableModels struct{ items *[]dshbridge.InboxItem }

func (m mutableModels) ReadInbox(context.Context) (dshbridge.InboxReadModel, error) {
	return dshbridge.InboxReadModel{SchemaVersion: dshbridge.ReadModelV1, Projection: testProjection, Items: *m.items, GeneratedAt: time.Unix(1, 0).UTC()}, nil
}
func (m mutableModels) ReadCalendar(context.Context) (dshbridge.CalendarReadModel, error) {
	return dshbridge.CalendarReadModel{SchemaVersion: dshbridge.ReadModelV1, Projection: testProjection, Items: []dshbridge.CalendarItem{}, GeneratedAt: time.Unix(1, 0).UTC()}, nil
}
func (m mutableModels) ReadWorkGraph(context.Context) (dshbridge.WorkGraphReadModel, error) {
	return dshbridge.WorkGraphReadModel{SchemaVersion: dshbridge.ReadModelV1, Projection: testProjection, Nodes: []dshbridge.WorkGraphNode{}, Edges: []dshbridge.WorkGraphEdge{}, GeneratedAt: time.Unix(1, 0).UTC()}, nil
}
func (m mutableModels) ReadTasks(context.Context) (dshbridge.TasksReadModel, error) {
	return dshbridge.TasksReadModel{SchemaVersion: dshbridge.ReadModelV1, Projection: testProjection, Items: []dshbridge.TaskItem{}, GeneratedAt: time.Unix(1, 0).UTC()}, nil
}
func (m mutableModels) ReadTime(context.Context) (dshbridge.TimeReadModel, error) {
	return dshbridge.TimeReadModel{SchemaVersion: dshbridge.ReadModelV1, Projection: testProjection, GeneratedAt: time.Unix(1, 0).UTC()}, nil
}
func (m mutableModels) ReadReviews(context.Context) (dshbridge.ReviewsReadModel, error) {
	return dshbridge.ReviewsReadModel{SchemaVersion: dshbridge.ReadModelV1, Projection: testProjection, Items: []dshbridge.ReviewItem{}, GeneratedAt: time.Unix(1, 0).UTC()}, nil
}
func (m mutableModels) ReadMemoryMetadata(context.Context) (dshbridge.MemoryMetadataReadModel, error) {
	return dshbridge.MemoryMetadataReadModel{SchemaVersion: dshbridge.ReadModelV1, Projection: testProjection, Items: []dshbridge.MemoryMetadata{}, GeneratedAt: time.Unix(1, 0).UTC()}, nil
}
func (m mutableModels) ReadHealth(context.Context) (dshbridge.HealthReadModel, error) {
	return dshbridge.HealthReadModel{SchemaVersion: dshbridge.ReadModelV1, Projection: testProjection, Status: "ok", ControllerAvailable: true, GeneratedAt: time.Unix(1, 0).UTC()}, nil
}

type mutatingVerifier struct{ items *[]dshbridge.InboxItem }

func (v mutatingVerifier) Verify(string, []byte, dshbridge.SafeProjection, time.Time) error {
	(*v.items)[0].Summary = "mutated-after-verify"
	return nil
}
func TestVerificationUsesImmutableSnapshotAndNilArraysBecomeEmpty(t *testing.T) {
	items := []dshbridge.InboxItem{{ID: "item", Summary: "original", Source: "source", Classification: dshbridge.ClassL1, UpdatedAt: time.Unix(1, 0).UTC()}}
	store, err := dshbridge.NewSessionStore(dshbridge.Config{Origin: "http://127.0.0.1:3000", Host: "127.0.0.1:8788"})
	if err != nil {
		t.Fatal(err)
	}
	session, err := store.Issue("mutation-client")
	if err != nil {
		t.Fatal(err)
	}
	h := (&Server{Bridge: &dshbridge.Bridge{Sessions: store, Models: mutableModels{items: &items}, ProjectionVerifier: mutatingVerifier{items: &items}}, Origin: session.Origin, Host: session.Host}).Handler()
	r := request(http.MethodGet, "/v1/read/inbox", "", session, "mutation-read")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK || strings.Contains(w.Body.String(), "mutated-after-verify") || !strings.Contains(w.Body.String(), "original") {
		t.Fatalf("snapshot changed after verify: %d %s", w.Code, w.Body.String())
	}
}

func TestEverySerializedReadEnvelopeHasConcreteSchemaShape(t *testing.T) {
	h, session := testHandler(t)
	for i, route := range []string{"inbox", "calendar", "workgraph", "tasks", "time", "reviews", "memory-metadata", "health"} {
		r := request(http.MethodGet, "/v1/read/"+route, "", session, fmt.Sprintf("fixture-%d", i))
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != http.StatusOK {
			t.Fatalf("route=%s code=%d", route, w.Code)
		}
		var envelope struct {
			SchemaVersion string          `json:"schema_version"`
			Route         string          `json:"route"`
			Data          json.RawMessage `json:"data"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &envelope); err != nil {
			t.Fatal(err)
		}
		if envelope.SchemaVersion != dshbridge.ReadModelV1 || envelope.Route != route || len(envelope.Data) == 0 || string(envelope.Data) == "null" {
			t.Fatalf("invalid envelope route=%s body=%s", route, w.Body.String())
		}
		var data struct {
			SchemaVersion string `json:"schema_version"`
		}
		if err := json.Unmarshal(envelope.Data, &data); err != nil || data.SchemaVersion != dshbridge.ReadModelV1 {
			t.Fatalf("invalid data route=%s", route)
		}
	}
}
