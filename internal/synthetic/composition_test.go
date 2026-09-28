package synthetic

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"openduck/internal/dshbridge"
	"openduck/internal/dshbridgehttp"
)

func TestSyntheticHTTPCompositionIsOpaqueAndFailClosed(t *testing.T) {
	const origin = "http://127.0.0.1:3000"
	const host = "127.0.0.1:8788"
	store, err := dshbridge.NewSessionStore(dshbridge.Config{Origin: origin, Host: host})
	if err != nil {
		t.Fatal(err)
	}
	a := NewAuthority()
	b := &dshbridge.Bridge{Sessions: store, Models: NewModels(time.Now().UTC()), Classifier: Classifier{}, Authority: a, ProjectionVerifier: ProjectionVerifier{}}
	h := FlatReadAdapter((&dshbridgehttp.Server{Bridge: b, Origin: origin, Host: host, ProjectionSigner: ProjectionSigner}).Handler())

	session, err := store.Issue("synthetic-client")
	if err != nil {
		t.Fatal(err)
	}
	compose := func(payload string, nonce string) (int, map[string]any) {
		req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1/v1/composer", bytes.NewBufferString(payload))
		req.RemoteAddr = "127.0.0.1:45000"
		req.Host = host
		req.Header.Set("Origin", origin)
		req.Header.Set("Authorization", "Bearer "+session.Token)
		req.Header.Set("X-UI-Nonce", session.ClientNonce)
		req.Header.Set("X-UI-Request-Nonce", nonce)
		req.Header.Set("Content-Type", "application/octet-stream")
		res := httptest.NewRecorder()
		h.ServeHTTP(res, req)
		var body map[string]any
		_ = json.NewDecoder(res.Body).Decode(&body)
		return res.Code, body
	}
	code, cloud := compose("safe synthetic summary", "compose-cloud")
	if code != http.StatusAccepted || cloud["route"] != "cloud" || cloud["admission_id"] == nil {
		t.Fatalf("cloud=%d %#v", code, cloud)
	}
	code, local := compose("PD: synthetic personal data", "compose-pd")
	if code != http.StatusAccepted || local["route"] != "local_pd" || local["local_pd_handle"] == nil {
		t.Fatalf("local=%d %#v", code, local)
	}
	if a.CloudCalls != 1 || a.LocalCalls != 1 {
		t.Fatalf("unexpected synthetic calls cloud=%d local=%d", a.CloudCalls, a.LocalCalls)
	}
	code, _ = compose("another safe summary", "compose-cloud")
	if code != http.StatusForbidden {
		t.Fatalf("replay status=%d", code)
	}

	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1/v1/read/health", nil)
	req.RemoteAddr = "127.0.0.1:45001"
	req.Host = host
	req.Header.Set("Origin", origin)
	req.Header.Set("Authorization", "Bearer "+session.Token)
	req.Header.Set("X-UI-Nonce", session.ClientNonce)
	req.Header.Set("X-UI-Request-Nonce", "health")
	res := httptest.NewRecorder()
	h.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("health status=%d", res.Code)
	}
	var health map[string]any
	if err := json.NewDecoder(res.Body).Decode(&health); err != nil {
		t.Fatal(err)
	}
	if health["schema_version"] != dshbridge.ReadModelV1 || health["status"] != "synthetic" {
		t.Fatalf("health=%#v", health)
	}
}

func TestSyntheticClassifierFailClosed(t *testing.T) {
	if _, err := (Classifier{}).Classify(nil); err == nil {
		t.Fatal("empty payload accepted")
	}
	if _, err := (NewAuthority()).AdmitCloud(context.Background(), nil); err == nil {
		t.Fatal("empty payload authority accepted")
	}
}
