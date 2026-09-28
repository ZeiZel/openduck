package server

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"openduck/internal/core"
	"strings"
	"testing"
)

func TestManualUnknownFieldAndLimit(t *testing.T) {
	s := (&Server{Queue: core.NewMemoryQueue(), Mode: "local-only"}).Handler()
	r := httptest.NewRequest(http.MethodPost, "/v1/manual/events", bytes.NewBufferString(`{"id":"e","text":"x","unexpected":1}`))
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != 400 {
		t.Fatalf("code=%d", w.Code)
	}
	r = httptest.NewRequest(http.MethodPost, "/v1/manual/events", bytes.NewBufferString(`{"id":"e","text":"x","classification":"L2","provenance":{"adapter_id":"a","account_id":"acc","schema_version":"1.0","trace_id":"t","source_event_id":"s","channel":"m","conversation_id":"c","sender":"p","timestamp":"1970-01-01T00:00:01Z","ingested_at":"1970-01-01T00:00:01Z","version":1,"digest":"sha256:x","timezone":"UTC"}}`))
	w = httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("code=%d body=%s", w.Code, w.Body)
	}
}
func TestHTTPGuards(t *testing.T) {
	s := (&Server{Queue: core.NewMemoryQueue(), Mode: "local-only"}).Handler()
	for _, method := range []string{http.MethodGet, http.MethodPut} {
		r := httptest.NewRequest(method, "/v1/manual/events", nil)
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		if w.Code != 405 {
			t.Fatalf("method %s=%d", method, w.Code)
		}
	}
	r := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatal(w.Code)
	}
	body := bytes.NewBufferString(`{"id":"e","text":"x","classification":"L2","provenance":{"adapter_id":"a","account_id":"acc","schema_version":"1.0","trace_id":"t","source_event_id":"s","channel":"m","conversation_id":"c","sender":"p","timestamp":"1970-01-01T00:00:01Z","ingested_at":"1970-01-01T00:00:01Z","version":1,"digest":"sha256:x","timezone":"UTC"}} trailing`)
	r = httptest.NewRequest(http.MethodPost, "/v1/manual/events", body)
	w = httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != 400 {
		t.Fatalf("trailing=%d", w.Code)
	}
}

func TestBodyLimit(t *testing.T) {
	s := (&Server{Queue: core.NewMemoryQueue(), Mode: "local-only"}).Handler()
	r := httptest.NewRequest(http.MethodPost, "/v1/manual/events", strings.NewReader(strings.Repeat("x", 70<<10)))
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != 400 {
		t.Fatalf("body limit=%d", w.Code)
	}
}
