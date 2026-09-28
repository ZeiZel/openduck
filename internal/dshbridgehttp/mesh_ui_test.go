package dshbridgehttp

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"openduck/internal/dshbridge"
	"openduck/internal/meshui"
)

type invalidMeshUIOutputInvoker struct{}

func (invalidMeshUIOutputInvoker) InvokeMeshUI(context.Context, string, any) (meshui.MeshUIResponse, error) {
	return meshui.MeshUIResponse{
		SchemaVersion: meshui.ResponseSchema,
		Kind:          "selection-revision",
		Selection:     &meshui.SelectionOutput{RevisionID: "secret-token", ActiveTurnChanged: false},
	}, nil
}

func TestMeshUIUsesExistingUIChannelSession(t *testing.T) {
	store, err := dshbridge.NewSessionStore(dshbridge.Config{Origin: "http://127.0.0.1:3000", Host: "127.0.0.1:8788"})
	if err != nil {
		t.Fatal(err)
	}
	session, err := store.Issue("shared-mesh")
	if err != nil {
		t.Fatal(err)
	}
	h := (&Server{Bridge: &dshbridge.Bridge{Sessions: store}, Origin: session.Origin, Host: session.Host, MeshUI: meshui.NewProjectionService(nil)}).Handler()
	r := httptest.NewRequest(http.MethodGet, "/v1/plugin-reads/mesh", nil)
	r.RemoteAddr = "127.0.0.1:1"
	r.Host = session.Host
	r.Header.Set("Origin", session.Origin)
	r.Header.Set("Authorization", "Bearer "+session.Token)
	r.Header.Set("X-UI-Nonce", session.ClientNonce)
	r.Header.Set("X-UI-Request-Nonce", "mesh-read")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("mesh=%d %s", w.Code, w.Body.String())
	}
	selection := httptest.NewRequest(http.MethodPost, "/v1/plugin-proposals/selection-revision", bytes.NewBufferString(`{"profile_id":"deepseek.api","operation":"new-root","base_revision_id":"mesh-disabled"}`))
	selection.RemoteAddr = "127.0.0.1:1"
	selection.Host = session.Host
	selection.Header.Set("Origin", session.Origin)
	selection.Header.Set("Authorization", "Bearer "+session.Token)
	selection.Header.Set("X-UI-Nonce", session.ClientNonce)
	selection.Header.Set("X-UI-Request-Nonce", "mesh-selection")
	selection.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, selection)
	if w.Code != http.StatusConflict || !bytes.Contains(w.Body.Bytes(), []byte(`"error_code":"MESH_UNAVAILABLE"`)) {
		t.Fatalf("selection=%d %s", w.Code, w.Body.String())
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized && w.Code != http.StatusForbidden {
		t.Fatalf("replay=%d", w.Code)
	}
	r.Header.Set("Origin", "http://127.0.0.1:9999")
	r.Header.Set("X-UI-Request-Nonce", "cross-origin")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("origin=%d", w.Code)
	}
	options := httptest.NewRequest(http.MethodOptions, "/v1/plugin-reads/mesh", nil)
	options.RemoteAddr = "127.0.0.1:1"
	options.Host = session.Host
	options.Header.Set("Origin", session.Origin)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, options)
	if w.Code != http.StatusNoContent || w.Header().Get("Access-Control-Allow-Methods") != "GET, OPTIONS" {
		t.Fatalf("options=%d %v", w.Code, w.Header())
	}
	unknown := httptest.NewRequest(http.MethodPost, "/v1/plugin-proposals/unknown", nil)
	unknown.RemoteAddr = "127.0.0.1:1"
	unknown.Host = session.Host
	unknown.Header.Set("Origin", session.Origin)
	unknown.Header.Set("Authorization", "Bearer "+session.Token)
	unknown.Header.Set("X-UI-Nonce", session.ClientNonce)
	unknown.Header.Set("X-UI-Request-Nonce", "unknown")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, unknown)
	if w.Code != http.StatusNotFound {
		t.Fatalf("unknown=%d", w.Code)
	}
}

func TestMeshUIInvalidInvokerOutputIsGenericBadGateway(t *testing.T) {
	store, err := dshbridge.NewSessionStore(dshbridge.Config{Origin: "http://127.0.0.1:3000", Host: "127.0.0.1:8788"})
	if err != nil {
		t.Fatal(err)
	}
	session, err := store.Issue("invalid-mesh-output")
	if err != nil {
		t.Fatal(err)
	}
	h := (&Server{Bridge: &dshbridge.Bridge{Sessions: store}, Origin: session.Origin, Host: session.Host, MeshUI: meshui.NewProjectionService(invalidMeshUIOutputInvoker{})}).Handler()
	r := httptest.NewRequest(http.MethodPost, "/v1/plugin-proposals/selection-revision", bytes.NewBufferString(`{"profile_id":"deepseek.api","operation":"new-root","base_revision_id":"mesh-disabled"}`))
	r.RemoteAddr = "127.0.0.1:1"
	r.Host = session.Host
	r.Header.Set("Origin", session.Origin)
	r.Header.Set("Authorization", "Bearer "+session.Token)
	r.Header.Set("X-UI-Nonce", session.ClientNonce)
	r.Header.Set("X-UI-Request-Nonce", "invalid-output")
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusBadGateway || bytes.Contains(w.Body.Bytes(), []byte("secret-token")) || !bytes.Contains(w.Body.Bytes(), []byte(`"error_code":"MESH_UNAVAILABLE"`)) {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if w.Header().Get("Access-Control-Allow-Origin") != session.Origin || w.Header().Get("X-Content-Type-Options") != "nosniff" || w.Header().Get("Content-Security-Policy") != "default-src 'none'; frame-ancestors 'none'" {
		t.Fatalf("headers=%v", w.Header())
	}
}
