package dshbridgehttp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"openduck/internal/dshbridge"
)

type pluginReadFixture struct{}

func (pluginReadFixture) ProjectGraph(context.Context) (dshbridge.PluginProjectGraph, error) {
	return dshbridge.PluginProjectGraph{SchemaVersion: "beads-project-graph.v1", ProjectID: "project", Version: 1, Digest: "sha256:0000000000000000000000000000000000000000000000000000000000000000", Nodes: []dshbridge.PluginProjectNode{{ID: "n1", Label: "First", State: "open"}, {ID: "n2", Label: "Second", State: "closed"}}, Edges: []dshbridge.PluginProjectEdge{{From: "n1", To: "n2"}}}, nil
}
func (pluginReadFixture) GlobalMetadata(context.Context) (dshbridge.PluginGlobalMetadata, error) {
	return dshbridge.PluginGlobalMetadata{SchemaVersion: "beads-global-metadata.v1", Version: 1, Digest: "sha256:0000000000000000000000000000000000000000000000000000000000000000", UpdatedAt: "2026-08-20T00:00:00.000Z", Records: []dshbridge.PluginGlobalRecord{}}, nil
}
func (pluginReadFixture) WorkspaceGroups(context.Context) (dshbridge.PluginWorkspaceGroups, error) {
	return dshbridge.PluginWorkspaceGroups{SchemaVersion: "workspace-groups.v1", Freshness: "current", Groups: []dshbridge.PluginWorkspaceGroup{}}, nil
}

func TestPluginReadRoutesRequireSessionAndUseExactPaths(t *testing.T) {
	store, err := dshbridge.NewSessionStore(dshbridge.Config{Origin: "http://127.0.0.1:3000", Host: "127.0.0.1:8788"})
	if err != nil {
		t.Fatal(err)
	}
	session, err := store.Issue("plugin-client")
	if err != nil {
		t.Fatal(err)
	}
	s := (&Server{Bridge: &dshbridge.Bridge{Sessions: store}, Origin: session.Origin, Host: session.Host, PluginReads: pluginReadFixture{}})
	unauth := httptest.NewRequest(http.MethodGet, "/v1/plugin-reads/beads/project-graph", nil)
	unauth.RemoteAddr = "127.0.0.1:1"
	unauth.Host = session.Host
	unauth.Header.Set("Origin", session.Origin)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, unauth)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("unauthorized=%d", w.Code)
	}
	r := httptest.NewRequest(http.MethodGet, "/v1/plugin-reads/beads/project-graph", nil)
	r.RemoteAddr = "127.0.0.1:1"
	r.Host = session.Host
	r.Header.Set("Origin", session.Origin)
	r.Header.Set("Authorization", "Bearer "+session.Token)
	r.Header.Set("X-UI-Nonce", session.ClientNonce)
	r.Header.Set("X-UI-Request-Nonce", "plugin-read-1")
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("read=%d %s", w.Code, w.Body.String())
	}
	r = httptest.NewRequest(http.MethodGet, "/v1/plugin-reads/beads/project-graph/extra", nil)
	r.RemoteAddr = "127.0.0.1:1"
	r.Host = session.Host
	r.Header.Set("Origin", session.Origin)
	r.Header.Set("Authorization", "Bearer "+session.Token)
	r.Header.Set("X-UI-Nonce", session.ClientNonce)
	r.Header.Set("X-UI-Request-Nonce", "plugin-read-2")
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusNotFound {
		t.Fatalf("non-exact=%d", w.Code)
	}
	for i, path := range []string{"/v1/plugin-reads/beads/project-graph", "/v1/plugin-reads/beads/global-metadata", "/v1/plugin-reads/workspace-groups"} {
		r = httptest.NewRequest(http.MethodGet, path, nil)
		r.RemoteAddr = "127.0.0.1:1"
		r.Host = session.Host
		r.Header.Set("Origin", session.Origin)
		r.Header.Set("Authorization", "Bearer "+session.Token)
		r.Header.Set("X-UI-Nonce", session.ClientNonce)
		r.Header.Set("X-UI-Request-Nonce", "plugin-read-all-"+string(rune('a'+i)))
		w = httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code != http.StatusOK {
			t.Fatalf("route %s=%d", path, w.Code)
		}
		if path == "/v1/plugin-reads/beads/project-graph" && !strings.Contains(w.Body.String(), `"id":"n1"`) {
			t.Fatalf("graph body=%s", w.Body.String())
		}
	}
	r = httptest.NewRequest(http.MethodGet, "/v1/plugin-reads/workspace-groups?unexpected=1", nil)
	r.RemoteAddr = "127.0.0.1:1"
	r.Host = session.Host
	r.Header.Set("Origin", session.Origin)
	r.Header.Set("Authorization", "Bearer "+session.Token)
	r.Header.Set("X-UI-Nonce", session.ClientNonce)
	r.Header.Set("X-UI-Request-Nonce", "plugin-query")
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("query=%d", w.Code)
	}
	r = httptest.NewRequest(http.MethodGet, "/v1/plugin-reads/workspace-groups", strings.NewReader("x"))
	r.RemoteAddr = "127.0.0.1:1"
	r.Host = session.Host
	r.Header.Set("Origin", session.Origin)
	r.Header.Set("Authorization", "Bearer "+session.Token)
	r.Header.Set("X-UI-Nonce", session.ClientNonce)
	r.Header.Set("X-UI-Request-Nonce", "plugin-body")
	r.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("body=%d", w.Code)
	}
	r = httptest.NewRequest(http.MethodOptions, "/v1/plugin-reads/unknown", nil)
	r.RemoteAddr = "127.0.0.1:1"
	r.Host = session.Host
	r.Header.Set("Origin", session.Origin)
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("options path=%d", w.Code)
	}
	r = httptest.NewRequest(http.MethodOptions, "/v1/plugin-reads/workspace-groups?x=1", nil)
	r.RemoteAddr = "127.0.0.1:1"
	r.Host = session.Host
	r.Header.Set("Origin", session.Origin)
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("options query=%d", w.Code)
	}
}

type failingPluginReads struct{}

func (failingPluginReads) ProjectGraph(context.Context) (dshbridge.PluginProjectGraph, error) {
	return dshbridge.PluginProjectGraph{}, context.DeadlineExceeded
}
func (failingPluginReads) GlobalMetadata(context.Context) (dshbridge.PluginGlobalMetadata, error) {
	return dshbridge.PluginGlobalMetadata{}, context.DeadlineExceeded
}
func (failingPluginReads) WorkspaceGroups(context.Context) (dshbridge.PluginWorkspaceGroups, error) {
	return dshbridge.PluginWorkspaceGroups{}, context.DeadlineExceeded
}
