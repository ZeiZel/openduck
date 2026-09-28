package dshbridge

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"openduck/internal/beadsview"
	"openduck/internal/workspacegroup"
)

type pluginBeads struct{}

func (pluginBeads) Scopes(context.Context) ([]beadsview.Scope, error) { return nil, nil }
func (pluginBeads) Graph(context.Context, beadsview.Namespace) (beadsview.Graph, error) {
	return beadsview.Graph{Nodes: []beadsview.GraphNode{{ID: "project:one", Title: "One", Status: "open"}}, Edges: []beadsview.GraphEdge{}}, nil
}
func (pluginBeads) Search(context.Context, beadsview.Namespace, string) ([]beadsview.SearchResult, error) {
	return nil, nil
}
func (pluginBeads) MemoryChats(context.Context, beadsview.Namespace) ([]beadsview.MemoryChatMetadata, error) {
	return []beadsview.MemoryChatMetadata{{ID: "private:one", UpdatedAt: time.Unix(1, 0).UTC()}}, nil
}

type pluginWorkspace struct{}

func (pluginWorkspace) ListProjections(context.Context) ([]workspacegroup.SafeProjection, error) {
	return []workspacegroup.SafeProjection{{SchemaVersion: workspacegroup.SchemaVersion, GroupID: "g", DisplayLabel: "G", PrimaryRootID: "r", Roots: []workspacegroup.RootProjection{{RootID: "r", Label: "R", Mode: workspacegroup.ReadMode}}, Version: 1, Digest: "sha256:" + strings.Repeat("0", 64), UpdatedAt: time.Unix(1, 0).UTC()}}, nil
}

func TestSafePluginReadsAreRedactedAndBounded(t *testing.T) {
	p := SafePluginReads{Beads: pluginBeads{}, Workspace: pluginWorkspace{}}
	g, err := p.ProjectGraph(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if g.SchemaVersion != "beads-project-graph.v1" || g.Digest == "" || g.Nodes[0].Label != "One" {
		t.Fatalf("graph=%+v", g)
	}
	m, err := p.GlobalMetadata(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Records) != 0 || m.SchemaVersion != "beads-global-metadata.v1" {
		t.Fatalf("metadata=%+v", m)
	}
	w, err := p.WorkspaceGroups(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(w)
	if len(w.Groups) != 1 || strings.Contains(string(b), "capability") {
		t.Fatalf("workspace leaked capability=%s", b)
	}
}
