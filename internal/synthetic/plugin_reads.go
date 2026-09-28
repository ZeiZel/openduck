package synthetic

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"

	"openduck/internal/dshbridge"
)

// PluginReads is the explicit provider-free synthetic fixture used only by
// -synthetic command-center composition. It has no beads, filesystem, or PD
// access and returns bounded empty projections.
type PluginReads struct{ now time.Time }

func NewPluginReads(now time.Time) PluginReads { return PluginReads{now: now.UTC()} }
func (p PluginReads) ProjectGraph(context.Context) (dshbridge.PluginProjectGraph, error) {
	g := dshbridge.PluginProjectGraph{SchemaVersion: "beads-project-graph.v1", ProjectID: "project", Version: 1, Nodes: []dshbridge.PluginProjectNode{}, Edges: []dshbridge.PluginProjectEdge{}}
	g.Digest = digestPlugin(g)
	return g, nil
}
func (p PluginReads) GlobalMetadata(context.Context) (dshbridge.PluginGlobalMetadata, error) {
	m := dshbridge.PluginGlobalMetadata{SchemaVersion: "beads-global-metadata.v1", Version: 1, UpdatedAt: p.now.UTC().Format("2006-01-02T15:04:05.000Z"), Records: []dshbridge.PluginGlobalRecord{}}
	m.Digest = digestPlugin(m)
	return m, nil
}
func (p PluginReads) WorkspaceGroups(context.Context) (dshbridge.PluginWorkspaceGroups, error) {
	return dshbridge.PluginWorkspaceGroups{SchemaVersion: "workspace-groups.v1", Freshness: "current", Groups: []dshbridge.PluginWorkspaceGroup{}}, nil
}
func digestPlugin(v any) string {
	b, _ := json.Marshal(v)
	h := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(h[:])
}
