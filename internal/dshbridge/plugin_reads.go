package dshbridge

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"sort"
	"strings"
	"time"

	"openduck/internal/beadsview"
	"openduck/internal/workspacegroup"
)

const PluginReadsV1 = "plugin-reads.v1"

var ErrPluginReadUnavailable = errors.New("plugin read unavailable")
var ErrPluginReadInvalid = errors.New("invalid plugin read")

type PluginProjectNode struct {
	ID    string `json:"id"`
	Label string `json:"label"`
	State string `json:"state"`
}
type PluginProjectEdge struct {
	From string `json:"from"`
	To   string `json:"to"`
}
type PluginProjectGraph struct {
	SchemaVersion string              `json:"schema_version"`
	ProjectID     string              `json:"project_id"`
	Version       uint64              `json:"version"`
	Digest        string              `json:"digest"`
	Nodes         []PluginProjectNode `json:"nodes"`
	Edges         []PluginProjectEdge `json:"edges"`
}
type PluginGlobalRecord struct {
	RecordID     string `json:"record_id"`
	Version      uint64 `json:"version"`
	UpdatedAt    string `json:"updated_at"`
	Availability string `json:"availability"`
}
type PluginGlobalMetadata struct {
	SchemaVersion string               `json:"schema_version"`
	Version       uint64               `json:"version"`
	Digest        string               `json:"digest"`
	UpdatedAt     string               `json:"updated_at"`
	Records       []PluginGlobalRecord `json:"records"`
}
type PluginWorkspaceGroup struct {
	SchemaVersion string                          `json:"schema_version"`
	GroupID       string                          `json:"group_id"`
	DisplayLabel  string                          `json:"display_label"`
	PrimaryRootID string                          `json:"primary_root_id"`
	Roots         []workspacegroup.RootProjection `json:"roots"`
	Version       uint64                          `json:"version"`
	Digest        string                          `json:"digest"`
	UpdatedAt     string                          `json:"updated_at"`
}
type PluginWorkspaceGroups struct {
	SchemaVersion string                 `json:"schema_version"`
	Freshness     string                 `json:"freshness"`
	Groups        []PluginWorkspaceGroup `json:"groups"`
}

type PluginReadProvider interface {
	ProjectGraph(context.Context) (PluginProjectGraph, error)
	GlobalMetadata(context.Context) (PluginGlobalMetadata, error)
	WorkspaceGroups(context.Context) (PluginWorkspaceGroups, error)
}

// SafePluginReads adapts the already-redacted provider contracts to the
// narrow DTOs consumed by DSH. It has no mutation, model, or network surface.
type SafePluginReads struct {
	Beads     beadsview.Provider
	Workspace interface {
		ListProjections(context.Context) ([]workspacegroup.SafeProjection, error)
	}
}

func (p SafePluginReads) ProjectGraph(ctx context.Context) (PluginProjectGraph, error) {
	if p.Beads == nil {
		return PluginProjectGraph{}, ErrPluginReadUnavailable
	}
	g, err := p.Beads.Graph(ctx, beadsview.Project)
	if err != nil {
		return PluginProjectGraph{}, err
	}
	if len(g.Nodes) > 200 || len(g.Edges) > 400 {
		return PluginProjectGraph{}, ErrPluginReadInvalid
	}
	out := PluginProjectGraph{SchemaVersion: "beads-project-graph.v1", ProjectID: "project", Version: 1, Nodes: []PluginProjectNode{}, Edges: []PluginProjectEdge{}}
	for _, n := range g.Nodes {
		if !pluginID(n.ID) || !pluginLabel(n.Title) || !pluginState(n.Status) {
			return PluginProjectGraph{}, ErrPluginReadInvalid
		}
		out.Nodes = append(out.Nodes, PluginProjectNode{ID: n.ID, Label: n.Title, State: n.Status})
	}
	for _, e := range g.Edges {
		if !pluginID(e.From) || !pluginID(e.To) {
			return PluginProjectGraph{}, ErrPluginReadInvalid
		}
		out.Edges = append(out.Edges, PluginProjectEdge{From: e.From, To: e.To})
	}
	sort.Slice(out.Nodes, func(i, j int) bool { return out.Nodes[i].ID < out.Nodes[j].ID })
	sort.Slice(out.Edges, func(i, j int) bool {
		if out.Edges[i].From != out.Edges[j].From {
			return out.Edges[i].From < out.Edges[j].From
		}
		return out.Edges[i].To < out.Edges[j].To
	})
	out.Digest = pluginDigest(out)
	if err := out.Validate(); err != nil {
		return PluginProjectGraph{}, err
	}
	return out, nil
}

func (p SafePluginReads) GlobalMetadata(ctx context.Context) (PluginGlobalMetadata, error) {
	if err := ctx.Err(); err != nil {
		return PluginGlobalMetadata{}, err
	}
	// Global memory is deliberately never queried. This static response is the
	// only honest contract while the local-PD authority is unavailable.
	out := PluginGlobalMetadata{SchemaVersion: "beads-global-metadata.v1", Version: 1, UpdatedAt: pluginTime(time.Now()), Records: []PluginGlobalRecord{}}
	out.Digest = pluginDigest(out)
	if err := out.Validate(); err != nil {
		return PluginGlobalMetadata{}, err
	}
	return out, nil
}

func (p SafePluginReads) WorkspaceGroups(ctx context.Context) (PluginWorkspaceGroups, error) {
	if p.Workspace == nil {
		return PluginWorkspaceGroups{}, ErrPluginReadUnavailable
	}
	groups, err := p.Workspace.ListProjections(ctx)
	if err != nil {
		return PluginWorkspaceGroups{}, err
	}
	if len(groups) > 32 {
		return PluginWorkspaceGroups{}, ErrPluginReadInvalid
	}
	out := PluginWorkspaceGroups{SchemaVersion: "workspace-groups.v1", Freshness: "current", Groups: []PluginWorkspaceGroup{}}
	for _, g := range groups {
		if g.SchemaVersion != workspacegroup.SchemaVersion || !pluginID(g.GroupID) || !pluginLabel(g.DisplayLabel) || !pluginID(g.PrimaryRootID) || g.Version == 0 || !pluginDigestText(g.Digest) || g.UpdatedAt.IsZero() || len(g.Roots) == 0 || len(g.Roots) > 32 {
			return PluginWorkspaceGroups{}, ErrPluginReadInvalid
		}
		for _, root := range g.Roots {
			if !pluginID(root.RootID) || !pluginLabel(root.Label) || root.Mode != workspacegroup.ReadMode && root.Mode != workspacegroup.WriteMode {
				return PluginWorkspaceGroups{}, ErrPluginReadInvalid
			}
		}
		out.Groups = append(out.Groups, PluginWorkspaceGroup{SchemaVersion: g.SchemaVersion, GroupID: g.GroupID, DisplayLabel: g.DisplayLabel, PrimaryRootID: g.PrimaryRootID, Roots: append([]workspacegroup.RootProjection(nil), g.Roots...), Version: g.Version, Digest: g.Digest, UpdatedAt: pluginTime(g.UpdatedAt)})
	}
	if err := out.Validate(); err != nil {
		return PluginWorkspaceGroups{}, err
	}
	return out, nil
}

var pluginIDRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$`)
var pluginLabelRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 _.,:;()#-]{0,127}$`)
var pluginTimeRE = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$`)

func pluginID(s string) bool    { return pluginIDRE.MatchString(s) }
func pluginLabel(s string) bool { return pluginLabelRE.MatchString(s) }
func pluginState(s string) bool {
	switch s {
	case "open", "in_progress", "blocked", "closed":
		return true
	}
	return false
}
func pluginDigestText(s string) bool {
	if len(s) != 71 || !strings.HasPrefix(s, "sha256:") {
		return false
	}
	b, err := hex.DecodeString(s[7:])
	return err == nil && len(b) == sha256.Size
}
func pluginTime(t time.Time) string {
	return t.UTC().Truncate(time.Millisecond).Format("2006-01-02T15:04:05.000Z")
}
func (g PluginProjectGraph) Validate() error {
	if g.SchemaVersion != "beads-project-graph.v1" || !pluginID(g.ProjectID) || g.Version == 0 || !pluginDigestText(g.Digest) || len(g.Nodes) > 200 || len(g.Edges) > 400 {
		return ErrPluginReadInvalid
	}
	ids := map[string]bool{}
	for _, n := range g.Nodes {
		if !pluginID(n.ID) || !pluginLabel(n.Label) || !pluginState(n.State) || ids[n.ID] {
			return ErrPluginReadInvalid
		}
		ids[n.ID] = true
	}
	for _, e := range g.Edges {
		if !pluginID(e.From) || !pluginID(e.To) || e.From == e.To || !ids[e.From] || !ids[e.To] {
			return ErrPluginReadInvalid
		}
	}
	return nil
}
func (m PluginGlobalMetadata) Validate() error {
	if m.SchemaVersion != "beads-global-metadata.v1" || m.Version == 0 || !pluginDigestText(m.Digest) || !pluginTimeRE.MatchString(m.UpdatedAt) || len(m.Records) > 100 {
		return ErrPluginReadInvalid
	}
	if len(m.Records) != 0 {
		return ErrPluginReadInvalid
	}
	return nil
}
func (w PluginWorkspaceGroups) Validate() error {
	if w.SchemaVersion != "workspace-groups.v1" || (w.Freshness != "current" && w.Freshness != "stale") || len(w.Groups) > 32 {
		return ErrPluginReadInvalid
	}
	seen := map[string]bool{}
	for _, g := range w.Groups {
		if g.SchemaVersion != workspacegroup.SchemaVersion || !pluginID(g.GroupID) || !pluginLabel(g.DisplayLabel) || !pluginID(g.PrimaryRootID) || g.Version == 0 || !pluginDigestText(g.Digest) || !pluginTimeRE.MatchString(g.UpdatedAt) || len(g.Roots) == 0 || len(g.Roots) > 32 || seen[g.GroupID] {
			return ErrPluginReadInvalid
		}
		seen[g.GroupID] = true
		roots := map[string]bool{}
		for _, r := range g.Roots {
			if !pluginID(r.RootID) || !pluginLabel(r.Label) || (r.Mode != workspacegroup.ReadMode && r.Mode != workspacegroup.WriteMode) || roots[r.RootID] {
				return ErrPluginReadInvalid
			}
			roots[r.RootID] = true
		}
		if !roots[g.PrimaryRootID] {
			return ErrPluginReadInvalid
		}
	}
	return nil
}

func pluginDigest(v any) string {
	b, _ := json.Marshal(v)
	h := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(h[:])
}
