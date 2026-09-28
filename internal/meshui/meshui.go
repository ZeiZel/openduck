// Package meshui owns redacted mesh UI DTOs only. Authentication and HTTP are
// deliberately owned by dshbridgehttp's single Controller UI session channel.
package meshui

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"sort"
	"strings"
	"time"

	"openduck/internal/mesh"
	"openduck/internal/providerbridge"
)

const (
	ProjectionSchema = "openduck-mesh-ui.v1"
	ResponseSchema   = "mesh-ui-response.v1"
	ErrorSchema      = "mesh-ui-error.v1"

	maxItems = 64
	// Keep the model-facing JSON boundary no wider than the Coordinator's
	// authoritative ProposeSpawnBatch contract (16). A wider UI allowance
	// would marshal requests the Controller must reject after routing them.
	maxBatchItems  = 16
	maxOutputBytes = 64 << 10
	maxSafeInteger = uint64(9007199254740991)
	maxJSONDepth   = 16
)

var (
	ErrInvalid       = errors.New("invalid mesh ui request")
	ErrUnavailable   = errors.New("mesh execution unavailable")
	ErrInvalidOutput = errors.New("invalid mesh ui output")
)

// EndpointInvoker is composed by the Controller only after it has
// authenticated a real mesh endpoint binding. UI requests cannot carry or mint
// endpoint fields. Its only possible successful output is MeshUIResponse.
type EndpointInvoker interface {
	InvokeMeshUI(context.Context, string, any) (MeshUIResponse, error)
}

// ProjectionSource is a deliberately narrow read seam. It is the only way a
// composed Controller may project a non-static mesh revision or verified,
// bounded metadata; this package is never a lifecycle or revision authority.
type ProjectionSource interface {
	MeshUIProjection(context.Context) (ProjectionSnapshot, error)
}

// ProjectionSnapshot accepts only closed, redacted DTOs. A nil field retains
// the static disabled projection. Nil Package means package metadata is not
// known and is rendered as absent, never as a fabricated digest.
type ProjectionSnapshot struct {
	RevisionID string
	// ProviderDirectory is produced only by providerbridge.Registry.Directory.
	// Its unexported payload prevents a Controller/UI caller from inventing a
	// verified spawn bit or evidence freshness.
	ProviderDirectory providerbridge.DirectorySnapshot
	Package           *PackageSnapshot
	Graph             *Graph
	Compare           *Comparison
	Diagnostics       *Diagnostics
	Policy            *Policy
	Templates         *Templates
	Lifecycle         *Lifecycle
	// Unavailable names closed UI operations for which this authoritative
	// snapshot has no signed source or exact receipt. They remain visible to a
	// client as explicitly unavailable rather than being presented as actions
	// that will fail only after submission.
	Unavailable []string
}

type PackageSnapshot struct {
	PackageID string
	Digest    string
	Status    string
}

type Service struct {
	invoker EndpointInvoker
	source  ProjectionSource
}

func NewProjectionService(invoker EndpointInvoker) *Service {
	return NewProjectionServiceWithSource(invoker, nil)
}

func NewProjectionServiceWithSource(invoker EndpointInvoker, source ProjectionSource) *Service {
	return &Service{invoker: invoker, source: source}
}

// Profile is intentionally directory metadata only. It carries no account,
// credential, provider handle, endpoint, or evidence body.
type Profile struct {
	ProfileID string `json:"profile_id"`
	Provider  string `json:"provider"`
	Model     string `json:"model"`
	Status    string `json:"status"`
	MeshSpawn bool   `json:"mesh_spawn"`
	LocalOnly bool   `json:"local_only"`
}

type GraphNode struct {
	ID        string `json:"id"`
	Status    string `json:"status"`
	Provider  string `json:"provider"`
	ProfileID string `json:"profile_id"`
}
type GraphEdge struct {
	From string `json:"from"`
	To   string `json:"to"`
	Type string `json:"type"`
}
type Graph struct {
	Nodes []GraphNode `json:"nodes"`
	Edges []GraphEdge `json:"edges"`
}

type CompareRun struct {
	Provider        string  `json:"provider"`
	ProfileID       string  `json:"profile_id"`
	Status          string  `json:"status"`
	ResultAvailable bool    `json:"result_available"`
	ResultRef       *string `json:"result_ref,omitempty"`
}
type Comparison struct {
	Runs []CompareRun `json:"runs"`
}

type ProviderDiagnostic struct {
	ProfileID string `json:"profile_id"`
	Status    string `json:"status"`
	Freshness string `json:"freshness"`
}
type Diagnostics struct {
	Providers []ProviderDiagnostic `json:"providers"`
}

type PolicyApproval struct {
	DecisionType string `json:"decision_type"`
	Status       string `json:"status"`
	ExpiresAt    string `json:"expires_at"`
}
type Policy struct {
	Approvals []PolicyApproval `json:"approvals"`
}

type Template struct {
	TemplateID string `json:"template_id"`
	Version    string `json:"version"`
}
type Templates struct {
	Approved []Template `json:"approved"`
}

type Package struct {
	PackageID string `json:"package_id"`
	Digest    string `json:"digest"`
	Status    string `json:"status"`
}
type Lifecycle struct {
	Packages []Package `json:"packages"`
}

// Projection contains no generic map or arbitrary payload. Every nested value
// has an exact wire shape and is validated before it reaches HTTP.
type Projection struct {
	SchemaVersion string      `json:"schema_version"`
	RevisionID    string      `json:"revision_id"`
	Profiles      []Profile   `json:"profiles"`
	Graph         Graph       `json:"graph"`
	Compare       Comparison  `json:"compare"`
	Diagnostics   Diagnostics `json:"diagnostics"`
	Policy        Policy      `json:"policy"`
	Templates     Templates   `json:"templates"`
	Lifecycle     Lifecycle   `json:"lifecycle"`
	Unavailable   []string    `json:"unavailable"`
}

// Projection is an honest disabled projection until the Controller injects a
// durable snapshot. All declared profiles remain unavailable for mesh spawn;
// no provider freshness or package digest is inferred locally.
func (s *Service) Projection(ctx context.Context) Projection {
	p := disabledProjection()
	if s.source == nil {
		return p
	}
	snapshot, err := s.source.MeshUIProjection(ctx)
	if err != nil {
		return p
	}
	if projected, ok := projectSnapshot(p, snapshot); ok {
		return projected
	}
	return p
}

func disabledProjection() Projection {
	p := Projection{
		SchemaVersion: ProjectionSchema,
		RevisionID:    "mesh-disabled",
		Profiles:      make([]Profile, 0, len(providerbridge.DeclaredProfiles())),
		Graph:         Graph{Nodes: []GraphNode{}, Edges: []GraphEdge{}},
		Compare:       Comparison{Runs: []CompareRun{}},
		Diagnostics:   Diagnostics{Providers: []ProviderDiagnostic{}},
		Policy:        Policy{Approvals: []PolicyApproval{}},
		Templates:     Templates{Approved: []Template{}},
		Lifecycle:     Lifecycle{Packages: []Package{}},
		Unavailable:   []string{"deployment-diagnostics", "plugin-lifecycle", "run-synthesis"},
	}
	for _, x := range providerbridge.DeclaredProfiles() {
		p.Profiles = append(p.Profiles, Profile{ProfileID: x.ID, Provider: string(x.Provider), Model: x.Model, Status: "disabled", MeshSpawn: false, LocalOnly: x.LocalOnly})
		p.Diagnostics.Providers = append(p.Diagnostics.Providers, ProviderDiagnostic{ProfileID: x.ID, Status: "disabled", Freshness: "unknown"})
	}
	sort.Slice(p.Profiles, func(i, j int) bool { return p.Profiles[i].ProfileID < p.Profiles[j].ProfileID })
	sort.Slice(p.Diagnostics.Providers, func(i, j int) bool {
		return p.Diagnostics.Providers[i].ProfileID < p.Diagnostics.Providers[j].ProfileID
	})
	return p
}

func projectSnapshot(base Projection, snapshot ProjectionSnapshot) (Projection, bool) {
	if !id(snapshot.RevisionID) || (snapshot.Package != nil && snapshot.Lifecycle != nil) {
		return Projection{}, false
	}
	p := base
	p.RevisionID = snapshot.RevisionID
	if !overlayProviderDirectory(&p, snapshot.ProviderDirectory) {
		return Projection{}, false
	}
	eligible := anyMeshEligible(p.Profiles)
	if snapshot.Package != nil {
		if snapshot.Package.Status == "enabled" && !eligible {
			return Projection{}, false
		}
		p.Lifecycle = Lifecycle{Packages: []Package{{PackageID: snapshot.Package.PackageID, Digest: snapshot.Package.Digest, Status: snapshot.Package.Status}}}
	}
	if snapshot.Graph != nil {
		p.Graph = cloneGraph(*snapshot.Graph)
	}
	if snapshot.Compare != nil {
		p.Compare = cloneComparison(*snapshot.Compare)
	}
	if snapshot.Diagnostics != nil {
		p.Diagnostics = cloneDiagnostics(*snapshot.Diagnostics)
	}
	if snapshot.Policy != nil {
		p.Policy = clonePolicy(*snapshot.Policy)
	}
	if snapshot.Templates != nil {
		p.Templates = cloneTemplates(*snapshot.Templates)
	}
	if snapshot.Lifecycle != nil {
		if lifecycleClaimsEnabled(*snapshot.Lifecycle) && !eligible {
			return Projection{}, false
		}
		p.Lifecycle = cloneLifecycle(*snapshot.Lifecycle)
	}
	if snapshot.Unavailable != nil {
		p.Unavailable = append([]string(nil), snapshot.Unavailable...)
	}
	return p, p.Validate() == nil
}

func overlayProviderDirectory(projection *Projection, directory providerbridge.DirectorySnapshot) bool {
	entries := directory.Profiles()
	if len(entries) == 0 {
		return true
	}
	profiles := make(map[string]Profile, len(projection.Profiles))
	diagnostics := make(map[string]ProviderDiagnostic, len(projection.Diagnostics.Providers))
	for _, profile := range projection.Profiles {
		profiles[profile.ProfileID] = profile
	}
	for _, diagnostic := range projection.Diagnostics.Providers {
		diagnostics[diagnostic.ProfileID] = diagnostic
	}
	for _, entry := range entries {
		profile, found := profiles[entry.ProfileID]
		if !found || string(entry.Provider) != profile.Provider || entry.Model != profile.Model || entry.LocalOnly != profile.LocalOnly || !profileStatus(string(entry.Status)) || !freshness(string(entry.Freshness)) {
			return false
		}
		// Registry derives this from successful Resolve. Keep the independent
		// compatible check here as an egress invariant as well.
		if entry.MeshSpawn && entry.Status != providerbridge.StatusCompatible {
			return false
		}
		profile.Status = string(entry.Status)
		profile.MeshSpawn = entry.MeshSpawn
		profiles[entry.ProfileID] = profile
		diagnostics[entry.ProfileID] = ProviderDiagnostic{ProfileID: entry.ProfileID, Status: string(entry.Status), Freshness: string(entry.Freshness)}
	}
	projection.Profiles = projection.Profiles[:0]
	projection.Diagnostics.Providers = projection.Diagnostics.Providers[:0]
	for _, declared := range providerbridge.DeclaredProfiles() {
		projection.Profiles = append(projection.Profiles, profiles[declared.ID])
		projection.Diagnostics.Providers = append(projection.Diagnostics.Providers, diagnostics[declared.ID])
	}
	return true
}

func anyMeshEligible(profiles []Profile) bool {
	for _, profile := range profiles {
		if profile.Status == string(providerbridge.StatusCompatible) && profile.MeshSpawn {
			return true
		}
	}
	return false
}

func lifecycleClaimsEnabled(lifecycle Lifecycle) bool {
	for _, pkg := range lifecycle.Packages {
		if pkg.Status == "enabled" {
			return true
		}
	}
	return false
}

func cloneGraph(v Graph) Graph {
	var nodes []GraphNode
	var edges []GraphEdge
	if v.Nodes != nil {
		nodes = make([]GraphNode, len(v.Nodes))
		copy(nodes, v.Nodes)
	}
	if v.Edges != nil {
		edges = make([]GraphEdge, len(v.Edges))
		copy(edges, v.Edges)
	}
	return Graph{Nodes: nodes, Edges: edges}
}
func cloneComparison(v Comparison) Comparison {
	var runs []CompareRun
	if v.Runs != nil {
		runs = make([]CompareRun, len(v.Runs))
		copy(runs, v.Runs)
	}
	out := Comparison{Runs: runs}
	for i := range out.Runs {
		if out.Runs[i].ResultRef != nil {
			ref := *out.Runs[i].ResultRef
			out.Runs[i].ResultRef = &ref
		}
	}
	return out
}
func cloneDiagnostics(v Diagnostics) Diagnostics {
	var providers []ProviderDiagnostic
	if v.Providers != nil {
		providers = make([]ProviderDiagnostic, len(v.Providers))
		copy(providers, v.Providers)
	}
	return Diagnostics{Providers: providers}
}
func clonePolicy(v Policy) Policy {
	var approvals []PolicyApproval
	if v.Approvals != nil {
		approvals = make([]PolicyApproval, len(v.Approvals))
		copy(approvals, v.Approvals)
	}
	return Policy{Approvals: approvals}
}
func cloneTemplates(v Templates) Templates {
	var approved []Template
	if v.Approved != nil {
		approved = make([]Template, len(v.Approved))
		copy(approved, v.Approved)
	}
	return Templates{Approved: approved}
}
func cloneLifecycle(v Lifecycle) Lifecycle {
	var packages []Package
	if v.Packages != nil {
		packages = make([]Package, len(v.Packages))
		copy(packages, v.Packages)
	}
	return Lifecycle{Packages: packages}
}

// Validate verifies every field that can be emitted through the UI read route.
func (p Projection) Validate() error {
	if p.SchemaVersion != ProjectionSchema || !id(p.RevisionID) || !validProfiles(p.Profiles) || !p.Graph.valid() || !p.Compare.valid() || !p.Diagnostics.valid() || !p.Policy.valid() || !p.Templates.valid() || !p.Lifecycle.valid() || !unavailableOperations(p.Unavailable) || !withinProjectionBudget(p) {
		return ErrInvalidOutput
	}
	return nil
}

func unavailableOperations(values []string) bool {
	if values == nil || len(values) > maxItems {
		return false
	}
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if value != "run-synthesis" && value != "deployment-diagnostics" && value != "plugin-lifecycle" {
			return false
		}
		if _, exists := seen[value]; exists {
			return false
		}
		seen[value] = struct{}{}
	}
	return true
}
func withinProjectionBudget(v Projection) bool {
	b, err := json.Marshal(v)
	return err == nil && len(b) <= maxOutputBytes
}

var (
	idRE     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$`)
	digestRE = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
)

func id(v string) bool {
	return idRE.MatchString(v) && !secretShaped(v)
}
func digest(v string) bool { return digestRE.MatchString(v) }
func secretShaped(v string) bool {
	v = strings.ToLower(v)
	for _, marker := range []string{"secret", "password", "passwd", "bearer", "authorization", "credential", "api_key", "apikey", "private_key", "access_key", "session_token", "oauth", "token"} {
		if strings.Contains(v, marker) {
			return true
		}
	}
	return false
}

func profileStatus(v string) bool {
	return v == "disabled" || v == "configured" || v == "auth_required" || v == "ready" || v == "degraded" || v == "compatible" || v == "incompatible"
}
func freshness(v string) bool { return v == "current" || v == "stale" || v == "unknown" }
func runStatus(v string) bool {
	return v == "queued" || v == "proposed" || v == "admitted" || v == "starting" || v == "running" || v == "partial" || v == "completed" || v == "failed" || v == "cancelled" || v == "uncertain"
}
func lifecycleStatus(v string) bool {
	return v == "disabled" || v == "planned" || v == "enabled" || v == "rolled_back" || v == "incompatible" || v == "revoked"
}
func declaredProfile(v string) bool {
	for _, p := range providerbridge.DeclaredProfiles() {
		if p.ID == v {
			return true
		}
	}
	return false
}
func providerForProfile(provider, profileID string) bool {
	for _, p := range providerbridge.DeclaredProfiles() {
		if p.ID == profileID {
			return string(p.Provider) == provider
		}
	}
	return false
}
func validProfiles(values []Profile) bool {
	declared := providerbridge.DeclaredProfiles()
	if len(values) != len(declared) || len(values) > maxItems {
		return false
	}
	return validProfileSet(values, true)
}
func validProfileSubset(values []Profile) bool {
	if values == nil || len(values) > len(providerbridge.DeclaredProfiles()) || len(values) > maxItems {
		return false
	}
	return validProfileSet(values, false)
}
func validProfileSet(values []Profile, requireAll bool) bool {
	declared := providerbridge.DeclaredProfiles()
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if !id(value.ProfileID) || !providerForProfile(value.Provider, value.ProfileID) || !id(value.Model) || !profileStatus(value.Status) {
			return false
		}
		if value.MeshSpawn && value.Status != "compatible" {
			return false
		}
		for _, p := range declared {
			if p.ID == value.ProfileID && (p.Model != value.Model || p.LocalOnly != value.LocalOnly) {
				return false
			}
		}
		if _, exists := seen[value.ProfileID]; exists {
			return false
		}
		seen[value.ProfileID] = struct{}{}
	}
	return !requireAll || len(seen) == len(declared)
}

func (g Graph) valid() bool {
	if g.Nodes == nil || g.Edges == nil || len(g.Nodes) > maxItems || len(g.Edges) > maxItems {
		return false
	}
	nodes := make(map[string]struct{}, len(g.Nodes))
	for _, node := range g.Nodes {
		if !id(node.ID) || !runStatus(node.Status) || !providerForProfile(node.Provider, node.ProfileID) {
			return false
		}
		if _, exists := nodes[node.ID]; exists {
			return false
		}
		nodes[node.ID] = struct{}{}
	}
	seenEdges := make(map[string]struct{}, len(g.Edges))
	for _, edge := range g.Edges {
		if !id(edge.From) || !id(edge.To) || edge.From == edge.To || (edge.Type != "spawn" && edge.Type != "send" && edge.Type != "steer" && edge.Type != "synthesis") {
			return false
		}
		if _, ok := nodes[edge.From]; !ok {
			return false
		}
		if _, ok := nodes[edge.To]; !ok {
			return false
		}
		key := edge.From + "\x00" + edge.To + "\x00" + edge.Type
		if _, exists := seenEdges[key]; exists {
			return false
		}
		seenEdges[key] = struct{}{}
	}
	return true
}
func (v Comparison) valid() bool {
	if v.Runs == nil || len(v.Runs) > maxItems {
		return false
	}
	seen := make(map[string]struct{}, len(v.Runs))
	for _, run := range v.Runs {
		if !providerForProfile(run.Provider, run.ProfileID) || !runStatus(run.Status) || (run.ResultAvailable && (run.ResultRef == nil || !id(*run.ResultRef))) || (!run.ResultAvailable && run.ResultRef != nil) {
			return false
		}
		key := run.ProfileID + "\x00" + run.Status
		if run.ResultRef != nil {
			key += "\x00" + *run.ResultRef
		}
		if _, exists := seen[key]; exists {
			return false
		}
		seen[key] = struct{}{}
	}
	return true
}
func (v Diagnostics) valid() bool {
	if v.Providers == nil || len(v.Providers) > maxItems {
		return false
	}
	seen := make(map[string]struct{}, len(v.Providers))
	for _, entry := range v.Providers {
		if !declaredProfile(entry.ProfileID) || !profileStatus(entry.Status) || !freshness(entry.Freshness) {
			return false
		}
		if _, exists := seen[entry.ProfileID]; exists {
			return false
		}
		seen[entry.ProfileID] = struct{}{}
	}
	return true
}
func (v Policy) valid() bool {
	if v.Approvals == nil || len(v.Approvals) > maxItems {
		return false
	}
	seen := make(map[string]struct{}, len(v.Approvals))
	for _, entry := range v.Approvals {
		if (entry.DecisionType != "provider-switch" && entry.DecisionType != "fanout-grant" && entry.DecisionType != "cloud-disclosure" && entry.DecisionType != "plugin-lifecycle" && entry.DecisionType != "deployment") || (entry.Status != "pending" && entry.Status != "approved" && entry.Status != "denied" && entry.Status != "revoked" && entry.Status != "expired") || !canonicalTimestamp(entry.ExpiresAt) {
			return false
		}
		key := entry.DecisionType + "\x00" + entry.Status + "\x00" + entry.ExpiresAt
		if _, exists := seen[key]; exists {
			return false
		}
		seen[key] = struct{}{}
	}
	return true
}
func (v Templates) valid() bool {
	if v.Approved == nil || len(v.Approved) > maxItems {
		return false
	}
	seen := make(map[string]struct{}, len(v.Approved))
	for _, entry := range v.Approved {
		if !id(entry.TemplateID) || !id(entry.Version) {
			return false
		}
		key := entry.TemplateID + "\x00" + entry.Version
		if _, exists := seen[key]; exists {
			return false
		}
		seen[key] = struct{}{}
	}
	return true
}
func (v Lifecycle) valid() bool {
	if v.Packages == nil || len(v.Packages) > maxItems {
		return false
	}
	seen := make(map[string]struct{}, len(v.Packages))
	for _, entry := range v.Packages {
		if !id(entry.PackageID) || !digest(entry.Digest) || !lifecycleStatus(entry.Status) {
			return false
		}
		if _, exists := seen[entry.PackageID]; exists {
			return false
		}
		seen[entry.PackageID] = struct{}{}
	}
	return true
}

// MeshUIResponse is the sole successful proposal output. The Kind discriminator
// and exactly one typed payload make cross-kind substitution impossible.
type MeshUIResponse struct {
	SchemaVersion string `json:"schema_version"`
	Kind          string `json:"kind"`

	Selection       *SelectionOutput       `json:"selection,omitempty"`
	Spawn           *SpawnOutput           `json:"spawn,omitempty"`
	SpawnBatch      *SpawnBatchOutput      `json:"spawn_batch,omitempty"`
	Send            *AcknowledgementOutput `json:"send,omitempty"`
	Steer           *AcknowledgementOutput `json:"steer,omitempty"`
	Wait            *SessionStatusOutput   `json:"wait,omitempty"`
	Collect         *ResultEnvelopeOutput  `json:"collect,omitempty"`
	Cancel          *AcknowledgementOutput `json:"cancel,omitempty"`
	List            *ListOutput            `json:"list,omitempty"`
	Status          *SessionStatusOutput   `json:"status,omitempty"`
	Result          *ResultEnvelopeOutput  `json:"result,omitempty"`
	ListProfiles    *ProfilesOutput        `json:"list_profiles,omitempty"`
	Directory       *ProfilesOutput        `json:"directory,omitempty"`
	Graph           *GraphOutput           `json:"graph,omitempty"`
	Compare         *CompareOutput         `json:"compare,omitempty"`
	Synthesis       *ResultEnvelopeOutput  `json:"synthesis,omitempty"`
	Templates       *TemplatesOutput       `json:"templates,omitempty"`
	Policy          *PolicyOutput          `json:"policy,omitempty"`
	Diagnostics     *DiagnosticsOutput     `json:"diagnostics,omitempty"`
	Deployment      *DeploymentOutput      `json:"deployment,omitempty"`
	PluginLifecycle *PluginLifecycleOutput `json:"plugin_lifecycle,omitempty"`
}

// Response is kept as a concise consumer alias for MeshUIResponse.
type Response = MeshUIResponse

type SelectionOutput struct {
	RevisionID        string `json:"revision_id"`
	ActiveTurnChanged bool   `json:"active_turn_changed"`
}

// ProposalOutput is the exact bounded public part of mesh.ProposalResult.
type ProposalOutput struct {
	ProposalID string `json:"proposal_id"`
	RunID      string `json:"run_id"`
	SessionID  string `json:"session_id"`
	OrderID    string `json:"order_id"`
	BindingID  string `json:"binding_id"`
	Replayed   bool   `json:"replayed"`
}
type SpawnOutput struct {
	Proposal ProposalOutput `json:"proposal"`
}
type SpawnBatchOutput struct {
	BatchID string           `json:"batch_id"`
	Results []ProposalOutput `json:"results"`
	Partial bool             `json:"partial"`
}

// OperationAcknowledgement is a deterministic, digest-bound confirmation for
// operations which have no native receipt. It never invents a receipt ID.
type OperationAcknowledgement struct {
	TargetRunID string `json:"target_run_id"`
	InputRef    string `json:"input_ref,omitempty"`
	RevisionRef string `json:"revision_ref,omitempty"`
	ReasonRef   string `json:"reason_ref,omitempty"`
	Digest      string `json:"digest"`
	Status      string `json:"status"`
}
type AcknowledgementOutput struct {
	Acknowledgement OperationAcknowledgement `json:"acknowledgement"`
}

// SessionStatusOutput is the exact bounded UI form of mesh.SessionStatus. It
// does not infer token counts, a result reference, or a usage source.
type SessionStatusOutput struct {
	State       string `json:"state"`
	UsageSource string `json:"usage_source"`
}

// ResultEnvelopeOutput is the exact bounded UI form of mesh.ResultEnvelope.
// Artifact references stay opaque; no artifact body or provider text crosses.
type ResultEnvelopeOutput struct {
	RunID             string `json:"run_id"`
	AttemptID         string `json:"attempt_id"`
	Status            string `json:"status"`
	OutputArtifactRef string `json:"output_artifact_ref"`
	SchemaRef         string `json:"schema_ref"`
	ProvenanceDigest  string `json:"provenance_digest"`
	Classification    string `json:"classification"`
}

// RunListItem intentionally omits provider session IDs and result details.
type RunListItem struct {
	RunID     string `json:"run_id"`
	ProfileID string `json:"profile_id"`
	Provider  string `json:"provider"`
	Status    string `json:"status"`
	Depth     uint64 `json:"depth"`
}
type ListOutput struct {
	Runs []RunListItem `json:"runs"`
}
type ProfilesOutput struct {
	Profiles []Profile `json:"profiles"`
}
type GraphOutput struct {
	Graph Graph `json:"graph"`
}
type CompareOutput struct {
	Compare Comparison `json:"compare"`
}
type TemplatesOutput struct {
	Templates Templates `json:"templates"`
}
type PolicyOutput struct {
	Policy Policy `json:"policy"`
}
type DiagnosticsOutput struct {
	Diagnostics Diagnostics `json:"diagnostics"`
}
type DeploymentOutput struct {
	Status          string                   `json:"status"`
	Acknowledgement OperationAcknowledgement `json:"acknowledgement"`
}
type PluginLifecycleOutput struct {
	Package         Package                  `json:"package"`
	Acknowledgement OperationAcknowledgement `json:"acknowledgement"`
}

func (r MeshUIResponse) payloadCount() int {
	count := 0
	for _, present := range []bool{r.Selection != nil, r.Spawn != nil, r.SpawnBatch != nil, r.Send != nil, r.Steer != nil, r.Wait != nil, r.Collect != nil, r.Cancel != nil, r.List != nil, r.Status != nil, r.Result != nil, r.ListProfiles != nil, r.Directory != nil, r.Graph != nil, r.Compare != nil, r.Synthesis != nil, r.Templates != nil, r.Policy != nil, r.Diagnostics != nil, r.Deployment != nil, r.PluginLifecycle != nil} {
		if present {
			count++
		}
	}
	return count
}

// Validate verifies the response once at the service seam and again at the
// HTTP egress. expectedKind prevents a valid response for one operation from
// being substituted into another operation's route.
func (r MeshUIResponse) Validate(expectedKind string) error {
	if r.SchemaVersion != ResponseSchema || r.Kind == "" || (expectedKind != "" && r.Kind != expectedKind) || r.payloadCount() != 1 {
		return ErrInvalidOutput
	}
	valid := false
	switch r.Kind {
	case "selection-revision":
		valid = r.Selection != nil && id(r.Selection.RevisionID)
	case "mesh-spawn":
		valid = r.Spawn != nil && r.Spawn.Proposal.valid()
	case "mesh-spawnBatch":
		valid = r.SpawnBatch != nil && id(r.SpawnBatch.BatchID) && proposalsValid(r.SpawnBatch.Results, maxBatchItems, true)
	case "mesh-send":
		valid = r.Send != nil && r.Send.Acknowledgement.valid("sent", "input")
	case "mesh-steer":
		valid = r.Steer != nil && r.Steer.Acknowledgement.valid("sent", "input")
	case "mesh-wait":
		valid = r.Wait != nil && r.Wait.valid()
	case "mesh-collect":
		valid = r.Collect != nil && r.Collect.valid()
	case "mesh-cancel":
		valid = r.Cancel != nil && r.Cancel.Acknowledgement.valid("cancelled", "cancel")
	case "mesh-list":
		valid = r.List != nil && runListValid(r.List.Runs)
	case "mesh-status":
		valid = r.Status != nil && r.Status.valid()
	case "mesh-result":
		valid = r.Result != nil && r.Result.valid()
	case "mesh-listProfiles":
		valid = r.ListProfiles != nil && validProfileSubset(r.ListProfiles.Profiles)
	case "provider-directory":
		valid = r.Directory != nil && validProfileSubset(r.Directory.Profiles)
	case "ui-session-graph":
		valid = r.Graph != nil && r.Graph.Graph.valid()
	case "run-compare":
		valid = r.Compare != nil && r.Compare.Compare.valid()
	case "run-synthesis":
		valid = r.Synthesis != nil && r.Synthesis.valid()
	case "run-templates":
		valid = r.Templates != nil && r.Templates.Templates.valid()
	case "policy-approval-inspector":
		valid = r.Policy != nil && r.Policy.Policy.valid()
	case "provider-diagnostics":
		valid = r.Diagnostics != nil && r.Diagnostics.Diagnostics.valid()
	case "deployment-diagnostics":
		valid = r.Deployment != nil && deploymentStatus(r.Deployment.Status) && r.Deployment.Acknowledgement.valid("completed", "revision")
	case "plugin-lifecycle":
		valid = r.PluginLifecycle != nil && Lifecycle{Packages: []Package{r.PluginLifecycle.Package}}.valid() && r.PluginLifecycle.Acknowledgement.valid("completed", "revision")
	}
	if !valid || !withinOutputBudget(r) {
		return ErrInvalidOutput
	}
	return nil
}

func (v ProposalOutput) valid() bool {
	return id(v.ProposalID) && id(v.RunID) && id(v.SessionID) && id(v.OrderID) && id(v.BindingID)
}
func proposalsValid(values []ProposalOutput, max int, nonempty bool) bool {
	if values == nil || len(values) > max || (nonempty && len(values) == 0) {
		return false
	}
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if !value.valid() {
			return false
		}
		if _, ok := seen[value.ProposalID]; ok {
			return false
		}
		seen[value.ProposalID] = struct{}{}
	}
	return true
}
func (v OperationAcknowledgement) valid(expectedStatus, referenceKind string) bool {
	if !id(v.TargetRunID) || !digest(v.Digest) || v.Status != expectedStatus {
		return false
	}
	switch referenceKind {
	case "input":
		return id(v.InputRef) && v.RevisionRef == "" && v.ReasonRef == ""
	case "cancel":
		return v.InputRef == "" && id(v.RevisionRef) && id(v.ReasonRef)
	case "revision":
		return v.InputRef == "" && id(v.RevisionRef) && v.ReasonRef == ""
	default:
		return false
	}
}
func sessionState(v string) bool {
	return v == "proposed" || v == "admitted" || v == "starting" || v == "running" || v == "completed" || v == "failed" || v == "cancelled" || v == "uncertain" || v == "unknown"
}
func usageSource(v string) bool {
	return v == "unknown" || v == "provider" || v == "controller" || v == "attested"
}
func (v SessionStatusOutput) valid() bool { return sessionState(v.State) && usageSource(v.UsageSource) }
func classification(v string) bool {
	return v == "L0" || v == "L1" || v == "L2" || v == "L3" || v == "PD"
}
func (v ResultEnvelopeOutput) valid() bool {
	return id(v.RunID) && id(v.AttemptID) && sessionState(v.Status) && id(v.OutputArtifactRef) && id(v.SchemaRef) && digest(v.ProvenanceDigest) && classification(v.Classification)
}
func runListValid(values []RunListItem) bool {
	if values == nil || len(values) > maxItems {
		return false
	}
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if !id(value.RunID) || !providerForProfile(value.Provider, value.ProfileID) || !sessionState(value.Status) || value.Depth > maxSafeInteger {
			return false
		}
		if _, ok := seen[value.RunID]; ok {
			return false
		}
		seen[value.RunID] = struct{}{}
	}
	return true
}
func deploymentStatus(v string) bool {
	return v == "disabled" || v == "healthy" || v == "degraded" || v == "failed" || v == "unknown"
}
func withinOutputBudget(v MeshUIResponse) bool {
	b, err := json.Marshal(v)
	return err == nil && len(b) <= maxOutputBytes
}

// cloneResponse reconstructs exactly the one payload permitted by Validate.
// It never traverses arbitrary values and never preserves invoker-owned slice
// backing arrays or pointers.
func cloneResponse(r MeshUIResponse) MeshUIResponse {
	out := MeshUIResponse{SchemaVersion: r.SchemaVersion, Kind: r.Kind}
	switch r.Kind {
	case "selection-revision":
		v := *r.Selection
		out.Selection = &v
	case "mesh-spawn":
		v := *r.Spawn
		out.Spawn = &v
	case "mesh-spawnBatch":
		v := *r.SpawnBatch
		v.Results = make([]ProposalOutput, len(v.Results))
		copy(v.Results, r.SpawnBatch.Results)
		out.SpawnBatch = &v
	case "mesh-send":
		v := *r.Send
		out.Send = &v
	case "mesh-steer":
		v := *r.Steer
		out.Steer = &v
	case "mesh-wait":
		v := *r.Wait
		out.Wait = &v
	case "mesh-collect":
		v := *r.Collect
		out.Collect = &v
	case "mesh-cancel":
		v := *r.Cancel
		out.Cancel = &v
	case "mesh-list":
		v := *r.List
		v.Runs = make([]RunListItem, len(v.Runs))
		copy(v.Runs, r.List.Runs)
		out.List = &v
	case "mesh-status":
		v := *r.Status
		out.Status = &v
	case "mesh-result":
		v := *r.Result
		out.Result = &v
	case "mesh-listProfiles":
		v := *r.ListProfiles
		v.Profiles = make([]Profile, len(v.Profiles))
		copy(v.Profiles, r.ListProfiles.Profiles)
		out.ListProfiles = &v
	case "provider-directory":
		v := *r.Directory
		v.Profiles = make([]Profile, len(v.Profiles))
		copy(v.Profiles, r.Directory.Profiles)
		out.Directory = &v
	case "ui-session-graph":
		v := *r.Graph
		v.Graph = cloneGraph(v.Graph)
		out.Graph = &v
	case "run-compare":
		v := *r.Compare
		v.Compare = cloneComparison(v.Compare)
		out.Compare = &v
	case "run-synthesis":
		v := *r.Synthesis
		out.Synthesis = &v
	case "run-templates":
		v := *r.Templates
		v.Templates = cloneTemplates(v.Templates)
		out.Templates = &v
	case "policy-approval-inspector":
		v := *r.Policy
		v.Policy = clonePolicy(v.Policy)
		out.Policy = &v
	case "provider-diagnostics":
		v := *r.Diagnostics
		v.Diagnostics = cloneDiagnostics(v.Diagnostics)
		out.Diagnostics = &v
	case "deployment-diagnostics":
		v := *r.Deployment
		out.Deployment = &v
	case "plugin-lifecycle":
		v := *r.PluginLifecycle
		out.PluginLifecycle = &v
	}
	return out
}

// ErrorResponse is the only typed mesh UI error written by HTTP. It never
// reflects an invoker error or output payload.
type ErrorResponse struct {
	SchemaVersion string `json:"schema_version"`
	ErrorCode     string `json:"error_code"`
}

func UnavailableError() ErrorResponse {
	return ErrorResponse{SchemaVersion: ErrorSchema, ErrorCode: "MESH_UNAVAILABLE"}
}
func (e ErrorResponse) Validate() error {
	if e.SchemaVersion != ErrorSchema || e.ErrorCode != "MESH_UNAVAILABLE" {
		return ErrInvalidOutput
	}
	return nil
}

type selection struct {
	ProfileID string `json:"profile_id"`
	Operation string `json:"operation"`
	Base      string `json:"base_revision_id"`
}

// Select validates and forwards an immutable selection proposal. It has no
// mutex, revision, or local state: only the authenticated Controller endpoint
// can create the resulting revision identifier.
func (s *Service) Select(ctx context.Context, body []byte) (MeshUIResponse, error) {
	var v selection
	if strict(body, &v) != nil || !id(v.ProfileID) || !id(v.Base) || !selectionOperation(v.Operation) || !declaredProfile(v.ProfileID) {
		return MeshUIResponse{}, ErrInvalid
	}
	return s.invoke(ctx, "selection-revision", v)
}

func selectionOperation(v string) bool {
	return v == "new-root" || v == "new-child" || v == "clean-fork" || v == "model-only-new-session"
}

type uiLimits struct {
	MaxDepth      uint64         `json:"max_depth"`
	MaxChildren   uint64         `json:"max_children_per_parent"`
	MaxConcurrent uint64         `json:"max_concurrent_runs"`
	MaxInput      uint64         `json:"max_input_tokens"`
	MaxOutput     uint64         `json:"max_output_tokens"`
	MaxWall       uint64         `json:"max_wall_ms"`
	MaxAttempts   uint64         `json:"max_attempts"`
	MaxResult     uint64         `json:"max_result_bytes"`
	Cost          mesh.CostLimit `json:"cost"`
}

func (l uiLimits) mesh() mesh.ExecutionLimits {
	return mesh.ExecutionLimits{SchemaVersion: mesh.ExecutionLimitsV1, MaxDepth: l.MaxDepth, MaxChildrenPerParent: l.MaxChildren, MaxConcurrentRuns: l.MaxConcurrent, MaxInputTokens: l.MaxInput, MaxOutputTokens: l.MaxOutput, MaxWallMS: l.MaxWall, MaxAttempts: l.MaxAttempts, MaxResultBytes: l.MaxResult, Cost: l.Cost}
}
func (l uiLimits) valid() bool {
	for _, value := range []uint64{l.MaxDepth, l.MaxChildren, l.MaxConcurrent, l.MaxInput, l.MaxOutput, l.MaxWall, l.MaxAttempts, l.MaxResult, l.Cost.MaxMinorUnits, l.Cost.MaxQuantity} {
		if value > maxSafeInteger {
			return false
		}
	}
	return true
}

type spawn struct {
	ClientNonce string   `json:"client_nonce"`
	Objective   string   `json:"objective"`
	Preferred   string   `json:"preferred_profile"`
	Role        string   `json:"requested_role"`
	Output      string   `json:"output_schema_ref"`
	Limits      uiLimits `json:"requested_limits"`
}

func (v spawn) mesh() (mesh.SpawnProposal, error) {
	if !declaredProfile(v.Preferred) || !short(v.Objective, 4096) || !v.Limits.valid() {
		return mesh.SpawnProposal{}, ErrInvalid
	}
	p := mesh.SpawnProposal{SchemaVersion: mesh.SpawnProposalV1, ClientNonce: v.ClientNonce, Objective: v.Objective, PreferredProfile: v.Preferred, RequestedRole: v.Role, OutputSchemaRef: v.Output, RequestedLimits: v.Limits.mesh(), InputArtifactRefs: []string{}, RequestedTools: []string{}}
	return p, p.Validate()
}

type batch struct {
	Proposals []spawn `json:"proposals"`
}
type runRevision struct {
	RunID       string `json:"run_id"`
	RevisionRef string `json:"revision_ref"`
}
type send struct {
	RunID    string `json:"run_id"`
	InputRef string `json:"input_ref"`
}
type cancel struct {
	RunID       string `json:"run_id"`
	ReasonRef   string `json:"reason_ref"`
	RevisionRef string `json:"revision_ref"`
}
type list struct {
	RootID      string `json:"root_id"`
	RevisionRef string `json:"revision_ref"`
}

func short(v string, max int) bool {
	return len(v) > 0 && len(v) <= max && !strings.ContainsAny(v, "\x00\r\n") && !secretShaped(v)
}

func (s *Service) Propose(ctx context.Context, kind string, body []byte) (MeshUIResponse, error) {
	payload, err := proposal(kind, body)
	if err != nil {
		return MeshUIResponse{}, ErrInvalid
	}
	return s.invoke(ctx, kind, payload)
}
func (s *Service) invoke(ctx context.Context, kind string, payload any) (MeshUIResponse, error) {
	if s.invoker == nil {
		return MeshUIResponse{}, ErrUnavailable
	}
	response, err := s.invoker.InvokeMeshUI(ctx, kind, payload)
	if err != nil {
		return MeshUIResponse{}, err
	}
	if err := response.Validate(kind); err != nil {
		return MeshUIResponse{}, ErrInvalidOutput
	}
	// The invoker is trusted only after its public data has been copied into a
	// fresh closed DTO. A retained pointer cannot alter the value later written
	// by HTTP between validation and serialization.
	response = cloneResponse(response)
	if err := response.Validate(kind); err != nil {
		return MeshUIResponse{}, ErrInvalidOutput
	}
	return response, nil
}

func proposal(kind string, body []byte) (any, error) {
	switch kind {
	case "mesh-spawn":
		var v spawn
		if strict(body, &v) != nil {
			return nil, ErrInvalid
		}
		return v.mesh()
	case "mesh-spawnBatch":
		var v batch
		if strict(body, &v) != nil || len(v.Proposals) == 0 || len(v.Proposals) > maxBatchItems {
			return nil, ErrInvalid
		}
		p := make([]mesh.SpawnProposal, 0, len(v.Proposals))
		for _, x := range v.Proposals {
			q, err := x.mesh()
			if err != nil {
				return nil, ErrInvalid
			}
			p = append(p, q)
		}
		return p, nil
	case "mesh-send", "mesh-steer":
		var v send
		if strict(body, &v) != nil || !id(v.RunID) || !id(v.InputRef) {
			return nil, ErrInvalid
		}
		return v, nil
	case "mesh-wait", "mesh-collect", "mesh-status", "mesh-result":
		var v runRevision
		if strict(body, &v) != nil || !id(v.RunID) || !id(v.RevisionRef) {
			return nil, ErrInvalid
		}
		return v, nil
	case "mesh-cancel":
		var v cancel
		if strict(body, &v) != nil || !id(v.RunID) || !id(v.ReasonRef) || !id(v.RevisionRef) {
			return nil, ErrInvalid
		}
		return v, nil
	case "mesh-list":
		var v list
		if strict(body, &v) != nil || !id(v.RootID) || !id(v.RevisionRef) {
			return nil, ErrInvalid
		}
		return v, nil
	case "mesh-listProfiles":
		var v struct{}
		if strict(body, &v) != nil {
			return nil, ErrInvalid
		}
		return v, nil
	case "plugin-lifecycle":
		return lifecycleProposal(body)
	case "provider-directory", "provider-diagnostics":
		return profileRefreshProposal(body)
	case "ui-session-graph":
		return graphProposal(body)
	case "run-compare":
		return compareProposal(body)
	case "run-synthesis":
		return synthesisProposal(body)
	case "run-templates":
		return templateProposal(body)
	case "policy-approval-inspector":
		return policyProposal(body)
	case "deployment-diagnostics":
		return deploymentProposal(body)
	default:
		return nil, ErrInvalid
	}
}

type lifecycleRequest struct {
	SchemaVersion       string `json:"schema_version"`
	Action              string `json:"action"`
	PackageID           string `json:"package_id"`
	PackageDigest       string `json:"package_digest"`
	ProfileRevision     string `json:"profile_revision"`
	ControllerBindingID string `json:"controller_binding_id"`
	ExpiresAt           string `json:"expires_at"`
}

func lifecycleProposal(body []byte) (any, error) {
	var v lifecycleRequest
	if strict(body, &v) != nil || v.SchemaVersion != "plugin-lifecycle-request.v1" || !(v.Action == "enable" || v.Action == "disable" || v.Action == "update" || v.Action == "rollback") || !id(v.PackageID) || !digest(v.PackageDigest) || !id(v.ProfileRevision) || !id(v.ControllerBindingID) || !canonicalTimestamp(v.ExpiresAt) {
		return nil, ErrInvalid
	}
	return v, nil
}

type profileRefreshRequest struct {
	Action    string `json:"action"`
	ProfileID string `json:"profile_id"`
}

func profileRefreshProposal(body []byte) (any, error) {
	var v profileRefreshRequest
	if strict(body, &v) != nil || v.Action != "refresh" || !declaredProfile(v.ProfileID) {
		return nil, ErrInvalid
	}
	return v, nil
}

type graphRequest struct {
	RootID string `json:"root_id"`
}

func graphProposal(body []byte) (any, error) {
	var v graphRequest
	if strict(body, &v) != nil || !id(v.RootID) {
		return nil, ErrInvalid
	}
	return v, nil
}

type compareRequest struct {
	RunIDs []string `json:"run_ids"`
}

func compareProposal(body []byte) (any, error) {
	var v compareRequest
	if strict(body, &v) != nil || !ids(v.RunIDs, maxItems, true) {
		return nil, ErrInvalid
	}
	return v, nil
}

type synthesisRequest struct {
	TemplateID       string   `json:"template_id"`
	SourceResultRefs []string `json:"source_result_refs"`
}

func synthesisProposal(body []byte) (any, error) {
	var v synthesisRequest
	if strict(body, &v) != nil || !id(v.TemplateID) || !ids(v.SourceResultRefs, maxItems, true) {
		return nil, ErrInvalid
	}
	return v, nil
}

type templateRequest struct {
	TemplateID string `json:"template_id"`
	Version    string `json:"version"`
}

func templateProposal(body []byte) (any, error) {
	var v templateRequest
	if strict(body, &v) != nil || !id(v.TemplateID) || !id(v.Version) {
		return nil, ErrInvalid
	}
	return v, nil
}

type policyRequest struct {
	DecisionRef string `json:"decision_ref"`
}

func policyProposal(body []byte) (any, error) {
	var v policyRequest
	if strict(body, &v) != nil || !id(v.DecisionRef) {
		return nil, ErrInvalid
	}
	return v, nil
}

type deploymentRequest struct {
	Action string `json:"action"`
}

func deploymentProposal(body []byte) (any, error) {
	var v deploymentRequest
	if strict(body, &v) != nil || v.Action != "doctor" {
		return nil, ErrInvalid
	}
	return v, nil
}

func ids(values []string, max int, nonempty bool) bool {
	if len(values) > max || (nonempty && len(values) == 0) {
		return false
	}
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if !id(value) {
			return false
		}
		if _, ok := seen[value]; ok {
			return false
		}
		seen[value] = struct{}{}
	}
	return true
}
func canonicalTimestamp(v string) bool {
	if len(v) != len("2006-01-02T15:04:05.000Z") {
		return false
	}
	t, err := time.Parse("2006-01-02T15:04:05.000Z", v)
	return err == nil && t.UTC().Format("2006-01-02T15:04:05.000Z") == v
}

func strict(data []byte, target any) error {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || len(data) > maxOutputBytes || trimmed[0] != '{' || duplicates(trimmed) {
		return ErrInvalid
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if d.Decode(target) != nil {
		return ErrInvalid
	}
	var extra json.RawMessage
	if err := d.Decode(&extra); err != io.EOF {
		return ErrInvalid
	}
	return nil
}
func duplicates(data []byte) bool {
	d := json.NewDecoder(bytes.NewReader(data))
	var walk func(int) bool
	walk = func(depth int) bool {
		if depth > maxJSONDepth {
			return true
		}
		t, err := d.Token()
		if err != nil {
			return true
		}
		delim, ok := t.(json.Delim)
		if !ok {
			return false
		}
		if delim == '{' {
			seen := map[string]bool{}
			for d.More() {
				key, err := d.Token()
				if err != nil {
					return true
				}
				name, ok := key.(string)
				if !ok || seen[name] {
					return true
				}
				seen[name] = true
				if walk(depth + 1) {
					return true
				}
			}
			_, err = d.Token()
			return err != nil
		}
		if delim == '[' {
			for d.More() {
				if walk(depth + 1) {
					return true
				}
			}
			_, err = d.Token()
			return err != nil
		}
		return true
	}
	return walk(0)
}
