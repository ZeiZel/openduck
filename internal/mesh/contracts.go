// Package mesh owns the Controller-side session mesh contracts. It deliberately
// models metadata and opaque references only: credentials, prompts, transcripts
// and provider-native handles never cross this boundary.
package mesh

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"
)

const (
	SpawnProposalV1      = "spawn-proposal.v1"
	WorkOrderV2          = "work-order.v2"
	RunDispatchBindingV2 = "run-dispatch-binding.v2"
	ExecutionLimitsV1    = "execution-limits.v1"
	EndpointBindingV1    = "mesh-endpoint-binding.v1"
	SnapshotV2           = "mesh-snapshot.v2"
	MaxProposalBytes     = 64 << 10
	MaxObjectiveBytes    = 8192
	MaxArtifactRefs      = 32
)

var (
	ErrInvalidContract      = errors.New("invalid mesh contract")
	ErrDenied               = errors.New("mesh request denied")
	ErrUnauthorized         = errors.New("mesh endpoint unauthorized")
	ErrReplay               = errors.New("mesh endpoint replay")
	ErrIdempotencyConflict  = errors.New("mesh idempotency conflict")
	ErrReconciliationNeeded = errors.New("mesh reconciliation required")
	ErrStartUncertain       = errors.New("mesh provider start outcome uncertain")
	ErrControlUncertain     = errors.New("mesh provider control outcome uncertain")
	ErrNotFound             = errors.New("mesh run not found")
	ErrCapacity             = errors.New("mesh capacity exceeded")
	ErrCycle                = errors.New("mesh lineage cycle")
	ErrPDCloudRoute         = errors.New("personal data cloud route denied")
	ErrDisclosure           = errors.New("cloud disclosure denied")
	ErrVersionConflict      = errors.New("mesh repository version conflict")
	ErrRepositoryPoisoned   = errors.New("mesh repository poisoned")
	ErrUnavailable          = errors.New("mesh journal unavailable")
)

type CostLimit struct {
	Kind              string `json:"kind"` // monetary or non_monetary
	Currency          string `json:"currency,omitempty"`
	MinorUnitExponent uint8  `json:"minor_unit_exponent,omitempty"`
	MaxMinorUnits     uint64 `json:"max_minor_units,omitempty"`
	Unit              string `json:"unit,omitempty"`
	MaxQuantity       uint64 `json:"max_quantity,omitempty"`
}

type ExecutionLimits struct {
	SchemaVersion        string    `json:"schema_version"`
	MaxDepth             uint64    `json:"max_depth"`
	MaxChildrenPerParent uint64    `json:"max_children_per_parent"`
	MaxConcurrentRuns    uint64    `json:"max_concurrent_runs"`
	MaxInputTokens       uint64    `json:"max_input_tokens"`
	MaxOutputTokens      uint64    `json:"max_output_tokens"`
	MaxWallMS            uint64    `json:"max_wall_ms"`
	MaxAttempts          uint64    `json:"max_attempts"`
	MaxResultBytes       uint64    `json:"max_result_bytes"`
	Cost                 CostLimit `json:"cost"`
}

func (l ExecutionLimits) Validate() error {
	if l.SchemaVersion != ExecutionLimitsV1 || l.MaxDepth == 0 || l.MaxChildrenPerParent == 0 || l.MaxConcurrentRuns == 0 || l.MaxInputTokens == 0 || l.MaxOutputTokens == 0 || l.MaxWallMS == 0 || l.MaxAttempts == 0 || l.MaxResultBytes == 0 {
		return ErrInvalidContract
	}
	// Bound values to positive signed-safe integers so later conversions cannot overflow.
	for _, n := range []uint64{l.MaxDepth, l.MaxChildrenPerParent, l.MaxConcurrentRuns, l.MaxInputTokens, l.MaxOutputTokens, l.MaxWallMS, l.MaxAttempts, l.MaxResultBytes} {
		if n > uint64(^uint(0)>>1) {
			return ErrInvalidContract
		}
	}
	switch l.Cost.Kind {
	case "monetary":
		if !validCurrency(l.Cost.Currency) || l.Cost.MinorUnitExponent > 3 || l.Cost.MaxMinorUnits == 0 || l.Cost.Unit != "" || l.Cost.MaxQuantity != 0 {
			return ErrInvalidContract
		}
	case "non_monetary":
		if l.Cost.Currency != "" || l.Cost.MinorUnitExponent != 0 || l.Cost.MaxMinorUnits != 0 || (l.Cost.Unit != "request" && l.Cost.Unit != "token" && l.Cost.Unit != "compute_ms") || l.Cost.MaxQuantity == 0 {
			return ErrInvalidContract
		}
	default:
		return ErrInvalidContract
	}
	return nil
}
func validCurrency(s string) bool {
	if len(s) != 3 {
		return false
	}
	for _, r := range s {
		if r < 'A' || r > 'Z' {
			return false
		}
	}
	return true
}
func (l ExecutionLimits) Narrows(policy ExecutionLimits) bool {
	if l.Validate() != nil || policy.Validate() != nil || l.Cost.Kind != policy.Cost.Kind {
		return false
	}
	if l.MaxDepth > policy.MaxDepth || l.MaxChildrenPerParent > policy.MaxChildrenPerParent || l.MaxConcurrentRuns > policy.MaxConcurrentRuns || l.MaxInputTokens > policy.MaxInputTokens || l.MaxOutputTokens > policy.MaxOutputTokens || l.MaxWallMS > policy.MaxWallMS || l.MaxAttempts > policy.MaxAttempts || l.MaxResultBytes > policy.MaxResultBytes {
		return false
	}
	if l.Cost.Kind == "monetary" {
		return l.Cost.Currency == policy.Cost.Currency && l.Cost.MinorUnitExponent == policy.Cost.MinorUnitExponent && l.Cost.MaxMinorUnits <= policy.Cost.MaxMinorUnits
	}
	return l.Cost.Unit == policy.Cost.Unit && l.Cost.MaxQuantity <= policy.Cost.MaxQuantity
}

// SpawnProposal is the only model-facing spawn input. It intentionally has no
// IDs, grants, authority timestamps, binding, or provider-account fields.
type SpawnProposal struct {
	SchemaVersion     string          `json:"schema_version"`
	ClientNonce       string          `json:"client_nonce"`
	Objective         string          `json:"objective"`
	InputArtifactRefs []string        `json:"input_artifact_refs"`
	PreferredProfile  string          `json:"preferred_profile"`
	RequestedRole     string          `json:"requested_role"`
	OutputSchemaRef   string          `json:"output_schema_ref"`
	RequestedLimits   ExecutionLimits `json:"requested_limits"`
	RequestedTools    []string        `json:"requested_tools"`
}

// TaskEnvelope is the closed, bounded task description carried from an
// admitted proposal to the provider runtime. References are opaque IDs only;
// payloads never cross the provider transport boundary.
type TaskEnvelope struct {
	Objective         string   `json:"objective"`
	InputArtifactRefs []string `json:"input_artifact_refs"`
	RequestedRole     string   `json:"requested_role"`
	OutputSchemaRef   string   `json:"output_schema_ref"`
}

func (e TaskEnvelope) Validate() error {
	if !validText(e.Objective, 1, MaxObjectiveBytes) || !validID(e.RequestedRole) || !validID(e.OutputSchemaRef) || len(e.InputArtifactRefs) > MaxArtifactRefs || !uniqueIDs(e.InputArtifactRefs) {
		return ErrInvalidContract
	}
	return nil
}

func (p SpawnProposal) TaskEnvelope() TaskEnvelope {
	return TaskEnvelope{Objective: p.Objective, InputArtifactRefs: append([]string(nil), p.InputArtifactRefs...), RequestedRole: p.RequestedRole, OutputSchemaRef: p.OutputSchemaRef}
}

func DecodeSpawnProposal(data []byte) (SpawnProposal, error) {
	if len(data) == 0 || len(data) > MaxProposalBytes {
		return SpawnProposal{}, ErrInvalidContract
	}
	var p SpawnProposal
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(&p); err != nil {
		return SpawnProposal{}, ErrInvalidContract
	}
	if err := ensureEOF(d); err != nil || p.Validate() != nil {
		return SpawnProposal{}, ErrInvalidContract
	}
	return p, nil
}
func (p SpawnProposal) Validate() error {
	if p.SchemaVersion != SpawnProposalV1 || !validID(p.ClientNonce) || !validID(p.PreferredProfile) || p.TaskEnvelope().Validate() != nil || p.RequestedLimits.Validate() != nil || len(p.RequestedTools) > 32 {
		return ErrInvalidContract
	}
	if !uniqueIDs(p.InputArtifactRefs) || !uniqueIDs(p.RequestedTools) {
		return ErrInvalidContract
	}
	return nil
}

type CapabilityEnvelope struct {
	Tools []string `json:"tools"`
}

func (c CapabilityEnvelope) Validate() error {
	if len(c.Tools) > 64 || !uniqueIDs(c.Tools) {
		return ErrInvalidContract
	}
	return nil
}
func IntersectCapabilities(parts ...CapabilityEnvelope) CapabilityEnvelope {
	if len(parts) == 0 {
		return CapabilityEnvelope{}
	}
	allowed := make(map[string]bool, len(parts[0].Tools))
	for _, v := range parts[0].Tools {
		allowed[v] = true
	}
	for _, p := range parts[1:] {
		seen := map[string]bool{}
		for _, v := range p.Tools {
			seen[v] = true
		}
		for v := range allowed {
			if !seen[v] {
				delete(allowed, v)
			}
		}
	}
	tools := make([]string, 0, len(allowed))
	for v := range allowed {
		tools = append(tools, v)
	}
	sort.Strings(tools)
	return CapabilityEnvelope{Tools: tools}
}

// ProfileDirectory is a consumer-side seam. Providers can adapt their own
// registries without mesh importing provider packages.
type ProfileDirectory interface {
	Lookup(context.Context, string) (Profile, error)
}
type Profile struct {
	ID               string
	Provider         string
	Model            string
	Status           string
	AccountHandleRef string
	LocalOnly        bool
	MeshSpawn        bool
	Limits           ExecutionLimits
	MappingVerified  bool
	EvidenceCurrent  bool
	Supported        CapabilityEnvelope
}

func (p Profile) Validate() error {
	if !validID(p.ID) || !validID(p.Provider) || !validID(p.Model) || !profileReadiness(p.Status) || (p.MeshSpawn && p.Status != "compatible") || (!p.LocalOnly && !validID(p.AccountHandleRef)) || p.Limits.Validate() != nil || p.Supported.Validate() != nil {
		return ErrInvalidContract
	}
	return nil
}
func (p Profile) Eligible() bool {
	return p.Validate() == nil && p.Status == "compatible" && p.MeshSpawn && p.MappingVerified && p.EvidenceCurrent
}

// profileReadiness is the bounded registry-derived status exposed to mesh
// composition. Ready is informational readiness only; only an independently
// verified compatible profile may enable mesh spawning.
func profileReadiness(status string) bool {
	switch status {
	case "disabled", "configured", "auth_required", "ready", "degraded", "compatible", "incompatible":
		return true
	default:
		return false
	}
}

type MeshEndpointBinding struct {
	SchemaVersion     string    `json:"schema_version"`
	EndpointID        string    `json:"endpoint_id"`
	Audience          string    `json:"audience"`
	RootRunID         string    `json:"root_run_id"`
	RunID             string    `json:"run_id"`
	SessionID         string    `json:"session_id"`
	AttemptID         string    `json:"attempt_id"`
	ToolDigest        string    `json:"tool_allowlist_digest"`
	AllowedOperations []string  `json:"allowed_operations"`
	PeerID            string    `json:"peer_id"`
	PolicyVersion     string    `json:"policy_version"`
	IssuedAt          time.Time `json:"issued_at"`
	ExpiresAt         time.Time `json:"expires_at"`
	Generation        uint64    `json:"generation"`
}

func (b MeshEndpointBinding) Validate(now time.Time) error {
	if b.SchemaVersion != EndpointBindingV1 || !validID(b.EndpointID) || (b.Audience != "mesh" && b.Audience != "workspace" && b.Audience != "process" && b.Audience != "network" && b.Audience != "browser" && b.Audience != "cua" && b.Audience != "mcp" && b.Audience != "effect" && b.Audience != "ui") || !validID(b.RootRunID) || !validID(b.RunID) || !validID(b.SessionID) || !validID(b.AttemptID) || !validID(b.PeerID) || !validID(b.PolicyVersion) || !uniqueIDs(b.AllowedOperations) || b.ToolDigest != hash(sortedStrings(b.AllowedOperations)) || b.Generation == 0 || b.IssuedAt.IsZero() || !b.ExpiresAt.After(b.IssuedAt) || !b.ExpiresAt.After(now) {
		return ErrInvalidContract
	}
	return nil
}

type EndpointRequest struct{ EndpointID, PeerID, Audience, Nonce, MessageDigest string }

type WorkOrderRecord struct {
	SchemaVersion, OrderID, OrderHash, RootRunID, ParentRunID, ParentSessionID, RunID, SessionID, AttemptID, ProfileID, Provider, Model, WorkspaceGroupID, Classification, IdempotencyKey, LeaseID, PolicyVersion string
	Depth                                                                                                                                                                                                         uint64
	Limits                                                                                                                                                                                                        ExecutionLimits
	Requested, Effective                                                                                                                                                                                          CapabilityEnvelope
	DisclosurePlanID, FanoutGrantID                                                                                                                                                                               string
	LeaseExpiry                                                                                                                                                                                                   time.Time
	Task                                                                                                                                                                                                          TaskEnvelope
}
type RunDispatchBinding struct {
	SchemaVersion, BindingID, BindingHash, OrderID, OrderHash, RootRunID, RunID, SessionID, AttemptID, EndpointID string
	Generation                                                                                                    uint64
	IssuedAt, ExpiresAt                                                                                           time.Time
}
type StartRequest struct {
	Order   WorkOrderRecord
	Binding RunDispatchBinding
	seal    string // Controller-only canonical guard; never serialized.
}

func (r StartRequest) isSealed() bool {
	return r.SealValid()
}

// SealValid is a read-only cross-package validation seam. External adapters
// can verify a Controller-minted request but cannot mint or repair its
// unexported seal. The seal hashes the complete order and dispatch binding, so
// mutating any exported field after construction invalidates the request.
func (r StartRequest) SealValid() bool {
	return isDigest(r.seal) && r.Order.Task.Validate() == nil && r.Order.SchemaVersion == WorkOrderV2 && r.Binding.SchemaVersion == RunDispatchBindingV2 && r.Order.OrderID == r.Binding.OrderID && r.Order.OrderHash == r.Binding.OrderHash && r.Order.RootRunID == r.Binding.RootRunID && r.Order.RunID == r.Binding.RunID && r.Order.SessionID == r.Binding.SessionID && r.Order.AttemptID == r.Binding.AttemptID && r.seal == hash(struct {
		SchemaVersion string
		Order         WorkOrderRecord
		Binding       RunDispatchBinding
	}{"mesh-start-request-seal.v1", r.Order, r.Binding})
}

func sealStartRequest(order WorkOrderRecord, binding RunDispatchBinding) StartRequest {
	r := StartRequest{Order: order, Binding: binding}
	r.seal = hash(struct {
		SchemaVersion string
		Order         WorkOrderRecord
		Binding       RunDispatchBinding
	}{"mesh-start-request-seal.v1", order, binding})
	return r
}

type SessionRef struct{ ProviderSessionID string }
type SessionStarter interface {
	Start(context.Context, StartRequest) (SessionRef, error)
}

// Cancellation is a closed provider-control envelope.  A user cancellation
// binds both the Controller revision and the separately opaque reason.  The
// two compensation modes deliberately have no user revision: their exact
// reason is an internal protocol constant and cannot be substituted with an
// ordinary user cancellation.
type Cancellation struct {
	Mode, RevisionRef, ReasonRef string
}

const (
	CancellationUser              = "user"
	CancellationStartCompensation = "start_compensation"
	CancellationBatchCompensation = "batch_compensation"
)

func (c Cancellation) Validate() error {
	switch c.Mode {
	case CancellationUser:
		if validID(c.RevisionRef) && validID(c.ReasonRef) {
			return nil
		}
	case CancellationStartCompensation:
		if c.RevisionRef == "" && c.ReasonRef == "start_commit_failed" {
			return nil
		}
	case CancellationBatchCompensation:
		if c.RevisionRef == "" && c.ReasonRef == "batch_compensation" {
			return nil
		}
	}
	return ErrInvalidContract
}

type SessionController interface {
	Send(context.Context, SessionRef, string) error
	Steer(context.Context, SessionRef, string) error
	Cancel(context.Context, SessionRef, Cancellation) error
	Status(context.Context, SessionRef) (SessionStatus, error)
	Wait(context.Context, SessionRef, time.Time) (SessionStatus, error)
	Result(context.Context, SessionRef, string) (ResultEnvelope, error)
}

// PersistedSessionRecoveryVerifier is an optional, explicit restart seam for a
// SessionController. A running provider child has a durable Controller
// ProviderSessionID, but that identifier alone never proves that a freshly
// constructed controller can still route to the native session. Implementers
// must verify the exact opaque reference against their own durable recovery
// evidence; they must not start, recreate, or redispatch native work.
//
// If a journal contains a running provider child and Sessions does not provide
// this verifier (or any verification fails), Coordinator remains poisoned until
// an external reconciliation path establishes the state safely.
type PersistedSessionRecoveryVerifier interface {
	RecoverPersistedSessions(context.Context, []PersistedSessionRecovery) error
}

// PersistedSessionRecovery is the Controller-owned identity projection used
// during process restart. Providers must match every populated field against
// their durable receipt; the opaque route alone is never recovery evidence.
type PersistedSessionRecovery struct {
	ProviderSessionID string
	Start             StartRequest
}
type SessionStatus struct {
	State       string
	UsageSource string
}
type ResultEnvelope struct{ RunID, AttemptID, Status, OutputArtifactRef, SchemaRef, ProvenanceDigest, Classification string }

// DisclosureAuthorizer is Controller-owned policy, not provider metadata. It
// returns an exact destination plan; a missing authorizer denies cloud routes.
type DisclosureAuthorizer interface {
	AuthorizeCloudDisclosure(context.Context, CloudDisclosureRequest) (CloudDisclosure, error)
}
type CloudDisclosureRequest struct {
	RootRunID, ParentRunID, ProfileID, DestinationProvider, AccountHandleRef, Model, Classification, PayloadDigest, Purpose, PolicyVersion string
	InputRevision                                                                                                                          uint64
	ExpiresAt                                                                                                                              time.Time
}
type CloudDisclosure struct {
	PlanID, FanoutGrantID, DestinationProvider, AccountHandleRef, Model, PayloadDigest, Purpose, PolicyVersion, PlanDigest, GrantDigest string
	InputRevision                                                                                                                       uint64
	ExpiresAt                                                                                                                           time.Time
}

func (d CloudDisclosure) ValidateFor(r CloudDisclosureRequest, now time.Time) error {
	if !validID(d.PlanID) || !validID(d.FanoutGrantID) || !isDigest(d.PlanDigest) || !isDigest(d.GrantDigest) || d.DestinationProvider != r.DestinationProvider || d.AccountHandleRef != r.AccountHandleRef || d.Model != r.Model || d.PayloadDigest != r.PayloadDigest || d.Purpose != r.Purpose || d.PolicyVersion != r.PolicyVersion || d.InputRevision != r.InputRevision || !d.ExpiresAt.After(now) || d.ExpiresAt.After(r.ExpiresAt) {
		return ErrDisclosure
	}
	return nil
}

// Capability endpoints are independently authenticated Controller adapters.
// They deliberately accept opaque request metadata rather than paths, shell
// fragments, browser state, or credentials; concrete brokers own those details.
type WorkspaceEndpoint interface {
	OpenWorkspace(context.Context, MeshEndpointBinding, string) error
}
type CapabilityEndpoint interface {
	InvokeCapability(context.Context, MeshEndpointBinding, string, string) error
}

type MeshEvent struct {
	SchemaVersion, Event, RootRunID, RunID, SessionID, AttemptID, ParentRunID, Provider, ProfileID, Phase, Status, Classification, ErrorCode, RecoveryState string
	At                                                                                                                                                      time.Time
}

func hash(v any) string {
	b, _ := json.Marshal(v)
	x := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(x[:])
}
func ensureEOF(d *json.Decoder) error {
	var x any
	if err := d.Decode(&x); err != io.EOF {
		return err
	}
	return nil
}
func validID(s string) bool {
	if len(s) < 1 || len(s) > 256 {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("_.:/-", r)) {
			return false
		}
	}
	return true
}
func validText(s string, min, max int) bool {
	return len(s) >= min && len(s) <= max && strings.IndexByte(s, 0) < 0
}
func uniqueIDs(v []string) bool {
	seen := map[string]bool{}
	for _, x := range v {
		if !validID(x) || seen[x] {
			return false
		}
		seen[x] = true
	}
	return true
}
func sortedStrings(v []string) []string {
	out := append([]string(nil), v...)
	sort.Strings(out)
	return out
}
func require(condition bool, format string, args ...any) error {
	if !condition {
		return fmt.Errorf("%w: "+format, append([]any{ErrInvalidContract}, args...)...)
	}
	return nil
}
