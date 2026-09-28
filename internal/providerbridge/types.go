// Package providerbridge contains offline, pinned provider transport metadata.
// It owns no provider process, credentials, Controller state, or admission.
package providerbridge

import "time"

const (
	EvidenceRecordV1      = "provider-evidence-record.v1"
	MappingV1             = "mesh-tool-transport-mapping.v1"
	CompatibilityRecordV1 = "provider-compatibility-record.v1"
)

// Provider is a canonical provider family identifier.
type Provider string

const (
	ProviderCodex    Provider = "codex"
	ProviderClaude   Provider = "claude"
	ProviderQwen     Provider = "qwen"
	ProviderKimi     Provider = "kimi"
	ProviderDeepSeek Provider = "deepseek"
)

// Canonical profile identifiers stay stable across provider runtime revisions.
const (
	ProfileCodexChatGPT = "codex.chatgpt.app-server"
	ProfileClaudeCode   = "claude.code.cli"
	ProfileQwenGeneral  = "qwen.general.headless"
	ProfileQwenLocalPD  = "qwen.local-pd"
	ProfileKimiCode     = "kimi.code.acp"
	ProfileDeepSeekAPI  = "deepseek.api"
)

// Status intentionally preserves the readiness ladder rather than presenting
// provider availability as a binary result.
type Status string

const (
	StatusDisabled     Status = "disabled"
	StatusConfigured   Status = "configured"
	StatusAuthRequired Status = "auth_required"
	StatusReady        Status = "ready"
	StatusDegraded     Status = "degraded"
	StatusCompatible   Status = "compatible"
	StatusIncompatible Status = "incompatible"
)

// validStatus is deliberately closed. A Registry must not accept a persisted
// readiness word it does not understand: doing so would make an unknown
// provider state look eligible after a future caller starts interpreting it.
func validStatus(status Status) bool {
	switch status {
	case StatusDisabled, StatusConfigured, StatusAuthRequired, StatusReady, StatusDegraded, StatusCompatible, StatusIncompatible:
		return true
	default:
		return false
	}
}

// Profile is the non-secret, Controller-readable directory entry. AccountRef
// is an opaque Controller/broker reference, never an account name, login URL,
// credential, or provider token. It is intentionally absent from fixtures.
type Profile struct {
	ID                     string
	Provider               Provider
	Model                  string
	RuntimeKind            string
	AuthModality           string
	AccountRef             string
	LocalOnly              bool
	MeshSpawnEnabled       bool
	ExecutionLimitsDigest  string
	MappingDigest          string
	ProviderEvidenceDigest string
	Revision               string
	Status                 Status
}

// ProfileResolution is the composition input for the consumer-owned mesh
// directory. It keeps profile-specific limits and the opaque account reference
// together with independently checked readiness; it does not promote a
// profile. The composition root must still decide whether a persisted,
// Controller-approved revision may expose MeshSpawnEnabled.
type ProfileResolution struct {
	Profile         Profile
	Limits          ExecutionLimits
	Mapping         Mapping
	Evidence        ProviderEvidenceRecord
	LimitsVerified  bool
	MappingVerified bool
	EvidenceCurrent bool
}

// DirectoryProfile is the redacted, derived provider state that may cross
// into the Controller UI. It has no account route, evidence body, signature,
// mapping, or transport data. MeshSpawn is derived by Registry.Resolve, never
// copied from an unverified UI input.
type DirectoryProfile struct {
	ProfileID string
	Provider  Provider
	Model     string
	Status    Status
	MeshSpawn bool
	LocalOnly bool
	Freshness EvidenceFreshness
}

// EvidenceFreshness is intentionally a small UI-safe classification. A
// malformed, untrusted, revoked, missing, or digest-mismatched record is
// unknown rather than being reported as current or stale.
type EvidenceFreshness string

const (
	EvidenceFreshnessCurrent EvidenceFreshness = "current"
	EvidenceFreshnessStale   EvidenceFreshness = "stale"
	EvidenceFreshnessUnknown EvidenceFreshness = "unknown"
)

// DirectorySnapshot can only be populated by Registry.Directory. Its data is
// private so another package cannot manufacture a "verified" mesh-spawn bit.
// Profiles returns a defensive copy for a redaction-only consumer.
type DirectorySnapshot struct {
	profiles []DirectoryProfile
}

func (s DirectorySnapshot) Profiles() []DirectoryProfile {
	out := make([]DirectoryProfile, len(s.profiles))
	copy(out, s.profiles)
	return out
}

const ExecutionLimitsV1 = "execution-limits.v1"

// ExecutionLimits mirrors the complete provider-neutral v1 semantics. The
// bridge owns validation only; Controller composition performs the explicit
// conversion to its consumer type without importing mesh here.
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

type CostLimit struct {
	Kind              string `json:"kind"`
	Currency          string `json:"currency"`
	MinorUnitExponent uint8  `json:"minor_unit_exponent"`
	MaxMinorUnits     uint64 `json:"max_minor_units"`
	Unit              string `json:"unit"`
	MaxQuantity       uint64 `json:"max_quantity"`
}

// Mapping describes how a provider's already-pinned offline protocol names
// the Controller mesh operations. It is evidence, not an instruction to start
// a native runtime.
type Mapping struct {
	SchemaVersion             string                `json:"schema_version"`
	Provider                  Provider              `json:"provider"`
	ProfileID                 string                `json:"profile_id"`
	ProfileRevision           string                `json:"profile_revision"`
	RuntimeVersion            string                `json:"runtime_version"`
	ProtocolVersion           string                `json:"protocol_version"`
	RuntimeDigest             string                `json:"runtime_digest"`
	ProtocolDigest            string                `json:"protocol_digest"`
	ToolSchemaDigest          string                `json:"tool_schema_digest"`
	CompatibilityRecordDigest string                `json:"compatibility_record_digest"`
	Maturity                  CompatibilityMaturity `json:"maturity"`
	EndpointAuthMode          string                `json:"endpoint_auth_mode"`
	Cancellation              string                `json:"cancellation"`
	Teardown                  string                `json:"teardown"`
	Operations                []OperationMapping    `json:"operations"`
	Digest                    string                `json:"digest"`
}

// CompatibilityMaturity separates synthetic mechanics fixtures from an
// externally probed, reviewed compatibility record. Only the latter may
// participate in Registry eligibility.
type CompatibilityMaturity string

const (
	CompatibilitySynthetic CompatibilityMaturity = "synthetic"
	CompatibilityPinned    CompatibilityMaturity = "pinned_compatibility"
)

// CompatibilityRecord is a sanitized, content-addressed outcome of an
// external provider probe. It deliberately records bounded categories and
// digests only: no prompts, tokens, credentials, stdout, or stderr belong here.
type CompatibilityRecord struct {
	SchemaVersion         string                `json:"schema_version"`
	Maturity              CompatibilityMaturity `json:"maturity"`
	Provider              Provider              `json:"provider"`
	ProfileID             string                `json:"profile_id"`
	ProfileRevision       string                `json:"profile_revision"`
	Model                 string                `json:"model"`
	AuthModality          string                `json:"auth_modality"`
	RuntimeVersion        string                `json:"runtime_version"`
	ProtocolVersion       string                `json:"protocol_version"`
	RuntimeArtifactDigest string                `json:"runtime_artifact_digest"`
	ProtocolSchemaDigest  string                `json:"protocol_schema_digest"`
	MeshToolSchemaDigest  string                `json:"mesh_tool_schema_digest"`
	TranscriptDigest      string                `json:"transcript_digest"`
	Operations            []OperationMapping    `json:"operations"`
	Handshake             string                `json:"handshake"`
	Start                 string                `json:"start"`
	Stream                string                `json:"stream"`
	Cancel                string                `json:"cancel"`
	Teardown              string                `json:"teardown"`
	Health                string                `json:"health"`
	GeneratorVersion      string                `json:"generator_version"`
	GeneratedAt           time.Time             `json:"generated_at"`
	SourceReferences      []CompatibilitySource `json:"source_references"`
	Digest                string                `json:"digest"`
}

type CompatibilitySource struct {
	Reference string `json:"reference"`
	Digest    string `json:"digest"`
}

type OperationMapping struct {
	Operation    string `json:"operation"`
	RequestEvent string `json:"request_event"`
	ResultEvent  string `json:"result_event"`
	CancelEvent  string `json:"cancel_event"`
}

// EndpointBinding is opaque transport bootstrap metadata. It deliberately
// has no credential field; actual credentials must stay in broker-owned IPC.
type EndpointBinding struct {
	BindingID string
	ProfileID string
	Audience  string
	PeerID    string
	ExpiresAt time.Time
}

// AttachedTransport proves only that a static mapping accepted a bound mesh
// endpoint. It cannot issue calls, start sessions, or reach a provider.
type AttachedTransport struct {
	ProfileID string
	Mapping   Mapping
	BindingID string
	proof     string
}

// StartedTransport is an in-memory compatibility-fixture session after a
// provider transport start. It cannot be fabricated from an attachment by a
// caller because only PinnedAdapter can place the start proof in it.
type StartedTransport struct {
	ProfileID string
	BindingID string
	attached  AttachedTransport
	proof     string
}

// ToolExposure is the provider-native name of a Controller mesh tool. The
// same operation deliberately has different event labels in every pinned
// provider mapping.
type ToolExposure struct {
	Operation    string
	RequestEvent string
	ResultEvent  string
	CancelEvent  string
}

const (
	ToolProposalV1 = "provider-tool-proposal.v1"
	SealedSpawnV1  = "controller-sealed-spawn-fixture.v1"
)

// ToolProposal is the bounded, unsealed result of a provider tool invocation.
// It deliberately has no Controller IDs, reservation, lease, capability,
// disclosure, binding, or sealed order fields.
type ToolProposal struct {
	SchemaVersion string
	ProfileID     string
	MappingDigest string
	Operation     string
	ClientNonce   string
	Objective     string
	RequestedRole string
	OutputSchema  string
	Digest        string
}

// SealedSpawn represents only an offline fixture assertion that Controller
// admission supplied a sealed dispatch matching the exact proposal and bound
// endpoint. It is not a production sealer and cannot start a provider runtime.
type SealedSpawn struct {
	SchemaVersion  string
	ProfileID      string
	MappingDigest  string
	ProposalDigest string
	BindingID      string
	SealDigest     string
}

// ToolResult contains protocol evidence only. No provider transcript or raw
// result bytes are retained by the offline compatibility harness.
type ToolResult struct {
	SessionID   string
	Operation   string
	ResultEvent string
	Terminal    string
}

// ProviderEvidenceRecord is a reproducible, closed P4 decision input. The
// signatures are verified over Digest; no credentials or raw source content
// belong in it.
type ProviderEvidenceRecord struct {
	SchemaVersion             string             `json:"schema_version"`
	Provider                  Provider           `json:"provider"`
	ProfileID                 string             `json:"profile_id"`
	ProfileRevision           string             `json:"profile_revision"`
	AuthModality              string             `json:"auth_modality"`
	OfficialURLs              []string           `json:"official_urls"`
	RetrievedAt               time.Time          `json:"retrieved_at"`
	FreshUntil                time.Time          `json:"fresh_until"`
	RuntimeVersion            string             `json:"runtime_version"`
	ProtocolVersion           string             `json:"protocol_version"`
	Model                     string             `json:"model"`
	ClaimModalities           map[string]string  `json:"claim_modalities"`
	SourceContentDigest       string             `json:"source_content_digest"`
	RuntimeArtifactDigest     string             `json:"runtime_artifact_digest"`
	SchemaDigest              string             `json:"schema_digest"`
	CompatibilityRecordDigest string             `json:"compatibility_record_digest"`
	ProtocolSchemaDigest      string             `json:"protocol_schema_digest"`
	MeshToolSchemaDigest      string             `json:"mesh_tool_schema_digest"`
	EvidenceGeneratorVersion  string             `json:"evidence_generator_version"`
	Digest                    string             `json:"digest"`
	Approvals                 []EvidenceApproval `json:"approvals"`
}

// EvidenceApproval is signed over the sealed evidence digest and cannot be
// reused for another profile revision, freshness window, or reviewer role.
type EvidenceApproval struct {
	SchemaVersion   string    `json:"schema_version"`
	Role            string    `json:"role"`
	ReviewerKeyID   string    `json:"reviewer_key_id"`
	ProfileID       string    `json:"profile_id"`
	ProfileRevision string    `json:"profile_revision"`
	EvidenceDigest  string    `json:"evidence_digest"`
	FreshUntil      time.Time `json:"fresh_until"`
	DecisionRef     string    `json:"decision_ref"`
	Signature       string    `json:"signature"`
}

// TrustRegistry is reread by the Controller before any profile promotion.
// It is an input to verification rather than mutable package state.
type TrustRegistry struct {
	TrustedTechnical map[string]bool
	TrustedSecurity  map[string]bool
	Revoked          map[string]bool
}

// SignatureVerifier permits production code to inject a real verifier while
// keeping all fixtures deterministic and offline.
type SignatureVerifier interface {
	Verify(signerKeyID, payloadDigest, signature string) bool
}
