// Package harness implements the local-only, deterministic H0/H1 controller boundary.
// It deliberately contains no network client, tool runner, or effector.
package harness

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

const (
	TaskSignalV1                 = "task-signal.v1"
	ContextCapsuleV1             = "context-capsule.v1"
	TaskSpecV1                   = "task-spec.v1"
	WorkOrderV1                  = "work-order.v1"
	EvidenceBundleV1             = "evidence-bundle.v1"
	ReviewVerdictV1              = "review-verdict.v1"
	RootRuntimeAttestationV1     = "root-runtime-attestation.v1"
	WorkerRuntimeAttestationV1   = "worker-runtime-attestation.v1"
	WorkerDispatchBindingV1      = "worker-dispatch-binding.v1"
	OwnerInteractionEnvelopeV1   = "owner-interaction-envelope.v1"
	InteractionRenderReceiptV1   = "interaction-render-receipt.v1"
	OwnerDecisionEventV1         = "owner-decision-event.v1"
	InteractionDeliveryBindingV1 = "interaction-delivery-binding.v1"
	DecisionChallengeV1          = "decision-challenge.v1"
	InteractionCallbackSessionV1 = "interaction-callback-session.v1"
)

var (
	ErrInvalidContract = errors.New("invalid harness contract")
	ErrUnknownVersion  = errors.New("unknown schema version")
)

type Coverage struct {
	Complete bool     `json:"complete"`
	GapRefs  []string `json:"gap_refs"`
}
type Fact struct {
	Key         string `json:"key"`
	Value       string `json:"value"`
	EvidenceRef string `json:"evidence_ref"`
}
type TaskSignal struct {
	SchemaVersion  string    `json:"schema_version"`
	SignalID       string    `json:"signal_id"`
	SourceRef      string    `json:"source_ref"`
	SourceVersion  int       `json:"source_version"`
	ObservedAt     time.Time `json:"observed_at"`
	Kind           string    `json:"kind"`
	Summary        string    `json:"summary"`
	Facts          []Fact    `json:"facts"`
	Urgency        string    `json:"urgency"`
	MaxClass       string    `json:"max_class"`
	Coverage       Coverage  `json:"coverage"`
	EvidenceRefs   []string  `json:"evidence_refs"`
	SuggestedRoute string    `json:"suggested_route"`
	PolicyVersion  string    `json:"policy_version"`
	Digest         string    `json:"digest"`
}
type ContextCapsule struct {
	SchemaVersion     string    `json:"schema_version"`
	CapsuleID         string    `json:"capsule_id"`
	Purpose           string    `json:"purpose"`
	TaskID            string    `json:"task_id,omitempty"`
	SourceRefs        []string  `json:"source_refs"`
	Facts             []Fact    `json:"facts"`
	Constraints       []string  `json:"constraints"`
	OpenQuestions     []string  `json:"open_questions"`
	Coverage          Coverage  `json:"coverage"`
	MaxClass          string    `json:"max_class"`
	PolicyAttestation string    `json:"policy_attestation"`
	TokenBudget       int       `json:"token_budget"`
	ExpiresAt         time.Time `json:"expires_at"`
	Digest            string    `json:"digest"`
}
type TaskSpec struct {
	SchemaVersion      string   `json:"schema_version"`
	TaskID             string   `json:"task_id"`
	SpecVersion        int      `json:"spec_version"`
	Title              string   `json:"title"`
	Objective          string   `json:"objective"`
	InScope            []string `json:"in_scope"`
	OutOfScope         []string `json:"out_of_scope"`
	Constraints        []string `json:"constraints"`
	AcceptanceChecks   []string `json:"acceptance_checks"`
	EvidenceRequired   []string `json:"evidence_required"`
	RiskClass          string   `json:"risk_class"`
	AllowedEffectTypes []string `json:"allowed_effect_types"`
	OwnerDecisions     []string `json:"owner_decisions"`
	Status             string   `json:"status"`
	ParentSpecHash     string   `json:"parent_spec_hash,omitempty"`
	SpecHash           string   `json:"spec_hash"`
}
type Lease struct {
	ID        string    `json:"id"`
	ExpiresAt time.Time `json:"expires_at"`
}
type WorkOrder struct {
	SchemaVersion           string         `json:"schema_version"`
	WorkOrderID             string         `json:"work_order_id"`
	TaskID                  string         `json:"task_id"`
	SpecHash                string         `json:"spec_hash"`
	Role                    string         `json:"role"`
	Objective               string         `json:"objective"`
	OwnedResources          []string       `json:"owned_resources"`
	ContextCapsuleRefs      []string       `json:"context_capsule_refs"`
	AllowedTools            []string       `json:"allowed_tools"`
	AllowedEffectTypes      []string       `json:"allowed_effect_types"`
	WorkspaceCapabilityRefs []string       `json:"workspace_capability_refs"`
	ForbiddenActions        []string       `json:"forbidden_actions"`
	AcceptanceChecks        []string       `json:"acceptance_checks"`
	EvidenceRequired        []string       `json:"evidence_required"`
	Budgets                 map[string]int `json:"budgets"`
	Lease                   Lease          `json:"lease"`
	OutputSchema            string         `json:"output_schema"`
	RuntimeConstraints      []string       `json:"runtime_constraints"`
	ProfileManifestDigest   string         `json:"profile_manifest_digest"`
	SandboxPolicyDigest     string         `json:"sandbox_policy_digest"`
	WorkspaceDescriptor     string         `json:"workspace_descriptor"`
	WorktreeBaseRef         string         `json:"worktree_base_ref"`
	DispatchBindingRef      string         `json:"dispatch_binding_ref,omitempty"`
	Digest                  string         `json:"digest"`
}
type EvidenceClaim struct {
	Claim        string   `json:"claim"`
	EvidenceRefs []string `json:"evidence_refs"`
}
type Verification struct {
	CheckID    string `json:"check_id"`
	CommandRef string `json:"command_ref"`
	ExitCode   int    `json:"exit_code"`
	OutputRef  string `json:"output_ref"`
}
type EvidenceBundle struct {
	SchemaVersion    string          `json:"schema_version"`
	WorkOrderID      string          `json:"work_order_id"`
	TaskID           string          `json:"task_id"`
	SpecHash         string          `json:"spec_hash"`
	Status           string          `json:"status"`
	Claims           []EvidenceClaim `json:"claims"`
	ChangeRefs       []string        `json:"change_refs"`
	Verification     []Verification  `json:"verification"`
	Deviations       []string        `json:"deviations"`
	ResidualRisks    []string        `json:"residual_risks"`
	CapabilitiesUsed []string        `json:"capabilities_used"`
	AuditRefs        []string        `json:"audit_refs"`
	Digest           string          `json:"digest"`
}
type ReviewFinding struct {
	FindingID     string   `json:"finding_id"`
	Severity      string   `json:"severity"`
	RequirementID string   `json:"requirement_id"`
	Claim         string   `json:"claim"`
	EvidenceRefs  []string `json:"evidence_refs"`
}
type ReviewVerdict struct {
	SchemaVersion        string          `json:"schema_version"`
	ReviewID             string          `json:"review_id"`
	TaskID               string          `json:"task_id"`
	SpecHash             string          `json:"spec_hash"`
	EvidenceBundleDigest string          `json:"evidence_bundle_digest"`
	ReviewerRole         string          `json:"reviewer_role"`
	Verdict              string          `json:"verdict"`
	Findings             []ReviewFinding `json:"findings"`
	MissingEvidence      []string        `json:"missing_evidence"`
	IndependentChecks    []string        `json:"independent_checks"`
	ReviewedAt           time.Time       `json:"reviewed_at"`
	Digest               string          `json:"digest"`
}
type SourceDigest struct {
	Source string `json:"source"`
	Digest string `json:"digest"`
}
type RootRuntimeAttestation struct {
	SchemaVersion             string         `json:"schema_version"`
	RuntimeID                 string         `json:"runtime_id"`
	CodexVersion              string         `json:"codex_version"`
	CleanHomeDigest           string         `json:"clean_home_digest"`
	ProfileDigest             string         `json:"profile_digest"`
	EffectiveConfigDigest     string         `json:"effective_config_digest"`
	InstructionSources        []SourceDigest `json:"instruction_sources"`
	MCPServers                []SourceDigest `json:"mcp_servers"`
	Skills                    []SourceDigest `json:"skills"`
	Hooks                     []SourceDigest `json:"hooks"`
	Apps                      []SourceDigest `json:"apps"`
	SandboxPolicy             string         `json:"sandbox_policy"`
	RestrictedReadRoots       []string       `json:"restricted_read_roots"`
	RestrictedReadRootsDigest string         `json:"restricted_read_roots_digest"`
	NetworkAccess             bool           `json:"network_access"`
	ApprovalPolicy            string         `json:"approval_policy"`
	AppServerSchemaDigest     string         `json:"app_server_schema_digest"`
	CreatedAt                 time.Time      `json:"created_at"`
	AttestationDigest         string         `json:"attestation_digest"`
}
type WorkerRuntimeAttestation struct {
	SchemaVersion             string         `json:"schema_version"`
	WorkerInstanceID          string         `json:"worker_instance_id"`
	WorkOrderID               string         `json:"work_order_id"`
	CodexVersion              string         `json:"codex_version"`
	AgentRole                 string         `json:"agent_role"`
	LaunchSurface             string         `json:"launch_surface"`
	ProcessIdentity           string         `json:"process_identity"`
	RootParentThreadID        string         `json:"root_parent_thread_id,omitempty"`
	ModelRoute                string         `json:"model_route"`
	CleanHomeDigest           string         `json:"clean_home_digest"`
	GeneratedProfileDigest    string         `json:"generated_profile_digest"`
	InstructionSources        []SourceDigest `json:"instruction_sources"`
	ToolInventory             []SourceDigest `json:"tool_inventory"`
	ApprovalPolicy            string         `json:"approval_policy"`
	SandboxMode               string         `json:"sandbox_mode"`
	SandboxPolicyDigest       string         `json:"sandbox_policy_digest"`
	WorkspaceDescriptorDigest string         `json:"workspace_descriptor_digest"`
	WorktreeBaseRef           string         `json:"worktree_base_ref"`
	WritableResources         []string       `json:"writable_resources"`
	ReadableResources         []string       `json:"readable_resources"`
	NetworkPolicy             string         `json:"network_policy"`
	CreatedAt                 time.Time      `json:"created_at"`
	AttestationDigest         string         `json:"attestation_digest"`
}
type WorkerDispatchBinding struct {
	SchemaVersion                  string    `json:"schema_version"`
	DispatchBindingID              string    `json:"dispatch_binding_id"`
	WorkOrderID                    string    `json:"work_order_id"`
	TaskID                         string    `json:"task_id"`
	SpecHash                       string    `json:"spec_hash"`
	WorkerInstanceID               string    `json:"worker_instance_id"`
	WorkerRuntimeAttestationDigest string    `json:"worker_runtime_attestation_digest"`
	ProfileManifestDigest          string    `json:"profile_manifest_digest"`
	WorkspaceDescriptorDigest      string    `json:"workspace_descriptor_digest"`
	WorktreeBaseRef                string    `json:"worktree_base_ref"`
	SandboxPolicyDigest            string    `json:"sandbox_policy_digest"`
	LeaseID                        string    `json:"lease_id"`
	BoundAt                        time.Time `json:"bound_at"`
	BindingDigest                  string    `json:"binding_digest"`
}
type ActionProposal struct {
	ActionID                   string          `json:"action_id"`
	TaskID                     string          `json:"task_id"`
	SpecHash                   string          `json:"spec_hash"`
	ActionType                 string          `json:"action_type"`
	Principal                  string          `json:"principal"`
	CanonicalPayload           json.RawMessage `json:"canonical_payload"`
	PayloadHash                string          `json:"payload_hash"`
	DestinationDescriptor      json.RawMessage `json:"destination_descriptor"`
	DestinationHash            string          `json:"destination_hash"`
	ReconciliationPolicyDigest string          `json:"reconciliation_policy_digest"`
	Effects                    []string        `json:"effects"`
	RiskClass                  string          `json:"risk_class"`
	SourceRefs                 []string        `json:"source_refs"`
	RequiredCapability         string          `json:"required_capability"`
	ApprovalMode               string          `json:"approval_mode"`
	PolicyVersion              string          `json:"policy_version"`
	ExpiresAt                  time.Time       `json:"expires_at"`
}
type OwnerInteractionEnvelope struct {
	SchemaVersion              string    `json:"schema_version"`
	InteractionID              string    `json:"interaction_id"`
	TaskID                     string    `json:"task_id"`
	Kind                       string    `json:"kind"`
	DeliveryBindingID          string    `json:"delivery_binding_id"`
	DisplayPayloadRef          string    `json:"display_payload_ref"`
	SourceRefs                 []string  `json:"source_refs"`
	Coverage                   Coverage  `json:"coverage"`
	RiskClass                  string    `json:"risk_class"`
	ActionID                   string    `json:"action_id,omitempty"`
	PayloadHash                string    `json:"payload_hash,omitempty"`
	DestinationHash            string    `json:"destination_hash,omitempty"`
	ReconciliationPolicyDigest string    `json:"reconciliation_policy_digest,omitempty"`
	PreviewBytesRef            string    `json:"preview_bytes_ref,omitempty"`
	PreviewDigest              string    `json:"preview_digest,omitempty"`
	RenderingVersion           string    `json:"rendering_version"`
	Nonce                      string    `json:"nonce,omitempty"`
	ChallengeDigest            string    `json:"challenge_digest,omitempty"`
	ExpiresAt                  time.Time `json:"expires_at,omitempty"`
	PolicyVersion              string    `json:"policy_version"`
	ControllerAttestation      string    `json:"controller_attestation"`
	EnvelopeDigest             string    `json:"envelope_digest"`
}
type InteractionRenderReceipt struct {
	SchemaVersion     string    `json:"schema_version"`
	InteractionID     string    `json:"interaction_id"`
	DeliveryBindingID string    `json:"delivery_binding_id"`
	DisplayInstanceID string    `json:"display_instance_id"`
	DisplayNonce      string    `json:"display_nonce"`
	EnvelopeDigest    string    `json:"envelope_digest"`
	PreviewDigest     string    `json:"preview_digest"`
	RenderingVersion  string    `json:"rendering_version"`
	RenderedAt        time.Time `json:"rendered_at"`
	ReceiptDigest     string    `json:"receipt_digest"`
}
type OwnerDecisionEvent struct {
	SchemaVersion              string    `json:"schema_version"`
	DecisionEventID            string    `json:"decision_event_id"`
	Decision                   string    `json:"decision"`
	InteractionID              string    `json:"interaction_id"`
	DeliveryBindingID          string    `json:"delivery_binding_id"`
	DisplayInstanceID          string    `json:"display_instance_id"`
	RenderReceiptDigest        string    `json:"render_receipt_digest"`
	EnvelopeDigest             string    `json:"envelope_digest"`
	PreviewDigest              string    `json:"preview_digest"`
	RenderingVersion           string    `json:"rendering_version"`
	ActionID                   string    `json:"action_id"`
	PayloadHash                string    `json:"payload_hash"`
	DestinationHash            string    `json:"destination_hash"`
	ReconciliationPolicyDigest string    `json:"reconciliation_policy_digest"`
	Nonce                      string    `json:"nonce"`
	ChallengeDigest            string    `json:"challenge_digest"`
	ExpiresAt                  time.Time `json:"expires_at"`
	PolicyVersion              string    `json:"policy_version"`
	ApproverID                 string    `json:"approver_id"`
	RecentAuthProofRef         string    `json:"recent_auth_proof_ref"`
	ReceivedAt                 time.Time `json:"received_at"`
	EventDigest                string    `json:"event_digest"`
}
type InteractionDeliveryBinding struct {
	SchemaVersion              string    `json:"schema_version"`
	DeliveryBindingID          string    `json:"delivery_binding_id"`
	Kind                       string    `json:"kind"`
	HostBuild                  string    `json:"host_build"`
	HostBuildDigest            string    `json:"host_build_digest"`
	ControllerEndpointIdentity string    `json:"controller_endpoint_identity"`
	CallbackAuthScheme         string    `json:"callback_auth_scheme"`
	AllowedOrigins             []string  `json:"allowed_origins"`
	CSP                        string    `json:"csp"`
	UIResourceDigest           string    `json:"ui_resource_digest"`
	RenderingVersion           string    `json:"rendering_version"`
	ProbeArtifactRefs          []string  `json:"probe_artifact_refs"`
	IssuedAt                   time.Time `json:"issued_at"`
	RevokedAt                  time.Time `json:"revoked_at,omitempty"`
	BindingDigest              string    `json:"binding_digest"`
}

// DecisionChallenge is the exact, server-derived tuple a callback must answer.
// Handle material is never stored here; only its digest is retained.
type DecisionChallenge struct {
	SchemaVersion              string    `json:"schema_version"`
	InteractionID              string    `json:"interaction_id"`
	DeliveryBindingID          string    `json:"delivery_binding_id"`
	EnvelopeDigest             string    `json:"envelope_digest"`
	PreviewDigest              string    `json:"preview_digest"`
	DisplayInstanceID          string    `json:"display_instance_id"`
	DisplayNonce               string    `json:"display_nonce"`
	RenderReceiptDigest        string    `json:"render_receipt_digest"`
	ActionID                   string    `json:"action_id"`
	PayloadHash                string    `json:"payload_hash"`
	DestinationHash            string    `json:"destination_hash"`
	ReconciliationPolicyDigest string    `json:"reconciliation_policy_digest"`
	RenderingVersion           string    `json:"rendering_version"`
	Nonce                      string    `json:"nonce"`
	ExpiresAt                  time.Time `json:"expires_at"`
	PolicyVersion              string    `json:"policy_version"`
	SessionID                  string    `json:"session_id"`
	HandleDigest               string    `json:"handle_digest"`
	ChallengeDigest            string    `json:"challenge_digest"`
}

type InteractionCallbackSession struct {
	SchemaVersion   string            `json:"schema_version"`
	SessionID       string            `json:"session_id"`
	TaskID          string            `json:"task_id"`
	InteractionID   string            `json:"interaction_id"`
	State           string            `json:"state"`
	Challenge       DecisionChallenge `json:"challenge"`
	ChallengeDigest string            `json:"challenge_digest"`
	IssuedAt        time.Time         `json:"issued_at"`
	RenderedAt      time.Time         `json:"rendered_at,omitempty"`
	DecidedAt       time.Time         `json:"decided_at,omitempty"`
	DecisionEventID string            `json:"decision_event_id,omitempty"`
	SessionDigest   string            `json:"session_digest"`
}

// CanonicalJSON uses encoding/json's stable map-key ordering and compact output. Contracts use
// only deterministic JSON kinds; hashes are always over the copy with its self-digest omitted.
func CanonicalJSON(v any) ([]byte, error) { return json.Marshal(v) }
func SHA256(v any) (string, error) {
	b, e := CanonicalJSON(v)
	if e != nil {
		return "", e
	}
	s := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(s[:]), nil
}
func hashWithout(v any, clear func()) (string, error) { clear(); return SHA256(v) }
func isDigest(s string) bool {
	if !strings.HasPrefix(s, "sha256:") || len(s) != 71 {
		return false
	}
	_, e := hex.DecodeString(s[7:])
	return e == nil
}
func required(values ...string) error {
	for _, v := range values {
		if strings.TrimSpace(v) == "" {
			return fmt.Errorf("%w: required field", ErrInvalidContract)
		}
	}
	return nil
}
func validClass(s string) bool { return s == "L0" || s == "L1" || s == "L2" || s == "L3" }
func noControls(s string) bool {
	return !strings.ContainsAny(s, "\x00\r\n\u202e\u202d\u200b\u200c\u200d")
}
func validateDigest(v any, got string, clear func()) error {
	want, e := hashWithout(v, clear)
	if e != nil {
		return e
	}
	if got != want {
		return fmt.Errorf("%w: digest mismatch", ErrInvalidContract)
	}
	return nil
}

func (v *TaskSignal) Seal() error {
	v.SchemaVersion = TaskSignalV1
	v.Digest = ""
	d, e := SHA256(v)
	v.Digest = d
	return e
}
func (v TaskSignal) Validate() error {
	if v.SchemaVersion != TaskSignalV1 {
		return ErrUnknownVersion
	}
	if e := required(v.SignalID, v.SourceRef, v.Kind, v.Summary, v.Urgency, v.MaxClass, v.SuggestedRoute, v.PolicyVersion, v.Digest); e != nil {
		return e
	}
	if v.SourceVersion < 1 || v.ObservedAt.IsZero() || !validClass(v.MaxClass) || !noControls(v.Summary) {
		return ErrInvalidContract
	}
	x := v
	return validateDigest(&x, v.Digest, func() { x.Digest = "" })
}
func (v *ContextCapsule) Seal() error {
	v.SchemaVersion = ContextCapsuleV1
	v.Digest = ""
	d, e := SHA256(v)
	v.Digest = d
	return e
}
func (v ContextCapsule) Validate() error {
	if v.SchemaVersion != ContextCapsuleV1 {
		return ErrUnknownVersion
	}
	if e := required(v.CapsuleID, v.Purpose, v.MaxClass, v.PolicyAttestation, v.Digest); e != nil {
		return e
	}
	if v.TokenBudget <= 0 || v.ExpiresAt.IsZero() || !validClass(v.MaxClass) {
		return ErrInvalidContract
	}
	x := v
	return validateDigest(&x, v.Digest, func() { x.Digest = "" })
}
func (v *TaskSpec) Seal() error {
	v.SchemaVersion = TaskSpecV1
	v.SpecHash = ""
	d, e := SHA256(v)
	v.SpecHash = d
	return e
}
func (v TaskSpec) Validate() error {
	if v.SchemaVersion != TaskSpecV1 {
		return ErrUnknownVersion
	}
	if e := required(v.TaskID, v.Title, v.Objective, v.RiskClass, v.Status, v.SpecHash); e != nil {
		return e
	}
	if v.SpecVersion < 1 || (v.Status != "draft" && v.Status != "frozen" && v.Status != "superseded") {
		return ErrInvalidContract
	}
	x := v
	return validateDigest(&x, v.SpecHash, func() { x.SpecHash = "" })
}
func (v *WorkOrder) Seal() error {
	v.SchemaVersion = WorkOrderV1
	v.Digest = ""
	d, e := SHA256(v)
	v.Digest = d
	return e
}
func (v WorkOrder) Validate() error {
	if v.SchemaVersion != WorkOrderV1 {
		return ErrUnknownVersion
	}
	if e := required(v.WorkOrderID, v.TaskID, v.SpecHash, v.Role, v.Objective, v.Lease.ID, v.OutputSchema, v.ProfileManifestDigest, v.SandboxPolicyDigest, v.WorkspaceDescriptor, v.WorktreeBaseRef, v.Digest); e != nil {
		return e
	}
	if v.Role != "codex_implementer" || len(v.AllowedEffectTypes) != 0 || v.Lease.ExpiresAt.IsZero() || !isDigest(v.SpecHash) {
		return ErrInvalidContract
	}
	x := v
	return validateDigest(&x, v.Digest, func() { x.Digest = "" })
}
func (v *EvidenceBundle) Seal() error {
	v.SchemaVersion = EvidenceBundleV1
	v.Digest = ""
	d, e := SHA256(v)
	v.Digest = d
	return e
}
func (v EvidenceBundle) Validate() error {
	if v.SchemaVersion != EvidenceBundleV1 {
		return ErrUnknownVersion
	}
	if e := required(v.WorkOrderID, v.TaskID, v.SpecHash, v.Status, v.Digest); e != nil {
		return e
	}
	if v.Status != "completed" || !isDigest(v.SpecHash) {
		return ErrInvalidContract
	}
	x := v
	return validateDigest(&x, v.Digest, func() { x.Digest = "" })
}
func (v *ReviewVerdict) Seal() error {
	v.SchemaVersion = ReviewVerdictV1
	v.Digest = ""
	d, e := SHA256(v)
	v.Digest = d
	return e
}
func (v ReviewVerdict) Validate() error {
	if v.SchemaVersion != ReviewVerdictV1 {
		return ErrUnknownVersion
	}
	if e := required(v.ReviewID, v.TaskID, v.SpecHash, v.EvidenceBundleDigest, v.ReviewerRole, v.Verdict, v.Digest); e != nil {
		return e
	}
	if (v.Verdict != "pass" && v.Verdict != "rework" && v.Verdict != "blocked") || !isDigest(v.SpecHash) || !isDigest(v.EvidenceBundleDigest) || (v.Verdict == "pass" && (len(v.MissingEvidence) > 0 || hasP0P1(v.Findings))) {
		return ErrInvalidContract
	}
	x := v
	return validateDigest(&x, v.Digest, func() { x.Digest = "" })
}
func hasP0P1(fs []ReviewFinding) bool {
	for _, f := range fs {
		if f.Severity == "P0" || f.Severity == "P1" {
			return true
		}
	}
	return false
}
func (v *RootRuntimeAttestation) Seal() error {
	v.SchemaVersion = RootRuntimeAttestationV1
	v.AttestationDigest = ""
	d, e := SHA256(v)
	v.AttestationDigest = d
	return e
}
func (v RootRuntimeAttestation) Validate() error {
	if v.SchemaVersion != RootRuntimeAttestationV1 {
		return ErrUnknownVersion
	}
	if e := required(v.RuntimeID, v.CodexVersion, v.CleanHomeDigest, v.ProfileDigest, v.EffectiveConfigDigest, v.SandboxPolicy, v.RestrictedReadRootsDigest, v.ApprovalPolicy, v.AppServerSchemaDigest, v.AttestationDigest); e != nil {
		return e
	}
	if v.NetworkAccess || v.ApprovalPolicy != "never" || !isUTCTimestamp(v.CreatedAt) || !validSourceDigests(v.InstructionSources) || !validSourceDigests(v.MCPServers) || !validSourceDigests(v.Skills) || !validSourceDigests(v.Hooks) || !validSourceDigests(v.Apps) || !validStrings(v.RestrictedReadRoots) || !isDigest(v.CleanHomeDigest) || !isDigest(v.ProfileDigest) || !isDigest(v.EffectiveConfigDigest) || !isDigest(v.AppServerSchemaDigest) || !isDigest(v.RestrictedReadRootsDigest) {
		return ErrInvalidContract
	}
	// RestrictedReadRootsDigest is the SHA256 of CanonicalJSON(RestrictedReadRoots),
	// preserving the attested order (duplicates are rejected by validStrings).
	if digest, e := SHA256(v.RestrictedReadRoots); e != nil || digest != v.RestrictedReadRootsDigest {
		return ErrInvalidContract
	}
	x := v
	return validateDigest(&x, v.AttestationDigest, func() { x.AttestationDigest = "" })
}
func (v *WorkerRuntimeAttestation) Seal() error {
	v.SchemaVersion = WorkerRuntimeAttestationV1
	v.AttestationDigest = ""
	d, e := SHA256(v)
	v.AttestationDigest = d
	return e
}
func (v WorkerRuntimeAttestation) Validate() error {
	if v.SchemaVersion != WorkerRuntimeAttestationV1 {
		return ErrUnknownVersion
	}
	if e := required(v.WorkerInstanceID, v.WorkOrderID, v.CodexVersion, v.AgentRole, v.LaunchSurface, v.ProcessIdentity, v.CleanHomeDigest, v.GeneratedProfileDigest, v.ApprovalPolicy, v.SandboxMode, v.SandboxPolicyDigest, v.WorkspaceDescriptorDigest, v.WorktreeBaseRef, v.NetworkPolicy, v.AttestationDigest); e != nil {
		return e
	}
	if v.AgentRole != "codex_implementer" || (v.LaunchSurface != "app_server" && v.LaunchSurface != "exec") || v.RootParentThreadID != "" || v.ApprovalPolicy != "never" || v.SandboxMode != "workspace-write" || v.NetworkPolicy != "false" || !isUTCTimestamp(v.CreatedAt) || !validSourceDigests(v.InstructionSources) || !validSourceDigests(v.ToolInventory) || !validStrings(v.WritableResources) || !validStrings(v.ReadableResources) || !isDigest(v.CleanHomeDigest) || !isDigest(v.GeneratedProfileDigest) || !isDigest(v.SandboxPolicyDigest) || !isDigest(v.WorkspaceDescriptorDigest) {
		return ErrInvalidContract
	}
	x := v
	return validateDigest(&x, v.AttestationDigest, func() { x.AttestationDigest = "" })
}

func isUTCTimestamp(t time.Time) bool {
	if t.IsZero() {
		return false
	}
	_, offset := t.Zone()
	return offset == 0
}

func validSourceDigests(values []SourceDigest) bool {
	if values == nil {
		return false
	}
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if value.Source == "" || !isDigest(value.Digest) {
			return false
		}
		if _, ok := seen[value.Source]; ok {
			return false
		}
		seen[value.Source] = struct{}{}
	}
	return true
}

func validStrings(values []string) bool {
	if values == nil {
		return false
	}
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if value == "" {
			return false
		}
		if _, ok := seen[value]; ok {
			return false
		}
		seen[value] = struct{}{}
	}
	return true
}
func (v *WorkerDispatchBinding) Seal() error {
	v.SchemaVersion = WorkerDispatchBindingV1
	v.BindingDigest = ""
	d, e := SHA256(v)
	v.BindingDigest = d
	return e
}
func (v WorkerDispatchBinding) Validate() error {
	if v.SchemaVersion != WorkerDispatchBindingV1 {
		return ErrUnknownVersion
	}
	if e := required(v.DispatchBindingID, v.WorkOrderID, v.TaskID, v.SpecHash, v.WorkerInstanceID, v.WorkerRuntimeAttestationDigest, v.ProfileManifestDigest, v.WorkspaceDescriptorDigest, v.WorktreeBaseRef, v.SandboxPolicyDigest, v.LeaseID, v.BindingDigest); e != nil {
		return e
	}
	if v.BoundAt.IsZero() || !isDigest(v.SpecHash) || !isDigest(v.WorkerRuntimeAttestationDigest) {
		return ErrInvalidContract
	}
	x := v
	return validateDigest(&x, v.BindingDigest, func() { x.BindingDigest = "" })
}
func (v *InteractionDeliveryBinding) Seal() error {
	v.SchemaVersion = InteractionDeliveryBindingV1
	v.BindingDigest = ""
	d, e := SHA256(v)
	v.BindingDigest = d
	return e
}
func (v InteractionDeliveryBinding) Validate() error {
	if v.SchemaVersion != InteractionDeliveryBindingV1 {
		return ErrUnknownVersion
	}
	if e := required(v.DeliveryBindingID, v.Kind, v.HostBuild, v.HostBuildDigest, v.ControllerEndpointIdentity, v.CallbackAuthScheme, v.CSP, v.UIResourceDigest, v.RenderingVersion, v.BindingDigest); e != nil {
		return e
	}
	if (v.Kind != "personal_plugin_mcp_apps" && v.Kind != "custom_app_server_client") || v.IssuedAt.IsZero() || !v.RevokedAt.IsZero() {
		return ErrInvalidContract
	}
	x := v
	return validateDigest(&x, v.BindingDigest, func() { x.BindingDigest = "" })
}

func (v *DecisionChallenge) Seal() error {
	v.SchemaVersion = DecisionChallengeV1
	v.ChallengeDigest = ""
	d, e := SHA256(v)
	v.ChallengeDigest = d
	return e
}
func (v DecisionChallenge) Validate() error {
	if v.SchemaVersion != DecisionChallengeV1 {
		return ErrUnknownVersion
	}
	if e := required(v.InteractionID, v.DeliveryBindingID, v.EnvelopeDigest, v.PreviewDigest, v.ActionID, v.PayloadHash, v.DestinationHash, v.ReconciliationPolicyDigest, v.RenderingVersion, v.Nonce, v.PolicyVersion, v.SessionID, v.HandleDigest, v.ChallengeDigest); e != nil {
		return e
	}
	if v.ExpiresAt.IsZero() || !isDigest(v.EnvelopeDigest) || !isDigest(v.PreviewDigest) || !isDigest(v.PayloadHash) || !isDigest(v.DestinationHash) || !isDigest(v.ReconciliationPolicyDigest) || !isDigest(v.HandleDigest) {
		return ErrInvalidContract
	}
	if v.RenderReceiptDigest != "" && (v.DisplayInstanceID == "" || v.DisplayNonce == "") {
		return ErrInvalidContract
	}
	x := v
	return validateDigest(&x, v.ChallengeDigest, func() { x.ChallengeDigest = "" })
}

func (v *InteractionCallbackSession) Seal() error {
	v.SchemaVersion = InteractionCallbackSessionV1
	v.SessionDigest = ""
	d, e := SHA256(v)
	v.SessionDigest = d
	return e
}
func (v InteractionCallbackSession) Validate() error {
	if v.SchemaVersion != InteractionCallbackSessionV1 {
		return ErrUnknownVersion
	}
	if e := required(v.SessionID, v.TaskID, v.InteractionID, v.State, v.ChallengeDigest, v.SessionDigest); e != nil {
		return e
	}
	if v.State != "ISSUED" && v.State != "RENDERED" && v.State != "DECIDED" && v.State != "INVALIDATED" {
		return ErrInvalidContract
	}
	if v.IssuedAt.IsZero() || v.Challenge.SchemaVersion != DecisionChallengeV1 || v.Challenge.SessionID != v.SessionID || v.ChallengeDigest != v.Challenge.ChallengeDigest {
		return ErrInvalidContract
	}
	if e := v.Challenge.Validate(); e != nil {
		return e
	}
	if v.State == "RENDERED" && v.RenderedAt.IsZero() || v.State == "DECIDED" && (v.DecidedAt.IsZero() || v.DecisionEventID == "") {
		return ErrInvalidContract
	}
	x := v
	return validateDigest(&x, v.SessionDigest, func() { x.SessionDigest = "" })
}
func (v *OwnerInteractionEnvelope) Seal() error {
	v.SchemaVersion = OwnerInteractionEnvelopeV1
	v.EnvelopeDigest = ""
	d, e := SHA256(v)
	v.EnvelopeDigest = d
	return e
}
func (v OwnerInteractionEnvelope) Validate() error {
	if v.SchemaVersion != OwnerInteractionEnvelopeV1 {
		return ErrUnknownVersion
	}
	if e := required(v.InteractionID, v.TaskID, v.Kind, v.DeliveryBindingID, v.DisplayPayloadRef, v.RenderingVersion, v.PolicyVersion, v.ControllerAttestation, v.EnvelopeDigest); e != nil {
		return e
	}
	if v.Kind != "approval_request" && v.Kind != "action_preview" && v.Kind != "suggestion" && v.Kind != "status" && v.Kind != "receipt" && v.Kind != "incident" {
		return ErrInvalidContract
	}
	if (v.Kind == "approval_request" || v.Kind == "action_preview") && (required(v.ActionID, v.PayloadHash, v.DestinationHash, v.ReconciliationPolicyDigest, v.PreviewDigest, v.Nonce, v.ChallengeDigest) != nil || v.ExpiresAt.IsZero()) {
		return ErrInvalidContract
	}
	x := v
	return validateDigest(&x, v.EnvelopeDigest, func() { x.EnvelopeDigest = "" })
}
func (v *InteractionRenderReceipt) Seal() error {
	v.SchemaVersion = InteractionRenderReceiptV1
	v.ReceiptDigest = ""
	d, e := SHA256(v)
	v.ReceiptDigest = d
	return e
}
func (v InteractionRenderReceipt) Validate() error {
	if v.SchemaVersion != InteractionRenderReceiptV1 {
		return ErrUnknownVersion
	}
	if e := required(v.InteractionID, v.DeliveryBindingID, v.DisplayInstanceID, v.EnvelopeDigest, v.PreviewDigest, v.RenderingVersion, v.ReceiptDigest); e != nil {
		return e
	}
	if v.RenderedAt.IsZero() {
		return ErrInvalidContract
	}
	x := v
	return validateDigest(&x, v.ReceiptDigest, func() { x.ReceiptDigest = "" })
}
func (v *OwnerDecisionEvent) Seal() error {
	v.SchemaVersion = OwnerDecisionEventV1
	v.EventDigest = ""
	d, e := SHA256(v)
	v.EventDigest = d
	return e
}
func (v OwnerDecisionEvent) Validate() error {
	if v.SchemaVersion != OwnerDecisionEventV1 {
		return ErrUnknownVersion
	}
	if e := required(v.DecisionEventID, v.Decision, v.InteractionID, v.DeliveryBindingID, v.DisplayInstanceID, v.RenderReceiptDigest, v.EnvelopeDigest, v.PreviewDigest, v.RenderingVersion, v.ActionID, v.PayloadHash, v.DestinationHash, v.ReconciliationPolicyDigest, v.Nonce, v.ChallengeDigest, v.PolicyVersion, v.ApproverID, v.RecentAuthProofRef, v.EventDigest); e != nil {
		return e
	}
	if (v.Decision != "approve" && v.Decision != "reject") || v.ExpiresAt.IsZero() || v.ReceivedAt.IsZero() {
		return ErrInvalidContract
	}
	x := v
	return validateDigest(&x, v.EventDigest, func() { x.EventDigest = "" })
}

func (v ActionProposal) Validate() error {
	if e := required(v.ActionID, v.TaskID, v.SpecHash, v.ActionType, v.Principal, v.PayloadHash, v.DestinationHash, v.ReconciliationPolicyDigest, v.RiskClass, v.RequiredCapability, v.ApprovalMode, v.PolicyVersion); e != nil {
		return e
	}
	if v.ApprovalMode != "owner" || v.ExpiresAt.IsZero() || !isDigest(v.SpecHash) {
		return ErrInvalidContract
	}
	p, e := canonicalRaw(v.CanonicalPayload)
	if e != nil {
		return e
	}
	d, e := SHA256(json.RawMessage(p))
	if e != nil || d != v.PayloadHash {
		return ErrInvalidContract
	}
	destination, e := canonicalRaw(v.DestinationDescriptor)
	if e != nil {
		return e
	}
	d, e = SHA256(json.RawMessage(destination))
	if e != nil || d != v.DestinationHash {
		return ErrInvalidContract
	}
	return nil
}
func canonicalRaw(in json.RawMessage) ([]byte, error) {
	var v any
	if len(in) == 0 || json.Unmarshal(in, &v) != nil {
		return nil, ErrInvalidContract
	}
	return CanonicalJSON(v)
}

// DecodeStrict rejects trailing data and every unknown JSON object member.
func DecodeStrict[T any](data []byte, out *T) error {
	if out == nil {
		return errors.New("nil decode target")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if e := d.Decode(out); e != nil {
		return e
	}
	if e := d.Decode(new(any)); e != io.EOF {
		return errors.New("trailing JSON data")
	}
	return nil
}
