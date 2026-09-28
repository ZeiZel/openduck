// Package localpd contains the Controller-owned contracts for the local
// personal-data path. These values carry attestations and digests only; they
// deliberately do not model transcript text, attachments, payloads, or
// runtime handles.
package localpd

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"sync"
	"time"
)

const (
	IngressGateStateV1         = "ingress-gate-state.v1"
	PDSessionBindingV1         = "pd-session-binding.v1"
	LocalPDViewBindingV1       = "local-pd-view-binding.v1"
	QwenRuntimeAttestationV1   = "qwen-runtime-attestation.v1"
	QwenConfigAttestationV1    = "qwen-config-attestation.v1"
	NativeInputProvenanceV1    = "native-input-provenance.v1"
	DeclassificationDecisionV1 = "declassification-decision.v1"
	PostscanAttestationV1      = "postscan-attestation.v1"
	ReconciliationBindingV1    = "reconciliation-binding.v1"
	ErasureReceiptV1           = "erasure-receipt.v1"
	CanonicalizationV1         = "canonical-json.v1"
	MaxListItems               = 64
	MaxStringLength            = 512
)

var (
	ErrInvalidContract = errors.New("invalid local-pd contract")
	ErrUnknownVersion  = errors.New("unknown local-pd schema version")
	digestPattern      = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	identifierPattern  = regexp.MustCompile(`^[A-Za-z0-9_.:/-]{1,512}$`)
)

type IngressGateState struct {
	SchemaVersion               string    `json:"schema_version"`
	GateID                      string    `json:"gate_id"`
	State                       string    `json:"state"`
	StateVersion                uint64    `json:"state_version"`
	HighWater                   uint64    `json:"high_water"`
	SourceCursorDigest          string    `json:"source_cursor_digest"`
	PolicyDigest                string    `json:"policy_digest"`
	ControllerAttestationDigest string    `json:"controller_attestation_digest"`
	Nonce                       string    `json:"nonce"`
	IssuedAt                    time.Time `json:"issued_at"`
	ExpiresAt                   time.Time `json:"expires_at"`
	Digest                      string    `json:"digest"`
	ConversationScope           string    `json:"conversation_scope"`
	SourceSequence              uint64    `json:"source_sequence"`
	SourceVersion               uint64    `json:"source_version"`
	IngestOrdinal               uint64    `json:"ingest_ordinal"`
	ScannedThrough              uint64    `json:"scanned_through"`
	PriorComplete               bool      `json:"prior_complete"`
	ChainHeadDigest             string    `json:"chain_head_digest"`
	GapRanges                   []string  `json:"gap_ranges"`
	PendingParts                []string  `json:"pending_parts"`
	Mode                        string    `json:"mode"`
	PolicyVersion               string    `json:"policy_version"`
	PolicyUpdatedAt             time.Time `json:"policy_updated_at"`
	ControllerSignature         string    `json:"controller_signature"`
}

type PDSessionBinding struct {
	SchemaVersion         string    `json:"schema_version"`
	SessionID             string    `json:"session_id"`
	BindingVersion        uint64    `json:"binding_version"`
	HighWater             uint64    `json:"high_water"`
	IngressGateDigest     string    `json:"ingress_gate_digest"`
	LocalPDViewDigest     string    `json:"local_pd_view_digest"`
	QwenRuntimeDigest     string    `json:"qwen_runtime_digest"`
	QwenConfigDigest      string    `json:"qwen_config_digest"`
	Nonce                 string    `json:"nonce"`
	IssuedAt              time.Time `json:"issued_at"`
	ExpiresAt             time.Time `json:"expires_at"`
	ControllerSignature   string    `json:"controller_signature"`
	Digest                string    `json:"digest"`
	ConversationScope     string    `json:"conversation_scope"`
	SourceSequence        uint64    `json:"source_sequence"`
	SourceVersion         uint64    `json:"source_version"`
	ClassHighWater        string    `json:"class_high_water"`
	ClassHighWaterVersion uint64    `json:"class_high_water_version"`
	Sticky                bool      `json:"sticky"`
}

type LocalPDViewBinding struct {
	SchemaVersion       string    `json:"schema_version"`
	ViewID              string    `json:"view_id"`
	BindingVersion      uint64    `json:"binding_version"`
	HighWater           uint64    `json:"high_water"`
	SourceVersion       uint64    `json:"source_version"`
	SourceDigest        string    `json:"source_digest"`
	RedactionDigest     string    `json:"redaction_digest"`
	AllowedFields       []string  `json:"allowed_fields"`
	IssuedAt            time.Time `json:"issued_at"`
	ExpiresAt           time.Time `json:"expires_at"`
	Nonce               string    `json:"nonce"`
	Digest              string    `json:"digest"`
	ControllerSignature string    `json:"controller_signature"`
}

type QwenRuntimeAttestation struct {
	SchemaVersion       string    `json:"schema_version"`
	RuntimeID           string    `json:"runtime_id"`
	ProcessDigest       string    `json:"process_digest"`
	BinaryDigest        string    `json:"binary_digest"`
	Model               string    `json:"model"`
	EndpointDigest      string    `json:"endpoint_digest"`
	NetworkPolicy       string    `json:"network_policy"`
	ToolsPolicy         string    `json:"tools_policy"`
	AttestedAt          time.Time `json:"attested_at"`
	ExpiresAt           time.Time `json:"expires_at"`
	Nonce               string    `json:"nonce"`
	Digest              string    `json:"digest"`
	ControllerSignature string    `json:"controller_signature"`
}

type QwenConfigAttestation struct {
	SchemaVersion       string    `json:"schema_version"`
	ConfigID            string    `json:"config_id"`
	ConfigDigest        string    `json:"config_digest"`
	Model               string    `json:"model"`
	NumCtx              uint32    `json:"num_ctx"`
	ContextTokens       uint32    `json:"context_tokens"`
	Thinking            string    `json:"thinking"`
	NetworkPolicy       string    `json:"network_policy"`
	ToolsPolicy         string    `json:"tools_policy"`
	ConfigVersion       uint64    `json:"config_version"`
	IssuedAt            time.Time `json:"issued_at"`
	ExpiresAt           time.Time `json:"expires_at"`
	Nonce               string    `json:"nonce"`
	Digest              string    `json:"digest"`
	ControllerSignature string    `json:"controller_signature"`
}

type NativeInputProvenance struct {
	SchemaVersion               string    `json:"schema_version"`
	ProvenanceID                string    `json:"provenance_id"`
	SourceKind                  string    `json:"source_kind"`
	SourceAccountDigest         string    `json:"source_account_digest"`
	ContainerDigest             string    `json:"container_digest"`
	EventDigest                 string    `json:"event_digest"`
	CaptureRevision             uint64    `json:"capture_revision"`
	HighWater                   uint64    `json:"high_water"`
	SourceVersion               uint64    `json:"source_version"`
	ObservedAt                  time.Time `json:"observed_at"`
	ExpiresAt                   time.Time `json:"expires_at"`
	ControllerAttestationDigest string    `json:"controller_attestation_digest"`
	Digest                      string    `json:"digest"`
	ControllerSignature         string    `json:"controller_signature"`
}

type DeclassificationDecision struct {
	SchemaVersion             string    `json:"schema_version"`
	DecisionID                string    `json:"decision_id"`
	SessionBindingDigest      string    `json:"session_binding_digest"`
	FromClass                 string    `json:"from_class"`
	TargetClass               string    `json:"target_class"`
	Decision                  string    `json:"decision"`
	AllowedFields             []string  `json:"allowed_fields"`
	RationaleDigest           string    `json:"rationale_digest"`
	PolicyDigest              string    `json:"policy_digest"`
	IssuedAt                  time.Time `json:"issued_at"`
	ExpiresAt                 time.Time `json:"expires_at"`
	Nonce                     string    `json:"nonce"`
	ControllerSignature       string    `json:"controller_signature"`
	Digest                    string    `json:"digest"`
	InputDigest               string    `json:"input_digest"`
	CandidateDigest           string    `json:"candidate_digest"`
	ReleasedDigest            string    `json:"released_digest"`
	SourceOrigin              string    `json:"source_origin"`
	CandidateOrigin           string    `json:"candidate_origin"`
	PostscanAttestationDigest string    `json:"postscan_attestation_digest"`
	DestinationRoute          string    `json:"destination_route"`
	ProviderDigest            string    `json:"provider_digest"`
	AuthContextDigest         string    `json:"auth_context_digest"`
	RetentionPolicyDigest     string    `json:"retention_policy_digest"`
	PurposeDigest             string    `json:"purpose_digest"`
	ApproverID                string    `json:"approver_id"`
	RecentAuthProofDigest     string    `json:"recent_auth_proof_digest"`
	RecentAuthAt              time.Time `json:"recent_auth_at"`
	RequestedAt               time.Time `json:"requested_at"`
	ApprovedAt                time.Time `json:"approved_at"`
	LifecycleState            string    `json:"lifecycle_state"`
	MaxUses                   int       `json:"max_uses"`
	UseNonce                  string    `json:"use_nonce"`
	CASBindingDigest          string    `json:"cas_binding_digest"`
}

type ErasureReceipt struct {
	SchemaVersion           string    `json:"schema_version"`
	ReceiptID               string    `json:"receipt_id"`
	SessionBindingDigest    string    `json:"session_binding_digest"`
	TargetDigest            string    `json:"target_digest"`
	ErasureScope            string    `json:"erasure_scope"`
	ErasureVersion          uint64    `json:"erasure_version"`
	HighWater               uint64    `json:"high_water"`
	ObservedTargetVersion   uint64    `json:"observed_target_version"`
	ObservedTargetHighWater uint64    `json:"observed_target_high_water"`
	DeletedThroughHighWater uint64    `json:"deleted_through_high_water"`
	DeletionStatus          string    `json:"deletion_status"`
	VerificationMethod      string    `json:"verification_method"`
	CoverageComplete        bool      `json:"coverage_complete"`
	ErasedAt                time.Time `json:"erased_at"`
	ExpiresAt               time.Time `json:"expires_at"`
	DeletionEvidenceDigest  string    `json:"deletion_evidence_digest"`
	CoverageDigest          string    `json:"coverage_digest"`
	VerificationDigest      string    `json:"verification_digest"`
	ControllerSignature     string    `json:"controller_signature"`
	Digest                  string    `json:"digest"`
}

// PostscanAttestation is a Controller-signed claim about the exact candidate
// bytes that would be released. It carries no candidate content.
type PostscanAttestation struct {
	SchemaVersion       string    `json:"schema_version"`
	AttestationID       string    `json:"attestation_id"`
	ReleasedDigest      string    `json:"released_digest"`
	PolicyDigest        string    `json:"policy_digest"`
	ScannerDigest       string    `json:"scanner_digest"`
	PolicyVersion       uint64    `json:"policy_version"`
	ScannerVersion      uint64    `json:"scanner_version"`
	MaxClass            string    `json:"max_class"`
	MatchedRuleIDs      []string  `json:"matched_rule_ids"`
	Decision            string    `json:"decision"`
	IssuedAt            time.Time `json:"issued_at"`
	ExpiresAt           time.Time `json:"expires_at"`
	Nonce               string    `json:"nonce"`
	ControllerSignature string    `json:"controller_signature"`
	Digest              string    `json:"digest"`
}

// ReconciliationBinding is the only authority that can move a quarantined
// gate back to pd after complete coverage and gap closure. A PD-latched
// conversation can never return to normal.
type ReconciliationBinding struct {
	SchemaVersion          string    `json:"schema_version"`
	ReconciliationID       string    `json:"reconciliation_id"`
	GateID                 string    `json:"gate_id"`
	PriorQuarantineDigest  string    `json:"prior_quarantine_digest"`
	NextGateDigest         string    `json:"next_gate_digest"`
	CompleteCoverageDigest string    `json:"complete_coverage_digest"`
	GapClosureDigest       string    `json:"gap_closure_digest"`
	HighWater              uint64    `json:"high_water"`
	PolicyDigest           string    `json:"policy_digest"`
	PolicyVersion          string    `json:"policy_version"`
	TargetMode             string    `json:"target_mode"`
	CompleteCoverage       bool      `json:"complete_coverage"`
	GapsClosed             bool      `json:"gaps_closed"`
	IssuedAt               time.Time `json:"issued_at"`
	ExpiresAt              time.Time `json:"expires_at"`
	Nonce                  string    `json:"nonce"`
	ControllerSignature    string    `json:"controller_signature"`
	Digest                 string    `json:"digest"`
}

func validDigest(s string) bool { return digestPattern.MatchString(s) }
func validID(s string) bool     { return identifierPattern.MatchString(s) && len(s) <= MaxStringLength }
func nonempty(v ...string) bool {
	for _, s := range v {
		if !validID(s) {
			return false
		}
	}
	return true
}
func uniqueList(v []string) bool {
	if v == nil || len(v) == 0 || len(v) > MaxListItems {
		return false
	}
	seen := map[string]bool{}
	for _, s := range v {
		if !validID(s) || seen[s] {
			return false
		}
		seen[s] = true
	}
	return true
}
func boundedList(v []string) bool {
	if v == nil || len(v) > MaxListItems {
		return false
	}
	seen := map[string]bool{}
	for _, s := range v {
		if !validID(s) || seen[s] {
			return false
		}
		seen[s] = true
	}
	return true
}
func allDigest(v ...string) bool {
	for _, s := range v {
		if !validDigest(s) {
			return false
		}
	}
	return true
}
func utc(t time.Time) bool       { return !t.IsZero() && t.Location() == time.UTC && t.Nanosecond() == 0 }
func window(a, b time.Time) bool { return utc(a) && utc(b) && b.After(a) && b.Sub(a) <= 24*time.Hour }
func version(got, want string) error {
	if got == want {
		return nil
	}
	if got == "" {
		return ErrInvalidContract
	}
	return ErrUnknownVersion
}
func base(got, want string, d ...string) error {
	if err := version(got, want); err != nil {
		return err
	}
	if !allDigest(d...) {
		return fmt.Errorf("%w: digest", ErrInvalidContract)
	}
	return nil
}
func class(s string) bool { return s == "L0" || s == "L1" || s == "L2" || s == "L3" }

var sourceKindPattern = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,63}$`)

func validSourceKind(s string) bool {
	return sourceKindPattern.MatchString(s)
}

func (x IngressGateState) Validate() error {
	matrix := (x.Mode == "normal" && x.State == "open") || (x.Mode == "pd" && x.State == "local_only") || (x.Mode == "quarantine" && x.State == "quarantine") || (x.Mode == "closed" && x.State == "closed")
	complete := x.PriorComplete && len(x.GapRanges) == 0 && len(x.PendingParts) == 0
	return validateWindow(base(x.SchemaVersion, IngressGateStateV1, x.SourceCursorDigest, x.PolicyDigest, x.ControllerAttestationDigest, x.ChainHeadDigest, x.ControllerSignature, x.Digest), window(x.IssuedAt, x.ExpiresAt), nonempty(x.GateID, x.Nonce, x.ConversationScope, x.PolicyVersion), x.StateVersion > 0, x.HighWater > 0, x.SourceVersion > 0, x.SourceSequence > 0 && x.SourceSequence <= x.HighWater, x.IngestOrdinal > 0 && x.IngestOrdinal <= x.HighWater, x.ScannedThrough > 0 && x.ScannedThrough <= x.HighWater, matrix, utc(x.PolicyUpdatedAt), !x.PolicyUpdatedAt.After(x.IssuedAt), x.Mode != "normal" || complete)
}
func (x PDSessionBinding) Validate() error {
	return validateWindow(base(x.SchemaVersion, PDSessionBindingV1, x.IngressGateDigest, x.LocalPDViewDigest, x.QwenRuntimeDigest, x.QwenConfigDigest, x.ControllerSignature, x.Digest), window(x.IssuedAt, x.ExpiresAt), nonempty(x.SessionID, x.Nonce, x.ConversationScope), x.BindingVersion > 0, x.HighWater > 0, x.SourceVersion > 0, x.SourceSequence > 0 && x.SourceSequence <= x.HighWater, x.ClassHighWater == "L2" || x.ClassHighWater == "L3", x.ClassHighWaterVersion > 0, x.Sticky)
}
func (x LocalPDViewBinding) Validate() error {
	return validateWindow(base(x.SchemaVersion, LocalPDViewBindingV1, x.SourceDigest, x.RedactionDigest, x.ControllerSignature, x.Digest), window(x.IssuedAt, x.ExpiresAt), nonempty(x.ViewID, x.Nonce), uniqueList(x.AllowedFields), x.BindingVersion > 0, x.HighWater > 0, x.SourceVersion > 0)
}
func (x QwenRuntimeAttestation) Validate() error {
	return validateWindow(base(x.SchemaVersion, QwenRuntimeAttestationV1, x.ProcessDigest, x.BinaryDigest, x.EndpointDigest, x.ControllerSignature, x.Digest), window(x.AttestedAt, x.ExpiresAt), nonempty(x.RuntimeID, x.Model, x.Nonce), strings.HasPrefix(strings.ToLower(x.Model), "qwen"), x.NetworkPolicy == "none", x.ToolsPolicy == "none")
}
func (x QwenConfigAttestation) Validate() error {
	return validateWindow(base(x.SchemaVersion, QwenConfigAttestationV1, x.ConfigDigest, x.ControllerSignature, x.Digest), window(x.IssuedAt, x.ExpiresAt), nonempty(x.ConfigID, x.Model, x.Nonce), strings.HasPrefix(strings.ToLower(x.Model), "qwen"), x.NumCtx > 0 && x.ContextTokens > 0 && x.ContextTokens <= x.NumCtx, x.Thinking == "disabled" || x.Thinking == "low" || x.Thinking == "medium" || x.Thinking == "high", x.NetworkPolicy == "none", x.ToolsPolicy == "none", x.ConfigVersion > 0)
}
func (x NativeInputProvenance) Validate() error {
	return validateWindow(base(x.SchemaVersion, NativeInputProvenanceV1, x.SourceAccountDigest, x.ContainerDigest, x.EventDigest, x.ControllerAttestationDigest, x.ControllerSignature, x.Digest), window(x.ObservedAt, x.ExpiresAt), nonempty(x.ProvenanceID, x.SourceKind), validSourceKind(x.SourceKind), x.CaptureRevision > 0, x.HighWater > 0, x.SourceVersion > 0)
}
func (x DeclassificationDecision) Validate() error {
	ordered := utc(x.IssuedAt) && utc(x.RequestedAt) && utc(x.RecentAuthAt) && utc(x.ApprovedAt) && !x.RequestedAt.Before(x.IssuedAt) && !x.RecentAuthAt.Before(x.RequestedAt) && x.RecentAuthAt.Before(x.ApprovedAt) && x.ExpiresAt.After(x.ApprovedAt)
	return validateWindow(base(x.SchemaVersion, DeclassificationDecisionV1, x.SessionBindingDigest, x.RationaleDigest, x.PolicyDigest, x.ControllerSignature, x.Digest, x.InputDigest, x.CandidateDigest, x.ReleasedDigest, x.PostscanAttestationDigest, x.ProviderDigest, x.AuthContextDigest, x.RetentionPolicyDigest, x.PurposeDigest, x.RecentAuthProofDigest, x.CASBindingDigest), window(x.IssuedAt, x.ExpiresAt), nonempty(x.DecisionID, x.Nonce, x.SourceOrigin, x.CandidateOrigin, x.DestinationRoute, x.ApproverID, x.UseNonce), x.SourceOrigin == "owner_manual_blank_editor", x.CandidateOrigin == "owner_manual_blank_editor", class(x.FromClass), x.FromClass == "L2" || x.FromClass == "L3", x.TargetClass == "L0", x.Decision == "allow", uniqueList(x.AllowedFields), x.MaxUses == 1, x.LifecycleState == "approved", ordered)
}
func (x ErasureReceipt) Validate() error {
	return validateWindow(base(x.SchemaVersion, ErasureReceiptV1, x.SessionBindingDigest, x.TargetDigest, x.VerificationDigest, x.DeletionEvidenceDigest, x.CoverageDigest, x.ControllerSignature, x.Digest), window(x.ErasedAt, x.ExpiresAt), nonempty(x.ReceiptID), x.ErasureScope == "view" || x.ErasureScope == "payload", x.ErasureVersion > 0, x.ObservedTargetVersion > 0, x.HighWater > 0, x.ObservedTargetHighWater == x.HighWater, x.DeletedThroughHighWater == x.ObservedTargetHighWater, x.DeletionStatus == "deleted", x.VerificationMethod == "authoritative_store_absence", x.CoverageComplete)
}
func (x PostscanAttestation) Validate() error {
	return validateWindow(base(x.SchemaVersion, PostscanAttestationV1, x.ReleasedDigest, x.PolicyDigest, x.ScannerDigest, x.ControllerSignature, x.Digest), window(x.IssuedAt, x.ExpiresAt), nonempty(x.AttestationID, x.Nonce), x.PolicyVersion > 0, x.ScannerVersion > 0, x.MaxClass == "L0", boundedList(x.MatchedRuleIDs), x.Decision == "allow")
}
func (x ReconciliationBinding) Validate() error {
	return validateWindow(base(x.SchemaVersion, ReconciliationBindingV1, x.PriorQuarantineDigest, x.NextGateDigest, x.CompleteCoverageDigest, x.GapClosureDigest, x.PolicyDigest, x.ControllerSignature, x.Digest), window(x.IssuedAt, x.ExpiresAt), nonempty(x.ReconciliationID, x.GateID, x.PolicyVersion, x.Nonce), x.HighWater > 0, x.TargetMode == "pd", x.CompleteCoverage, x.GapsClosed)
}
func validateWindow(err error, ok ...bool) error {
	if err != nil {
		return err
	}
	for _, v := range ok {
		if !v {
			return ErrInvalidContract
		}
	}
	return nil
}
func validateSimple(err error, ok ...bool) error { return validateWindow(err, ok...) }

func CanonicalDigest(v any) (string, error) {
	b, e := json.Marshal(v)
	if e != nil {
		return "", e
	}
	h := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(h[:]), nil
}

// AuthorityMetadata is passed to the durable consumer so it can atomically
// enforce stream monotonicity. A successfully validated struct is still only
// data; VerifyAuthoritative is the authority boundary.
type AuthorityMetadata struct {
	StreamID  string
	Version   uint64
	HighWater uint64
	IssuedAt  time.Time
	ExpiresAt time.Time
}

type AuthoritativeContract interface {
	Validate() error
	CanonicalUnsigned() ([]byte, error)
	AuthorityMetadata() AuthorityMetadata
	AuthoritySignature() string
	AuthorityDigest() string
}

type SignatureVerifier interface {
	Verify(unsignedCanonical []byte, signature string) bool
}

// MonotonicAuthorityConsumer must atomically reject replayed, stale, or
// conflicting metadata before committing value. The complete typed value is
// supplied so implementations cannot accidentally authorize a detached
// digest.
type MonotonicAuthorityConsumer[T AuthoritativeContract] interface {
	ConsumeIfMonotonic(value T, metadata AuthorityMetadata) error
}

func VerifyAuthoritative[T AuthoritativeContract](now time.Time, value T, verifier SignatureVerifier, consumer MonotonicAuthorityConsumer[T]) error {
	// Gate and session authority has additional state-machine invariants and
	// must not bypass their type-specific CAS boundaries.
	switch any(value).(type) {
	case IngressGateState, PDSessionBinding:
		return ErrInvalidContract
	}
	meta, err := verifyAuthorityOnly(now, value, verifier)
	if err != nil || consumer == nil {
		return ErrInvalidContract
	}
	if err := consumer.ConsumeIfMonotonic(value, meta); err != nil {
		return fmt.Errorf("%w: monotonic consume", ErrInvalidContract)
	}
	return nil
}

func verifyAuthorityOnly[T AuthoritativeContract](now time.Time, value T, verifier SignatureVerifier) (AuthorityMetadata, error) {
	if verifier == nil || !utc(now) || value.Validate() != nil {
		return AuthorityMetadata{}, ErrInvalidContract
	}
	meta := value.AuthorityMetadata()
	if !validID(meta.StreamID) || meta.Version == 0 || meta.HighWater == 0 || !window(meta.IssuedAt, meta.ExpiresAt) || now.Before(meta.IssuedAt) || !now.Before(meta.ExpiresAt) {
		return AuthorityMetadata{}, ErrInvalidContract
	}
	unsigned, err := value.CanonicalUnsigned()
	if err != nil {
		return AuthorityMetadata{}, ErrInvalidContract
	}
	digest, err := CanonicalDigest(json.RawMessage(unsigned))
	if err != nil || digest != value.AuthorityDigest() || !verifier.Verify(unsigned, value.AuthoritySignature()) {
		return AuthorityMetadata{}, ErrInvalidContract
	}
	return meta, nil
}

// IngressGateTransitionConsumer exposes an atomic compare-and-swap boundary.
// Load is advisory; ConsumeGateCAS must compare expectedDigest again while
// holding its durable lock.
type IngressGateTransitionConsumer interface {
	LoadGate(gateID string) (IngressGateState, bool, error)
	ConsumeGateCAS(expectedDigest string, next IngressGateState, metadata AuthorityMetadata) error
}

func VerifyIngressGateTransition(now time.Time, next IngressGateState, verifier SignatureVerifier, consumer IngressGateTransitionConsumer) error {
	meta, err := verifyAuthorityOnly(now, next, verifier)
	if err != nil || consumer == nil {
		return ErrInvalidContract
	}
	previous, found, err := consumer.LoadGate(next.GateID)
	if err != nil {
		return ErrInvalidContract
	}
	expected := ""
	if found {
		expected = previous.Digest
		if !validGateProgress(previous, next) || gateModeRank(next.Mode) < gateModeRank(previous.Mode) {
			return ErrInvalidContract
		}
	}
	if err := consumer.ConsumeGateCAS(expected, next, meta); err != nil {
		return fmt.Errorf("%w: gate CAS", ErrInvalidContract)
	}
	return nil
}

func validGateProgress(previous, next IngressGateState) bool {
	return previous.Validate() == nil && next.StateVersion > previous.StateVersion && next.HighWater >= previous.HighWater && next.SourceSequence >= previous.SourceSequence && next.SourceVersion >= previous.SourceVersion && next.IngestOrdinal >= previous.IngestOrdinal && next.ScannedThrough >= previous.ScannedThrough
}

func VerifyReconciledIngressGateTransition(now time.Time, next IngressGateState, reconciliation ReconciliationBinding, verifier SignatureVerifier, consumer IngressGateTransitionConsumer) error {
	meta, err := verifyAuthorityOnly(now, next, verifier)
	if err != nil || consumer == nil {
		return ErrInvalidContract
	}
	if _, err := verifyAuthorityOnly(now, reconciliation, verifier); err != nil {
		return ErrInvalidContract
	}
	previous, found, err := consumer.LoadGate(next.GateID)
	if err != nil || !found || previous.Mode != "quarantine" || !validGateProgress(previous, next) {
		return ErrInvalidContract
	}
	if next.Mode != "pd" || !next.PriorComplete || len(next.GapRanges) != 0 || len(next.PendingParts) != 0 || reconciliation.GateID != next.GateID || reconciliation.PriorQuarantineDigest != previous.Digest || reconciliation.NextGateDigest != next.Digest || reconciliation.HighWater != next.HighWater || reconciliation.PolicyDigest != next.PolicyDigest || reconciliation.PolicyVersion != next.PolicyVersion || reconciliation.TargetMode != next.Mode || !reconciliation.CompleteCoverage || !reconciliation.GapsClosed {
		return ErrInvalidContract
	}
	if err := consumer.ConsumeGateCAS(previous.Digest, next, meta); err != nil {
		return fmt.Errorf("%w: reconciled gate CAS", ErrInvalidContract)
	}
	return nil
}

func gateModeRank(mode string) int {
	switch mode {
	case "normal":
		return 0
	case "pd":
		return 1
	case "quarantine":
		return 2
	case "closed":
		return 3
	default:
		return -1
	}
}

type PDSessionTransitionConsumer interface {
	LoadSession(sessionID string) (PDSessionBinding, bool, error)
	ConsumeSessionCAS(expectedDigest string, next PDSessionBinding, metadata AuthorityMetadata) error
}

func VerifyPDSessionTransition(now time.Time, next PDSessionBinding, verifier SignatureVerifier, consumer PDSessionTransitionConsumer) error {
	meta, err := verifyAuthorityOnly(now, next, verifier)
	if err != nil || consumer == nil {
		return ErrInvalidContract
	}
	previous, found, err := consumer.LoadSession(next.SessionID)
	if err != nil {
		return ErrInvalidContract
	}
	expected := ""
	if found {
		expected = previous.Digest
		classChanged := next.ClassHighWater != previous.ClassHighWater
		if previous.Validate() != nil || next.BindingVersion <= previous.BindingVersion || next.HighWater < previous.HighWater || next.SourceSequence < previous.SourceSequence || next.SourceVersion < previous.SourceVersion || classRank(next.ClassHighWater) < classRank(previous.ClassHighWater) || next.ClassHighWaterVersion < previous.ClassHighWaterVersion || (classChanged && next.ClassHighWaterVersion == previous.ClassHighWaterVersion) {
			return ErrInvalidContract
		}
	}
	if err := consumer.ConsumeSessionCAS(expected, next, meta); err != nil {
		return fmt.Errorf("%w: session CAS", ErrInvalidContract)
	}
	return nil
}

func classRank(class string) int {
	switch class {
	case "L0":
		return 0
	case "L1":
		return 1
	case "L2":
		return 2
	case "L3":
		return 3
	default:
		return -1
	}
}

func unsigned(v any) ([]byte, error) { return json.Marshal(v) }

func (x IngressGateState) CanonicalUnsigned() ([]byte, error) {
	x.ControllerSignature, x.Digest = "", ""
	return unsigned(x)
}
func (x IngressGateState) AuthorityMetadata() AuthorityMetadata {
	return AuthorityMetadata{x.GateID, x.StateVersion, x.HighWater, x.IssuedAt, x.ExpiresAt}
}
func (x IngressGateState) AuthoritySignature() string { return x.ControllerSignature }
func (x IngressGateState) AuthorityDigest() string    { return x.Digest }

func (x PDSessionBinding) CanonicalUnsigned() ([]byte, error) {
	x.ControllerSignature, x.Digest = "", ""
	return unsigned(x)
}
func (x PDSessionBinding) AuthorityMetadata() AuthorityMetadata {
	return AuthorityMetadata{x.SessionID, x.BindingVersion, x.HighWater, x.IssuedAt, x.ExpiresAt}
}
func (x PDSessionBinding) AuthoritySignature() string { return x.ControllerSignature }
func (x PDSessionBinding) AuthorityDigest() string    { return x.Digest }

func (x LocalPDViewBinding) CanonicalUnsigned() ([]byte, error) {
	x.ControllerSignature, x.Digest = "", ""
	return unsigned(x)
}
func (x LocalPDViewBinding) AuthorityMetadata() AuthorityMetadata {
	return AuthorityMetadata{x.ViewID, x.BindingVersion, x.HighWater, x.IssuedAt, x.ExpiresAt}
}
func (x LocalPDViewBinding) AuthoritySignature() string { return x.ControllerSignature }
func (x LocalPDViewBinding) AuthorityDigest() string    { return x.Digest }

func (x QwenRuntimeAttestation) CanonicalUnsigned() ([]byte, error) {
	x.ControllerSignature, x.Digest = "", ""
	return unsigned(x)
}
func (x QwenRuntimeAttestation) AuthorityMetadata() AuthorityMetadata {
	return AuthorityMetadata{x.RuntimeID, 1, 1, x.AttestedAt, x.ExpiresAt}
}
func (x QwenRuntimeAttestation) AuthoritySignature() string { return x.ControllerSignature }
func (x QwenRuntimeAttestation) AuthorityDigest() string    { return x.Digest }

func (x QwenConfigAttestation) CanonicalUnsigned() ([]byte, error) {
	x.ControllerSignature, x.Digest = "", ""
	return unsigned(x)
}
func (x QwenConfigAttestation) AuthorityMetadata() AuthorityMetadata {
	return AuthorityMetadata{x.ConfigID, x.ConfigVersion, x.ConfigVersion, x.IssuedAt, x.ExpiresAt}
}
func (x QwenConfigAttestation) AuthoritySignature() string { return x.ControllerSignature }
func (x QwenConfigAttestation) AuthorityDigest() string    { return x.Digest }

func (x NativeInputProvenance) CanonicalUnsigned() ([]byte, error) {
	x.ControllerSignature, x.Digest = "", ""
	return unsigned(x)
}
func (x NativeInputProvenance) AuthorityMetadata() AuthorityMetadata {
	return AuthorityMetadata{x.ProvenanceID, x.CaptureRevision, x.HighWater, x.ObservedAt, x.ExpiresAt}
}
func (x NativeInputProvenance) AuthoritySignature() string { return x.ControllerSignature }
func (x NativeInputProvenance) AuthorityDigest() string    { return x.Digest }

func (x ErasureReceipt) CanonicalUnsigned() ([]byte, error) {
	x.ControllerSignature, x.Digest = "", ""
	return unsigned(x)
}
func (x ErasureReceipt) AuthorityMetadata() AuthorityMetadata {
	return AuthorityMetadata{x.ReceiptID, x.ErasureVersion, x.HighWater, x.ErasedAt, x.ExpiresAt}
}
func (x ErasureReceipt) AuthoritySignature() string { return x.ControllerSignature }
func (x ErasureReceipt) AuthorityDigest() string    { return x.Digest }

func (x PostscanAttestation) CanonicalUnsigned() ([]byte, error) {
	x.ControllerSignature, x.Digest = "", ""
	return unsigned(x)
}
func (x PostscanAttestation) AuthorityMetadata() AuthorityMetadata {
	return AuthorityMetadata{x.AttestationID, x.ScannerVersion, x.PolicyVersion, x.IssuedAt, x.ExpiresAt}
}
func (x PostscanAttestation) AuthoritySignature() string { return x.ControllerSignature }
func (x PostscanAttestation) AuthorityDigest() string    { return x.Digest }

func (x ReconciliationBinding) CanonicalUnsigned() ([]byte, error) {
	x.ControllerSignature, x.Digest = "", ""
	return unsigned(x)
}
func (x ReconciliationBinding) AuthorityMetadata() AuthorityMetadata {
	return AuthorityMetadata{x.ReconciliationID, 1, x.HighWater, x.IssuedAt, x.ExpiresAt}
}
func (x ReconciliationBinding) AuthoritySignature() string { return x.ControllerSignature }
func (x ReconciliationBinding) AuthorityDigest() string    { return x.Digest }

// DeclassificationAuthority is the only path that can turn a structural
// decision into an effective release. Validate deliberately remains
// structural and never grants authority.
type DeclassificationVerifier = SignatureVerifier
type PostscanResolver interface {
	ResolvePostscan(attestationDigest string) (PostscanAttestation, error)
}
type DeclassificationConsumer interface {
	ConsumeOneUseCAS(DeclassificationDecision, DeclassificationCASExpectation) error
}
type DeclassificationCASExpectation struct {
	DecisionID     string
	UseNonce       string
	DecisionDigest string
	LifecycleState string
}

func (x DeclassificationDecision) CanonicalUnsigned() ([]byte, error) {
	u := x
	u.ControllerSignature = ""
	u.Digest = ""
	return json.Marshal(u)
}
func (x DeclassificationDecision) Authorize(now time.Time, verifier DeclassificationVerifier, resolver PostscanResolver, consumer DeclassificationConsumer) error {
	if err := x.Validate(); err != nil || verifier == nil || resolver == nil || consumer == nil || !utc(now) || now.Before(x.ApprovedAt) || !now.Before(x.ExpiresAt) || now.Sub(x.RecentAuthAt) < 0 || now.Sub(x.RecentAuthAt) > 15*time.Minute {
		return ErrInvalidContract
	}
	b, err := x.CanonicalUnsigned()
	if err != nil {
		return ErrInvalidContract
	}
	d, err := CanonicalDigest(json.RawMessage(b))
	if err != nil || d != x.Digest || !verifier.Verify(b, x.ControllerSignature) {
		return ErrInvalidContract
	}
	postscan, err := resolver.ResolvePostscan(x.PostscanAttestationDigest)
	if err != nil || postscan.Digest != x.PostscanAttestationDigest || postscan.ReleasedDigest != x.ReleasedDigest || postscan.PolicyDigest != x.PolicyDigest {
		return ErrInvalidContract
	}
	if _, err := verifyAuthorityOnly(now, postscan, verifier); err != nil {
		return ErrInvalidContract
	}
	expected := DeclassificationCASExpectation{DecisionID: x.DecisionID, UseNonce: x.UseNonce, DecisionDigest: x.Digest, LifecycleState: x.LifecycleState}
	if err := consumer.ConsumeOneUseCAS(x, expected); err != nil {
		return ErrInvalidContract
	}
	return nil
}

// MemoryDeclassificationConsumer is a reference one-process CAS consumer for
// tests and synthetic mode. Durable deployments must provide a transactional
// implementation with the same one-use behavior.
type MemoryDeclassificationConsumer struct {
	mu   sync.Mutex
	used map[string]declassificationUse
}

type declassificationUse struct {
	UseNonce       string
	DecisionDigest string
	LifecycleState string
}

func NewMemoryDeclassificationConsumer() *MemoryDeclassificationConsumer {
	return &MemoryDeclassificationConsumer{used: make(map[string]declassificationUse)}
}

func (c *MemoryDeclassificationConsumer) ConsumeOneUseCAS(x DeclassificationDecision, expected DeclassificationCASExpectation) error {
	if c == nil || x.Validate() != nil || expected.DecisionID != x.DecisionID || expected.UseNonce != x.UseNonce || expected.DecisionDigest != x.Digest || expected.LifecycleState != x.LifecycleState {
		return ErrInvalidContract
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, exists := c.used[x.DecisionID]; exists {
		return ErrInvalidContract
	}
	c.used[x.DecisionID] = declassificationUse{UseNonce: x.UseNonce, DecisionDigest: x.Digest, LifecycleState: x.LifecycleState}
	return nil
}

func DecodeStrict(data []byte, out any) error {
	if err := scan(data); err != nil {
		return err
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(out); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidContract, err)
	}
	var extra any
	if err := d.Decode(&extra); err != io.EOF {
		return fmt.Errorf("%w: trailing data", ErrInvalidContract)
	}
	return nil
}
func scan(data []byte) error {
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	if err := scanValue(d); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidContract, err)
	}
	var x any
	if err := d.Decode(&x); err != io.EOF {
		return fmt.Errorf("%w: trailing data", ErrInvalidContract)
	}
	return nil
}
func scanValue(d *json.Decoder) error {
	t, e := d.Token()
	if e != nil {
		return e
	}
	if t == nil {
		return errors.New("null is forbidden")
	}
	if q, ok := t.(json.Delim); ok {
		switch q {
		case '{':
			seen := map[string]bool{}
			for d.More() {
				k, e := d.Token()
				if e != nil {
					return e
				}
				s, ok := k.(string)
				if !ok || seen[s] {
					return errors.New("duplicate or invalid object key")
				}
				seen[s] = true
				if e := scanValue(d); e != nil {
					return e
				}
			}
			_, e = d.Token()
			return e
		case '[':
			for d.More() {
				if e := scanValue(d); e != nil {
					return e
				}
			}
			_, e = d.Token()
			return e
		default:
			return errors.New("unexpected delimiter")
		}
	}
	return nil
}
