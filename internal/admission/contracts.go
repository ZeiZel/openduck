// Package admission contains the fail-closed seam between the Controller,
// DSH and the model runtimes. It deliberately has no transport or storage
// dependencies.
package admission

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
	SourceEventV1                       = "source-event.v1"
	AuthoritativeConversationSnapshotV1 = "authoritative-conversation-snapshot.v1"
	HighWaterBindingV1                  = "high-water-binding.v1"
	PrivacyDecisionV1                   = "privacy-decision.v1"
	CloudAdmittedPromptV1               = "cloud-admitted-prompt.v1"
	LocalPDDispatchV1                   = "local-pd-dispatch.v1"
	CloudAdmissionConsumptionV1         = "cloud-admission-consumption.v1"
	CloudAppendReceiptV1                = "cloud-append-receipt.v1"
	CloudEgressReservationV1            = "cloud-egress-reservation.v1"
	DSHDistributionAttestationV1        = "dsh-distribution-attestation.v1"
	UIChannelSessionV1                  = "ui-channel-session.v1"
	SafeCapsuleV1                       = "safe-capsule.v1"
	CanonicalizationV1                  = "canonical-json.v1"
)

var (
	ErrInvalidContract = errors.New("invalid admission contract")
	ErrUnknownVersion  = errors.New("unknown admission schema version")
	ErrCloudOnly       = errors.New("contract is cloud-only")
	ErrControllerOnly  = errors.New("contract is Controller-only")
)

type Classification string

const (
	L0 Classification = "L0"
	L1 Classification = "L1"
	L2 Classification = "L2"
	L3 Classification = "L3"
)

func (c Classification) valid() bool     { return c == L0 || c == L1 || c == L2 || c == L3 }
func (c Classification) cloudSafe() bool { return c == L0 || c == L1 }
func (c Classification) Valid() bool     { return c.valid() }

type SourceEvent struct {
	SchemaVersion     string    `json:"schema_version"`
	SourceKind        string    `json:"source_kind"`
	AccountID         string    `json:"account_id"`
	ContainerID       string    `json:"container_id"`
	ThreadID          string    `json:"thread_id"`
	EventID           string    `json:"event_id"`
	Revision          int64     `json:"revision"`
	EventType         string    `json:"event_type"`
	AuthorRef         string    `json:"author_ref"`
	SourceTime        time.Time `json:"source_time"`
	ObservedAt        time.Time `json:"observed_at"`
	Locator           string    `json:"locator"`
	ContentDigest     string    `json:"content_digest"`
	PayloadRef        string    `json:"payload_ref"`
	CoverageCursor    string    `json:"coverage_cursor"`
	AuthContextDigest string    `json:"auth_context_digest"`
	CarrierType       string    `json:"carrier_type"`
	CaptureQuality    string    `json:"capture_quality"`
	Digest            string    `json:"digest"`
}

type AuthoritativeConversationSnapshot struct {
	SchemaVersion               string         `json:"schema_version"`
	ConversationScope           string         `json:"conversation_scope"`
	EventRevisionSetDigest      string         `json:"event_revision_set_digest"`
	CompleteThroughWatermark    string         `json:"complete_through_watermark"`
	IngressGateStateDigest      string         `json:"ingress_gate_state_digest"`
	AuthoritativeCoverageDigest string         `json:"authoritative_coverage_digest"`
	ClassHighWater              Classification `json:"class_high_water"`
	ClassHighWaterVersion       int64          `json:"class_high_water_version"`
	Digest                      string         `json:"digest"`
}

type HighWaterBinding struct {
	SchemaVersion               string         `json:"schema_version"`
	ConversationScope           string         `json:"conversation_scope"`
	EventRevisionSetDigest      string         `json:"event_revision_set_digest"`
	CompleteThroughWatermark    string         `json:"complete_through_watermark"`
	IngressGateStateDigest      string         `json:"ingress_gate_state_digest"`
	AuthoritativeCoverageDigest string         `json:"authoritative_coverage_digest"`
	ClassHighWater              Classification `json:"class_high_water"`
	ClassHighWaterVersion       int64          `json:"class_high_water_version"`
	Digest                      string         `json:"digest"`
}

type PrivacyDecision struct {
	SchemaVersion               string         `json:"schema_version"`
	ConversationScope           string         `json:"conversation_scope"`
	EventDigest                 string         `json:"event_digest"`
	EventRevisionSetDigest      string         `json:"event_revision_set_digest"`
	CompleteThroughWatermark    string         `json:"complete_through_watermark"`
	IngressGateStateDigest      string         `json:"ingress_gate_state_digest"`
	AuthoritativeCoverageDigest string         `json:"authoritative_coverage_digest"`
	ClassHighWater              Classification `json:"class_high_water"`
	ClassHighWaterVersion       int64          `json:"class_high_water_version"`
	Detectors                   []string       `json:"detectors"`
	PDLatchID                   string         `json:"pd_latch_id"`
	Route                       string         `json:"route"`
	AllowedFields               []string       `json:"allowed_fields"`
	PolicyVersion               string         `json:"policy_version"`
	DecisionHash                string         `json:"decision_hash"`
}

// SafeCapsule is the only payload shape that a cloud admission may carry.
// It contains allowlisted scalar facts only; raw transcript, handles, URLs,
// attachments and history are intentionally not representable.
type SafeCapsule struct {
	SchemaVersion  string            `json:"schema_version"`
	Purpose        string            `json:"purpose"`
	Fields         map[string]string `json:"fields"`
	AllowedFields  []string          `json:"allowed_fields"`
	Constraints    []string          `json:"constraints"`
	Classification Classification    `json:"classification"`
	PostScanDigest string            `json:"post_scan_digest"`
	Digest         string            `json:"digest"`
}

type CloudAdmittedPrompt struct {
	SchemaVersion                          string         `json:"schema_version"`
	AdmissionID                            string         `json:"admission_id"`
	Nonce                                  string         `json:"nonce"`
	IssuedAt                               time.Time      `json:"issued_at"`
	ExpiresAt                              time.Time      `json:"expires_at"`
	MaxUses                                int            `json:"max_uses"`
	TargetSessionID                        string         `json:"target_session_id"`
	TargetCodexThreadID                    string         `json:"target_codex_thread_id"`
	ConversationScope                      string         `json:"conversation_scope"`
	EventRevisionSetDigest                 string         `json:"event_revision_set_digest"`
	CompleteThroughWatermark               string         `json:"complete_through_watermark"`
	IngressGateStateDigest                 string         `json:"ingress_gate_state_digest"`
	AuthoritativeCoverageDigest            string         `json:"authoritative_coverage_digest"`
	ClassHighWater                         Classification `json:"class_high_water"`
	ClassHighWaterVersion                  int64          `json:"class_high_water_version"`
	ContentDigest                          string         `json:"content_digest"`
	PrivacyDecisionDigest                  string         `json:"privacy_decision_digest"`
	PolicyDigest                           string         `json:"policy_digest"`
	SourceRefs                             []string       `json:"source_refs"`
	Classification                         Classification `json:"classification"`
	Route                                  string         `json:"route"`
	TargetRuntimeAttestationDigest         string         `json:"target_runtime_attestation_digest"`
	TargetDSHDistributionAttestationDigest string         `json:"target_dsh_distribution_attestation_digest"`
	TargetCodexProfileAttestationDigest    string         `json:"target_codex_profile_attestation_digest"`
	ModelClass                             string         `json:"model_class"`
	ModelTransportPolicyDigest             string         `json:"model_transport_policy_digest"`
	ToolsetDigest                          string         `json:"toolset_digest"`
	ToolNetworkPolicyDigest                string         `json:"tool_network_policy_digest"`
	DSHAppendStore                         string         `json:"dsh_append_store"`
	DSHAppendSchema                        string         `json:"dsh_append_schema"`
	IdempotencyKey                         string         `json:"idempotency_key"`
	ExpectedRunnerBinding                  string         `json:"expected_runner_binding"`
	SafeCapsule                            SafeCapsule    `json:"safe_capsule"`
	ControllerSignature                    string         `json:"controller_signature"`
	CanonicalizationVersion                string         `json:"canonicalization_version"`
	CanonicalizationDigest                 string         `json:"canonicalization_digest"`
	Digest                                 string         `json:"digest"`
}

type LocalPDDispatch struct {
	SchemaVersion                string         `json:"schema_version"`
	DispatchID                   string         `json:"dispatch_id"`
	Nonce                        string         `json:"nonce"`
	IssuedAt                     time.Time      `json:"issued_at"`
	ExpiresAt                    time.Time      `json:"expires_at"`
	PrivacyDecisionDigest        string         `json:"privacy_decision_digest"`
	ConversationScope            string         `json:"conversation_scope"`
	EventRevisionSetDigest       string         `json:"event_revision_set_digest"`
	ClassHighWater               Classification `json:"class_high_water"`
	ClassHighWaterVersion        int64          `json:"class_high_water_version"`
	PayloadRef                   string         `json:"payload_ref"`
	QwenModel                    string         `json:"qwen_model"`
	QwenRuntimeAttestationDigest string         `json:"qwen_runtime_attestation_digest"`
	QwenConfigDigest             string         `json:"qwen_config_digest"`
	LocalPDViewBindingDigest     string         `json:"local_pd_view_binding_digest"`
	ToolsNetworkPolicy           string         `json:"tools_network_policy"`
	Fallback                     string         `json:"fallback"`
	ControllerSignature          string         `json:"controller_signature"`
	Digest                       string         `json:"digest"`
}

type CloudAdmissionConsumption struct {
	SchemaVersion   string    `json:"schema_version"`
	AdmissionID     string    `json:"admission_id"`
	PromptDigest    string    `json:"prompt_digest"`
	AppendAttemptID string    `json:"append_attempt_id"`
	Destination     string    `json:"destination"`
	IdempotencyKey  string    `json:"idempotency_key"`
	State           string    `json:"state"`
	ConsumedAt      time.Time `json:"consumed_at"`
	Digest          string    `json:"digest"`
}

type CloudAppendReceipt struct {
	SchemaVersion           string    `json:"schema_version"`
	AdmissionID             string    `json:"admission_id"`
	PromptDigest            string    `json:"prompt_digest"`
	ContentDigest           string    `json:"content_digest"`
	DestinationStore        string    `json:"destination_store"`
	DestinationRecord       string    `json:"destination_record"`
	DestinationSchema       string    `json:"destination_schema"`
	ObservedAppendRevision  int64     `json:"observed_append_revision"`
	ObservedAt              time.Time `json:"observed_at"`
	SignerAttestationDigest string    `json:"signer_attestation_digest"`
	ReceiptSignature        string    `json:"receipt_signature"`
	Digest                  string    `json:"digest"`
}

type CloudEgressReservation struct {
	SchemaVersion                  string    `json:"schema_version"`
	ReservationID                  string    `json:"reservation_id"`
	AdmissionID                    string    `json:"admission_id"`
	ConsumptionDigest              string    `json:"consumption_digest"`
	AppendReceiptDigest            string    `json:"append_receipt_digest"`
	EgressNonce                    string    `json:"egress_nonce"`
	ReservedAt                     time.Time `json:"reserved_at"`
	ExpiresAt                      time.Time `json:"expires_at"`
	TargetRuntimeAttestationDigest string    `json:"target_runtime_attestation_digest"`
	TargetProfileAttestationDigest string    `json:"target_profile_attestation_digest"`
	ModelRoute                     string    `json:"model_route"`
	State                          string    `json:"state"`
	ControllerSignature            string    `json:"controller_signature"`
	Digest                         string    `json:"digest"`
}

type DSHDistributionAttestation struct {
	SchemaVersion           string    `json:"schema_version"`
	DistributionID          string    `json:"distribution_id"`
	Version                 string    `json:"version"`
	CommitDigest            string    `json:"commit_digest"`
	BundleDigest            string    `json:"bundle_digest"`
	ProfileDigest           string    `json:"profile_digest"`
	IngressForkDigest       string    `json:"ingress_fork_digest"`
	SchemaDigest            string    `json:"schema_digest"`
	AttestedAt              time.Time `json:"attested_at"`
	SignerAttestationDigest string    `json:"signer_attestation_digest"`
	Digest                  string    `json:"digest"`
}

type UIChannelSession struct {
	SchemaVersion               string    `json:"schema_version"`
	SessionID                   string    `json:"session_id"`
	ChannelID                   string    `json:"channel_id"`
	OriginDigest                string    `json:"origin_digest"`
	CSPDigest                   string    `json:"csp_digest"`
	IPCChannelDigest            string    `json:"ipc_channel_digest"`
	OpaqueHandleDigest          string    `json:"opaque_handle_digest"`
	IssuedAt                    time.Time `json:"issued_at"`
	ExpiresAt                   time.Time `json:"expires_at"`
	Ephemeral                   bool      `json:"ephemeral"`
	Persistent                  bool      `json:"persistent"`
	DSHSessionEvents            bool      `json:"dsh_session_events"`
	DSHBrowserStorage           bool      `json:"dsh_browser_storage"`
	ControllerAttestationDigest string    `json:"controller_attestation_digest"`
	Digest                      string    `json:"digest"`
}

func digestValid(s string) bool {
	if len(s) != 71 || !strings.HasPrefix(s, "sha256:") {
		return false
	}
	_, err := hex.DecodeString(s[7:])
	return err == nil
}
func nonempty(v ...string) bool {
	for _, s := range v {
		if strings.TrimSpace(s) == "" {
			return false
		}
	}
	return true
}
func nonemptyUnique(v []string) bool {
	if len(v) == 0 {
		return false
	}
	seen := make(map[string]struct{}, len(v))
	for _, s := range v {
		if strings.TrimSpace(s) == "" {
			return false
		}
		if _, ok := seen[s]; ok {
			return false
		}
		seen[s] = struct{}{}
	}
	return true
}
func timeWindow(issued, expires time.Time) bool {
	return !issued.IsZero() && !expires.IsZero() && expires.After(issued) && expires.Sub(issued) <= 24*time.Hour
}
func checkDigests(v ...string) bool {
	for _, d := range v {
		if !digestValid(d) {
			return false
		}
	}
	return true
}
func checkVersion(got, want string) error {
	if got != want {
		if strings.TrimSpace(got) == "" {
			return ErrInvalidContract
		}
		return ErrUnknownVersion
	}
	return nil
}
func validBase(v, want string, ds ...string) error {
	if err := checkVersion(v, want); err != nil {
		return err
	}
	if !checkDigests(ds...) {
		return fmt.Errorf("%w: invalid digest", ErrInvalidContract)
	}
	return nil
}

func (s SourceEvent) Validate() error {
	if err := validBase(s.SchemaVersion, SourceEventV1, s.ContentDigest, s.AuthContextDigest, s.Digest); err != nil {
		return err
	}
	if s.Revision < 1 || s.SourceTime.IsZero() || s.ObservedAt.IsZero() || !nonempty(s.SourceKind, s.AccountID, s.ContainerID, s.ThreadID, s.EventID, s.EventType, s.AuthorRef, s.Locator, s.PayloadRef, s.CoverageCursor, s.CarrierType, s.CaptureQuality) {
		return ErrInvalidContract
	}
	return nil
}
func (s AuthoritativeConversationSnapshot) Validate() error {
	return validateSnapshot(s.SchemaVersion, AuthoritativeConversationSnapshotV1, s.ConversationScope, s.EventRevisionSetDigest, s.CompleteThroughWatermark, s.IngressGateStateDigest, s.AuthoritativeCoverageDigest, s.ClassHighWater, s.ClassHighWaterVersion, s.Digest)
}
func (h HighWaterBinding) Validate() error {
	return validateSnapshot(h.SchemaVersion, HighWaterBindingV1, h.ConversationScope, h.EventRevisionSetDigest, h.CompleteThroughWatermark, h.IngressGateStateDigest, h.AuthoritativeCoverageDigest, h.ClassHighWater, h.ClassHighWaterVersion, h.Digest)
}
func validateSnapshot(v, want, scope, event, water, gate, cov string, class Classification, version int64, digest string) error {
	if err := validBase(v, want, event, gate, cov, digest); err != nil {
		return err
	}
	if !nonempty(scope, water) || !class.valid() || version < 1 {
		return ErrInvalidContract
	}
	return nil
}
func (p PrivacyDecision) Validate() error {
	if err := validBase(p.SchemaVersion, PrivacyDecisionV1, p.EventDigest, p.EventRevisionSetDigest, p.IngressGateStateDigest, p.AuthoritativeCoverageDigest, p.DecisionHash); err != nil {
		return err
	}
	if !nonempty(p.ConversationScope, p.CompleteThroughWatermark, p.PDLatchID, p.PolicyVersion) || !nonemptyUnique(p.Detectors) || !nonemptyUnique(p.AllowedFields) || !p.ClassHighWater.valid() || p.ClassHighWaterVersion < 1 || p.Route != "local_qwen" && p.Route != "safe_capsule" && p.Route != "quarantine" && p.Route != "deny" {
		return ErrInvalidContract
	}
	if p.Route == "safe_capsule" && !p.ClassHighWater.cloudSafe() {
		return ErrInvalidContract
	}
	if p.Route == "local_qwen" && p.ClassHighWater.cloudSafe() {
		return ErrInvalidContract
	}
	return nil
}
func (s SafeCapsule) Validate() error {
	if err := validBase(s.SchemaVersion, SafeCapsuleV1, s.PostScanDigest, s.Digest); err != nil {
		return err
	}
	if !nonempty(s.Purpose) || s.Classification.Valid() == false || !s.Classification.cloudSafe() || !nonemptyUnique(s.AllowedFields) || len(s.Fields) == 0 || s.Fields == nil || s.Constraints == nil || len(s.Fields) > 32 || len(s.Constraints) > 32 {
		return ErrInvalidContract
	}
	for key, value := range s.Fields {
		if !nonempty(key, value) {
			return ErrInvalidContract
		}
		keyLower := strings.ToLower(key)
		for _, forbidden := range []string{"raw", "transcript", "history", "attachment", "payload", "handle", "token", "secret", "url", "locator", "ref"} {
			if strings.Contains(keyLower, forbidden) {
				return ErrInvalidContract
			}
		}
		found := false
		for _, allowed := range s.AllowedFields {
			if key == allowed {
				found = true
				break
			}
		}
		valueLower := strings.ToLower(value)
		if !found || strings.Contains(valueLower, "quarantine://") || strings.Contains(valueLower, "://") || strings.Contains(valueLower, "attachment") || strings.Contains(valueLower, "transcript") || strings.Contains(valueLower, "locator") || strings.Contains(valueLower, "uri") {
			return ErrInvalidContract
		}
	}
	return nil
}
func (s SafeCapsule) canonicalBytes() ([]byte, error) {
	copy := s
	copy.Digest = ""
	return json.Marshal(copy)
}
func (s SafeCapsule) CanonicalBytes() ([]byte, error) { return s.canonicalBytes() }

// Validate is structural only. It never grants cloud admission; callers that
// need authority must use Admit with a trusted verifier and one-shot consumer.
func (p CloudAdmittedPrompt) Validate() error {
	if err := validBase(p.SchemaVersion, CloudAdmittedPromptV1, p.EventRevisionSetDigest, p.IngressGateStateDigest, p.AuthoritativeCoverageDigest, p.ContentDigest, p.PrivacyDecisionDigest, p.PolicyDigest, p.TargetRuntimeAttestationDigest, p.TargetDSHDistributionAttestationDigest, p.TargetCodexProfileAttestationDigest, p.ModelTransportPolicyDigest, p.ToolsetDigest, p.ToolNetworkPolicyDigest, p.ControllerSignature, p.CanonicalizationDigest, p.Digest); err != nil {
		return err
	}
	if !timeWindow(p.IssuedAt, p.ExpiresAt) || p.MaxUses != 1 || !nonempty(p.AdmissionID, p.Nonce, p.TargetSessionID, p.TargetCodexThreadID, p.ConversationScope, p.CompleteThroughWatermark, p.DSHAppendStore, p.DSHAppendSchema, p.IdempotencyKey, p.ExpectedRunnerBinding) || !nonemptyUnique(p.SourceRefs) || !p.Classification.cloudSafe() || !p.ClassHighWater.cloudSafe() || p.ClassHighWaterVersion < 1 || p.Route != "codex_cloud" || p.ModelClass != "codex" || p.CanonicalizationVersion != CanonicalizationV1 {
		return ErrCloudOnly
	}
	if err := p.SafeCapsule.Validate(); err != nil || p.SafeCapsule.Classification != p.Classification {
		return ErrCloudOnly
	}
	return nil
}
func (p LocalPDDispatch) Validate() error {
	if err := validBase(p.SchemaVersion, LocalPDDispatchV1, p.PrivacyDecisionDigest, p.EventRevisionSetDigest, p.QwenRuntimeAttestationDigest, p.QwenConfigDigest, p.LocalPDViewBindingDigest, p.ControllerSignature, p.Digest); err != nil {
		return err
	}
	if !timeWindow(p.IssuedAt, p.ExpiresAt) || !nonempty(p.DispatchID, p.Nonce, p.ConversationScope, p.PayloadRef, p.QwenModel) || !strings.HasPrefix(strings.ToLower(p.QwenModel), "qwen") || !p.ClassHighWater.valid() || p.ClassHighWater.Rank() < L2.Rank() || p.ClassHighWaterVersion < 1 || p.ToolsNetworkPolicy != "none" || p.Fallback != "none" {
		return ErrControllerOnly
	}
	return nil
}
func (p LocalPDDispatch) ValidateCloud() error { return ErrControllerOnly }
func (c CloudAdmissionConsumption) Validate() error {
	if err := validBase(c.SchemaVersion, CloudAdmissionConsumptionV1, c.PromptDigest, c.Digest); err != nil {
		return err
	}
	if !nonempty(c.AdmissionID, c.AppendAttemptID, c.Destination, c.IdempotencyKey) || c.State != "pending" && c.State != "consuming" && c.State != "consumed" && c.State != "uncertain" {
		return ErrInvalidContract
	}
	if c.State == "consumed" && !c.ConsumedAt.IsZero() {
		return nil
	}
	if c.State == "consumed" {
		return ErrInvalidContract
	}
	return nil
}
func (r CloudAppendReceipt) Validate() error {
	if err := validBase(r.SchemaVersion, CloudAppendReceiptV1, r.PromptDigest, r.ContentDigest, r.SignerAttestationDigest, r.ReceiptSignature, r.Digest); err != nil {
		return err
	}
	if !nonempty(r.AdmissionID, r.DestinationStore, r.DestinationRecord, r.DestinationSchema) || r.ObservedAppendRevision < 1 || r.ObservedAt.IsZero() {
		return ErrInvalidContract
	}
	return nil
}
func (r CloudEgressReservation) Validate() error {
	if err := validBase(r.SchemaVersion, CloudEgressReservationV1, r.ConsumptionDigest, r.AppendReceiptDigest, r.TargetRuntimeAttestationDigest, r.TargetProfileAttestationDigest, r.ControllerSignature, r.Digest); err != nil {
		return err
	}
	if !timeWindow(r.ReservedAt, r.ExpiresAt) || !nonempty(r.ReservationID, r.AdmissionID, r.EgressNonce) || r.ModelRoute != "codex_cloud" || r.State != "reserved" {
		return ErrInvalidContract
	}
	return nil
}
func (a DSHDistributionAttestation) Validate() error {
	if err := validBase(a.SchemaVersion, DSHDistributionAttestationV1, a.CommitDigest, a.BundleDigest, a.ProfileDigest, a.IngressForkDigest, a.SchemaDigest, a.SignerAttestationDigest, a.Digest); err != nil {
		return err
	}
	if !nonempty(a.DistributionID, a.Version) || a.AttestedAt.IsZero() {
		return ErrInvalidContract
	}
	return nil
}
func (s UIChannelSession) Validate() error {
	if err := validBase(s.SchemaVersion, UIChannelSessionV1, s.OriginDigest, s.CSPDigest, s.IPCChannelDigest, s.OpaqueHandleDigest, s.ControllerAttestationDigest, s.Digest); err != nil {
		return err
	}
	if !timeWindow(s.IssuedAt, s.ExpiresAt) || !nonempty(s.SessionID, s.ChannelID) || !s.Ephemeral || s.Persistent || s.DSHSessionEvents || s.DSHBrowserStorage {
		return ErrInvalidContract
	}
	return nil
}

func CanonicalDigest(v any) (string, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

type SignatureVerifier interface {
	Verify(message []byte, signature string) bool
}
type AdmissionConsumer interface {
	Consume(admissionID, nonce string) error
}

// Admit is the sole cloud-authority operation. Structural validation alone is
// deliberately insufficient: this verifies canonical bytes/signature and
// atomically consumes the admission nonce through the injected checker.
func (p CloudAdmittedPrompt) Admit(now time.Time, verifier SignatureVerifier, consumer AdmissionConsumer) error {
	if err := p.Validate(); err != nil {
		return err
	}
	if verifier == nil || consumer == nil || now.IsZero() || now.Before(p.IssuedAt) || !now.Before(p.ExpiresAt) {
		return ErrCloudOnly
	}
	capsuleBytes, err := p.SafeCapsule.canonicalBytes()
	if err != nil {
		return ErrCloudOnly
	}
	capsuleDigest, err := CanonicalDigest(json.RawMessage(capsuleBytes))
	if err != nil || capsuleDigest != p.ContentDigest {
		return ErrCloudOnly
	}
	canonVersionDigest, err := CanonicalDigest(p.CanonicalizationVersion)
	if err != nil || canonVersionDigest != p.CanonicalizationDigest {
		return ErrCloudOnly
	}
	unsigned := p
	unsigned.ControllerSignature = ""
	unsigned.Digest = ""
	canonical, err := json.Marshal(unsigned)
	if err != nil {
		return ErrCloudOnly
	}
	contractDigest, err := CanonicalDigest(json.RawMessage(canonical))
	if err != nil || contractDigest != p.Digest {
		return ErrCloudOnly
	}
	if !verifier.Verify(canonical, p.ControllerSignature) {
		return ErrCloudOnly
	}
	if err := consumer.Consume(p.AdmissionID, p.Nonce); err != nil {
		return ErrCloudOnly
	}
	return nil
}

func DecodeStrict(data []byte, out any) error {
	if err := rejectDuplicateAndNull(data); err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidContract, err)
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return fmt.Errorf("%w: trailing data", ErrInvalidContract)
	}
	return nil
}

func rejectDuplicateAndNull(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := scanJSONValue(dec); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidContract, err)
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return fmt.Errorf("%w: trailing data", ErrInvalidContract)
	}
	return nil
}
func scanJSONValue(dec *json.Decoder) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	switch v := tok.(type) {
	case nil:
		return errors.New("null is forbidden")
	case json.Delim:
		switch v {
		case '{':
			keys := map[string]struct{}{}
			for dec.More() {
				keyToken, keyErr := dec.Token()
				if keyErr != nil {
					return keyErr
				}
				key, ok := keyToken.(string)
				if !ok {
					return errors.New("object key is not string")
				}
				if _, exists := keys[key]; exists {
					return fmt.Errorf("duplicate key %q", key)
				}
				keys[key] = struct{}{}
				if err := scanJSONValue(dec); err != nil {
					return err
				}
			}
			_, err := dec.Token()
			return err
		case '[':
			for dec.More() {
				if err := scanJSONValue(dec); err != nil {
					return err
				}
			}
			_, err := dec.Token()
			return err
		default:
			return errors.New("unexpected delimiter")
		}
	}
	return nil
}

// Rank is intentionally unexported in normal use; this method exists solely
// to keep route validation independent from core's classification package.
func (c Classification) Rank() int {
	switch c {
	case L0:
		return 0
	case L1:
		return 1
	case L2:
		return 2
	case L3:
		return 3
	}
	return 99
}
