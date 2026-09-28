package localpd

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const testDigest = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func testWindow() (time.Time, time.Time) {
	a := time.Date(2026, 8, 19, 10, 0, 0, 0, time.UTC)
	return a, a.Add(30 * time.Minute)
}

func validContracts() []interface{ Validate() error } {
	a, b := testWindow()
	return []interface{ Validate() error }{
		IngressGateState{SchemaVersion: IngressGateStateV1, GateID: "gate-1", State: "local_only", StateVersion: 1, HighWater: 1, SourceCursorDigest: testDigest, PolicyDigest: testDigest, ControllerAttestationDigest: testDigest, ChainHeadDigest: testDigest, ControllerSignature: testDigest, ConversationScope: "scope", SourceSequence: 1, SourceVersion: 1, IngestOrdinal: 1, ScannedThrough: 1, PriorComplete: true, GapRanges: []string{}, PendingParts: []string{}, Mode: "pd", PolicyVersion: "p1", PolicyUpdatedAt: a.Add(-time.Minute), Nonce: "nonce-1", IssuedAt: a, ExpiresAt: b, Digest: testDigest},
		PDSessionBinding{SchemaVersion: PDSessionBindingV1, SessionID: "session-1", BindingVersion: 1, HighWater: 1, IngressGateDigest: testDigest, LocalPDViewDigest: testDigest, QwenRuntimeDigest: testDigest, QwenConfigDigest: testDigest, ConversationScope: "scope", SourceSequence: 1, SourceVersion: 1, ClassHighWater: "L2", ClassHighWaterVersion: 1, Sticky: true, Nonce: "nonce-1", IssuedAt: a, ExpiresAt: b, ControllerSignature: testDigest, Digest: testDigest},
		LocalPDViewBinding{SchemaVersion: LocalPDViewBindingV1, ViewID: "view-1", BindingVersion: 1, HighWater: 1, SourceVersion: 1, SourceDigest: testDigest, RedactionDigest: testDigest, AllowedFields: []string{"summary"}, IssuedAt: a, ExpiresAt: b, Nonce: "nonce-1", ControllerSignature: testDigest, Digest: testDigest},
		QwenRuntimeAttestation{SchemaVersion: QwenRuntimeAttestationV1, RuntimeID: "runtime-1", ProcessDigest: testDigest, BinaryDigest: testDigest, Model: "qwen3:8b", EndpointDigest: testDigest, NetworkPolicy: "none", ToolsPolicy: "none", AttestedAt: a, ExpiresAt: b, Nonce: "nonce-1", ControllerSignature: testDigest, Digest: testDigest},
		QwenConfigAttestation{SchemaVersion: QwenConfigAttestationV1, ConfigID: "config-1", ConfigDigest: testDigest, Model: "qwen3:8b", NumCtx: 40960, ContextTokens: 32768, Thinking: "medium", NetworkPolicy: "none", ToolsPolicy: "none", ConfigVersion: 1, IssuedAt: a, ExpiresAt: b, Nonce: "nonce-1", ControllerSignature: testDigest, Digest: testDigest},
		NativeInputProvenance{SchemaVersion: NativeInputProvenanceV1, ProvenanceID: "prov-1", SourceKind: "telegram", SourceAccountDigest: testDigest, ContainerDigest: testDigest, EventDigest: testDigest, CaptureRevision: 1, HighWater: 1, SourceVersion: 1, ObservedAt: a, ExpiresAt: b, ControllerAttestationDigest: testDigest, ControllerSignature: testDigest, Digest: testDigest},
		DeclassificationDecision{SchemaVersion: DeclassificationDecisionV1, DecisionID: "decision-1", SessionBindingDigest: testDigest, FromClass: "L2", TargetClass: "L0", Decision: "allow", AllowedFields: []string{"summary"}, RationaleDigest: testDigest, PolicyDigest: testDigest, IssuedAt: a, ExpiresAt: b, Nonce: "nonce-1", ControllerSignature: testDigest, Digest: testDigest, InputDigest: testDigest, CandidateDigest: testDigest, ReleasedDigest: testDigest, SourceOrigin: "owner_manual_blank_editor", CandidateOrigin: "owner_manual_blank_editor", PostscanAttestationDigest: testDigest, DestinationRoute: "local", ProviderDigest: testDigest, AuthContextDigest: testDigest, RetentionPolicyDigest: testDigest, PurposeDigest: testDigest, ApproverID: "owner", RecentAuthProofDigest: testDigest, RequestedAt: a, RecentAuthAt: a.Add(time.Minute), ApprovedAt: a.Add(2 * time.Minute), LifecycleState: "approved", MaxUses: 1, UseNonce: "use-1", CASBindingDigest: testDigest},
		ErasureReceipt{SchemaVersion: ErasureReceiptV1, ReceiptID: "receipt-1", SessionBindingDigest: testDigest, TargetDigest: testDigest, ErasureScope: "payload", ErasureVersion: 1, HighWater: 1, ObservedTargetVersion: 1, ObservedTargetHighWater: 1, DeletedThroughHighWater: 1, DeletionStatus: "deleted", VerificationMethod: "authoritative_store_absence", CoverageComplete: true, ErasedAt: a, ExpiresAt: b, DeletionEvidenceDigest: testDigest, CoverageDigest: testDigest, VerificationDigest: testDigest, ControllerSignature: testDigest, Digest: testDigest},
		PostscanAttestation{SchemaVersion: PostscanAttestationV1, AttestationID: "postscan-1", ReleasedDigest: testDigest, PolicyDigest: testDigest, ScannerDigest: testDigest, PolicyVersion: 1, ScannerVersion: 1, MaxClass: "L0", MatchedRuleIDs: []string{}, Decision: "allow", IssuedAt: a, ExpiresAt: b, Nonce: "postscan-nonce", ControllerSignature: testDigest, Digest: testDigest},
		ReconciliationBinding{SchemaVersion: ReconciliationBindingV1, ReconciliationID: "reconcile-1", GateID: "gate-1", PriorQuarantineDigest: testDigest, NextGateDigest: testDigest, CompleteCoverageDigest: testDigest, GapClosureDigest: testDigest, HighWater: 1, PolicyDigest: testDigest, PolicyVersion: "p1", TargetMode: "pd", CompleteCoverage: true, GapsClosed: true, IssuedAt: a, ExpiresAt: b, Nonce: "reconcile-nonce", ControllerSignature: testDigest, Digest: testDigest},
	}
}

func TestContractsValidate(t *testing.T) {
	for i, c := range validContracts() {
		if err := c.Validate(); err != nil {
			t.Fatalf("contract %d: %v", i, err)
		}
	}
}

func TestNativeInputProvenanceAcceptsGenericSourceKinds(t *testing.T) {
	a, b := testWindow()
	for _, kind := range []string{"enterprise_chat", "custom_source.v1", "telegram"} {
		p := NativeInputProvenance{SchemaVersion: NativeInputProvenanceV1, ProvenanceID: "prov-1", SourceKind: kind, SourceAccountDigest: testDigest, ContainerDigest: testDigest, EventDigest: testDigest, CaptureRevision: 1, HighWater: 1, SourceVersion: 1, ObservedAt: a, ExpiresAt: b, ControllerAttestationDigest: testDigest, ControllerSignature: testDigest, Digest: testDigest}
		if err := p.Validate(); err != nil {
			t.Fatalf("%s: %v", kind, err)
		}
	}
	for _, kind := range []string{"X" + "5Rooms", "bad source", "https://example.invalid"} {
		p := NativeInputProvenance{SchemaVersion: NativeInputProvenanceV1, ProvenanceID: "prov-1", SourceKind: kind, SourceAccountDigest: testDigest, ContainerDigest: testDigest, EventDigest: testDigest, CaptureRevision: 1, HighWater: 1, SourceVersion: 1, ObservedAt: a, ExpiresAt: b, ControllerAttestationDigest: testDigest, ControllerSignature: testDigest, Digest: testDigest}
		if err := p.Validate(); err == nil {
			t.Fatalf("accepted %s", kind)
		}
	}
}

func TestStrictDecodeRejectsUnknownNullDuplicateTrailingAndMissing(t *testing.T) {
	b, err := json.Marshal(validContracts()[0])
	if err != nil {
		t.Fatal(err)
	}
	inputs := []string{strings.TrimSuffix(string(b), "}") + `,"unexpected":true}`, "null", string(b) + " {}", `{"schema_version":"ingress-gate-state.v1","gate_id":"x","gate_id":"y"}`, `{"schema_version":"ingress-gate-state.v1"}`}
	for _, input := range inputs {
		var got IngressGateState
		if err := DecodeStrict([]byte(input), &got); err == nil && got.Validate() == nil {
			t.Fatalf("accepted invalid JSON: %s", input)
		}
	}
}

func TestIngressGateClosedMatrixAndExactHighWater(t *testing.T) {
	base := validContracts()[0].(IngressGateState)
	for _, pair := range [][2]string{{"normal", "open"}, {"pd", "local_only"}, {"quarantine", "quarantine"}, {"closed", "closed"}} {
		x := base
		x.Mode, x.State = pair[0], pair[1]
		if err := x.Validate(); err != nil {
			t.Fatalf("valid matrix pair %v: %v", pair, err)
		}
	}
	for _, mutate := range []func(*IngressGateState){
		func(x *IngressGateState) { x.State = "open" }, func(x *IngressGateState) { x.SourceVersion = 0 }, func(x *IngressGateState) { x.SourceSequence = x.HighWater + 1 }, func(x *IngressGateState) { x.IngestOrdinal = x.HighWater + 1 }, func(x *IngressGateState) { x.ScannedThrough = x.HighWater + 1 }, func(x *IngressGateState) { x.PolicyUpdatedAt = x.IssuedAt.Add(time.Second) }, func(x *IngressGateState) { x.PolicyUpdatedAt = x.PolicyUpdatedAt.In(time.FixedZone("UTC+1", 3600)) },
	} {
		x := base
		mutate(&x)
		if err := x.Validate(); err == nil {
			t.Fatal("accepted incoherent gate")
		}
	}
	x := base
	x.Mode, x.State, x.PriorComplete = "normal", "open", false
	if err := x.Validate(); err == nil {
		t.Fatal("accepted incomplete normal gate")
	}
	x = base
	x.HighWater, x.SourceSequence, x.SourceVersion, x.IngestOrdinal, x.ScannedThrough = 9, 7, 3, 6, 8
	if err := x.Validate(); err != nil {
		t.Fatalf("independent ordered axes rejected: %v", err)
	}
}

func TestSessionContextRelations(t *testing.T) {
	base := validContracts()[1].(PDSessionBinding)
	for _, mutate := range []func(*PDSessionBinding){func(x *PDSessionBinding) { x.SourceVersion = 0 }, func(x *PDSessionBinding) { x.SourceSequence = x.HighWater + 1 }, func(x *PDSessionBinding) { x.ClassHighWater = "LX" }, func(x *PDSessionBinding) { x.ClassHighWaterVersion = 0 }, func(x *PDSessionBinding) { x.Sticky = false }} {
		x := base
		mutate(&x)
		if err := x.Validate(); err == nil {
			t.Fatal("accepted incoherent PD session")
		}
	}
}

func TestSessionFirstAuthorityRejectsL0L1AndAcceptsL2L3(t *testing.T) {
	now := time.Date(2026, 8, 19, 10, 5, 0, 0, time.UTC)
	for _, class := range []string{"L0", "L1"} {
		x := validContracts()[1].(PDSessionBinding)
		x.ClassHighWater = class
		x = seal(t, x, func(x PDSessionBinding, d string) PDSessionBinding { x.Digest = d; return x })
		if err := VerifyPDSessionTransition(now, x, acceptVerifier{}, &sessionStore{}); err == nil {
			t.Fatalf("first authoritative %s accepted", class)
		}
	}
	for _, class := range []string{"L2", "L3"} {
		x := validContracts()[1].(PDSessionBinding)
		x.ClassHighWater = class
		x = seal(t, x, func(x PDSessionBinding, d string) PDSessionBinding { x.Digest = d; return x })
		if err := VerifyPDSessionTransition(now, x, acceptVerifier{}, &sessionStore{}); err != nil {
			t.Fatalf("first authoritative %s rejected: %v", class, err)
		}
	}
}

func TestDeclassificationTimeDecisionAndOrigin(t *testing.T) {
	base := validContracts()[6].(DeclassificationDecision)
	for _, mutate := range []func(*DeclassificationDecision){func(x *DeclassificationDecision) { x.RequestedAt = x.IssuedAt.Add(-time.Second) }, func(x *DeclassificationDecision) { x.RecentAuthAt = x.RequestedAt.Add(-time.Second) }, func(x *DeclassificationDecision) { x.ApprovedAt = x.RecentAuthAt }, func(x *DeclassificationDecision) { x.ApprovedAt = x.ExpiresAt }, func(x *DeclassificationDecision) { x.TargetClass = "L1" }, func(x *DeclassificationDecision) { x.Decision = "deny" }, func(x *DeclassificationDecision) { x.LifecycleState = "requested" }, func(x *DeclassificationDecision) { x.SourceOrigin = "qwen" }, func(x *DeclassificationDecision) { x.CandidateOrigin = "qwen" }} {
		x := base
		mutate(&x)
		if err := x.Validate(); err == nil {
			t.Fatal("accepted invalid decision chronology/origin")
		}
	}
}

func TestErasureCannotOverclaimCoverage(t *testing.T) {
	base := validContracts()[7].(ErasureReceipt)
	for _, mutate := range []func(*ErasureReceipt){func(x *ErasureReceipt) { x.DeletedThroughHighWater-- }, func(x *ErasureReceipt) { x.ObservedTargetHighWater++ }, func(x *ErasureReceipt) { x.ObservedTargetVersion = 0 }, func(x *ErasureReceipt) { x.CoverageComplete = false }, func(x *ErasureReceipt) { x.DeletionStatus = "requested" }, func(x *ErasureReceipt) { x.VerificationMethod = "self_report" }, func(x *ErasureReceipt) { x.DeletionEvidenceDigest = "" }} {
		x := base
		mutate(&x)
		if err := x.Validate(); err == nil {
			t.Fatal("accepted overclaiming erasure receipt")
		}
	}
}

type acceptVerifier struct{}

func (acceptVerifier) Verify(b []byte, signature string) bool {
	return len(b) != 0 && signature == testDigest
}

type monotonicConsumer[T AuthoritativeContract] struct {
	last AuthorityMetadata
	n    int
}

func (c *monotonicConsumer[T]) ConsumeIfMonotonic(_ T, next AuthorityMetadata) error {
	if c.n > 0 && (next.StreamID != c.last.StreamID || next.Version <= c.last.Version || next.HighWater < c.last.HighWater) {
		return errors.New("stale")
	}
	c.last, c.n = next, c.n+1
	return nil
}

func seal[T AuthoritativeContract](t *testing.T, value T, set func(T, string) T) T {
	t.Helper()
	b, err := value.CanonicalUnsigned()
	if err != nil {
		t.Fatal(err)
	}
	d, err := CanonicalDigest(json.RawMessage(b))
	if err != nil {
		t.Fatal(err)
	}
	return set(value, d)
}

func TestTypedAuthoritativeVerification(t *testing.T) {
	now := time.Date(2026, 8, 19, 10, 5, 0, 0, time.UTC)
	g := seal(t, validContracts()[0].(IngressGateState), func(x IngressGateState, d string) IngressGateState { x.Digest = d; return x })
	v := seal(t, validContracts()[2].(LocalPDViewBinding), func(x LocalPDViewBinding, d string) LocalPDViewBinding { x.Digest = d; return x })
	r := seal(t, validContracts()[3].(QwenRuntimeAttestation), func(x QwenRuntimeAttestation, d string) QwenRuntimeAttestation { x.Digest = d; return x })
	cfg := seal(t, validContracts()[4].(QwenConfigAttestation), func(x QwenConfigAttestation, d string) QwenConfigAttestation { x.Digest = d; return x })
	p := seal(t, validContracts()[5].(NativeInputProvenance), func(x NativeInputProvenance, d string) NativeInputProvenance { x.Digest = d; return x })
	e := seal(t, validContracts()[7].(ErasureReceipt), func(x ErasureReceipt, d string) ErasureReceipt { x.Digest = d; return x })
	if err := VerifyAuthoritative(now, g, acceptVerifier{}, &monotonicConsumer[IngressGateState]{}); err == nil {
		t.Fatal("generic boundary bypassed type-specific gate CAS")
	}
	if err := VerifyAuthoritative(now, v, acceptVerifier{}, &monotonicConsumer[LocalPDViewBinding]{}); err != nil {
		t.Fatal(err)
	}
	if err := VerifyAuthoritative(now, r, acceptVerifier{}, &monotonicConsumer[QwenRuntimeAttestation]{}); err != nil {
		t.Fatal(err)
	}
	if err := VerifyAuthoritative(now, cfg, acceptVerifier{}, &monotonicConsumer[QwenConfigAttestation]{}); err != nil {
		t.Fatal(err)
	}
	if err := VerifyAuthoritative(now, p, acceptVerifier{}, &monotonicConsumer[NativeInputProvenance]{}); err != nil {
		t.Fatal(err)
	}
	if err := VerifyAuthoritative(now, e, acceptVerifier{}, &monotonicConsumer[ErasureReceipt]{}); err != nil {
		t.Fatal(err)
	}
	bad := g
	bad.PolicyVersion = "tampered"
	if err := VerifyAuthoritative(now, bad, acceptVerifier{}, &monotonicConsumer[IngressGateState]{}); err == nil {
		t.Fatal("accepted digest mismatch")
	}
	if err := VerifyAuthoritative(g.IssuedAt.Add(-time.Second), g, acceptVerifier{}, &monotonicConsumer[IngressGateState]{}); err == nil {
		t.Fatal("accepted not-yet-issued authority")
	}
	consumer := &monotonicConsumer[LocalPDViewBinding]{}
	if err := VerifyAuthoritative(now, v, acceptVerifier{}, consumer); err != nil {
		t.Fatal(err)
	}
	if err := VerifyAuthoritative(now, v, acceptVerifier{}, consumer); err == nil {
		t.Fatal("accepted replay at monotonic consumer")
	}
}

type postscanResolver struct {
	value PostscanAttestation
	err   error
}

func (r postscanResolver) ResolvePostscan(string) (PostscanAttestation, error) { return r.value, r.err }

func TestDeclassificationAuthorizeExactChronologyAndFreshAuth(t *testing.T) {
	x := validContracts()[6].(DeclassificationDecision)
	postscan := seal(t, validContracts()[8].(PostscanAttestation), func(x PostscanAttestation, d string) PostscanAttestation { x.Digest = d; return x })
	x.PostscanAttestationDigest = postscan.Digest
	b, err := x.CanonicalUnsigned()
	if err != nil {
		t.Fatal(err)
	}
	x.Digest, err = CanonicalDigest(json.RawMessage(b))
	if err != nil {
		t.Fatal(err)
	}
	consumer := NewMemoryDeclassificationConsumer()
	now := x.ApprovedAt.Add(time.Minute)
	resolver := postscanResolver{value: postscan}
	if err := x.Authorize(now, acceptVerifier{}, resolver, consumer); err != nil {
		t.Fatalf("authorize: %v", err)
	}
	if err := x.Authorize(now, acceptVerifier{}, resolver, consumer); err == nil {
		t.Fatal("accepted repeated one-use decision")
	}
	if err := x.Authorize(x.ApprovedAt.Add(-time.Second), acceptVerifier{}, resolver, NewMemoryDeclassificationConsumer()); err == nil {
		t.Fatal("accepted future approval")
	}
	if err := x.Authorize(x.RecentAuthAt.Add(15*time.Minute+time.Second), acceptVerifier{}, resolver, NewMemoryDeclassificationConsumer()); err == nil {
		t.Fatal("accepted stale auth")
	}
	badPostscan := postscan
	badPostscan.ReleasedDigest = testDigest[:len(testDigest)-1] + "0"
	if err := x.Authorize(now, acceptVerifier{}, postscanResolver{value: badPostscan}, NewMemoryDeclassificationConsumer()); err == nil {
		t.Fatal("accepted mismatched/forged postscan")
	}
}

func TestMemoryDeclassificationConsumerAtomicOneUse(t *testing.T) {
	x := validContracts()[6].(DeclassificationDecision)
	consumer := NewMemoryDeclassificationConsumer()
	var successes atomic.Int32
	var wg sync.WaitGroup
	for i := range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			candidate := x
			candidate.UseNonce = fmt.Sprintf("use-%d", i)
			candidate.Digest = fmt.Sprintf("sha256:%064x", i+1)
			expected := DeclassificationCASExpectation{DecisionID: candidate.DecisionID, UseNonce: candidate.UseNonce, DecisionDigest: candidate.Digest, LifecycleState: candidate.LifecycleState}
			if consumer.ConsumeOneUseCAS(candidate, expected) == nil {
				successes.Add(1)
			}
		}()
	}
	wg.Wait()
	if got := successes.Load(); got != 1 {
		t.Fatalf("one-use CAS successes=%d, want 1", got)
	}
}

func TestMemoryDeclassificationConsumerRejectsSameDecisionDifferentNonceAndDigest(t *testing.T) {
	x := validContracts()[6].(DeclassificationDecision)
	c := NewMemoryDeclassificationConsumer()
	expected := DeclassificationCASExpectation{DecisionID: x.DecisionID, UseNonce: x.UseNonce, DecisionDigest: x.Digest, LifecycleState: x.LifecycleState}
	wrong := expected
	wrong.UseNonce = "wrong"
	if err := c.ConsumeOneUseCAS(x, wrong); err == nil {
		t.Fatal("mismatched CAS expectation accepted")
	}
	if err := c.ConsumeOneUseCAS(x, expected); err != nil {
		t.Fatal(err)
	}
	x.UseNonce = "different-use"
	x.Digest = "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	expected = DeclassificationCASExpectation{DecisionID: x.DecisionID, UseNonce: x.UseNonce, DecisionDigest: x.Digest, LifecycleState: x.LifecycleState}
	if err := c.ConsumeOneUseCAS(x, expected); err == nil {
		t.Fatal("same decision id reused with different nonce/digest")
	}
}

type gateStore struct {
	current IngressGateState
	found   bool
}

func (s *gateStore) LoadGate(string) (IngressGateState, bool, error) { return s.current, s.found, nil }
func (s *gateStore) ConsumeGateCAS(expected string, next IngressGateState, _ AuthorityMetadata) error {
	if s.found && s.current.Digest != expected {
		return errors.New("CAS")
	}
	s.current, s.found = next, true
	return nil
}

func TestGateTransitionNeverReversesMode(t *testing.T) {
	now := time.Date(2026, 8, 19, 10, 5, 0, 0, time.UTC)
	previous := validContracts()[0].(IngressGateState)
	previous.Mode, previous.State = "normal", "open"
	previous = seal(t, previous, func(x IngressGateState, d string) IngressGateState { x.Digest = d; return x })
	store := &gateStore{current: previous, found: true}
	next := previous
	next.Mode, next.State, next.StateVersion = "pd", "local_only", 2
	next = seal(t, next, func(x IngressGateState, d string) IngressGateState { x.Digest = d; return x })
	if err := VerifyIngressGateTransition(now, next, acceptVerifier{}, store); err != nil {
		t.Fatal(err)
	}
	reverse := next
	reverse.Mode, reverse.State, reverse.StateVersion = "normal", "open", 3
	reverse = seal(t, reverse, func(x IngressGateState, d string) IngressGateState { x.Digest = d; return x })
	if err := VerifyIngressGateTransition(now, reverse, acceptVerifier{}, store); err == nil {
		t.Fatal("accepted signed later gate downgrade")
	}
}

func TestQuarantineExitRequiresSignedReconciliation(t *testing.T) {
	now := time.Date(2026, 8, 19, 10, 5, 0, 0, time.UTC)
	previous := validContracts()[0].(IngressGateState)
	previous.Mode, previous.State = "quarantine", "quarantine"
	previous = seal(t, previous, func(x IngressGateState, d string) IngressGateState { x.Digest = d; return x })
	next := previous
	next.Mode, next.State, next.StateVersion = "pd", "local_only", 2
	next = seal(t, next, func(x IngressGateState, d string) IngressGateState { x.Digest = d; return x })
	if err := VerifyIngressGateTransition(now, next, acceptVerifier{}, &gateStore{current: previous, found: true}); err == nil {
		t.Fatal("ordinary transition escaped quarantine")
	}
	reconciliation := validContracts()[9].(ReconciliationBinding)
	reconciliation.PriorQuarantineDigest, reconciliation.NextGateDigest = previous.Digest, next.Digest
	reconciliation.HighWater, reconciliation.PolicyDigest, reconciliation.PolicyVersion, reconciliation.TargetMode = next.HighWater, next.PolicyDigest, next.PolicyVersion, next.Mode
	reconciliation = seal(t, reconciliation, func(x ReconciliationBinding, d string) ReconciliationBinding { x.Digest = d; return x })
	store := &gateStore{current: previous, found: true}
	if err := VerifyReconciledIngressGateTransition(now, next, reconciliation, acceptVerifier{}, store); err != nil {
		t.Fatalf("verified reconciliation rejected: %v", err)
	}

	forged := reconciliation
	forged.PriorQuarantineDigest = testDigest
	forged = seal(t, forged, func(x ReconciliationBinding, d string) ReconciliationBinding { x.Digest = d; return x })
	if err := VerifyReconciledIngressGateTransition(now, next, forged, acceptVerifier{}, &gateStore{current: previous, found: true}); err == nil {
		t.Fatal("mismatched reconciliation accepted")
	}
}

func TestPDLatchedConversationNeverReturnsToNormal(t *testing.T) {
	now := time.Date(2026, 8, 19, 10, 5, 0, 0, time.UTC)
	normal := validContracts()[0].(IngressGateState)
	normal.Mode, normal.State = "normal", "open"
	normal = seal(t, normal, func(x IngressGateState, d string) IngressGateState { x.Digest = d; return x })
	store := &gateStore{current: normal, found: true}
	pd := normal
	pd.Mode, pd.State, pd.StateVersion = "pd", "local_only", 2
	pd = seal(t, pd, func(x IngressGateState, d string) IngressGateState { x.Digest = d; return x })
	if err := VerifyIngressGateTransition(now, pd, acceptVerifier{}, store); err != nil {
		t.Fatal(err)
	}
	quarantine := pd
	quarantine.Mode, quarantine.State, quarantine.StateVersion = "quarantine", "quarantine", 3
	quarantine = seal(t, quarantine, func(x IngressGateState, d string) IngressGateState { x.Digest = d; return x })
	if err := VerifyIngressGateTransition(now, quarantine, acceptVerifier{}, store); err != nil {
		t.Fatal(err)
	}
	attempt := quarantine
	attempt.Mode, attempt.State, attempt.StateVersion = "normal", "open", 4
	attempt = seal(t, attempt, func(x IngressGateState, d string) IngressGateState { x.Digest = d; return x })
	if err := VerifyIngressGateTransition(now, attempt, acceptVerifier{}, store); err == nil {
		t.Fatal("ordinary normal->pd->quarantine->normal accepted")
	}
	reconciliation := validContracts()[9].(ReconciliationBinding)
	reconciliation.PriorQuarantineDigest, reconciliation.NextGateDigest = quarantine.Digest, attempt.Digest
	reconciliation.HighWater, reconciliation.PolicyDigest, reconciliation.PolicyVersion, reconciliation.TargetMode = attempt.HighWater, attempt.PolicyDigest, attempt.PolicyVersion, "normal"
	reconciliation = seal(t, reconciliation, func(x ReconciliationBinding, d string) ReconciliationBinding { x.Digest = d; return x })
	if err := VerifyReconciledIngressGateTransition(now, attempt, reconciliation, acceptVerifier{}, store); err == nil {
		t.Fatal("reconciliation returned PD-latched conversation to normal")
	}
}

type sessionStore struct {
	current PDSessionBinding
	found   bool
}

func (s *sessionStore) LoadSession(string) (PDSessionBinding, bool, error) {
	return s.current, s.found, nil
}
func (s *sessionStore) ConsumeSessionCAS(expected string, next PDSessionBinding, _ AuthorityMetadata) error {
	if s.found && s.current.Digest != expected {
		return errors.New("CAS")
	}
	s.current, s.found = next, true
	return nil
}

func TestSessionTransitionNeverDowngradesClass(t *testing.T) {
	now := time.Date(2026, 8, 19, 10, 5, 0, 0, time.UTC)
	previous := seal(t, validContracts()[1].(PDSessionBinding), func(x PDSessionBinding, d string) PDSessionBinding { x.Digest = d; return x })
	store := &sessionStore{current: previous, found: true}
	next := previous
	next.BindingVersion, next.ClassHighWater, next.ClassHighWaterVersion = 2, "L3", 2
	next = seal(t, next, func(x PDSessionBinding, d string) PDSessionBinding { x.Digest = d; return x })
	if err := VerifyPDSessionTransition(now, next, acceptVerifier{}, store); err != nil {
		t.Fatal(err)
	}
	reverse := next
	reverse.BindingVersion, reverse.ClassHighWater, reverse.ClassHighWaterVersion = 3, "L2", 3
	reverse = seal(t, reverse, func(x PDSessionBinding, d string) PDSessionBinding { x.Digest = d; return x })
	if err := VerifyPDSessionTransition(now, reverse, acceptVerifier{}, store); err == nil {
		t.Fatal("accepted signed later class downgrade")
	}
	staleClassVersion := next
	staleClassVersion.BindingVersion, staleClassVersion.ClassHighWaterVersion = 4, 1
	staleClassVersion = seal(t, staleClassVersion, func(x PDSessionBinding, d string) PDSessionBinding { x.Digest = d; return x })
	if err := VerifyPDSessionTransition(now, staleClassVersion, acceptVerifier{}, store); err == nil {
		t.Fatal("accepted class version downgrade")
	}
}

func TestEveryAuthorityBoundaryCallsGoValidate(t *testing.T) {
	now := time.Date(2026, 8, 19, 10, 5, 0, 0, time.UTC)
	badGate := validContracts()[0].(IngressGateState)
	badGate.SourceSequence = badGate.HighWater + 1
	badGate = seal(t, badGate, func(x IngressGateState, d string) IngressGateState { x.Digest = d; return x })
	if err := VerifyAuthoritative(now, badGate, acceptVerifier{}, &monotonicConsumer[IngressGateState]{}); err == nil {
		t.Fatal("generic boundary skipped gate Validate")
	}
	if err := VerifyIngressGateTransition(now, badGate, acceptVerifier{}, &gateStore{}); err == nil {
		t.Fatal("gate transition skipped Validate")
	}

	badSession := validContracts()[1].(PDSessionBinding)
	badSession.ClassHighWater = "LX"
	badSession = seal(t, badSession, func(x PDSessionBinding, d string) PDSessionBinding { x.Digest = d; return x })
	if err := VerifyPDSessionTransition(now, badSession, acceptVerifier{}, &sessionStore{}); err == nil {
		t.Fatal("session transition skipped Validate")
	}

	decision := validContracts()[6].(DeclassificationDecision)
	decision.RequestedAt = decision.IssuedAt.Add(-time.Second)
	postscan := seal(t, validContracts()[8].(PostscanAttestation), func(x PostscanAttestation, d string) PostscanAttestation { x.Digest = d; return x })
	decision.PostscanAttestationDigest = postscan.Digest
	decision = func() DeclassificationDecision {
		b, _ := decision.CanonicalUnsigned()
		d, _ := CanonicalDigest(json.RawMessage(b))
		decision.Digest = d
		return decision
	}()
	if err := decision.Authorize(now, acceptVerifier{}, postscanResolver{value: postscan}, NewMemoryDeclassificationConsumer()); err == nil {
		t.Fatal("declassification boundary skipped decision Validate")
	}

	validDecision := validContracts()[6].(DeclassificationDecision)
	badPostscan := validContracts()[8].(PostscanAttestation)
	badPostscan.MaxClass = "L1"
	badPostscan = seal(t, badPostscan, func(x PostscanAttestation, d string) PostscanAttestation { x.Digest = d; return x })
	validDecision.PostscanAttestationDigest = badPostscan.Digest
	b, _ := validDecision.CanonicalUnsigned()
	validDecision.Digest, _ = CanonicalDigest(json.RawMessage(b))
	if err := validDecision.Authorize(now, acceptVerifier{}, postscanResolver{value: badPostscan}, NewMemoryDeclassificationConsumer()); err == nil {
		t.Fatal("declassification boundary skipped postscan Validate")
	}
}

func TestContractSecurityInvariants(t *testing.T) {
	for _, c := range []interface{ Validate() error }{func() QwenRuntimeAttestation {
		x := validContracts()[3].(QwenRuntimeAttestation)
		x.NetworkPolicy = "internet"
		return x
	}(), func() QwenConfigAttestation {
		x := validContracts()[4].(QwenConfigAttestation)
		x.ContextTokens = x.NumCtx + 1
		return x
	}(), func() DeclassificationDecision {
		x := validContracts()[6].(DeclassificationDecision)
		x.FromClass = "L1"
		return x
	}()} {
		if err := c.Validate(); err == nil {
			t.Fatal("accepted unsafe mutation")
		}
	}
	x := validContracts()[0].(IngressGateState)
	x.ExpiresAt = x.IssuedAt.Add(25 * time.Hour)
	if err := x.Validate(); err == nil {
		t.Fatal("accepted excessive TTL")
	}
	x.ExpiresAt = x.IssuedAt.Add(30 * time.Minute).In(time.FixedZone("UTC+3", 3*60*60))
	if err := x.Validate(); err == nil {
		t.Fatal("accepted non-UTC timestamp")
	}
}

func TestCanonicalDigest(t *testing.T) {
	d, err := CanonicalDigest(struct {
		A string `json:"a"`
	}{"x"})
	if err != nil || !validDigest(d) {
		t.Fatalf("bad digest %q: %v", d, err)
	}
}
