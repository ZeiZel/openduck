package admission

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

const fixtureDigest = "sha256:" + "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func fixtureTime() (time.Time, time.Time) {
	return time.Date(2026, 8, 19, 10, 0, 0, 0, time.UTC), time.Date(2026, 8, 19, 10, 30, 0, 0, time.UTC)
}

func snapshot() AuthoritativeConversationSnapshot {
	return AuthoritativeConversationSnapshot{SchemaVersion: AuthoritativeConversationSnapshotV1, ConversationScope: "tg:account/chat", EventRevisionSetDigest: fixtureDigest, CompleteThroughWatermark: "rev:9", IngressGateStateDigest: fixtureDigest, AuthoritativeCoverageDigest: fixtureDigest, ClassHighWater: L1, ClassHighWaterVersion: 2, Digest: fixtureDigest}
}

func cloudPrompt() CloudAdmittedPrompt {
	issued, expires := fixtureTime()
	capsule := SafeCapsule{SchemaVersion: SafeCapsuleV1, Purpose: "summary", Fields: map[string]string{"summary": "safe"}, AllowedFields: []string{"summary"}, Constraints: []string{}, Classification: L1, PostScanDigest: fixtureDigest, Digest: fixtureDigest}
	return CloudAdmittedPrompt{SchemaVersion: CloudAdmittedPromptV1, AdmissionID: "adm_1", Nonce: "nonce_1", IssuedAt: issued, ExpiresAt: expires, MaxUses: 1, TargetSessionID: "session_1", TargetCodexThreadID: "thread_1", ConversationScope: "tg:account/chat", EventRevisionSetDigest: fixtureDigest, CompleteThroughWatermark: "rev:9", IngressGateStateDigest: fixtureDigest, AuthoritativeCoverageDigest: fixtureDigest, ClassHighWater: L1, ClassHighWaterVersion: 2, ContentDigest: fixtureDigest, PrivacyDecisionDigest: fixtureDigest, PolicyDigest: fixtureDigest, SourceRefs: []string{"source:1"}, Classification: L1, Route: "codex_cloud", TargetRuntimeAttestationDigest: fixtureDigest, TargetDSHDistributionAttestationDigest: fixtureDigest, TargetCodexProfileAttestationDigest: fixtureDigest, ModelClass: "codex", ModelTransportPolicyDigest: fixtureDigest, ToolsetDigest: fixtureDigest, ToolNetworkPolicyDigest: fixtureDigest, DSHAppendStore: "dsh-session", DSHAppendSchema: "session.prompt.v1", IdempotencyKey: "idem_1", ExpectedRunnerBinding: "runner_1", SafeCapsule: capsule, ControllerSignature: fixtureDigest, CanonicalizationVersion: CanonicalizationV1, CanonicalizationDigest: fixtureDigest, Digest: fixtureDigest}
}

func TestStrictV1Validation(t *testing.T) {
	issued, expires := fixtureTime()
	values := []struct {
		name     string
		validate func() error
	}{
		{"source", func() error {
			return (SourceEvent{SchemaVersion: SourceEventV1, SourceKind: "telegram", AccountID: "a", ContainerID: "c", ThreadID: "t", EventID: "e", Revision: 1, EventType: "message.created", AuthorRef: "u", SourceTime: issued, ObservedAt: issued, Locator: "tg://x", ContentDigest: fixtureDigest, PayloadRef: "quarantine://x", CoverageCursor: "9", AuthContextDigest: fixtureDigest, CarrierType: "api", CaptureQuality: "complete", Digest: fixtureDigest}).Validate()
		}},
		{"snapshot", snapshot().Validate},
		{"high-water", func() error {
			return (HighWaterBinding{SchemaVersion: HighWaterBindingV1, ConversationScope: "scope", EventRevisionSetDigest: fixtureDigest, CompleteThroughWatermark: "rev:1", IngressGateStateDigest: fixtureDigest, AuthoritativeCoverageDigest: fixtureDigest, ClassHighWater: L1, ClassHighWaterVersion: 1, Digest: fixtureDigest}).Validate()
		}},
		{"privacy", func() error {
			return (PrivacyDecision{SchemaVersion: PrivacyDecisionV1, ConversationScope: "scope", EventDigest: fixtureDigest, EventRevisionSetDigest: fixtureDigest, CompleteThroughWatermark: "rev:1", IngressGateStateDigest: fixtureDigest, AuthoritativeCoverageDigest: fixtureDigest, ClassHighWater: L1, ClassHighWaterVersion: 1, Detectors: []string{"owner"}, PDLatchID: "latch", Route: "safe_capsule", AllowedFields: []string{"summary"}, PolicyVersion: "p1", DecisionHash: fixtureDigest}).Validate()
		}},
		{"cloud-prompt", cloudPrompt().Validate},
		{"local-pd", func() error {
			return (LocalPDDispatch{SchemaVersion: LocalPDDispatchV1, DispatchID: "pd_1", Nonce: "n", IssuedAt: issued, ExpiresAt: expires, PrivacyDecisionDigest: fixtureDigest, ConversationScope: "scope", EventRevisionSetDigest: fixtureDigest, ClassHighWater: L2, ClassHighWaterVersion: 1, PayloadRef: "quarantine://pd", QwenModel: "qwen3:8b", QwenRuntimeAttestationDigest: fixtureDigest, QwenConfigDigest: fixtureDigest, LocalPDViewBindingDigest: fixtureDigest, ToolsNetworkPolicy: "none", Fallback: "none", ControllerSignature: fixtureDigest, Digest: fixtureDigest}).Validate()
		}},
	}
	for _, tc := range values {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.validate(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestCloudAndControllerRoutesAreDisjoint(t *testing.T) {
	p := cloudPrompt()
	p.Route = "local_qwen"
	if err := p.Validate(); err == nil {
		t.Fatal("local route accepted by cloud admission")
	}
	issued, expires := fixtureTime()
	l := LocalPDDispatch{SchemaVersion: LocalPDDispatchV1, DispatchID: "pd", Nonce: "n", IssuedAt: issued, ExpiresAt: expires, PrivacyDecisionDigest: fixtureDigest, ConversationScope: "scope", EventRevisionSetDigest: fixtureDigest, ClassHighWater: L2, ClassHighWaterVersion: 1, PayloadRef: "quarantine://pd", QwenModel: "qwen3:8b", QwenRuntimeAttestationDigest: fixtureDigest, QwenConfigDigest: fixtureDigest, LocalPDViewBindingDigest: fixtureDigest, ToolsNetworkPolicy: "none", Fallback: "none", ControllerSignature: fixtureDigest, Digest: fixtureDigest}
	if err := l.ValidateCloud(); err != ErrControllerOnly {
		t.Fatalf("expected Controller-only error, got %v", err)
	}
}

func TestRejectsUnknownFieldsNullTrailingAndBadDigest(t *testing.T) {
	p := cloudPrompt()
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, input string }{{"unknown", strings.TrimSuffix(string(b), "}") + `,"unexpected":true}`}, {"null", "null"}, {"trailing", string(b) + " {}"}} {
		t.Run(tc.name, func(t *testing.T) {
			var got CloudAdmittedPrompt
			if err := DecodeStrict([]byte(tc.input), &got); err == nil {
				t.Fatal("accepted invalid JSON")
			}
		})
	}
	p.ContentDigest = "sha256:bad"
	if err := p.Validate(); err == nil {
		t.Fatal("accepted malformed digest")
	}
	duplicate := `{"schema_version":"cloud-admitted-prompt.v1","safe_capsule":{"schema_version":"safe-capsule.v1","purpose":"x","fields":{"a":"x","a":"y"}}}`
	var got CloudAdmittedPrompt
	if err := DecodeStrict([]byte(duplicate), &got); err == nil {
		t.Fatal("accepted nested duplicate key")
	}
}

func TestRejectsTTLAndModelMismatches(t *testing.T) {
	p := cloudPrompt()
	p.ExpiresAt = p.IssuedAt.Add(25 * time.Hour)
	if err := p.Validate(); err == nil {
		t.Fatal("accepted excessive TTL")
	}
	p = cloudPrompt()
	p.ModelClass = "qwen"
	if err := p.Validate(); err == nil {
		t.Fatal("accepted non-Codex model")
	}
	issued, expires := fixtureTime()
	l := LocalPDDispatch{SchemaVersion: LocalPDDispatchV1, DispatchID: "pd", Nonce: "n", IssuedAt: issued, ExpiresAt: expires, PrivacyDecisionDigest: fixtureDigest, ConversationScope: "scope", EventRevisionSetDigest: fixtureDigest, ClassHighWater: L2, ClassHighWaterVersion: 1, PayloadRef: "quarantine://pd", QwenModel: "codex", QwenRuntimeAttestationDigest: fixtureDigest, QwenConfigDigest: fixtureDigest, LocalPDViewBindingDigest: fixtureDigest, ToolsNetworkPolicy: "none", Fallback: "none", ControllerSignature: fixtureDigest, Digest: fixtureDigest}
	if err := l.Validate(); err == nil {
		t.Fatal("accepted non-Qwen model")
	}
}

func TestSafeCapsuleRejectsAllRawURIForms(t *testing.T) {
	for _, value := range []string{"custom://locator", "file:///tmp/value", "https://example.invalid/value"} {
		p := SafeCapsule{SchemaVersion: SafeCapsuleV1, Purpose: "summary", Fields: map[string]string{"summary": value}, AllowedFields: []string{"summary"}, Constraints: []string{}, Classification: L1, PostScanDigest: fixtureDigest, Digest: fixtureDigest}
		if err := p.Validate(); err == nil {
			t.Fatalf("accepted raw URI %q", value)
		}
	}
}

func TestCanonicalDigestShape(t *testing.T) {
	digest, err := CanonicalDigest(struct {
		A string `json:"a"`
	}{A: "x"})
	if err != nil || !digestValid(digest) {
		t.Fatalf("bad canonical digest: %s %v", digest, err)
	}
}

type testVerifier bool

func (v testVerifier) Verify([]byte, string) bool { return bool(v) }

type testConsumer struct{ used bool }

func (c *testConsumer) Consume(_, _ string) error {
	if c.used {
		return ErrCloudOnly
	}
	c.used = true
	return nil
}

func authorizedPrompt(t *testing.T) CloudAdmittedPrompt {
	t.Helper()
	p := cloudPrompt()
	cb, err := p.SafeCapsule.canonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	p.ContentDigest, err = CanonicalDigest(json.RawMessage(cb))
	if err != nil {
		t.Fatal(err)
	}
	p.CanonicalizationDigest, err = CanonicalDigest(p.CanonicalizationVersion)
	if err != nil {
		t.Fatal(err)
	}
	p.ControllerSignature = fixtureDigest
	u := p
	u.ControllerSignature = ""
	u.Digest = ""
	b, err := json.Marshal(u)
	if err != nil {
		t.Fatal(err)
	}
	p.Digest, err = CanonicalDigest(json.RawMessage(b))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestAdmitRequiresAuthorityAndOneShot(t *testing.T) {
	p := authorizedPrompt(t)
	now := p.IssuedAt.Add(time.Minute)
	consumer := &testConsumer{}
	if err := p.Admit(now, testVerifier(true), consumer); err != nil {
		t.Fatal(err)
	}
	if err := p.Admit(now, testVerifier(true), consumer); err == nil {
		t.Fatal("replay admitted")
	}
	if err := p.Admit(now, testVerifier(false), &testConsumer{}); err == nil {
		t.Fatal("forged signature admitted")
	}
	if err := p.Admit(p.ExpiresAt, testVerifier(true), &testConsumer{}); err == nil {
		t.Fatal("expired admission admitted")
	}
	p.ContentDigest = fixtureDigest
	if err := p.Admit(now, testVerifier(true), &testConsumer{}); err == nil {
		t.Fatal("forged capsule digest admitted")
	}
}

func TestSafeCapsuleRejectsRawPDHandlesAndNilLists(t *testing.T) {
	s := SafeCapsule{SchemaVersion: SafeCapsuleV1, Purpose: "summary", Fields: map[string]string{"summary": "https://private.example"}, AllowedFields: []string{"summary"}, Classification: L1, PostScanDigest: fixtureDigest, Digest: fixtureDigest}
	if err := s.Validate(); err == nil {
		t.Fatal("accepted URL/raw capsule")
	}
	s = SafeCapsule{SchemaVersion: SafeCapsuleV1, Purpose: "summary", Fields: map[string]string{"summary": "x"}, AllowedFields: nil, Classification: L1, PostScanDigest: fixtureDigest, Digest: fixtureDigest}
	if err := s.Validate(); err == nil {
		t.Fatal("accepted nil allowlist")
	}
	s = SafeCapsule{SchemaVersion: SafeCapsuleV1, Purpose: "summary", Fields: map[string]string{"summary": "x"}, AllowedFields: []string{"summary"}, Classification: L1, PostScanDigest: fixtureDigest, Digest: fixtureDigest}
	if err := s.Validate(); err == nil {
		t.Fatal("accepted nil constraints")
	}
	p := PrivacyDecision{SchemaVersion: PrivacyDecisionV1, ConversationScope: "s", EventDigest: fixtureDigest, EventRevisionSetDigest: fixtureDigest, CompleteThroughWatermark: "w", IngressGateStateDigest: fixtureDigest, AuthoritativeCoverageDigest: fixtureDigest, ClassHighWater: L1, ClassHighWaterVersion: 1, PDLatchID: "l", Route: "safe_capsule", PolicyVersion: "p", DecisionHash: fixtureDigest}
	if err := p.Validate(); err == nil {
		t.Fatal("accepted nil detector/allowlist")
	}
}
