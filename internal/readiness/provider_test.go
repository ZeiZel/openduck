package readiness

import (
	"strings"
	"testing"
	"time"
)

func TestTwoProviderOperationalContractAndFacetFailures(t *testing.T) {
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	d := "sha256:" + strings.Repeat("a", 64)
	expected := []ExpectedProvider{
		{Provider: "claude", ProfileID: "claude-code", ProfileRevision: "r1", TopologyDigest: d, InactiveDaemonPath: "/fixed/inactive/claude", JobLabel: "com.openduck.provider.claude", ServiceUser: "_claude", ServiceGroup: "_claude", ChannelGroup: "_claude_channel"},
		{Provider: "codex", ProfileID: "codex-app", ProfileRevision: "r1", TopologyDigest: d, InactiveDaemonPath: "/fixed/inactive/codex", JobLabel: "com.openduck.provider.codex", ServiceUser: "_codex", ServiceGroup: "_codex", ChannelGroup: "_codex_channel"},
	}
	provider := func(w ExpectedProvider, pid int) ProviderEvidence {
		return ProviderEvidence{Provider: w.Provider, ProfileID: w.ProfileID, ProfileRevision: w.ProfileRevision, TopologyDigest: w.TopologyDigest, JobLabel: w.JobLabel, PID: pid, StartIdentity: "start:" + w.Provider, ExecutingImageIdentity: d, ServiceUser: w.ServiceUser, ServiceGroup: w.ServiceGroup, ChannelPeerGroup: w.ChannelGroup, ChannelPeerAuthenticated: true, ChannelDescriptorDigest: d, ChannelProofDigest: d, ChannelAuthenticated: true, AccountRef: "account:current", CanaryRef: "canary:current", CanaryResultDigest: d, CompatibilityDigest: d, ProviderEvidenceDigest: d, CompatibilityFreshUntil: now.Add(time.Minute), RecoveryProofDigest: d, ReceiptStoreRevision: "receipt:r1", RequestIDRetention: true, BindingDigestRetention: true, InflightReconciled: true, ObservedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Minute)}
	}
	evidence := Evidence{SchemaVersion: EvidenceSchema, ReleaseID: "release", ObservedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Minute), Providers: []ProviderEvidence{provider(expected[0], 101), provider(expected[1], 102)}}
	live := []LiveProvider{{Provider: "claude", JobLabel: expected[0].JobLabel, PID: 101, Running: true, StartIdentity: "start:claude", ExecutingImageIdentity: d, ServiceUser: "_claude", ServiceGroup: "_claude", ChannelPeerGroup: "_claude_channel", ChannelPeerAuthenticated: true}, {Provider: "codex", JobLabel: expected[1].JobLabel, PID: 102, Running: true, StartIdentity: "start:codex", ExecutingImageIdentity: d, ServiceUser: "_codex", ServiceGroup: "_codex", ChannelPeerGroup: "_codex_channel", ChannelPeerAuthenticated: true}}
	activation := Activation{ReleaseID: "release", ActiveRelease: "release", ActivatedRelease: "release", Complete: true}
	if got := Evaluate(expected, evidence, activation, live, now); !got.Operational || len(got.ReasonCodes) != 0 {
		t.Fatalf("valid two-provider evidence rejected: %+v", got)
	}
	tests := []struct {
		name, reason string
		mutate       func(*Evidence, []LiveProvider)
	}{
		{"image substitution", ReasonDaemonIdentity, func(_ *Evidence, l []LiveProvider) { l[0].ExecutingImageIdentity = "sha256:" + strings.Repeat("b", 64) }},
		{"start identity substitution", ReasonDaemonIdentity, func(_ *Evidence, l []LiveProvider) { l[0].StartIdentity = "start:other" }},
		{"pid restart", ReasonDaemonIdentity, func(_ *Evidence, l []LiveProvider) { l[0].PID++ }},
		{"uid substitution", ReasonDaemonIdentity, func(_ *Evidence, l []LiveProvider) { l[0].ServiceUser = "_attacker" }},
		{"gid substitution", ReasonDaemonIdentity, func(_ *Evidence, l []LiveProvider) { l[0].ServiceGroup = "_attacker" }},
		{"peer credential substitution", ReasonChannelHealth, func(_ *Evidence, l []LiveProvider) { l[0].ChannelPeerGroup = "_attacker" }},
		{"channel", ReasonChannelHealth, func(e *Evidence, _ []LiveProvider) { e.Providers[0].ChannelAuthenticated = false }},
		{"account canary", ReasonAccountCanary, func(e *Evidence, _ []LiveProvider) { e.Providers[0].CanaryRef = "" }},
		{"compatibility", ReasonRevisionCompatibility, func(e *Evidence, _ []LiveProvider) { e.Providers[0].CompatibilityFreshUntil = now }},
		{"recovery", ReasonSessionRecovery, func(e *Evidence, _ []LiveProvider) { e.Providers[0].InflightReconciled = false }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			copyEvidence := evidence
			copyEvidence.Providers = append([]ProviderEvidence(nil), evidence.Providers...)
			copyLive := append([]LiveProvider(nil), live...)
			tc.mutate(&copyEvidence, copyLive)
			got := Evaluate(expected, copyEvidence, activation, copyLive, now)
			if got.Operational || !containsReason(got.ReasonCodes, tc.reason) {
				t.Fatalf("failure was not closed: %+v", got)
			}
		})
	}
	if got := Evaluate(expected, evidence, activation, live, now.Add(2*time.Minute)); got.Operational || !containsReason(got.ReasonCodes, ReasonEvidenceStale) {
		t.Fatalf("stale evidence accepted: %+v", got)
	}
}

func containsReason(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
