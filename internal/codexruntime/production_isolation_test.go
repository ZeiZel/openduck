package codexruntime

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestPFEvidenceFailsClosedForClockBootAndRulesDrift(t *testing.T) {
	now := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	e := PFEvidence{SchemaVersion: PFEvidenceV1, BootID: "boot-1", Anchor: pfAnchor, Enabled: true, PolicyDigest: strings.Repeat("a", 64), RulesDigest: strings.Repeat("b", 64), RootUID: 0, RootGID: 0, RootMode: 0755, RootDigest: strings.Repeat("d", 64)}
	if err := validatePFEvidence(e, e.PolicyDigest, e.RulesDigest, "boot-1", now); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*PFEvidence, time.Time){
		func(v *PFEvidence, _ time.Time) { v.BootID = "other-boot" },
		func(v *PFEvidence, _ time.Time) { v.RulesDigest = strings.Repeat("c", 64) },
		func(v *PFEvidence, _ time.Time) { v.RootMode = 0700 },
	} {
		bad := e
		mutate(&bad, now)
		if err := validatePFEvidence(bad, e.PolicyDigest, e.RulesDigest, "boot-1", now); err == nil {
			t.Fatal("stale or drifted PF evidence accepted")
		}
	}
}

func TestPFEvidenceCanonicalRecordIsBootBoundNotWallClockBound(t *testing.T) {
	now := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	e := PFEvidence{SchemaVersion: PFEvidenceV1, BootID: "boot-1", Anchor: pfAnchor, Enabled: true, PolicyDigest: strings.Repeat("a", 64), RulesDigest: strings.Repeat("b", 64), RootUID: 0, RootGID: 0, RootMode: 0755, RootDigest: strings.Repeat("d", 64)}
	b, err := e.Canonical()
	if err != nil || !strings.HasPrefix(string(b), `{"schema_version":`) {
		t.Fatalf("canonical PF evidence err=%v bytes=%q", err, b)
	}
	if err := validatePFEvidence(e, e.PolicyDigest, e.RulesDigest, "boot-1", now.Add(24*time.Hour)); err != nil {
		t.Fatalf("boot-bound PF evidence became wall-clock stale: %v", err)
	}
	if err := validatePFEvidence(e, e.PolicyDigest, e.RulesDigest, "other-boot", now.Add(24*time.Hour)); err == nil {
		t.Fatal("reboot-mismatched PF evidence accepted")
	}
}

func TestProductionIsolationRejectsExpiredGrantImmediatelyBeforeStart(t *testing.T) {
	p := &productionIsolation{cfg: ProductionIsolationConfig{ProxyGrantExpiresAt: time.Now().UTC().Add(-time.Nanosecond)}}
	if _, err := p.proxyAddress(context.Background()); !errors.Is(err, ErrProductionIsolationConfig) {
		t.Fatalf("expired grant proxy address err=%v", err)
	}
	if _, err := p.start(context.Background()); !errors.Is(err, ErrProductionIsolationConfig) {
		t.Fatalf("expired grant start err=%v", err)
	}
}
