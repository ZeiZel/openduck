package localpd

import (
	"encoding/json"
	"errors"
	"testing"
	"time"
)

type viewAuthorityFixture struct{}

func (viewAuthorityFixture) VerifyView(b []byte, sig string) bool {
	d, _ := CanonicalDigest(json.RawMessage(b))
	return d == sig
}

func signedViewIssue(x LocalPDViewIssue) LocalPDViewIssue {
	b := LocalPDViewBinding{SchemaVersion: LocalPDViewBindingV1, ViewID: x.ViewID, BindingVersion: x.BindingVersion, HighWater: x.HighWater, SourceVersion: x.SourceVersion, SourceDigest: x.SourceDigest, RedactionDigest: x.RedactionDigest, AllowedFields: x.AllowedFields, IssuedAt: x.IssuedAt, ExpiresAt: x.IssuedAt.Add(x.TTL), Nonce: x.Nonce, ControllerSignature: x.ControllerSignature}
	u, _ := b.CanonicalUnsigned()
	d, _ := CanonicalDigest(json.RawMessage(u))
	x.Digest = d
	x.CoverageDigest, x.Class = testDigest, "L2"
	e := LocalPDViewEnvelope{Binding: b, GateDigest: x.GateDigest, SessionDigest: x.SessionDigest, PolicyDigest: x.PolicyDigest, HighWater: x.HighWater, SourceVersion: x.SourceVersion, CoverageDigest: x.CoverageDigest, Class: x.Class}
	eu, _ := e.CanonicalUnsigned()
	ed, _ := CanonicalDigest(json.RawMessage(eu))
	x.EnvelopeDigest, x.EnvelopeSignature = ed, ed
	return x
}

func TestLocalPDViewIsBoundedAndInvalidatable(t *testing.T) {
	now := time.Date(2026, 8, 20, 10, 0, 0, 0, time.UTC)
	m := newLocalPDViewManagerWithAuthority(viewAuthorityFixture{})
	base := signedViewIssue(LocalPDViewIssue{ViewID: "view-1", BindingVersion: 1, HighWater: 7, SourceVersion: 3, SourceDigest: testDigest, RedactionDigest: testDigest, GateDigest: testDigest, SessionDigest: testDigest, PolicyDigest: testDigest, AllowedFields: []string{"summary"}, IssuedAt: now, TTL: time.Minute, Nonce: "nonce", ControllerSignature: testDigest})
	if _, err := m.Issue(base); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Get("view-1", now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := m.CheckLineage("view-1", testDigest, testDigest, testDigest, 7, 3, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := m.CheckLineage("view-1", testDigest, testDigest, testDigest, 8, 3, now.Add(time.Second)); !errors.Is(err, ErrViewLineageStale) {
		t.Fatalf("stale high-water: %v", err)
	}
	if err := m.Invalidate("view-1"); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Get("view-1", now.Add(time.Second)); !errors.Is(err, ErrViewInvalidated) {
		t.Fatalf("invalidated view: %v", err)
	}
}

func TestLocalPDViewRejectsUnboundedTTL(t *testing.T) {
	now := time.Now().UTC()
	m := newLocalPDViewManagerWithAuthority(viewAuthorityFixture{})
	x := LocalPDViewIssue{ViewID: "v", BindingVersion: 1, HighWater: 1, SourceVersion: 1, SourceDigest: testDigest, RedactionDigest: testDigest, GateDigest: testDigest, SessionDigest: testDigest, PolicyDigest: testDigest, IssuedAt: now, TTL: MaxLocalPDViewTTL + time.Nanosecond, Nonce: "n", ControllerSignature: testDigest, Digest: testDigest}
	if _, err := m.Issue(x); !errors.Is(err, ErrViewTTL) && !errors.Is(err, ErrInvalidContract) {
		t.Fatalf("ttl accepted: %v", err)
	}
}

func TestLocalPDEnvelopeRejectsLineageTamper(t *testing.T) {
	now := time.Date(2026, 8, 20, 10, 0, 0, 0, time.UTC)
	mutators := []func(*LocalPDViewIssue){
		func(x *LocalPDViewIssue) {
			x.GateDigest = "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
		},
		func(x *LocalPDViewIssue) {
			x.SessionDigest = "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
		},
		func(x *LocalPDViewIssue) {
			x.PolicyDigest = "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
		},
		func(x *LocalPDViewIssue) { x.HighWater++ }, func(x *LocalPDViewIssue) { x.SourceVersion++ },
		func(x *LocalPDViewIssue) {
			x.CoverageDigest = "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
		},
		func(x *LocalPDViewIssue) { x.Class = "L3" }, func(x *LocalPDViewIssue) { x.TTL = 2 * time.Minute },
	}
	for i, mutate := range mutators {
		m := newLocalPDViewManagerWithAuthority(viewAuthorityFixture{})
		x := signedViewIssue(LocalPDViewIssue{ViewID: "v", BindingVersion: 1, HighWater: 1, SourceVersion: 1, SourceDigest: testDigest, RedactionDigest: testDigest, GateDigest: testDigest, SessionDigest: testDigest, PolicyDigest: testDigest, AllowedFields: []string{"summary"}, IssuedAt: now, TTL: time.Minute, Nonce: "n", ControllerSignature: testDigest})
		mutate(&x)
		if _, err := m.Issue(x); err == nil {
			t.Fatalf("tamper %d accepted", i)
		}
	}
}
