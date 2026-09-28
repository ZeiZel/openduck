package macosattest

import (
	"errors"
	"openduck/internal/readiness"
	"testing"
)

func validBinding() Binding {
	p := Process{PID: 42, StartSec: 100, StartUsec: 2, UID: 501, GID: 502, CDHash: [20]byte{1}}
	e := readiness.ProviderEvidence{Provider: "codex", JobLabel: "com.openduck.provider.codex", PID: p.PID, StartIdentity: p.StartIdentity(), ExecutingImageIdentity: p.ImageIdentity(), ServiceUser: "_codex", ServiceGroup: "_codex", ChannelPeerGroup: "_codex_channel"}
	return Binding{Provider: "codex", JobLabel: e.JobLabel, Before: p, After: p, Peer: Peer{UID: 500, GID: 503, Authenticated: true}, ExpectedUID: 501, ExpectedGID: 502, ExpectedPeerGID: 503, Evidence: e}
}

func TestVerifyRejectsSubstitutionRestartAndPeerMismatch(t *testing.T) {
	if _, err := Verify(validBinding()); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*Binding){
		func(b *Binding) { b.After.StartSec++ },
		func(b *Binding) { b.After.CDHash[0]++ },
		func(b *Binding) { b.After.UID++ },
		func(b *Binding) { b.After.GID++ },
		func(b *Binding) { b.Peer.GID++ },
		func(b *Binding) { b.Peer.Authenticated = false },
		func(b *Binding) { b.Evidence.StartIdentity = "replayed" },
	} {
		b := validBinding()
		mutate(&b)
		if _, err := Verify(b); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("substitution accepted: %v", err)
		}
	}
}
