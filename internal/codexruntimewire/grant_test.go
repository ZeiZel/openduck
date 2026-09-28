package codexruntimewire

import (
	"testing"
	"time"

	"openduck/internal/macoschannel"
)

func grantFixture(now time.Time) (ProxyGrant, macoschannel.Evidence) {
	ev := macoschannel.Evidence{Channel: "broker-runtime", BindingDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Local: macoschannel.Peer{UID: 2002, GID: 2002}, Peer: macoschannel.Peer{UID: 2001, GID: 2001}}
	return ProxyGrant{Version: ProtocolV1, Channel: ev.Channel, BindingDigest: ev.BindingDigest, BrokerUID: 2001, BrokerGID: 2001, RuntimeUID: 2002, RuntimeGID: 2002, IssuedAt: now.Add(-time.Second), ExpiresAt: now.Add(time.Second), ProxyURL: "http://openduck:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef@127.0.0.1:8790", Tag: "tag"}, ev
}

func TestProxyGrantRejectsDelayedUseReplayAndWrongPrincipal(t *testing.T) {
	now := time.Now().UTC()
	g, ev := grantFixture(now)
	if err := g.validate(now, ev, true); err != nil {
		t.Fatalf("valid runtime grant rejected: %v", err)
	}
	if err := g.validate(g.ExpiresAt, ev, true); err == nil {
		t.Fatal("expired delayed grant accepted")
	}
	replayed := ev
	replayed.BindingDigest = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	if err := g.validate(now, replayed, true); err == nil {
		t.Fatal("replayed grant on another channel binding accepted")
	}
	wrongUID := ev
	wrongUID.Peer.UID++
	if err := g.validate(now, wrongUID, true); err == nil {
		t.Fatal("wrong broker UID accepted")
	}
}
