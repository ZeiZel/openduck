package codexbroker

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net"
	"testing"
	"time"

	"openduck/internal/macoschannel"
)

type seamConn struct {
	net.Conn
	ev macoschannel.Evidence
}

func (c *seamConn) Evidence() macoschannel.Evidence { return c.ev }
func (c *seamConn) Seal(domain string, payload []byte) (string, error) {
	d := sha256.Sum256(append([]byte(domain), payload...))
	return hex.EncodeToString(d[:]), nil
}
func (c *seamConn) Verify(domain string, payload []byte, tag string) error {
	want, _ := c.Seal(domain, payload)
	if want != tag {
		return macoschannel.ErrBinding
	}
	return nil
}

func expectedRuntimeFixture() ExpectedRuntime {
	e := ExpectedRuntime{
		RuntimeID:                   "runtime_1",
		BrokerBinaryDigest:          Digest("broker-binary"),
		RuntimeBinaryDigest:         Digest("runtime-binary"),
		PolicyDigest:                Digest("policy"),
		BrokerReleaseDigest:         Digest("release-manifest"),
		BrokerSocketDigest:          Digest("socket-metadata"),
		PeerUID:                     1000,
		PeerGID:                     1000,
		RuntimeUID:                  1001,
		RuntimeGID:                  1001,
		ExpectedEgressUID:           1002,
		ExpectedEgressGID:           1003,
		ExpectedEgressReleaseDigest: Digest("egress-release"),
		ExpectedEgressSocketDigest:  Digest("egress-socket"),
		KeyEpoch:                    7,
		Channel:                     "codex-control",
		LocalRole:                   "broker",
		PeerRole:                    "controller",
		BindingDigest:               Digest("pending-binding"),
	}
	e.BindingDigest = e.ComputeBindingDigest(evidenceFixture(e))
	return e
}

func evidenceFixture(e ExpectedRuntime) macoschannel.Evidence {
	return macoschannel.Evidence{
		Local:    macoschannel.Peer{UID: e.RuntimeUID, GID: e.RuntimeGID},
		Peer:     macoschannel.Peer{UID: e.PeerUID, GID: e.PeerGID},
		KeyEpoch: e.KeyEpoch,
		Channel:  e.Channel, LocalRole: e.LocalRole, PeerRole: e.PeerRole,
		BindingDigest: e.BindingDigest,
		LocalRelease: macoschannel.ReleasePin{
			ReleaseID:      "release-1",
			BinaryDigest:   e.BrokerBinaryDigest[7:],
			ManifestDigest: e.BrokerReleaseDigest[7:],
			SocketDigest:   e.BrokerSocketDigest[7:],
		},
	}
}

func TestExpectedRuntimeBindsStableChannelEvidence(t *testing.T) {
	e := expectedRuntimeFixture()
	if err := e.Validate(); err != nil {
		t.Fatal(err)
	}
	ev := evidenceFixture(e)
	if !e.matches(ev) {
		t.Fatal("matching channel evidence rejected")
	}
	if e.ComputeBindingDigest(ev) == "" {
		t.Fatal("missing binding digest")
	}
	for _, mutate := range []func(*macoschannel.Evidence){
		func(v *macoschannel.Evidence) { v.Peer.UID++ },
		func(v *macoschannel.Evidence) { v.KeyEpoch++ },
		func(v *macoschannel.Evidence) { v.LocalRelease.ManifestDigest = Digest("other")[7:] },
	} {
		bad := ev
		mutate(&bad)
		if e.matches(bad) {
			t.Fatal("spliced channel evidence accepted")
		}
	}
	wrongEgress := e
	wrongEgress.ExpectedEgressReleaseDigest = Digest("other-egress-release")
	if wrongEgress.matches(ev) {
		t.Fatal("spliced egress identity accepted")
	}
}

func TestExpectedRuntimeDerivesBindingBeforeItIsSet(t *testing.T) {
	e := expectedRuntimeFixture()
	e.BindingDigest = ""
	if got := e.ComputeBindingDigest(evidenceFixture(expectedRuntimeFixture())); got == "" {
		t.Fatal("production listener could not derive its transcript binding")
	}
}

func TestProductionConstructorsRequireSealedConn(t *testing.T) {
	e := expectedRuntimeFixture()
	if _, err := NewProductionClient(nil, e); !errors.Is(err, ErrAttestation) {
		t.Fatalf("client constructor err=%v", err)
	}
	if _, err := NewProductionServer(nil, nil, e); !errors.Is(err, ErrAttestation) {
		t.Fatalf("server constructor err=%v", err)
	}
	bad := e
	bad.KeyEpoch = 0
	if _, err := NewProductionClient(nil, bad); !errors.Is(err, ErrAttestation) {
		t.Fatalf("invalid expected runtime err=%v", err)
	}
}

func TestProductionServerCannotServeBeforeConstruction(t *testing.T) {
	if err := (*ProductionServer)(nil).Serve(context.Background()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("nil server err=%v", err)
	}
}

func TestProductionConstructorsRejectReversedChannelOrientation(t *testing.T) {
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	e := expectedRuntimeFixture()
	serverEvidence := evidenceFixture(e)
	clientEvidence := serverEvidence
	clientEvidence.Local, clientEvidence.Peer = serverEvidence.Peer, serverEvidence.Local
	clientEvidence.LocalRole, clientEvidence.PeerRole = e.PeerRole, e.LocalRole
	clientEvidence.LocalRelease, clientEvidence.PeerRelease = serverEvidence.PeerRelease, serverEvidence.LocalRelease
	serverConn := &seamConn{Conn: right, ev: serverEvidence}
	clientConn := &seamConn{Conn: left, ev: clientEvidence}
	f := &fake{AttestationValue: fixtureAttestation()}
	if _, err := newProductionClient(serverConn, e); !errors.Is(err, ErrAttestation) {
		t.Fatalf("client accepted broker-oriented channel: %v", err)
	}
	if _, err := newProductionServer(clientConn, f, e); !errors.Is(err, ErrAttestation) {
		t.Fatalf("server accepted controller-oriented channel: %v", err)
	}
}

func TestPrivateProductionLifecycleDistinctOrientationAndDrift(t *testing.T) {
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	brokerDigest, runtimeDigest, releaseDigest, socketDigest := Digest("broker"), Digest("runtime"), Digest("release"), Digest("socket")
	bind := Digest("binding")
	r := macoschannel.ReleasePin{ReleaseID: "broker", BinaryDigest: brokerDigest[7:], ManifestDigest: releaseDigest[7:], SocketDigest: socketDigest[7:]}
	p := macoschannel.ReleasePin{ReleaseID: "controller", BinaryDigest: Digest("controller")[7:], ManifestDigest: Digest("controller-release")[7:], SocketDigest: socketDigest[7:]}
	serverConn := &seamConn{Conn: right, ev: macoschannel.Evidence{Local: macoschannel.Peer{UID: 2001, GID: 3001}, Peer: macoschannel.Peer{UID: 2002, GID: 3002}, KeyEpoch: 7, LocalRelease: r, PeerRelease: p, Channel: "codex-control", LocalRole: "broker", PeerRole: "controller", BindingDigest: bind}}
	clientConn := &seamConn{Conn: left, ev: macoschannel.Evidence{Local: macoschannel.Peer{UID: 2002, GID: 3002}, Peer: macoschannel.Peer{UID: 2001, GID: 3001}, KeyEpoch: 7, LocalRelease: p, PeerRelease: r, Channel: "codex-control", LocalRole: "controller", PeerRole: "broker", BindingDigest: bind}}
	e := ExpectedRuntime{RuntimeID: "runtime", BrokerBinaryDigest: brokerDigest, RuntimeBinaryDigest: runtimeDigest, PolicyDigest: Digest("policy"), BrokerReleaseDigest: releaseDigest, BrokerSocketDigest: socketDigest, PeerUID: 2002, PeerGID: 3002, RuntimeUID: 2001, RuntimeGID: 3001, ExpectedEgressUID: 2003, ExpectedEgressGID: 3003, ExpectedEgressReleaseDigest: Digest("egress-release"), ExpectedEgressSocketDigest: Digest("egress-socket"), KeyEpoch: 7, Channel: "codex-control", LocalRole: "broker", PeerRole: "controller", BindingDigest: Digest("pending-binding")}
	e.BindingDigest = e.ComputeBindingDigest(serverConn.Evidence())
	f := &fake{AttestationValue: fixtureAttestation(), InventoryValue: fixtureInventory(), Answer: "ok"}
	f.AttestationValue.RuntimeID, f.AttestationValue.PeerID, f.AttestationValue.RuntimeBinaryDigest, f.AttestationValue.PolicyDigest, f.AttestationValue.PeerUID, f.AttestationValue.PeerGID, f.AttestationValue.Epoch, f.AttestationValue.BrokerSocketDigest, f.AttestationValue.BrokerReleaseDigest = e.RuntimeID, e.Channel+":"+e.PeerRole, e.RuntimeBinaryDigest, e.PolicyDigest, e.PeerUID, e.PeerGID, e.KeyEpoch, e.BrokerSocketDigest, e.BrokerReleaseDigest
	f.AttestationValue.ExpectedEgressUID, f.AttestationValue.ExpectedEgressGID, f.AttestationValue.ExpectedEgressReleaseDigest, f.AttestationValue.ExpectedEgressSocketDigest = e.ExpectedEgressUID, e.ExpectedEgressGID, e.ExpectedEgressReleaseDigest, e.ExpectedEgressSocketDigest
	s, err := newProductionServer(serverConn, f, e)
	if err != nil {
		t.Fatal(err)
	}
	c, err := newProductionClient(clientConn, e)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- s.Serve(context.Background()) }()
	if _, err = c.Attestation(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err = c.Inventory(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.Delay = 50 * time.Millisecond
	turnDone := make(chan error, 1)
	go func() {
		_, e := c.Turn(context.Background(), Turn{SessionID: "s", TurnID: "turn_1", Prompt: "x", Classification: "L0", MaxOutputBytes: 32})
		turnDone <- e
	}()
	time.Sleep(10 * time.Millisecond)
	if err = c.Cancel(context.Background(), Cancel{SessionID: "s", TurnID: "turn_1"}); err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel err=%v", err)
	}
	<-turnDone
	f.mu.Lock()
	f.AttestationValue.RuntimeBinaryDigest = Digest("drifted-runtime")
	f.mu.Unlock()
	if _, err = c.Inventory(context.Background()); err == nil {
		t.Fatalf("backend drift err=%v", err)
	}
	_ = c.Close(context.Background())
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("server did not stop")
	}
}
