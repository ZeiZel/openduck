// Command openduck-codex-broker owns Controller and egress authority. It
// never starts Codex; requests are forwarded to _openduck_codex.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"openduck/internal/codexbroker"
	"openduck/internal/codexruntimewire"
	"openduck/internal/macoschannel"
	"openduck/internal/modelegress"
	"openduck/internal/servicekey"
	"openduck/internal/verifiedroot"
)

const fixedProxyAddress = "127.0.0.1:8790"
const runtimeEgressRenewInterval = 10 * time.Second

type brokerOptions struct {
	production                                                                                                                            bool
	binary, binaryName, runtimeID, runtimeDigest, model                                                                                   string
	channel, socketRoot, controllerSocket, releaseRoot                                                                                    string
	controllerKeyRoot, controllerKeyFile, egressKeyRoot, egressKeyFile                                                                    string
	brokerLocalRelease, controllerLocalRelease                                                                                            string
	egressSocketRoot, policyFile, egressLocalRelease, brokerEgressRelease                                                                 string
	runtimeChannel, runtimeSocketRoot, runtimeSocket, runtimeKeyRoot, runtimeKeyFile, runtimeLocalRelease, brokerRuntimeRelease           string
	peerUID, peerGID, brokerUID, brokerGID, channelGID, egressUID, egressGID, egressChannelGID, runtimeUID, runtimeGID, runtimeChannelGID uint
	epoch                                                                                                                                 uint64
}
type brokerListener interface {
	AcceptAuthenticated(context.Context) (macoschannel.Conn, error)
	Close() error
}

func loadBrokerJSON(path string, out any) error {
	f, e := os.Open(path)
	if e != nil {
		return e
	}
	defer f.Close()
	d := json.NewDecoder(f)
	d.DisallowUnknownFields()
	return d.Decode(out)
}
func trimDigest(v string) string {
	if len(v) == 71 && v[:7] == "sha256:" {
		return v[7:]
	}
	return ""
}

func parseBrokerOptions(args []string) (brokerOptions, error) {
	var o brokerOptions
	f := flag.NewFlagSet("openduck-codex-broker", flag.ContinueOnError)
	f.BoolVar(&o.production, "production-admission", false, "require authenticated production composition")
	f.StringVar(&o.binary, "binary", "", "pinned broker binary")
	f.StringVar(&o.binaryName, "binary-name", "", "broker binary leaf")
	f.StringVar(&o.runtimeID, "runtime-id", "", "runtime identity")
	f.StringVar(&o.runtimeDigest, "runtime-digest", "", "runtime digest")
	f.StringVar(&o.model, "model", "", "model")
	f.StringVar(&o.channel, "channel", "", "Controller channel")
	f.StringVar(&o.socketRoot, "socket-root", "", "Controller socket root")
	f.StringVar(&o.controllerSocket, "controller-socket", "owner.sock", "Controller socket leaf")
	f.StringVar(&o.releaseRoot, "release-root", "", "broker release root")
	f.StringVar(&o.controllerKeyRoot, "controller-key-root", "", "Controller channel key root")
	f.StringVar(&o.controllerKeyFile, "controller-key-file", "", "Controller channel key leaf")
	f.StringVar(&o.egressKeyRoot, "egress-key-root", "", "model-egress channel key root")
	f.StringVar(&o.egressKeyFile, "egress-key-file", "", "model-egress channel key leaf")
	f.StringVar(&o.brokerLocalRelease, "broker-local-release", "", "broker release pin")
	f.StringVar(&o.controllerLocalRelease, "controller-local-release", "", "Controller release pin")
	f.StringVar(&o.egressSocketRoot, "egress-socket-root", "", "egress socket root")
	f.StringVar(&o.policyFile, "policy-file", "", "egress policy")
	f.StringVar(&o.egressLocalRelease, "egress-local-release", "", "egress pin")
	f.StringVar(&o.brokerEgressRelease, "broker-egress-release", "", "broker egress pin")
	f.StringVar(&o.runtimeChannel, "runtime-channel", "", "runtime channel")
	f.StringVar(&o.runtimeSocketRoot, "runtime-socket-root", "", "runtime socket root")
	f.StringVar(&o.runtimeSocket, "runtime-socket", "runtime.sock", "runtime socket leaf")
	f.StringVar(&o.runtimeKeyRoot, "runtime-key-root", "", "runtime key root")
	f.StringVar(&o.runtimeKeyFile, "runtime-key-file", "", "runtime key leaf")
	f.StringVar(&o.runtimeLocalRelease, "runtime-local-release", "", "runtime release pin")
	f.StringVar(&o.brokerRuntimeRelease, "broker-runtime-release", "", "broker runtime pin")
	f.UintVar(&o.peerUID, "peer-uid", 0, "Controller uid")
	f.UintVar(&o.peerGID, "peer-gid", 0, "Controller gid")
	f.UintVar(&o.brokerUID, "broker-uid", 0, "broker uid")
	f.UintVar(&o.brokerGID, "broker-gid", 0, "broker gid")
	f.UintVar(&o.channelGID, "channel-gid", 0, "Controller channel gid")
	f.UintVar(&o.egressUID, "egress-uid", 0, "egress uid")
	f.UintVar(&o.egressGID, "egress-gid", 0, "egress gid")
	f.UintVar(&o.egressChannelGID, "egress-channel-gid", 0, "egress channel gid")
	f.UintVar(&o.runtimeUID, "runtime-uid", 0, "runtime uid")
	f.UintVar(&o.runtimeGID, "runtime-gid", 0, "runtime gid")
	f.UintVar(&o.runtimeChannelGID, "runtime-channel-gid", 0, "runtime channel gid")
	f.Uint64Var(&o.epoch, "epoch", 0, "key epoch")
	if e := f.Parse(args); e != nil || f.NArg() != 0 || !o.production {
		return brokerOptions{}, errors.New("production broker mode is required")
	}
	for _, p := range []string{o.binary, o.socketRoot, o.releaseRoot, o.controllerKeyRoot, o.egressKeyRoot, o.egressSocketRoot, o.runtimeSocketRoot, o.runtimeKeyRoot} {
		if !filepath.IsAbs(p) || filepath.Clean(p) != p || p == string(filepath.Separator) {
			return brokerOptions{}, errors.New("invalid broker path")
		}
	}
	for _, s := range []string{o.binaryName, o.runtimeID, o.runtimeDigest, o.model, o.channel, o.controllerSocket, o.controllerKeyFile, o.egressKeyFile, o.brokerLocalRelease, o.controllerLocalRelease, o.policyFile, o.egressLocalRelease, o.brokerEgressRelease, o.runtimeChannel, o.runtimeSocket, o.runtimeKeyFile, o.runtimeLocalRelease, o.brokerRuntimeRelease} {
		if s == "" {
			return brokerOptions{}, errors.New("missing broker production value")
		}
	}
	if filepath.Base(o.controllerSocket) != o.controllerSocket || filepath.Base(o.runtimeSocket) != o.runtimeSocket || filepath.Base(o.controllerKeyFile) != o.controllerKeyFile || filepath.Base(o.egressKeyFile) != o.egressKeyFile || filepath.Base(o.runtimeKeyFile) != o.runtimeKeyFile || o.peerUID == 0 || o.peerGID == 0 || o.brokerUID == 0 || o.brokerGID == 0 || o.runtimeUID == 0 || o.runtimeGID == 0 || o.runtimeUID == o.brokerUID || o.channelGID == 0 || o.runtimeChannelGID == 0 || o.egressUID == 0 || o.egressGID == 0 || o.egressChannelGID == 0 || o.epoch == 0 {
		return brokerOptions{}, errors.New("invalid broker principal topology")
	}
	return o, nil
}
func main() {
	if e := run(os.Args[1:]); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
func run(a []string) error {
	o, e := parseBrokerOptions(a)
	if e != nil {
		return e
	}
	return runBroker(o)
}

func connectEgress(ctx context.Context, o brokerOptions, sessionID string) (modelegress.ProductionCapability, error) {
	var p modelegress.Policy
	if e := loadBrokerJSON(o.policyFile, &p); e != nil || p.Validate() != nil || p.ProxyUID != uint32(o.egressUID) || p.ProxyGID != uint32(o.egressGID) || p.Epoch != o.epoch {
		return nil, errors.New("egress policy unavailable")
	}
	var eg, br macoschannel.ReleasePin
	if e := loadBrokerJSON(o.egressLocalRelease, &eg); e != nil {
		return nil, e
	}
	if e := loadBrokerJSON(o.brokerEgressRelease, &br); e != nil {
		return nil, e
	}
	roots, e := verifiedroot.OpenAll([]verifiedroot.Requirement{{Name: "egress socket", Path: o.egressSocketRoot, UID: uint32(o.egressUID), GID: uint32(o.egressChannelGID), Mode: 0750}, {Name: "broker egress release", Path: o.releaseRoot, UID: 0, GID: uint32(o.brokerGID), Mode: 0550}, {Name: "broker egress key", Path: o.egressKeyRoot, UID: uint32(o.brokerUID), GID: uint32(o.brokerGID), Mode: 0700}})
	if e != nil {
		return nil, e
	}
	defer verifiedroot.CloseAll(roots)
	key, e := servicekey.New(roots[2].Handle(), servicekey.Policy{FileName: o.egressKeyFile, Channel: "model-egress", OwnerUID: uint32(o.brokerUID), OwnerGID: uint32(o.brokerGID), Mode: 0600, RootUID: uint32(o.brokerUID), RootGID: uint32(o.brokerGID), RootMode: 0700})
	if e != nil {
		return nil, e
	}
	uid, gid := uint32(o.egressUID), uint32(o.egressGID)
	cfg := macoschannel.Config{Contract: macoschannel.SocketContract{Channel: "model-egress", LocalRole: "broker", PeerRole: "egress", SocketPath: "control.sock", SocketRoot: o.egressSocketRoot, ExpectedPeerUID: &uid, ExpectedPeerGID: &gid, ExpectedSocketRootUID: uid, ExpectedSocketRootGID: uint32(o.egressChannelGID), ExpectedSocketRootMode: 0750, ExpectedSocketUID: uid, ExpectedSocketGID: uint32(o.egressChannelGID), ExpectedSocketMode: 0660}, LocalRelease: br, PeerRelease: eg, ReleaseRoot: roots[1].Handle(), SocketRootFD: roots[0].Handle(), BinaryName: o.binaryName, KeySource: key, ExpectedReleaseRootUID: 0, ExpectedReleaseRootGID: uint32(o.brokerGID), ExpectedReleaseRootMode: 0550, ExpectedManifestMode: 0440, ExpectedBinaryMode: 0550}
	d, e := macoschannel.NewDialer(cfg)
	if e != nil {
		return nil, e
	}
	c, e := d.Dial(ctx)
	if e != nil {
		return nil, e
	}
	defer c.Close()
	x := modelegress.ControlExpectation{Policy: p, Channel: "model-egress", LocalRole: "egress", PeerRole: "broker", LocalUID: uid, LocalGID: gid, PeerUID: uint32(o.brokerUID), PeerGID: uint32(o.brokerGID), LocalRelease: eg, PeerRelease: br, Epoch: o.epoch, ProxyAddress: fixedProxyAddress}
	client, e := modelegress.NewAuthenticatedControlClientForPeer(c, x)
	if e != nil {
		return nil, e
	}
	return client.ProbeCapabilityForSession(ctx, p, x, sessionID)
}

func revokeEgress(ctx context.Context, o brokerOptions, sessionID string) error {
	var p modelegress.Policy
	if e := loadBrokerJSON(o.policyFile, &p); e != nil || p.Validate() != nil {
		return errors.New("egress policy unavailable")
	}
	var eg, br macoschannel.ReleasePin
	if e := loadBrokerJSON(o.egressLocalRelease, &eg); e != nil {
		return e
	}
	if e := loadBrokerJSON(o.brokerEgressRelease, &br); e != nil {
		return e
	}
	roots, e := verifiedroot.OpenAll([]verifiedroot.Requirement{{Name: "egress socket", Path: o.egressSocketRoot, UID: uint32(o.egressUID), GID: uint32(o.egressChannelGID), Mode: 0750}, {Name: "broker egress release", Path: o.releaseRoot, UID: 0, GID: uint32(o.brokerGID), Mode: 0550}, {Name: "broker egress key", Path: o.egressKeyRoot, UID: uint32(o.brokerUID), GID: uint32(o.brokerGID), Mode: 0700}})
	if e != nil {
		return e
	}
	defer verifiedroot.CloseAll(roots)
	key, e := servicekey.New(roots[2].Handle(), servicekey.Policy{FileName: o.egressKeyFile, Channel: "model-egress", OwnerUID: uint32(o.brokerUID), OwnerGID: uint32(o.brokerGID), Mode: 0600, RootUID: uint32(o.brokerUID), RootGID: uint32(o.brokerGID), RootMode: 0700})
	if e != nil {
		return e
	}
	uid, gid := uint32(o.egressUID), uint32(o.egressGID)
	cfg := macoschannel.Config{Contract: macoschannel.SocketContract{Channel: "model-egress", LocalRole: "broker", PeerRole: "egress", SocketPath: "control.sock", SocketRoot: o.egressSocketRoot, ExpectedPeerUID: &uid, ExpectedPeerGID: &gid, ExpectedSocketRootUID: uid, ExpectedSocketRootGID: uint32(o.egressChannelGID), ExpectedSocketRootMode: 0750, ExpectedSocketUID: uid, ExpectedSocketGID: uint32(o.egressChannelGID), ExpectedSocketMode: 0660}, LocalRelease: br, PeerRelease: eg, ReleaseRoot: roots[1].Handle(), SocketRootFD: roots[0].Handle(), BinaryName: o.binaryName, KeySource: key, ExpectedReleaseRootUID: 0, ExpectedReleaseRootGID: uint32(o.brokerGID), ExpectedReleaseRootMode: 0550, ExpectedManifestMode: 0440, ExpectedBinaryMode: 0550}
	d, e := macoschannel.NewDialer(cfg)
	if e != nil {
		return e
	}
	c, e := d.Dial(ctx)
	if e != nil {
		return e
	}
	defer c.Close()
	x := modelegress.ControlExpectation{Policy: p, Channel: "model-egress", LocalRole: "egress", PeerRole: "broker", LocalUID: uid, LocalGID: gid, PeerUID: uint32(o.brokerUID), PeerGID: uint32(o.brokerGID), LocalRelease: eg, PeerRelease: br, Epoch: o.epoch, ProxyAddress: fixedProxyAddress}
	client, e := modelegress.NewAuthenticatedControlClientForPeer(c, x)
	if e != nil {
		return e
	}
	return client.RevokeSession(ctx, sessionID)
}

func runtimeIdentity(o brokerOptions, pin macoschannel.ReleasePin, ev macoschannel.Evidence) codexbroker.ExpectedRuntimeIdentity {
	i := codexbroker.ExpectedRuntimeIdentity{RuntimeID: o.runtimeID, BrokerBinaryDigest: "sha256:" + pin.BinaryDigest, RuntimeBinaryDigest: o.runtimeDigest, PolicyDigest: policyDigest(o.policyFile), BrokerReleaseDigest: "sha256:" + pin.ManifestDigest, BrokerSocketDigest: "sha256:" + pin.SocketDigest, PeerUID: uint32(o.brokerUID), PeerGID: uint32(o.brokerGID), RuntimeUID: uint32(o.runtimeUID), RuntimeGID: uint32(o.runtimeGID), ExpectedEgressUID: uint32(o.egressUID), ExpectedEgressGID: uint32(o.egressGID), ExpectedEgressReleaseDigest: releaseDigest(o.egressLocalRelease), ExpectedEgressSocketDigest: socketDigest(o.egressLocalRelease), KeyEpoch: o.epoch, Channel: o.runtimeChannel, LocalRole: "runtime", PeerRole: "broker"}
	i.BindingDigest = i.ComputeBindingDigest(ev)
	return i
}

// renewRuntimeEgress keeps the broker-authenticated egress session alive for
// as long as its paired runtime channel exists. The runtime never receives a
// renewal capability: egress extends its bounded registry only after this
// broker control proof succeeds. Failure closes both ends fail-closed.
func renewRuntimeEgress(ctx context.Context, o brokerOptions, sessionID string, controller, runtime macoschannel.Conn) context.CancelFunc {
	childCtx, cancel := context.WithCancel(ctx)
	go func() {
		defer func() {
			proof, done := context.WithTimeout(context.Background(), 10*time.Second)
			_ = revokeEgress(proof, o, sessionID)
			done()
		}()
		ticker := time.NewTicker(runtimeEgressRenewInterval)
		defer ticker.Stop()
		for {
			select {
			case <-childCtx.Done():
				return
			case <-ticker.C:
				proofCtx, proofCancel := context.WithTimeout(childCtx, runtimeEgressRenewInterval)
				cap, err := connectEgress(proofCtx, o, sessionID)
				proofCancel()
				if err != nil || cap == nil {
					_ = runtime.Close()
					_ = controller.Close()
					return
				}
			}
		}
	}()
	return cancel
}

func runBroker(o brokerOptions) error {
	var broker, controller, runtimePin, brokerRuntime macoschannel.ReleasePin
	var e error
	if e = loadBrokerJSON(o.brokerLocalRelease, &broker); e != nil {
		return e
	}
	if e = loadBrokerJSON(o.controllerLocalRelease, &controller); e != nil {
		return e
	}
	if e = loadBrokerJSON(o.runtimeLocalRelease, &runtimePin); e != nil {
		return e
	}
	if e = loadBrokerJSON(o.brokerRuntimeRelease, &brokerRuntime); e != nil {
		return e
	}
	roots, e := verifiedroot.OpenAll([]verifiedroot.Requirement{{Name: "Controller socket", Path: o.socketRoot, UID: uint32(o.brokerUID), GID: uint32(o.channelGID), Mode: 0750}, {Name: "broker release", Path: o.releaseRoot, UID: 0, GID: uint32(o.brokerGID), Mode: 0550}, {Name: "Controller key", Path: o.controllerKeyRoot, UID: uint32(o.brokerUID), GID: uint32(o.brokerGID), Mode: 0700}, {Name: "runtime socket", Path: o.runtimeSocketRoot, UID: uint32(o.runtimeUID), GID: uint32(o.runtimeChannelGID), Mode: 0750}, {Name: "runtime key", Path: o.runtimeKeyRoot, UID: uint32(o.brokerUID), GID: uint32(o.brokerGID), Mode: 0700}})
	if e != nil {
		return e
	}
	defer verifiedroot.CloseAll(roots)
	key, e := servicekey.New(roots[2].Handle(), servicekey.Policy{FileName: o.controllerKeyFile, Channel: o.channel, OwnerUID: uint32(o.brokerUID), OwnerGID: uint32(o.brokerGID), Mode: 0600, RootUID: uint32(o.brokerUID), RootGID: uint32(o.brokerGID), RootMode: 0700})
	if e != nil {
		return e
	}
	rkey, e := servicekey.New(roots[4].Handle(), servicekey.Policy{FileName: o.runtimeKeyFile, Channel: o.runtimeChannel, OwnerUID: uint32(o.brokerUID), OwnerGID: uint32(o.brokerGID), Mode: 0600, RootUID: uint32(o.brokerUID), RootGID: uint32(o.brokerGID), RootMode: 0700})
	if e != nil {
		return e
	}
	uid, gid := uint32(o.peerUID), uint32(o.peerGID)
	cfg := macoschannel.Config{Contract: macoschannel.SocketContract{Channel: o.channel, LocalRole: "broker", PeerRole: "controller", SocketPath: o.controllerSocket, SocketRoot: o.socketRoot, ExpectedPeerUID: &uid, ExpectedPeerGID: &gid, ExpectedSocketRootUID: uint32(o.brokerUID), ExpectedSocketRootGID: uint32(o.channelGID), ExpectedSocketRootMode: 0750, ExpectedSocketUID: uint32(o.brokerUID), ExpectedSocketGID: uint32(o.channelGID), ExpectedSocketMode: 0660}, LocalRelease: broker, PeerRelease: controller, ReleaseRoot: roots[1].Handle(), SocketRootFD: roots[0].Handle(), BinaryName: o.binaryName, KeySource: key, ExpectedReleaseRootUID: 0, ExpectedReleaseRootGID: uint32(o.brokerGID), ExpectedReleaseRootMode: 0550, ExpectedManifestMode: 0440, ExpectedBinaryMode: 0550}
	ln, e := macoschannel.Listen(cfg)
	if e != nil {
		return e
	}
	defer ln.Close()
	ruid, rgid := uint32(o.runtimeUID), uint32(o.runtimeGID)
	rcfg := macoschannel.Config{Contract: macoschannel.SocketContract{Channel: o.runtimeChannel, LocalRole: "broker", PeerRole: "runtime", SocketPath: o.runtimeSocket, SocketRoot: o.runtimeSocketRoot, ExpectedPeerUID: &ruid, ExpectedPeerGID: &rgid, ExpectedSocketRootUID: ruid, ExpectedSocketRootGID: uint32(o.runtimeChannelGID), ExpectedSocketRootMode: 0750, ExpectedSocketUID: ruid, ExpectedSocketGID: uint32(o.runtimeChannelGID), ExpectedSocketMode: 0660}, LocalRelease: brokerRuntime, PeerRelease: runtimePin, ReleaseRoot: roots[1].Handle(), SocketRootFD: roots[3].Handle(), BinaryName: o.binaryName, KeySource: rkey, ExpectedReleaseRootUID: 0, ExpectedReleaseRootGID: uint32(o.brokerGID), ExpectedReleaseRootMode: 0550, ExpectedManifestMode: 0440, ExpectedBinaryMode: 0550}
	d, e := macoschannel.NewDialer(rcfg)
	if e != nil {
		return e
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() { <-ctx.Done(); _ = ln.Close() }()
	var wg sync.WaitGroup
	for {
		cc, e := ln.AcceptAuthenticated(ctx)
		if e != nil {
			break
		}
		sessionID := cc.Evidence().BindingDigest
		if sessionID == "" {
			_ = cc.Close()
			continue
		}
		// A grant is issued only from a newly authenticated egress receipt. The
		// broker keeps the opaque capability; the runtime receives neither a
		// renewable handle nor a path to the egress control channel.
		renewCtx, renewCancel := context.WithTimeout(ctx, 10*time.Second)
		currentCap, renewErr := connectEgress(renewCtx, o, sessionID)
		renewCancel()
		if renewErr != nil || currentCap == nil {
			_ = cc.Close()
			continue
		}
		rc, e := d.Dial(ctx)
		if e != nil {
			_ = cc.Close()
			continue
		}
		g, e := codexruntimewire.Issue(rc, currentCap, uint32(o.brokerUID), uint32(o.brokerGID), ruid, rgid, time.Now().UTC())
		if e == nil {
			gc, cancel := context.WithTimeout(ctx, 5*time.Second)
			e = codexruntimewire.WriteGrant(gc, rc, g)
			cancel()
		}
		ri := runtimeIdentity(o, runtimePin, rc.Evidence())
		if e != nil || ri.BindingDigest == "" {
			_ = rc.Close()
			_ = cc.Close()
			continue
		}
		client, e := codexbroker.NewProductionClient(rc, ri)
		if e != nil {
			_ = rc.Close()
			_ = cc.Close()
			continue
		}
		ci := codexbroker.ExpectedRuntimeIdentity{RuntimeID: o.runtimeID, BrokerBinaryDigest: "sha256:" + broker.BinaryDigest, RuntimeBinaryDigest: o.runtimeDigest, PolicyDigest: ri.PolicyDigest, BrokerReleaseDigest: "sha256:" + broker.ManifestDigest, BrokerSocketDigest: "sha256:" + broker.SocketDigest, PeerUID: uid, PeerGID: gid, RuntimeUID: uint32(o.brokerUID), RuntimeGID: uint32(o.brokerGID), ExpectedEgressUID: uint32(o.egressUID), ExpectedEgressGID: uint32(o.egressGID), ExpectedEgressReleaseDigest: ri.ExpectedEgressReleaseDigest, ExpectedEgressSocketDigest: ri.ExpectedEgressSocketDigest, KeyEpoch: o.epoch, Channel: o.channel, LocalRole: "broker", PeerRole: "controller"}
		ci.BindingDigest = ci.ComputeBindingDigest(cc.Evidence())
		att := codexbroker.BoundaryAttestation{SchemaVersion: codexbroker.ProtocolV1, RuntimeID: o.runtimeID, PeerID: o.channel + ":controller", RuntimeBinaryDigest: o.runtimeDigest, PolicyDigest: ci.PolicyDigest, IssuedAt: time.Now().UTC(), PeerUID: uid, PeerGID: gid, Epoch: o.epoch, BrokerSocketDigest: ci.BrokerSocketDigest, BrokerReleaseDigest: ci.BrokerReleaseDigest, ExpectedEgressUID: uint32(o.egressUID), ExpectedEgressGID: uint32(o.egressGID), ExpectedEgressReleaseDigest: ci.ExpectedEgressReleaseDigest, ExpectedEgressSocketDigest: ci.ExpectedEgressSocketDigest, Signature: codexbroker.Digest(ci.BindingDigest)}
		b, e := codexbroker.NewForwardingBackend(client, att)
		if e != nil || ci.BindingDigest == "" {
			_ = rc.Close()
			_ = cc.Close()
			continue
		}
		s, e := codexbroker.NewProductionServer(cc, b, ci)
		if e != nil {
			_ = rc.Close()
			_ = cc.Close()
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer rc.Close()
			defer cc.Close()
			renewStop := renewRuntimeEgress(ctx, o, sessionID, cc, rc)
			defer renewStop()
			_ = s.Serve(ctx)
		}()
	}
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
		return nil
	case <-time.After(3 * time.Second):
		return errors.New("broker shutdown timed out")
	}
}
func policyDigest(path string) string {
	var p modelegress.Policy
	if loadBrokerJSON(path, &p) != nil {
		return ""
	}
	d, _ := p.Digest()
	return d
}
func releaseDigest(path string) string {
	var p macoschannel.ReleasePin
	if loadBrokerJSON(path, &p) != nil {
		return ""
	}
	return "sha256:" + p.ManifestDigest
}
func socketDigest(path string) string {
	var p macoschannel.ReleasePin
	if loadBrokerJSON(path, &p) != nil {
		return ""
	}
	return "sha256:" + p.SocketDigest
}
