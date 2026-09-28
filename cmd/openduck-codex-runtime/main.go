// Command openduck-codex-runtime is the only process that launches Codex.
// It runs as _openduck_codex and accepts a sealed, non-renewable ProxyGrant
// from _openduck_broker before exposing the typed runtime protocol.
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
	"openduck/internal/codexruntime"
	"openduck/internal/codexruntimewire"
	"openduck/internal/macoschannel"
	"openduck/internal/servicekey"
	"openduck/internal/verifiedroot"
)

type options struct {
	production                                                                                                                                bool
	binaryName, runtimeID, home, cwd, model                                                                                                   string
	channel, socketRoot, socket, releaseRoot, keyRoot, keyFile                                                                                string
	runtimeRelease, brokerRelease                                                                                                             string
	codexReleaseRoot, codexBinaryName, codexReleaseID, codexBinaryDigest, codexManifestDigest, codexSocketDigest                              string
	sandboxRoot, sandboxExec, pfStateFile, pfDigest, pfEvidenceFile, pfEvidenceDigest, pfRulesDigest, bootID, seatbeltProfile, seatbeltDigest string
	policyDigest, egressReleaseDigest, egressSocketDigest                                                                                     string
	runtimeUID, runtimeGID, brokerUID, brokerGID, channelGID, egressUID, egressGID                                                            uint
	epoch                                                                                                                                     uint64
}

func load(path string, out any) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	d := json.NewDecoder(f)
	d.DisallowUnknownFields()
	return d.Decode(out)
}

func parse(args []string) (options, error) {
	var o options
	f := flag.NewFlagSet("openduck-codex-runtime", flag.ContinueOnError)
	f.BoolVar(&o.production, "production-admission", false, "require authenticated runtime composition")
	f.StringVar(&o.binaryName, "runtime-binary-name", "", "runtime daemon release binary leaf")
	f.StringVar(&o.runtimeID, "runtime-id", "", "runtime identity")
	f.StringVar(&o.codexReleaseRoot, "codex-release-root", "", "root-owned immutable Codex artifact release root")
	f.StringVar(&o.codexBinaryName, "codex-binary-name", "", "Codex artifact binary leaf")
	f.StringVar(&o.codexReleaseID, "codex-release-id", "", "Codex artifact release id")
	f.StringVar(&o.codexBinaryDigest, "codex-binary-digest", "", "sha256: Codex artifact binary digest")
	f.StringVar(&o.codexManifestDigest, "codex-manifest-digest", "", "sha256: Codex artifact manifest digest")
	f.StringVar(&o.codexSocketDigest, "codex-socket-digest", "", "sha256: Codex artifact release socket metadata digest")
	f.StringVar(&o.home, "codex-home", "", "runtime-only CODEX_HOME")
	f.StringVar(&o.cwd, "cwd", "", "runtime-only working directory")
	f.StringVar(&o.model, "model", "", "fixed model")
	f.StringVar(&o.channel, "runtime-channel", "", "broker-runtime channel")
	f.StringVar(&o.socketRoot, "runtime-socket-root", "", "broker-runtime socket root")
	f.StringVar(&o.socket, "runtime-socket", "runtime.sock", "broker-runtime socket leaf")
	f.StringVar(&o.releaseRoot, "runtime-release-root", "", "runtime release root")
	f.StringVar(&o.keyRoot, "runtime-key-root", "", "runtime channel key root")
	f.StringVar(&o.keyFile, "runtime-key-file", "", "runtime channel key leaf")
	f.StringVar(&o.runtimeRelease, "runtime-local-release", "", "runtime release pin JSON")
	f.StringVar(&o.brokerRelease, "broker-runtime-release", "", "broker release pin JSON")
	f.StringVar(&o.sandboxRoot, "sandbox-root", "", "root-owned PF and seatbelt evidence root")
	f.StringVar(&o.sandboxExec, "sandbox-exec", "", "sandbox-exec")
	f.StringVar(&o.pfStateFile, "pf-state-file", "", "PF state leaf")
	f.StringVar(&o.pfDigest, "pf-digest", "", "PF policy digest")
	f.StringVar(&o.pfEvidenceFile, "pf-evidence-file", "", "root-produced canonical PF evidence leaf")
	f.StringVar(&o.pfEvidenceDigest, "pf-evidence-digest", "", "canonical PF evidence sha256")
	f.StringVar(&o.pfRulesDigest, "pf-rules-digest", "", "canonical com.openduck PF anchor rules sha256")
	f.StringVar(&o.bootID, "boot-id", "", "activation boot identity")
	f.StringVar(&o.seatbeltProfile, "seatbelt-profile", "", "seatbelt profile leaf")
	f.StringVar(&o.seatbeltDigest, "seatbelt-digest", "", "seatbelt digest")
	f.StringVar(&o.policyDigest, "policy-digest", "", "egress policy digest")
	f.StringVar(&o.egressReleaseDigest, "egress-release-digest", "", "egress release digest")
	f.StringVar(&o.egressSocketDigest, "egress-socket-digest", "", "egress socket digest")
	f.UintVar(&o.runtimeUID, "runtime-uid", 0, "runtime uid")
	f.UintVar(&o.runtimeGID, "runtime-gid", 0, "runtime gid")
	f.UintVar(&o.brokerUID, "broker-uid", 0, "broker uid")
	f.UintVar(&o.brokerGID, "broker-gid", 0, "broker gid")
	f.UintVar(&o.channelGID, "runtime-channel-gid", 0, "runtime channel gid")
	f.UintVar(&o.egressUID, "egress-uid", 0, "egress uid (attestation only)")
	f.UintVar(&o.egressGID, "egress-gid", 0, "egress gid (attestation only)")
	f.Uint64Var(&o.epoch, "key-epoch", 0, "channel key epoch")
	if err := f.Parse(args); err != nil || f.NArg() != 0 || !o.production {
		return options{}, errors.New("production runtime mode is required")
	}
	for _, p := range []string{o.home, o.cwd, o.socketRoot, o.releaseRoot, o.keyRoot, o.codexReleaseRoot, o.sandboxRoot, o.sandboxExec} {
		if !filepath.IsAbs(p) || filepath.Clean(p) != p || p == string(filepath.Separator) {
			return options{}, codexruntime.ErrProductionIsolationConfig
		}
	}
	for _, s := range []string{o.binaryName, o.runtimeID, o.codexBinaryName, o.codexReleaseID, o.codexBinaryDigest, o.codexManifestDigest, o.codexSocketDigest, o.model, o.channel, o.socket, o.keyFile, o.runtimeRelease, o.brokerRelease, o.pfStateFile, o.pfDigest, o.pfEvidenceFile, o.pfEvidenceDigest, o.pfRulesDigest, o.bootID, o.seatbeltProfile, o.seatbeltDigest, o.policyDigest, o.egressReleaseDigest, o.egressSocketDigest} {
		if s == "" {
			return options{}, codexruntime.ErrProductionIsolationConfig
		}
	}
	if filepath.Base(o.socket) != o.socket || filepath.Base(o.keyFile) != o.keyFile || filepath.Base(o.codexBinaryName) != o.codexBinaryName || filepath.Base(o.pfStateFile) != o.pfStateFile || filepath.Base(o.pfEvidenceFile) != o.pfEvidenceFile || filepath.Base(o.seatbeltProfile) != o.seatbeltProfile || trim(o.codexBinaryDigest) == "" || trim(o.codexManifestDigest) == "" || trim(o.codexSocketDigest) == "" || o.runtimeUID == 0 || o.runtimeGID == 0 || o.brokerUID == 0 || o.brokerGID == 0 || o.runtimeUID == o.brokerUID || o.channelGID == 0 || o.egressUID == 0 || o.egressGID == 0 || o.epoch == 0 {
		return options{}, codexruntime.ErrProductionIsolationConfig
	}
	return o, nil
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string) error {
	o, err := parse(args)
	if err != nil {
		return err
	}
	var local, peer macoschannel.ReleasePin
	if err = load(o.runtimeRelease, &local); err != nil {
		return err
	}
	if err = load(o.brokerRelease, &peer); err != nil {
		return err
	}
	roots, err := verifiedroot.OpenAll([]verifiedroot.Requirement{
		{Name: "runtime channel", Path: o.socketRoot, UID: uint32(o.runtimeUID), GID: uint32(o.channelGID), Mode: 0750},
		{Name: "runtime release", Path: o.releaseRoot, UID: 0, GID: uint32(o.runtimeGID), Mode: 0550},
		{Name: "runtime key", Path: o.keyRoot, UID: uint32(o.runtimeUID), GID: uint32(o.runtimeGID), Mode: 0700},
		{Name: "runtime home", Path: o.home, UID: uint32(o.runtimeUID), GID: uint32(o.runtimeGID), Mode: 0700},
		{Name: "runtime cwd", Path: o.cwd, UID: uint32(o.runtimeUID), GID: uint32(o.runtimeGID), Mode: 0700},
		{Name: "codex artifact", Path: o.codexReleaseRoot, UID: 0, GID: 0, Mode: 0755},
		{Name: "sandbox evidence", Path: o.sandboxRoot, UID: 0, GID: 0, Mode: 0755},
	})
	if err != nil {
		return err
	}
	defer verifiedroot.CloseAll(roots)
	key, err := servicekey.New(roots[2].Handle(), servicekey.Policy{FileName: o.keyFile, Channel: o.channel, OwnerUID: uint32(o.runtimeUID), OwnerGID: uint32(o.runtimeGID), Mode: 0600, RootUID: uint32(o.runtimeUID), RootGID: uint32(o.runtimeGID), RootMode: 0700})
	if err != nil {
		return err
	}
	uid, gid := uint32(o.brokerUID), uint32(o.brokerGID)
	cfg := macoschannel.Config{Contract: macoschannel.SocketContract{Channel: o.channel, LocalRole: "runtime", PeerRole: "broker", SocketPath: o.socket, SocketRoot: o.socketRoot, ExpectedPeerUID: &uid, ExpectedPeerGID: &gid, ExpectedSocketRootUID: uint32(o.runtimeUID), ExpectedSocketRootGID: uint32(o.channelGID), ExpectedSocketRootMode: 0750, ExpectedSocketUID: uint32(o.runtimeUID), ExpectedSocketGID: uint32(o.channelGID), ExpectedSocketMode: 0660}, LocalRelease: local, PeerRelease: peer, ReleaseRoot: roots[1].Handle(), SocketRootFD: roots[0].Handle(), BinaryName: o.binaryName, KeySource: key, ExpectedReleaseRootUID: 0, ExpectedReleaseRootGID: uint32(o.runtimeGID), ExpectedReleaseRootMode: 0550, ExpectedManifestMode: 0440, ExpectedBinaryMode: 0550}
	listener, err := macoschannel.Listen(cfg)
	if err != nil {
		return err
	}
	defer listener.Close()
	codexPin := macoschannel.ReleasePin{ReleaseID: o.codexReleaseID, BinaryDigest: trim(o.codexBinaryDigest), SocketDigest: trim(o.codexSocketDigest), ManifestDigest: trim(o.codexManifestDigest)}
	if err := macoschannel.VerifyReleaseOwned(roots[5].Handle(), codexPin, o.codexBinaryName, 0, 0, 0644, 0755, 0755); err != nil {
		return err
	}
	sandbox, err := codexruntime.NewDarwinSandbox(&roots[6], o.pfStateFile, o.seatbeltProfile, o.pfDigest, o.seatbeltDigest, o.pfEvidenceFile, o.pfEvidenceDigest, o.pfRulesDigest, o.bootID)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() { <-ctx.Done(); _ = listener.Close() }()
	var wg sync.WaitGroup
	for {
		conn, err := listener.AcceptAuthenticated(ctx)
		if err != nil {
			break
		}
		grantCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		grant, err := codexruntimewire.ReadGrant(grantCtx, conn)
		cancel()
		if err != nil {
			_ = conn.Close()
			continue
		}
		// PF evidence is activation-fresh, not a daemon-start boolean. Recheck
		// it for every accepted broker-runtime session before composing backend.
		if codexruntime.RevalidateProductionSandbox(sandbox) != nil {
			_ = conn.Close()
			continue
		}
		identity := codexbroker.ExpectedRuntimeIdentity{RuntimeID: o.runtimeID, BrokerBinaryDigest: "sha256:" + local.BinaryDigest, RuntimeBinaryDigest: o.codexBinaryDigest, PolicyDigest: o.policyDigest, BrokerReleaseDigest: "sha256:" + local.ManifestDigest, BrokerSocketDigest: "sha256:" + local.SocketDigest, PeerUID: uint32(o.brokerUID), PeerGID: uint32(o.brokerGID), RuntimeUID: uint32(o.runtimeUID), RuntimeGID: uint32(o.runtimeGID), ExpectedEgressUID: uint32(o.egressUID), ExpectedEgressGID: uint32(o.egressGID), ExpectedEgressReleaseDigest: o.egressReleaseDigest, ExpectedEgressSocketDigest: o.egressSocketDigest, KeyEpoch: o.epoch, Channel: o.channel, LocalRole: "runtime", PeerRole: "broker"}
		identity.BindingDigest = identity.ComputeBindingDigest(conn.Evidence())
		if identity.BindingDigest == "" || grant.BindingDigest != conn.Evidence().BindingDigest {
			_ = conn.Close()
			continue
		}
		att := codexbroker.BoundaryAttestation{SchemaVersion: codexbroker.ProtocolV1, RuntimeID: identity.RuntimeID, PeerID: o.channel + ":broker", RuntimeBinaryDigest: identity.RuntimeBinaryDigest, PolicyDigest: identity.PolicyDigest, IssuedAt: time.Now().UTC(), PeerUID: identity.PeerUID, PeerGID: identity.PeerGID, Epoch: identity.KeyEpoch, BrokerSocketDigest: identity.BrokerSocketDigest, BrokerReleaseDigest: identity.BrokerReleaseDigest, ExpectedEgressUID: identity.ExpectedEgressUID, ExpectedEgressGID: identity.ExpectedEgressGID, ExpectedEgressReleaseDigest: identity.ExpectedEgressReleaseDigest, ExpectedEgressSocketDigest: identity.ExpectedEgressSocketDigest, Signature: codexbroker.Digest(identity.BindingDigest)}
		isolation, err := codexruntime.NewProductionRuntimeIsolation(codexruntime.ProductionIsolationConfig{Binary: filepath.Join(o.codexReleaseRoot, o.codexBinaryName), SandboxExec: o.sandboxExec, SandboxProfile: filepath.Join(o.sandboxRoot, o.seatbeltProfile), Arguments: []string{"app-server", "--model", o.model}, CodexHome: o.home, PrivateCWD: o.cwd, Model: o.model, ProxyAddress: grant.ProxyURL, ProxyGrantExpiresAt: grant.ExpiresAt, Identity: identity, Attestation: att, HomeRoot: &roots[3], CWDRoot: &roots[4], ReleaseRoot: &roots[5], BinaryName: o.codexBinaryName, BinaryDigest: trim(o.codexBinaryDigest), ArtifactRelease: codexPin, Sandbox: sandbox})
		if err != nil {
			_ = conn.Close()
			continue
		}
		backend, err := codexruntime.NewProductionBackend(identity, isolation, o.model)
		if err != nil {
			_ = conn.Close()
			continue
		}
		server, err := codexbroker.NewProductionServer(conn, backend, identity)
		if err != nil {
			_ = conn.Close()
			continue
		}
		wg.Add(1)
		go func() { defer wg.Done(); defer conn.Close(); _ = server.Serve(ctx) }()
	}
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
		return nil
	case <-time.After(3 * time.Second):
		return errors.New("runtime shutdown timed out")
	}
}

func trim(v string) string {
	if len(v) == 71 && v[:7] == "sha256:" {
		return v[7:]
	}
	return ""
}
