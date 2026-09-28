// Command openduck-egress is intentionally only a production composition root.
// Until launchd supplies an authenticated capability it exits closed and never
// opens a listener, resolves a name, or reads credentials.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"

	"openduck/internal/macoschannel"
	"openduck/internal/modelegress"
	"openduck/internal/servicekey"
	"openduck/internal/verifiedroot"
)

type egressOptions struct {
	production                                                                                                bool
	channel, socketRoot, releaseRoot, keyRoot, binary, keyFile, policyFile, localReleaseFile, peerReleaseFile string
	policyDigest, releaseDigest, socketDigest                                                                 string
	localUID, localGID, peerUID, peerGID, socketUID, socketGID, rootUID, rootGID, channelGID                  uint
	epoch                                                                                                     uint64
	controlSocket, binaryName                                                                                 string
	max                                                                                                       int
	rootMode, socketMode, keyMode, manifestMode, binaryMode                                                   os.FileMode
	proxyAddress                                                                                              string
}

func parseMode(s string, def os.FileMode) (os.FileMode, error) {
	if s == "" {
		return def, nil
	}
	n, err := strconv.ParseUint(s, 8, 9)
	return os.FileMode(n), err
}
func loadJSON(path string, out any) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	d := json.NewDecoder(f)
	d.DisallowUnknownFields()
	return d.Decode(out)
}

func validatePolicyPins(opts egressOptions, p modelegress.Policy) error {
	policyDigest, err := p.Digest()
	if err != nil || policyDigest != opts.policyDigest || p.ReleaseDigest != opts.releaseDigest || p.SocketDigest != opts.socketDigest || p.ProxyUID != uint32(opts.localUID) || p.ProxyGID != uint32(opts.localGID) || p.Epoch != opts.epoch {
		return errors.New("egress policy pins do not match launch contract")
	}
	return nil
}

func compose(opts egressOptions) (context.CancelFunc, <-chan struct{}, error) {
	if opts.channel == "" || opts.controlSocket == "" || opts.binaryName == "" || opts.max < 1 {
		return nil, nil, errors.New("egress channel options incomplete")
	}
	var p modelegress.Policy
	if err := loadJSON(opts.policyFile, &p); err != nil || p.Validate() != nil {
		return nil, nil, errors.New("egress policy unavailable")
	}
	if err := validatePolicyPins(opts, p); err != nil {
		return nil, nil, err
	}
	var local, peer macoschannel.ReleasePin
	if err := loadJSON(opts.localReleaseFile, &local); err != nil {
		return nil, nil, err
	}
	if err := loadJSON(opts.peerReleaseFile, &peer); err != nil {
		return nil, nil, err
	}
	roots, err := verifiedroot.OpenAll([]verifiedroot.Requirement{{Name: "socket", Path: opts.socketRoot, UID: uint32(opts.localUID), GID: uint32(opts.channelGID), Mode: 0750}, {Name: "release", Path: opts.releaseRoot, UID: 0, GID: uint32(opts.localGID), Mode: 0550}, {Name: "key", Path: opts.keyRoot, UID: uint32(opts.localUID), GID: uint32(opts.localGID), Mode: opts.rootMode}})
	if err != nil {
		return nil, nil, err
	}
	cleanup := func() { verifiedroot.CloseAll(roots) }
	ks, err := servicekey.New(roots[2].Handle(), servicekey.Policy{FileName: opts.keyFile, Channel: opts.channel, OwnerUID: uint32(opts.localUID), OwnerGID: uint32(opts.localGID), Mode: opts.keyMode, RootUID: uint32(opts.localUID), RootGID: uint32(opts.localGID), RootMode: opts.rootMode})
	if err != nil {
		cleanup()
		return nil, nil, err
	}
	uid, gid := uint32(opts.peerUID), uint32(opts.peerGID)
	cfg := macoschannel.Config{Contract: macoschannel.SocketContract{Channel: opts.channel, LocalRole: "egress", PeerRole: "broker", SocketPath: opts.controlSocket, SocketRoot: opts.socketRoot, ExpectedPeerUID: &uid, ExpectedPeerGID: &gid, ExpectedSocketRootUID: uint32(opts.localUID), ExpectedSocketRootGID: uint32(opts.channelGID), ExpectedSocketRootMode: 0750, ExpectedSocketUID: uint32(opts.localUID), ExpectedSocketGID: uint32(opts.channelGID), ExpectedSocketMode: 0660}, LocalRelease: local, PeerRelease: peer, ReleaseRoot: roots[1].Handle(), SocketRootFD: roots[0].Handle(), BinaryName: opts.binaryName, KeySource: ks, ExpectedReleaseRootUID: 0, ExpectedReleaseRootGID: uint32(opts.localGID), ExpectedReleaseRootMode: 0550, ExpectedManifestMode: 0440, ExpectedBinaryMode: 0550}
	ln, err := macoschannel.Listen(cfg)
	if err != nil {
		cleanup()
		return nil, nil, err
	}
	data, err := net.Listen("tcp", opts.proxyAddress)
	if err != nil {
		_ = ln.Close()
		cleanup()
		return nil, nil, err
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	var wg sync.WaitGroup
	// Both values are process-global for this egress daemon. Constructing a
	// proxy per TCP connection must not create an independent connection limit
	// or invalidate a different runtime session's token.
	registry := modelegress.NewCapabilityRegistry(opts.max * 4)
	admission := modelegress.NewConnectionLimiter(opts.max * 2)
	limiter := modelegress.NewConnectionLimiter(opts.max)
	if registry == nil || admission == nil || limiter == nil {
		_ = ln.Close()
		_ = data.Close()
		cleanup()
		return nil, nil, errors.New("egress session registry unavailable")
	}
	wg.Add(1)
	go func() { defer wg.Done(); <-ctx.Done(); _ = ln.Close(); _ = data.Close() }()
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			c, e := ln.AcceptAuthenticated(ctx)
			if e != nil {
				return
			}
			go func() {
				s, e := modelegress.NewAuthenticatedControlServer(c, modelegress.ControlExpectation{Policy: p, Channel: opts.channel, LocalRole: "egress", PeerRole: "broker", LocalUID: uint32(opts.localUID), LocalGID: uint32(opts.localGID), PeerUID: uint32(opts.peerUID), PeerGID: uint32(opts.peerGID), LocalRelease: local, PeerRelease: peer, Epoch: opts.epoch, ProxyAddress: opts.proxyAddress})
				if e == nil {
					// ServeWithRegistry registers a token before its ready receipt,
					// but only under the exact supplied runtime session. Renewal
					// refreshes that entry rather than every live or orphan token.
					_ = s.ServeWithRegistry(ctx, registry)
				}
				_ = c.Close()
			}()
		}
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			c, e := data.Accept()
			if e != nil {
				return
			}
			go func() {
				srv, err := modelegress.NewProductionProxyWithRegistry(p, registry, modelegress.SystemResolver{}, modelegress.SystemDialer{}, admission, limiter)
				if err == nil {
					_ = srv.ServeConn(ctx, c)
				} else {
					_ = c.Close()
				}
			}()
		}
	}()
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	return func() { cancel(); <-done; cleanup() }, done, nil
}

func parseEgressOptions(args []string) (egressOptions, error) {
	fs := flag.NewFlagSet("openduck-egress", flag.ContinueOnError)
	production := fs.Bool("production-admission", false, "require authenticated production composition")
	channel := fs.String("channel", "", "exact channel name")
	socketRoot := fs.String("socket-root", "", "pre-provisioned channel root")
	releaseRoot := fs.String("release-root", "", "pre-provisioned release root")
	keyRoot := fs.String("key-root", "", "pre-provisioned key root")
	binary := fs.String("binary", "", "pinned egress binary")
	policy := fs.String("policy", "", "policy digest")
	release := fs.String("release-digest", "", "release digest")
	socket := fs.String("socket-digest", "", "socket digest")
	keyFile := fs.String("key-file", "", "key leaf name")
	uid := fs.Uint("uid", 0, "egress service uid")
	gid := fs.Uint("gid", 0, "egress service gid")
	peerUID := fs.Uint("peer-uid", 0, "broker peer uid")
	peerGID := fs.Uint("peer-gid", 0, "broker peer gid")
	channelGID := fs.Uint("channel-gid", 0, "shared channel group gid")
	epoch := fs.Uint64("epoch", 0, "channel key epoch")
	controlSocket := fs.String("control-socket", "control.sock", "control socket leaf")
	policyFile := fs.String("policy-file", "", "policy JSON")
	localReleaseFile := fs.String("local-release", "", "local release pin JSON")
	peerReleaseFile := fs.String("peer-release", "", "peer release pin JSON")
	binaryName := fs.String("binary-name", "", "release binary leaf")
	max := fs.Int("max-connections", 8, "maximum proxy connections")
	proxyAddress := fs.String("proxy-address", "127.0.0.1:8790", "fixed loopback model proxy address")
	if err := fs.Parse(args); err != nil {
		return egressOptions{}, err
	}
	if fs.NArg() != 0 || !*production {
		return egressOptions{}, errors.New("production mode is required; synthetic egress is disabled")
	}
	for _, p := range []string{*socketRoot, *releaseRoot, *keyRoot, *binary} {
		if p == "" || !filepath.IsAbs(p) || filepath.Clean(p) != p || p == string(filepath.Separator) {
			return egressOptions{}, errors.New("explicit production roots and binary are required")
		}
	}
	if *channel == "" || *policy == "" || *release == "" || *socket == "" || *keyFile == "" || *policyFile == "" || *localReleaseFile == "" || *peerReleaseFile == "" || *binaryName == "" || *uid == 0 || *gid == 0 || *channelGID == 0 || *peerUID == 0 || *peerGID == 0 || *uid == *peerUID || *channelGID == *gid || *channelGID == *peerGID || *epoch == 0 || filepath.Base(*keyFile) != *keyFile || filepath.Base(*controlSocket) != *controlSocket || filepath.Base(*binaryName) != *binaryName {
		return egressOptions{}, errors.New("explicit production channel, policy, identity and key are required")
	}
	rootMode, _ := parseMode("", 0700)
	socketMode, _ := parseMode("", 0660)
	keyMode, _ := parseMode("", 0600)
	manifestMode, _ := parseMode("", 0600)
	binaryMode, _ := parseMode("", 0700)
	return egressOptions{production: true, channel: *channel, socketRoot: *socketRoot, releaseRoot: *releaseRoot, keyRoot: *keyRoot, binary: *binary, keyFile: *keyFile, policyFile: *policyFile, localReleaseFile: *localReleaseFile, peerReleaseFile: *peerReleaseFile, policyDigest: *policy, releaseDigest: *release, socketDigest: *socket, localUID: uint(*uid), localGID: uint(*gid), channelGID: uint(*channelGID), peerUID: uint(*peerUID), peerGID: uint(*peerGID), socketUID: uint(*uid), socketGID: uint(*channelGID), rootUID: uint(*uid), rootGID: uint(*gid), epoch: *epoch, controlSocket: *controlSocket, binaryName: *binaryName, max: *max, rootMode: rootMode, socketMode: socketMode, keyMode: keyMode, manifestMode: manifestMode, binaryMode: binaryMode, proxyAddress: *proxyAddress}, nil
}

func run(args []string) error {
	opts, err := parseEgressOptions(args)
	if err != nil {
		return err
	}
	stop, done, err := compose(opts)
	if err != nil {
		return err
	}
	defer stop()
	<-done
	return nil
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
