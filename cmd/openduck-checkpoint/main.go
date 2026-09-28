// Command openduck-checkpoint hosts the independently-owned monotonic
// checkpoint authority. It is production-only: synthetic checkpoints remain
// explicit test fixtures in internal/platformcheckpoint.
package main

import (
	"context"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"openduck/internal/macoschannel"
	"openduck/internal/platformcheckpoint"
	"openduck/internal/servicekey"
	"openduck/internal/verifiedroot"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
)

type options struct {
	state, socketRoot, socket, keyRoot, keyFile, releaseRoot                             string
	journalSocketRoot, journalSocket, journalKeyRoot, journalKeyFile, journalReleaseRoot string
	channel, localRole, peerRole                                                         string
	journalRole, journalPeerRole                                                         string
	localRelease, peerRelease                                                            macoschannel.ReleasePin
	journalLocalRelease, journalPeerRelease                                              macoschannel.ReleasePin
	localUID, localGID, peerUID, peerGID, channelGID                                     uint32
	journalPeerUID, journalPeerGID, journalChannelGID                                    uint32
	keyEpoch                                                                             uint64
	numeric                                                                              map[string]bool
	specified                                                                            map[string]bool
}

const (
	journalChannel   = platformcheckpoint.JournalAudience
	journalLocalRole = "checkpoint"
	journalPeerRole  = "installer"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "openduck-checkpoint:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	o, err := parse(args)
	if err != nil {
		return err
	}
	return runProduction(o)
}

func parse(args []string) (options, error) {
	o := options{numeric: map[string]bool{}, specified: map[string]bool{}}
	fs := flag.NewFlagSet("openduck-checkpoint", flag.ContinueOnError)
	fs.StringVar(&o.state, "state", "", "private checkpoint state directory")
	fs.StringVar(&o.socketRoot, "socket-root", "", "pre-provisioned checkpoint socket directory")
	fs.StringVar(&o.socket, "socket", "checkpoint.sock", "checkpoint socket leaf")
	fs.StringVar(&o.keyRoot, "key-root", "", "pre-provisioned service-key root")
	fs.StringVar(&o.keyFile, "key-file", "service.key", "service-key leaf")
	fs.StringVar(&o.releaseRoot, "release-root", "", "pre-provisioned checkpoint release root")
	fs.StringVar(&o.journalSocketRoot, "journal-socket-root", "", "installer journal socket root")
	fs.StringVar(&o.journalSocket, "journal-socket", "journal.sock", "installer journal socket leaf")
	fs.StringVar(&o.journalKeyRoot, "journal-key-root", "", "installer journal key root")
	fs.StringVar(&o.journalKeyFile, "journal-key-file", "journal.key", "installer journal key leaf")
	fs.StringVar(&o.journalReleaseRoot, "journal-release-root", "", "installer journal release root")
	fs.StringVar(&o.channel, "channel", "platform-checkpoint", "authenticated channel")
	fs.StringVar(&o.localRole, "local-role", "checkpoint", "local channel role")
	fs.StringVar(&o.peerRole, "peer-role", "anchor", "peer channel role")
	fs.StringVar(&o.journalRole, "journal-local-role", "checkpoint", "journal local role")
	fs.StringVar(&o.journalPeerRole, "journal-peer-role", "installer", "journal peer role")
	bindPin(fs, &o.localRelease, "local")
	bindPin(fs, &o.peerRelease, "peer")
	bindPin(fs, &o.journalLocalRelease, "journal-local")
	bindPin(fs, &o.journalPeerRelease, "journal-peer")
	bindUint(fs, &o.localUID, "local-uid", o.numeric)
	bindUint(fs, &o.localGID, "local-gid", o.numeric)
	bindUint(fs, &o.peerUID, "peer-uid", o.numeric)
	bindUint(fs, &o.peerGID, "peer-gid", o.numeric)
	bindUint(fs, &o.channelGID, "channel-gid", o.numeric)
	bindUint64(fs, &o.keyEpoch, "key-epoch", o.numeric)
	bindUint(fs, &o.journalPeerUID, "journal-peer-uid", o.numeric)
	bindUint(fs, &o.journalPeerGID, "journal-peer-gid", o.numeric)
	bindUint(fs, &o.journalChannelGID, "journal-channel-gid", o.numeric)
	if err := fs.Parse(args); err != nil {
		return options{}, err
	}
	if fs.NArg() != 0 {
		return options{}, errors.New("unexpected positional arguments")
	}
	fs.Visit(func(f *flag.Flag) { o.specified[f.Name] = true })
	if err := validate(o); err != nil {
		return options{}, err
	}
	return o, nil
}

func bindPin(fs *flag.FlagSet, p *macoschannel.ReleasePin, prefix string) {
	fs.StringVar(&p.ReleaseID, prefix+"-release", "", prefix+" release id")
	fs.StringVar(&p.BinaryDigest, prefix+"-binary-digest", "", prefix+" binary digest")
	fs.StringVar(&p.SocketDigest, prefix+"-socket-digest", "", prefix+" socket digest")
	fs.StringVar(&p.ManifestDigest, prefix+"-manifest-digest", "", prefix+" manifest digest")
}
func bindUint(fs *flag.FlagSet, p *uint32, name string, set map[string]bool) {
	fs.Func(name, name, func(raw string) error {
		n, err := strconv.ParseUint(raw, 10, 32)
		if err != nil {
			return err
		}
		*p = uint32(n)
		set[name] = true
		return nil
	})
}
func bindUint64(fs *flag.FlagSet, p *uint64, name string, set map[string]bool) {
	fs.Func(name, name, func(raw string) error {
		n, err := strconv.ParseUint(raw, 10, 64)
		if err != nil || n == 0 {
			return errors.New("invalid positive integer")
		}
		*p = n
		set[name] = true
		return nil
	})
}
func validate(o options) error {
	for name, p := range map[string]string{"state": o.state, "socket-root": o.socketRoot, "key-root": o.keyRoot, "release-root": o.releaseRoot} {
		if p == "" || !filepath.IsAbs(p) || filepath.Clean(p) != p {
			return fmt.Errorf("invalid %s", name)
		}
	}
	for name, p := range map[string]string{"journal-socket-root": o.journalSocketRoot, "journal-key-root": o.journalKeyRoot, "journal-release-root": o.journalReleaseRoot} {
		if p == "" || !filepath.IsAbs(p) || filepath.Clean(p) != p {
			return fmt.Errorf("invalid %s", name)
		}
	}
	if o.socket == "" || filepath.Base(o.socket) != o.socket || filepath.Clean(o.socket) != o.socket || o.keyFile == "" || filepath.Base(o.keyFile) != o.keyFile || filepath.Clean(o.keyFile) != o.keyFile || o.channel != "platform-checkpoint" || o.localRole != "checkpoint" || o.peerRole != "anchor" || o.journalSocket == "" || filepath.Base(o.journalSocket) != o.journalSocket || filepath.Clean(o.journalSocket) != o.journalSocket || o.journalKeyFile == "" || filepath.Base(o.journalKeyFile) != o.journalKeyFile || filepath.Clean(o.journalKeyFile) != o.journalKeyFile || o.journalRole != journalLocalRole || o.journalPeerRole != journalPeerRole {
		return errors.New("invalid checkpoint channel")
	}
	for _, name := range []string{"journal-socket-root", "journal-socket", "journal-key-root", "journal-key-file", "journal-release-root", "journal-local-role", "journal-peer-role"} {
		if !o.specified[name] {
			return fmt.Errorf("missing %s", name)
		}
	}
	roots := []string{o.state, o.socketRoot, o.keyRoot, o.releaseRoot, o.journalSocketRoot, o.journalKeyRoot, o.journalReleaseRoot}
	for i := range roots {
		for j := i + 1; j < len(roots); j++ {
			if pathOverlaps(roots[i], roots[j]) {
				return errors.New("journal roots must be separate")
			}
		}
	}
	if o.socket == o.journalSocket {
		return errors.New("journal socket leaf must be separate")
	}
	for name, p := range map[string]string{"local-uid": "", "local-gid": "", "peer-uid": "", "peer-gid": "", "channel-gid": "", "key-epoch": ""} {
		if !o.numeric[name] {
			return fmt.Errorf("missing %s", name)
		}
		_ = p
	}
	for _, name := range []string{"journal-peer-uid", "journal-peer-gid", "journal-channel-gid"} {
		if !o.numeric[name] {
			return fmt.Errorf("missing %s", name)
		}
	}
	if o.localUID == 0 || o.peerUID == 0 || o.localUID == o.peerUID || o.channelGID == o.localGID || o.channelGID == o.peerGID || o.keyEpoch == 0 {
		return errors.New("invalid checkpoint identities")
	}
	if o.journalPeerUID == o.localUID || o.journalChannelGID == o.localGID || o.journalChannelGID == o.journalPeerGID {
		return errors.New("invalid journal identities")
	}
	pins := []macoschannel.ReleasePin{o.localRelease, o.peerRelease, o.journalLocalRelease, o.journalPeerRelease}
	for _, p := range pins {
		if p.ReleaseID == "" {
			return errors.New("missing release pin")
		}
		for _, d := range []string{p.BinaryDigest, p.SocketDigest, p.ManifestDigest} {
			b, err := hex.DecodeString(d)
			if err != nil || len(b) != 32 {
				return errors.New("invalid release digest")
			}
		}
	}
	return nil
}

func pathOverlaps(a, b string) bool {
	return a == b || strings.HasPrefix(a, b+string(filepath.Separator)) || strings.HasPrefix(b, a+string(filepath.Separator))
}

// BuildProductionArgs is the canonical launchd argument builder. It keeps the
// daemon's required identity/release/channel contract reviewable without
// starting a service or reading credentials.
func BuildProductionArgs(o options) []string {
	a := []string{"-state", o.state, "-socket-root", o.socketRoot, "-socket", o.socket, "-key-root", o.keyRoot, "-key-file", o.keyFile, "-release-root", o.releaseRoot, "-channel", o.channel, "-local-role", o.localRole, "-peer-role", o.peerRole, "-local-release", o.localRelease.ReleaseID, "-local-binary-digest", o.localRelease.BinaryDigest, "-local-socket-digest", o.localRelease.SocketDigest, "-local-manifest-digest", o.localRelease.ManifestDigest, "-peer-release", o.peerRelease.ReleaseID, "-peer-binary-digest", o.peerRelease.BinaryDigest, "-peer-socket-digest", o.peerRelease.SocketDigest, "-peer-manifest-digest", o.peerRelease.ManifestDigest, "-local-uid", strconv.FormatUint(uint64(o.localUID), 10), "-local-gid", strconv.FormatUint(uint64(o.localGID), 10), "-peer-uid", strconv.FormatUint(uint64(o.peerUID), 10), "-peer-gid", strconv.FormatUint(uint64(o.peerGID), 10), "-channel-gid", strconv.FormatUint(uint64(o.channelGID), 10), "-key-epoch", strconv.FormatUint(o.keyEpoch, 10)}
	return append(a, "-journal-socket-root", o.journalSocketRoot, "-journal-socket", o.journalSocket, "-journal-key-root", o.journalKeyRoot, "-journal-key-file", o.journalKeyFile, "-journal-release-root", o.journalReleaseRoot, "-journal-local-role", o.journalRole, "-journal-peer-role", o.journalPeerRole, "-journal-local-release", o.journalLocalRelease.ReleaseID, "-journal-local-binary-digest", o.journalLocalRelease.BinaryDigest, "-journal-local-socket-digest", o.journalLocalRelease.SocketDigest, "-journal-local-manifest-digest", o.journalLocalRelease.ManifestDigest, "-journal-peer-release", o.journalPeerRelease.ReleaseID, "-journal-peer-binary-digest", o.journalPeerRelease.BinaryDigest, "-journal-peer-socket-digest", o.journalPeerRelease.SocketDigest, "-journal-peer-manifest-digest", o.journalPeerRelease.ManifestDigest, "-journal-peer-uid", strconv.FormatUint(uint64(o.journalPeerUID), 10), "-journal-peer-gid", strconv.FormatUint(uint64(o.journalPeerGID), 10), "-journal-channel-gid", strconv.FormatUint(uint64(o.journalChannelGID), 10))
}

func runProduction(o options) error {
	roots, err := verifiedroot.OpenAll([]verifiedroot.Requirement{
		{Name: "state", Path: o.state, UID: o.localUID, GID: o.localGID, Mode: 0700},
		{Name: "socket", Path: o.socketRoot, UID: o.localUID, GID: o.channelGID, Mode: 0750},
		{Name: "key", Path: o.keyRoot, UID: o.localUID, GID: o.localGID, Mode: 0700},
		{Name: "release", Path: o.releaseRoot, UID: 0, GID: o.localGID, Mode: 0550},
		{Name: "journal-socket", Path: o.journalSocketRoot, UID: o.localUID, GID: o.journalChannelGID, Mode: 0750},
		{Name: "journal-key", Path: o.journalKeyRoot, UID: o.localUID, GID: o.localGID, Mode: 0700},
		{Name: "journal-release", Path: o.journalReleaseRoot, UID: 0, GID: o.localGID, Mode: 0550},
	})
	if err != nil {
		return errors.New("checkpoint roots unavailable")
	}
	defer verifiedroot.CloseAll(roots)
	key, err := servicekey.New(roots[2].Handle(), servicekey.Policy{FileName: o.keyFile, Channel: o.channel, OwnerUID: o.localUID, OwnerGID: o.localGID, Mode: 0600, RootUID: o.localUID, RootGID: o.localGID, RootMode: 0700})
	if err != nil {
		return errors.New("checkpoint key unavailable")
	}
	peerUID, peerGID := o.peerUID, o.peerGID
	cfg := macoschannel.Config{Contract: macoschannel.SocketContract{Channel: o.channel, LocalRole: o.localRole, PeerRole: o.peerRole, SocketPath: o.socket, SocketRoot: o.socketRoot, ExpectedPeerUID: &peerUID, ExpectedPeerGID: &peerGID, ExpectedSocketRootUID: o.localUID, ExpectedSocketRootGID: o.channelGID, ExpectedSocketRootMode: 0750, ExpectedSocketUID: o.localUID, ExpectedSocketGID: o.channelGID, ExpectedSocketMode: 0660}, LocalRelease: o.localRelease, PeerRelease: o.peerRelease, ReleaseRoot: roots[3].Handle(), SocketRootFD: roots[1].Handle(), BinaryName: "openduck-checkpoint", KeySource: key, ExpectedReleaseRootUID: 0, ExpectedReleaseRootGID: o.localGID, ExpectedReleaseRootMode: 0550, ExpectedManifestMode: 0440, ExpectedBinaryMode: 0550}
	if err := macoschannel.ValidateConfig(cfg); err != nil {
		return errors.New("checkpoint release unavailable")
	}
	journalKey, err := servicekey.New(roots[5].Handle(), servicekey.Policy{FileName: o.journalKeyFile, Channel: journalChannel, OwnerUID: o.localUID, OwnerGID: o.localGID, Mode: 0600, RootUID: o.localUID, RootGID: o.localGID, RootMode: 0700})
	if err != nil {
		return errors.New("journal key unavailable")
	}
	journalPeerUID, journalPeerGID := o.journalPeerUID, o.journalPeerGID
	journalCfg := macoschannel.Config{Contract: macoschannel.SocketContract{Channel: journalChannel, LocalRole: o.journalRole, PeerRole: o.journalPeerRole, SocketPath: o.journalSocket, SocketRoot: o.journalSocketRoot, ExpectedPeerUID: &journalPeerUID, ExpectedPeerGID: &journalPeerGID, ExpectedSocketRootUID: o.localUID, ExpectedSocketRootGID: o.journalChannelGID, ExpectedSocketRootMode: 0750, ExpectedSocketUID: o.localUID, ExpectedSocketGID: o.journalChannelGID, ExpectedSocketMode: 0660}, LocalRelease: o.journalLocalRelease, PeerRelease: o.journalPeerRelease, ReleaseRoot: roots[6].Handle(), SocketRootFD: roots[4].Handle(), BinaryName: "openduck-checkpoint", KeySource: journalKey, ExpectedReleaseRootUID: 0, ExpectedReleaseRootGID: o.localGID, ExpectedReleaseRootMode: 0550, ExpectedManifestMode: 0440, ExpectedBinaryMode: 0550}
	if err := macoschannel.ValidateConfig(journalCfg); err != nil {
		return errors.New("journal release unavailable")
	}
	store, err := platformcheckpoint.NewStore(o.state)
	if err != nil {
		return errors.New("checkpoint state unavailable")
	}
	defer store.Close()
	server, err := platformcheckpoint.NewServer(store, platformcheckpoint.Policy{Channel: o.channel, LocalRole: o.localRole, PeerRole: o.peerRole, LocalUID: o.localUID, LocalGID: o.localGID, PeerUID: o.peerUID, PeerGID: o.peerGID, KeyEpoch: o.keyEpoch, LocalRelease: o.localRelease, PeerRelease: o.peerRelease})
	if err != nil {
		return errors.New("checkpoint server unavailable")
	}
	ln, err := macoschannel.Listen(cfg)
	if err != nil {
		return errors.New("checkpoint listener unavailable")
	}
	journalLn, err := macoschannel.Listen(journalCfg)
	if err != nil {
		_ = ln.Close()
		return errors.New("journal listener unavailable")
	}
	defer ln.Close()
	defer journalLn.Close()
	// The two isolated keys are rotated under one daemon-wide epoch; both
	// channels reject a key whose explicit epoch differs from this value.
	journalServer, err := platformcheckpoint.NewJournalServer(store, platformcheckpoint.JournalPolicy{Policy: platformcheckpoint.Policy{Channel: journalChannel, LocalRole: o.journalRole, PeerRole: o.journalPeerRole, LocalUID: o.localUID, LocalGID: o.localGID, PeerUID: o.journalPeerUID, PeerGID: o.journalPeerGID, KeyEpoch: o.keyEpoch, LocalRelease: o.journalLocalRelease, PeerRelease: o.journalPeerRelease}, Audience: journalChannel})
	if err != nil {
		return errors.New("journal server unavailable")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return serveBoth(ctx, server, ln, journalServer, journalLn)
}

type authenticatedListener interface {
	AcceptAuthenticated(context.Context) (macoschannel.Conn, error)
	Close() error
}

type connectionServer interface {
	ServeConn(context.Context, macoschannel.Conn) error
}

func serve(ctx context.Context, server connectionServer, ln authenticatedListener) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var wg sync.WaitGroup
	defer wg.Wait()
	for {
		conn, err := ln.AcceptAuthenticated(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return errors.New("checkpoint accept failed")
		}
		wg.Add(1)
		go func() { defer wg.Done(); _ = server.ServeConn(ctx, conn) }()
	}
}

// serveBoth binds the two authenticated protocols to one store while ensuring
// an unavailable listener cannot leave its sibling accepting requests alone.
func serveBoth(ctx context.Context, checkpoint connectionServer, checkpointLn authenticatedListener, journal connectionServer, journalLn authenticatedListener) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	type outcome struct{ err error }
	results := make(chan outcome, 2)
	go func() { results <- outcome{serve(ctx, checkpoint, checkpointLn)} }()
	go func() { results <- outcome{serve(ctx, journal, journalLn)} }()
	first := <-results
	cancel()
	_ = checkpointLn.Close()
	_ = journalLn.Close()
	second := <-results
	if first.err != nil {
		return first.err
	}
	return second.err
}
