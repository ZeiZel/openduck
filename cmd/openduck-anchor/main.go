// Command openduck-anchor composes the platform anchor. Production mode is
// deliberately explicit and fail-closed; the synthetic fixture is available
// only through an explicit -synthetic flag.
package main

import (
	"context"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"openduck/internal/macoschannel"
	"openduck/internal/platformanchor"
	"openduck/internal/platformcheckpoint"
	"openduck/internal/servicekey"
)

type options struct {
	synthetic                                                                                                                          bool
	state, socket, socketRoot, checkpoint                                                                                              string
	keyRoot, keyFile, checkpointKeyRoot, checkpointKeyFile, releaseRoot, checkpointReleaseRoot, checkpointSocketRoot, checkpointSocket string
	journalSocketRoot, journalSocket, journalKeyRoot, journalKeyFile, journalReleaseRoot                                               string
	channel, localRole, peerRole, checkpointLocalRole, checkpointPeerRole                                                              string
	journalRole, journalPeerRole                                                                                                       string
	localRelease, peerRelease, checkpointLocalRelease, checkpointPeerRelease                                                           macoschannel.ReleasePin
	journalLocalRelease, journalPeerRelease                                                                                            macoschannel.ReleasePin
	localUID, localGID, peerUID, peerGID                                                                                               uint32
	channelGID                                                                                                                         uint32
	checkpointChannelGID                                                                                                               uint32
	checkpointLocalUID, checkpointLocalGID, checkpointPeerUID, checkpointPeerGID                                                       uint32
	journalPeerUID, journalPeerGID, journalChannelGID                                                                                  uint32
	keyEpoch                                                                                                                           uint64
	numericSet                                                                                                                         map[string]bool
	specified                                                                                                                          map[string]bool
}

const (
	journalChannel   = platformanchor.JournalAudience
	journalLocalRole = "anchor"
	journalPeerRole  = "installer"
)

type fileIdentity struct{ dev, ino uint64 }

type verifiedRoot struct {
	name     string
	path     string
	root     *os.Root
	identity fileIdentity
	ancestry map[fileIdentity]struct{}
}

type rootRequirement struct {
	name     string
	path     string
	uid, gid uint32
	mode     os.FileMode
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "openduck-anchor:", err)
		os.Exit(1)
	}
}
func run(args []string) error {
	o, err := parse(args)
	if err != nil {
		return err
	}
	if o.synthetic {
		return runSynthetic(o)
	}
	return runProduction(o)
}

func parse(args []string) (options, error) {
	var o options
	fs := flag.NewFlagSet("openduck-anchor", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.BoolVar(&o.synthetic, "synthetic", false, "run the explicit synthetic fixture")
	fs.StringVar(&o.state, "state", "", "anchor state directory")
	fs.StringVar(&o.socket, "socket", "", "anchor Unix socket path")
	fs.StringVar(&o.socketRoot, "socket-root", "", "pre-provisioned anchor socket directory")
	fs.StringVar(&o.checkpoint, "checkpoint", "", "synthetic checkpoint directory")
	fs.StringVar(&o.keyRoot, "key-root", "", "pre-provisioned service-key root")
	fs.StringVar(&o.keyFile, "key-file", "service.key", "service-key leaf name")
	fs.StringVar(&o.checkpointKeyRoot, "checkpoint-key-root", "", "pre-provisioned checkpoint service-key root")
	fs.StringVar(&o.checkpointKeyFile, "checkpoint-key-file", "checkpoint.key", "checkpoint service-key leaf name")
	fs.StringVar(&o.releaseRoot, "release-root", "", "pre-provisioned anchor release root")
	fs.StringVar(&o.checkpointReleaseRoot, "checkpoint-release-root", "", "pre-provisioned checkpoint client release root")
	fs.StringVar(&o.checkpointSocketRoot, "checkpoint-socket-root", "", "checkpoint socket root")
	fs.StringVar(&o.checkpointSocket, "checkpoint-socket", "", "checkpoint socket leaf")
	fs.StringVar(&o.journalSocketRoot, "journal-socket-root", "", "installer journal socket root")
	fs.StringVar(&o.journalSocket, "journal-socket", "journal.sock", "installer journal socket leaf")
	fs.StringVar(&o.journalKeyRoot, "journal-key-root", "", "installer journal key root")
	fs.StringVar(&o.journalKeyFile, "journal-key-file", "journal.key", "installer journal key leaf")
	fs.StringVar(&o.journalReleaseRoot, "journal-release-root", "", "installer journal release root")
	fs.StringVar(&o.channel, "channel", "platform-anchor", "anchor channel")
	fs.StringVar(&o.localRole, "local-role", "anchor", "anchor local role")
	fs.StringVar(&o.peerRole, "peer-role", "controller", "anchor peer role")
	fs.StringVar(&o.checkpointLocalRole, "checkpoint-local-role", "anchor", "checkpoint local role")
	fs.StringVar(&o.checkpointPeerRole, "checkpoint-peer-role", "checkpoint", "checkpoint peer role")
	fs.StringVar(&o.journalRole, "journal-local-role", journalLocalRole, "journal local role")
	fs.StringVar(&o.journalPeerRole, "journal-peer-role", journalPeerRole, "journal peer role")
	bindPin(fs, &o.localRelease, "local")
	bindPin(fs, &o.peerRelease, "peer")
	bindPin(fs, &o.checkpointLocalRelease, "checkpoint-local")
	bindPin(fs, &o.checkpointPeerRelease, "checkpoint-peer")
	bindPin(fs, &o.journalLocalRelease, "journal-local")
	bindPin(fs, &o.journalPeerRelease, "journal-peer")
	o.numericSet = make(map[string]bool)
	o.specified = make(map[string]bool)
	bindUint(fs, &o.localUID, "local-uid", o.numericSet)
	bindUint(fs, &o.localGID, "local-gid", o.numericSet)
	bindUint(fs, &o.peerUID, "peer-uid", o.numericSet)
	bindUint(fs, &o.peerGID, "peer-gid", o.numericSet)
	bindUint(fs, &o.channelGID, "channel-gid", o.numericSet)
	bindUint(fs, &o.checkpointChannelGID, "checkpoint-channel-gid", o.numericSet)
	bindUint(fs, &o.checkpointLocalUID, "checkpoint-local-uid", o.numericSet)
	bindUint(fs, &o.checkpointLocalGID, "checkpoint-local-gid", o.numericSet)
	bindUint(fs, &o.checkpointPeerUID, "checkpoint-peer-uid", o.numericSet)
	bindUint(fs, &o.checkpointPeerGID, "checkpoint-peer-gid", o.numericSet)
	bindUint(fs, &o.journalPeerUID, "journal-peer-uid", o.numericSet)
	bindUint(fs, &o.journalPeerGID, "journal-peer-gid", o.numericSet)
	bindUint(fs, &o.journalChannelGID, "journal-channel-gid", o.numericSet)
	bindUint64(fs, &o.keyEpoch, "key-epoch", o.numericSet)
	if err := fs.Parse(args); err != nil {
		return options{}, err
	}
	if fs.NArg() != 0 {
		return options{}, errors.New("unexpected positional arguments")
	}
	fs.Visit(func(f *flag.Flag) { o.specified[f.Name] = true })
	if o.synthetic {
		mixed := false
		fs.Visit(func(f *flag.Flag) {
			if f.Name != "synthetic" && f.Name != "state" && f.Name != "socket" && f.Name != "checkpoint" {
				mixed = true
			}
		})
		if mixed || o.keyRoot != "" || o.checkpointKeyRoot != "" || o.releaseRoot != "" || o.checkpointReleaseRoot != "" || o.checkpointSocketRoot != "" || o.checkpointSocket != "" || o.socketRoot != "" || o.keyEpoch != 0 {
			return options{}, errors.New("synthetic and production inputs cannot be mixed")
		}
		return o, validateSynthetic(o)
	}
	if o.checkpoint != "" {
		return options{}, errors.New("-checkpoint is synthetic-only")
	}
	if err := validateProductionOptions(o); err != nil {
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
	fs.Func(name, name, func(s string) error {
		n, err := strconv.ParseUint(s, 10, 32)
		if err != nil {
			return err
		}
		*p = uint32(n)
		set[name] = true
		return nil
	})
}
func bindUint64(fs *flag.FlagSet, p *uint64, name string, set map[string]bool) {
	fs.Func(name, name, func(s string) error {
		n, err := strconv.ParseUint(s, 10, 64)
		if err != nil || n == 0 {
			return errors.New("invalid positive integer")
		}
		*p = n
		set[name] = true
		return nil
	})
}

func validateSynthetic(o options) error {
	if o.state == "" || o.socket == "" || o.checkpoint == "" || !absClean(o.state) || !absClean(o.socket) || !absClean(o.checkpoint) {
		return errors.New("synthetic mode requires absolute state, socket and checkpoint paths")
	}
	if rootsOverlap(filepath.Clean(o.state), filepath.Clean(o.checkpoint)) || filepath.Dir(filepath.Clean(o.socket)) != filepath.Clean(o.state) {
		return errors.New("invalid synthetic state/socket roots")
	}
	return nil
}
func validateProductionOptions(o options) error {
	for name, p := range map[string]string{"state": o.state, "socket": o.socket, "socket-root": o.socketRoot, "key-root": o.keyRoot, "checkpoint-key-root": o.checkpointKeyRoot, "release-root": o.releaseRoot, "checkpoint-release-root": o.checkpointReleaseRoot, "checkpoint-socket-root": o.checkpointSocketRoot, "journal-socket-root": o.journalSocketRoot, "journal-key-root": o.journalKeyRoot, "journal-release-root": o.journalReleaseRoot} {
		if !absClean(p) {
			return fmt.Errorf("production %s must be an absolute clean path", name)
		}
	}
	if o.checkpointSocket == "" || filepath.Base(o.checkpointSocket) != o.checkpointSocket || filepath.Clean(o.checkpointSocket) != o.checkpointSocket {
		return errors.New("invalid checkpoint socket leaf")
	}
	if o.journalSocket == "" || filepath.Base(o.journalSocket) != o.journalSocket || filepath.Clean(o.journalSocket) != o.journalSocket || o.journalKeyFile == "" || filepath.Base(o.journalKeyFile) != o.journalKeyFile || filepath.Clean(o.journalKeyFile) != o.journalKeyFile {
		return errors.New("invalid journal leaf")
	}
	if filepath.Dir(o.socket) != o.socketRoot || rootsOverlap(o.state, o.socketRoot) {
		return errors.New("anchor socket must be directly inside a separate socket root")
	}
	roots := []string{o.state, o.socketRoot, o.keyRoot, o.checkpointKeyRoot, o.releaseRoot, o.checkpointReleaseRoot, o.checkpointSocketRoot, o.journalSocketRoot, o.journalKeyRoot, o.journalReleaseRoot}
	for i := range roots {
		for j := i + 1; j < len(roots); j++ {
			if rootsOverlap(roots[i], roots[j]) {
				return errors.New("production roots overlap")
			}
		}
	}
	if o.channel != "platform-anchor" || o.localRole != "anchor" || o.peerRole != "controller" || o.checkpointLocalRole != "anchor" || o.checkpointPeerRole != "checkpoint" || o.journalRole != journalLocalRole || o.journalPeerRole != journalPeerRole || o.keyEpoch == 0 {
		return errors.New("invalid production roles or epoch")
	}
	for _, name := range []string{"journal-socket-root", "journal-socket", "journal-key-root", "journal-key-file", "journal-release-root", "journal-local-role", "journal-peer-role"} {
		if !o.specified[name] {
			return fmt.Errorf("missing journal input: %s", name)
		}
	}
	for name, p := range map[string]macoschannel.ReleasePin{"local": o.localRelease, "peer": o.peerRelease, "checkpoint-local": o.checkpointLocalRelease, "checkpoint-peer": o.checkpointPeerRelease, "journal-local": o.journalLocalRelease, "journal-peer": o.journalPeerRelease} {
		if err := validPin(p); err != nil {
			return fmt.Errorf("%s release: %w", name, err)
		}
	}
	for _, n := range []string{"local-uid", "local-gid", "peer-uid", "peer-gid", "channel-gid", "checkpoint-channel-gid", "checkpoint-local-uid", "checkpoint-local-gid", "checkpoint-peer-uid", "checkpoint-peer-gid", "journal-peer-uid", "journal-peer-gid", "journal-channel-gid", "key-epoch"} {
		if !o.numericSet[n] {
			return fmt.Errorf("missing numeric input: %s", n)
		}
	}
	if o.channelGID == o.localGID || o.channelGID == o.peerGID {
		return errors.New("anchor channel group must be distinct from service primary groups")
	}
	if o.checkpointChannelGID == 0 || o.checkpointChannelGID == o.checkpointLocalGID || o.checkpointChannelGID == o.checkpointPeerGID {
		return errors.New("checkpoint channel group must be distinct from service primary groups")
	}
	if o.journalChannelGID == 0 || o.journalChannelGID == o.localGID || o.journalChannelGID == o.journalPeerGID || o.journalPeerUID == o.localUID {
		return errors.New("invalid journal principals")
	}
	if o.localUID == 0 || o.checkpointLocalUID == 0 || o.localUID != o.checkpointLocalUID || o.localGID != o.checkpointLocalGID || o.peerUID == 0 || o.checkpointPeerUID == 0 || o.localUID == o.peerUID || o.localUID == o.checkpointPeerUID || o.checkpointLocalUID == o.checkpointPeerUID {
		return errors.New("production principals must have distinct UIDs")
	}
	return nil
}
func validPin(p macoschannel.ReleasePin) error {
	if p.ReleaseID == "" {
		return errors.New("missing release id")
	}
	for _, d := range []string{p.BinaryDigest, p.SocketDigest, p.ManifestDigest} {
		b, e := hex.DecodeString(d)
		if e != nil || len(b) != 32 {
			return errors.New("invalid sha256 digest")
		}
	}
	return nil
}
func absClean(s string) bool { return s != "" && filepath.IsAbs(s) && filepath.Clean(s) == s }

func BuildProductionArgs(o options) []string {
	a := []string{"-state", o.state, "-socket", o.socket, "-socket-root", o.socketRoot, "-key-root", o.keyRoot, "-key-file", o.keyFile, "-checkpoint-key-root", o.checkpointKeyRoot, "-checkpoint-key-file", o.checkpointKeyFile, "-release-root", o.releaseRoot, "-checkpoint-release-root", o.checkpointReleaseRoot, "-checkpoint-socket-root", o.checkpointSocketRoot, "-checkpoint-socket", o.checkpointSocket, "-channel", o.channel, "-local-role", o.localRole, "-peer-role", o.peerRole, "-checkpoint-local-role", o.checkpointLocalRole, "-checkpoint-peer-role", o.checkpointPeerRole}
	for _, p := range []struct {
		prefix string
		pin    macoschannel.ReleasePin
	}{{"local", o.localRelease}, {"peer", o.peerRelease}, {"checkpoint-local", o.checkpointLocalRelease}, {"checkpoint-peer", o.checkpointPeerRelease}} {
		a = append(a, "-"+p.prefix+"-release", p.pin.ReleaseID, "-"+p.prefix+"-binary-digest", p.pin.BinaryDigest, "-"+p.prefix+"-socket-digest", p.pin.SocketDigest, "-"+p.prefix+"-manifest-digest", p.pin.ManifestDigest)
	}
	a = append(a, "-local-uid", strconv.FormatUint(uint64(o.localUID), 10), "-local-gid", strconv.FormatUint(uint64(o.localGID), 10), "-peer-uid", strconv.FormatUint(uint64(o.peerUID), 10), "-peer-gid", strconv.FormatUint(uint64(o.peerGID), 10), "-channel-gid", strconv.FormatUint(uint64(o.channelGID), 10), "-checkpoint-channel-gid", strconv.FormatUint(uint64(o.checkpointChannelGID), 10), "-checkpoint-local-uid", strconv.FormatUint(uint64(o.checkpointLocalUID), 10), "-checkpoint-local-gid", strconv.FormatUint(uint64(o.checkpointLocalGID), 10), "-checkpoint-peer-uid", strconv.FormatUint(uint64(o.checkpointPeerUID), 10), "-checkpoint-peer-gid", strconv.FormatUint(uint64(o.checkpointPeerGID), 10), "-key-epoch", strconv.FormatUint(o.keyEpoch, 10))
	for _, p := range []struct {
		prefix string
		pin    macoschannel.ReleasePin
	}{{"journal-local", o.journalLocalRelease}, {"journal-peer", o.journalPeerRelease}} {
		a = append(a, "-"+p.prefix+"-release", p.pin.ReleaseID, "-"+p.prefix+"-binary-digest", p.pin.BinaryDigest, "-"+p.prefix+"-socket-digest", p.pin.SocketDigest, "-"+p.prefix+"-manifest-digest", p.pin.ManifestDigest)
	}
	return append(a, "-journal-socket-root", o.journalSocketRoot, "-journal-socket", o.journalSocket, "-journal-key-root", o.journalKeyRoot, "-journal-key-file", o.journalKeyFile, "-journal-release-root", o.journalReleaseRoot, "-journal-local-role", o.journalRole, "-journal-peer-role", o.journalPeerRole, "-journal-peer-uid", strconv.FormatUint(uint64(o.journalPeerUID), 10), "-journal-peer-gid", strconv.FormatUint(uint64(o.journalPeerGID), 10), "-journal-channel-gid", strconv.FormatUint(uint64(o.journalChannelGID), 10))
}

func runSynthetic(o options) error {
	stateClean, socketClean, checkpointClean := filepath.Clean(o.state), filepath.Clean(o.socket), filepath.Clean(o.checkpoint)
	if rs, e := platformanchor.CanonicalizeAllowMissing(stateClean); e == nil {
		if rc, x := platformanchor.CanonicalizeAllowMissing(checkpointClean); x == nil && rootsOverlap(rs, rc) {
			return errors.New("physical state/checkpoint roots overlap")
		}
	}
	if err := os.MkdirAll(stateClean, 0700); err != nil {
		return err
	}
	stateRoot, err := os.OpenRoot(stateClean)
	if err != nil {
		return err
	}
	defer stateRoot.Close()
	if err := refuseActiveSocket(stateRoot, socketClean); err != nil {
		return err
	}
	cp, err := platformanchor.NewSyntheticFileCheckpoint(checkpointClean)
	if err != nil {
		return err
	}
	store, err := platformanchor.NewSyntheticStoreWithCheckpoint(stateClean, cp)
	if err != nil {
		return err
	}
	defer store.Close()
	server, err := platformanchor.NewSyntheticServer(store, platformanchor.SyntheticPeer{UID: 1, Executable: "synthetic-anchor", Socket: socketClean})
	if err != nil {
		return err
	}
	ln, err := net.Listen("unix", socketClean)
	if err != nil {
		return err
	}
	defer ln.Close()
	if err := os.Chmod(socketClean, 0600); err != nil {
		return err
	}
	return serveSynthetic(server, ln)
}

func runProduction(o options) error {
	requirements := []rootRequirement{
		{name: "state", path: o.state, uid: o.localUID, gid: o.localGID, mode: 0700},
		{name: "socket-root", path: o.socketRoot, uid: o.localUID, gid: o.channelGID, mode: 0750},
		{name: "key-root", path: o.keyRoot, uid: o.localUID, gid: o.localGID, mode: 0700},
		{name: "checkpoint-key-root", path: o.checkpointKeyRoot, uid: o.checkpointLocalUID, gid: o.checkpointLocalGID, mode: 0700},
		{name: "release-root", path: o.releaseRoot, uid: 0, gid: o.localGID, mode: 0550},
		{name: "checkpoint-release-root", path: o.checkpointReleaseRoot, uid: 0, gid: o.checkpointLocalGID, mode: 0550},
		{name: "checkpoint-socket-root", path: o.checkpointSocketRoot, uid: o.checkpointPeerUID, gid: o.checkpointChannelGID, mode: 0750},
		{name: "journal-socket-root", path: o.journalSocketRoot, uid: o.localUID, gid: o.journalChannelGID, mode: 0750},
		{name: "journal-key-root", path: o.journalKeyRoot, uid: o.localUID, gid: o.localGID, mode: 0700},
		{name: "journal-release-root", path: o.journalReleaseRoot, uid: 0, gid: o.localGID, mode: 0550},
	}
	roots, e := openVerifiedRoots(requirements)
	if e != nil {
		return e
	}
	defer closeVerifiedRoots(roots)
	socketRoot := roots[1].root
	keyRoot := roots[2].root
	checkpointKeyRoot := roots[3].root
	releaseRoot := roots[4].root
	checkpointReleaseRoot := roots[5].root
	checkpointRoot := roots[6].root
	journalSocketRoot := roots[7].root
	journalKeyRoot := roots[8].root
	journalReleaseRoot := roots[9].root
	key, e := servicekey.New(keyRoot, servicekey.Policy{FileName: o.keyFile, Channel: o.channel, OwnerUID: o.localUID, OwnerGID: o.localGID, Mode: 0600, RootUID: o.localUID, RootGID: o.localGID, RootMode: 0700})
	if e != nil {
		return e
	}
	anchorCfg := macoschannel.Config{Contract: macoschannel.SocketContract{Channel: o.channel, LocalRole: o.localRole, PeerRole: o.peerRole, SocketPath: filepath.Base(o.socket), SocketRoot: o.socketRoot, ExpectedPeerUID: &o.peerUID, ExpectedPeerGID: &o.peerGID, ExpectedSocketRootUID: o.localUID, ExpectedSocketRootGID: o.channelGID, ExpectedSocketRootMode: 0750, ExpectedSocketUID: o.localUID, ExpectedSocketGID: o.channelGID, ExpectedSocketMode: 0660}, LocalRelease: o.localRelease, PeerRelease: o.peerRelease, ReleaseRoot: releaseRoot, SocketRootFD: socketRoot, BinaryName: "openduck-anchor", KeySource: key, ExpectedReleaseRootUID: 0, ExpectedReleaseRootGID: o.localGID, ExpectedReleaseRootMode: 0550, ExpectedManifestMode: 0440, ExpectedBinaryMode: 0550}
	checkpointKey, e := servicekey.New(checkpointKeyRoot, servicekey.Policy{FileName: o.checkpointKeyFile, Channel: "platform-checkpoint", OwnerUID: o.checkpointLocalUID, OwnerGID: o.checkpointLocalGID, Mode: 0600, RootUID: o.checkpointLocalUID, RootGID: o.checkpointLocalGID, RootMode: 0700})
	if e != nil {
		return e
	}
	checkpointCfg := anchorCfg
	checkpointCfg.Contract = macoschannel.SocketContract{Channel: "platform-checkpoint", LocalRole: o.checkpointLocalRole, PeerRole: o.checkpointPeerRole, SocketPath: o.checkpointSocket, SocketRoot: o.checkpointSocketRoot, ExpectedPeerUID: &o.checkpointPeerUID, ExpectedPeerGID: &o.checkpointPeerGID, ExpectedSocketRootUID: o.checkpointPeerUID, ExpectedSocketRootGID: o.checkpointChannelGID, ExpectedSocketRootMode: 0750, ExpectedSocketUID: o.checkpointPeerUID, ExpectedSocketGID: o.checkpointChannelGID, ExpectedSocketMode: 0660}
	checkpointCfg.LocalRelease = o.checkpointLocalRelease
	checkpointCfg.PeerRelease = o.checkpointPeerRelease
	checkpointCfg.ReleaseRoot = checkpointReleaseRoot
	checkpointCfg.SocketRootFD = checkpointRoot
	checkpointCfg.KeySource = checkpointKey
	checkpointCfg.BinaryName = "openduck-anchor"
	checkpointCfg.ExpectedReleaseRootUID = 0
	checkpointCfg.ExpectedReleaseRootGID = o.checkpointLocalGID
	journalKey, e := servicekey.New(journalKeyRoot, servicekey.Policy{FileName: o.journalKeyFile, Channel: journalChannel, OwnerUID: o.localUID, OwnerGID: o.localGID, Mode: 0600, RootUID: o.localUID, RootGID: o.localGID, RootMode: 0700})
	if e != nil {
		return e
	}
	journalCfg := macoschannel.Config{Contract: macoschannel.SocketContract{Channel: journalChannel, LocalRole: o.journalRole, PeerRole: o.journalPeerRole, SocketPath: o.journalSocket, SocketRoot: o.journalSocketRoot, ExpectedPeerUID: &o.journalPeerUID, ExpectedPeerGID: &o.journalPeerGID, ExpectedSocketRootUID: o.localUID, ExpectedSocketRootGID: o.journalChannelGID, ExpectedSocketRootMode: 0750, ExpectedSocketUID: o.localUID, ExpectedSocketGID: o.journalChannelGID, ExpectedSocketMode: 0660}, LocalRelease: o.journalLocalRelease, PeerRelease: o.journalPeerRelease, ReleaseRoot: journalReleaseRoot, SocketRootFD: journalSocketRoot, BinaryName: "openduck-anchor", KeySource: journalKey, ExpectedReleaseRootUID: 0, ExpectedReleaseRootGID: o.localGID, ExpectedReleaseRootMode: 0550, ExpectedManifestMode: 0440, ExpectedBinaryMode: 0550}
	if e := macoschannel.ValidateConfig(anchorCfg); e != nil {
		return e
	}
	if e := macoschannel.ValidateConfig(checkpointCfg); e != nil {
		return e
	}
	if e := macoschannel.ValidateConfig(journalCfg); e != nil {
		return e
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if e := preflightKey(ctx, key, o.channel, o.keyEpoch); e != nil {
		return e
	}
	if e := preflightKey(ctx, checkpointKey, "platform-checkpoint", o.keyEpoch); e != nil {
		return e
	}
	if e := preflightKey(ctx, journalKey, journalChannel, o.keyEpoch); e != nil {
		return e
	}
	dial, e := macoschannel.NewDialer(checkpointCfg)
	if e != nil {
		return e
	}
	client, e := platformcheckpoint.NewProductionClient(dial, platformcheckpoint.Policy{Channel: "platform-checkpoint", LocalRole: o.checkpointLocalRole, PeerRole: o.checkpointPeerRole, LocalUID: o.checkpointLocalUID, LocalGID: o.checkpointLocalGID, PeerUID: o.checkpointPeerUID, PeerGID: o.checkpointPeerGID, KeyEpoch: o.keyEpoch, LocalRelease: o.checkpointLocalRelease, PeerRelease: o.checkpointPeerRelease})
	if e != nil {
		return e
	}
	cp, e := platformanchor.NewProductionAnchorCheckpoint(client)
	if e != nil {
		return e
	}
	if _, _, e = cp.Load(); e != nil {
		return fmt.Errorf("checkpoint unavailable: %w", e)
	}
	// Cleanup is intentionally the final preflight step. Listen itself never
	// unlinks a path, so a socket created after this point makes Listen fail.
	if err := refuseActiveSocket(socketRoot, o.socket); err != nil {
		return err
	}
	if err := refuseActiveSocket(journalSocketRoot, filepath.Join(o.journalSocketRoot, o.journalSocket)); err != nil {
		return err
	}
	store, e := platformanchor.NewProductionStore(o.state, cp)
	if e != nil {
		return e
	}
	// The isolated journal key shares the daemon-wide explicit rotation epoch.
	journalSrv, e := platformanchor.NewProductionJournalServer(store, platformanchor.JournalPolicy{ProductionPolicy: platformanchor.ProductionPolicy{Channel: journalChannel, LocalRole: o.journalRole, PeerRole: o.journalPeerRole, LocalRelease: o.journalLocalRelease, PeerRelease: o.journalPeerRelease, ExpectedLocalUID: &o.localUID, ExpectedLocalGID: &o.localGID, ExpectedPeerUID: &o.journalPeerUID, ExpectedPeerGID: &o.journalPeerGID, ExpectedKeyEpoch: o.keyEpoch}, Audience: journalChannel})
	if e != nil {
		return e
	}
	defer store.Close()
	srv, e := platformanchor.NewProductionServer(store, platformanchor.ProductionPolicy{Channel: o.channel, LocalRole: o.localRole, PeerRole: o.peerRole, LocalRelease: o.localRelease, PeerRelease: o.peerRelease, ExpectedLocalUID: &o.localUID, ExpectedLocalGID: &o.localGID, ExpectedPeerUID: &o.peerUID, ExpectedPeerGID: &o.peerGID, ExpectedKeyEpoch: o.keyEpoch})
	if e != nil {
		return e
	}
	ln, e := macoschannel.Listen(anchorCfg)
	if e != nil {
		return e
	}
	defer ln.Close()
	journalLn, e := macoschannel.Listen(journalCfg)
	if e != nil {
		return e
	}
	defer journalLn.Close()
	defer srv.Close()
	ctx, cancel = signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	return serveProductionBoth(ctx, srv, ln, journalSrv, journalLn)
}

func preflightKey(ctx context.Context, source *servicekey.Source, channel string, expectedEpoch uint64) error {
	key, epoch, err := source.LoadContext(ctx, channel)
	for i := range key {
		key[i] = 0
	}
	if err != nil || epoch == 0 || epoch != expectedEpoch {
		return errors.New("service key unavailable")
	}
	return nil
}
func serveSynthetic(server *platformanchor.Server, ln net.Listener) error {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	var wg sync.WaitGroup
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		select {
		case <-ctx.Done():
			_ = ln.Close()
		case <-stop:
		}
	}()
	defer wg.Wait()
	for {
		c, e := ln.Accept()
		if e != nil {
			if errors.Is(e, net.ErrClosed) {
				return nil
			}
			select {
			case <-ctx.Done():
				return nil
			default:
				continue
			}
		}
		wg.Add(1)
		go func() { defer wg.Done(); _ = server.ServeConn(ctx, c) }()
	}
}

type productionServer interface {
	ServeConn(context.Context, macoschannel.Conn) error
}

type productionListener interface {
	AcceptAuthenticated(context.Context) (macoschannel.Conn, error)
	Close() error
}

func serveProductionBoth(ctx context.Context, anchor productionServer, anchorLn productionListener, journal productionServer, journalLn productionListener) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	results := make(chan error, 2)
	go func() { results <- serveProduction(ctx, anchor, anchorLn) }()
	go func() { results <- serveProduction(ctx, journal, journalLn) }()
	first := <-results
	cancel()
	_ = anchorLn.Close()
	_ = journalLn.Close()
	second := <-results
	if first != nil {
		return first
	}
	return second
}

func serveProduction(ctx context.Context, server productionServer, ln productionListener) error {
	serveCtx, cancel := context.WithCancel(ctx)
	var wg sync.WaitGroup
	defer func() {
		cancel()
		wg.Wait()
	}()
	for {
		c, e := ln.AcceptAuthenticated(serveCtx)
		if e != nil {
			if serveCtx.Err() != nil {
				return nil
			}
			cancel()
			return fmt.Errorf("authenticated accept failed: %w", e)
		}
		wg.Add(1)
		go func() { defer wg.Done(); _ = server.ServeConn(serveCtx, c) }()
	}
}

func openVerifiedRoots(requirements []rootRequirement) ([]verifiedRoot, error) {
	roots := make([]verifiedRoot, 0, len(requirements))
	for _, requirement := range requirements {
		r, err := openVerifiedRoot(requirement)
		if err != nil {
			closeVerifiedRoots(roots)
			return nil, err
		}
		roots = append(roots, r)
	}
	for i := range roots {
		for j := i + 1; j < len(roots); j++ {
			_, iContainsJ := roots[i].ancestry[roots[j].identity]
			_, jContainsI := roots[j].ancestry[roots[i].identity]
			if roots[i].identity == roots[j].identity || iContainsJ || jContainsI {
				closeVerifiedRoots(roots)
				return nil, fmt.Errorf("production roots physically overlap: %s and %s", roots[i].name, roots[j].name)
			}
		}
	}
	return roots, nil
}

func openVerifiedRoot(requirement rootRequirement) (verifiedRoot, error) {
	if requirement.name == "" || !absClean(requirement.path) || requirement.mode.Perm() == 0 || requirement.mode&^os.FileMode(0777) != 0 {
		return verifiedRoot{}, fmt.Errorf("production %s root unavailable", requirement.name)
	}
	volumeRoot := filepath.VolumeName(requirement.path) + string(filepath.Separator)
	current, err := os.OpenRoot(volumeRoot)
	if err != nil {
		return verifiedRoot{}, fmt.Errorf("production %s root unavailable", requirement.name)
	}
	ancestry := make(map[fileIdentity]struct{})
	addIdentity := func(info os.FileInfo) (fileIdentity, bool) {
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || st == nil {
			return fileIdentity{}, false
		}
		id := fileIdentity{dev: uint64(st.Dev), ino: uint64(st.Ino)}
		ancestry[id] = struct{}{}
		return id, true
	}
	rootInfo, err := current.Lstat(".")
	if err != nil {
		_ = current.Close()
		return verifiedRoot{}, fmt.Errorf("production %s root unavailable", requirement.name)
	}
	if _, ok := addIdentity(rootInfo); !ok {
		_ = current.Close()
		return verifiedRoot{}, fmt.Errorf("production %s root unavailable", requirement.name)
	}
	rest := strings.TrimPrefix(requirement.path, volumeRoot)
	for _, part := range strings.Split(rest, string(filepath.Separator)) {
		if part == "" {
			continue
		}
		info, statErr := current.Lstat(part)
		if statErr != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			_ = current.Close()
			return verifiedRoot{}, fmt.Errorf("production %s root unavailable", requirement.name)
		}
		next, openErr := current.OpenRoot(part)
		if openErr != nil {
			_ = current.Close()
			return verifiedRoot{}, fmt.Errorf("production %s root unavailable", requirement.name)
		}
		opened, openedErr := next.Lstat(".")
		pathID, pathOK := identityOf(info)
		openedID, openedOK := identityOf(opened)
		_ = current.Close()
		if openedErr != nil || !pathOK || !openedOK || pathID != openedID {
			_ = next.Close()
			return verifiedRoot{}, fmt.Errorf("production %s root unavailable", requirement.name)
		}
		ancestry[openedID] = struct{}{}
		current = next
	}
	info, err := current.Lstat(".")
	id, ok := identityOf(info)
	if err != nil || !ok {
		_ = current.Close()
		return verifiedRoot{}, fmt.Errorf("production %s root unavailable", requirement.name)
	}
	if !rootMetadataMatches(info, requirement) {
		_ = current.Close()
		return verifiedRoot{}, fmt.Errorf("production %s root metadata mismatch", requirement.name)
	}
	return verifiedRoot{name: requirement.name, path: requirement.path, root: current, identity: id, ancestry: ancestry}, nil
}

func identityOf(info os.FileInfo) (fileIdentity, bool) {
	if info == nil {
		return fileIdentity{}, false
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st == nil {
		return fileIdentity{}, false
	}
	return fileIdentity{dev: uint64(st.Dev), ino: uint64(st.Ino)}, true
}

func rootMetadataMatches(info os.FileInfo, requirement rootRequirement) bool {
	if info == nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != requirement.mode.Perm() || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		return false
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	return ok && st != nil && uint32(st.Uid) == requirement.uid && uint32(st.Gid) == requirement.gid && uint32(st.Mode)&07000 == 0
}

func closeVerifiedRoots(roots []verifiedRoot) {
	for i := range roots {
		if roots[i].root != nil {
			_ = roots[i].root.Close()
		}
	}
}
func refuseActiveSocket(root *os.Root, path string) error {
	fi, e := os.Lstat(path)
	if errors.Is(e, os.ErrNotExist) {
		return nil
	}
	if e != nil {
		return e
	}
	if fi.Mode()&os.ModeSocket == 0 {
		return errors.New("existing anchor path is not a socket")
	}
	if c, e := net.DialTimeout("unix", path, 100*time.Millisecond); e == nil {
		_ = c.Close()
		return errors.New("active anchor socket exists; refusing replacement")
	}
	if root == nil {
		return nil
	}
	return platformanchor.RemoveStaleSocket(root, filepath.Base(path))
}
func rootsOverlap(a, b string) bool {
	ra, ea := filepath.Rel(a, b)
	rb, eb := filepath.Rel(b, a)
	return (ea == nil && (ra == "." || (ra != ".." && !strings.HasPrefix(ra, ".."+string(filepath.Separator))))) || (eb == nil && (rb == "." || (rb != ".." && !strings.HasPrefix(rb, ".."+string(filepath.Separator)))))
}
