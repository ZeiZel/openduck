package main

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"openduck/internal/macoschannel"
)

type testKeySource struct{}

func (testKeySource) LoadContext(context.Context, string) ([]byte, uint64, error) {
	return []byte("01234567890123456789012345678901"), 1, nil
}

type countingFailListener struct{ calls atomic.Int32 }

func (l *countingFailListener) AcceptAuthenticated(context.Context) (macoschannel.Conn, error) {
	l.calls.Add(1)
	return nil, errors.New("persistent accept failure")
}
func (*countingFailListener) Close() error { return nil }

type unusedProductionServer struct{}

func (unusedProductionServer) ServeConn(context.Context, macoschannel.Conn) error { return nil }

type dualFakeListener struct {
	started chan struct{}
	fail    error
	closed  chan struct{}
	once    atomic.Bool
}

func (l *dualFakeListener) AcceptAuthenticated(ctx context.Context) (macoschannel.Conn, error) {
	select {
	case l.started <- struct{}{}:
	default:
	}
	if l.fail != nil {
		return nil, l.fail
	}
	<-ctx.Done()
	return nil, ctx.Err()
}
func (l *dualFakeListener) Close() error {
	if l.once.CompareAndSwap(false, true) {
		close(l.closed)
	}
	return nil
}

type joiningProductionServer struct {
	started chan struct{}
	joined  chan struct{}
}

func skipIfUnixSocketUnavailable(t *testing.T, err error) {
	t.Helper()
	// The desktop test harness can prohibit AF_UNIX even though the macOS
	// implementation is correct. Keep these kernel-backed checks enabled on
	// normal hosts while making that external sandbox restriction explicit.
	if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) {
		t.Skipf("Unix socket unavailable in current execution sandbox: %v", err)
	}
}

func (s *joiningProductionServer) ServeConn(ctx context.Context, c macoschannel.Conn) error {
	defer close(s.joined)
	defer c.Close()
	close(s.started)
	<-ctx.Done()
	return ctx.Err()
}

func TestParseRejectsMixedModesWithoutFilesystemMutation(t *testing.T) {
	dir := t.TempDir()
	state := filepath.Join(dir, "state")
	_, err := parse([]string{"-synthetic", "-state", state, "-socket", filepath.Join(state, "anchor.sock"), "-checkpoint", filepath.Join(dir, "checkpoint"), "-release-root", filepath.Join(dir, "release")})
	if err == nil {
		t.Fatal("mixed production/synthetic inputs accepted")
	}
	if _, err := os.Stat(state); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("parse mutated state root: %v", err)
	}
}

func TestParseProductionRequiresCompleteValidatedInputs(t *testing.T) {
	if _, err := parse([]string{"-state", "/private/tmp/state", "-socket", "/private/tmp/state/anchor.sock"}); err == nil {
		t.Fatal("incomplete production options accepted")
	}
	d := strings.Repeat("a", 64)
	args := []string{
		"-state", "/private/tmp/state", "-socket", "/private/tmp/socket/anchor.sock", "-socket-root", "/private/tmp/socket",
		"-key-root", "/private/tmp/key", "-checkpoint-key-root", "/private/tmp/checkpoint-key", "-release-root", "/private/tmp/release", "-checkpoint-release-root", "/private/tmp/checkpoint-release",
		"-checkpoint-socket-root", "/private/tmp/checkpoint", "-checkpoint-socket", "checkpoint.sock",
		"-local-release", "anchor", "-local-binary-digest", d, "-local-socket-digest", d, "-local-manifest-digest", d,
		"-peer-release", "controller", "-peer-binary-digest", d, "-peer-socket-digest", d, "-peer-manifest-digest", d,
		"-checkpoint-local-release", "anchor", "-checkpoint-local-binary-digest", d, "-checkpoint-local-socket-digest", d, "-checkpoint-local-manifest-digest", d,
		"-checkpoint-peer-release", "checkpoint", "-checkpoint-peer-binary-digest", d, "-checkpoint-peer-socket-digest", d, "-checkpoint-peer-manifest-digest", d,
		"-local-uid", "1000", "-local-gid", "1000", "-peer-uid", "1001", "-peer-gid", "1001", "-channel-gid", "1003", "-checkpoint-channel-gid", "1004",
		"-checkpoint-local-uid", "1000", "-checkpoint-local-gid", "1000", "-checkpoint-peer-uid", "1002", "-checkpoint-peer-gid", "1002", "-key-epoch", "1",
		"-journal-socket-root", "/private/tmp/journal-socket", "-journal-socket", "journal.sock", "-journal-key-root", "/private/tmp/journal-key", "-journal-key-file", "journal.key", "-journal-release-root", "/private/tmp/journal-release", "-journal-local-role", "anchor", "-journal-peer-role", "installer",
		"-journal-local-release", "anchor-journal", "-journal-local-binary-digest", d, "-journal-local-socket-digest", d, "-journal-local-manifest-digest", d, "-journal-peer-release", "installer", "-journal-peer-binary-digest", d, "-journal-peer-socket-digest", d, "-journal-peer-manifest-digest", d,
		"-journal-peer-uid", "0", "-journal-peer-gid", "1005", "-journal-channel-gid", "1006",
	}
	o, err := parse(args)
	if err != nil {
		t.Fatalf("complete options rejected before filesystem checks: %v", err)
	}
	canonical := BuildProductionArgs(o)
	if _, err := parse(canonical); err != nil {
		t.Fatalf("canonical production args rejected: %v", err)
	}
	for _, omitted := range []string{"-journal-socket-root", "-journal-socket", "-journal-key-root", "-journal-key-file", "-journal-release-root", "-journal-local-role", "-journal-peer-role", "-journal-peer-uid", "-journal-peer-gid", "-journal-channel-gid", "-journal-local-release", "-journal-peer-release"} {
		trimmed := append([]string(nil), canonical...)
		for i := range trimmed {
			if trimmed[i] == omitted {
				trimmed = append(trimmed[:i], trimmed[i+2:]...)
				break
			}
		}
		if _, err := parse(trimmed); err == nil {
			t.Fatalf("omitted journal input accepted: %s", omitted)
		}
	}
	for name, mutate := range map[string]func(*options){
		"state overlap":      func(x *options) { x.state = x.journalKeyRoot },
		"journal overlap":    func(x *options) { x.journalReleaseRoot = x.journalKeyRoot },
		"wrong journal role": func(x *options) { x.journalRole = "controller" },
		"same journal uid":   func(x *options) { x.journalPeerUID = x.localUID },
	} {
		t.Run(name, func(t *testing.T) {
			x := o
			mutate(&x)
			if _, err := parse(BuildProductionArgs(x)); err == nil {
				t.Fatal("invalid journal contract accepted")
			}
		})
	}
	for name, gid := range map[string]uint32{"local-primary": o.localGID, "peer-primary": o.peerGID} {
		t.Run("channel-group-distinct-from-"+name, func(t *testing.T) {
			invalid := o
			invalid.channelGID = gid
			if err := validateProductionOptions(invalid); err == nil {
				t.Fatal("service primary group accepted as the shared channel group")
			}
		})
	}
}

func TestRefuseActiveSocketPreservesLiveSocket(t *testing.T) {
	dir, err := os.MkdirTemp("/private/tmp", "oda-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	path := filepath.Join(dir, "anchor.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		skipIfUnixSocketUnavailable(t, err)
		t.Fatal(err)
	}
	defer ln.Close()
	if err := refuseActiveSocket(nil, path); err == nil {
		t.Fatal("live socket accepted for replacement")
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("live socket was removed: %v", err)
	}
}

func TestRunProductionFailsBeforeStateMutationWhenPreflightUnavailable(t *testing.T) {
	base, err := os.MkdirTemp("/private/tmp", "oda-preflight-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	paths := []string{"state", "key", "checkpoint-key", "release", "checkpoint-release"}
	for _, name := range paths {
		if err := os.Mkdir(filepath.Join(base, name), 0700); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"socket-root", "checkpoint-socket"} {
		if err := os.Mkdir(filepath.Join(base, name), 0750); err != nil {
			t.Fatal(err)
		}
	}
	d := strings.Repeat("a", 64)
	set := map[string]bool{}
	for _, name := range []string{"local-uid", "local-gid", "peer-uid", "peer-gid", "channel-gid", "checkpoint-channel-gid", "checkpoint-local-uid", "checkpoint-local-gid", "checkpoint-peer-uid", "checkpoint-peer-gid", "key-epoch"} {
		set[name] = true
	}
	o := options{state: filepath.Join(base, "state"), socketRoot: filepath.Join(base, "socket-root"), socket: filepath.Join(base, "socket-root", "anchor.sock"), keyRoot: filepath.Join(base, "key"), checkpointKeyRoot: filepath.Join(base, "checkpoint-key"), releaseRoot: filepath.Join(base, "release"), checkpointReleaseRoot: filepath.Join(base, "checkpoint-release"), checkpointSocketRoot: filepath.Join(base, "checkpoint-socket"), checkpointSocket: "checkpoint.sock", channel: "anchor", localRole: "anchor", peerRole: "controller", checkpointLocalRole: "anchor", checkpointPeerRole: "checkpoint", localRelease: macoschannel.ReleasePin{ReleaseID: "a", BinaryDigest: d, SocketDigest: d, ManifestDigest: d}, peerRelease: macoschannel.ReleasePin{ReleaseID: "p", BinaryDigest: d, SocketDigest: d, ManifestDigest: d}, checkpointLocalRelease: macoschannel.ReleasePin{ReleaseID: "a", BinaryDigest: d, SocketDigest: d, ManifestDigest: d}, checkpointPeerRelease: macoschannel.ReleasePin{ReleaseID: "c", BinaryDigest: d, SocketDigest: d, ManifestDigest: d}, localUID: 1000, localGID: 1000, peerUID: 1001, peerGID: 1001, channelGID: 1003, checkpointLocalUID: 1000, checkpointLocalGID: 1000, checkpointPeerUID: 1002, checkpointPeerGID: 1002, keyEpoch: 1, numericSet: set}
	if err := runProduction(o); err == nil {
		t.Fatal("production unexpectedly started without service records")
	}
	entries, err := os.ReadDir(o.state)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("production preflight mutated state: %v", entries)
	}
}

func TestOpenVerifiedRootsEnforcesExactModesAndPhysicalSeparation(t *testing.T) {
	base, err := os.MkdirTemp("/private/tmp", "oda-roots-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	uid := uint32(os.Geteuid())
	privatePath := filepath.Join(base, "private")
	channelPath := filepath.Join(base, "channel")
	if err := os.Mkdir(privatePath, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(channelPath, 0750); err != nil {
		t.Fatal(err)
	}
	privateGID := fileGID(t, privatePath)
	channelGID := fileGID(t, channelPath)
	reqs := []rootRequirement{{name: "private", path: privatePath, uid: uid, gid: privateGID, mode: 0700}, {name: "channel", path: channelPath, uid: uid, gid: channelGID, mode: 0750}}
	roots, err := openVerifiedRoots(reqs)
	if err != nil {
		t.Fatalf("valid root set rejected: %v", err)
	}
	closeVerifiedRoots(roots)
	if err := os.Chmod(privatePath, 0750); err != nil {
		t.Fatal(err)
	}
	if roots, err = openVerifiedRoots(reqs); err == nil {
		closeVerifiedRoots(roots)
		t.Fatal("private root with channel mode accepted")
	}
	if err := os.Chmod(privatePath, 0700); err != nil {
		t.Fatal(err)
	}
	overlap := []rootRequirement{{name: "one", path: privatePath, uid: uid, gid: privateGID, mode: 0700}, {name: "alias", path: privatePath, uid: uid, gid: privateGID, mode: 0700}}
	if roots, err = openVerifiedRoots(overlap); err == nil {
		closeVerifiedRoots(roots)
		t.Fatal("same physical root accepted twice")
	}
	nestedPath := filepath.Join(privatePath, "nested")
	if err := os.Mkdir(nestedPath, 0700); err != nil {
		t.Fatal(err)
	}
	nestedGID := fileGID(t, nestedPath)
	nested := []rootRequirement{{name: "parent", path: privatePath, uid: uid, gid: privateGID, mode: 0700}, {name: "child", path: nestedPath, uid: uid, gid: nestedGID, mode: 0700}}
	if roots, err = openVerifiedRoots(nested); err == nil {
		closeVerifiedRoots(roots)
		t.Fatal("physically nested roots accepted")
	}
	symlinkPath := filepath.Join(base, "private-alias")
	if err := os.Symlink(privatePath, symlinkPath); err != nil {
		t.Fatal(err)
	}
	if roots, err = openVerifiedRoots([]rootRequirement{{name: "symlink", path: symlinkPath, uid: uid, gid: privateGID, mode: 0700}}); err == nil {
		closeVerifiedRoots(roots)
		t.Fatal("symlink root accepted")
	}
}

func TestServeProductionReturnsPersistentAcceptErrorWithoutSpin(t *testing.T) {
	ln := &countingFailListener{}
	err := serveProduction(context.Background(), unusedProductionServer{}, ln)
	if err == nil || !strings.Contains(err.Error(), "authenticated accept failed") {
		t.Fatalf("persistent accept error not returned: %v", err)
	}
	if got := ln.calls.Load(); got != 1 {
		t.Fatalf("accept retried %d times", got)
	}
}

func TestServeProductionBothStartsAndCancelsBothListeners(t *testing.T) {
	a := &dualFakeListener{started: make(chan struct{}, 1), closed: make(chan struct{})}
	j := &dualFakeListener{started: make(chan struct{}, 1), closed: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- serveProductionBoth(ctx, unusedProductionServer{}, a, unusedProductionServer{}, j) }()
	for _, l := range []*dualFakeListener{a, j} {
		select {
		case <-l.started:
		case <-time.After(time.Second):
			t.Fatal("listener was not served")
		}
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("signal cancellation: %v", err)
	}
}

func TestServeProductionBothFailureClosesSibling(t *testing.T) {
	a := &dualFakeListener{started: make(chan struct{}, 1), fail: errors.New("boom"), closed: make(chan struct{})}
	j := &dualFakeListener{started: make(chan struct{}, 1), closed: make(chan struct{})}
	if err := serveProductionBoth(context.Background(), unusedProductionServer{}, a, unusedProductionServer{}, j); err == nil || !strings.Contains(err.Error(), "authenticated accept failed") {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, l := range []*dualFakeListener{a, j} {
		select {
		case <-l.closed:
		case <-time.After(time.Second):
			t.Fatal("listener not closed")
		}
	}
}

func TestServeProductionAuthenticatedSameUIDLifecycleJoins(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("kernel peer credential transport is Darwin-only")
	}
	base, err := os.MkdirTemp("/private/tmp", "oda-lifecycle-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	socketRoot := filepath.Join(base, "channel")
	if err := os.Mkdir(socketRoot, 0750); err != nil {
		t.Fatal(err)
	}
	uid, peerGID := uint32(os.Geteuid()), uint32(os.Getegid())
	socketRootGID := fileGID(t, socketRoot)
	socketDigest := testSocketDigest("anchor.sock", uid, socketRootGID, 0660)
	serverRoot, serverPin := testRelease(t, base, "server-release", "server", socketDigest)
	clientRoot, clientPin := testRelease(t, base, "client-release", "client", socketDigest)
	serverReleaseGID := rootGID(t, serverRoot)
	clientReleaseGID := rootGID(t, clientRoot)
	serverSocketRoot, err := os.OpenRoot(socketRoot)
	if err != nil {
		t.Fatal(err)
	}
	defer serverSocketRoot.Close()
	clientSocketRoot, err := os.OpenRoot(socketRoot)
	if err != nil {
		t.Fatal(err)
	}
	defer clientSocketRoot.Close()
	serverCfg := lifecycleConfig(socketRoot, serverSocketRoot, serverRoot, serverPin, clientPin, "anchor", "controller", uid, peerGID, socketRootGID, serverReleaseGID)
	clientCfg := lifecycleConfig(socketRoot, clientSocketRoot, clientRoot, clientPin, serverPin, "controller", "anchor", uid, peerGID, socketRootGID, clientReleaseGID)
	ln, err := macoschannel.Listen(serverCfg)
	if err != nil {
		skipIfUnixSocketUnavailable(t, err)
		t.Fatal(err)
	}
	defer ln.Close()
	ctx, cancel := context.WithCancel(context.Background())
	server := &joiningProductionServer{started: make(chan struct{}), joined: make(chan struct{})}
	done := make(chan error, 1)
	go func() { done <- serveProduction(ctx, server, ln) }()
	conn, err := macoschannel.Dial(context.Background(), clientCfg)
	if err != nil {
		cancel()
		skipIfUnixSocketUnavailable(t, err)
		t.Fatal(err)
	}
	defer conn.Close()
	select {
	case <-server.started:
	case <-time.After(3 * time.Second):
		cancel()
		t.Fatal("server did not accept authenticated connection")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("canceled production loop returned error: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("production loop did not stop")
	}
	select {
	case <-server.joined:
	case <-time.After(time.Second):
		t.Fatal("connection handler was not joined")
	}
}

func TestProductionListenNeverUnlinksSocketCreatedAfterCleanup(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("production Unix socket validation is Darwin-only")
	}
	base, err := os.MkdirTemp("/private/tmp", "oda-listen-race-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	socketRoot := filepath.Join(base, "channel")
	if err := os.Mkdir(socketRoot, 0750); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(socketRoot, "anchor.sock")
	raceListener, err := net.Listen("unix", path)
	if err != nil {
		skipIfUnixSocketUnavailable(t, err)
		t.Fatal(err)
	}
	defer raceListener.Close()
	if err := os.Chmod(path, 0660); err != nil {
		t.Fatal(err)
	}
	before, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	uid, peerGID := uint32(os.Geteuid()), uint32(os.Getegid())
	socketRootGID := fileGID(t, socketRoot)
	socketDigest := testSocketDigest("anchor.sock", uid, socketRootGID, 0660)
	releaseRoot, pin := testRelease(t, base, "race-release", "race", socketDigest)
	releaseGID := rootGID(t, releaseRoot)
	socketFD, err := os.OpenRoot(socketRoot)
	if err != nil {
		t.Fatal(err)
	}
	defer socketFD.Close()
	cfg := lifecycleConfig(socketRoot, socketFD, releaseRoot, pin, pin, "anchor", "controller", uid, peerGID, socketRootGID, releaseGID)
	if ln, err := macoschannel.Listen(cfg); err == nil {
		_ = ln.Close()
		t.Fatal("listener replaced a socket that appeared after cleanup")
	}
	after, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("racing socket was removed: %v", err)
	}
	beforeID, beforeOK := identityOf(before)
	afterID, afterOK := identityOf(after)
	if !beforeOK || !afterOK || beforeID != afterID {
		t.Fatal("racing socket identity changed")
	}
	conn, err := net.DialTimeout("unix", path, time.Second)
	if err != nil {
		t.Fatalf("racing socket no longer active: %v", err)
	}
	_ = conn.Close()
}

func lifecycleConfig(socketRoot string, socketFD, releaseRoot *os.Root, local, peer macoschannel.ReleasePin, localRole, peerRole string, uid, peerGID, socketRootGID, releaseRootGID uint32) macoschannel.Config {
	return macoschannel.Config{
		Contract:     macoschannel.SocketContract{Channel: "platform-anchor", LocalRole: localRole, PeerRole: peerRole, SocketPath: "anchor.sock", SocketRoot: socketRoot, ExpectedPeerUID: &uid, ExpectedPeerGID: &peerGID, ExpectedSocketRootUID: uid, ExpectedSocketRootGID: socketRootGID, ExpectedSocketRootMode: 0750, ExpectedSocketUID: uid, ExpectedSocketGID: socketRootGID, ExpectedSocketMode: 0660},
		LocalRelease: local, PeerRelease: peer, ReleaseRoot: releaseRoot, SocketRootFD: socketFD, BinaryName: "openduck-anchor", KeySource: testKeySource{}, ExpectedReleaseRootUID: uid, ExpectedReleaseRootGID: releaseRootGID, ExpectedReleaseRootMode: 0700, ExpectedManifestMode: 0600, ExpectedBinaryMode: 0700,
	}
}

func fileGID(t *testing.T, path string) uint32 {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st == nil {
		t.Fatal("missing stat metadata")
	}
	return uint32(st.Gid)
}

func rootGID(t *testing.T, root *os.Root) uint32 {
	t.Helper()
	info, err := root.Lstat(".")
	if err != nil {
		t.Fatal(err)
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st == nil {
		t.Fatal("missing stat metadata")
	}
	return uint32(st.Gid)
}

func testRelease(t *testing.T, base, dir, id, socketDigest string) (*os.Root, macoschannel.ReleasePin) {
	t.Helper()
	path := filepath.Join(base, dir)
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	binaryContent := []byte("binary-" + id)
	if err := os.WriteFile(filepath.Join(path, "openduck-anchor"), binaryContent, 0700); err != nil {
		t.Fatal(err)
	}
	pin := macoschannel.ReleasePin{ReleaseID: id, BinaryDigest: testDigest(binaryContent), SocketDigest: socketDigest}
	manifest := []byte(`{"release_id":"` + id + `","binary":"openduck-anchor","socket":"anchor.sock","binary_digest":"` + pin.BinaryDigest + `","socket_digest":"` + pin.SocketDigest + `"}`)
	pin.ManifestDigest = testDigest(manifest)
	if err := os.WriteFile(filepath.Join(path, "manifest.json"), manifest, 0600); err != nil {
		t.Fatal(err)
	}
	r, err := os.OpenRoot(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })
	return r, pin
}

func testDigest(b []byte) string {
	d := sha256.Sum256(b)
	return hex.EncodeToString(d[:])
}

func testSocketDigest(name string, uid, gid uint32, mode os.FileMode) string {
	h := sha256.New()
	_, _ = h.Write([]byte(name))
	_, _ = h.Write([]byte{0})
	var modeBytes [4]byte
	binary.BigEndian.PutUint32(modeBytes[:], uint32(mode.Perm()))
	_, _ = h.Write(modeBytes[:])
	var ids [8]byte
	binary.BigEndian.PutUint32(ids[:4], uid)
	binary.BigEndian.PutUint32(ids[4:], gid)
	_, _ = h.Write(ids[:])
	return hex.EncodeToString(h.Sum(nil))
}

func TestDisabledAnchorPlistParsesCompleteJournalContractAndFailsClosed(t *testing.T) {
	path := filepath.Join("..", "..", "deploy", "macos", "com.openduck.anchor.plist")
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	args, disabled, runAtLoad, err := plistProgramArguments(f)
	if err != nil {
		t.Fatal(err)
	}
	if !disabled || runAtLoad {
		t.Fatalf("anchor plist activation flags unsafe: Disabled=%v RunAtLoad=%v", disabled, runAtLoad)
	}
	if len(args) < 2 || !strings.Contains(args[0], "/releases/anchor/RELEASE_ID/openduck-anchor") {
		t.Fatalf("unexpected immutable program path: %v", args)
	}
	digest := strings.Repeat("a", 64)
	values := map[string]string{
		"ANCHOR_UID":                   "1000",
		"ANCHOR_GID":                   "1000",
		"CONTROLLER_UID":               "1001",
		"CONTROLLER_GID":               "1001",
		"CHANNEL_GID":                  "1003",
		"CHECKPOINT_CHANNEL_GID":       "1004",
		"CHECKPOINT_UID":               "1002",
		"CHECKPOINT_GID":               "1002",
		"KEY_EPOCH":                    "1",
		"ANCHOR_RELEASE_ID":            "anchor-r",
		"CONTROLLER_RELEASE_ID":        "controller-r",
		"ANCHOR_CHECKPOINT_RELEASE_ID": "anchor-checkpoint-r",
		"CHECKPOINT_RELEASE_ID":        "checkpoint-r",
		"JOURNAL_IA_RELEASE":           "installer-r",
		"JOURNAL_AN_SOCKET":            digest,
		"JOURNAL_AN_MANIFEST":          digest,
		"JOURNAL_IA_BINARY":            digest,
		"JOURNAL_IA_SOCKET":            digest,
		"JOURNAL_IA_MANIFEST":          digest,
		"JOURNAL_INSTALLER_UID":        "0",
		"JOURNAL_INSTALLER_GID":        "0",
		"JOURNAL_IA_GID":               "1006",
	}
	for i := 1; i < len(args); i++ {
		args[i] = strings.ReplaceAll(args[i], "RELEASE_ID", "anchor-r")
		if value, ok := values[args[i]]; ok {
			args[i] = value
			continue
		}
		if !strings.Contains(args[i], "/") && strings.HasSuffix(args[i], "_DIGEST") {
			args[i] = digest
		}
	}
	if _, err := parse(args[1:]); err != nil {
		t.Fatalf("complete anchor plist contract rejected: %v", err)
	}
	trimmed := append([]string(nil), args[1:]...)
	for i := 0; i < len(trimmed); i++ {
		if trimmed[i] == "-journal-key-root" {
			trimmed = append(trimmed[:i], trimmed[i+2:]...)
			break
		}
	}
	if _, err := parse(trimmed); err == nil {
		t.Fatal("anchor plist accepted without mandatory installer-journal key root")
	}
}

func plistProgramArguments(r io.Reader) (args []string, disabled, runAtLoad bool, err error) {
	decoder := xml.NewDecoder(r)
	var lastKey string
	inArguments := false
	for {
		token, decodeErr := decoder.Token()
		if decodeErr == io.EOF {
			return args, disabled, runAtLoad, nil
		}
		if decodeErr != nil {
			return nil, false, false, decodeErr
		}
		switch value := token.(type) {
		case xml.StartElement:
			switch value.Name.Local {
			case "key":
				if decodeErr = decoder.DecodeElement(&lastKey, &value); decodeErr != nil {
					return nil, false, false, decodeErr
				}
			case "array":
				inArguments = lastKey == "ProgramArguments"
			case "string":
				if inArguments {
					var item string
					if decodeErr = decoder.DecodeElement(&item, &value); decodeErr != nil {
						return nil, false, false, decodeErr
					}
					args = append(args, item)
				}
			case "true":
				if lastKey == "Disabled" {
					disabled = true
				}
				if lastKey == "RunAtLoad" {
					runAtLoad = true
				}
			case "false":
				if lastKey == "Disabled" {
					disabled = false
				}
				if lastKey == "RunAtLoad" {
					runAtLoad = false
				}
			}
		case xml.EndElement:
			if value.Name.Local == "array" {
				inArguments = false
			}
		}
	}
}
