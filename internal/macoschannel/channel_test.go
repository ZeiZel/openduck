package macoschannel

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"syscall"
	"testing"
	"time"
)

type testKeys struct {
	key   []byte
	epoch uint64
}

func (k testKeys) LoadContext(context.Context, string) ([]byte, uint64, error) {
	return append([]byte(nil), k.key...), k.epoch, nil
}
func testKey() testKeys { return testKeys{key: []byte("01234567890123456789012345678901"), epoch: 7} }

type blockingContextKeySource struct{}

func (blockingContextKeySource) Load(string) ([]byte, uint64, error) {
	panic("context loader required")
}
func (blockingContextKeySource) LoadContext(ctx context.Context, _ string) ([]byte, uint64, error) {
	<-ctx.Done()
	return nil, 0, ctx.Err()
}

func TestLoadKeyContextHonorsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := loadKeyContext(ctx, blockingContextKeySource{}, "anchor"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("blocked key source returned %v", err)
	}
}

func digest(s string) string   { d := sha256.Sum256([]byte(s)); return hex.EncodeToString(d[:]) }
func uintPtr(v uint32) *uint32 { return &v }
func shortTemp(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("/private/tmp", "odch-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(d) })
	return d
}

func release(t *testing.T, id, socketDigest string) (*os.Root, ReleasePin) {
	t.Helper()
	d := t.TempDir()
	if err := os.Chmod(d, 0700); err != nil {
		t.Fatal(err)
	}
	binaryContent := []byte("binary-" + id)
	if err := os.WriteFile(filepath.Join(d, "bin"), binaryContent, 0700); err != nil {
		t.Fatal(err)
	}
	p := ReleasePin{ReleaseID: id, BinaryDigest: digest(string(binaryContent)), SocketDigest: socketDigest}
	manifest := `{"release_id":"` + id + `","binary":"bin","socket":"channel.sock","binary_digest":"` + p.BinaryDigest + `","socket_digest":"` + p.SocketDigest + `"}`
	p.ManifestDigest = digest(manifest)
	if err := os.WriteFile(filepath.Join(d, "manifest.json"), []byte(manifest), 0600); err != nil {
		t.Fatal(err)
	}
	r, err := os.OpenRoot(d)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })
	return r, p
}

func testConfig(t *testing.T, root, socket string, local, peer ReleasePin) Config {
	t.Helper()
	uid, gid := uint32(os.Geteuid()), uint32(os.Getegid())
	rootInfo, err := os.Lstat(root)
	if err != nil {
		t.Fatal(err)
	}
	rootStat := rootInfo.Sys().(*syscall.Stat_t)
	socketRoot, err := os.OpenRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = socketRoot.Close() })
	return Config{
		Contract: SocketContract{Channel: "control", LocalRole: "a", PeerRole: "b", SocketRoot: root, SocketPath: socket,
			ExpectedPeerUID: uintPtr(uid), ExpectedPeerGID: uintPtr(gid), ExpectedSocketRootUID: uint32(rootStat.Uid), ExpectedSocketRootGID: uint32(rootStat.Gid),
			ExpectedSocketRootMode: 0700, ExpectedSocketUID: uid, ExpectedSocketGID: uint32(rootStat.Gid), ExpectedSocketMode: 0660},
		LocalRelease: local, PeerRelease: peer, ReleaseRoot: mustRoot(t, local), SocketRootFD: socketRoot, BinaryName: "bin", KeySource: testKey(),
		ExpectedReleaseRootUID: uid, ExpectedReleaseRootGID: gid, ExpectedReleaseRootMode: 0700, ExpectedManifestMode: 0600, ExpectedBinaryMode: 0700,
	}
}

// release roots differ by role; bind it to the pin supplied by the test.
var roots sync.Map // map[ReleasePin]*os.Root; only test-local immutable roots
func mustRoot(t *testing.T, p ReleasePin) *os.Root {
	t.Helper()
	r, ok := roots.Load(p.ManifestDigest)
	if !ok {
		t.Fatal("missing release root")
	}
	return r.(*os.Root)
}
func registerRoot(p ReleasePin, r *os.Root) { roots.Store(p.ManifestDigest, r) }

func TestContractRejectsNilPeerAndWeakPin(t *testing.T) {
	c := SocketContract{Channel: "c", LocalRole: "a", PeerRole: "b", SocketRoot: t.TempDir(), SocketPath: "sock"}
	if !errors.Is(c.validate(), ErrUnavailable) {
		t.Fatal("nil peer identity accepted")
	}
	p := ReleasePin{ReleaseID: "r", BinaryDigest: "00", SocketDigest: "00", ManifestDigest: "00"}
	if !errors.Is(p.validate(), ErrRelease) {
		t.Fatal("short digest accepted")
	}
}
func TestProductionAuthenticationFailsClosedWithoutKernelPeerCredentials(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	if _, err := authenticate(a, Config{}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("got %v", err)
	}
}
func TestVerifyReleaseRejectsSymlinkDigestDuplicateAndTrailing(t *testing.T) {
	d := t.TempDir()
	_ = os.Chmod(d, 0700)
	if err := os.WriteFile(filepath.Join(d, "bin"), []byte("binary"), 0700); err != nil {
		t.Fatal(err)
	}
	p := ReleasePin{ReleaseID: "r", BinaryDigest: digest("binary"), SocketDigest: digest("socket")}
	bad := `{"release_id":"r","release_id":"r","binary":"bin","socket":"s","binary_digest":"` + p.BinaryDigest + `","socket_digest":"` + p.SocketDigest + `"}`
	p.ManifestDigest = digest(bad)
	if err := os.WriteFile(filepath.Join(d, "manifest.json"), []byte(bad), 0600); err != nil {
		t.Fatal(err)
	}
	r, err := os.OpenRoot(d)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if !errors.Is(VerifyRelease(r, p, "bin"), ErrRelease) {
		t.Fatal("duplicate manifest accepted")
	}
	if err := os.Symlink("bin", filepath.Join(d, "link")); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(verifyRegular(r, "link", p.BinaryDigest, uint32(os.Geteuid()), uint32(os.Getegid()), 0700), ErrRelease) {
		t.Fatal("symlink accepted")
	}
}

func TestVerifyReleaseDefaultUsesManifest0600Binary0700(t *testing.T) {
	d := t.TempDir()
	if err := os.Chmod(d, 0700); err != nil {
		t.Fatal(err)
	}
	binary := []byte("binary")
	if err := os.WriteFile(filepath.Join(d, "bin"), binary, 0700); err != nil {
		t.Fatal(err)
	}
	manifest := []byte(`{"release_id":"r","binary":"bin","socket":"sock","binary_digest":"` + digest(string(binary)) + `","socket_digest":"` + digest("socket") + `"}`)
	if err := os.WriteFile(filepath.Join(d, "manifest.json"), manifest, 0600); err != nil {
		t.Fatal(err)
	}
	r, err := os.OpenRoot(d)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	p := ReleasePin{ReleaseID: "r", BinaryDigest: digest(string(binary)), SocketDigest: digest("socket"), ManifestDigest: digest(string(manifest))}
	if err := VerifyRelease(r, p, "bin"); err != nil {
		t.Fatalf("default release policy rejected valid files: %v", err)
	}
}

func TestKeyCopyEpochAndZeroing(t *testing.T) {
	source := []byte("01234567890123456789012345678901")
	called := false
	ks := keySourceFunc(func(string) ([]byte, uint64, error) { called = true; return source, 3, nil })
	got, epoch, err := loadKeyContext(context.Background(), ks, "c")
	if err != nil || epoch != 3 || !called {
		t.Fatal(err)
	}
	if string(got) == string(source) {
		t.Fatal("source should have been wiped")
	}
	if len(source) != 32 || source[0] != 0 {
		t.Fatal("provided key not wiped")
	}
	zero(got)
	if _, _, err := loadKeyContext(context.Background(), keySourceFunc(func(string) ([]byte, uint64, error) { return make([]byte, 32), 0, nil }), "c"); !errors.Is(err, ErrUnavailable) {
		t.Fatal("zero epoch accepted")
	}
}

type keySourceFunc func(string) ([]byte, uint64, error)

func (f keySourceFunc) LoadContext(_ context.Context, s string) ([]byte, uint64, error) { return f(s) }

func TestStrictJSONRejectsNullUnknownDuplicateAndTrailing(t *testing.T) {
	for _, raw := range []string{
		`{"version":null,"nonce":"x","mac":"y"}`,
		`{"version":"v","nonce":"x","mac":"y","extra":1}`,
		`{"version":"v","nonce":"x","nonce":"x","mac":"y"}`,
		`{"version":"v","nonce":"x","mac":"y"} {}`,
	} {
		if err := decodeExactJSON([]byte(raw), &ack{}, []string{"version", "nonce", "mac"}); !errors.Is(err, ErrProtocol) {
			t.Fatalf("accepted %s: %v", raw, err)
		}
	}
}

func TestSpecialModeBitsAreRejectedAndBoundIntoDigest(t *testing.T) {
	path := filepath.Join(t.TempDir(), "artifact")
	if err := os.WriteFile(path, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	uid, gid := uint32(os.Geteuid()), uint32(os.Getegid())
	for _, bit := range []os.FileMode{os.ModeSetuid, os.ModeSetgid, os.ModeSticky} {
		if err := os.Chmod(path, 0600|bit); err != nil {
			t.Fatal(err)
		}
		fi, err := os.Lstat(path)
		if err != nil {
			t.Fatal(err)
		}
		if !hasSecurityModeBits(fi.Mode()) {
			t.Fatalf("test filesystem did not retain %v", bit)
		}
		if matchesFile(fi, uid, gid, 0600) {
			t.Fatalf("accepted security mode %v", bit)
		}
		if validImmutableMode(0700|bit, true) {
			t.Fatalf("accepted configured security mode %v", bit)
		}
		if socketDigest("channel.sock", uid, gid, 0660) == socketDigest("channel.sock", uid, gid, 0660|bit) {
			t.Fatalf("digest omitted security mode %v", bit)
		}
	}
}

func TestDarwinUnixSocketMutualHandshake(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("Darwin kernel credentials required")
	}
	root := shortTemp(t)
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	uid, gid := uint32(os.Geteuid()), uint32(os.Getegid())
	rootStat := func() *syscall.Stat_t { fi, _ := os.Lstat(root); return fi.Sys().(*syscall.Stat_t) }()
	sd := socketDigest("channel.sock", uid, uint32(rootStat.Gid), 0660)
	ra, pa := release(t, "a", sd)
	rb, pb := release(t, "b", sd)
	registerRoot(pa, ra)
	registerRoot(pb, rb)
	server := testConfig(t, root, "channel.sock", pa, pb)
	client := testConfig(t, root, "channel.sock", pb, pa)
	client.Contract.LocalRole, client.Contract.PeerRole = "b", "a"
	ln, err := Listen(server)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	requestTag := make(chan string, 1)
	type bindingResult struct {
		tag string
		err error
	}
	response := make(chan bindingResult, 1)
	payload := []byte("darwin authenticated transcript")
	go func() {
		c, e := ln.AcceptAuthenticated(context.Background())
		if e == nil {
			defer c.Close()
			ev := c.Evidence()
			if ev.Peer.UID != uid || ev.LocalRelease != pa || ev.PeerRelease != pb || ev.BindingDigest == "" {
				e = errors.New("bad server evidence")
			} else if e = c.Verify("macoschannel.test.v1", payload, <-requestTag); e == nil {
				var tag string
				tag, e = c.Seal("macoschannel.test.v1", payload)
				response <- bindingResult{tag: tag, err: e}
			}
		}
		if e != nil {
			response <- bindingResult{err: e}
		}
	}()
	c, e := Dial(context.Background(), client)
	if e != nil {
		t.Fatalf("dial=%v accept=%v", e, (<-response).err)
	}
	ev := c.Evidence()
	tag, e := c.Seal("macoschannel.test.v1", payload)
	if e != nil {
		t.Fatal(e)
	}
	requestTag <- tag
	serverResult := <-response
	if serverResult.err != nil {
		t.Fatal(serverResult.err)
	}
	if e = c.Verify("macoschannel.test.v1", payload, serverResult.tag); e != nil {
		t.Fatal(e)
	}
	_ = c.Close()
	if ev.Peer.GID != gid || ev.LocalRelease != pb || ev.PeerRelease != pa || ev.BindingDigest == "" {
		t.Fatal("bad client evidence")
	}
}

func TestAcceptCancellationUnblocks(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("Darwin channel only")
	}
	root := shortTemp(t)
	_ = os.Chmod(root, 0700)
	uid := uint32(os.Geteuid())
	rootStat := func() *syscall.Stat_t { fi, _ := os.Lstat(root); return fi.Sys().(*syscall.Stat_t) }()
	sd := socketDigest("channel.sock", uid, uint32(rootStat.Gid), 0660)
	r, p := release(t, "a", sd)
	registerRoot(p, r)
	cfg := testConfig(t, root, "channel.sock", p, p)
	ln, err := Listen(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, e := ln.AcceptAuthenticated(ctx); done <- e }()
	cancel()
	select {
	case e := <-done:
		if !errors.Is(e, context.Canceled) {
			t.Fatal(e)
		}
	case <-time.After(time.Second):
		t.Fatal("accept did not unblock")
	}
}

func TestTranscriptAckBindsBothHellos(t *testing.T) {
	k := []byte("01234567890123456789012345678901")
	a := hello{Version: "v", Nonce: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
	b := hello{Version: "v", Nonce: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}
	x := macAck(k, a, b, a.Nonce)
	if x == macAck(k, a, b, b.Nonce) || x == macAck(k, a, hello{Version: "other", Nonce: b.Nonce}, a.Nonce) {
		t.Fatal("ack transcript not bound")
	}
}

func TestPeerHelloRejectsReplayKeyEpochReleaseAndClaims(t *testing.T) {
	key := []byte("01234567890123456789012345678901")
	uid, gid := uint32(42), uint32(24)
	localPin := ReleasePin{ReleaseID: "local", BinaryDigest: digest("a"), SocketDigest: digest("b"), ManifestDigest: digest("c")}
	peerPin := ReleasePin{ReleaseID: "peer", BinaryDigest: digest("d"), SocketDigest: digest("e"), ManifestDigest: digest("f")}
	cfg := Config{Contract: SocketContract{Channel: "c", LocalRole: "a", PeerRole: "b"}, PeerRelease: peerPin}
	local := hello{Nonce: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
	makePeer := func() hello {
		h := hello{Version: ProtocolVersion, Channel: "c", LocalRole: "b", PeerRole: "a", UID: uid, GID: gid, KeyEpoch: 9, Release: peerPin, Nonce: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}
		h.MAC = macHello(key, h)
		return h
	}
	h := makePeer()
	if err := validatePeerHello(cfg, local, h, Peer{UID: uid, GID: gid}, 9, key); err != nil {
		t.Fatal(err)
	}
	h.Nonce = local.Nonce
	h.MAC = macHello(key, h)
	if !errors.Is(validatePeerHello(cfg, local, h, Peer{UID: uid, GID: gid}, 9, key), ErrReplay) {
		t.Fatal("replay accepted")
	}
	h = makePeer()
	h.KeyEpoch = 10
	h.MAC = macHello(key, h)
	if !errors.Is(validatePeerHello(cfg, local, h, Peer{UID: uid, GID: gid}, 9, key), ErrPeer) {
		t.Fatal("epoch mismatch accepted")
	}
	h = makePeer()
	h.Release = localPin
	h.MAC = macHello(key, h)
	if !errors.Is(validatePeerHello(cfg, local, h, Peer{UID: uid, GID: gid}, 9, key), ErrPeer) {
		t.Fatal("asymmetric release pin accepted")
	}
	h = makePeer()
	h.UID++
	h.MAC = macHello(key, h)
	if !errors.Is(validatePeerHello(cfg, local, h, Peer{UID: uid, GID: gid}, 9, key), ErrPeer) {
		t.Fatal("kernel claim mismatch accepted")
	}
	h = makePeer()
	h.MAC = macHello([]byte("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"), h)
	if !errors.Is(validatePeerHello(cfg, local, h, Peer{UID: uid, GID: gid}, 9, key), ErrPeer) {
		t.Fatal("wrong key accepted")
	}
}

func TestContextDeadlineInterruptsSilentHandshake(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	stop, err := startHandshakeDeadline(a, ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	buf := make([]byte, 1)
	if _, err := a.Read(buf); err == nil {
		t.Fatal("silent peer read did not time out")
	}
}
