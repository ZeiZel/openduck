package codexbroker

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"

	"openduck/internal/macoschannel"
)

func e2eDigest(v []byte) string { d := sha256.Sum256(v); return hex.EncodeToString(d[:]) }

func e2eRelease(t *testing.T, id, socketDigest string) (*os.Root, macoschannel.ReleasePin) {
	t.Helper()
	d := t.TempDir()
	if runtime.GOOS == "darwin" {
		d, _ = os.MkdirTemp("/private/tmp", "od-broker-release-")
		t.Cleanup(func() { _ = os.RemoveAll(d) })
	}
	_ = os.Chmod(d, 0700)
	bin := []byte("codex-runtime-" + id)
	if err := os.WriteFile(filepath.Join(d, "bin"), bin, 0700); err != nil {
		t.Fatal(err)
	}
	p := macoschannel.ReleasePin{ReleaseID: id, BinaryDigest: e2eDigest(bin), SocketDigest: socketDigest}
	manifest := fmt.Sprintf(`{"release_id":%q,"binary":"bin","socket":"channel.sock","binary_digest":%q,"socket_digest":%q}`, id, p.BinaryDigest, p.SocketDigest)
	p.ManifestDigest = e2eDigest([]byte(manifest))
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

func TestAuthenticatedSocketTransportBinder(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("Darwin kernel credentials required")
	}
	root, err := os.MkdirTemp("/private/tmp", "od-broker-channel-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	_ = os.Chmod(root, 0700)
	uid, gid := uint32(os.Geteuid()), uint32(os.Getegid())
	st, _ := os.Lstat(root)
	rootStat := st.Sys().(*syscall.Stat_t)
	sd := e2eSocketDigest("channel.sock", uid, uint32(rootStat.Gid), 0660)
	brokerRoot, brokerRelease := e2eRelease(t, "broker", sd)
	controllerRoot, controllerRelease := e2eRelease(t, "controller", sd)
	newCfg := func(localRoot *os.Root, local, peer macoschannel.ReleasePin, localRole, peerRole string) macoschannel.Config {
		fd, err := os.OpenRoot(root)
		if err != nil {
			t.Fatal(err)
		}
		lf, err := localRoot.Lstat(".")
		if err != nil {
			t.Fatal(err)
		}
		ls := lf.Sys().(*syscall.Stat_t)
		return macoschannel.Config{Contract: macoschannel.SocketContract{Channel: "codex-control", LocalRole: localRole, PeerRole: peerRole, SocketRoot: root, SocketPath: "channel.sock", ExpectedPeerUID: &uid, ExpectedPeerGID: &gid, ExpectedSocketRootUID: uint32(rootStat.Uid), ExpectedSocketRootGID: uint32(rootStat.Gid), ExpectedSocketRootMode: 0700, ExpectedSocketUID: uid, ExpectedSocketGID: uint32(rootStat.Gid), ExpectedSocketMode: 0660}, LocalRelease: local, PeerRelease: peer, ReleaseRoot: localRoot, SocketRootFD: fd, BinaryName: "bin", KeySource: e2eKeys{}, ExpectedReleaseRootUID: uint32(ls.Uid), ExpectedReleaseRootGID: uint32(ls.Gid), ExpectedReleaseRootMode: 0700, ExpectedManifestMode: 0600, ExpectedBinaryMode: 0700}
	}
	serverCfg := newCfg(brokerRoot, brokerRelease, controllerRelease, "broker", "controller")
	clientCfg := newCfg(controllerRoot, controllerRelease, brokerRelease, "controller", "broker")
	ln, err := macoschannel.Listen(serverCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	type accepted struct {
		c   macoschannel.Conn
		err error
	}
	accept := make(chan accepted, 1)
	go func() { c, e := ln.AcceptAuthenticated(context.Background()); accept <- accepted{c, e} }()
	clientConn, err := macoschannel.Dial(context.Background(), clientCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer clientConn.Close()
	acceptedResult := <-accept
	if acceptedResult.err != nil {
		t.Fatal(acceptedResult.err)
	}
	serverConn := acceptedResult.c
	if serverConn == nil {
		t.Fatal("server connection missing")
	}
	defer serverConn.Close()
	bev, cev := serverConn.Evidence(), clientConn.Evidence()
	if cev.BindingDigest != bev.BindingDigest {
		t.Fatal("binding mismatch")
	}
	payload := []byte(`{"op":"production-binder"}`)
	tag, err := clientConn.Seal("codexbroker.frame.v1", payload)
	if err != nil {
		t.Fatal(err)
	}
	if err := serverConn.Verify("codexbroker.frame.v1", payload, tag); err != nil {
		t.Fatal(err)
	}
	if err := clientConn.Verify("codexbroker.frame.v1", payload, tag); err == nil {
		t.Fatal("outbound tag accepted in wrong direction")
	}
}

type e2eKeys struct{}

func (e2eKeys) Load(string) ([]byte, uint64, error) {
	return []byte("01234567890123456789012345678901"), 7, nil
}
func (e2eKeys) LoadContext(context.Context, string) ([]byte, uint64, error) {
	return []byte("01234567890123456789012345678901"), 7, nil
}
func e2eSocketDigest(name string, uid, gid uint32, mode os.FileMode) string {
	h := sha256.New()
	_, _ = h.Write([]byte(name))
	_, _ = h.Write([]byte{0})
	var m [4]byte
	binary.BigEndian.PutUint32(m[:], uint32(mode.Perm()))
	_, _ = h.Write(m[:])
	var ids [8]byte
	binary.BigEndian.PutUint32(ids[:4], uid)
	binary.BigEndian.PutUint32(ids[4:], gid)
	_, _ = h.Write(ids[:])
	return hex.EncodeToString(h.Sum(nil))
}
