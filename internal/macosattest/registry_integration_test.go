package macosattest

import (
	"context"
	"net"
	"openduck/internal/nativemcp"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestHostLaunchedShimBindsLocalPeerCredAndParentChain(t *testing.T) {
	if os.Getenv("OPENDUCK_ATTEST_SHIM_HELPER") == "1" {
		t.Skip("helper")
	}
	host, err := SampleProcess(os.Getpid())
	if err != nil {
		t.Skip("platform unavailable")
	}
	dir, err := os.MkdirTemp("/tmp", "oda-")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "shim.sock")
	t.Cleanup(func() { _ = os.Remove(path); _ = os.Remove(dir) })
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	cmd := exec.Command(os.Args[0], "-test.run=TestAttestorShimHelper")
	cmd.Env = append(os.Environ(), "OPENDUCK_ATTEST_SHIM_HELPER=1", "OPENDUCK_ATTEST_SHIM_SOCKET="+path)
	gate, _ := cmd.StdinPipe()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = gate.Close(); _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	shim, err := SampleProcess(cmd.Process.Pid)
	if err != nil {
		t.Fatal(err)
	}
	r := NewHostRegistry(func() time.Time { return time.Unix(100, 0).UTC() })
	reg := HostRegistration{Provider: "codex", PeerID: "peer", SessionID: "ui", ChannelID: "channel", ProfileID: "profile", RevisionID: "revision", Host: host, ShimImageIdentity: shim.ImageIdentity(), ShimUID: shim.UID, ShimGID: shim.GID, ExpiresAt: time.Unix(200, 0).UTC()}
	if err := r.Register(reg); err != nil {
		t.Skip("kernel registration unavailable")
	}
	if _, err := gate.Write([]byte{1}); err != nil {
		t.Fatal(err)
	}
	conn, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	peer, err := r.PeerFor(context.Background(), conn)
	if err != nil || peer.Provider != "codex" || peer.PeerID != "peer" {
		t.Fatalf("peer rejected: %+v %v", peer, err)
	}
	identity, err := r.RegistrationFor(peer)
	if err != nil || identity.Provider != "codex" || identity.ProfileID != "profile" || identity.SessionID != "ui" || identity.ChannelID != "channel" || identity.RevisionID != "revision" {
		t.Fatalf("bounded session identity unavailable: %+v %v", identity, err)
	}
	contract := nativemcp.SessionContract{Provider: "codex", PeerID: "peer", UISessionID: "ui", ProfileID: "profile", RevisionID: "revision"}
	if err := r.VerifyNativeMCPPeer(context.Background(), contract, peer); err != nil {
		t.Fatal(err)
	}
	reg.Provider = "claude"
	if err := r.VerifyNativeMCPPeer(context.Background(), contract, nativemcp.PeerIdentity{Provider: "claude", PeerID: "peer"}); err == nil {
		t.Fatal("provider substitution accepted")
	}
}

func TestAttestorShimHelper(t *testing.T) {
	if os.Getenv("OPENDUCK_ATTEST_SHIM_HELPER") != "1" {
		return
	}
	var gate [1]byte
	if _, err := os.Stdin.Read(gate[:]); err != nil {
		os.Exit(3)
	}
	conn, err := net.Dial("unix", os.Getenv("OPENDUCK_ATTEST_SHIM_SOCKET"))
	if err != nil {
		os.Exit(4)
	}
	defer conn.Close()
	_, _ = os.Stdin.Read(gate[:])
	os.Exit(0)
}
