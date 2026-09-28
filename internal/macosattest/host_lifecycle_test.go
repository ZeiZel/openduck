package macosattest

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestLaunchOfficialHostRegistersAndStopRevokes(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("Darwin kernel identity contract")
	}
	probe, err := SampleProcess(os.Getpid())
	if err != nil {
		t.Skipf("process identity unavailable: %v", err)
	}
	fixture := exec.Command("/usr/bin/sleep", "30")
	if err := fixture.Start(); err != nil {
		t.Skipf("fixture image unavailable: %v", err)
	}
	fixtureProcess, err := SampleProcess(fixture.Process.Pid)
	_ = fixture.Process.Kill()
	_ = fixture.Wait()
	if err != nil {
		t.Skipf("fixture image unavailable: %v", err)
	}
	image := fixtureProcess.ImageIdentity()
	registry := NewHostRegistry(time.Now)
	identity := []byte(fmt.Sprintf(`{"schema":"openduck.provider-host-identity.v1","provider":"codex","team_id":"test-team","artifact_digest":"%s","image_identity":"%s"}`, digestFile("/usr/bin/sleep"), image))
	p, err := LaunchOfficialHost(context.Background(), registry, identity, HostLaunchSpec{
		Executable: "/usr/bin/sleep",
		Provider:   "codex", PeerID: "peer", SessionID: "session", ChannelID: "ui-channel", ProfileID: "profile", RevisionID: "revision",
		ShimImageIdentity: "sha256:shim", HostUID: probe.UID, HostGID: probe.GID, ShimUID: probe.UID, ShimGID: probe.GID,
		ExpiresAt: time.Now().Add(time.Minute), Args: []string{"30"},
	})
	if err != nil {
		t.Fatalf("launch: %v", err)
	}
	registry.mu.RLock()
	_, registered := registry.byHost[p.pid]
	registry.mu.RUnlock()
	if !registered {
		t.Fatal("host was not registered before launch returned")
	}
	if err := p.Stop(); err != nil {
		t.Fatal(err)
	}
	registry.mu.RLock()
	_, registered = registry.byHost[p.pid]
	registry.mu.RUnlock()
	if registered {
		t.Fatal("stopped host registration remained live")
	}
}

func TestLaunchOfficialHostRejectsWritableOrSubstitutedPath(t *testing.T) {
	path := t.TempDir() + "/host"
	if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 0\n"), 0755); err != nil {
		t.Fatal(err)
	}
	if trustedExecutablePath(path) {
		t.Fatal("user-owned executable path trusted")
	}
}

func TestQwenClosureRejectsUserOwnedAndManifestSubstitution(t *testing.T) {
	root := t.TempDir()
	manifest := root + "/qwen-closure.sha256"
	if err := os.MkdirAll(root+"/node/bin", 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(root+"/node/bin/node", []byte("not-authoritative"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manifest, []byte("00\t755\tnode/bin/node\n"), 0440); err != nil {
		t.Fatal(err)
	}
	if VerifyQwenClosure(root, manifest, "sha256:"+strings.Repeat("0", 64), uint32(os.Getuid()), uint32(os.Getgid())) == nil {
		t.Fatal("user-owned/substituted closure accepted")
	}
}
