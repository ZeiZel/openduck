package macosattest

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"openduck/internal/qwenclosure"
	"openduck/internal/releasecatalog"
)

// HostLaunchSpec is server-side lifecycle state. Args must be a closed,
// release-defined vector: session/profile identifiers and credentials are
// deliberately absent from argv and the environment.
type HostLaunchSpec struct {
	Executable                                                    string
	hostIdentity                                                  releasecatalog.ProviderHostIdentity
	Provider, PeerID, SessionID, ChannelID, ProfileID, RevisionID string
	ShimImageIdentity                                             string
	HostUID, HostGID, ShimUID, ShimGID                            uint32
	ExpiresAt                                                     time.Time
	Args                                                          []string
	ClosureRoot, ClosureManifest, ExpectedClosureManifestDigest   string
}

type HostProcess struct {
	mu       sync.Mutex
	cmd      *exec.Cmd
	registry *HostRegistry
	pid      int
	stopped  bool
}

// LaunchOfficialHost starts an exact root-owned executable, samples the
// executing Mach-O identity from the kernel, then registers the PID before a
// host-launched native MCP shim can be admitted. Registration is revoked on
// exit, cancellation and Stop. It never inherits an ambient environment.
func LaunchOfficialHost(ctx context.Context, registry *HostRegistry, hostIdentityRaw []byte, spec HostLaunchSpec) (*HostProcess, error) {
	identity, identityErr := releasecatalog.DecodeProviderHostIdentity(hostIdentityRaw)
	spec.hostIdentity = identity
	if identityErr != nil || ctx == nil || registry == nil || !filepath.IsAbs(spec.Executable) || identity.Provider != spec.Provider || identity.TeamID == "" || identity.ImageIdentity == "" || identity.ArtifactDigest != digestFile(spec.Executable) || spec.Provider == "" || spec.PeerID == "" || spec.SessionID == "" || spec.ChannelID == "" || spec.ProfileID == "" || spec.RevisionID == "" || spec.ShimImageIdentity == "" || !time.Now().UTC().Before(spec.ExpiresAt) || !trustedExecutablePath(spec.Executable) || (spec.Provider == "qwen" && VerifyQwenClosure(spec.ClosureRoot, spec.ClosureManifest, spec.ExpectedClosureManifestDigest, spec.HostUID, spec.HostGID) != nil) {
		return nil, ErrUnavailable
	}
	cmd := exec.CommandContext(ctx, spec.Executable, append([]string(nil), spec.Args...)...)
	cmd.Env = []string{"PATH=/usr/bin:/bin"}
	cmd.Stdin, cmd.Stdout, cmd.Stderr = nil, nil, nil
	if err := cmd.Start(); err != nil {
		return nil, ErrUnavailable
	}
	host, err := SampleProcess(cmd.Process.Pid)
	if err != nil || host.UID != spec.HostUID || host.GID != spec.HostGID || host.ImageIdentity() != identity.ImageIdentity || identity.ArtifactDigest != digestFile(spec.Executable) || (spec.Provider == "qwen" && VerifyQwenClosure(spec.ClosureRoot, spec.ClosureManifest, spec.ExpectedClosureManifestDigest, spec.HostUID, spec.HostGID) != nil) {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return nil, ErrUnavailable
	}
	reg := HostRegistration{Provider: spec.Provider, PeerID: spec.PeerID, SessionID: spec.SessionID, ChannelID: spec.ChannelID, ProfileID: spec.ProfileID, RevisionID: spec.RevisionID, Host: host, ShimImageIdentity: spec.ShimImageIdentity, ShimUID: spec.ShimUID, ShimGID: spec.ShimGID, ExpiresAt: spec.ExpiresAt}
	if err := registry.Register(reg); err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return nil, err
	}
	p := &HostProcess{cmd: cmd, registry: registry, pid: host.PID}
	go func() { _ = cmd.Wait(); registry.Revoke(host.PID) }()
	return p, nil
}

func digestFile(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	h := sha256.New()
	if _, err = io.Copy(h, f); err != nil {
		return ""
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}

func (p *HostProcess) Stop() error {
	if p == nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.stopped {
		return nil
	}
	p.stopped = true
	p.registry.Revoke(p.pid)
	if p.cmd == nil || p.cmd.Process == nil {
		return nil
	}
	err := p.cmd.Process.Kill()
	if errors.Is(err, os.ErrProcessDone) {
		return nil
	}
	return err
}

// VerifyQwenClosure binds the private Node image to every regular runtime file
// in the root-owned extracted official distribution. The signed release binds
// the manifest digest; extra, missing, writable, linked, or changed files fail.
func VerifyQwenClosure(root, manifestPath, expectedManifestDigest string, expectedUID, expectedGID uint32) error {
	if !filepath.IsAbs(root) || !filepath.IsAbs(manifestPath) || !trustedTreePath(root) || !trustedRegularPath(manifestPath) || !trustedExecutablePath(filepath.Join(root, "node/bin/node")) {
		return ErrUnavailable
	}
	raw, err := os.ReadFile(manifestPath)
	if err != nil || len(raw) == 0 || len(raw) > 2<<20 {
		return ErrUnavailable
	}
	sum := sha256.Sum256(raw)
	if expectedManifestDigest != "sha256:"+hex.EncodeToString(sum[:]) {
		return ErrUnavailable
	}
	manifest, decodeErr := qwenclosure.Decode(raw)
	if decodeErr != nil {
		return ErrUnavailable
	}
	expected := make(map[string]qwenclosure.Entry, len(manifest.Entries))
	expectedDirectories := map[string]bool{}
	for _, entry := range manifest.Entries {
		expected[entry.Path] = entry
		for directory := filepath.ToSlash(filepath.Dir(entry.Path)); directory != "."; directory = filepath.ToSlash(filepath.Dir(directory)) {
			expectedDirectories[directory] = true
		}
	}
	seen := 0
	err = filepath.Walk(root, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil || info == nil {
			return ErrUnavailable
		}
		st, owned := info.Sys().(*syscall.Stat_t)
		if info.Mode()&os.ModeSymlink != 0 || !owned || st.Uid != expectedUID || st.Gid != expectedGID || info.Mode().Perm()&0022 != 0 || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
			return ErrUnavailable
		}
		if info.IsDir() {
			if path == root {
				return nil
			}
			rel, relErr := filepath.Rel(root, path)
			if relErr != nil || !expectedDirectories[filepath.ToSlash(rel)] {
				return ErrUnavailable
			}
			return nil
		}
		if !info.Mode().IsRegular() {
			return ErrUnavailable
		}
		rel, relErr := filepath.Rel(root, path)
		body, readErr := os.ReadFile(path)
		fileSum := sha256.Sum256(body)
		entry, known := expected[filepath.ToSlash(rel)]
		if relErr != nil || readErr != nil || !known || entry.Digest != "sha256:"+hex.EncodeToString(fileSum[:]) || entry.Size != info.Size() || entry.Mode != fmt.Sprintf("%04o", info.Mode().Perm()) {
			return ErrUnavailable
		}
		seen++
		return nil
	})
	if err != nil || seen != len(expected) {
		return ErrUnavailable
	}
	return nil
}

func trustedTreePath(path string) bool {
	info, err := os.Lstat(path)
	st, ok := infoSys(info)
	return err == nil && ok && st.Uid == 0 && info.IsDir() && info.Mode()&os.ModeSymlink == 0 && info.Mode().Perm()&0022 == 0
}

func trustedRegularPath(path string) bool {
	info, err := os.Lstat(path)
	st, ok := infoSys(info)
	return err == nil && ok && st.Uid == 0 && info.Mode().IsRegular() && info.Mode().Perm()&0022 == 0
}

func infoSys(info os.FileInfo) (*syscall.Stat_t, bool) {
	if info == nil {
		return nil, false
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	return st, ok && st != nil
}

func trustedExecutablePath(path string) bool {
	clean := filepath.Clean(path)
	if clean != path {
		return false
	}
	for current := clean; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0022 != 0 {
			return false
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || st.Uid != 0 {
			return false
		}
		if current == "/" {
			break
		}
	}
	info, err := os.Lstat(clean)
	return err == nil && info.Mode().IsRegular() && info.Mode().Perm()&0111 != 0
}
