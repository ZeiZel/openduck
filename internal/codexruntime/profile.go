package codexruntime

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	"openduck/internal/harness"
)

const ProfileV1 = "codex-runtime-profile.v1"

// Profile is intentionally explicit: the generated worker profile contains
// no ambient permissions and cannot be widened by the runtime client.
type Profile struct {
	SchemaVersion     string   `json:"schema_version"`
	ApprovalPolicy    string   `json:"approval_policy"`
	PermissionProfile string   `json:"permission_profile"`
	WorkspaceAccess   string   `json:"workspace_access"`
	NetworkAccess     bool     `json:"network_access"`
	ReadRoots         []string `json:"read_roots"`
	WriteRoots        []string `json:"write_roots"`
	AppsEnabled       bool     `json:"apps_enabled"`
	PluginsEnabled    bool     `json:"plugins_enabled"`
	HooksEnabled      bool     `json:"hooks_enabled"`
	WebEnabled        bool     `json:"web_enabled"`
	MultiAgentEnabled bool     `json:"multi_agent_enabled"`
}

func GenerateProfile(readRoots, writeRoots []string) (Profile, string, error) {
	if e := exactRoots(readRoots); e != nil {
		return Profile{}, "", e
	}
	if e := exactRoots(writeRoots); e != nil {
		return Profile{}, "", e
	}
	for _, write := range writeRoots {
		ok := false
		for _, read := range readRoots {
			if write == read || strings.HasPrefix(write, read+string(filepath.Separator)) {
				ok = true
				break
			}
		}
		if !ok {
			return Profile{}, "", harness.ErrInvalidContract
		}
	}
	p := Profile{
		SchemaVersion: ProfileV1, ApprovalPolicy: "never", PermissionProfile: "codex_worker",
		WorkspaceAccess: "workspace-write", NetworkAccess: false,
		ReadRoots: append([]string(nil), readRoots...), WriteRoots: append([]string(nil), writeRoots...),
	}
	if e := p.Validate(); e != nil {
		return Profile{}, "", e
	}
	d, e := harness.SHA256(p)
	return p, d, e
}

func (p Profile) Validate() error {
	if p.SchemaVersion != ProfileV1 || p.ApprovalPolicy != "never" || p.PermissionProfile != "codex_worker" || p.WorkspaceAccess != "workspace-write" || p.NetworkAccess || p.AppsEnabled || p.PluginsEnabled || p.HooksEnabled || p.WebEnabled || p.MultiAgentEnabled {
		return harness.ErrInvalidContract
	}
	if e := exactRoots(p.ReadRoots); e != nil {
		return e
	}
	return exactRoots(p.WriteRoots)
}

func exactRoots(roots []string) error {
	if roots == nil {
		return errors.New("roots must be explicit")
	}
	seen := map[string]struct{}{}
	for _, root := range roots {
		if root == "" || !filepath.IsAbs(root) || filepath.Clean(root) != root || root == string(filepath.Separator) || broadSystemRoot(root) {
			return harness.ErrInvalidContract
		}
		if info, err := os.Lstat(root); err == nil {
			if info.Mode()&os.ModeSymlink != 0 {
				return harness.ErrInvalidContract
			}
			resolved, err := filepath.EvalSymlinks(root)
			if err != nil || filepath.Clean(resolved) != root {
				return harness.ErrInvalidContract
			}
		}
		if _, ok := seen[root]; ok {
			return harness.ErrInvalidContract
		}
		seen[root] = struct{}{}
	}
	return nil
}

func broadSystemRoot(root string) bool {
	for _, prefix := range []string{"/System", "/Library", "/usr", "/bin", "/sbin", "/private/etc"} {
		if root == prefix || strings.HasPrefix(root, prefix+"/") {
			return true
		}
	}
	return false
}
