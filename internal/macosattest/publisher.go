package macosattest

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

var publisherNow = time.Now

type NativePackagePublish struct {
	Parent, PackageLeaf, InstalledHelper string
	Provider                             string
	UID, GID                             int
	Receipt, Projection                  []byte
	ProjectionKey                        []byte
	ReceiptKey                           []byte
}

// PublishNativePackage is the sole privileged filesystem publisher for native
// plugin packages. Inputs are descriptor-relative, staged privately under the
// trusted parent, fsynced, and published with renameatx_np(RENAME_EXCL).
func PublishNativePackage(c NativePackagePublish) error {
	if c.UID != 0 || !filepath.IsAbs(c.Parent) || filepath.Base(c.PackageLeaf) != c.PackageLeaf || c.PackageLeaf == "." || !trustedPackageAncestry(c.Parent) || !trustedExecutablePath(c.InstalledHelper) || len(c.Receipt) == 0 || len(c.Projection) == 0 {
		return ErrUnavailable
	}
	now := publisherNow().UTC()
	projection, err := DecodeLifecycleProjection(c.Projection)
	if err != nil || len(c.ProjectionKey) != 32 || !bytes.Equal(c.ReceiptKey, c.ProjectionKey) || projection.Verify(c.ProjectionKey, now) != nil {
		return ErrUnavailable
	}
	receipt, err := VerifyNativeReceiptChain(c.Receipt, ed25519.PublicKey(c.ReceiptKey), projection, now)
	if err != nil || stringValue(receipt, "provider") != c.Provider || stringValue(receipt, "action") != "enable" || stringValue(receipt, "package_id") != "openduck-mesh" {
		return ErrUnavailable
	}
	parent, err := os.OpenRoot(c.Parent)
	if err != nil {
		return ErrUnavailable
	}
	defer parent.Close()
	stageLeaf := "." + c.PackageLeaf + ".staging"
	if err = parent.Mkdir(stageLeaf, 0700); err != nil {
		return ErrUnavailable
	}
	published := false
	defer func() {
		if !published {
			_ = parent.RemoveAll(stageLeaf)
		}
	}()
	stage, err := parent.OpenRoot(stageLeaf)
	if err != nil {
		return ErrUnavailable
	}
	defer stage.Close()
	files, err := canonicalNativePackageFiles(receipt)
	if err != nil {
		return ErrUnavailable
	}
	packageDigest := nativePackageDigest(files, projection.ShimArtifactDigest)
	if stringValue(receipt, "package_digest") != packageDigest {
		return ErrUnavailable
	}
	files["openduck.lifecycle.receipt.json"] = append([]byte(nil), c.Receipt...)
	files["openduck.lifecycle.projection.json"] = append([]byte(nil), c.Projection...)
	if c.Provider == "kimi" {
		helper, readErr := os.ReadFile(c.InstalledHelper)
		if readErr != nil || "sha256:"+digestBytes(helper) != projection.ShimArtifactDigest {
			return ErrUnavailable
		}
		files["bin/openduck-native-mcp"] = helper
	}
	paths := make([]string, 0, len(files))
	for path := range files {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	inventory := sha256.New()
	for _, path := range paths {
		if !safePublishRelative(path) {
			return ErrUnavailable
		}
		if err = mkdirParents(stage, filepath.Join(c.Parent, stageLeaf), filepath.Dir(path), c.UID, c.GID); err != nil {
			return ErrUnavailable
		}
		mode := os.FileMode(0440)
		if path == "bin/openduck-native-mcp" {
			mode = 0550
		}
		f, openErr := stage.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
		if openErr != nil {
			return ErrUnavailable
		}
		if _, err = f.Write(files[path]); err == nil {
			err = f.Sync()
		}
		if err == nil {
			err = f.Chown(c.UID, c.GID)
		}
		if err == nil {
			err = f.Chmod(mode)
		}
		closeErr := f.Close()
		if err != nil || closeErr != nil {
			return ErrUnavailable
		}
		inventory.Write([]byte(path))
		inventory.Write([]byte{0})
		inventory.Write([]byte(digestBytes(files[path])))
	}
	marker, _ := json.Marshal(struct {
		Schema          string `json:"schema"`
		Provider        string `json:"provider"`
		InventoryDigest string `json:"inventory_digest"`
		PackageDigest   string `json:"package_digest"`
		ReceiptDigest   string `json:"receipt_digest"`
	}{"openduck.native-package-commit.v1", c.Provider, "sha256:" + hex.EncodeToString(inventory.Sum(nil)), packageDigest, stringValue(receipt, "receipt_digest")})
	f, err := stage.OpenFile(".openduck-commit.json", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0440)
	if err != nil {
		return ErrUnavailable
	}
	if _, err = f.Write(marker); err == nil {
		err = f.Sync()
	}
	if err == nil {
		err = f.Chown(c.UID, c.GID)
	}
	if err == nil {
		err = f.Chmod(0440)
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	stageHandle, stageErr := stage.Open(".")
	if stageErr == nil {
		stageErr = stageHandle.Chown(c.UID, c.GID)
	}
	if stageErr == nil {
		stageErr = stageHandle.Chmod(0750)
	}
	if stageHandle != nil {
		_ = stageHandle.Close()
	}
	if err != nil || stageErr != nil {
		return ErrUnavailable
	}
	if renameNoReplace(filepath.Join(c.Parent, stageLeaf), filepath.Join(c.Parent, c.PackageLeaf)) != nil {
		return ErrUnavailable
	}
	packageRoot, openErr := os.OpenRoot(filepath.Join(c.Parent, c.PackageLeaf))
	if openErr != nil {
		return ErrUnavailable
	}
	defer packageRoot.Close()
	authorityCommitted := false
	defer func() {
		if !authorityCommitted {
			_ = parent.Remove(filepath.Join(c.PackageLeaf, ".openduck-commit.json"))
		}
	}()
	for _, path := range paths {
		body, readErr := packageRoot.ReadFile(path)
		info, statErr := packageRoot.Lstat(path)
		st, owned := infoSys(info)
		if readErr != nil || statErr != nil || !owned || st.Uid != uint32(c.UID) || st.Gid != uint32(c.GID) || digestBytes(body) != digestBytes(files[path]) {
			return ErrUnavailable
		}
	}
	commitBody, commitErr := packageRoot.ReadFile(".openduck-commit.json")
	if commitErr != nil || !json.Valid(commitBody) || !bytes.Equal(commitBody, marker) {
		return ErrUnavailable
	}
	if VerifyNativePackageCommit(filepath.Join(c.Parent, c.PackageLeaf), c.Provider, packageDigest, stringValue(receipt, "receipt_digest"), uint32(c.GID)) != nil {
		return ErrUnavailable
	}
	authorityCommitted = true
	published = true
	return nil
}

func digestBytes(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }
func validDigest(s string) bool {
	if len(s) != 64 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil && strings.ToLower(s) == s
}

func VerifyNativePackageCommit(root, provider, packageDigest, receiptDigest string, gid uint32) error {
	if !filepath.IsAbs(root) || provider == "" || !validDigest(packageDigest) || !validDigest(receiptDigest) || !trustedPackageAncestry(root) {
		return ErrUnavailable
	}
	rootInfo, err := os.Lstat(root)
	rootStat, ok := infoSys(rootInfo)
	if err != nil || !ok || !rootInfo.IsDir() || rootInfo.Mode().Perm() != 0750 || rootStat.Uid != 0 || rootStat.Gid != gid {
		return ErrUnavailable
	}
	r, err := os.OpenRoot(root)
	if err != nil {
		return ErrUnavailable
	}
	defer r.Close()
	files := map[string][]byte{}
	if err = collectCommittedFiles(r, ".", gid, files); err != nil {
		return err
	}
	raw, present := files[".openduck-commit.json"]
	if !present {
		return ErrUnavailable
	}
	delete(files, ".openduck-commit.json")
	var m struct {
		Schema          string `json:"schema"`
		Provider        string `json:"provider"`
		InventoryDigest string `json:"inventory_digest"`
		PackageDigest   string `json:"package_digest"`
		ReceiptDigest   string `json:"receipt_digest"`
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&m) != nil || d.Decode(&struct{}{}) != io.EOF || m.Schema != "openduck.native-package-commit.v1" || m.Provider != provider || m.PackageDigest != packageDigest || m.ReceiptDigest != receiptDigest || len(m.InventoryDigest) != 71 || !strings.HasPrefix(m.InventoryDigest, "sha256:") || !validDigest(strings.TrimPrefix(m.InventoryDigest, "sha256:")) {
		return ErrUnavailable
	}
	paths := make([]string, 0, len(files))
	for p := range files {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	h := sha256.New()
	for _, p := range paths {
		h.Write([]byte(p))
		h.Write([]byte{0})
		h.Write([]byte(digestBytes(files[p])))
	}
	if m.InventoryDigest != "sha256:"+hex.EncodeToString(h.Sum(nil)) {
		return ErrUnavailable
	}
	var projection LifecycleProjection
	if json.Unmarshal(files["openduck.lifecycle.projection.json"], &projection) != nil {
		return ErrUnavailable
	}
	if nativePackageDigest(files, projection.ShimArtifactDigest) != packageDigest {
		return ErrUnavailable
	}
	return nil
}

func trustedPackageAncestry(path string) bool {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return false
	}
	current := string(filepath.Separator)
	for _, part := range strings.Split(strings.TrimPrefix(path, string(filepath.Separator)), string(filepath.Separator)) {
		if part == "" || part == "." || part == ".." {
			return false
		}
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		st, ok := infoSys(info)
		if err != nil || !ok || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || st.Uid != 0 || info.Mode().Perm()&0022 != 0 {
			return false
		}
	}
	return true
}

func collectCommittedFiles(root *os.Root, dir string, gid uint32, out map[string][]byte) error {
	h, err := root.Open(dir)
	if err != nil {
		return ErrUnavailable
	}
	entries, err := h.ReadDir(-1)
	_ = h.Close()
	if err != nil {
		return ErrUnavailable
	}
	for _, entry := range entries {
		path := entry.Name()
		if dir != "." {
			path = filepath.Join(dir, path)
		}
		info, err := root.Lstat(path)
		st, ok := infoSys(info)
		if err != nil || !ok || st.Uid != 0 || st.Gid != gid || info.Mode()&(os.ModeSymlink|os.ModeSetuid|os.ModeSetgid|os.ModeSticky|os.ModeDevice|os.ModeNamedPipe|os.ModeSocket) != 0 || info.Mode().Perm()&0022 != 0 {
			return ErrUnavailable
		}
		if info.IsDir() {
			if info.Mode().Perm() != 0750 || collectCommittedFiles(root, path, gid, out) != nil {
				return ErrUnavailable
			}
			continue
		}
		if !info.Mode().IsRegular() || (path == "bin/openduck-native-mcp" && info.Mode().Perm() != 0550) || (path != "bin/openduck-native-mcp" && info.Mode().Perm() != 0440) {
			return ErrUnavailable
		}
		body, err := root.ReadFile(path)
		if err != nil {
			return ErrUnavailable
		}
		out[path] = body
	}
	return nil
}

func nativePackageDigest(files map[string][]byte, shimDigest string) string {
	paths := make([]string, 0, len(files))
	for p := range files {
		if p != "openduck.lifecycle.receipt.json" && p != "openduck.lifecycle.projection.json" && p != "bin/openduck-native-mcp" && p != ".openduck-commit.json" {
			paths = append(paths, p)
		}
	}
	_, helperPresent := files["bin/openduck-native-mcp"]
	_, kimiPackage := files["kimi.plugin.json"]
	if helperPresent || kimiPackage {
		paths = append(paths, "bin/openduck-native-mcp")
	}
	sort.Strings(paths)
	rows := make([]any, 0, len(paths))
	for _, p := range paths {
		digest := digestBytes(files[p])
		if p == "bin/openduck-native-mcp" {
			digest = strings.TrimPrefix(shimDigest, "sha256:")
		}
		rows = append(rows, map[string]any{"path": p, "sha256": digest})
	}
	raw, _ := canonicalJSON(rows)
	return digestBytes(raw)
}
func canonicalNativePackageFiles(r map[string]any) (map[string][]byte, error) {
	provider := stringValue(r, "provider")
	command := "/Library/Application Support/OpenDuck/.openduck-native-mcp"
	manifest := ""
	if provider == "kimi" {
		command = "./bin/openduck-native-mcp"
		manifest = "kimi.plugin.json"
	} else if provider == "qwen" {
		manifest = "qwen-extension.json"
	} else if provider == "codex" {
		manifest = ".codex-plugin/plugin.json"
	} else if provider == "claude" {
		manifest = ".claude-plugin/plugin.json"
	} else {
		return nil, ErrUnavailable
	}
	server := map[string]any{"command": command, "args": []any{}}
	common := map[string]any{"name": "openduck-mesh", "version": "0.1.0", "description": "Controller-authenticated OpenDuck child-session operations.", "author": map[string]any{"name": "OpenDuck"}}
	if provider == "qwen" || provider == "kimi" {
		common["mcpServers"] = map[string]any{"openduck-mesh": server}
	} else if provider == "codex" {
		common["mcpServers"] = "./.mcp.json"
		common["interface"] = map[string]any{"displayName": "OpenDuck Mesh", "shortDescription": "Authenticated child sessions", "longDescription": "Child-session operations are authorized and relayed exclusively by OpenDuck Controller.", "developerName": "OpenDuck", "category": "Developer Tools", "capabilities": []any{}, "defaultPrompt": []any{}}
	}
	manifestRaw, _ := canonicalJSON(common)
	files := map[string][]byte{manifest: append(manifestRaw, '\n')}
	if provider == "codex" || provider == "claude" {
		m, _ := canonicalJSON(map[string]any{"mcpServers": map[string]any{"openduck-mesh": server}})
		files[".mcp.json"] = append(m, '\n')
	}
	descriptor := map[string]any{
		"schema_version": "openduck-native-package.v1", "provider": provider, "profile_id": stringValue(r, "profile_id"), "profile_revision": stringValue(r, "profile_revision"), "package_id": stringValue(r, "package_id"),
		"controller":   map[string]any{"audience": "mesh", "binding_id": r["controller_binding_id"], "endpoint_id": r["endpoint_id"], "generation": r["endpoint_generation"], "expires_at": r["endpoint_expires_at"], "association_digest": r["association_digest"], "ui_session_id": r["ui_session_id"], "ui_channel_id": r["ui_channel_id"], "root_run_id": r["root_run_id"], "run_id": r["run_id"], "mesh_session_id": r["mesh_session_id"]},
		"lifecycle":    map[string]any{"projection_digest": r["native_lifecycle_projection_digest"], "release_id": r["native_release_id"], "release_digest": r["native_release_digest"], "manifest_digest": r["native_manifest_digest"], "shim_artifact_digest": r["native_shim_artifact_digest"], "socket_generation": r["native_socket_generation"], "socket_identity_digest": r["native_socket_identity_digest"], "host_catalog_generation": r["native_host_catalog_generation"], "provider_topology_digest": r["native_provider_topology_digest"], "host_artifact_digest": r["native_host_artifact_digest"], "host_team_id": r["native_host_team_id"], "host_image_identity": r["native_host_image_identity"], "expires_at": r["native_lifecycle_expires_at"]},
		"capabilities": r["capabilities"], "capability_digest": r["capability_digest"],
	}
	d, _ := canonicalJSON(descriptor)
	files["openduck.controller-tools.json"] = append(d, '\n')
	return files, nil
}
func safePublishRelative(p string) bool {
	return p != "" && !filepath.IsAbs(p) && filepath.Clean(p) == p && p != "." && p != ".." && !strings.HasPrefix(p, "../")
}
func mkdirParents(root *os.Root, _ string, dir string, uid, gid int) error {
	if dir == "." {
		return nil
	}
	current := ""
	for _, part := range strings.Split(dir, string(filepath.Separator)) {
		if part == "" || part == "." || part == ".." {
			return ErrUnavailable
		}
		if current == "" {
			current = part
		} else {
			current = filepath.Join(current, part)
		}
		if err := root.Mkdir(current, 0750); err != nil && !errors.Is(err, os.ErrExist) {
			return err
		}
		h, openErr := root.Open(current)
		if openErr != nil {
			return ErrUnavailable
		}
		handleErr := h.Chown(uid, gid)
		if handleErr == nil {
			handleErr = h.Chmod(0750)
		}
		_ = h.Close()
		if handleErr != nil {
			return ErrUnavailable
		}
	}
	return nil
}
