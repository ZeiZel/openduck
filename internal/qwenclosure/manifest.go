// Package qwenclosure validates and materializes the fixed Qwen Code closure.
// It owns the archive grammar so importer, catalog packaging and privileged
// activation cannot drift onto different interpretations of the signed input.
package qwenclosure

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"golang.org/x/text/cases"
	"golang.org/x/text/unicode/norm"
)

const SchemaV1 = "openduck.qwen-closure-manifest.v1"
const PinnedArchiveDigest = "sha256:c1909e12b7c8bd9abe669c09487fdf65ef8b2d60cc04755fead0dd8ee0ce4152"
const FileCount = 5790

const (
	maxManifestBytes = 2 << 20
	maxArchiveBytes  = 128 << 20
	maxEntries       = 6000
	maxTotalBytes    = 512 << 20
)

var ErrInvalid = errors.New("qwen closure: invalid manifest")

// Policy is explicit only for small deterministic unit fixtures. Production
// callers use Decode/Validate/BuildArchive, which always pin the archive.
type Policy struct {
	ArchiveDigest string
	FileCount     int
}

func ProductionPolicy() Policy {
	return Policy{ArchiveDigest: PinnedArchiveDigest, FileCount: FileCount}
}
func (p Policy) valid() bool {
	return validDigest(p.ArchiveDigest) && p.FileCount > 0 && p.FileCount <= maxEntries
}

type Entry struct {
	Path   string `json:"path"`
	Type   string `json:"type"`
	Mode   string `json:"mode"`
	Size   int64  `json:"size"`
	Digest string `json:"digest"`
}
type Manifest struct {
	SchemaVersion      string  `json:"schema_version"`
	ArchiveDigest      string  `json:"archive_digest"`
	NodePath           string  `json:"node_path"`
	NodeDigest         string  `json:"node_digest"`
	NodeCDHash         string  `json:"node_cdhash"`
	NodeTeamID         string  `json:"node_team_id"`
	HostIdentityDigest string  `json:"host_identity_digest"`
	Entries            []Entry `json:"entries"`
	InventoryDigest    string  `json:"inventory_digest"`
}

func Decode(raw []byte) (Manifest, error) { return DecodeWithPolicy(raw, ProductionPolicy()) }
func DecodeWithPolicy(raw []byte, policy Policy) (Manifest, error) {
	if len(raw) == 0 || len(raw) > maxManifestBytes || !json.Valid(raw) || !policy.valid() {
		return Manifest{}, ErrInvalid
	}
	var m Manifest
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&m) != nil || d.Decode(&struct{}{}) != io.EOF || m.validate(policy) != nil {
		return Manifest{}, ErrInvalid
	}
	canonical, _ := json.Marshal(m)
	if !bytes.Equal(canonical, raw) {
		return Manifest{}, ErrInvalid
	}
	return m, nil
}
func (m Manifest) Validate() error                        { return m.validate(ProductionPolicy()) }
func (m Manifest) ValidateWithPolicy(policy Policy) error { return m.validate(policy) }
func (m Manifest) validate(policy Policy) error {
	if !policy.valid() || m.SchemaVersion != SchemaV1 || m.ArchiveDigest != policy.ArchiveDigest || m.NodePath != "node/bin/node" || !validDigest(m.NodeDigest) || !validCDHash(m.NodeCDHash) || m.NodeTeamID != "HX7739G8FX" || !validDigest(m.HostIdentityDigest) || len(m.Entries) != policy.FileCount || !validDigest(m.InventoryDigest) {
		return ErrInvalid
	}
	last := ""
	folded := make(map[string]struct{}, len(m.Entries))
	h := sha256.New()
	node := false
	for _, e := range m.Entries {
		if e.Path <= last || !validRelativeFile(e.Path) || e.Type != "file" || !validMode(e.Mode) || e.Size < 0 || !validDigest(e.Digest) {
			return ErrInvalid
		}
		fold := foldKey(e.Path)
		if _, exists := folded[fold]; exists {
			return ErrInvalid
		}
		folded[fold] = struct{}{}
		last = e.Path
		writeInventoryRecord(h, e)
		if e.Path == m.NodePath {
			if e.Digest != m.NodeDigest {
				return ErrInvalid
			}
			node = true
		}
	}
	if !node || digestHash(h) != m.InventoryDigest {
		return ErrInvalid
	}
	return nil
}

// BuildArchive performs a bounded streaming inventory pass after pinning the
// compressed archive. The observed code-signature values and host identity are
// immutable fields of the output, rather than ambient activation input.
func BuildArchive(archivePath, nodeCDHash, nodeTeamID string, hostIdentityRaw []byte) (Manifest, []byte, error) {
	policy := ProductionPolicy()
	if !validCDHash(nodeCDHash) || nodeTeamID != "HX7739G8FX" || len(hostIdentityRaw) == 0 || len(hostIdentityRaw) > maxManifestBytes || digestFile(archivePath) != policy.ArchiveDigest {
		return Manifest{}, nil, ErrInvalid
	}
	entries, err := streamArchive(archivePath, nil, nil)
	if err != nil {
		return Manifest{}, nil, ErrInvalid
	}
	m := Manifest{SchemaVersion: SchemaV1, ArchiveDigest: policy.ArchiveDigest, NodePath: "node/bin/node", NodeCDHash: strings.ToLower(nodeCDHash), NodeTeamID: nodeTeamID, HostIdentityDigest: DigestBytes(hostIdentityRaw), Entries: entries}
	for _, e := range entries {
		if e.Path == m.NodePath {
			m.NodeDigest = e.Digest
			break
		}
	}
	identity, err := decodeHostIdentity(hostIdentityRaw)
	if err != nil || identity.Provider != "qwen" || identity.TeamID != m.NodeTeamID || identity.ArtifactDigest != m.NodeDigest || identity.ImageIdentity != imageIdentity(m.NodeCDHash) {
		return Manifest{}, nil, ErrInvalid
	}
	h := sha256.New()
	for _, e := range entries {
		writeInventoryRecord(h, e)
	}
	m.InventoryDigest = digestHash(h)
	if m.Validate() != nil {
		return Manifest{}, nil, ErrInvalid
	}
	raw, err := json.Marshal(m)
	if err != nil {
		return Manifest{}, nil, ErrInvalid
	}
	return m, raw, nil
}

// VerifyArchive rejects links, special entries, aliases, extras and modified
// bytes before materialization. It is a production fixed-digest operation.
func VerifyArchive(archivePath string, manifest Manifest) error {
	if manifest.Validate() != nil || digestFile(archivePath) != manifest.ArchiveDigest {
		return ErrInvalid
	}
	entries, err := streamArchive(archivePath, nil, nil)
	if err != nil || len(entries) != len(manifest.Entries) {
		return ErrInvalid
	}
	for i := range entries {
		if entries[i] != manifest.Entries[i] {
			return ErrInvalid
		}
	}
	return nil
}

// ExtractArchive uses descriptor-rooted paths and O_EXCL in an already-private
// empty destination, then compares the exact streamed inventory to the signed
// manifest. Publication is intentionally left to the Darwin no-replace gate.
func ExtractArchive(archivePath, destination string, manifest Manifest, uid, gid int) error {
	if manifest.Validate() != nil || digestFile(archivePath) != manifest.ArchiveDigest || !path.IsAbs(destination) {
		return ErrInvalid
	}
	root, err := os.OpenRoot(destination)
	if err != nil {
		return ErrInvalid
	}
	defer root.Close()
	entries, err := streamArchive(archivePath, root, &extractOptions{uid, gid})
	if err != nil || len(entries) != len(manifest.Entries) {
		return ErrInvalid
	}
	for i := range entries {
		if entries[i] != manifest.Entries[i] {
			return ErrInvalid
		}
	}
	return nil
}

type extractOptions struct{ uid, gid int }

func streamArchive(archivePath string, root *os.Root, extract *extractOptions) ([]Entry, error) {
	info, err := os.Lstat(archivePath)
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maxArchiveBytes {
		return nil, ErrInvalid
	}
	f, err := os.Open(archivePath)
	if err != nil {
		return nil, ErrInvalid
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return nil, ErrInvalid
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	entries := make([]Entry, 0, FileCount)
	seen := make(map[string]struct{}, maxEntries)
	folded := make(map[string]struct{}, maxEntries)
	dirs := map[string]struct{}{}
	rootSeen := false
	var total int64
	for headers := 0; ; headers++ {
		h, nextErr := tr.Next()
		if errors.Is(nextErr, io.EOF) {
			break
		}
		if nextErr != nil || headers >= maxEntries+1000 || h.Size < 0 || h.Size > maxTotalBytes || total > maxTotalBytes-h.Size {
			return nil, ErrInvalid
		}
		total += h.Size
		if !rootSeen {
			if h.Name != "qwen-code/" || h.Typeflag != tar.TypeDir || h.Size != 0 || h.Mode&^0777 != 0 || h.Mode&0777 != 0755 {
				return nil, ErrInvalid
			}
			rootSeen = true
			continue
		}
		name, isDir, e := archiveName(h)
		if e != nil || name == "" {
			return nil, ErrInvalid
		}
		if _, ok := seen[name]; ok {
			return nil, ErrInvalid
		}
		seen[name] = struct{}{}
		fold := foldKey(name)
		if _, ok := folded[fold]; ok {
			return nil, ErrInvalid
		}
		folded[fold] = struct{}{}
		if isDir {
			dirs[name] = struct{}{}
			if root != nil && ensureDirectory(root, name, os.FileMode(h.Mode).Perm(), extract) != nil {
				return nil, ErrInvalid
			}
			continue
		}
		if len(entries) >= maxEntries || !parentsDeclared(name, dirs) {
			return nil, ErrInvalid
		}
		d, e := copyEntry(tr, h.Size, root, name, os.FileMode(h.Mode).Perm(), extract)
		if e != nil {
			return nil, ErrInvalid
		}
		entries = append(entries, Entry{Path: name, Type: "file", Mode: fmt.Sprintf("%04o", h.Mode&0777), Size: h.Size, Digest: d})
	}
	if !rootSeen || len(entries) == 0 {
		return nil, ErrInvalid
	}
	// Directories are not serialized separately, but they are still closed
	// inventory: every archive directory must be the ancestor of a signed file.
	// This rejects an otherwise invisible empty-directory addition.
	expectedDirectories := make(map[string]struct{}, len(dirs))
	for _, entry := range entries {
		for directory := path.Dir(entry.Path); directory != "."; directory = path.Dir(directory) {
			expectedDirectories[directory] = struct{}{}
		}
	}
	if len(dirs) != len(expectedDirectories) {
		return nil, ErrInvalid
	}
	for directory := range dirs {
		if _, ok := expectedDirectories[directory]; !ok {
			return nil, ErrInvalid
		}
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
	return entries, nil
}
func archiveName(h *tar.Header) (string, bool, error) {
	if h == nil || h.Size < 0 || h.Mode&^0777 != 0 || h.Mode&0022 != 0 || !strings.HasPrefix(h.Name, "qwen-code/") {
		return "", false, ErrInvalid
	}
	name := strings.TrimPrefix(h.Name, "qwen-code/")
	if h.Typeflag == tar.TypeDir {
		name = strings.TrimSuffix(name, "/")
		// Distribution directories are closed to a single safe mode. File modes
		// are separately serialized per entry in the manifest.
		if h.Size != 0 || h.Mode&0777 != 0755 || name == "" || !validRelative(name) {
			return "", false, ErrInvalid
		}
		return name, true, nil
	}
	if (h.Typeflag != tar.TypeReg && h.Typeflag != tar.TypeRegA) || !validRelativeFile(name) {
		return "", false, ErrInvalid
	}
	return name, false, nil
}
func parentsDeclared(name string, dirs map[string]struct{}) bool {
	for p := path.Dir(name); p != "."; p = path.Dir(p) {
		if _, ok := dirs[p]; !ok {
			return false
		}
	}
	return true
}
func ensureDirectory(root *os.Root, name string, mode os.FileMode, extract *extractOptions) error {
	if extract == nil {
		return ErrInvalid
	}
	info, err := root.Lstat(name)
	if err == nil {
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return ErrInvalid
		}
		return nil
	}
	if !errors.Is(err, os.ErrNotExist) || root.Mkdir(name, mode) != nil || root.Chown(name, extract.uid, extract.gid) != nil {
		return ErrInvalid
	}
	return nil
}
func copyEntry(src io.Reader, size int64, root *os.Root, name string, mode os.FileMode, extract *extractOptions) (string, error) {
	h := sha256.New()
	writer := io.Writer(h)
	var out *os.File
	if root != nil {
		if extract == nil {
			return "", ErrInvalid
		}
		var err error
		out, err = root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
		if err != nil {
			return "", ErrInvalid
		}
		writer = io.MultiWriter(h, out)
	}
	_, err := io.CopyN(writer, src, size)
	if out != nil {
		syncErr := out.Sync()
		closeErr := out.Close()
		if err == nil && (syncErr != nil || closeErr != nil || root.Chown(name, extract.uid, extract.gid) != nil) {
			err = ErrInvalid
		}
	}
	if err != nil {
		return "", ErrInvalid
	}
	return digestHash(h), nil
}
func validDigest(s string) bool {
	if len(s) != 71 || !strings.HasPrefix(s, "sha256:") {
		return false
	}
	_, err := hex.DecodeString(s[7:])
	return err == nil
}
func validCDHash(s string) bool {
	if len(s) != 40 || s != strings.ToLower(s) {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

type hostIdentity struct {
	Schema         string `json:"schema"`
	Provider       string `json:"provider"`
	TeamID         string `json:"team_id"`
	ArtifactDigest string `json:"artifact_digest"`
	ImageIdentity  string `json:"image_identity"`
}

func decodeHostIdentity(raw []byte) (hostIdentity, error) {
	var value hostIdentity
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if len(raw) == 0 || len(raw) > 4096 || decoder.Decode(&value) != nil || decoder.Decode(&struct{}{}) != io.EOF || value.Schema != "openduck.provider-host-identity.v1" || value.Provider != "qwen" || value.TeamID != "HX7739G8FX" || !validDigest(value.ArtifactDigest) || !validDigest(value.ImageIdentity) {
		return hostIdentity{}, ErrInvalid
	}
	canonical, _ := json.Marshal(value)
	if !bytes.Equal(canonical, raw) {
		return hostIdentity{}, ErrInvalid
	}
	return value, nil
}

func imageIdentity(cdhash string) string {
	decoded, err := hex.DecodeString(cdhash)
	if err != nil {
		return ""
	}
	h := sha256.New()
	_, _ = h.Write([]byte("darwin-cdhash-v1\x00"))
	_, _ = h.Write(decoded)
	return digestHash(h)
}

// ImageIdentityForCDHash is the single release-wide derivation for a macOS
// CodeDirectory hash. Catalog generation must never compare the raw CDHash to
// the host identity's sha256 image identity.
func ImageIdentityForCDHash(cdhash string) string { return imageIdentity(cdhash) }
func validMode(s string) bool {
	if len(s) != 4 {
		return false
	}
	value, err := strconv.ParseUint(s, 8, 16)
	return err == nil && value&007000 == 0 && value&0022 == 0 && value <= 0777
}
func validRelativeFile(s string) bool { return validRelative(s) && !strings.HasSuffix(s, "/") }
func validRelative(s string) bool {
	if s == "" || len(s) > 1024 || !utf8.ValidString(s) || norm.NFC.String(s) != s || strings.ContainsAny(s, "\x00\r\n\t") || strings.HasPrefix(s, "/") || path.Clean(s) != s {
		return false
	}
	for _, p := range strings.Split(s, "/") {
		if p == "" || p == "." || p == ".." {
			return false
		}
	}
	return true
}

func foldKey(s string) string {
	// NFC before and after full Unicode case folding makes the collision key
	// deterministic across composed/decomposed names and multi-rune folds such
	// as ß→ss. strings.ToLower is intentionally insufficient here.
	return norm.NFC.String(cases.Fold().String(norm.NFC.String(s)))
}
func writeInventoryRecord(h io.Writer, e Entry) {
	_, _ = io.WriteString(h, e.Digest+"\x00"+e.Mode+"\x00"+strconv.FormatInt(e.Size, 10)+"\x00"+e.Path+"\x00")
}
func digestHash(h interface{ Sum([]byte) []byte }) string {
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}
func DigestBytes(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// FileDigest is a bounded regular-file digest helper for the importer command.
// It intentionally does not relax any production archive validation policy.
func FileDigest(name string) string { return digestFile(name) }

func digestFile(name string) string {
	info, err := os.Lstat(name)
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maxArchiveBytes {
		return ""
	}
	f, err := os.Open(name)
	if err != nil {
		return ""
	}
	defer f.Close()
	h := sha256.New()
	if _, err = io.Copy(h, f); err != nil {
		return ""
	}
	return digestHash(h)
}
func Sorted(entries []Entry) {
	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
}
