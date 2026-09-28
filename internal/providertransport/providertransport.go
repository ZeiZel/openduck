// Package providertransport implements the Controller-side, descriptor-bound
// transport seam for separately-attested provider daemons.  It intentionally
// does not know how to start a provider, login, read credentials, or reach a
// network endpoint.  A missing or invalid descriptor is a denial, never a
// fallback to an ambient CLI.
package providertransport

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"openduck/internal/macoschannel"
	"openduck/internal/mesh"
	"openduck/internal/providerbridge"
	"openduck/internal/providerrevision"
	"openduck/internal/servicekey"
	"openduck/internal/verifiedroot"
)

const (
	DescriptorV1 = "openduck-provider-transport-descriptor.v1"
	// InactiveDescriptorV1 is pre-release inventory only.  Unlike Descriptor,
	// it deliberately cannot name a provisioned socket, UID/GID, release
	// manifest, key epoch, or peer.  Those are observations made only by the
	// privileged P7 activation boundary after an owner-authorized lifecycle
	// operation; putting them in a release payload creates a fixed point.
	InactiveDescriptorV1 = "openduck-provider-transport-inactive-descriptor.v1"
	// ActiveDescriptorV1 documents the schema used by an activated descriptor.
	// DescriptorV1 remains the wire value for installed compatibility; callers
	// must never decode it from an unsigned/pre-release provider import.
	ActiveDescriptorV1 = DescriptorV1
	ProtocolV1         = "openduck-provider-transport-rpc.v1"
	FixedKeyRoot       = "/Library/Application Support/OpenDuck/keys/controller-provider"
	FixedReleaseParent = "/Library/Application Support/OpenDuck/releases/controller"
	// ServiceKeyRecordSize is the exact metadata size of a canonical v1
	// service-key record. Installers may verify this size but must never read or
	// project the key bytes into plans or diagnostics.
	ServiceKeyRecordSize = 116
	maxDescriptorBytes   = 32 << 10
	maxFrameBytes        = 64 << 10
)

var (
	ErrInvalid     = errors.New("provider transport: invalid contract")
	ErrUnavailable = errors.New("provider transport: unavailable")
	ErrDenied      = errors.New("provider transport: denied")
	ErrReconcile   = errors.New("provider transport: reconciliation required")
)

// Descriptor carries only immutable identity pins. Paths are leaves below the
// configured root; command lines, environments, URLs, tokens and credential
// references are deliberately not representable.
type Descriptor struct {
	SchemaVersion   string `json:"schema_version"`
	Provider        string `json:"provider"`
	ProfileID       string `json:"profile_id"`
	ProfileRevision string `json:"profile_revision"`
	MappingDigest   string `json:"mapping_digest"`
	RuntimeDigest   string `json:"runtime_digest"`
	ProtocolDigest  string `json:"protocol_digest"`
	Channel         string `json:"channel"`
	SocketLeaf      string `json:"socket_leaf"`
	SocketRoot      string `json:"socket_root"`
	PeerIdentity    string `json:"peer_identity"`
	PeerUID         uint32 `json:"peer_uid"`
	PeerGID         uint32 `json:"peer_gid"`
	// ChannelGID is the separately provisioned supplementary group shared by
	// the controller and this peer. It is not the peer's kernel credential GID.
	ChannelGID     uint32 `json:"channel_gid"`
	ReleaseID      string `json:"release_id"`
	BinaryDigest   string `json:"binary_digest"`
	SocketDigest   string `json:"socket_digest"`
	ManifestDigest string `json:"manifest_digest"`
	KeyEpoch       uint64 `json:"key_epoch"`
	Audience       string `json:"audience"`
	Digest         string `json:"digest"`
}

// ActiveDescriptor is the P7-only observed descriptor.  It aliases the
// established runtime wire type so installed Controller/daemon callers keep
// their exact active contract while pre-release code must use
// InactiveDescriptor explicitly.
type ActiveDescriptor = Descriptor

// InactiveDescriptor is a content-bound pre-release declaration.  It has no
// activation-observed identity or capability and is therefore safe to include
// in a signed disabled release.  The P7 attestor must construct a separate
// Descriptor from this declaration and the observed system state.
type InactiveDescriptor struct {
	SchemaVersion   string `json:"schema_version"`
	Provider        string `json:"provider"`
	ProfileID       string `json:"profile_id"`
	ProfileRevision string `json:"profile_revision"`
	MappingDigest   string `json:"mapping_digest"`
	RuntimeDigest   string `json:"runtime_digest"`
	ProtocolDigest  string `json:"protocol_digest"`
	Audience        string `json:"audience"`
	Digest          string `json:"digest"`
}

// DecodeInactiveDescriptor rejects all legacy/active descriptor forms.  This
// is intentional: migration cannot silently interpret an observed UID/socket
// as a symbolic pre-release value.
func DecodeInactiveDescriptor(raw []byte) (InactiveDescriptor, error) {
	if len(raw) == 0 || len(raw) > maxDescriptorBytes || !json.Valid(raw) || duplicateKeys(raw) {
		return InactiveDescriptor{}, ErrInvalid
	}
	var d InactiveDescriptor
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&d); err != nil || dec.Decode(&struct{}{}) != io.EOF || d.Validate() != nil {
		return InactiveDescriptor{}, ErrInvalid
	}
	canonical, err := json.Marshal(d)
	if err != nil || !bytes.Equal(canonical, raw) {
		return InactiveDescriptor{}, ErrInvalid
	}
	return d, nil
}

func (d InactiveDescriptor) Validate() error {
	if d.SchemaVersion != InactiveDescriptorV1 || !provider(d.Provider) || !providerProfile(d.Provider, d.ProfileID) || !id(d.ProfileRevision) || !digest(d.MappingDigest) || !digest(d.RuntimeDigest) || !digest(d.ProtocolDigest) || d.Audience != "mesh" || !digest(d.Digest) {
		return ErrInvalid
	}
	copy := d
	copy.Digest = ""
	raw, _ := json.Marshal(copy)
	if d.Digest != providerbridge.DigestBytes(raw) {
		return ErrInvalid
	}
	return nil
}

func (d *InactiveDescriptor) Seal() error {
	if d == nil {
		return ErrInvalid
	}
	d.Digest = ""
	if d.SchemaVersion == "" {
		d.SchemaVersion = InactiveDescriptorV1
	}
	raw, err := json.Marshal(*d)
	if err != nil {
		return ErrInvalid
	}
	d.Digest = providerbridge.DigestBytes(raw)
	return d.Validate()
}

// BaseInstallerPrerequisites are the only empty directories a base installer
// may create. They contain no peer principal, socket or key material.
type BaseInstallerPrerequisite struct {
	Path      string
	Mode      os.FileMode
	OwnerRole string
}

func BaseInstallerPrerequisites() []BaseInstallerPrerequisite {
	return []BaseInstallerPrerequisite{{Path: "/Library/Application Support/OpenDuck/channels/providers", Mode: 0711, OwnerRole: "root-wheel"}, {Path: FixedKeyRoot, Mode: 0700, OwnerRole: "controller"}}
}

// PostPrincipalPrerequisite is signed-gate inventory only. It never assigns a
// guessed UID/GID: a provisioned peer and channel group must be descriptor-bound
// before its directory/key can exist.
type PostPrincipalPrerequisite struct {
	ProfileID, SocketRoot, Channel, KeyLeaf string
	RequiresProvisionedPeer                 bool
}

func PostPrincipalPrerequisites() []PostPrincipalPrerequisite {
	out := make([]PostPrincipalPrerequisite, 0, 5)
	for _, profile := range []string{providerbridge.ProfileCodexChatGPT, providerbridge.ProfileClaudeCode, providerbridge.ProfileQwenGeneral, providerbridge.ProfileKimiCode, providerbridge.ProfileDeepSeekAPI} {
		out = append(out, PostPrincipalPrerequisite{ProfileID: profile, SocketRoot: socketRootForProfile(profile), Channel: channelForProfile(profile), KeyLeaf: keyLeaf(profile), RequiresProvisionedPeer: true})
	}
	return out
}
func KeyLeaves() map[string]string {
	return map[string]string{providerbridge.ProfileCodexChatGPT: keyLeaf(providerbridge.ProfileCodexChatGPT), providerbridge.ProfileClaudeCode: keyLeaf(providerbridge.ProfileClaudeCode), providerbridge.ProfileQwenGeneral: keyLeaf(providerbridge.ProfileQwenGeneral), providerbridge.ProfileKimiCode: keyLeaf(providerbridge.ProfileKimiCode), providerbridge.ProfileDeepSeekAPI: keyLeaf(providerbridge.ProfileDeepSeekAPI)}
}

// DecodeDescriptor accepts precisely canonical JSON, rejecting duplicate and
// unknown keys before any path or identity is used.
func DecodeDescriptor(raw []byte) (Descriptor, error) {
	if len(raw) == 0 || len(raw) > maxDescriptorBytes || !json.Valid(raw) || duplicateKeys(raw) {
		return Descriptor{}, ErrInvalid
	}
	var d Descriptor
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&d); err != nil || dec.Decode(&struct{}{}) != io.EOF || d.Validate() != nil {
		return Descriptor{}, ErrInvalid
	}
	canonical, err := json.Marshal(d)
	if err != nil || !bytes.Equal(canonical, raw) {
		return Descriptor{}, ErrInvalid
	}
	return d, nil
}

func (d Descriptor) Validate() error {
	if d.SchemaVersion != DescriptorV1 || !provider(d.Provider) || !providerProfile(d.Provider, d.ProfileID) || !id(d.ProfileRevision) || !digest(d.MappingDigest) || !digest(d.RuntimeDigest) || !digest(d.ProtocolDigest) || d.Channel != channelForProfile(d.ProfileID) || !leaf(d.SocketLeaf) || d.SocketRoot != socketRootForProfile(d.ProfileID) || !id(d.PeerIdentity) || d.PeerUID == 0 || d.PeerGID == 0 || d.ChannelGID == 0 || d.ChannelGID == d.PeerGID || !id(d.ReleaseID) || !bareDigest(d.BinaryDigest) || !bareDigest(d.SocketDigest) || !bareDigest(d.ManifestDigest) || d.KeyEpoch == 0 || d.Audience != "mesh" || !digest(d.Digest) {
		return ErrInvalid
	}
	copy := d
	copy.Digest = ""
	raw, _ := json.Marshal(copy)
	if d.Digest != providerbridge.DigestBytes(raw) {
		return ErrInvalid
	}
	if d.Provider == string(providerbridge.ProviderDeepSeek) && strings.Contains(d.ProfileID, "subscription") {
		return ErrInvalid
	}
	if d.Provider == string(providerbridge.ProviderQwen) && strings.Contains(d.ProfileID, "local-pd") && d.Audience != "mesh" {
		return ErrInvalid
	}
	return nil
}
func socketRootForProfile(profile string) string {
	switch profile {
	case providerbridge.ProfileCodexChatGPT:
		return "/Library/Application Support/OpenDuck/channels/providers/codex"
	case providerbridge.ProfileClaudeCode:
		return "/Library/Application Support/OpenDuck/channels/providers/claude"
	case providerbridge.ProfileQwenGeneral:
		return "/Library/Application Support/OpenDuck/channels/providers/qwen"
	case providerbridge.ProfileQwenLocalPD:
		return "/Library/Application Support/OpenDuck/channels/providers/qwen-local-pd"
	case providerbridge.ProfileKimiCode:
		return "/Library/Application Support/OpenDuck/channels/providers/kimi"
	case providerbridge.ProfileDeepSeekAPI:
		return "/Library/Application Support/OpenDuck/channels/providers/deepseek"
	default:
		return ""
	}
}
func channelForProfile(profile string) string {
	switch profile {
	case providerbridge.ProfileCodexChatGPT:
		return "provider-codex"
	case providerbridge.ProfileClaudeCode:
		return "provider-claude"
	case providerbridge.ProfileQwenGeneral:
		return "provider-qwen"
	case providerbridge.ProfileQwenLocalPD:
		return "provider-qwen-local-pd"
	case providerbridge.ProfileKimiCode:
		return "provider-kimi"
	case providerbridge.ProfileDeepSeekAPI:
		return "provider-deepseek"
	default:
		return ""
	}
}

// Seal computes the descriptor's content address. It is a packaging helper;
// callers still must write the exact canonical bytes under a verified root.
func (d *Descriptor) Seal() error {
	if d == nil {
		return ErrInvalid
	}
	d.Digest = ""
	if d.SchemaVersion == "" {
		d.SchemaVersion = DescriptorV1
	}
	raw, err := json.Marshal(*d)
	if err != nil {
		return ErrInvalid
	}
	d.Digest = providerbridge.DigestBytes(raw)
	return d.Validate()
}
func provider(s string) bool {
	return s == "codex" || s == "claude" || s == "qwen" || s == "kimi" || s == "deepseek"
}
func providerProfile(provider, profile string) bool {
	switch provider {
	case "codex":
		return profile == providerbridge.ProfileCodexChatGPT
	case "claude":
		return profile == providerbridge.ProfileClaudeCode
	case "qwen":
		return profile == providerbridge.ProfileQwenGeneral || profile == providerbridge.ProfileQwenLocalPD
	case "kimi":
		return profile == providerbridge.ProfileKimiCode
	case "deepseek":
		return profile == providerbridge.ProfileDeepSeekAPI
	default:
		return false
	}
}
func id(s string) bool {
	if len(s) == 0 || len(s) > 160 {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("._:-", r)) {
			return false
		}
	}
	return true
}
func leaf(s string) bool { return id(s) && filepath.Base(s) == s && s != "." && s != ".." }
func digest(s string) bool {
	return len(s) == 71 && strings.HasPrefix(s, "sha256:") && bareDigest(s[7:])
}
func bareDigest(s string) bool {
	if len(s) != 64 || strings.ToLower(s) != s {
		return false
	}
	for _, r := range s {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f') {
			return false
		}
	}
	return true
}

// LoadConfig gives the fixed controller-owned descriptor directory.  The
// descriptor may choose only a leaf; it can never redirect the Controller to
// an arbitrary system path.
type LoadConfig struct {
	RootPath, DescriptorLeaf string
	OwnerUID, OwnerGID       uint32
}

func Load(c LoadConfig) (Descriptor, error) {
	return loadWithFS(c, osLoadFS{})
}

type loadFile interface {
	io.Reader
	Stat() (os.FileInfo, error)
	Close() error
}
type loadRoot interface {
	Stat(string) (os.FileInfo, error)
	Lstat(string) (os.FileInfo, error)
	Open(string) (loadFile, error)
	Close() error
}
type loadFS interface {
	Lstat(string) (os.FileInfo, error)
	OpenRoot(string) (loadRoot, error)
}
type osLoadFS struct{}
type osLoadRoot struct{ root *os.Root }

func (osLoadFS) Lstat(path string) (os.FileInfo, error) { return os.Lstat(path) }
func (osLoadFS) OpenRoot(path string) (loadRoot, error) {
	r, e := os.OpenRoot(path)
	if e != nil {
		return nil, e
	}
	return osLoadRoot{r}, nil
}
func (r osLoadRoot) Stat(path string) (os.FileInfo, error)  { return r.root.Stat(path) }
func (r osLoadRoot) Lstat(path string) (os.FileInfo, error) { return r.root.Lstat(path) }
func (r osLoadRoot) Open(path string) (loadFile, error)     { return r.root.Open(path) }
func (r osLoadRoot) Close() error                           { return r.root.Close() }

func loadWithFS(c LoadConfig, fs loadFS) (Descriptor, error) {
	if fs == nil {
		return Descriptor{}, ErrInvalid
	}
	providerDir, descriptorLeaf, ok := descriptorParts(c.DescriptorLeaf)
	if !ok || !filepath.IsAbs(c.RootPath) || filepath.Clean(c.RootPath) != c.RootPath {
		return Descriptor{}, ErrInvalid
	}
	parentPath := filepath.Dir(c.RootPath)
	parentBefore, err := fs.Lstat(parentPath)
	if err != nil || !safeAncestor(parentBefore) {
		return Descriptor{}, ErrUnavailable
	}
	before, err := fs.Lstat(c.RootPath)
	if err != nil || !safeDir(before, c.OwnerUID, c.OwnerGID) {
		return Descriptor{}, ErrUnavailable
	}
	r, err := fs.OpenRoot(c.RootPath)
	if err != nil {
		return Descriptor{}, ErrUnavailable
	}
	defer r.Close()
	opened, err := r.Stat(".")
	if err != nil || !safeDir(opened, c.OwnerUID, c.OwnerGID) || !same(before, opened) {
		return Descriptor{}, ErrUnavailable
	}
	providerBefore, err := r.Lstat(providerDir)
	if err != nil || !safeDir(providerBefore, c.OwnerUID, c.OwnerGID) {
		return Descriptor{}, ErrUnavailable
	}
	path := filepath.Join(providerDir, descriptorLeaf)
	pre, err := r.Lstat(path)
	if err != nil || !safeFile(pre, c.OwnerUID, c.OwnerGID) {
		return Descriptor{}, ErrUnavailable
	}
	f, err := r.Open(path)
	if err != nil {
		return Descriptor{}, ErrUnavailable
	}
	raw, readErr := io.ReadAll(io.LimitReader(f, maxDescriptorBytes+1))
	post, statErr := f.Stat()
	_ = f.Close()
	if readErr != nil || statErr != nil || len(raw) == 0 || len(raw) > maxDescriptorBytes || !safeFile(post, c.OwnerUID, c.OwnerGID) || !same(pre, post) {
		return Descriptor{}, ErrUnavailable
	}
	providerAfter, providerStatErr := r.Lstat(providerDir)
	after, err := fs.Lstat(c.RootPath)
	parentAfter, parentErr := fs.Lstat(parentPath)
	if err != nil || parentErr != nil || providerStatErr != nil || !safeDir(after, c.OwnerUID, c.OwnerGID) || !safeDir(providerAfter, c.OwnerUID, c.OwnerGID) || !same(providerBefore, providerAfter) || !safeAncestor(parentAfter) || !same(before, after) || !same(parentBefore, parentAfter) {
		return Descriptor{}, ErrUnavailable
	}
	d, err := DecodeDescriptor(raw)
	if err != nil || d.Provider != providerDir {
		return Descriptor{}, ErrInvalid
	}
	return d, nil
}
func descriptorParts(path string) (string, string, bool) {
	parts := strings.Split(path, "/")
	if len(parts) != 2 || !id(parts[0]) || !leaf(parts[1]) {
		return "", "", false
	}
	switch parts[0] {
	case "codex", "claude", "qwen", "kimi":
		if parts[1] == "runtime-descriptor.json" || parts[1] == "plugin-descriptor.json" {
			return parts[0], parts[1], true
		}
	case "deepseek":
		if parts[1] == "dsh-adapter-descriptor.json" {
			return parts[0], parts[1], true
		}
	}
	return "", "", false
}

// The inactive provider directory lives below a root:wheel, non-writable
// parent.  Checking it before and after descriptor reads prevents replacing
// the complete directory tree through an attacker-controlled ancestor.
func safeAncestor(fi os.FileInfo) bool {
	if fi == nil || !exactDirMode(fi.Mode(), 0711, 0750) {
		return false
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	return ok && st != nil && st.Uid == 0 && st.Gid == 0 && uint32(st.Mode)&07000 == 0
}
func safeDir(fi os.FileInfo, uid, gid uint32) bool {
	if fi == nil || !exactDirMode(fi.Mode(), 0750) {
		return false
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	return ok && st != nil && st.Uid == uid && st.Gid == gid && uint32(st.Mode)&07000 == 0
}
func safeFile(fi os.FileInfo, uid, gid uint32) bool {
	if fi == nil || !fi.Mode().IsRegular() || fi.Mode().Perm() != 0440 || fi.Mode()&^os.FileMode(0440) != 0 {
		return false
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	return ok && st != nil && st.Uid == uid && st.Gid == gid && st.Nlink == 1 && uint32(st.Mode)&07000 == 0
}
func exactDirMode(mode os.FileMode, expected ...os.FileMode) bool {
	if !mode.IsDir() {
		return false
	}
	for _, perm := range expected {
		if mode.Perm() == perm && mode&^(os.ModeDir|perm) == 0 {
			return true
		}
	}
	return false
}
func same(a, b os.FileInfo) bool {
	x, ok := a.Sys().(*syscall.Stat_t)
	y, ok2 := b.Sys().(*syscall.Stat_t)
	return ok && ok2 && x != nil && y != nil && x.Dev == y.Dev && x.Ino == y.Ino
}

// FrameConn is an authenticated, descriptor-bound local channel supplied by
// the macOS boundary composition.  It has no ambient bearer token surface.
type FrameConn interface {
	Call(context.Context, []byte) ([]byte, error)
	Close() error
}
type Dialer interface {
	Dial(context.Context, Descriptor) (FrameConn, error)
}

// BoundDialer turns the already-authenticated macoschannel boundary into a
// bounded request/response channel. Builder belongs to the Controller
// composition: it constructs macoschannel.Config from independently provisioned
// release roots and service keys, never from daemon-controlled JSON.
type BoundDialer struct {
	Builder func(Descriptor) (*macoschannel.Dialer, error)
}

// ControllerChannelConfig is the closed privileged composition input.  It
// takes already-open roots rather than paths: flags may pin releases and Unix
// identities, but cannot redirect a key/socket/release lookup. Key leaves are
// derived from the profile; no descriptor can select one.
type ControllerChannelConfig struct {
	SocketRoots                  map[string]*os.Root
	KeyRoot, ReleaseRoot         *os.Root
	LocalRelease                 macoschannel.ReleasePin
	ControllerUID, ControllerGID uint32
	ChannelGID                   uint32
	ExpectedKeyEpoch             uint64
}

func (c ControllerChannelConfig) BoundDialer() (BoundDialer, error) {
	if len(c.SocketRoots) == 0 || c.KeyRoot == nil || c.ReleaseRoot == nil || c.ControllerUID == 0 || c.ControllerGID == 0 || c.ChannelGID == 0 || c.ChannelGID == c.ControllerGID || c.ExpectedKeyEpoch == 0 || c.LocalRelease.ReleaseID == "" {
		return BoundDialer{}, ErrInvalid
	}
	return BoundDialer{Builder: func(d Descriptor) (*macoschannel.Dialer, error) {
		if d.Validate() != nil || d.KeyEpoch != c.ExpectedKeyEpoch || d.ChannelGID != c.ChannelGID {
			return nil, ErrDenied
		}
		socketRoot := c.SocketRoots[d.ProfileID]
		if socketRoot == nil {
			return nil, ErrDenied
		}
		key, err := servicekey.New(c.KeyRoot, servicekey.Policy{FileName: keyLeaf(d.ProfileID), Channel: d.Channel, OwnerUID: c.ControllerUID, OwnerGID: c.ControllerGID, Mode: 0600, RootUID: c.ControllerUID, RootGID: c.ControllerGID, RootMode: 0700})
		if err != nil {
			return nil, ErrUnavailable
		}
		peerUID, peerGID := d.PeerUID, d.PeerGID
		cfg := macoschannel.Config{Contract: macoschannel.SocketContract{Channel: d.Channel, LocalRole: "controller", PeerRole: d.PeerIdentity, SocketPath: d.SocketLeaf, SocketRoot: d.SocketRoot, ExpectedPeerUID: &peerUID, ExpectedPeerGID: &peerGID, ExpectedSocketRootUID: d.PeerUID, ExpectedSocketRootGID: d.ChannelGID, ExpectedSocketRootMode: 0750, ExpectedSocketUID: d.PeerUID, ExpectedSocketGID: d.ChannelGID, ExpectedSocketMode: 0660}, LocalRelease: c.LocalRelease, PeerRelease: macoschannel.ReleasePin{ReleaseID: d.ReleaseID, BinaryDigest: d.BinaryDigest, SocketDigest: d.SocketDigest, ManifestDigest: d.ManifestDigest}, ReleaseRoot: c.ReleaseRoot, SocketRootFD: socketRoot, BinaryName: "openduck-controller", KeySource: key, ExpectedReleaseRootUID: 0, ExpectedReleaseRootGID: c.ControllerGID, ExpectedReleaseRootMode: 0550, ExpectedManifestMode: 0440, ExpectedBinaryMode: 0550}
		return macoschannel.NewDialer(cfg)
	}}, nil
}
func keyLeaf(profile string) string {
	switch profile {
	case providerbridge.ProfileCodexChatGPT:
		return "codex.key"
	case providerbridge.ProfileClaudeCode:
		return "claude.key"
	case providerbridge.ProfileQwenGeneral:
		return "qwen-general.key"
	case providerbridge.ProfileQwenLocalPD:
		return "qwen-local-pd.key"
	case providerbridge.ProfileKimiCode:
		return "kimi.key"
	case providerbridge.ProfileDeepSeekAPI:
		return "deepseek.key"
	default:
		return "invalid.key"
	}
}

func releaseRootForPin(pin macoschannel.ReleasePin) (string, error) {
	if !leaf(pin.ReleaseID) {
		return "", ErrInvalid
	}
	path := filepath.Join(FixedReleaseParent, pin.ReleaseID)
	if filepath.Dir(path) != FixedReleaseParent {
		return "", ErrInvalid
	}
	return path, nil
}
func releaseRequirement(pin macoschannel.ReleasePin, gid uint32) (verifiedroot.Requirement, error) {
	path, err := releaseRootForPin(pin)
	if err != nil {
		return verifiedroot.Requirement{}, err
	}
	return verifiedroot.Requirement{Name: "controller-release", Path: path, UID: 0, GID: gid, Mode: 0550}, nil
}

// OpenFixedControllerChannel opens only installer-defined roots. It is the
// sole production pathname entry point for this transport; the close function
// must remain deferred for the Controller lifetime.
func OpenFixedControllerChannel(local macoschannel.ReleasePin, uid, gid, channelGID uint32, epoch uint64, descriptors []Descriptor) (BoundDialer, func(), error) {
	return openFixedControllerChannelWith(local, uid, gid, channelGID, epoch, descriptors, openVerifiedRoots)
}

type openedRoot struct {
	path   string
	handle *os.Root
}

type rootOpener func([]verifiedroot.Requirement) ([]openedRoot, func(), error)

func openVerifiedRoots(requirements []verifiedroot.Requirement) ([]openedRoot, func(), error) {
	roots, err := verifiedroot.OpenAll(requirements)
	if err != nil {
		return nil, nil, err
	}
	out := make([]openedRoot, len(roots))
	for i := range roots {
		out[i] = openedRoot{path: roots[i].Path(), handle: roots[i].Handle()}
	}
	return out, func() { verifiedroot.CloseAll(roots) }, nil
}

func openFixedControllerChannelWith(local macoschannel.ReleasePin, uid, gid, channelGID uint32, epoch uint64, descriptors []Descriptor, opener rootOpener) (BoundDialer, func(), error) {
	if opener == nil || uid == 0 || gid == 0 || channelGID == 0 || channelGID == gid || epoch == 0 {
		return BoundDialer{}, nil, ErrInvalid
	}
	if len(descriptors) == 0 || len(descriptors) > 5 {
		return BoundDialer{}, nil, ErrInvalid
	}
	reqs := make([]verifiedroot.Requirement, 0, len(descriptors)+2)
	seen := map[string]bool{}
	for _, d := range descriptors {
		if d.Validate() != nil || seen[d.ProfileID] || d.KeyEpoch != epoch || d.ChannelGID != channelGID {
			return BoundDialer{}, nil, ErrDenied
		}
		seen[d.ProfileID] = true
		reqs = append(reqs, verifiedroot.Requirement{Name: "provider-socket-" + d.ProfileID, Path: d.SocketRoot, UID: d.PeerUID, GID: d.ChannelGID, Mode: 0750})
	}
	releaseReq, err := releaseRequirement(local, gid)
	if err != nil {
		return BoundDialer{}, nil, err
	}
	reqs = append(reqs, verifiedroot.Requirement{Name: "provider-key", Path: FixedKeyRoot, UID: uid, GID: gid, Mode: 0700}, releaseReq)
	roots, closeRoots, err := opener(reqs)
	if err != nil {
		return BoundDialer{}, nil, ErrUnavailable
	}
	if closeRoots == nil {
		return BoundDialer{}, nil, ErrUnavailable
	}
	close := closeRoots
	if len(roots) != len(reqs) {
		close()
		return BoundDialer{}, nil, ErrUnavailable
	}
	for i := range roots {
		if roots[i].path != reqs[i].Path || roots[i].handle == nil {
			close()
			return BoundDialer{}, nil, ErrUnavailable
		}
	}
	socketRoots := map[string]*os.Root{}
	for i, d := range descriptors {
		socketRoots[d.ProfileID] = roots[i].handle
	}
	dial, err := (ControllerChannelConfig{SocketRoots: socketRoots, KeyRoot: roots[len(descriptors)].handle, ReleaseRoot: roots[len(descriptors)+1].handle, LocalRelease: local, ControllerUID: uid, ControllerGID: gid, ChannelGID: channelGID, ExpectedKeyEpoch: epoch}).BoundDialer()
	if err != nil {
		close()
		return BoundDialer{}, nil, err
	}
	return dial, close, nil
}

func (d BoundDialer) Dial(ctx context.Context, descriptor Descriptor) (FrameConn, error) {
	if d.Builder == nil {
		return nil, ErrUnavailable
	}
	dial, err := d.Builder(descriptor)
	if err != nil || dial == nil || !dial.Valid() {
		return nil, ErrUnavailable
	}
	conn, err := dial.Dial(ctx)
	if err != nil {
		return nil, ErrUnavailable
	}
	e := conn.Evidence()
	if validateEvidence(descriptor, e) != nil {
		_ = conn.Close()
		return nil, ErrDenied
	}
	return &boundConn{conn: conn}, nil
}

func validateEvidence(d Descriptor, e macoschannel.Evidence) error {
	if d.Validate() != nil || e.Channel != d.Channel || e.LocalRole != "controller" || e.PeerRole != d.PeerIdentity || e.Peer.UID != d.PeerUID || e.Peer.GID != d.PeerGID || e.PeerRelease.ReleaseID != d.ReleaseID || e.PeerRelease.BinaryDigest != d.BinaryDigest || e.PeerRelease.SocketDigest != d.SocketDigest || e.PeerRelease.ManifestDigest != d.ManifestDigest || e.KeyEpoch != d.KeyEpoch {
		return ErrDenied
	}
	return nil
}

type sealedFrame struct {
	Payload json.RawMessage `json:"payload"`
	Tag     string          `json:"tag"`
}
type boundConn struct {
	conn   macoschannel.Conn
	mu     sync.Mutex
	closed bool
}

func (c *boundConn) Call(ctx context.Context, payload []byte) ([]byte, error) {
	if c == nil || c.conn == nil || ctx == nil || ctx.Err() != nil || len(payload) == 0 || len(payload) > maxFrameBytes {
		return nil, ErrUnavailable
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil, ErrUnavailable
	}
	if deadline, ok := ctx.Deadline(); ok {
		if err := c.conn.SetDeadline(deadline); err != nil {
			return nil, ErrUnavailable
		}
		defer c.conn.SetDeadline(time.Time{})
	}
	tag, err := c.conn.Seal("providertransport.frame.v1", payload)
	if err != nil {
		return nil, ErrUnavailable
	}
	out, err := json.Marshal(sealedFrame{Payload: payload, Tag: tag})
	if err != nil || len(out) > maxFrameBytes {
		return nil, ErrInvalid
	}
	if err = writeFrame(ctx, c.conn, out); err != nil {
		return nil, ErrUnavailable
	}
	raw, err := readFrame(ctx, c.conn)
	if err != nil {
		return nil, ErrUnavailable
	}
	var in sealedFrame
	if decodeCanonical(raw, &in) != nil || len(in.Payload) == 0 || len(in.Payload) > maxFrameBytes || in.Tag == "" || c.conn.Verify("providertransport.frame.v1", in.Payload, in.Tag) != nil {
		return nil, ErrDenied
	}
	return append([]byte(nil), in.Payload...), nil
}
func (c *boundConn) Close() error {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	return c.conn.Close()
}
func writeFrame(ctx context.Context, w io.Writer, raw []byte) error {
	if len(raw) == 0 || len(raw) > maxFrameBytes {
		return ErrInvalid
	}
	var h [4]byte
	binary.BigEndian.PutUint32(h[:], uint32(len(raw)))
	if err := writeFull(ctx, w, h[:]); err != nil {
		return err
	}
	return writeFull(ctx, w, raw)
}
func writeFull(ctx context.Context, w io.Writer, b []byte) error {
	for len(b) > 0 {
		if err := ctx.Err(); err != nil {
			return err
		}
		n, e := w.Write(b)
		if e != nil || n <= 0 {
			return ErrUnavailable
		}
		b = b[n:]
	}
	return nil
}
func readFrame(ctx context.Context, r io.Reader) ([]byte, error) {
	var h [4]byte
	if err := readFull(ctx, r, h[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(h[:])
	if n == 0 || n > maxFrameBytes {
		return nil, ErrInvalid
	}
	b := make([]byte, n)
	if err := readFull(ctx, r, b); err != nil {
		return nil, err
	}
	return b, nil
}
func readFull(ctx context.Context, r io.Reader, b []byte) error {
	for len(b) > 0 {
		if err := ctx.Err(); err != nil {
			return err
		}
		n, e := r.Read(b)
		if e != nil || n <= 0 {
			return ErrUnavailable
		}
		b = b[n:]
	}
	return nil
}

type request struct {
	SchemaVersion   string            `json:"schema_version"`
	Operation       string            `json:"operation"`
	RequestID       string            `json:"request_id"`
	ProfileID       string            `json:"profile_id"`
	ProfileRevision string            `json:"profile_revision"`
	MappingDigest   string            `json:"mapping_digest"`
	RuntimeDigest   string            `json:"runtime_digest"`
	ProtocolDigest  string            `json:"protocol_digest"`
	Audience        string            `json:"audience"`
	SessionID       string            `json:"session_id"`
	RevisionRef     string            `json:"revision_ref"`
	InputRef        string            `json:"input_ref"`
	CancelMode      string            `json:"cancel_mode"`
	ReasonRef       string            `json:"reason_ref"`
	OrderID         string            `json:"order_id"`
	OrderHash       string            `json:"order_hash"`
	BindingID       string            `json:"binding_id"`
	BindingHash     string            `json:"binding_hash"`
	RunID           string            `json:"run_id"`
	AttemptID       string            `json:"attempt_id"`
	Nonce           string            `json:"nonce"`
	Deadline        time.Time         `json:"deadline"`
	Task            mesh.TaskEnvelope `json:"task"`
}
type response struct {
	SchemaVersion     string                 `json:"schema_version"`
	Operation         string                 `json:"operation"`
	RequestID         string                 `json:"request_id"`
	State             string                 `json:"state"`
	UsageSource       string                 `json:"usage_source"`
	SessionID         string                 `json:"session_id"`
	RunID             string                 `json:"run_id"`
	AttemptID         string                 `json:"attempt_id"`
	Status            string                 `json:"status"`
	OutputArtifactRef string                 `json:"output_artifact_ref"`
	SchemaRef         string                 `json:"schema_ref"`
	ProvenanceDigest  string                 `json:"provenance_digest"`
	Classification    string                 `json:"classification"`
	ProfileID         string                 `json:"profile_id"`
	ProfileRevision   string                 `json:"profile_revision"`
	MappingDigest     string                 `json:"mapping_digest"`
	RuntimeDigest     string                 `json:"runtime_digest"`
	ProtocolDigest    string                 `json:"protocol_digest"`
	Audience          string                 `json:"audience"`
	Recovery          *PersistedSessionProof `json:"recovery,omitempty"`
}

// PersistedSessionProof is returned by the closed recovery RPC. Every field
// is an identity pin from the durable provider receipt; it is never sufficient
// to merely know a volatile native session handle.
type PersistedSessionProof struct {
	SchemaVersion   string `json:"schema_version"`
	RouteRef        string `json:"route_ref"`
	NativeSessionID string `json:"native_session_id"`
	ProfileID       string `json:"profile_id"`
	ProfileRevision string `json:"profile_revision"`
	MappingDigest   string `json:"mapping_digest"`
	RuntimeDigest   string `json:"runtime_digest"`
	ProtocolDigest  string `json:"protocol_digest"`
	OrderID         string `json:"order_id"`
	OrderHash       string `json:"order_hash"`
	BindingID       string `json:"binding_id"`
	BindingHash     string `json:"binding_hash"`
	RunID           string `json:"run_id"`
	AttemptID       string `json:"attempt_id"`
	RequestID       string `json:"request_id"`
	RequestDigest   string `json:"request_digest"`
	State           string `json:"state"`
}

const PersistedSessionProofV1 = "openduck-provider-session-recovery.v1"

func (p PersistedSessionProof) Validate() error {
	if p.SchemaVersion != PersistedSessionProofV1 || !id(p.RouteRef) || !id(p.NativeSessionID) || !id(p.ProfileID) || !id(p.ProfileRevision) || !digest(p.MappingDigest) || !digest(p.RuntimeDigest) || !digest(p.ProtocolDigest) || !id(p.OrderID) || !id(p.OrderHash) || !id(p.BindingID) || !id(p.BindingHash) || !id(p.RunID) || !id(p.AttemptID) || !id(p.RequestID) || !digest(p.RequestDigest) || p.State != "running" {
		return ErrReconcile
	}
	expected := "ptv2-" + p.ProfileID + "-" + digestBytes([]byte(p.ProfileID+":"+p.BindingID+":"+p.BindingHash))
	if p.RouteRef != expected {
		return ErrReconcile
	}
	return nil
}

func (q request) Validate() error {
	if q.SchemaVersion != ProtocolV1 || !operation(q.Operation) || !id(q.RequestID) || !id(q.ProfileID) || !id(q.ProfileRevision) || !digest(q.MappingDigest) || !digest(q.RuntimeDigest) || !digest(q.ProtocolDigest) || q.Audience != "mesh" || q.Nonce != q.RequestID || q.Deadline.IsZero() || !q.Deadline.Equal(q.Deadline.UTC()) {
		return ErrInvalid
	}
	switch q.Operation {
	case "recover-session":
		if !id(q.SessionID) || !blankStart(q) {
			return ErrInvalid
		}
	case "start":
		if q.SessionID != "" || q.RevisionRef != "" || q.InputRef != "" || q.CancelMode != "" || q.ReasonRef != "" || q.Task.Validate() != nil || !id(q.OrderID) || !id(q.OrderHash) || !id(q.BindingID) || !id(q.BindingHash) || !id(q.RunID) || !id(q.AttemptID) {
			return ErrInvalid
		}
	case "send", "steer":
		if !id(q.SessionID) || !id(q.InputRef) || q.RevisionRef != "" || q.CancelMode != "" || q.ReasonRef != "" || !blankStart(q) {
			return ErrInvalid
		}
	case "cancel":
		if !id(q.SessionID) || q.InputRef != "" || !blankStart(q) || cancellationForRequest(q).Validate() != nil {
			return ErrInvalid
		}
	case "status", "wait":
		if !id(q.SessionID) || q.RevisionRef != "" || q.InputRef != "" || q.CancelMode != "" || q.ReasonRef != "" || !blankStart(q) {
			return ErrInvalid
		}
	case "result", "collect":
		if !id(q.SessionID) || !id(q.RevisionRef) || q.InputRef != "" || q.CancelMode != "" || q.ReasonRef != "" || !blankStart(q) {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	return nil
}
func blankStart(q request) bool {
	return q.OrderID == "" && q.OrderHash == "" && q.BindingID == "" && q.BindingHash == "" && q.RunID == "" && q.AttemptID == "" && emptyTask(q.Task)
}
func emptyTask(t mesh.TaskEnvelope) bool {
	return t.Objective == "" && len(t.InputArtifactRefs) == 0 && t.RequestedRole == "" && t.OutputSchemaRef == ""
}
func cancellationForRequest(q request) mesh.Cancellation {
	return mesh.Cancellation{Mode: q.CancelMode, RevisionRef: q.RevisionRef, ReasonRef: q.ReasonRef}
}
func operation(v string) bool {
	switch v {
	case "start", "send", "steer", "cancel", "status", "wait", "result", "collect", "recover-session":
		return true
	}
	return false
}
func (r response) Validate() error {
	if r.SchemaVersion != ProtocolV1 || !operation(r.Operation) || !id(r.RequestID) || !id(r.ProfileID) || !id(r.ProfileRevision) || !digest(r.MappingDigest) || !digest(r.RuntimeDigest) || !digest(r.ProtocolDigest) || r.Audience != "mesh" {
		return ErrInvalid
	}
	noResult := r.Status == "" && r.OutputArtifactRef == "" && r.SchemaRef == "" && r.ProvenanceDigest == "" && r.Classification == ""
	switch r.Operation {
	case "recover-session":
		if r.State != "" || r.UsageSource != "" || r.SessionID != "" || r.RunID != "" || r.AttemptID != "" || !noResult || r.Recovery == nil || r.Recovery.Validate() != nil {
			return ErrInvalid
		}
	case "start":
		return validStartResponse(r, noResult)
	case "status", "wait":
		if !state(r.State) || !usage(r.UsageSource) || r.SessionID != "" || r.RunID != "" || r.AttemptID != "" || !noResult {
			return ErrInvalid
		}
	case "result", "collect":
		if r.State != "" || r.UsageSource != "" || r.SessionID != "" || !id(r.RunID) || !id(r.AttemptID) || !terminal(r.Status) || !id(r.OutputArtifactRef) || !id(r.SchemaRef) || !digest(r.ProvenanceDigest) || !classification(r.Classification) {
			return ErrInvalid
		}
	case "send", "steer", "cancel":
		if r.State != "" || r.UsageSource != "" || r.SessionID != "" || r.RunID != "" || r.AttemptID != "" || !noResult {
			return ErrInvalid
		}
	}
	return nil
}
func validStartResponse(r response, noResult bool) error {
	if r.State != "" || r.UsageSource != "" || !id(r.SessionID) || !id(r.RunID) || !id(r.AttemptID) || !noResult {
		return ErrInvalid
	}
	return nil
}

// Adapter maps the seven narrow mesh interfaces onto a strictly typed local
// RPC protocol. Routing IDs are Controller-generated opaque values. A fresh
// Adapter remains empty until an exact durable recovery batch succeeds.
type Adapter struct {
	descriptor Descriptor
	dialer     Dialer
	now        func() time.Time
	mu         sync.Mutex
	sessions   map[string]string
	terminal   map[string]time.Time
	starting   int
	limit      int
}

const maxAdapterSessions = 256

func NewAdapter(d Descriptor, dialer Dialer) (*Adapter, error) {
	if d.Validate() != nil || dialer == nil {
		return nil, ErrInvalid
	}
	return &Adapter{descriptor: d, dialer: dialer, now: time.Now, sessions: map[string]string{}, terminal: map[string]time.Time{}, limit: maxAdapterSessions}, nil
}
func (a *Adapter) ProfileID() string       { return a.descriptor.ProfileID }
func (a *Adapter) ProfileRevision() string { return a.descriptor.ProfileRevision }
func (a *Adapter) MappingDigest() string   { return a.descriptor.MappingDigest }
func (a *Adapter) RuntimeDigest() string   { return a.descriptor.RuntimeDigest }

// RecoverPersistedSessions verifies every durable identity before atomically
// publishing the volatile route map. It never invokes Start or another native
// mutating operation.
func (a *Adapter) RecoverPersistedSessions(ctx context.Context, recoveries []mesh.PersistedSessionRecovery) error {
	if a == nil || ctx == nil || ctx.Err() != nil || len(recoveries) == 0 || len(recoveries) > a.sessionLimitLocked() {
		return mesh.ErrReconciliationNeeded
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	candidate := make(map[string]string, len(a.sessions)+len(recoveries))
	reverse := make(map[string]string, len(a.sessions)+len(recoveries))
	for route, native := range a.sessions {
		candidate[route] = native
		if prior, exists := reverse[native]; exists && prior != route {
			return mesh.ErrReconciliationNeeded
		}
		reverse[native] = route
	}
	for _, recovery := range recoveries {
		q, raw, err := a.buildStartWire(recovery.Start)
		expectedRoute := "ptv2-" + a.descriptor.ProfileID + "-" + digestBytes([]byte(a.descriptor.ProfileID+":"+recovery.Start.Binding.BindingID+":"+recovery.Start.Binding.BindingHash))
		if err != nil || recovery.ProviderSessionID != expectedRoute {
			return mesh.ErrReconciliationNeeded
		}
		proof, err := a.callRecovery(ctx, recovery.ProviderSessionID)
		if err != nil || proof.RouteRef != expectedRoute || proof.ProfileID != q.ProfileID || proof.ProfileRevision != q.ProfileRevision || proof.MappingDigest != q.MappingDigest || proof.RuntimeDigest != q.RuntimeDigest || proof.ProtocolDigest != q.ProtocolDigest || proof.OrderID != q.OrderID || proof.OrderHash != q.OrderHash || proof.BindingID != q.BindingID || proof.BindingHash != q.BindingHash || proof.RunID != q.RunID || proof.AttemptID != q.AttemptID || proof.RequestID != q.RequestID || proof.RequestDigest != requestDigest(raw) || proof.State != "running" {
			return mesh.ErrReconciliationNeeded
		}
		if prior, exists := candidate[proof.RouteRef]; exists && prior != proof.NativeSessionID {
			return mesh.ErrReconciliationNeeded
		}
		if prior, exists := reverse[proof.NativeSessionID]; exists && prior != proof.RouteRef {
			return mesh.ErrReconciliationNeeded
		}
		candidate[proof.RouteRef] = proof.NativeSessionID
		reverse[proof.NativeSessionID] = proof.RouteRef
	}
	if len(candidate) > a.sessionLimitLocked() {
		return mesh.ErrReconciliationNeeded
	}
	a.sessions = candidate
	for route := range candidate {
		delete(a.terminal, route)
	}
	return nil
}

func (a *Adapter) Start(ctx context.Context, s mesh.StartRequest) (mesh.SessionRef, error) {
	if a == nil || !s.SealValid() || s.Order.ProfileID != a.ProfileID() || s.Order.Provider != a.descriptor.Provider || s.Order.OrderID == "" || s.Binding.BindingID == "" || s.Binding.IssuedAt.IsZero() || !s.Binding.ExpiresAt.After(s.Binding.IssuedAt) || !s.Binding.ExpiresAt.Equal(s.Order.LeaseExpiry) {
		return mesh.SessionRef{}, mesh.ErrDenied
	}
	deadline := s.Binding.IssuedAt.UTC().Add(15 * time.Second)
	if s.Binding.ExpiresAt.UTC().Before(deadline) {
		deadline = s.Binding.ExpiresAt.UTC()
	}
	id := "ptv2-" + a.descriptor.ProfileID + "-" + digestBytes([]byte(a.descriptor.ProfileID+":"+s.Binding.BindingID+":"+s.Binding.BindingHash))
	// Bound local opaque routing state before any native Start.  `starting`
	// reserves concurrent slots, so a burst cannot pass a len(map) check and
	// leave the Adapter unable to retain the successful native handles.
	a.mu.Lock()
	reserved := false
	a.reapTerminalLocked(a.now().UTC())
	if _, exists := a.sessions[id]; !exists {
		if len(a.sessions)+a.starting >= a.sessionLimitLocked() {
			a.mu.Unlock()
			return mesh.SessionRef{}, mesh.ErrReconciliationNeeded
		}
		a.starting++
		reserved = true
	}
	a.mu.Unlock()
	defer func() {
		if reserved {
			a.mu.Lock()
			a.starting--
			a.mu.Unlock()
		}
	}()
	r, err := a.callStart(ctx, s, deadline)
	if err != nil {
		if errors.Is(err, ErrReconcile) {
			return mesh.SessionRef{}, errors.Join(mesh.ErrReconciliationNeeded, mesh.ErrStartUncertain)
		}
		return mesh.SessionRef{}, mesh.ErrDenied
	}
	if r.SessionID == "" || r.RunID != s.Order.RunID || r.AttemptID != s.Order.AttemptID {
		return mesh.SessionRef{}, errors.Join(mesh.ErrReconciliationNeeded, mesh.ErrStartUncertain)
	}
	a.mu.Lock()
	if reserved && a.starting > 0 {
		a.starting--
	}
	reserved = false
	if prior, exists := a.sessions[id]; exists {
		a.mu.Unlock()
		if prior != r.SessionID {
			return mesh.SessionRef{}, errors.Join(mesh.ErrReconciliationNeeded, mesh.ErrStartUncertain)
		}
		return mesh.SessionRef{ProviderSessionID: id}, nil
	}
	a.sessions[id] = r.SessionID
	delete(a.terminal, id)
	a.mu.Unlock()
	return mesh.SessionRef{ProviderSessionID: id}, nil
}
func (a *Adapter) Send(ctx context.Context, ref mesh.SessionRef, revision string) error {
	return a.control(ctx, "send", ref, revision, "")
}
func (a *Adapter) Steer(ctx context.Context, ref mesh.SessionRef, revision string) error {
	return a.control(ctx, "steer", ref, revision, "")
}
func (a *Adapter) Cancel(ctx context.Context, ref mesh.SessionRef, cancellation mesh.Cancellation) error {
	if cancellation.Validate() != nil {
		return mesh.ErrDenied
	}
	sid, ok := a.session(ref)
	if !ok {
		return mesh.ErrReconciliationNeeded
	}
	_, err := a.call(ctx, "cancel", sid, cancellation.RevisionRef, "", "", "", "", "", "", cancellation.ReasonRef, cancellation.Mode)
	if err != nil {
		if errors.Is(err, ErrReconcile) {
			return errors.Join(mesh.ErrReconciliationNeeded, mesh.ErrControlUncertain)
		}
		return mesh.ErrDenied
	}
	a.markTerminal(ref.ProviderSessionID)
	return nil
}
func (a *Adapter) control(ctx context.Context, op string, ref mesh.SessionRef, revision, reason string) error {
	sid, ok := a.session(ref)
	if !ok {
		return mesh.ErrReconciliationNeeded
	}
	_, err := a.call(ctx, op, sid, revision, "", "", "", "", "", "", reason, "")
	if err != nil {
		if errors.Is(err, ErrReconcile) {
			return errors.Join(mesh.ErrReconciliationNeeded, mesh.ErrControlUncertain)
		}
		return mesh.ErrDenied
	}
	return nil
}
func (a *Adapter) Status(ctx context.Context, ref mesh.SessionRef) (mesh.SessionStatus, error) {
	sid, ok := a.session(ref)
	if !ok {
		return mesh.SessionStatus{}, mesh.ErrReconciliationNeeded
	}
	r, e := a.call(ctx, "status", sid, "", "", "", "", "", "", "", "", "")
	if e != nil || !state(r.State) || !usage(r.UsageSource) {
		return mesh.SessionStatus{}, mesh.ErrDenied
	}
	if terminalState(r.State) {
		a.markTerminal(ref.ProviderSessionID)
	}
	return mesh.SessionStatus{State: r.State, UsageSource: r.UsageSource}, nil
}
func (a *Adapter) Wait(ctx context.Context, ref mesh.SessionRef, deadline time.Time) (mesh.SessionStatus, error) {
	if deadline.IsZero() || !deadline.After(a.now().UTC()) {
		return mesh.SessionStatus{}, mesh.ErrDenied
	}
	sid, ok := a.session(ref)
	if !ok {
		return mesh.SessionStatus{}, mesh.ErrReconciliationNeeded
	}
	r, e := a.callDeadline(ctx, "wait", sid, "", "", "", "", "", "", "", "", "", deadline)
	if e != nil || !state(r.State) || !usage(r.UsageSource) {
		return mesh.SessionStatus{}, mesh.ErrDenied
	}
	if terminalState(r.State) {
		a.markTerminal(ref.ProviderSessionID)
	}
	return mesh.SessionStatus{State: r.State, UsageSource: r.UsageSource}, nil
}
func (a *Adapter) Result(ctx context.Context, ref mesh.SessionRef, revision string) (mesh.ResultEnvelope, error) {
	sid, ok := a.session(ref)
	if !ok {
		return mesh.ResultEnvelope{}, mesh.ErrReconciliationNeeded
	}
	r, e := a.call(ctx, "result", sid, revision, "", "", "", "", "", "", "", "")
	if e != nil || r.RunID == "" || r.AttemptID == "" || !terminal(r.Status) || !id(r.OutputArtifactRef) || !id(r.SchemaRef) || !digest(r.ProvenanceDigest) || !classification(r.Classification) {
		return mesh.ResultEnvelope{}, mesh.ErrDenied
	}
	a.markTerminal(ref.ProviderSessionID)
	return mesh.ResultEnvelope{RunID: r.RunID, AttemptID: r.AttemptID, Status: r.Status, OutputArtifactRef: r.OutputArtifactRef, SchemaRef: r.SchemaRef, ProvenanceDigest: r.ProvenanceDigest, Classification: r.Classification}, nil
}
func (a *Adapter) session(ref mesh.SessionRef) (string, bool) {
	if a == nil || ref.ProviderSessionID == "" {
		return "", false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	s, ok := a.sessions[ref.ProviderSessionID]
	return s, ok
}

func terminalState(value string) bool {
	return value == "completed" || value == "failed" || value == "cancelled" || value == "uncertain"
}

func (a *Adapter) markTerminal(id string) {
	if a == nil || id == "" {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, ok := a.sessions[id]; ok {
		if a.terminal == nil {
			a.terminal = map[string]time.Time{}
		}
		if a.terminal[id].IsZero() {
			a.terminal[id] = a.now().UTC()
		}
	}
}

func (a *Adapter) reapTerminalLocked(now time.Time) {
	if a == nil || now.IsZero() || a.terminal == nil {
		return
	}
	for id, terminalAt := range a.terminal {
		if !terminalAt.IsZero() && !now.Before(terminalAt.Add(sessionRecoveryWindow)) {
			delete(a.sessions, id)
			delete(a.terminal, id)
		}
	}
}

func (a *Adapter) sessionLimitLocked() int {
	if a != nil && a.limit >= 1 && a.limit <= maxAdapterSessions {
		return a.limit
	}
	return maxAdapterSessions
}
func (a *Adapter) call(ctx context.Context, op, sid, rev, oid, oh, bid, bh, run, attempt, reason, cancelMode string) (response, error) {
	return a.callDeadline(ctx, op, sid, rev, oid, oh, bid, bh, run, attempt, reason, cancelMode, a.now().UTC().Add(15*time.Second))
}
func (a *Adapter) callStart(ctx context.Context, s mesh.StartRequest, deadline time.Time) (response, error) {
	q, raw, err := a.buildStartWire(s)
	if err != nil || !q.Deadline.Equal(deadline.UTC()) {
		return response{}, ErrInvalid
	}
	return a.callPrepared(ctx, q, raw)
}

func (a *Adapter) buildStartWire(s mesh.StartRequest) (request, []byte, error) {
	if a == nil || !s.SealValid() || s.Order.ProfileID != a.descriptor.ProfileID || s.Order.Provider != a.descriptor.Provider || !s.Binding.ExpiresAt.Equal(s.Order.LeaseExpiry) || !s.Binding.ExpiresAt.After(a.now().UTC()) {
		return request{}, nil, ErrInvalid
	}
	deadline := s.Binding.IssuedAt.UTC().Add(15 * time.Second)
	if s.Binding.ExpiresAt.UTC().Before(deadline) {
		deadline = s.Binding.ExpiresAt.UTC()
	}
	q := request{SchemaVersion: ProtocolV1, Operation: "start", ProfileID: a.descriptor.ProfileID, ProfileRevision: a.descriptor.ProfileRevision, MappingDigest: a.descriptor.MappingDigest, RuntimeDigest: a.descriptor.RuntimeDigest, ProtocolDigest: a.descriptor.ProtocolDigest, Audience: a.descriptor.Audience, OrderID: s.Order.OrderID, OrderHash: s.Order.OrderHash, BindingID: s.Binding.BindingID, BindingHash: s.Binding.BindingHash, RunID: s.Order.RunID, AttemptID: s.Order.AttemptID, Deadline: deadline, Task: s.Order.Task}
	identity, err := canonical(q)
	if err != nil {
		return request{}, nil, ErrInvalid
	}
	q.RequestID = "pt-start-" + digestBytes(identity)
	q.Nonce = q.RequestID
	if q.Validate() != nil {
		return request{}, nil, ErrInvalid
	}
	raw, err := canonical(q)
	if err != nil {
		return request{}, nil, ErrInvalid
	}
	return q, raw, nil
}

func (a *Adapter) callRecovery(ctx context.Context, route string) (PersistedSessionProof, error) {
	if a == nil || ctx == nil || ctx.Err() != nil || !id(route) {
		return PersistedSessionProof{}, ErrDenied
	}
	deadline := a.now().UTC().Add(15 * time.Second)
	q := request{SchemaVersion: ProtocolV1, Operation: "recover-session", ProfileID: a.descriptor.ProfileID, ProfileRevision: a.descriptor.ProfileRevision, MappingDigest: a.descriptor.MappingDigest, RuntimeDigest: a.descriptor.RuntimeDigest, ProtocolDigest: a.descriptor.ProtocolDigest, Audience: a.descriptor.Audience, SessionID: route, Deadline: deadline}
	seed := []byte("recover-session:" + route + ":" + a.descriptor.Digest)
	q.RequestID = "pt-recover-" + digestBytes(seed)
	q.Nonce = q.RequestID
	raw, err := canonical(q)
	if err != nil || q.Validate() != nil {
		return PersistedSessionProof{}, ErrInvalid
	}
	callCtx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	c, err := a.dialer.Dial(callCtx, a.descriptor)
	if err != nil {
		return PersistedSessionProof{}, ErrUnavailable
	}
	reply, callErr := c.Call(callCtx, raw)
	_ = c.Close()
	if callErr != nil || len(reply) == 0 || len(reply) > maxFrameBytes {
		return PersistedSessionProof{}, ErrReconcile
	}
	var out response
	if decodeCanonical(reply, &out) != nil || out.Validate() != nil || out.Operation != q.Operation || out.RequestID != q.RequestID || out.ProfileID != a.descriptor.ProfileID || out.ProfileRevision != a.descriptor.ProfileRevision || out.MappingDigest != a.descriptor.MappingDigest || out.RuntimeDigest != a.descriptor.RuntimeDigest || out.ProtocolDigest != a.descriptor.ProtocolDigest || out.Recovery == nil {
		return PersistedSessionProof{}, ErrReconcile
	}
	return *out.Recovery, nil
}
func (a *Adapter) callDeadline(ctx context.Context, op, sid, rev, oid, oh, bid, bh, run, attempt, reason, cancelMode string, deadline time.Time) (response, error) {
	return a.callDeadlineTask(ctx, op, sid, rev, oid, oh, bid, bh, run, attempt, reason, cancelMode, deadline, mesh.TaskEnvelope{})
}

func (a *Adapter) callPrepared(ctx context.Context, q request, raw []byte) (response, error) {
	if a == nil || ctx == nil || ctx.Err() != nil || q.Validate() != nil || len(raw) == 0 || !q.Deadline.After(a.now().UTC()) {
		return response{}, ErrDenied
	}
	callCtx, cancel := context.WithDeadline(ctx, q.Deadline)
	defer cancel()
	possibleEffect := false
	for try := 0; try < 2; try++ {
		c, err := a.dialer.Dial(callCtx, a.descriptor)
		if err != nil {
			if possibleEffect {
				return response{}, ErrReconcile
			}
			return response{}, ErrUnavailable
		}
		reply, callErr := c.Call(callCtx, raw)
		_ = c.Close()
		if callErr != nil || len(reply) == 0 || len(reply) > maxFrameBytes {
			possibleEffect = true
			if try == 0 {
				continue
			}
			return response{}, ErrReconcile
		}
		var out response
		if decodeCanonical(reply, &out) != nil || out.Validate() != nil || out.Operation != q.Operation || out.RequestID != q.RequestID || out.ProfileID != q.ProfileID || out.ProfileRevision != q.ProfileRevision || out.MappingDigest != q.MappingDigest || out.RuntimeDigest != q.RuntimeDigest || out.ProtocolDigest != q.ProtocolDigest || out.Audience != q.Audience {
			possibleEffect = true
			if try == 0 {
				continue
			}
			return response{}, ErrReconcile
		}
		return out, nil
	}
	return response{}, ErrReconcile
}

func (a *Adapter) callDeadlineTask(ctx context.Context, op, sid, rev, oid, oh, bid, bh, run, attempt, reason, cancelMode string, deadline time.Time, task mesh.TaskEnvelope) (response, error) {
	if a == nil || ctx.Err() != nil || !deadline.After(a.now().UTC()) {
		return response{}, ErrDenied
	}
	q := request{SchemaVersion: ProtocolV1, Operation: op, ProfileID: a.descriptor.ProfileID, ProfileRevision: a.descriptor.ProfileRevision, MappingDigest: a.descriptor.MappingDigest, RuntimeDigest: a.descriptor.RuntimeDigest, ProtocolDigest: a.descriptor.ProtocolDigest, Audience: a.descriptor.Audience, SessionID: sid, OrderID: oid, OrderHash: oh, BindingID: bid, BindingHash: bh, RunID: run, AttemptID: attempt, Deadline: deadline.UTC(), Task: task}
	switch op {
	case "send", "steer":
		q.InputRef = rev
	case "cancel":
		q.RevisionRef = rev
		q.ReasonRef = reason
		q.CancelMode = cancelMode
	case "result", "collect":
		q.RevisionRef = rev
	}
	if op == "start" {
		identity, err := canonical(q)
		if err != nil {
			return response{}, ErrInvalid
		}
		q.RequestID = "pt-start-" + digestBytes(identity)
	} else {
		nonce, err := opaque()
		if err != nil {
			return response{}, ErrUnavailable
		}
		q.RequestID = nonce
	}
	q.Nonce = q.RequestID
	if q.Validate() != nil {
		return response{}, ErrInvalid
	}
	raw, e := canonical(q)
	if e != nil {
		return response{}, ErrInvalid
	}
	callCtx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	mutating := op == "start" || op == "send" || op == "steer" || op == "cancel"
	attempts := 1
	if op == "start" {
		// Start may retry only because RuntimeStart carries this exact stable
		// request ID and the driver contract requires durable idempotency.
		attempts = 2
	}
	possibleEffect := false
	for try := 0; try < attempts; try++ {
		c, err := a.dialer.Dial(callCtx, a.descriptor)
		if err != nil {
			if possibleEffect {
				return response{}, ErrReconcile
			}
			return response{}, ErrUnavailable
		}
		reply, callErr := c.Call(callCtx, raw)
		_ = c.Close()
		if callErr != nil || len(reply) == 0 || len(reply) > maxFrameBytes {
			if mutating {
				possibleEffect = true
				if op == "start" && try+1 < attempts {
					continue
				}
				return response{}, ErrReconcile
			}
			return response{}, ErrUnavailable
		}
		var out response
		if decodeCanonical(reply, &out) != nil || out.Validate() != nil || out.Operation != op || out.RequestID != q.RequestID || out.ProfileID != a.descriptor.ProfileID || out.ProfileRevision != a.descriptor.ProfileRevision || out.MappingDigest != a.descriptor.MappingDigest || out.RuntimeDigest != a.descriptor.RuntimeDigest || out.ProtocolDigest != a.descriptor.ProtocolDigest || out.Audience != a.descriptor.Audience {
			if mutating {
				possibleEffect = true
				if op == "start" && try+1 < attempts {
					continue
				}
				return response{}, ErrReconcile
			}
			return response{}, ErrDenied
		}
		return out, nil
	}
	return response{}, ErrReconcile
}
func opaque() (string, error) {
	b := make([]byte, 18)
	if _, e := rand.Read(b); e != nil {
		return "", e
	}
	return "pt-" + base64.RawURLEncoding.EncodeToString(b), nil
}
func state(v string) bool {
	return v == "proposed" || v == "admitted" || v == "starting" || v == "running" || v == "completed" || v == "failed" || v == "cancelled" || v == "uncertain" || v == "unknown"
}
func terminal(v string) bool { return v == "completed" || v == "failed" || v == "cancelled" }
func usage(v string) bool {
	return v == "provider" || v == "controller" || v == "attested" || v == "unknown"
}
func classification(v string) bool {
	return v == "L0" || v == "L1" || v == "L2" || v == "L3" || v == "PD"
}
func canonical(v any) ([]byte, error) { return json.Marshal(v) }
func decodeCanonical(raw []byte, out any) error {
	if len(raw) == 0 || len(raw) > maxFrameBytes || !json.Valid(raw) || duplicateKeys(raw) {
		return ErrInvalid
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if e := d.Decode(out); e != nil || d.Decode(&struct{}{}) != io.EOF {
		return ErrInvalid
	}
	b, e := json.Marshal(out)
	if e != nil || !bytes.Equal(b, raw) {
		return ErrInvalid
	}
	return nil
}
func duplicateKeys(raw []byte) bool {
	var walk func(*json.Decoder) bool
	walk = func(d *json.Decoder) bool {
		t, e := d.Token()
		if e != nil {
			return true
		}
		if x, ok := t.(json.Delim); ok && x == '{' {
			seen := map[string]bool{}
			for d.More() {
				k, e := d.Token()
				if e != nil {
					return true
				}
				s, ok := k.(string)
				if !ok || seen[s] {
					return true
				}
				seen[s] = true
				if walk(d) {
					return true
				}
			}
			_, e = d.Token()
			return e != nil
		}
		if x, ok := t.(json.Delim); ok && x == '[' {
			for d.More() {
				if walk(d) {
					return true
				}
			}
			_, e = d.Token()
			return e != nil
		}
		return false
	}
	return walk(json.NewDecoder(bytes.NewReader(raw)))
}

// NewRouters revalidates the active revision immediately before admitting
// descriptors.  Every enabled eligible profile must have exactly one route;
// a descriptor for a disabled, stale, synthetic, foreign or PD profile fails
// closed.  The caller passes the resulting adapters to profileSessionRouter.
type registryResolver interface {
	Resolve(context.Context, string, time.Time) (providerbridge.ProfileResolution, error)
}

func NewAdapters(installed providerrevision.Installed, registry *providerbridge.Registry, descriptors []Descriptor, dialer Dialer, now time.Time) ([]*Adapter, error) {
	return newAdaptersWithResolver(installed, registry, descriptors, dialer, now)
}
func newAdaptersWithResolver(installed providerrevision.Installed, registry registryResolver, descriptors []Descriptor, dialer Dialer, now time.Time) ([]*Adapter, error) {
	if registry == nil || dialer == nil {
		return nil, ErrInvalid
	}
	enabled := map[string]providerbridge.Profile{}
	for _, p := range installed.Profiles() {
		if p.MeshSpawnEnabled {
			enabled[p.ID] = p
		}
	}
	if len(enabled) == 0 {
		if len(descriptors) != 0 {
			return nil, ErrInvalid
		}
		return nil, nil
	}
	seen := map[string]bool{}
	out := make([]*Adapter, 0, len(descriptors))
	for _, d := range descriptors {
		if d.Validate() != nil || seen[d.ProfileID] {
			return nil, ErrInvalid
		}
		seen[d.ProfileID] = true
		p, ok := enabled[d.ProfileID]
		if !ok || string(p.Provider) != d.Provider || p.Revision != d.ProfileRevision || p.MappingDigest != d.MappingDigest {
			return nil, ErrDenied
		}
		r, e := registry.Resolve(context.Background(), d.ProfileID, now.UTC())
		if e != nil || !r.MeshSpawnEnabled() || r.Profile.ID != p.ID || r.Profile.Provider != p.Provider || r.Profile.Revision != p.Revision || r.Profile.AuthModality != p.AuthModality || r.Mapping.Provider != p.Provider || r.Mapping.ProfileID != p.ID || r.Mapping.ProfileRevision != p.Revision || r.Mapping.Digest != d.MappingDigest || r.Mapping.Maturity != providerbridge.CompatibilityPinned || strings.HasPrefix(r.Mapping.RuntimeVersion, "synthetic/") || r.Mapping.RuntimeDigest != d.RuntimeDigest || r.Mapping.ProtocolDigest != d.ProtocolDigest {
			return nil, ErrDenied
		}
		if p.ID == providerbridge.ProfileDeepSeekAPI && (p.AuthModality != "api-key" || p.RuntimeKind != "deepseek-api") {
			return nil, ErrDenied
		}
		if p.LocalOnly {
			return nil, ErrDenied
		}
		a, e := NewAdapter(d, dialer)
		if e != nil {
			return nil, e
		}
		out = append(out, a)
	}
	if len(seen) != len(enabled) {
		return nil, ErrDenied
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ProfileID() < out[j].ProfileID() })
	return out, nil
}
