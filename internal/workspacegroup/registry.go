// Package workspacegroup owns immutable, versioned multi-root workspace scopes.
// Canonical paths are Controller-only data: callers outside this package receive
// opaque identifiers and safe projections instead.
package workspacegroup

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	SchemaVersion       = "workspace-group.v1"
	ChatBindingVersion  = "workspace-chat-binding.v1"
	MaxStoreBytes       = 4 << 20
	MaxGroups           = 256
	MaxRootsPerGroup    = 32
	MaxLabelBytes       = 128
	MaxCapabilityRefs   = 32
	MaxCapabilityRefLen = 256
)

var (
	ErrInvalidGroup          = errors.New("invalid workspace group")
	ErrNotFound              = errors.New("workspace group not found")
	ErrStaleVersion          = errors.New("stale workspace group version")
	ErrDigestMismatch        = errors.New("workspace group digest mismatch")
	ErrIntegrity             = errors.New("workspace group store integrity failure")
	ErrCheckpointUnavailable = errors.New("workspace group checkpoint unavailable")
	ErrCheckpointMismatch    = errors.New("workspace group checkpoint mismatch")
	ErrUnsafePath            = errors.New("unsafe workspace root path")
	ErrBindingUnauthorized   = errors.New("workspace chat binding is not authorized")
	ErrLimit                 = errors.New("workspace group limit exceeded")
	identifierRE             = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,255}$`)
	labelRE                  = regexp.MustCompile(`^[\x20-\x7E]{1,128}$`)
)

type AccessMode string

const (
	ReadMode  AccessMode = "read"
	WriteMode AccessMode = "write"
)

type WorkspaceRoot struct {
	RootID string     `json:"root_id"`
	Label  string     `json:"label"`
	Mode   AccessMode `json:"mode"`
}

// rootState is Controller-only state. It is never part of the public contract.
type rootState struct {
	WorkspaceRoot
	canonicalPath string
	Device        uint64 `json:"device"`
	Inode         uint64 `json:"inode"`
}

// fileIdentity is deliberately persisted with each root.  A path string is a
// locator, not an authority: the identity catches replacement and aliasing.
type fileIdentity struct{ Device, Inode uint64 }

type trustedRoot struct {
	path string
	root *os.Root
	id   fileIdentity
}

type WorkspaceGroup struct {
	SchemaVersion       string          `json:"schema_version"`
	GroupID             string          `json:"group_id"`
	DisplayLabel        string          `json:"display_label"`
	PrimaryRootID       string          `json:"primary_root_id"`
	Roots               []WorkspaceRoot `json:"roots"`
	BeadsScopeRef       string          `json:"beads_scope_ref,omitempty"`
	BeadsCapabilityRefs []string        `json:"beads_capability_refs,omitempty"`
	Version             uint64          `json:"version"`
	Digest              string          `json:"digest"`
	UpdatedAt           time.Time       `json:"updated_at"`
}

type RootProjection struct {
	RootID string     `json:"root_id"`
	Label  string     `json:"label"`
	Mode   AccessMode `json:"mode"`
}
type SafeProjection struct {
	SchemaVersion string           `json:"schema_version"`
	GroupID       string           `json:"group_id"`
	DisplayLabel  string           `json:"display_label"`
	PrimaryRootID string           `json:"primary_root_id"`
	Roots         []RootProjection `json:"roots"`
	Version       uint64           `json:"version"`
	Digest        string           `json:"digest"`
	UpdatedAt     time.Time        `json:"updated_at"`
}

type ChatBinding struct {
	SchemaVersion string `json:"schema_version"`
	ChatID        string `json:"chat_id"`
	GroupID       string `json:"group_id"`
	GroupVersion  uint64 `json:"group_version"`
	GroupDigest   string `json:"group_digest"`
	Signature     string `json:"signature"`
}

type RootSpec struct {
	Label string
	Path  string
	Mode  AccessMode
}
type GroupSpec struct {
	DisplayLabel        string
	PrimaryLabel        string
	Roots               []RootSpec
	BeadsScopeRef       string
	BeadsCapabilityRefs []string
}

type Checkpoint struct {
	Version     uint64
	StateDigest string
}
type CheckpointStore interface {
	LoadCheckpoint() (Checkpoint, error)
	CommitCheckpoint(uint64, Checkpoint) error
}
type memoryCheckpointStore struct {
	mu sync.Mutex
	c  Checkpoint
}

func (s *memoryCheckpointStore) LoadCheckpoint() (Checkpoint, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.c, nil
}
func (s *memoryCheckpointStore) CommitCheckpoint(expected uint64, next Checkpoint) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.c.Version != expected || next.Version != expected+1 {
		return ErrCheckpointMismatch
	}
	s.c = next
	return nil
}

type snapshot struct {
	SchemaVersion string `json:"schema_version"`
	Version       uint64 `json:"version"`
	// LockDevice and LockInode bind this state to the one lock inode created
	// for the registry.  Flock alone is not sufficient: replacing the lock
	// pathname creates a second, independently lockable inode.
	LockDevice uint64                 `json:"lock_device"`
	LockInode  uint64                 `json:"lock_inode"`
	Groups     map[string]storedGroup `json:"groups"`
}
type storedGroup struct {
	SchemaVersion       string      `json:"schema_version"`
	GroupID             string      `json:"group_id"`
	DisplayLabel        string      `json:"display_label"`
	PrimaryRootID       string      `json:"primary_root_id"`
	Roots               []rootState `json:"roots"`
	BeadsScopeRef       string      `json:"beads_scope_ref,omitempty"`
	BeadsCapabilityRefs []string    `json:"beads_capability_refs,omitempty"`
	Version             uint64      `json:"version"`
	Digest              string      `json:"digest"`
	UpdatedAt           time.Time   `json:"updated_at"`
}
type storedRootJSON struct {
	RootID        string     `json:"root_id"`
	Label         string     `json:"label"`
	Mode          AccessMode `json:"mode"`
	CanonicalPath string     `json:"canonical_path"`
	Device        uint64     `json:"device"`
	Inode         uint64     `json:"inode"`
}

func (g storedGroup) MarshalJSON() ([]byte, error) {
	type wire struct {
		SchemaVersion       string           `json:"schema_version"`
		GroupID             string           `json:"group_id"`
		DisplayLabel        string           `json:"display_label"`
		PrimaryRootID       string           `json:"primary_root_id"`
		Roots               []storedRootJSON `json:"roots"`
		BeadsScopeRef       string           `json:"beads_scope_ref,omitempty"`
		BeadsCapabilityRefs []string         `json:"beads_capability_refs,omitempty"`
		Version             uint64           `json:"version"`
		Digest              string           `json:"digest"`
		UpdatedAt           time.Time        `json:"updated_at"`
	}
	w := wire{SchemaVersion: g.SchemaVersion, GroupID: g.GroupID, DisplayLabel: g.DisplayLabel, PrimaryRootID: g.PrimaryRootID, BeadsScopeRef: g.BeadsScopeRef, BeadsCapabilityRefs: g.BeadsCapabilityRefs, Version: g.Version, Digest: g.Digest, UpdatedAt: g.UpdatedAt}
	for _, r := range g.Roots {
		w.Roots = append(w.Roots, storedRootJSON{RootID: r.RootID, Label: r.Label, Mode: r.Mode, CanonicalPath: r.canonicalPath, Device: r.Device, Inode: r.Inode})
	}
	return json.Marshal(w)
}
func (g *storedGroup) UnmarshalJSON(b []byte) error {
	type wire struct {
		SchemaVersion       string           `json:"schema_version"`
		GroupID             string           `json:"group_id"`
		DisplayLabel        string           `json:"display_label"`
		PrimaryRootID       string           `json:"primary_root_id"`
		Roots               []storedRootJSON `json:"roots"`
		BeadsScopeRef       string           `json:"beads_scope_ref,omitempty"`
		BeadsCapabilityRefs []string         `json:"beads_capability_refs,omitempty"`
		Version             uint64           `json:"version"`
		Digest              string           `json:"digest"`
		UpdatedAt           time.Time        `json:"updated_at"`
	}
	var w wire
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if e := d.Decode(&w); e != nil {
		return e
	}
	g.SchemaVersion = w.SchemaVersion
	g.GroupID = w.GroupID
	g.DisplayLabel = w.DisplayLabel
	g.PrimaryRootID = w.PrimaryRootID
	g.BeadsScopeRef = w.BeadsScopeRef
	g.BeadsCapabilityRefs = w.BeadsCapabilityRefs
	g.Version = w.Version
	g.Digest = w.Digest
	g.UpdatedAt = w.UpdatedAt
	for _, r := range w.Roots {
		g.Roots = append(g.Roots, rootState{WorkspaceRoot: WorkspaceRoot{RootID: r.RootID, Label: r.Label, Mode: r.Mode}, canonicalPath: r.CanonicalPath, Device: r.Device, Inode: r.Inode})
	}
	return nil
}

type envelope struct {
	SchemaVersion string `json:"schema_version"`
	Nonce         string `json:"nonce"`
	Ciphertext    string `json:"ciphertext"`
}

type Registry struct {
	mu          sync.Mutex
	base        string
	key         []byte
	checkpoints CheckpointStore
	snap        snapshot
	now         func() time.Time
	store       trustedRoot
	lockFile    *os.File
	lockID      fileIdentity
	allowed     []trustedRoot
	closed      bool
	poisoned    bool
	// beforePersist exists only to make the replacement boundary testable. It
	// is never set by production construction.
	beforePersist func()
}

// AllowedRoot and Anchor are package-sealed capabilities.  A production
// provider must deliberately mint both after DR-020 installs an attested
// checkpoint authority; strings alone can never widen the workspace scope.
type AllowedRoot interface{ allowedRoot() trustedRoot }
type Anchor interface {
	anchor()
	checkpointStore() CheckpointStore
}

// NewAnchoredRegistry only accepts retained allowed-root capabilities.  No
// ordinary build path can mint either capability yet, so production remains
// fail-closed while the implementation is ready for the attested provider.
func NewAnchoredRegistry(path string, key []byte, anchor Anchor, allowed ...AllowedRoot) (*Registry, error) {
	if path == "" || len(key) != 32 || anchor == nil || len(allowed) == 0 {
		return nil, ErrCheckpointUnavailable
	}
	roots := make([]trustedRoot, 0, len(allowed))
	for _, capability := range allowed {
		if capability == nil {
			return nil, ErrCheckpointUnavailable
		}
		root := capability.allowedRoot()
		if err := validateAllowedCapability(root); err != nil {
			return nil, ErrCheckpointUnavailable
		}
		roots = append(roots, root)
	}
	return newRegistry(path, key, anchor.checkpointStore(), roots)
}

// newRegistry is intentionally private.  Test-only construction lives in a
// _test.go file; ordinary builds have no memory checkpoint or raw-path seam.
func newRegistry(path string, key []byte, checkpoints CheckpointStore, allowed []trustedRoot) (*Registry, error) {
	if hasUnsafePathComponent(path) {
		return nil, ErrUnsafePath
	}
	if path == "" || len(key) != 32 || checkpoints == nil || !filepath.IsAbs(path) || len(allowed) == 0 {
		return nil, ErrInvalidGroup
	}
	for _, root := range allowed {
		if err := validateAllowedCapability(root); err != nil {
			return nil, ErrUnsafePath
		}
	}
	clean := filepath.Clean(path)
	store, err := openTrustedStoreRoot(filepath.Dir(clean))
	if err != nil {
		return nil, err
	}
	lockName := filepath.Base(clean) + ".lock"
	if fi, e := store.root.Lstat(lockName); e == nil && (fi.Mode()&os.ModeSymlink != 0 || !fi.Mode().IsRegular()) {
		_ = store.root.Close()
		return nil, ErrUnsafePath
	} else if e != nil && !os.IsNotExist(e) {
		_ = store.root.Close()
		return nil, e
	}
	lock, err := store.root.OpenFile(lockName, os.O_CREATE|os.O_RDWR|syscall.O_CLOEXEC, 0600)
	if err != nil {
		_ = store.root.Close()
		return nil, fmt.Errorf("%w: lock: %v", ErrUnsafePath, err)
	}
	if err = validatePrivateRegular(store.root, lock, lockName); err != nil {
		_ = lock.Close()
		_ = store.root.Close()
		return nil, err
	}
	lockInfo, err := lock.Stat()
	if err != nil {
		_ = lock.Close()
		_ = store.root.Close()
		return nil, ErrUnsafePath
	}
	lockID, err := identityOf(lockInfo)
	if err != nil {
		_ = lock.Close()
		_ = store.root.Close()
		return nil, err
	}
	r := &Registry{base: filepath.Base(clean), key: append([]byte(nil), key...), checkpoints: checkpoints, now: func() time.Time { return time.Now().UTC() }, snap: snapshot{SchemaVersion: SchemaVersion, LockDevice: lockID.Device, LockInode: lockID.Inode, Groups: map[string]storedGroup{}}, store: store, lockFile: lock, lockID: lockID, allowed: allowed}
	if err = r.withLock(func() error { return r.load() }); err != nil {
		_ = r.Close()
		return nil, err
	}
	return r, nil
}

func (r *Registry) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil
	}
	r.closed = true
	var err error
	if r.lockFile != nil {
		err = r.lockFile.Close()
	}
	if r.store.root != nil {
		if e := r.store.root.Close(); err == nil {
			err = e
		}
	}
	for _, root := range r.allowed {
		if root.root != nil {
			if e := root.root.Close(); err == nil {
				err = e
			}
		}
	}
	return err
}

func (r *Registry) Create(ctx context.Context, spec GroupSpec) (WorkspaceGroup, error) {
	if err := ctx.Err(); err != nil {
		return WorkspaceGroup{}, err
	}
	roots, primary, err := r.normalizeSpec(spec)
	if err != nil {
		return WorkspaceGroup{}, err
	}
	g := storedGroup{SchemaVersion: SchemaVersion, GroupID: opaqueID("wg"), DisplayLabel: spec.DisplayLabel, PrimaryRootID: primary, Roots: roots, BeadsScopeRef: spec.BeadsScopeRef, BeadsCapabilityRefs: append([]string(nil), spec.BeadsCapabilityRefs...), Version: 1, UpdatedAt: r.now()}
	g.Digest = digestGroup(g)
	if err := r.validateGroup(g); err != nil {
		return WorkspaceGroup{}, err
	}
	return r.transact(ctx, 0, "", func(s *snapshot) (WorkspaceGroup, error) {
		if len(s.Groups) >= MaxGroups {
			return WorkspaceGroup{}, ErrLimit
		}
		if _, ok := s.Groups[g.GroupID]; ok {
			return WorkspaceGroup{}, ErrInvalidGroup
		}
		s.Groups[g.GroupID] = g
		s.Version++
		return publicGroup(g), nil
	})
}

func (r *Registry) Get(ctx context.Context, id string) (WorkspaceGroup, error) {
	if err := ctx.Err(); err != nil {
		return WorkspaceGroup{}, err
	}
	var out WorkspaceGroup
	err := r.withLock(func() error {
		if err := r.load(); err != nil {
			return err
		}
		g, ok := r.snap.Groups[id]
		if !ok {
			return ErrNotFound
		}
		out = publicGroup(g)
		return nil
	})
	return out, err
}
func (r *Registry) Projection(ctx context.Context, id string) (SafeProjection, error) {
	g, e := r.Get(ctx, id)
	if e != nil {
		return SafeProjection{}, e
	}
	return projectionForPublic(g), nil
}

// ListProjections returns one locked, live snapshot. Paths and capabilities
// remain inside the registry; callers receive only safe projections.
func (r *Registry) ListProjections(ctx context.Context) ([]SafeProjection, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var out []SafeProjection
	err := r.withLock(func() error {
		if err := r.load(); err != nil {
			return err
		}
		out = make([]SafeProjection, 0, len(r.snap.Groups))
		for _, g := range r.snap.Groups {
			out = append(out, projectionForPublic(publicGroup(g)))
		}
		sort.Slice(out, func(i, j int) bool { return out[i].GroupID < out[j].GroupID })
		return nil
	})
	return out, err
}
func (r *Registry) Update(ctx context.Context, id string, expectedVersion uint64, expectedDigest string, spec GroupSpec) (WorkspaceGroup, error) {
	roots, primary, e := r.normalizeSpec(spec)
	if e != nil {
		return WorkspaceGroup{}, e
	}
	return r.transact(ctx, expectedVersion, id, func(s *snapshot) (WorkspaceGroup, error) {
		old, ok := s.Groups[id]
		if !ok {
			return WorkspaceGroup{}, ErrNotFound
		}
		if old.Version != expectedVersion {
			return WorkspaceGroup{}, ErrStaleVersion
		}
		if old.Digest != expectedDigest {
			return WorkspaceGroup{}, ErrDigestMismatch
		}
		g := storedGroup{SchemaVersion: SchemaVersion, GroupID: id, DisplayLabel: spec.DisplayLabel, PrimaryRootID: primary, Roots: roots, BeadsScopeRef: spec.BeadsScopeRef, BeadsCapabilityRefs: append([]string(nil), spec.BeadsCapabilityRefs...), Version: old.Version + 1, UpdatedAt: r.now()}
		g.Digest = digestGroup(g)
		if e := r.validateGroup(g); e != nil {
			return WorkspaceGroup{}, e
		}
		s.Groups[id] = g
		s.Version++
		return publicGroup(g), nil
	})
}
func (r *Registry) BindChat(ctx context.Context, chatID, id string, version uint64, digest string) (ChatBinding, error) {
	if chatID == "" || !identifierRE.MatchString(chatID) {
		return ChatBinding{}, ErrInvalidGroup
	}
	if err := ctx.Err(); err != nil {
		return ChatBinding{}, err
	}
	var binding ChatBinding
	err := r.withLock(func() error {
		if e := r.load(); e != nil {
			return e
		}
		g, ok := r.snap.Groups[id]
		if !ok {
			return ErrNotFound
		}
		if g.Version != version {
			return ErrStaleVersion
		}
		if g.Digest != digest {
			return ErrDigestMismatch
		}
		binding = ChatBinding{SchemaVersion: ChatBindingVersion, ChatID: chatID, GroupID: id, GroupVersion: version, GroupDigest: digest}
		binding.Signature = r.signBinding(binding)
		return binding.Validate()
	})
	return binding, err
}
func (b ChatBinding) Validate() error {
	if b.SchemaVersion != ChatBindingVersion || !identifierRE.MatchString(b.ChatID) || !identifierRE.MatchString(b.GroupID) || b.GroupVersion == 0 || !isDigest(b.GroupDigest) || !isDigest(b.Signature) {
		return ErrInvalidGroup
	}
	return nil
}

// AuthorizeChatBinding is the final boundary check.  It reloads the encrypted
// live state while holding the stable lock, so an old binding, a chat splice,
// a changed group, or a forged signature cannot authorize work.
func (r *Registry) AuthorizeChatBinding(ctx context.Context, expectedChatID string, binding ChatBinding) (SafeProjection, error) {
	if err := ctx.Err(); err != nil {
		return SafeProjection{}, err
	}
	if !identifierRE.MatchString(expectedChatID) || binding.ChatID != expectedChatID || binding.Validate() != nil {
		return SafeProjection{}, ErrBindingUnauthorized
	}
	var projection SafeProjection
	err := r.withLock(func() error {
		if err := r.load(); err != nil {
			return err
		}
		if !hmac.Equal([]byte(binding.Signature), []byte(r.signBinding(binding))) {
			return ErrBindingUnauthorized
		}
		g, ok := r.snap.Groups[binding.GroupID]
		if !ok || g.Version != binding.GroupVersion || g.Digest != binding.GroupDigest {
			return ErrBindingUnauthorized
		}
		projection = projectionForPublic(publicGroup(g))
		return nil
	})
	return projection, err
}

func (r *Registry) signBinding(b ChatBinding) string {
	mac := hmac.New(sha256.New, r.key)
	_, _ = io.WriteString(mac, b.SchemaVersion+"\x00"+b.ChatID+"\x00"+b.GroupID+"\x00"+fmt.Sprintf("%d", b.GroupVersion)+"\x00"+b.GroupDigest)
	return "sha256:" + hex.EncodeToString(mac.Sum(nil))
}

func (r *Registry) transact(ctx context.Context, expected uint64, id string, fn func(*snapshot) (WorkspaceGroup, error)) (WorkspaceGroup, error) {
	if err := ctx.Err(); err != nil {
		return WorkspaceGroup{}, err
	}
	var out WorkspaceGroup
	err := r.withLock(func() error {
		if e := r.load(); e != nil {
			return e
		}
		if expected > 0 && r.snap.Version < expected {
			return ErrStaleVersion
		}
		next := cloneSnapshot(r.snap)
		var e error
		out, e = fn(&next)
		if e != nil {
			return e
		}
		oldc, e := r.checkpoints.LoadCheckpoint()
		if e != nil {
			return e
		}
		if oldc.Version != r.snap.Version {
			return ErrCheckpointMismatch
		}
		stateDigest := digestSnapshot(next)
		if r.beforePersist != nil {
			r.beforePersist()
		}
		if e = r.verifyLockPath(); e != nil {
			return r.poison(e)
		}
		if e = r.persist(next); e != nil {
			// A failed atomic write may have failed after rename or directory sync,
			// when the caller cannot know which durable state survived.
			return r.poison(e)
		}
		if e = r.verifyLockPath(); e != nil {
			return r.poison(e)
		}
		if e = r.checkpoints.CommitCheckpoint(oldc.Version, Checkpoint{Version: next.Version, StateDigest: stateDigest}); e != nil {
			// The encrypted state may now be ahead of the checkpoint.  Do not let
			// this process continue after an ambiguous durability boundary.
			return r.poison(e)
		}
		if e = r.verifyLockPath(); e != nil {
			return r.poison(e)
		}
		r.snap = next
		return nil
	})
	return out, err
}

func (r *Registry) load() error {
	b, e := readRootFile(r.store.root, r.base, MaxStoreBytes)
	if os.IsNotExist(e) {
		cp, ce := r.checkpoints.LoadCheckpoint()
		if ce != nil {
			return ce
		}
		if cp.Version != 0 || cp.StateDigest != "" {
			return ErrCheckpointMismatch
		}
		return nil
	}
	if e != nil {
		return e
	}
	if len(b) > MaxStoreBytes {
		return ErrLimit
	}
	var env envelope
	if e = decodeStrict(b, &env); e != nil || env.SchemaVersion != SchemaVersion {
		return ErrIntegrity
	}
	plain, e := openEnvelope(env, r.key)
	if e != nil {
		return ErrIntegrity
	}
	var s snapshot
	if e = decodeStrict(plain, &s); e != nil || s.SchemaVersion != SchemaVersion || s.Groups == nil || len(s.Groups) > MaxGroups {
		return ErrIntegrity
	}
	for id, g := range s.Groups {
		if id != g.GroupID || r.validateGroup(g) != nil || g.Digest != digestGroup(g) {
			return ErrIntegrity
		}
	}
	cp, ce := r.checkpoints.LoadCheckpoint()
	if ce != nil {
		return ce
	}
	if s.LockDevice != r.lockID.Device || s.LockInode != r.lockID.Inode {
		return ErrUnsafePath
	}
	if s.Version == 0 {
		if cp.Version != 0 || cp.StateDigest != "" {
			return ErrCheckpointMismatch
		}
	} else if cp.Version != s.Version || cp.StateDigest != digestSnapshot(s) {
		return ErrCheckpointMismatch
	}
	r.snap = s
	return nil
}

func (r *Registry) withLock(fn func() error) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.poisoned {
		return ErrUnsafePath
	}
	if err := verifyTrustedStoreRoot(r.store); err != nil {
		return err
	}
	for _, allowed := range r.allowed {
		if err := verifyAllowedRoot(allowed); err != nil {
			return err
		}
	}
	if err := syscall.Flock(int(r.lockFile.Fd()), syscall.LOCK_EX); err != nil {
		return err
	}
	defer func() { _ = syscall.Flock(int(r.lockFile.Fd()), syscall.LOCK_UN) }()
	if err := r.verifyLockPath(); err != nil {
		return r.poison(err)
	}
	return fn()
}

func (r *Registry) verifyLockPath() error {
	if r.lockFile == nil || r.lockID == (fileIdentity{}) {
		return ErrUnsafePath
	}
	if err := validatePrivateRegular(r.store.root, r.lockFile, r.base+".lock"); err != nil {
		return err
	}
	fi, err := r.store.root.Lstat(r.base + ".lock")
	if err != nil {
		return ErrUnsafePath
	}
	id, err := identityOf(fi)
	if err != nil || id != r.lockID {
		return ErrUnsafePath
	}
	return nil
}

func (r *Registry) poison(err error) error {
	r.poisoned = true
	if errors.Is(err, ErrUnsafePath) {
		return ErrUnsafePath
	}
	return err
}

func safeWorkspaceBase(path string) bool {
	if hasUnsafePathComponent(path) {
		return false
	}
	clean := filepath.Clean(path)
	if clean == "/" || !filepath.IsAbs(clean) {
		return false
	}
	// Capability bases are intentionally much narrower than a filesystem root.
	// In particular, removable/network devices and broad OS trees must never be
	// made ambient merely by minting an AllowedRoot capability.
	for _, protected := range []string{"/dev", "/Volumes", "/Network", "/home", "/System", "/Library", "/Applications", "/bin", "/sbin", "/usr", "/etc", "/opt"} {
		if clean == protected || strings.HasPrefix(clean, protected+string(filepath.Separator)) {
			return false
		}
	}
	// /private and /var are not general workspace locations.  The only
	// exception is a concrete child of the fixed macOS temporary roots after
	// canonicalMacAlias has resolved /tmp and /var aliases.
	if strings.HasPrefix(clean, "/private") {
		return narrowMacTempBase(clean)
	}
	if strings.HasPrefix(clean, "/var") {
		return false
	}
	if clean == "/Users" {
		return false
	}
	parts := strings.Split(strings.TrimPrefix(clean, "/"), "/")
	if len(parts) >= 1 && parts[0] == "Users" {
		// /Users/<name> is the complete home and therefore an ambient grant;
		// an exact named subtree is the minimum user-scoped capability.
		return len(parts) >= 3 && parts[1] != "" && parts[2] != ""
	}
	return false
}

func narrowMacTempBase(clean string) bool {
	parts := strings.Split(strings.TrimPrefix(clean, "/"), "/")
	// /tmp/foo canonicalizes to /private/tmp/foo.  The root itself remains
	// prohibited; a concrete child is a narrowly scoped temporary base.
	if len(parts) >= 3 && parts[0] == "private" && parts[1] == "tmp" && parts[2] != "" {
		return true
	}
	// macOS's per-user temporary directory is /var/folders/<a>/<b>/T/… and
	// resolves through /private/var.  Require a concrete descendant of T.
	return len(parts) >= 7 && parts[0] == "private" && parts[1] == "var" && parts[2] == "folders" && parts[3] != "" && parts[4] != "" && parts[5] == "T" && parts[6] != ""
}

func hasUnsafePathComponent(path string) bool {
	for _, component := range strings.Split(path, string(filepath.Separator)) {
		if component == "." || component == ".." {
			return true
		}
	}
	return false
}

func canonicalMacAlias(path string) string {
	clean := filepath.Clean(path)
	if clean == "/var" || strings.HasPrefix(clean, "/var/") {
		return "/private" + clean
	}
	if clean == "/tmp" || strings.HasPrefix(clean, "/tmp/") {
		return "/private/tmp" + strings.TrimPrefix(clean, "/tmp")
	}
	return clean
}

func openTrustedStoreRoot(path string) (trustedRoot, error) {
	if hasUnsafePathComponent(path) {
		return trustedRoot{}, ErrUnsafePath
	}
	path = canonicalMacAlias(path)
	root, err := openNoFollowRoot(path)
	if err != nil {
		return trustedRoot{}, err
	}
	fi, err := root.Lstat(".")
	if err != nil || !fi.IsDir() || fi.Mode().Perm()&0077 != 0 {
		_ = root.Close()
		return trustedRoot{}, fmt.Errorf("%w: store root metadata %v %v", ErrUnsafePath, err, fi.Mode())
	}
	id, err := identityOf(fi)
	if err != nil {
		_ = root.Close()
		return trustedRoot{}, err
	}
	return trustedRoot{path: filepath.Clean(path), root: root, id: id}, nil
}

func verifyTrustedStoreRoot(expected trustedRoot) error {
	fresh, err := openTrustedStoreRoot(expected.path)
	if err != nil {
		return ErrUnsafePath
	}
	defer fresh.root.Close()
	if fresh.id != expected.id {
		return ErrUnsafePath
	}
	return nil
}

func verifyAllowedRoot(expected trustedRoot) error {
	fresh, err := openNoFollowRoot(expected.path)
	if err != nil {
		return ErrUnsafePath
	}
	defer fresh.Close()
	fi, err := fresh.Lstat(".")
	if err != nil || !fi.IsDir() {
		return ErrUnsafePath
	}
	id, err := identityOf(fi)
	if err != nil || id != expected.id {
		return ErrUnsafePath
	}
	return nil
}

func validateAllowedCapability(root trustedRoot) error {
	if root.root == nil || root.id == (fileIdentity{}) || hasUnsafePathComponent(root.path) || !safeWorkspaceBase(root.path) {
		return ErrUnsafePath
	}
	fi, err := root.root.Lstat(".")
	if err != nil || !fi.IsDir() {
		return ErrUnsafePath
	}
	id, err := identityOf(fi)
	if err != nil || id != root.id {
		return ErrUnsafePath
	}
	return nil
}

func openNoFollowRoot(path string) (*os.Root, error) {
	if hasUnsafePathComponent(path) {
		return nil, ErrUnsafePath
	}
	path = canonicalMacAlias(path)
	if !filepath.IsAbs(path) || path != filepath.Clean(path) {
		return nil, ErrUnsafePath
	}
	root, err := os.OpenRoot("/")
	if err != nil {
		return nil, err
	}
	for _, component := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
		if component == "" || component == "." || component == ".." {
			_ = root.Close()
			return nil, fmt.Errorf("%w: invalid component", ErrUnsafePath)
		}
		fi, err := root.Lstat(component)
		if err != nil || !fi.IsDir() || fi.Mode()&os.ModeSymlink != 0 {
			_ = root.Close()
			return nil, fmt.Errorf("%w: directory component %q", ErrUnsafePath, component)
		}
		next, err := root.OpenRoot(component)
		_ = root.Close()
		if err != nil {
			return nil, fmt.Errorf("%w: open directory component %q: %v", ErrUnsafePath, component, err)
		}
		root = next
	}
	return root, nil
}

func openDescendantRoot(base *os.Root, rel string) (*os.Root, error) {
	if rel == "." {
		return base.OpenRoot(".")
	}
	root, err := base.OpenRoot(".")
	if err != nil {
		return nil, ErrUnsafePath
	}
	for _, component := range strings.Split(rel, "/") {
		if component == "" || component == "." || component == ".." {
			_ = root.Close()
			return nil, ErrUnsafePath
		}
		fi, err := root.Lstat(component)
		if err != nil || !fi.IsDir() || fi.Mode()&os.ModeSymlink != 0 {
			_ = root.Close()
			return nil, ErrUnsafePath
		}
		next, err := root.OpenRoot(component)
		_ = root.Close()
		if err != nil {
			return nil, ErrUnsafePath
		}
		root = next
	}
	return root, nil
}

func identityOf(fi os.FileInfo) (fileIdentity, error) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || st.Dev == 0 || st.Ino == 0 {
		return fileIdentity{}, ErrUnsafePath
	}
	return fileIdentity{Device: uint64(st.Dev), Inode: uint64(st.Ino)}, nil
}

func validatePrivateRegular(root *os.Root, f *os.File, name string) error {
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() || fi.Mode().Perm()&0077 != 0 {
		return ErrUnsafePath
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != uint32(os.Getuid()) || st.Nlink != 1 {
		return ErrUnsafePath
	}
	pathInfo, err := root.Lstat(name)
	if err != nil || pathInfo.Mode()&os.ModeSymlink != 0 || !os.SameFile(fi, pathInfo) {
		return ErrUnsafePath
	}
	return nil
}

func readRootFile(root *os.Root, name string, limit int64) ([]byte, error) {
	fi, err := root.Lstat(name)
	if err != nil {
		return nil, err
	}
	if fi.Mode()&os.ModeSymlink != 0 || !fi.Mode().IsRegular() {
		return nil, ErrUnsafePath
	}
	f, err := root.OpenFile(name, os.O_RDONLY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if err := validatePrivateRegular(root, f, name); err != nil {
		return nil, err
	}
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(b)) > limit {
		return nil, ErrLimit
	}
	return b, nil
}

func atomicRootWrite(root *os.Root, base string, contents []byte) error {
	if fi, err := root.Lstat(base); err == nil && (fi.Mode()&os.ModeSymlink != 0 || !fi.Mode().IsRegular()) {
		return ErrUnsafePath
	} else if err != nil && !os.IsNotExist(err) {
		return err
	}
	random := make([]byte, 12)
	if _, err := rand.Read(random); err != nil {
		return err
	}
	tmp := "." + base + ".tmp-" + hex.EncodeToString(random)
	f, err := root.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_CLOEXEC, 0600)
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		_ = f.Close()
		if !ok {
			_ = root.Remove(tmp)
		}
	}()
	if err = validatePrivateRegular(root, f, tmp); err != nil {
		return err
	}
	if _, err = f.Write(contents); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = root.Rename(tmp, base); err != nil {
		return err
	}
	dir, err := root.Open(".")
	if err != nil {
		return err
	}
	defer dir.Close()
	if err = dir.Sync(); err != nil {
		return err
	}
	ok = true
	return nil
}

func decodeStrict(b []byte, v any) error {
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		return err
	}
	var extra any
	if err := d.Decode(&extra); err != io.EOF {
		if err == nil {
			return ErrIntegrity
		}
		return err
	}
	return nil
}

func (r *Registry) persist(s snapshot) error {
	plain, _ := json.Marshal(s)
	block, e := aes.NewCipher(r.key)
	if e != nil {
		return e
	}
	g, e := cipher.NewGCM(block)
	if e != nil {
		return e
	}
	nonce := make([]byte, g.NonceSize())
	if _, e = io.ReadFull(rand.Reader, nonce); e != nil {
		return e
	}
	env := envelope{SchemaVersion: SchemaVersion, Nonce: hex.EncodeToString(nonce), Ciphertext: hex.EncodeToString(g.Seal(nil, nonce, plain, nil))}
	b, _ := json.Marshal(env)
	return atomicRootWrite(r.store.root, r.base, b)
}
func openEnvelope(env envelope, key []byte) ([]byte, error) {
	block, e := aes.NewCipher(key)
	if e != nil {
		return nil, e
	}
	g, e := cipher.NewGCM(block)
	if e != nil {
		return nil, e
	}
	n, e := hex.DecodeString(env.Nonce)
	if e != nil || len(n) != g.NonceSize() {
		return nil, ErrIntegrity
	}
	c, e := hex.DecodeString(env.Ciphertext)
	if e != nil || len(c) > MaxStoreBytes {
		return nil, ErrIntegrity
	}
	return g.Open(nil, n, c, nil)
}

func (r *Registry) normalizeSpec(s GroupSpec) ([]rootState, string, error) {
	if len(s.Roots) == 0 || len(s.Roots) > MaxRootsPerGroup || !validLabel(s.DisplayLabel) {
		return nil, "", ErrInvalidGroup
	}
	if len(s.BeadsCapabilityRefs) > MaxCapabilityRefs {
		return nil, "", ErrLimit
	}
	seen := map[string]bool{}
	roots := make([]rootState, 0, len(s.Roots))
	var primary string
	for _, x := range s.Roots {
		if !validLabel(x.Label) || x.Mode != ReadMode && x.Mode != WriteMode {
			return nil, "", ErrInvalidGroup
		}
		p, identity, e := r.resolveAllowedRoot(x.Path)
		if e != nil {
			return nil, "", e
		}
		identityKey := fmt.Sprintf("%d:%d", identity.Device, identity.Inode)
		if seen[identityKey] {
			return nil, "", ErrUnsafePath
		}
		seen[identityKey] = true
		id := opaqueID("root")
		roots = append(roots, rootState{WorkspaceRoot: WorkspaceRoot{RootID: id, Label: x.Label, Mode: x.Mode}, canonicalPath: p, Device: identity.Device, Inode: identity.Inode})
		if s.PrimaryLabel == x.Label {
			if primary != "" {
				return nil, "", ErrInvalidGroup
			}
			primary = id
		}
	}
	if primary == "" {
		primary = roots[0].RootID
	}
	for i := range roots {
		for j := range roots {
			if i != j && r.rootsOverlap(roots[i], roots[j]) {
				return nil, "", ErrUnsafePath
			}
		}
	}
	for _, c := range s.BeadsCapabilityRefs {
		if len(c) == 0 || len(c) > MaxCapabilityRefLen || !identifierRE.MatchString(c) {
			return nil, "", ErrInvalidGroup
		}
	}
	if s.BeadsScopeRef != "" && !identifierRE.MatchString(s.BeadsScopeRef) {
		return nil, "", ErrInvalidGroup
	}
	return roots, primary, nil
}
func (r *Registry) resolveAllowedRoot(raw string) (string, fileIdentity, error) {
	if hasUnsafePathComponent(raw) {
		return "", fileIdentity{}, ErrUnsafePath
	}
	raw = canonicalMacAlias(raw)
	if raw == "" || !filepath.IsAbs(raw) || raw != filepath.Clean(raw) || !safeWorkspaceBase(raw) {
		return "", fileIdentity{}, ErrUnsafePath
	}
	for _, allowed := range r.allowed {
		rel, ok := relativeTo(allowed.path, raw)
		if !ok {
			continue
		}
		if rel == "." {
			fi, err := allowed.root.Lstat(".")
			if err != nil || !fi.IsDir() {
				return "", fileIdentity{}, ErrUnsafePath
			}
			identity, err := identityOf(fi)
			if err != nil {
				return "", fileIdentity{}, err
			}
			return raw, identity, nil
		}
		candidate, err := openDescendantRoot(allowed.root, rel)
		if err != nil {
			return "", fileIdentity{}, err
		}
		fi, err := candidate.Lstat(".")
		_ = candidate.Close()
		if err != nil || !fi.IsDir() {
			return "", fileIdentity{}, ErrUnsafePath
		}
		identity, err := identityOf(fi)
		if err != nil {
			return "", fileIdentity{}, err
		}
		return raw, identity, nil
	}
	return "", fileIdentity{}, ErrUnsafePath
}

func relativeTo(base, target string) (string, bool) {
	if target == base {
		return ".", true
	}
	if strings.HasPrefix(target, base+string(filepath.Separator)) {
		return strings.TrimPrefix(target, base+string(filepath.Separator)), true
	}
	return "", false
}
func isAncestor(a, b string) bool {
	return a != b && strings.HasPrefix(b, a+string(filepath.Separator))
}
func (r *Registry) validateGroup(g storedGroup) error {
	if g.SchemaVersion != SchemaVersion || !identifierRE.MatchString(g.GroupID) || g.Version == 0 || !isDigest(g.Digest) || len(g.Roots) == 0 || len(g.Roots) > MaxRootsPerGroup || !validLabel(g.DisplayLabel) {
		return ErrInvalidGroup
	}
	if len(g.BeadsCapabilityRefs) > MaxCapabilityRefs || (g.BeadsScopeRef != "" && !identifierRE.MatchString(g.BeadsScopeRef)) {
		return ErrInvalidGroup
	}
	capabilities := map[string]bool{}
	for _, capability := range g.BeadsCapabilityRefs {
		if len(capability) == 0 || len(capability) > MaxCapabilityRefLen || !identifierRE.MatchString(capability) || capabilities[capability] {
			return ErrInvalidGroup
		}
		capabilities[capability] = true
	}
	seen := map[string]bool{}
	primary := false
	for _, storedRoot := range g.Roots {
		if !identifierRE.MatchString(storedRoot.RootID) || seen[storedRoot.RootID] || !validLabel(storedRoot.Label) || storedRoot.Mode != ReadMode && storedRoot.Mode != WriteMode || storedRoot.Device == 0 || storedRoot.Inode == 0 {
			return ErrInvalidGroup
		}
		_, current, err := r.resolveAllowedRoot(storedRoot.canonicalPath)
		if err != nil || current.Device != storedRoot.Device || current.Inode != storedRoot.Inode {
			return ErrUnsafePath
		}
		seen[storedRoot.RootID] = true
		if storedRoot.RootID == g.PrimaryRootID {
			primary = true
		}
	}
	if !primary {
		return ErrInvalidGroup
	}
	for i := range g.Roots {
		for j := i + 1; j < len(g.Roots); j++ {
			if r.rootsOverlap(g.Roots[i], g.Roots[j]) {
				return ErrUnsafePath
			}
		}
	}
	return nil
}
func (r *Registry) rootsOverlap(a, b rootState) bool {
	if a.Device == b.Device && a.Inode == b.Inode {
		return true
	}
	return isAncestor(a.canonicalPath, b.canonicalPath) || isAncestor(b.canonicalPath, a.canonicalPath)
}
func digestGroup(g storedGroup) string {
	u := g
	u.Digest = ""
	b, _ := json.Marshal(u)
	h := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(h[:])
}
func digestSnapshot(s snapshot) string {
	b, _ := json.Marshal(s)
	h := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(h[:])
}
func isDigest(s string) bool {
	return len(s) == 71 && strings.HasPrefix(s, "sha256:") && regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(s[7:])
}
func validLabel(s string) bool { return len(s) <= MaxLabelBytes && labelRE.MatchString(s) }
func opaqueID(prefix string) string {
	b := make([]byte, 16)
	_, _ = io.ReadFull(rand.Reader, b)
	return prefix + ":" + hex.EncodeToString(b)
}
func publicGroup(g storedGroup) WorkspaceGroup {
	roots := make([]WorkspaceRoot, len(g.Roots))
	for i, root := range g.Roots {
		roots[i] = root.WorkspaceRoot
	}
	return WorkspaceGroup{SchemaVersion: g.SchemaVersion, GroupID: g.GroupID, DisplayLabel: g.DisplayLabel, PrimaryRootID: g.PrimaryRootID, Roots: roots, BeadsScopeRef: g.BeadsScopeRef, BeadsCapabilityRefs: append([]string(nil), g.BeadsCapabilityRefs...), Version: g.Version, Digest: g.Digest, UpdatedAt: g.UpdatedAt}
}
func projectionForPublic(g WorkspaceGroup) SafeProjection {
	p := SafeProjection{SchemaVersion: g.SchemaVersion, GroupID: g.GroupID, DisplayLabel: g.DisplayLabel, PrimaryRootID: g.PrimaryRootID, Version: g.Version, Digest: g.Digest, UpdatedAt: g.UpdatedAt}
	for _, root := range g.Roots {
		p.Roots = append(p.Roots, RootProjection{RootID: root.RootID, Label: root.Label, Mode: root.Mode})
	}
	return p
}
func cloneGroup(g storedGroup) storedGroup {
	g.Roots = append([]rootState(nil), g.Roots...)
	g.BeadsCapabilityRefs = append([]string(nil), g.BeadsCapabilityRefs...)
	return g
}
func cloneSnapshot(s snapshot) snapshot {
	n := snapshot{SchemaVersion: s.SchemaVersion, Version: s.Version, LockDevice: s.LockDevice, LockInode: s.LockInode, Groups: make(map[string]storedGroup, len(s.Groups))}
	for k, v := range s.Groups {
		n.Groups[k] = cloneGroup(v)
	}
	return n
}
