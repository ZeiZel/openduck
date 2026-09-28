// Package providerdaemon contains the disabled-by-default provider runtime.
package providerdaemon

import (
	"bytes"
	"context"
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
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	MaxReceipts = 256
	// stateSchemaV1 is deliberately rejected. Compensating carries a durable
	// provider handle, and there is no safe way to infer that intent from v1's
	// Uncertain state. Deployments must start from an empty verified root rather
	// than silently reinterpret legacy state.
	stateSchemaV1      = "provider-daemon-state.v1"
	stateSchemaV2      = "provider-daemon-state.v2"
	enablementSchemaV1 = "provider-daemon-enablement.v1"
	maxStateBytes      = 1 << 20
	maxIDBytes         = 128
	maxOpaqueBytes     = 256
)

// EnablementSchemaV1 is exported solely for a composition root constructing a
// signed, verified enablement proof. It does not grant enablement by itself.
const EnablementSchemaV1 = enablementSchemaV1

var (
	ErrDisabled        = errors.New("provider daemon disabled")
	ErrUnavailable     = errors.New("provider daemon unavailable")
	ErrCorrupt         = errors.New("provider daemon state corrupt")
	ErrExpired         = errors.New("provider daemon receipt expired")
	ErrConflict        = errors.New("provider daemon identity conflict")
	ErrInvalidState    = errors.New("provider daemon invalid state")
	ErrCapacity        = errors.New("provider daemon receipt capacity exhausted")
	ErrInFlight        = errors.New("provider daemon operation in flight")
	ErrCommitUncertain = errors.New("provider daemon commit uncertain")
)

type State string

const (
	Starting  State = "starting"
	Running   State = "running"
	Terminal  State = "terminal"
	Uncertain State = "uncertain"
	// Compensating means a provider session is known and only teardown is
	// permitted. It is durable before Stop is invoked so a restart never starts
	// a second session while attempting cleanup.
	Compensating State = "compensating"
)

// Identity contains only opaque digests and references, never task text or credentials.
type Identity struct {
	Profile  string `json:"profile"`
	Revision string `json:"revision"`
	Mapping  string `json:"mapping"`
	Runtime  string `json:"runtime"`
	Protocol string `json:"protocol"`
	// Request is the daemon operation identity.  It is intentionally not the
	// transport wire digest: the latter is retained below as an independent
	// value so a caller cannot substitute one for the other after a restart.
	Request string `json:"request"`
	Route   string `json:"route"`
	Binding string `json:"binding"`

	// The following fields are either all absent for the legacy, local-only
	// Core API or all present for the providertransport adapter.  They retain
	// the exact authenticated transport Start tuple alongside Request above.
	// No prompt, credential, command line, or account text is representable.
	WireRequest string `json:"wire_request,omitempty"`
	WireDigest  string `json:"wire_digest,omitempty"`
	Order       string `json:"order,omitempty"`
	OrderHash   string `json:"order_hash,omitempty"`
	BindingID   string `json:"binding_id,omitempty"`
	BindingHash string `json:"binding_hash,omitempty"`
	Run         string `json:"run,omitempty"`
	Attempt     string `json:"attempt,omitempty"`
}

func (i Identity) static() Identity {
	i.Request, i.Binding = "", ""
	i.WireRequest, i.WireDigest = "", ""
	i.Order, i.OrderHash, i.BindingID, i.BindingHash, i.Run, i.Attempt = "", "", "", "", "", ""
	return i
}

func (i Identity) hasTransportBinding() bool {
	return i.WireRequest != "" || i.WireDigest != "" || i.Order != "" || i.OrderHash != "" || i.BindingID != "" || i.BindingHash != "" || i.Run != "" || i.Attempt != ""
}

func (i Identity) validTransportBinding() bool {
	if !i.hasTransportBinding() {
		return true
	}
	return safeOpaque(i.WireRequest, maxIDBytes) && validDigest(i.WireDigest) && safeOpaque(i.Order, maxIDBytes) && safeOpaque(i.OrderHash, maxIDBytes) && safeOpaque(i.BindingID, maxIDBytes) && safeOpaque(i.BindingHash, maxIDBytes) && safeOpaque(i.Run, maxIDBytes) && safeOpaque(i.Attempt, maxIDBytes) && i.Binding == i.BindingHash
}

type Descriptor struct {
	Provider, Profile, Revision, MappingDigest, RuntimeDigest, ProtocolDigest string
	RootDescriptorPath, ReleaseFactPath, KeyFactPath, EnablementDigest        string
}

func (d Descriptor) identity() Identity {
	return Identity{Profile: d.Profile, Revision: d.Revision, Mapping: d.MappingDigest, Runtime: d.RuntimeDigest, Protocol: d.ProtocolDigest, Route: d.Provider}
}

type descriptorBody struct {
	Provider string `json:"provider"`
	Profile  string `json:"profile"`
	Revision string `json:"revision"`
	Mapping  string `json:"mapping"`
	Runtime  string `json:"runtime"`
	Protocol string `json:"protocol"`
	Root     string `json:"root"`
	Release  string `json:"release"`
	Key      string `json:"key"`
}

func descriptorDigest(d Descriptor) string {
	b, _ := json.Marshal(descriptorBody{d.Provider, d.Profile, d.Revision, d.MappingDigest, d.RuntimeDigest, d.ProtocolDigest, d.RootDescriptorPath, d.ReleaseFactPath, d.KeyFactPath})
	return digestBytes(b)
}

// DescriptorDigest returns the non-secret descriptor binding used by a
// separately verified EnablementProof. Callers still need VerifyEnablement;
// knowing this digest is not authority to create an enabled Core.
func DescriptorDigest(d Descriptor) string { return descriptorDigest(d) }

type Request struct {
	ID        string    `json:"id"`
	Identity  Identity  `json:"identity"`
	ExpiresAt time.Time `json:"expires_at"`
}

func RequestDigest(r Request) string {
	r.Identity.Request = ""
	b, _ := json.Marshal(r)
	return digestBytes(b)
}

type Receipt struct {
	ID        string    `json:"id"`
	Identity  Identity  `json:"identity"`
	State     State     `json:"state"`
	Session   string    `json:"session,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type Bridge interface {
	// Start and Reconcile may return a safe, non-empty session together with an
	// error when the provider performed native work but could not complete its
	// acknowledgement. Such a session is still authoritative cleanup evidence:
	// Core persists Compensating before it invokes Stop and preserves the
	// provider error. Implementations must never return credential or task text
	// as a session, including on an error path.
	Start(context.Context, Request) (string, error)
	Reconcile(context.Context, Receipt) (string, State, error)
	Stop(context.Context, string) error
}
type unavailableBridge struct{}

func (unavailableBridge) Start(context.Context, Request) (string, error) { return "", ErrUnavailable }
func (unavailableBridge) Reconcile(context.Context, Receipt) (string, State, error) {
	return "", Uncertain, ErrUnavailable
}
func (unavailableBridge) Stop(context.Context, string) error { return ErrUnavailable }

// HighWater is an independent rollback anchor. Advance is atomic compare-and-set.
type HighWater interface {
	Current(context.Context) (uint64, string, error)
	Advance(context.Context, uint64, uint64, string) error
}
type StoreConfig struct {
	RootPath, StateLeaf, LockLeaf      string
	OwnerUID, OwnerGID                 uint32
	KeyEpoch                           uint64
	DescriptorDigest, EnablementDigest string
	HighWater                          HighWater
	hooks                              storeHooks
}
type storeHooks struct{ afterRootOpen, beforeStateOpen, afterStateOpen, beforeRename, afterRename func() }
type diskBody struct {
	SchemaVersion    string    `json:"schema_version"`
	Generation       uint64    `json:"generation"`
	PreviousDigest   string    `json:"previous_digest"`
	DescriptorDigest string    `json:"descriptor_digest"`
	EnablementDigest string    `json:"enablement_digest"`
	KeyEpoch         uint64    `json:"key_epoch"`
	Receipts         []Receipt `json:"receipts"`
}
type diskState struct {
	Body diskBody `json:"body"`
	MAC  string   `json:"mac"`
}
type Store struct {
	config           StoreConfig
	root             *os.Root
	lock             *os.File
	key              []byte
	mu               sync.Mutex
	receipts         map[string]Receipt
	generation       uint64
	stateDigest      string
	closed, poisoned bool
}

// OpenStore requires an already-created private root and retains a lifetime flock.
func OpenStore(c StoreConfig, key []byte) (*Store, error) {
	if !validStoreConfig(c) || len(key) != sha256.Size || ensureNoSymlinkComponents(c.RootPath) != nil {
		return nil, ErrUnavailable
	}
	named, e := os.Lstat(c.RootPath)
	if e != nil || !safeDir(named, c.OwnerUID, c.OwnerGID) {
		return nil, ErrUnavailable
	}
	r, e := os.OpenRoot(c.RootPath)
	if e != nil {
		return nil, ErrUnavailable
	}
	fail := func(x error) (*Store, error) { _ = r.Close(); return nil, x }
	if c.hooks.afterRootOpen != nil {
		c.hooks.afterRootOpen()
	}
	opened, e := r.Stat(".")
	if e != nil || !safeDir(opened, c.OwnerUID, c.OwnerGID) || !sameFile(named, opened) || !namedRootIs(c, opened) {
		return fail(ErrUnavailable)
	}
	l, e := r.OpenFile(c.LockLeaf, os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if e != nil {
		return fail(ErrUnavailable)
	}
	li, se := l.Stat()
	ln, ne := r.Lstat(c.LockLeaf)
	if se != nil || ne != nil || !safeFile(li, c.OwnerUID, c.OwnerGID, 0600) || !safeFile(ln, c.OwnerUID, c.OwnerGID, 0600) || !sameFile(li, ln) {
		_ = l.Close()
		return fail(ErrUnavailable)
	}
	if e = syscall.Flock(int(l.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); e != nil {
		_ = l.Close()
		return fail(ErrUnavailable)
	}
	s := &Store{config: c, root: r, lock: l, key: append([]byte(nil), key...), receipts: map[string]Receipt{}}
	if e = s.loadLocked(context.Background()); e != nil {
		_ = s.Close()
		return nil, e
	}
	return s, nil
}
func validStoreConfig(c StoreConfig) bool {
	return filepath.IsAbs(c.RootPath) && filepath.Clean(c.RootPath) == c.RootPath && safeLeaf(c.StateLeaf) && safeLeaf(c.LockLeaf) && c.StateLeaf != c.LockLeaf && c.KeyEpoch > 0 && validDigest(c.DescriptorDigest) && validDigest(c.EnablementDigest) && c.HighWater != nil
}
func ensureNoSymlinkComponents(path string) error {
	prefix := "/"
	for _, part := range strings.Split(strings.TrimPrefix(filepath.Clean(path), "/"), "/") {
		if part == "" {
			continue
		}
		prefix = filepath.Join(prefix, part)
		i, e := os.Lstat(prefix)
		if e != nil || i.Mode()&os.ModeSymlink != 0 {
			return ErrUnavailable
		}
	}
	return nil
}
func namedRootIs(c StoreConfig, want os.FileInfo) bool {
	i, e := os.Lstat(c.RootPath)
	return e == nil && safeDir(i, c.OwnerUID, c.OwnerGID) && sameFile(i, want)
}
func (s *Store) validateRootLocked() error {
	if s == nil || s.closed || s.poisoned || s.root == nil {
		return ErrUnavailable
	}
	ri, e := s.root.Stat(".")
	if e != nil || !safeDir(ri, s.config.OwnerUID, s.config.OwnerGID) || !namedRootIs(s.config, ri) {
		return ErrUnavailable
	}
	li, e := s.lock.Stat()
	ln, ne := s.root.Lstat(s.config.LockLeaf)
	if e != nil || ne != nil || !safeFile(li, s.config.OwnerUID, s.config.OwnerGID, 0600) || !safeFile(ln, s.config.OwnerUID, s.config.OwnerGID, 0600) || !sameFile(li, ln) {
		return ErrUnavailable
	}
	return nil
}

func (s *Store) loadLocked(ctx context.Context) error {
	if e := s.validateRootLocked(); e != nil {
		return e
	}
	raw, e := secureReadState(s)
	if errors.Is(e, os.ErrNotExist) {
		g, d, a := s.config.HighWater.Current(ctx)
		if a != nil || g != 0 || d != "" {
			return ErrCorrupt
		}
		return nil
	}
	if e != nil {
		return e
	}
	d, e := decodeDiskState(raw, s.key, s.config)
	if e != nil {
		return e
	}
	fd := digestBytes(raw)
	ag, ad, e := s.config.HighWater.Current(ctx)
	if e != nil {
		return ErrUnavailable
	}
	if ag == d.Body.Generation && ad == fd {
	} else if d.Body.Generation == ag+1 && d.Body.PreviousDigest == ad {
		if e = s.config.HighWater.Advance(ctx, ag, d.Body.Generation, fd); e != nil {
			return ErrCommitUncertain
		}
	} else {
		return ErrCorrupt
	}
	for _, x := range d.Body.Receipts {
		s.receipts[x.ID] = x
	}
	s.generation = d.Body.Generation
	s.stateDigest = fd
	return nil
}
func secureReadState(s *Store) ([]byte, error) {
	if s.config.hooks.beforeStateOpen != nil {
		s.config.hooks.beforeStateOpen()
	}
	before, e := s.root.Lstat(s.config.StateLeaf)
	if e != nil {
		return nil, e
	}
	if !safeFile(before, s.config.OwnerUID, s.config.OwnerGID, 0600) || before.Size() < 1 || before.Size() > maxStateBytes {
		return nil, ErrCorrupt
	}
	f, e := s.root.Open(s.config.StateLeaf)
	if e != nil {
		return nil, ErrCorrupt
	}
	defer f.Close()
	if s.config.hooks.afterStateOpen != nil {
		s.config.hooks.afterStateOpen()
	}
	after, e := f.Stat()
	if e != nil || !safeFile(after, s.config.OwnerUID, s.config.OwnerGID, 0600) || !sameFile(before, after) || after.Size() != before.Size() {
		return nil, ErrCorrupt
	}
	raw, e := io.ReadAll(io.LimitReader(f, maxStateBytes+1))
	if e != nil || len(raw) == 0 || len(raw) > maxStateBytes || int64(len(raw)) != after.Size() {
		return nil, ErrCorrupt
	}
	named, e := s.root.Lstat(s.config.StateLeaf)
	if e != nil || !safeFile(named, s.config.OwnerUID, s.config.OwnerGID, 0600) || !sameFile(before, named) {
		return nil, ErrCorrupt
	}
	return raw, nil
}
func decodeDiskState(raw, key []byte, c StoreConfig) (diskState, error) {
	if len(raw) == 0 || len(raw) > maxStateBytes || !json.Valid(raw) {
		return diskState{}, ErrCorrupt
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var d diskState
	if e := dec.Decode(&d); e != nil || dec.Decode(&struct{}{}) != io.EOF {
		return diskState{}, ErrCorrupt
	}
	canonical, e := json.Marshal(d)
	if e != nil || !bytes.Equal(raw, canonical) {
		return diskState{}, ErrCorrupt
	}
	body, _ := json.Marshal(d.Body)
	m := hmac.New(sha256.New, key)
	_, _ = m.Write(body)
	want := hex.EncodeToString(m.Sum(nil))
	if !hmac.Equal([]byte(want), []byte(d.MAC)) || d.Body.SchemaVersion != stateSchemaV2 || d.Body.Generation == 0 || d.Body.DescriptorDigest != c.DescriptorDigest || d.Body.EnablementDigest != c.EnablementDigest || d.Body.KeyEpoch != c.KeyEpoch || len(d.Body.Receipts) > MaxReceipts {
		return diskState{}, ErrCorrupt
	}
	if (d.Body.Generation == 1 && d.Body.PreviousDigest != "") || (d.Body.Generation > 1 && !validDigest(d.Body.PreviousDigest)) {
		return diskState{}, ErrCorrupt
	}
	for i, x := range d.Body.Receipts {
		if x.validate() != nil || (i > 0 && d.Body.Receipts[i-1].ID >= x.ID) {
			return diskState{}, ErrCorrupt
		}
	}
	return d, nil
}

func (s *Store) saveLocked(ctx context.Context, candidate map[string]Receipt) error {
	if e := s.validateRootLocked(); e != nil {
		return e
	}
	if len(candidate) > MaxReceipts {
		return ErrCapacity
	}
	if e := s.verifyCurrentLocked(); e != nil {
		s.poisoned = true
		return e
	}
	anchorGeneration, anchorDigest, anchorErr := s.config.HighWater.Current(ctx)
	if anchorErr != nil || anchorGeneration != s.generation || anchorDigest != s.stateDigest {
		s.poisoned = true
		return ErrCorrupt
	}
	receipts := sortedReceipts(candidate)
	body := diskBody{stateSchemaV2, s.generation + 1, s.stateDigest, s.config.DescriptorDigest, s.config.EnablementDigest, s.config.KeyEpoch, receipts}
	br, _ := json.Marshal(body)
	m := hmac.New(sha256.New, s.key)
	_, _ = m.Write(br)
	raw, _ := json.Marshal(diskState{body, hex.EncodeToString(m.Sum(nil))})
	committed, e := s.atomicWriteLocked(raw)
	if e != nil {
		if committed {
			s.poisoned = true
			return ErrCommitUncertain
		}
		return e
	}
	digest := digestBytes(raw)
	if e = s.config.HighWater.Advance(ctx, s.generation, body.Generation, digest); e != nil {
		s.poisoned = true
		return ErrCommitUncertain
	}
	s.receipts = candidate
	s.generation = body.Generation
	s.stateDigest = digest
	return nil
}
func (s *Store) verifyCurrentLocked() error {
	if s.generation == 0 {
		if _, e := s.root.Lstat(s.config.StateLeaf); !errors.Is(e, os.ErrNotExist) {
			return ErrCorrupt
		}
		return nil
	}
	raw, e := secureReadState(s)
	if e != nil || digestBytes(raw) != s.stateDigest {
		return ErrCorrupt
	}
	d, e := decodeDiskState(raw, s.key, s.config)
	if e != nil || d.Body.Generation != s.generation {
		return ErrCorrupt
	}
	return nil
}
func (s *Store) atomicWriteLocked(raw []byte) (bool, error) {
	var random [16]byte
	if _, e := rand.Read(random[:]); e != nil {
		return false, e
	}
	leaf := ".provider-state-" + hex.EncodeToString(random[:])
	f, e := s.root.OpenFile(leaf, os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW, 0600)
	if e != nil {
		return false, e
	}
	info, e := f.Stat()
	if e != nil || !safeFile(info, s.config.OwnerUID, s.config.OwnerGID, 0600) {
		_ = f.Close()
		_ = removeIfSame(s.root, leaf, info)
		return false, ErrCorrupt
	}
	failed := true
	defer func() {
		if failed {
			_ = removeIfSame(s.root, leaf, info)
		}
	}()
	if e = writeFull(f, raw); e == nil {
		e = f.Sync()
	}
	after, se := f.Stat()
	ce := f.Close()
	if e != nil || se != nil || ce != nil || !sameFile(info, after) || !safeFile(after, s.config.OwnerUID, s.config.OwnerGID, 0600) || after.Size() != int64(len(raw)) {
		return false, ErrUnavailable
	}
	if s.config.hooks.beforeRename != nil {
		s.config.hooks.beforeRename()
	}
	if s.validateRootLocked() != nil || s.verifyCurrentLocked() != nil {
		return false, ErrCorrupt
	}
	tempNamed, tempErr := s.root.Lstat(leaf)
	if tempErr != nil || !sameFile(info, tempNamed) || !safeFile(tempNamed, s.config.OwnerUID, s.config.OwnerGID, 0600) || tempNamed.Size() != int64(len(raw)) {
		return false, ErrCorrupt
	}
	if e = s.root.Rename(leaf, s.config.StateLeaf); e != nil {
		return false, e
	}
	failed = false
	if s.config.hooks.afterRename != nil {
		s.config.hooks.afterRename()
	}
	final, fe := s.root.Lstat(s.config.StateLeaf)
	if fe != nil || !sameFile(info, final) || !safeFile(final, s.config.OwnerUID, s.config.OwnerGID, 0600) || final.Size() != int64(len(raw)) || s.validateRootLocked() != nil || syncRoot(s.root) != nil {
		return true, ErrCommitUncertain
	}
	return true, nil
}
func writeFull(f *os.File, b []byte) error {
	for len(b) > 0 {
		n, e := f.Write(b)
		if e != nil || n <= 0 {
			return ErrUnavailable
		}
		b = b[n:]
	}
	return nil
}
func syncRoot(root *os.Root) error {
	d, e := root.Open(".")
	if e != nil {
		return e
	}
	e = d.Sync()
	ce := d.Close()
	if e != nil {
		return e
	}
	return ce
}
func removeIfSame(root *os.Root, leaf string, want os.FileInfo) error {
	if root == nil || want == nil {
		return ErrUnavailable
	}
	got, e := root.Lstat(leaf)
	if e != nil || !sameFile(want, got) || !got.Mode().IsRegular() {
		return ErrUnavailable
	}
	return root.Remove(leaf)
}
func (s *Store) Snapshot() []Receipt {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.poisoned {
		return nil
	}
	return sortedReceipts(s.receipts)
}
func (s *Store) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	for i := range s.key {
		s.key[i] = 0
	}
	s.key = nil
	return errors.Join(syscall.Flock(int(s.lock.Fd()), syscall.LOCK_UN), s.lock.Close(), s.root.Close())
}
func sortedReceipts(m map[string]Receipt) []Receipt {
	out := make([]Receipt, 0, len(m))
	for _, x := range m {
		out = append(out, x)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
func cloneReceipts(m map[string]Receipt) map[string]Receipt {
	out := make(map[string]Receipt, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// EnablementProof is an externally signed canonical enablement statement.
type EnablementProof struct {
	SchemaVersion    string    `json:"schema_version"`
	DescriptorDigest string    `json:"descriptor_digest"`
	StaticIdentity   Identity  `json:"static_identity"`
	KeyEpoch         uint64    `json:"key_epoch"`
	SignerKeyID      string    `json:"signer_key_id"`
	IssuedAt         time.Time `json:"issued_at"`
	ExpiresAt        time.Time `json:"expires_at"`
	Revoked          bool      `json:"revoked"`
	Digest           string    `json:"digest"`
	Signature        string    `json:"signature"`
}
type EnablementVerifier interface {
	VerifyEnablement(context.Context, EnablementProof) error
}
type VerifiedEnablement struct {
	descriptor Descriptor
	proof      EnablementProof
	verifier   EnablementVerifier
}

func VerifyEnablement(ctx context.Context, d Descriptor, p EnablementProof, v EnablementVerifier, now time.Time) (VerifiedEnablement, error) {
	if v == nil || validateDescriptor(d) != nil || p.SchemaVersion != enablementSchemaV1 || p.DescriptorDigest != descriptorDigest(d) || p.StaticIdentity != d.identity() || p.StaticIdentity.Request != "" || p.StaticIdentity.Binding != "" || p.KeyEpoch == 0 || !safeOpaque(p.SignerKeyID, maxIDBytes) || p.Revoked || p.IssuedAt.IsZero() || p.IssuedAt.After(now.UTC()) || !p.ExpiresAt.After(now.UTC()) || !p.ExpiresAt.After(p.IssuedAt) || p.ExpiresAt.Sub(p.IssuedAt) > 24*time.Hour || !validDigest(p.Digest) || !safeOpaque(p.Signature, maxOpaqueBytes) || p.Digest != enablementProofDigest(p) || d.EnablementDigest != p.Digest {
		return VerifiedEnablement{}, ErrUnavailable
	}
	if e := v.VerifyEnablement(ctx, p); e != nil {
		return VerifiedEnablement{}, ErrUnavailable
	}
	return VerifiedEnablement{descriptor: d, proof: p, verifier: v}, nil
}
func enablementProofDigest(p EnablementProof) string {
	p.Digest, p.Signature = "", ""
	b, _ := json.Marshal(p)
	return digestBytes(b)
}
func SealEnablementProof(p *EnablementProof) {
	if p != nil {
		p.Digest = enablementProofDigest(*p)
	}
}
func (v VerifiedEnablement) StoreConfig(root, state, lock string, uid, gid uint32, a HighWater) StoreConfig {
	return StoreConfig{RootPath: root, StateLeaf: state, LockLeaf: lock, OwnerUID: uid, OwnerGID: gid, KeyEpoch: v.proof.KeyEpoch, DescriptorDigest: v.proof.DescriptorDigest, EnablementDigest: v.proof.Digest, HighWater: a}
}

type AuthorizationAction string

const (
	AuthorizeStart     AuthorizationAction = "start"
	AuthorizeReconcile AuthorizationAction = "reconcile"
	AuthorizeTeardown  AuthorizationAction = "teardown"
	AuthorizeSend      AuthorizationAction = "send"
	AuthorizeSteer     AuthorizationAction = "steer"
	AuthorizeCancel    AuthorizationAction = "cancel"
	AuthorizeStatus    AuthorizationAction = "status"
	AuthorizeWait      AuthorizationAction = "wait"
	AuthorizeResult    AuthorizationAction = "result"
	AuthorizeCollect   AuthorizationAction = "collect"
)

// RequestAuthorizer receives the complete receipt/request binding and a
// purpose-specific action. A grant for Start is never authority to reconcile
// or tear down an independently addressed session.
type RequestAuthorizer interface {
	AuthorizeProviderRequest(context.Context, AuthorizationAction, Request, string) error
}

// SessionBridge is a deliberately narrow continuation seam.  References are
// opaque Controller-created identifiers, not task text or native runtime
// protocol values.  Core never exposes its Store through this interface.
// Implementations are allowed to return only the fixed status/result shapes.
type SessionBridge interface {
	Send(context.Context, string, string) error
	Steer(context.Context, string, string) error
	Cancel(context.Context, string, string, string, string) error
	Status(context.Context, string) (SessionStatus, error)
	Wait(context.Context, string, time.Time) (SessionStatus, error)
	Result(context.Context, string, string) (SessionResult, error)
}

type SessionStatus struct{ State, UsageSource string }
type SessionResult struct {
	Status, OutputArtifactRef, SchemaRef, ProvenanceDigest, Classification string
}

type Core struct {
	descriptor Descriptor
	verified   *VerifiedEnablement
	store      *Store
	bridge     Bridge
	authorizer RequestAuthorizer
	now        func() time.Time
	mu         sync.Mutex
	inflight   map[string]bool
}

func NewDisabled(d Descriptor) (*Core, error) {
	if validateDescriptor(d) != nil {
		return nil, ErrUnavailable
	}
	return &Core{descriptor: d, bridge: unavailableBridge{}, now: time.Now, inflight: map[string]bool{}}, nil
}
func NewEnabled(v VerifiedEnablement, s *Store, b Bridge, a RequestAuthorizer) (*Core, error) {
	if s == nil || b == nil || a == nil || v.verifier == nil || v.proof.Digest == "" || s.config.DescriptorDigest != v.proof.DescriptorDigest || s.config.EnablementDigest != v.proof.Digest || s.config.KeyEpoch != v.proof.KeyEpoch {
		return nil, ErrUnavailable
	}
	return &Core{descriptor: v.descriptor, verified: &v, store: s, bridge: b, authorizer: a, now: time.Now, inflight: map[string]bool{}}, nil
}
func (c *Core) enablementAt(ctx context.Context, now time.Time) bool {
	return c != nil && c.verified != nil && c.store != nil && c.verified.proof.ExpiresAt.After(now.UTC()) && !c.verified.proof.Revoked && c.verified.verifier != nil && c.verified.verifier.VerifyEnablement(ctx, c.verified.proof) == nil
}
func (c *Core) freshnessAt(ctx context.Context, r Request, now time.Time) error {
	if r.ExpiresAt.IsZero() || !r.ExpiresAt.After(now.UTC()) {
		return ErrExpired
	}
	if !c.enablementAt(ctx, now) {
		return ErrDisabled
	}
	return nil
}
func (c *Core) authorize(ctx context.Context, action AuthorizationAction, r Request) error {
	if c == nil || c.verified == nil || c.authorizer == nil || c.verified.proof.Digest == "" {
		return ErrDisabled
	}
	if e := c.authorizer.AuthorizeProviderRequest(ctx, action, r, c.verified.proof.Digest); e != nil {
		return ErrUnavailable
	}
	return nil
}
func (c *Core) begin(id string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.inflight[id] {
		return ErrInFlight
	}
	c.inflight[id] = true
	return nil
}
func (c *Core) finish(id string) { c.mu.Lock(); delete(c.inflight, id); c.mu.Unlock() }

func (c *Core) Start(ctx context.Context, r Request) (Receipt, error) {
	if c == nil || c.verified == nil || c.store == nil {
		return Receipt{}, ErrDisabled
	}
	now := c.now().UTC()
	if e := c.validateRequest(r, now); e != nil {
		return Receipt{}, e
	}
	if e := c.freshnessAt(ctx, r, now); e != nil {
		return Receipt{}, e
	}
	if e := c.authorize(ctx, AuthorizeStart, r); e != nil {
		return Receipt{}, e
	}
	if e := c.begin(r.ID); e != nil {
		return Receipt{}, e
	}
	defer c.finish(r.ID)
	receipt, existing, e := c.store.prepare(ctx, r, now)
	if e != nil || existing {
		return receipt, e
	}
	session, bridgeErr := c.bridge.Start(ctx, r)
	postIO := c.now().UTC()
	if freshnessErr := c.freshnessAt(ctx, r, postIO); freshnessErr != nil {
		if safeOpaque(session, maxOpaqueBytes) {
			return c.compensate(ctx, r.ID, Starting, session, errors.Join(freshnessErr, bridgeErr))
		}
		final, finalErr := c.store.finalize(ctx, r.ID, Starting, Uncertain, "", postIO)
		if finalErr != nil {
			c.store.poison()
			return final, errors.Join(freshnessErr, bridgeErr, ErrCommitUncertain)
		}
		return final, errors.Join(freshnessErr, bridgeErr)
	}
	// A native provider can create a session and lose its acknowledgement. A
	// safe returned handle is not optional output: leaving it in Uncertain
	// would make restart recovery unable to tear it down. Persist the exact
	// handle before the unlocked Stop, while retaining the original error.
	if bridgeErr != nil && safeOpaque(session, maxOpaqueBytes) {
		return c.compensate(ctx, r.ID, Starting, session, bridgeErr)
	}
	state := Running
	if bridgeErr != nil || !safeOpaque(session, maxOpaqueBytes) {
		state = Uncertain
		if bridgeErr == nil {
			bridgeErr = ErrInvalidState
		}
		session = ""
	}
	final, finalErr := c.store.finalize(ctx, r.ID, Starting, state, session, postIO)
	if finalErr != nil {
		c.store.poison()
		return final, errors.Join(bridgeErr, ErrCommitUncertain)
	}
	return final, bridgeErr
}
func (c *Core) Reconcile(ctx context.Context, id string) (Receipt, error) {
	receipt, e := c.lookupAndAuthorize(ctx, id, AuthorizeReconcile)
	if e != nil {
		return Receipt{}, e
	}
	if e := c.begin(id); e != nil {
		return Receipt{}, e
	}
	defer c.finish(id)
	receipt, e = c.store.lookupAny(id)
	if e != nil {
		return receipt, e
	}
	if receipt.State == Terminal || receipt.State == Compensating {
		return receipt, nil
	}
	if receipt.State != Starting && receipt.State != Uncertain {
		return receipt, ErrInvalidState
	}
	// This fence observes dynamic revocation before provider I/O. A stale
	// receipt is still reconciled only to discover and tear down an already
	// existing provider session; it can never re-enter Running below.
	_ = c.enablementAt(ctx, c.now().UTC())
	session, state, bridgeErr := c.bridge.Reconcile(ctx, receipt)
	postIO := c.now().UTC()
	freshnessErr := c.freshnessAt(ctx, receipt.request(), postIO)
	if bridgeErr != nil {
		cause := errors.Join(freshnessErr, bridgeErr)
		if safeOpaque(session, maxOpaqueBytes) {
			return c.compensate(ctx, id, receipt.State, session, cause)
		}
		// An unsafe handle cannot be persisted or presented to Stop. Record the
		// ambiguity explicitly, while preserving both a post-I/O freshness loss
		// and the native provider error for the caller.
		final, finalErr := c.store.finalize(ctx, id, receipt.State, Uncertain, "", postIO)
		if finalErr != nil {
			c.store.poison()
			return final, errors.Join(cause, ErrCommitUncertain)
		}
		return final, cause
	}
	if !validState(state) || state == Compensating || (state == Running && !safeOpaque(session, maxOpaqueBytes)) || (session != "" && !safeOpaque(session, maxOpaqueBytes)) {
		return receipt, ErrInvalidState
	}
	if state == Terminal {
		final, finalErr := c.store.finalize(ctx, id, receipt.State, Terminal, session, postIO)
		if finalErr != nil {
			c.store.poison()
			return final, ErrCommitUncertain
		}
		return final, nil
	}
	if freshnessErr != nil {
		if safeOpaque(session, maxOpaqueBytes) {
			return c.compensate(ctx, id, receipt.State, session, freshnessErr)
		}
		final, finalErr := c.store.finalize(ctx, id, receipt.State, Uncertain, "", postIO)
		if finalErr != nil {
			c.store.poison()
			return final, errors.Join(freshnessErr, ErrCommitUncertain)
		}
		return final, freshnessErr
	}
	final, e := c.store.finalize(ctx, id, receipt.State, state, session, postIO)
	if e != nil {
		c.store.poison()
		return final, ErrCommitUncertain
	}
	return final, nil
}
func (c *Core) Stop(ctx context.Context, id string) error {
	receipt, e := c.lookupAndAuthorize(ctx, id, AuthorizeTeardown)
	if e != nil {
		return e
	}
	if e = c.begin(id); e != nil {
		return e
	}
	defer c.finish(id)
	receipt, e = c.store.lookupAny(id)
	if e != nil {
		return e
	}
	if receipt.State == Terminal {
		return nil
	}
	if (receipt.State != Running && receipt.State != Compensating) || !safeOpaque(receipt.Session, maxOpaqueBytes) {
		return ErrInvalidState
	}
	// Revocation/expiry cannot strand an already durable session. Observe
	// dynamic trust at both boundaries, but allow this strictly downward path.
	_ = c.enablementAt(ctx, c.now().UTC())
	if receipt.State == Running {
		receipt, e = c.store.finalize(ctx, id, Running, Compensating, receipt.Session, c.now().UTC())
		if e != nil {
			c.store.poison()
			return ErrCommitUncertain
		}
	}
	if e = c.bridge.Stop(ctx, receipt.Session); e != nil {
		return e // Compensating remains durable for an explicit retry/recovery.
	}
	_ = c.enablementAt(ctx, c.now().UTC())
	if _, e = c.store.finalize(ctx, id, Compensating, Terminal, receipt.Session, c.now().UTC()); e != nil {
		c.store.poison()
		return ErrCommitUncertain
	}
	return nil
}

// Send, Steer and Cancel have individual authorization actions.  A Start or
// generic lifecycle grant is deliberately insufficient to perform a later
// control operation, even when the receipt ID is known.
func (c *Core) Send(ctx context.Context, id, inputRef string) error {
	return c.control(ctx, id, inputRef, AuthorizeSend, func(b SessionBridge, session string) error { return b.Send(ctx, session, inputRef) })
}
func (c *Core) Steer(ctx context.Context, id, inputRef string) error {
	return c.control(ctx, id, inputRef, AuthorizeSteer, func(b SessionBridge, session string) error { return b.Steer(ctx, session, inputRef) })
}
func (c *Core) Cancel(ctx context.Context, id, mode, revisionRef, reasonRef string) error {
	validCancel := (mode == "user" && safeOpaque(revisionRef, maxIDBytes) && safeOpaque(reasonRef, maxIDBytes)) || (mode == "start_compensation" && revisionRef == "" && reasonRef == "start_commit_failed") || (mode == "batch_compensation" && revisionRef == "" && reasonRef == "batch_compensation")
	if !validCancel {
		return ErrConflict
	}
	receipt, e := c.lookupAndAuthorize(ctx, id, AuthorizeCancel)
	if e != nil {
		return e
	}
	if e = c.begin(id); e != nil {
		return e
	}
	defer c.finish(id)
	b, ok := c.bridge.(SessionBridge)
	if !ok || receipt.State != Running || !safeOpaque(receipt.Session, maxOpaqueBytes) || !c.enablementAt(ctx, c.now().UTC()) {
		return ErrDisabled
	}
	if e = b.Cancel(ctx, receipt.Session, mode, revisionRef, reasonRef); e != nil {
		return ErrUnavailable
	}
	// A successful provider cancellation is terminal.  Persist the outcome so
	// RecoverSession can never re-advertise a cancelled native session as
	// running after a daemon restart.
	if _, e = c.store.finalize(ctx, id, Running, Terminal, receipt.Session, c.now().UTC()); e != nil {
		c.store.poison()
		return ErrCommitUncertain
	}
	return nil
}

func (c *Core) Status(ctx context.Context, id string) (SessionStatus, error) {
	return c.observe(ctx, id, AuthorizeStatus, time.Time{}, false)
}
func (c *Core) Wait(ctx context.Context, id string, deadline time.Time) (SessionStatus, error) {
	if deadline.IsZero() || !deadline.Equal(deadline.UTC()) {
		return SessionStatus{}, ErrConflict
	}
	return c.observe(ctx, id, AuthorizeWait, deadline, true)
}
func (c *Core) Result(ctx context.Context, id, revisionRef string) (SessionResult, error) {
	if !safeOpaque(revisionRef, maxIDBytes) {
		return SessionResult{}, ErrConflict
	}
	receipt, e := c.lookupAndAuthorize(ctx, id, AuthorizeResult)
	if e != nil {
		return SessionResult{}, e
	}
	if e = c.begin(id); e != nil {
		return SessionResult{}, e
	}
	defer c.finish(id)
	b, ok := c.bridge.(SessionBridge)
	if !ok || receipt.State != Running || !safeOpaque(receipt.Session, maxOpaqueBytes) || !c.enablementAt(ctx, c.now().UTC()) {
		return SessionResult{}, ErrDisabled
	}
	result, e := b.Result(ctx, receipt.Session, revisionRef)
	if e != nil || !validSessionResult(result) {
		return SessionResult{}, ErrUnavailable
	}
	return result, nil
}

// Collect has a separate grant despite sharing the bounded result shape.
func (c *Core) Collect(ctx context.Context, id, revisionRef string) (SessionResult, error) {
	if !safeOpaque(revisionRef, maxIDBytes) {
		return SessionResult{}, ErrConflict
	}
	receipt, e := c.lookupAndAuthorize(ctx, id, AuthorizeCollect)
	if e != nil {
		return SessionResult{}, e
	}
	if e = c.begin(id); e != nil {
		return SessionResult{}, e
	}
	defer c.finish(id)
	b, ok := c.bridge.(SessionBridge)
	if !ok || receipt.State != Running || !safeOpaque(receipt.Session, maxOpaqueBytes) || !c.enablementAt(ctx, c.now().UTC()) {
		return SessionResult{}, ErrDisabled
	}
	result, e := b.Result(ctx, receipt.Session, revisionRef)
	if e != nil || !validSessionResult(result) {
		return SessionResult{}, ErrUnavailable
	}
	return result, nil
}

func (c *Core) control(ctx context.Context, id, inputRef string, action AuthorizationAction, invoke func(SessionBridge, string) error) error {
	if !safeOpaque(inputRef, maxIDBytes) {
		return ErrConflict
	}
	receipt, e := c.lookupAndAuthorize(ctx, id, action)
	if e != nil {
		return e
	}
	if e = c.begin(id); e != nil {
		return e
	}
	defer c.finish(id)
	b, ok := c.bridge.(SessionBridge)
	if !ok || receipt.State != Running || !safeOpaque(receipt.Session, maxOpaqueBytes) || !c.enablementAt(ctx, c.now().UTC()) {
		return ErrDisabled
	}
	if e = invoke(b, receipt.Session); e != nil {
		return ErrUnavailable
	}
	return nil
}

func (c *Core) observe(ctx context.Context, id string, action AuthorizationAction, deadline time.Time, wait bool) (SessionStatus, error) {
	receipt, e := c.lookupAndAuthorize(ctx, id, action)
	if e != nil {
		return SessionStatus{}, e
	}
	if e = c.begin(id); e != nil {
		return SessionStatus{}, e
	}
	defer c.finish(id)
	b, ok := c.bridge.(SessionBridge)
	if !ok || receipt.State != Running || !safeOpaque(receipt.Session, maxOpaqueBytes) || !c.enablementAt(ctx, c.now().UTC()) {
		return SessionStatus{}, ErrDisabled
	}
	var status SessionStatus
	if wait {
		status, e = b.Wait(ctx, receipt.Session, deadline)
	} else {
		status, e = b.Status(ctx, receipt.Session)
	}
	if e != nil || !validSessionStatus(status) {
		return SessionStatus{}, ErrUnavailable
	}
	return status, nil
}

func validSessionStatus(v SessionStatus) bool {
	return (v.State == "starting" || v.State == "running" || v.State == "completed" || v.State == "failed" || v.State == "cancelled") && (v.UsageSource == "unknown" || v.UsageSource == "provider")
}
func validSessionResult(v SessionResult) bool {
	return (v.Status == "completed" || v.Status == "failed" || v.Status == "cancelled") && safeOpaque(v.OutputArtifactRef, maxIDBytes) && safeOpaque(v.SchemaRef, maxIDBytes) && validDigest(v.ProvenanceDigest) && (v.Classification == "L1" || v.Classification == "L2" || v.Classification == "L3")
}
func (c *Core) Prune(ctx context.Context) error {
	if !c.enablementAt(ctx, c.now().UTC()) {
		return ErrDisabled
	}
	return c.store.prune(ctx, c.now().UTC())
}
func (c *Core) lookupAndAuthorize(ctx context.Context, id string, action AuthorizationAction) (Receipt, error) {
	if c == nil || c.store == nil || c.verified == nil {
		return Receipt{}, ErrDisabled
	}
	if !safeOpaque(id, maxIDBytes) {
		return Receipt{}, ErrConflict
	}
	fresh := c.enablementAt(ctx, c.now().UTC())
	r, e := c.store.lookupAny(id)
	if e != nil {
		if !fresh {
			return Receipt{}, ErrDisabled
		}
		return Receipt{}, e
	}
	if e = c.authorize(ctx, action, r.request()); e != nil {
		return Receipt{}, e
	}
	return r, nil
}
func (c *Core) compensate(ctx context.Context, id string, expected State, session string, cause error) (Receipt, error) {
	compensating, e := c.store.finalize(ctx, id, expected, Compensating, session, c.now().UTC())
	if e != nil {
		c.store.poison()
		return compensating, errors.Join(cause, ErrCommitUncertain)
	}
	if e = c.bridge.Stop(ctx, session); e != nil {
		return compensating, errors.Join(cause, e)
	}
	terminal, e := c.store.finalize(ctx, id, Compensating, Terminal, session, c.now().UTC())
	if e != nil {
		c.store.poison()
		return terminal, errors.Join(cause, ErrCommitUncertain)
	}
	return terminal, cause
}
func (r Receipt) request() Request {
	return Request{ID: r.ID, Identity: r.Identity, ExpiresAt: r.ExpiresAt}
}
func (c *Core) validateRequest(r Request, now time.Time) error {
	if !safeOpaque(r.ID, maxIDBytes) || !validIdentity(r.Identity) || r.Identity.static() != c.verified.proof.StaticIdentity || r.Identity.Request != RequestDigest(r) {
		return ErrConflict
	}
	if r.ExpiresAt.IsZero() || !r.ExpiresAt.After(now) || r.ExpiresAt.Sub(now) > 10*time.Minute {
		return ErrExpired
	}
	return nil
}

func (s *Store) prepare(ctx context.Context, r Request, now time.Time) (Receipt, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.poisoned {
		return Receipt{}, false, ErrUnavailable
	}
	if old, ok := s.receipts[r.ID]; ok {
		if old.Identity != r.Identity || !old.ExpiresAt.Equal(r.ExpiresAt) {
			return Receipt{}, true, ErrConflict
		}
		if !old.ExpiresAt.After(now) && old.State != Terminal {
			return old, true, ErrExpired
		}
		return old, true, nil
	}
	// A sealed Start binding is one-to-one even when a caller presents a fresh
	// request ID. This bounded scan is the daemon-side counterpart of the
	// transport binding fence and runs before any provider effect.
	for _, old := range s.receipts {
		if old.Identity.Binding == r.Identity.Binding && old.ID != r.ID {
			return Receipt{}, false, ErrConflict
		}
	}
	candidate := cloneReceipts(s.receipts)
	pruneTerminal(candidate, now)
	if len(candidate) >= MaxReceipts {
		return Receipt{}, false, ErrCapacity
	}
	receipt := Receipt{r.ID, r.Identity, Starting, "", now, r.ExpiresAt.UTC(), now}
	if e := receipt.validate(); e != nil {
		return Receipt{}, false, e
	}
	candidate[receipt.ID] = receipt
	if e := s.saveLocked(ctx, candidate); e != nil {
		return Receipt{}, false, e
	}
	return receipt, false, nil
}
func (s *Store) lookup(id string, now time.Time) (Receipt, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.poisoned {
		return Receipt{}, ErrUnavailable
	}
	r, ok := s.receipts[id]
	if !ok {
		return Receipt{}, ErrUnavailable
	}
	if !r.ExpiresAt.After(now) && r.State != Terminal {
		return r, ErrExpired
	}
	return r, nil
}

// lookupAny is intentionally private: it exposes an expired receipt only to
// action-bound reconciliation/teardown so expiry cannot strand an existing
// provider session. Admission still uses lookup/prepare and rejects expiry.
func (s *Store) lookupAny(id string) (Receipt, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.poisoned {
		return Receipt{}, ErrUnavailable
	}
	r, ok := s.receipts[id]
	if !ok {
		return Receipt{}, ErrUnavailable
	}
	if r.validate() != nil {
		return Receipt{}, ErrCorrupt
	}
	return r, nil
}
func (s *Store) finalize(ctx context.Context, id string, expected, next State, session string, now time.Time) (Receipt, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.poisoned {
		return Receipt{}, ErrUnavailable
	}
	r, ok := s.receipts[id]
	if !ok || r.State != expected || !allowedTransition(expected, next) {
		return r, ErrConflict
	}
	if next == Running && !r.ExpiresAt.After(now.UTC()) {
		return r, ErrExpired
	}
	r.State, r.Session, r.UpdatedAt = next, session, now
	if r.validate() != nil {
		return r, ErrInvalidState
	}
	candidate := cloneReceipts(s.receipts)
	candidate[id] = r
	if e := s.saveLocked(ctx, candidate); e != nil {
		return r, e
	}
	return r, nil
}
func (s *Store) prune(ctx context.Context, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.poisoned {
		return ErrUnavailable
	}
	candidate := cloneReceipts(s.receipts)
	pruneTerminal(candidate, now)
	if len(candidate) == len(s.receipts) {
		return nil
	}
	return s.saveLocked(ctx, candidate)
}
func (s *Store) poison() { s.mu.Lock(); s.poisoned = true; s.mu.Unlock() }
func pruneTerminal(m map[string]Receipt, now time.Time) {
	for id, r := range m {
		if r.State == Terminal && !r.ExpiresAt.After(now) {
			delete(m, id)
		}
	}
}
func validState(s State) bool {
	return s == Starting || s == Running || s == Terminal || s == Uncertain || s == Compensating
}
func allowedTransition(from, to State) bool {
	switch from {
	case Starting:
		return to == Running || to == Uncertain || to == Terminal || to == Starting || to == Compensating
	case Running:
		return to == Terminal || to == Uncertain || to == Compensating
	case Uncertain:
		return to == Running || to == Terminal || to == Uncertain || to == Starting || to == Compensating
	case Compensating:
		return to == Terminal || to == Compensating
	}
	return false
}
func (r Receipt) validate() error {
	if !safeOpaque(r.ID, maxIDBytes) || !validIdentity(r.Identity) || r.Identity.Request != RequestDigest(r.request()) || !validState(r.State) || r.CreatedAt.IsZero() || r.UpdatedAt.Before(r.CreatedAt) || !r.ExpiresAt.After(r.CreatedAt) || (r.Session != "" && !safeOpaque(r.Session, maxOpaqueBytes)) || (r.State == Starting && r.Session != "") || ((r.State == Running || r.State == Compensating) && r.Session == "") {
		return ErrInvalidState
	}
	return nil
}

func validateDescriptor(d Descriptor) error {
	if !safeOpaque(d.Provider, maxIDBytes) || !safeOpaque(d.Profile, maxIDBytes) || !safeOpaque(d.Revision, maxIDBytes) || !validDigest(d.MappingDigest) || !validDigest(d.RuntimeDigest) || !validDigest(d.ProtocolDigest) || ValidateDescriptorPaths(d) != nil {
		return ErrUnavailable
	}
	return nil
}
func ValidateDescriptorPaths(d Descriptor) error {
	for _, p := range []string{d.RootDescriptorPath, d.ReleaseFactPath, d.KeyFactPath} {
		if p == "" || !filepath.IsAbs(p) || filepath.Clean(p) != p {
			return fmt.Errorf("%w: descriptor path", ErrUnavailable)
		}
	}
	return nil
}
func validIdentity(i Identity) bool {
	return safeOpaque(i.Profile, maxIDBytes) && safeOpaque(i.Revision, maxIDBytes) && validDigest(i.Mapping) && validDigest(i.Runtime) && validDigest(i.Protocol) && validDigest(i.Request) && safeOpaque(i.Route, maxIDBytes) && validDigest(i.Binding) && i.validTransportBinding()
}
func safeLeaf(v string) bool {
	return safeOpaque(v, maxIDBytes) && v != "." && v != ".." && !strings.Contains(v, "/")
}
func safeOpaque(v string, max int) bool {
	if len(v) == 0 || len(v) > max {
		return false
	}
	for _, r := range v {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || strings.ContainsRune("._:-", r)) {
			return false
		}
	}
	lower := strings.ToLower(v)
	for _, marker := range []string{"secret", "password", "token", "api_key", "apikey", "sk-"} {
		if strings.Contains(lower, marker) {
			return false
		}
	}
	return true
}
func validDigest(v string) bool {
	if len(v) != len("sha256:")+sha256.Size*2 || !strings.HasPrefix(v, "sha256:") || v != strings.ToLower(v) {
		return false
	}
	_, e := hex.DecodeString(strings.TrimPrefix(v, "sha256:"))
	return e == nil
}
func digestBytes(v []byte) string { d := sha256.Sum256(v); return "sha256:" + hex.EncodeToString(d[:]) }
func safeDir(i os.FileInfo, uid, gid uint32) bool {
	if i == nil || !i.IsDir() || i.Mode().Perm() != 0700 {
		return false
	}
	s, ok := i.Sys().(*syscall.Stat_t)
	return ok && s != nil && s.Mode&syscall.S_IFMT == syscall.S_IFDIR && s.Mode&(syscall.S_ISUID|syscall.S_ISGID|syscall.S_ISVTX) == 0 && s.Uid == uid && s.Gid == gid
}
func safeFile(i os.FileInfo, uid, gid uint32, mode os.FileMode) bool {
	if i == nil || !i.Mode().IsRegular() || i.Mode().Perm() != mode {
		return false
	}
	s, ok := i.Sys().(*syscall.Stat_t)
	return ok && s != nil && s.Mode&syscall.S_IFMT == syscall.S_IFREG && s.Mode&(syscall.S_ISUID|syscall.S_ISGID|syscall.S_ISVTX) == 0 && s.Uid == uid && s.Gid == gid && s.Nlink == 1
}
func sameFile(a, b os.FileInfo) bool {
	if a == nil || b == nil {
		return false
	}
	x, okx := a.Sys().(*syscall.Stat_t)
	y, oky := b.Sys().(*syscall.Stat_t)
	return okx && oky && x != nil && y != nil && x.Dev == y.Dev && x.Ino == y.Ino
}
