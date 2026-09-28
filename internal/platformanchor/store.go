package platformanchor

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"

	"openduck/internal/platformcheckpoint"
)

const maxRetainedRequests = 1024

var errNoStoreWrite = errors.New("platform anchor no store write")

type checkpoint struct {
	Version uint64 `json:"version"`
	Digest  string `json:"digest,omitempty"`
}
type diskState struct {
	SchemaVersion       string                `json:"schema_version"`
	StateID             string                `json:"state_id"`
	Generation          uint64                `json:"generation"`
	Namespaces          map[string]checkpoint `json:"namespaces"`
	Requests            map[string]Response   `json:"requests"`
	RequestFingerprints map[string]string     `json:"request_fingerprints"`
	RequestOrder        []string              `json:"request_order"`
	LastCAS             map[string]casReplay  `json:"last_cas"`
}
type casReplay struct {
	RequestID   string   `json:"request_id"`
	Fingerprint string   `json:"fingerprint"`
	Response    Response `json:"response"`
}
type anchorMeta struct {
	SchemaVersion string `json:"schema_version"`
	Generation    uint64 `json:"generation"`
	StateDigest   string `json:"state_digest"`
	MAC           string `json:"mac"`
}

// AnchorCheckpoint is deliberately separate from Store state. Its version is
// the generation of the complete store state, never a per-namespace/key CAS
// version. The digest binds that generation to the complete canonical state.
// Production composition must inject an independently-owned implementation.
type AnchorCheckpoint interface {
	Load() (uint64, string, error)
	Commit(expected, next uint64, digest string) error
}

// ProductionAnchorCheckpoint is an opaque capability obtained from the
// independently hosted platform checkpoint authority. Its private field
// prevents foreign or synthetic values from being accepted by production
// composition.
type ProductionAnchorCheckpoint struct {
	client *platformcheckpoint.ProductionClient
	test   AnchorCheckpoint
}

// newProductionAnchorCheckpointForTest is a package-private fixture seam;
// production constructors never accept this synthetic-backed capability.
func newProductionAnchorCheckpointForTest(cp AnchorCheckpoint) *ProductionAnchorCheckpoint {
	if cp == nil {
		return nil
	}
	return &ProductionAnchorCheckpoint{test: cp}
}

// Valid reports whether this capability came from the authenticated
// platform-checkpoint constructor. Synthetic test seams deliberately return
// false.
func (c *ProductionAnchorCheckpoint) Valid() bool {
	return c != nil && c.test == nil && c.client != nil && c.client.Valid()
}

func (c *ProductionAnchorCheckpoint) Load() (uint64, string, error) {
	if c == nil || (c.client == nil && c.test == nil) {
		return 0, "", ErrProductionSealed
	}
	if c.test != nil {
		return c.test.Load()
	}
	return c.client.Load(context.Background())
}
func (c *ProductionAnchorCheckpoint) Commit(expected, next uint64, digest string) error {
	if c == nil || (c.client == nil && c.test == nil) {
		return ErrProductionSealed
	}
	if c.test != nil {
		return c.test.Commit(expected, next, digest)
	}
	id := deterministicCASRequestID("anchor", expected, next, digest)
	return c.client.CAS(context.Background(), id, expected, next, digest)
}

// TestMonotonicCheckpoint is an explicit independent synthetic authority.
type TestMonotonicCheckpoint struct {
	mu      sync.Mutex
	version uint64
	digest  string
}

func NewTestMonotonicCheckpoint() *TestMonotonicCheckpoint { return &TestMonotonicCheckpoint{} }
func (c *TestMonotonicCheckpoint) Load() (uint64, string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.version, c.digest, nil
}
func (c *TestMonotonicCheckpoint) Commit(expected, next uint64, digest string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.version != expected || (next != expected+1 && !(expected == 0 && next == 0)) {
		return ErrCAS
	}
	if expected == 0 && next == 0 && c.digest != "" {
		if c.digest == digest {
			return nil
		}
		return ErrCAS
	}
	c.version, c.digest = next, digest
	return nil
}

// Store uses an inode-stable lock and independently authenticated metadata.
// State replacement by this process is safe; rollback, substitution, deletion,
// and lock replacement fail closed.
type Store struct {
	dir, path string
	root      *os.Root
	lock      *os.File
	secret    []byte
	anchor    AnchorCheckpoint
	mu        sync.Mutex
}

type fileAnchor struct {
	dir    string
	root   *os.Root
	secret []byte
	mu     sync.Mutex
}
type fileAnchorRecord struct {
	SchemaVersion string `json:"schema_version"`
	Version       uint64 `json:"version"`
	Digest        string `json:"digest"`
	MAC           string `json:"mac"`
}

func newFileAnchor(dir string) (*fileAnchor, error) {
	if !filepath.IsAbs(dir) || filepath.Clean(dir) != dir {
		return nil, ErrUnavailable
	}
	if err := validatePrivatePath(dir); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	i, err := os.Stat(dir)
	if err != nil || i.Mode().Perm() != 0700 || !sameOwner(i) {
		return nil, ErrUnavailable
	}
	r, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	a := &fileAnchor{dir: dir, root: r}
	b, err := r.ReadFile("secret")
	if errors.Is(err, os.ErrNotExist) {
		b = make([]byte, 32)
		if _, err = rand.Read(b); err != nil {
			_ = r.Close()
			return nil, fmt.Errorf("%w: entropy", ErrUnavailable)
		}
		f, e := r.OpenFile("secret", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if e != nil {
			_ = r.Close()
			return nil, e
		}
		if e = syncRoot(r); e != nil {
			_ = r.Close()
			return nil, e
		}
		_, e = f.Write(b)
		if e == nil {
			e = f.Sync()
		}
		ce := f.Close()
		if e == nil {
			e = ce
		}
		if e != nil {
			_ = r.Close()
			return nil, e
		}
	}
	if err != nil || len(b) != 32 {
		_ = r.Close()
		return nil, ErrUnavailable
	}
	a.secret = append([]byte(nil), b...)
	return a, nil
}
func validatePrivatePath(path string) error {
	cur := filepath.VolumeName(path) + string(filepath.Separator)
	rest := strings.TrimPrefix(path, cur)
	for _, part := range strings.Split(rest, string(filepath.Separator)) {
		if part == "" {
			continue
		}
		cur = filepath.Join(cur, part)
		i, err := os.Lstat(cur)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return ErrUnavailable
		}
		if err == nil && i.Mode()&os.ModeSymlink != 0 && cur != "/var" {
			return ErrUnavailable
		}
	}
	return nil
}

func canonicalizeAllowMissing(path string) (string, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return "", ErrUnavailable
	}
	missing := []string{}
	cur := path
	for {
		if info, err := os.Lstat(cur); err == nil {
			if info.Mode()&os.ModeSymlink != 0 && cur != "/var" {
				return "", ErrUnavailable
			}
			real, err := filepath.EvalSymlinks(cur)
			if err != nil {
				return "", ErrUnavailable
			}
			for i := len(missing) - 1; i >= 0; i-- {
				real = filepath.Join(real, missing[i])
			}
			return filepath.Clean(real), nil
		} else if !errors.Is(err, os.ErrNotExist) {
			return "", ErrUnavailable
		}
		parent, base := filepath.Dir(cur), filepath.Base(cur)
		missing = append(missing, base)
		if parent == cur {
			return "", ErrUnavailable
		}
		cur = parent
	}
}
func CanonicalizeAllowMissing(path string) (string, error) { return canonicalizeAllowMissing(path) }

// NewSyntheticFileCheckpoint creates the explicitly separate synthetic
// checkpoint root used by the fixture command.
func NewSyntheticFileCheckpoint(dir string) (AnchorCheckpoint, error) { return newFileAnchor(dir) }
func (a *fileAnchor) mac(v uint64, d string) string {
	h := hmac.New(sha256.New, a.secret)
	fmt.Fprintf(h, "%d\x00%s", v, d)
	return hex.EncodeToString(h.Sum(nil))
}
func (a *fileAnchor) Load() (uint64, string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	b, err := a.root.ReadFile("checkpoint.json")
	if errors.Is(err, os.ErrNotExist) {
		return 0, "", nil
	}
	if err != nil {
		return 0, "", ErrUnavailable
	}
	var r fileAnchorRecord
	if json.Unmarshal(b, &r) != nil || r.SchemaVersion != SchemaVersion || !hmac.Equal([]byte(r.MAC), []byte(a.mac(r.Version, r.Digest))) {
		return 0, "", ErrUnavailable
	}
	return r.Version, r.Digest, nil
}
func (a *fileAnchor) Commit(expected, next uint64, digest string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	cur, currentDigest, err := a.LoadUnlocked()
	if err != nil || cur != expected || next != expected+1 && !(expected == 0 && next == 0) {
		return ErrCAS
	}
	if expected == 0 && next == 0 && currentDigest != "" {
		if currentDigest == digest {
			return nil
		}
		return ErrCAS
	}
	r := fileAnchorRecord{SchemaVersion: SchemaVersion, Version: next, Digest: digest}
	r.MAC = a.mac(next, digest)
	b, _ := json.Marshal(r)
	f, err := a.root.OpenFile("checkpoint.next", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUncertain, err)
	}
	_, err = f.Write(b)
	if err == nil {
		err = f.Sync()
	}
	ce := f.Close()
	if err == nil {
		err = ce
	}
	if err != nil {
		_ = a.root.Remove("checkpoint.next")
		return fmt.Errorf("%w: %v", ErrUncertain, err)
	}
	if err = a.root.Rename("checkpoint.next", "checkpoint.json"); err != nil {
		return fmt.Errorf("%w: %v", ErrUncertain, err)
	}
	if err = syncRoot(a.root); err != nil {
		return fmt.Errorf("%w: %v", ErrUncertain, err)
	}
	return nil
}
func (a *fileAnchor) LoadUnlocked() (uint64, string, error) {
	b, err := a.root.ReadFile("checkpoint.json")
	if errors.Is(err, os.ErrNotExist) {
		return 0, "", nil
	}
	if err != nil {
		return 0, "", ErrUnavailable
	}
	var r fileAnchorRecord
	if json.Unmarshal(b, &r) != nil || r.SchemaVersion != SchemaVersion || !hmac.Equal([]byte(r.MAC), []byte(a.mac(r.Version, r.Digest))) {
		return 0, "", ErrUnavailable
	}
	return r.Version, r.Digest, nil
}

// NewSyntheticStore intentionally refuses implicit colocated checkpointing.
// Callers must inject an independently-owned test checkpoint explicitly.
func NewSyntheticStore(_ string) (*Store, error) {
	return nil, fmt.Errorf("%w: checkpoint injection required", ErrUnavailable)
}

func newStoreWithCheckpoint(dir string, cp AnchorCheckpoint) (*Store, error) {
	if dir == "" || !filepath.IsAbs(dir) || filepath.Clean(dir) != dir {
		return nil, fmt.Errorf("%w: unsafe store path", ErrUnavailable)
	}
	if cp == nil {
		return nil, ErrUnavailable
	}
	if err := validatePrivatePath(dir); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	li, err := os.Lstat(dir)
	if err != nil || li.Mode()&os.ModeSymlink != 0 || !li.IsDir() {
		return nil, fmt.Errorf("%w: state directory", ErrUnavailable)
	}
	if i, err := os.Stat(dir); err != nil || i.Mode().Perm() != 0700 || !sameOwner(i) {
		return nil, fmt.Errorf("%w: state directory owner", ErrUnavailable)
	}
	r, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	lock, err := r.OpenFile("anchor.lock", os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		_ = r.Close()
		return nil, err
	}
	s := &Store{dir: dir, path: filepath.Join(dir, "anchor.json"), root: r, lock: lock, anchor: cp}
	if err := s.initSecret(); err != nil {
		_ = s.Close()
		return nil, err
	}
	if err := s.initState(); err != nil {
		_ = s.Close()
		return nil, err
	}
	return s, nil
}

// NewProductionStore accepts only the opaque checkpoint capability obtained
// from platformcheckpoint.ProductionClient.
type ProductionStore struct{ store *Store }

func (s *ProductionStore) Close() error {
	if s == nil || s.store == nil {
		return nil
	}
	return s.store.Close()
}

func NewProductionStore(dir string, cp *ProductionAnchorCheckpoint) (*ProductionStore, error) {
	if !cp.Valid() {
		return nil, ErrProductionSealed
	}
	s, err := newStoreWithCheckpoint(dir, cp)
	if err != nil {
		return nil, err
	}
	return &ProductionStore{store: s}, nil
}

// newProductionStoreForTest is package-private and exists solely to exercise
// store recovery with a synthetic checkpoint in same-package tests.
func newProductionStoreForTest(dir string, cp AnchorCheckpoint) (*ProductionStore, error) {
	if cp == nil {
		return nil, ErrProductionSealed
	}
	s, err := newStoreWithCheckpoint(dir, cp)
	if err != nil {
		return nil, err
	}
	return &ProductionStore{store: s}, nil
}

func NewSyntheticStoreWithCheckpoint(dir string, cp AnchorCheckpoint) (*Store, error) {
	return newStoreWithCheckpoint(dir, cp)
}
func sameOwner(i os.FileInfo) bool {
	st, ok := i.Sys().(*syscall.Stat_t)
	return ok && uint32(st.Uid) == uint32(os.Getuid())
}
func (s *Store) Close() error {
	if s == nil {
		return nil
	}
	if s.lock != nil {
		_ = s.lock.Close()
	}
	if s.root != nil {
		return s.root.Close()
	}
	return nil
}
func (s *Store) initSecret() error {
	b, err := s.root.ReadFile("anchor.secret")
	if errors.Is(err, os.ErrNotExist) {
		b = make([]byte, 32)
		if _, err = rand.Read(b); err != nil {
			return fmt.Errorf("%w: entropy", ErrUnavailable)
		}
		f, e := s.root.OpenFile("anchor.secret", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if e != nil {
			return e
		}
		_, e = f.Write(b)
		if e == nil {
			e = f.Sync()
		}
		ce := f.Close()
		if e == nil {
			e = ce
		}
		if e != nil {
			return e
		}
	}
	if err != nil {
		return err
	}
	if len(b) != 32 {
		return fmt.Errorf("%w: secret", ErrUnavailable)
	}
	s.secret = append([]byte(nil), b...)
	return nil
}
func emptyState() *diskState {
	return &diskState{SchemaVersion: SchemaVersion, Namespaces: map[string]checkpoint{}, Requests: map[string]Response{}, RequestFingerprints: map[string]string{}, RequestOrder: []string{}, LastCAS: map[string]casReplay{}}
}
func (s *Store) initState() error {
	_, err := s.root.Stat("anchor.json")
	if errors.Is(err, os.ErrNotExist) {
		generation, digest, checkpointErr := s.anchor.Load()
		if checkpointErr != nil || generation != 0 || digest != "" {
			return fmt.Errorf("%w: state missing after checkpoint binding", ErrUnavailable)
		}
		return s.save(emptyState(), true)
	}
	if err != nil {
		return err
	}
	_, err = s.load()
	return err
}
func sameFile(a, b os.FileInfo) bool {
	as, ao := a.Sys().(*syscall.Stat_t)
	bs, bo := b.Sys().(*syscall.Stat_t)
	return ao && bo && as.Dev == bs.Dev && as.Ino == bs.Ino
}
func (s *Store) withLock(fn func(*diskState) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lock == nil || s.root == nil {
		return ErrUnavailable
	}
	before, err := s.lock.Stat()
	if err != nil {
		return ErrUnavailable
	}
	if st, ok := before.Sys().(*syscall.Stat_t); !ok || st.Mode&syscall.S_IFMT != syscall.S_IFREG {
		return ErrUnavailable
	}
	if err = syscall.Flock(int(s.lock.Fd()), syscall.LOCK_EX); err != nil {
		return err
	}
	defer syscall.Flock(int(s.lock.Fd()), syscall.LOCK_UN)
	after, err := s.lock.Stat()
	if err != nil || !sameFile(before, after) {
		return fmt.Errorf("%w: lock replaced", ErrUnavailable)
	}
	pathInfo, err := s.root.Stat("anchor.lock")
	if err != nil || !sameFile(before, pathInfo) {
		return fmt.Errorf("%w: lock pathname replaced", ErrUnavailable)
	}
	st, err := s.load()
	if err != nil {
		return err
	}
	if err = fn(st); err != nil {
		if errors.Is(err, errNoStoreWrite) {
			return nil
		}
		return err
	}
	if err = s.save(st, false); err != nil {
		return fmt.Errorf("%w: %v", ErrUncertain, err)
	}
	return nil
}
func canonicalState(st *diskState) []byte { b, _ := json.Marshal(st); return b }
func stateDigest(st *diskState) string {
	h := sha256.Sum256(canonicalState(st))
	return "sha256:" + hex.EncodeToString(h[:])
}
func (s *Store) mac(g uint64, d string) string {
	h := hmac.New(sha256.New, s.secret)
	fmt.Fprintf(h, "%d\x00%s", g, d)
	return hex.EncodeToString(h.Sum(nil))
}
func (s *Store) load() (*diskState, error) {
	b, err := s.root.ReadFile("anchor.json")
	if err != nil {
		return nil, fmt.Errorf("%w: state", ErrUnavailable)
	}
	var st diskState
	if json.Unmarshal(b, &st) != nil || st.SchemaVersion != SchemaVersion || st.StateID == "" || st.Namespaces == nil || st.Requests == nil {
		return nil, fmt.Errorf("%w: corrupt state", ErrUnavailable)
	}
	if st.RequestFingerprints == nil {
		st.RequestFingerprints = map[string]string{}
	}
	if st.RequestOrder == nil {
		st.RequestOrder = []string{}
	}
	if st.LastCAS == nil {
		st.LastCAS = map[string]casReplay{}
	}
	for n := range st.Namespaces {
		ns, _, ok := strings.Cut(n, "\x00")
		if !ok || !validStoredNamespace(ns) {
			return nil, fmt.Errorf("%w: namespace", ErrProtocol)
		}
	}
	mraw, err := s.root.ReadFile("anchor.meta")
	if err != nil {
		return nil, fmt.Errorf("%w: checkpoint", ErrUnavailable)
	}
	var m anchorMeta
	if json.Unmarshal(mraw, &m) != nil || m.SchemaVersion != SchemaVersion || m.Generation != st.Generation || m.StateDigest != stateDigest(&st) || !hmac.Equal([]byte(m.MAC), []byte(s.mac(m.Generation, m.StateDigest))) {
		return nil, fmt.Errorf("%w: rollback or substitution", ErrUnavailable)
	}
	// The colocated state and MACed metadata are not sufficient: an attacker
	// who can restore both files must still be unable to roll the store back.
	// The independent checkpoint is the monotonic authority for the complete
	// state generation and digest.
	anchorGeneration, anchorDigest, err := s.anchor.Load()
	if err != nil || anchorGeneration != st.Generation || anchorDigest != stateDigest(&st) {
		return nil, fmt.Errorf("%w: independent checkpoint rollback", ErrUnavailable)
	}
	return &st, nil
}
func (s *Store) save(st *diskState, initial bool) error {
	previousGeneration := st.Generation
	if initial {
		var id [16]byte
		if _, err := rand.Read(id[:]); err != nil {
			return fmt.Errorf("%w: entropy", ErrUnavailable)
		}
		st.StateID = hex.EncodeToString(id[:])
	}
	if !initial {
		st.Generation++
	}
	d := stateDigest(st)
	m := anchorMeta{SchemaVersion: SchemaVersion, Generation: st.Generation, StateDigest: d}
	m.MAC = s.mac(m.Generation, d)
	b, _ := json.Marshal(st)
	mb, _ := json.Marshal(m)
	if err := s.writeReplace("anchor.next", b); err != nil {
		return err
	}
	if err := s.writeReplace("anchor.meta.next", mb); err != nil {
		_ = s.root.Remove("anchor.next")
		return err
	}
	if err := s.root.Rename("anchor.next", "anchor.json"); err != nil {
		return err
	}
	if err := s.root.Rename("anchor.meta.next", "anchor.meta"); err != nil {
		return err
	}
	if err := s.anchor.Commit(previousGeneration, st.Generation, d); err != nil {
		return err
	}
	if initial {
		// The initial state is generation zero; the independent checkpoint is
		// initialized by the same global commit above.
	}
	return syncRoot(s.root)
}
func (s *Store) writeReplace(name string, b []byte) error {
	f, err := s.root.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	_, err = f.Write(b)
	if err == nil {
		err = f.Sync()
	}
	ce := f.Close()
	if err == nil {
		err = ce
	}
	if err != nil {
		_ = s.root.Remove(name)
	}
	return err
}
func syncRoot(r *os.Root) error {
	f, err := r.Open(".")
	if err != nil {
		return err
	}
	err = f.Sync()
	_ = f.Close()
	return err
}
func (s *Store) Load(namespace, key string) (uint64, string, error) {
	if !validNamespace(namespace) || key == "" {
		return 0, "", ErrUnknownNamespace
	}
	var out checkpoint
	err := s.withLock(func(st *diskState) error {
		out = st.Namespaces[namespace+"\x00"+key]
		return errNoStoreWrite
	})
	return out.Version, out.Digest, err
}
func (s *Store) CAS(namespace, key string, expected, next uint64, digest string) error {
	if !validNamespace(namespace) || key == "" {
		return ErrUnknownNamespace
	}
	if next != expected+1 || !digestPattern.MatchString(digest) {
		return fmt.Errorf("%w: checkpoint", ErrProtocol)
	}
	return s.withLock(func(st *diskState) error {
		id := namespace + "\x00" + key
		cur := st.Namespaces[id]
		if cur.Version != expected {
			return ErrCAS
		}
		st.Namespaces[id] = checkpoint{next, digest}
		return nil
	})
}

// journalRequest is intentionally package-private: journal callers cannot
// select arbitrary Controller namespaces or keys. The existing admission
// namespace, authenticated Store state, and replay ledger remain authoritative.
func (s *Store) journalRequest(r JournalRequest) (JournalResponse, error) {
	if s == nil || r.validate() != nil {
		return JournalResponse{}, ErrProtocol
	}
	genericID, key, fp := journalRequestID(r), journalKey(r.RunID, r.ReleaseDigest), journalFingerprint(r)
	out := JournalResponse{SchemaVersion: JournalSchemaVersion, RequestID: r.RequestID, Audience: JournalAudience}
	err := s.withLock(func(st *diskState) error {
		if old, ok := st.Requests[genericID]; ok {
			if st.RequestFingerprints[genericID] != fp {
				return ErrReplay
			}
			out.OK, out.Sequence, out.Digest, out.Error = old.OK, old.Version, old.Digest, old.Error
			return errNoStoreWrite
		}
		cur := st.Namespaces[journalInternalNamespace+"\x00"+key]
		if r.Operation == "cas" && (cur.Version != r.ExpectedSequence || cur.Digest != r.ExpectedDigest) {
			out.Error = ErrCAS.Error()
		} else {
			if r.Operation == "cas" {
				cur = checkpoint{Version: r.NextSequence, Digest: r.NextDigest}
				st.Namespaces[journalInternalNamespace+"\x00"+key] = cur
			}
			out.OK, out.Sequence, out.Digest = true, cur.Version, cur.Digest
		}
		st.Requests[genericID] = Response{SchemaVersion: SchemaVersion, RequestID: genericID, Namespace: journalInternalNamespace, OK: out.OK, Version: out.Sequence, Digest: out.Digest, Error: out.Error}
		st.RequestFingerprints[genericID] = fp
		st.RequestOrder = append(st.RequestOrder, genericID)
		for len(st.RequestOrder) > maxRetainedRequests {
			old := st.RequestOrder[0]
			st.RequestOrder = st.RequestOrder[1:]
			delete(st.Requests, old)
			delete(st.RequestFingerprints, old)
		}
		return nil
	})
	if err != nil {
		out.Error = journalWireError(err)
		return out, err
	}
	return out, journalResponseError(out)
}
func journalWireError(err error) string {
	for _, e := range []error{ErrCAS, ErrReplay, ErrProtocol, ErrUnavailable} {
		if errors.Is(err, e) {
			return e.Error()
		}
	}
	return ErrUnavailable.Error()
}
func journalResponseError(r JournalResponse) error {
	if r.OK {
		return nil
	}
	for _, e := range []error{ErrCAS, ErrReplay, ErrProtocol, ErrUnavailable} {
		if r.Error == e.Error() {
			return e
		}
	}
	return ErrUnavailable
}
func requestFingerprint(r Request) string {
	b, _ := json.Marshal(r)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
func (s *Store) Request(r Request) (Response, error) {
	if err := r.validate(); err != nil {
		return Response{}, err
	}
	var out Response
	err := s.withLock(func(st *diskState) error {
		fp := requestFingerprint(r)
		if old, ok := st.Requests[r.RequestID]; ok {
			if st.RequestFingerprints[r.RequestID] != fp {
				return ErrReplay
			}
			out = old
			return errNoStoreWrite
		}
		id := r.Namespace + "\x00" + r.Key
		cur := st.Namespaces[id]
		if r.Operation == "cas" {
			if replay, ok := st.LastCAS[id]; ok && replay.RequestID == r.RequestID {
				if replay.Fingerprint != fp {
					return ErrReplay
				}
				out = replay.Response
				return errNoStoreWrite
			}
			if cur.Version != r.ExpectedVersion {
				out = Response{SchemaVersion: SchemaVersion, RequestID: r.RequestID, Namespace: r.Namespace, Error: ErrCAS.Error()}
			} else {
				cur = checkpoint{r.NextVersion, r.Digest}
				st.Namespaces[id] = cur
				out = Response{SchemaVersion: SchemaVersion, RequestID: r.RequestID, OK: true, Namespace: r.Namespace, Version: cur.Version, Digest: cur.Digest}
				st.LastCAS[id] = casReplay{RequestID: r.RequestID, Fingerprint: fp, Response: out}
			}
		} else {
			out = Response{SchemaVersion: SchemaVersion, RequestID: r.RequestID, OK: true, Namespace: r.Namespace, Version: cur.Version, Digest: cur.Digest}
		}
		st.Requests[r.RequestID] = out
		st.RequestFingerprints[r.RequestID] = fp
		st.RequestOrder = append(st.RequestOrder, r.RequestID)
		for len(st.RequestOrder) > maxRetainedRequests {
			old := st.RequestOrder[0]
			st.RequestOrder = st.RequestOrder[1:]
			delete(st.Requests, old)
			delete(st.RequestFingerprints, old)
		}
		return nil
	})
	if err == nil && out.Error == ErrCAS.Error() {
		return out, ErrCAS
	}
	return out, err
}
