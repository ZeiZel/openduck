package mesh

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

const maxJournalBytes = 1 << 20

var (
	ErrRepositoryCorrupt = errors.New("mesh repository integrity failure")
	ErrCommitUncertain   = errors.New("mesh repository commit outcome uncertain")
	ErrRepositoryClosed  = errors.New("mesh repository closed")
)

// EncryptedFileRepository is the production mesh journal: AES-GCM protects
// state at rest and fsync+rename+directory-fsync makes a post-rename failure
// explicitly uncertain. Coordinators must reload/reconcile after that error.
type EncryptedFileRepository struct {
	mu      sync.Mutex
	path    string
	key     []byte
	persist func(string, []byte) error
	policy  RetentionPolicy
	now     func() time.Time
	closed  bool
}

func NewEncryptedFileRepository(path string, key []byte) (*EncryptedFileRepository, error) {
	if path == "" || len(key) != 32 {
		return nil, ErrInvalidContract
	}
	r := &EncryptedFileRepository{path: path, key: append([]byte(nil), key...), persist: atomicWrite, policy: defaultRetentionPolicy(), now: time.Now}
	if _, err := r.Load(context.Background()); err != nil {
		return nil, err
	}
	return r, nil
}

// NewEncryptedFileRepositoryWithRetention is a bounded test/composition seam.
// Production uses the closed default policy; callers cannot select mutation
// class through this constructor.
func NewEncryptedFileRepositoryWithRetention(path string, key []byte, policy RetentionPolicy) (*EncryptedFileRepository, error) {
	if policy.Validate() != nil {
		return nil, ErrInvalidContract
	}
	r, err := NewEncryptedFileRepository(path, key)
	if err != nil {
		return nil, err
	}
	r.policy = policy
	return r, nil
}
func NewEncryptedFileRepositoryWithPersister(path string, key []byte, persist func(string, []byte) error) (*EncryptedFileRepository, error) {
	r, err := NewEncryptedFileRepository(path, key)
	if err == nil && persist != nil {
		r.persist = persist
	}
	return r, err
}
func (r *EncryptedFileRepository) Load(ctx context.Context) (Snapshot, error) {
	if err := ctx.Err(); err != nil {
		return Snapshot{}, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return Snapshot{}, ErrRepositoryClosed
	}
	return r.loadLocked()
}
func (r *EncryptedFileRepository) CompareAndSwap(ctx context.Context, old, next Snapshot) error {
	return r.compareAndSwap(ctx, old, next, journalMutationNormal)
}

// CompareAndSwapSafety is an internal-only escape from the admission reserve.
// It is intentionally not parameterized by untrusted input; composition uses
// it only to finish already-durable control/recovery mutations.
func (r *EncryptedFileRepository) CompareAndSwapSafety(ctx context.Context, old, next Snapshot) error {
	return r.compareAndSwap(ctx, old, next, journalMutationSafety)
}

func (r *EncryptedFileRepository) compareAndSwap(ctx context.Context, old, next Snapshot, class journalMutationClass) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if r == nil || r.policy.Validate() != nil || r.now == nil {
		return ErrUnavailable
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return ErrRepositoryClosed
	}
	lock, err := openMeshCASLock(r.path)
	if err != nil {
		return err
	}
	defer closeMeshCASLock(lock)
	current, err := r.loadLocked()
	if err != nil {
		return err
	}
	if hash(current) != hash(old) {
		return ErrVersionConflict
	}
	next.Version = old.Version + 1
	next, err = prepareJournalCommit(old, next, r.now().UTC(), r.policy, class)
	if err != nil {
		return err
	}
	plain, err := json.Marshal(next)
	if err != nil {
		return err
	}
	sealed, err := r.seal(plain)
	if err != nil {
		return err
	}
	if err = r.persist(r.path, sealed); err != nil {
		if errors.Is(err, ErrCommitUncertain) {
			return err
		}
		return err
	}
	return nil
}
func (r *EncryptedFileRepository) loadLocked() (Snapshot, error) {
	b, err := secureJournalRead(r.path)
	if errors.Is(err, os.ErrNotExist) {
		return emptySnapshot(), nil
	}
	if err != nil {
		return Snapshot{}, ErrRepositoryCorrupt
	}
	plain, err := r.open(b)
	if err != nil {
		return Snapshot{}, ErrRepositoryCorrupt
	}
	var s Snapshot
	d := json.NewDecoder(bytes.NewReader(plain))
	d.DisallowUnknownFields()
	if err = d.Decode(&s); err != nil {
		return Snapshot{}, ErrRepositoryCorrupt
	}
	if err = ensureEOF(d); err != nil {
		return Snapshot{}, ErrRepositoryCorrupt
	}
	// SnapshotV2 predates durable cancellation receipts. The field is additive:
	// a legacy encrypted journal omits it, so normalize only the missing map
	// before strict validation. We do not synthesize a receipt or retry any
	// native operation; terminal legacy runs remain terminal and a later cancel
	// without an exact receipt is denied.
	upgradeSnapshotV2(&s)
	if err = s.Validate(); err != nil {
		return Snapshot{}, fmt.Errorf("%w: %v", ErrRepositoryCorrupt, err)
	}
	return s.clone(), nil
}

func upgradeSnapshotV2(s *Snapshot) {
	if s != nil && s.SchemaVersion == SnapshotV2 {
		if s.CancelReceipts == nil {
			s.CancelReceipts = map[string]CancelReceipt{}
		}
		if s.Tombstones == nil {
			s.Tombstones = map[string]JournalTombstone{}
		}
	}
}

// secureJournalRead rejects links, replacement races and unsafe metadata before
// decoding any attacker-controlled bytes. The journal is single-link, 0600 and
// owned by the process effective UID (root in production).
func secureJournalRead(path string) ([]byte, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !safeRepositoryFile(before) {
		return nil, ErrRepositoryCorrupt
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	after, err := f.Stat()
	if err != nil || !sameRepositoryFile(before, after) || !safeRepositoryFile(after) || after.Size() < 1 || after.Size() > maxJournalBytes {
		return nil, ErrRepositoryCorrupt
	}
	b, err := io.ReadAll(io.LimitReader(f, maxJournalBytes+1))
	if err != nil || len(b) == 0 || len(b) > maxJournalBytes {
		return nil, ErrRepositoryCorrupt
	}
	return b, nil
}

func safeRepositoryFile(info os.FileInfo) bool {
	if info == nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0600 {
		return false
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	return ok && st != nil && st.Nlink == 1 && st.Uid == uint32(os.Geteuid())
}

func sameRepositoryFile(before, after os.FileInfo) bool {
	a, aOK := before.Sys().(*syscall.Stat_t)
	b, bOK := after.Sys().(*syscall.Stat_t)
	return aOK && bOK && a != nil && b != nil && a.Dev == b.Dev && a.Ino == b.Ino
}
func (r *EncryptedFileRepository) Close() error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil
	}
	for i := range r.key {
		r.key[i] = 0
	}
	r.key = nil
	r.closed = true
	return nil
}
func (r *EncryptedFileRepository) seal(plain []byte) ([]byte, error) {
	block, err := aes.NewCipher(r.key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plain, nil), nil
}
func (r *EncryptedFileRepository) open(in []byte) ([]byte, error) {
	block, err := aes.NewCipher(r.key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil || len(in) < gcm.NonceSize() {
		return nil, ErrRepositoryCorrupt
	}
	return gcm.Open(nil, in[:gcm.NonceSize()], in[gcm.NonceSize():], nil)
}
func atomicWrite(path string, b []byte) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(b)
	}
	if err == nil {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err = os.Rename(tmp, path); err != nil {
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrCommitUncertain, err)
	}
	defer d.Close()
	if err = d.Sync(); err != nil {
		return fmt.Errorf("%w: %v", ErrCommitUncertain, err)
	}
	return nil
}
func openMeshCASLock(path string) (*os.File, error) {
	lockPath := filepath.Clean(path) + ".cas.lock"
	if info, err := os.Lstat(lockPath); err == nil {
		if !safeRepositoryFile(info) {
			return nil, ErrRepositoryCorrupt
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, err
	}
	if err = f.Chmod(0600); err != nil {
		_ = f.Close()
		return nil, err
	}
	if info, statErr := f.Stat(); statErr != nil || !safeRepositoryFile(info) {
		_ = f.Close()
		return nil, ErrRepositoryCorrupt
	}
	if err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		_ = f.Close()
		return nil, err
	}
	return f, nil
}
func closeMeshCASLock(f *os.File) {
	if f != nil {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		_ = f.Close()
	}
}
