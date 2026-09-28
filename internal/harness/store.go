package harness

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"syscall"
)

var (
	ErrRepositoryCorrupt  = errors.New("harness repository integrity failure")
	ErrCommitUncertain    = errors.New("harness repository commit outcome uncertain")
	ErrRepositoryPoisoned = errors.New("harness repository poisoned")
	ErrRepositoryClosed   = errors.New("harness repository closed")
)

// Repository persists only controller state. It is intentionally the sole durable authority.
type Repository interface {
	Load(context.Context) (ControllerSnapshot, error)
	Save(context.Context, ControllerSnapshot) error
}
type CompareAndSwapRepository interface {
	Repository
	CompareAndSwap(context.Context, ControllerSnapshot, ControllerSnapshot) error
}

type MemoryRepository struct {
	mu       sync.Mutex
	snapshot ControllerSnapshot
}

func (r *MemoryRepository) Load(ctx context.Context) (ControllerSnapshot, error) {
	if e := ctx.Err(); e != nil {
		return ControllerSnapshot{}, e
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return cloneSnapshot(r.snapshot), nil
}
func (r *MemoryRepository) Save(ctx context.Context, s ControllerSnapshot) error {
	if e := ctx.Err(); e != nil {
		return e
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.snapshot = cloneSnapshot(s)
	return nil
}
func (r *MemoryRepository) CompareAndSwap(ctx context.Context, old, next ControllerSnapshot) error {
	if e := ctx.Err(); e != nil {
		return e
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.snapshot.Tasks) != 0 || r.snapshot.SchemaVersion != "" {
		dg, _ := SHA256(r.snapshot)
		x, _ := SHA256(old)
		if dg != x {
			return ErrVersionConflict
		}
	}
	r.snapshot = cloneSnapshot(next)
	return nil
}

// EncryptedFileRepository uses AES-GCM and fsync+rename+directory-fsync persistence. An error
// after rename is deliberately reported as uncertain, so callers must poison and reload.
type EncryptedFileRepository struct {
	mu      sync.Mutex
	path    string
	key     []byte
	persist func(string, []byte) error
	closed  bool
}

func NewEncryptedFileRepository(path string, key []byte) (*EncryptedFileRepository, error) {
	if path == "" || len(key) != 32 {
		return nil, errors.New("repository path and 32-byte key required")
	}
	r := &EncryptedFileRepository{path: path, key: append([]byte(nil), key...), persist: atomicWrite}
	if _, e := r.Load(context.Background()); e != nil {
		return nil, e
	}
	return r, nil
}
func NewEncryptedFileRepositoryWithPersister(path string, key []byte, p func(string, []byte) error) (*EncryptedFileRepository, error) {
	r, e := NewEncryptedFileRepository(path, key)
	if e == nil && p != nil {
		r.persist = p
	}
	return r, e
}
func (r *EncryptedFileRepository) Load(ctx context.Context) (ControllerSnapshot, error) {
	if e := ctx.Err(); e != nil {
		return ControllerSnapshot{}, e
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return ControllerSnapshot{}, ErrRepositoryClosed
	}
	b, e := os.ReadFile(r.path)
	if os.IsNotExist(e) {
		return ControllerSnapshot{Tasks: map[string]TaskRecord{}}, nil
	}
	if e != nil {
		return ControllerSnapshot{}, e
	}
	p, e := r.open(b)
	if e != nil {
		return ControllerSnapshot{}, ErrRepositoryCorrupt
	}
	var s ControllerSnapshot
	if e = DecodeStrict(p, &s); e != nil {
		return ControllerSnapshot{}, ErrRepositoryCorrupt
	}
	if e = s.Validate(); e != nil {
		return ControllerSnapshot{}, fmt.Errorf("%w: %v", ErrRepositoryCorrupt, e)
	}
	return cloneSnapshot(s), nil
}
func (r *EncryptedFileRepository) Save(ctx context.Context, s ControllerSnapshot) error {
	if e := ctx.Err(); e != nil {
		return e
	}
	if e := s.Validate(); e != nil {
		return e
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return ErrRepositoryClosed
	}
	p, e := CanonicalJSON(s)
	if e != nil {
		return e
	}
	b, e := r.seal(p)
	if e != nil {
		return e
	}
	return r.persist(r.path, b)
}
func (r *EncryptedFileRepository) CompareAndSwap(ctx context.Context, old, next ControllerSnapshot) error {
	if e := ctx.Err(); e != nil {
		return e
	}
	if e := next.Validate(); e != nil {
		return e
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return ErrRepositoryClosed
	}
	lock, e := openCASLock(r.path)
	if e != nil {
		return e
	}
	defer closeCASLock(lock)
	current, e := r.loadLocked()
	if e != nil {
		return e
	}
	a, _ := SHA256(current)
	b, _ := SHA256(old)
	if a != b {
		return ErrVersionConflict
	}
	p, e := CanonicalJSON(next)
	if e != nil {
		return e
	}
	enc, e := r.seal(p)
	if e != nil {
		return e
	}
	return r.persist(r.path, enc)
}

// openCASLock serializes compare-and-swap across independently opened
// repositories and processes. It is deliberately separate from the controller
// process lock so a Controller cannot deadlock its own repository CAS.
func openCASLock(path string) (*os.File, error) {
	lockPath := filepath.Clean(path) + ".cas.lock"
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, err
	}
	if err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		_ = f.Close()
		return nil, err
	}
	return f, nil
}

func closeCASLock(f *os.File) {
	if f == nil {
		return
	}
	_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	_ = f.Close()
}
func (r *EncryptedFileRepository) loadLocked() (ControllerSnapshot, error) {
	b, e := os.ReadFile(r.path)
	if os.IsNotExist(e) {
		return ControllerSnapshot{SchemaVersion: "controller-snapshot.v1", Tasks: map[string]TaskRecord{}}, nil
	}
	if e != nil {
		return ControllerSnapshot{}, e
	}
	p, e := r.open(b)
	if e != nil {
		return ControllerSnapshot{}, ErrRepositoryCorrupt
	}
	var s ControllerSnapshot
	if e = DecodeStrict(p, &s); e != nil {
		return ControllerSnapshot{}, e
	}
	if e = s.Validate(); e != nil {
		return ControllerSnapshot{}, e
	}
	return s, nil
}

// Close makes the repository unusable and best-effort erases its in-memory key copy.
// It cannot erase copies made by the Go runtime or cryptographic primitives.
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
func (r *EncryptedFileRepository) seal(p []byte) ([]byte, error) {
	b, e := aes.NewCipher(r.key)
	if e != nil {
		return nil, e
	}
	g, e := cipher.NewGCM(b)
	if e != nil {
		return nil, e
	}
	n := make([]byte, g.NonceSize())
	if _, e = rand.Read(n); e != nil {
		return nil, e
	}
	return g.Seal(n, n, p, nil), nil
}
func (r *EncryptedFileRepository) open(in []byte) ([]byte, error) {
	b, e := aes.NewCipher(r.key)
	if e != nil {
		return nil, e
	}
	g, e := cipher.NewGCM(b)
	if e != nil || len(in) < g.NonceSize() {
		return nil, ErrRepositoryCorrupt
	}
	return g.Open(nil, in[:g.NonceSize()], in[g.NonceSize():], nil)
}
func atomicWrite(path string, b []byte) error {
	dir := filepath.Dir(path)
	f, e := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-")
	if e != nil {
		return e
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if e = f.Chmod(0600); e == nil {
		_, e = f.Write(b)
	}
	if e == nil {
		e = f.Sync()
	}
	if c := f.Close(); e == nil {
		e = c
	}
	if e != nil {
		return e
	}
	if e = os.Rename(tmp, path); e != nil {
		return e
	}
	d, e := os.Open(dir)
	if e != nil {
		return fmt.Errorf("%w: %v", ErrCommitUncertain, e)
	}
	defer d.Close()
	if e = d.Sync(); e != nil {
		return fmt.Errorf("%w: %v", ErrCommitUncertain, e)
	}
	return nil
}
