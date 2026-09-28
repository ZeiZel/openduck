package core

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

func KeyFromEnvRef(name string) ([]byte, error) {
	ref := os.Getenv(name)
	if ref == "" {
		return nil, fmt.Errorf("missing key reference %s", name)
	}
	b, e := os.ReadFile(ref)
	if e != nil {
		return nil, e
	}
	if len(b) != 16 && len(b) != 24 && len(b) != 32 {
		return nil, errors.New("invalid key length")
	}
	return b, nil
}

type KeyProvider interface {
	Key(context.Context) ([]byte, error)
}
type CommitUncertainError struct{ Err error }

func (e *CommitUncertainError) Error() string { return "commit outcome uncertain: " + e.Err.Error() }
func (e *CommitUncertainError) Unwrap() error { return e.Err }

var ErrQueuePoisoned = errors.New("queue poisoned after uncertain commit")

type StaticKeyProvider struct{ Value []byte }

func (p StaticKeyProvider) Key(ctx context.Context) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(p.Value) != 32 {
		return nil, errors.New("invalid key length")
	}
	return append([]byte(nil), p.Value...), nil
}

type MacOSKeychainProvider struct{ Service, Account string }

func NewFileQueueFromProvider(ctx context.Context, path string, provider KeyProvider) (*FileQueue, error) {
	if provider == nil {
		return nil, errors.New("key provider required")
	}
	key, err := provider.Key(ctx)
	if err != nil {
		return nil, err
	}
	return NewFileQueue(path, key)
}

func (p MacOSKeychainProvider) Key(ctx context.Context) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	valid := func(s string) bool {
		if s == "" || len(s) > 128 {
			return false
		}
		for _, r := range s {
			if !(r == '-' || r == '_' || r == '.' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9') {
				return false
			}
		}
		return true
	}
	if !valid(p.Service) || !valid(p.Account) {
		return nil, errors.New("invalid keychain service or account")
	}
	out, err := exec.CommandContext(ctx, "/usr/bin/security", "find-generic-password", "-s", p.Service, "-a", p.Account, "-w").Output()
	if err != nil {
		return nil, errors.New("keychain lookup failed")
	}
	b := []byte(strings.TrimSpace(string(out)))
	if len(b) != 32 {
		return nil, errors.New("keychain key must be 32 bytes")
	}
	return b, nil
}

// FileQueue is a small encrypted-at-rest queue. The key is supplied by the caller
// (typically an ephemeral test key or a reference resolved outside configuration).
// It never serializes the key or plaintext to logs.
type FileQueue struct {
	mu       sync.Mutex
	path     string
	key      []byte
	mem      *MemoryQueue
	leases   map[string]LeaseRecord
	persist  func(string, []byte) error
	poisoned bool
	degraded bool
	reason   string
}
type LeaseRecord struct {
	Token     string       `json:"token"`
	Event     InboundEvent `json:"event"`
	Worker    string       `json:"worker"`
	ExpiresAt time.Time    `json:"expires_at"`
}

func NewFileQueue(path string, key []byte) (*FileQueue, error) {
	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		return nil, errors.New("queue key must be 16, 24, or 32 bytes")
	}
	q := &FileQueue{path: path, key: append([]byte(nil), key...), mem: NewMemoryQueue(), leases: map[string]LeaseRecord{}, persist: atomicPersist}
	if err := q.load(); err != nil {
		return nil, err
	}
	return q, nil
}
func NewFileQueueWithPersister(path string, key []byte, persist func(string, []byte) error) (*FileQueue, error) {
	q, e := NewFileQueue(path, key)
	if e == nil && persist != nil {
		q.persist = persist
	}
	return q, e
}
func (q *FileQueue) seal(data []byte) ([]byte, error) {
	b, _ := aes.NewCipher(q.key)
	a, _ := cipher.NewGCM(b)
	n := make([]byte, a.NonceSize())
	if _, e := rand.Read(n); e != nil {
		return nil, e
	}
	return a.Seal(n, n, data, nil), nil
}
func (q *FileQueue) open(data []byte) ([]byte, error) {
	b, e := aes.NewCipher(q.key)
	if e != nil {
		return nil, e
	}
	a, e := cipher.NewGCM(b)
	if e != nil || len(data) < a.NonceSize() {
		return nil, errors.New("corrupt queue")
	}
	return a.Open(nil, data[:a.NonceSize()], data[a.NonceSize():], nil)
}
func (q *FileQueue) load() error { q.mu.Lock(); defer q.mu.Unlock(); return q.loadUnlocked() }
func (q *FileQueue) loadUnlocked() error {
	raw, e := os.ReadFile(q.path)
	if os.IsNotExist(e) {
		return nil
	}
	if e != nil {
		return e
	}
	plain, e := q.open(raw)
	if e != nil {
		return errors.New("queue integrity failure")
	}
	var state struct {
		Events []InboundEvent `json:"events"`
		Leases []LeaseRecord  `json:"leases"`
	}
	if e = json.Unmarshal(plain, &state); e != nil {
		return errors.New("queue decode failure")
	}
	for _, x := range state.Events {
		if _, e := q.mem.Enqueue(context.Background(), x); e != nil {
			return errors.New("queue decode failure")
		}
	}
	now := time.Now()
	for _, l := range state.Leases {
		if l.ExpiresAt.After(now) {
			q.leases[l.Token] = l
		} else {
			q.mem.Enqueue(context.Background(), l.Event)
		}
	}
	return nil
}
func (q *FileQueue) reloadUnlocked() error {
	tmp := &FileQueue{path: q.path, key: q.key, mem: NewMemoryQueue(), leases: map[string]LeaseRecord{}}
	if err := tmp.loadUnlocked(); err != nil {
		return err
	}
	q.mem, q.leases = tmp.mem, tmp.leases
	return nil
}
func (q *FileQueue) poisonedErr() error {
	if q.poisoned {
		return fmt.Errorf("%w: %s", ErrQueuePoisoned, q.reason)
	}
	return nil
}
func (q *FileQueue) uncertain(err error) error {
	q.poisoned, q.degraded = true, true
	q.reason = err.Error()
	if e := q.reloadUnlocked(); e != nil {
		q.reason += "; reload failed"
	}
	return &CommitUncertainError{Err: err}
}
func (q *FileQueue) snapshot() ([]InboundEvent, map[string]LeaseRecord) {
	q.mem.mu.Lock()
	ev := make([]InboundEvent, 0, len(q.mem.order))
	for _, k := range q.mem.order {
		ev = append(ev, q.mem.events[k])
	}
	q.mem.mu.Unlock()
	leases := make([]LeaseRecord, 0, len(q.leases))
	for _, l := range q.leases {
		leases = append(leases, l)
	}
	copyLeases := make(map[string]LeaseRecord, len(q.leases))
	for k, v := range q.leases {
		copyLeases[k] = v
	}
	return ev, copyLeases
}
func (q *FileQueue) save() error {
	ev, leasesMap := q.snapshot()
	leases := make([]LeaseRecord, 0, len(leasesMap))
	for _, l := range leasesMap {
		leases = append(leases, l)
	}
	plain, _ := json.Marshal(struct {
		Events []InboundEvent `json:"events"`
		Leases []LeaseRecord  `json:"leases"`
	}{ev, leases})
	enc, e := q.seal(plain)
	if e != nil {
		return e
	}
	return q.persist(q.path, enc)
}
func atomicPersist(path string, enc []byte) error {
	dir := filepath.Dir(path)
	f, e := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-")
	if e != nil {
		return e
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if e = f.Chmod(0600); e == nil {
		_, e = f.Write(enc)
	}
	if e == nil {
		e = f.Sync()
	}
	if ce := f.Close(); e == nil {
		e = ce
	}
	if e != nil {
		return e
	}
	if e = os.Rename(tmp, path); e != nil {
		return e
	}
	d, e := os.Open(dir)
	if e == nil {
		e = d.Sync()
		_ = d.Close()
	}
	if e != nil {
		return &CommitUncertainError{Err: e}
	}
	return e
}
func (q *FileQueue) restore(ev []InboundEvent, leases map[string]LeaseRecord) {
	q.mem = NewMemoryQueue()
	for _, e := range ev {
		_, _ = q.mem.Enqueue(context.Background(), e)
	}
	q.leases = leases
}
func (q *FileQueue) Enqueue(ctx context.Context, e InboundEvent) (bool, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if err := q.poisonedErr(); err != nil {
		return false, err
	}
	oldEv, oldLeases := q.snapshot()
	ok, err := q.mem.Enqueue(ctx, e)
	if err != nil || !ok {
		return ok, err
	}
	if err = q.save(); err != nil {
		if errors.Is(err, ErrQueuePoisoned) {
			return false, err
		}
		var uncertain *CommitUncertainError
		if errors.As(err, &uncertain) {
			return false, q.uncertain(err)
		}
		q.restore(oldEv, oldLeases)
		return false, err
	}
	return true, nil
}
func (q *FileQueue) Dequeue(ctx context.Context) (InboundEvent, bool, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if err := q.poisonedErr(); err != nil {
		return InboundEvent{}, false, err
	}
	oldEv, oldLeases := q.snapshot()
	e, ok, err := q.mem.Dequeue(ctx)
	if err == nil && ok {
		err = q.save()
		if err != nil {
			var uncertain *CommitUncertainError
			if errors.As(err, &uncertain) {
				return e, ok, q.uncertain(err)
			}
			q.restore(oldEv, oldLeases)
		}
	}
	return e, ok, err
}
func (q *FileQueue) Depth() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.mem.Depth()
}
func (q *FileQueue) Health() Health {
	q.mu.Lock()
	defer q.mu.Unlock()
	return Health{Status: func() string {
		if q.poisoned {
			return "poisoned"
		}
		return "ok"
	}(), Mode: "file", QueueDepth: q.mem.Depth(), Degraded: q.degraded, Reason: q.reason}
}
func (q *FileQueue) Purge(ctx context.Context) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	if err := q.poisonedErr(); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	oldEv, oldLeases := q.snapshot()
	q.restore(nil, map[string]LeaseRecord{})
	if e := q.save(); e != nil {
		var uncertain *CommitUncertainError
		if errors.As(e, &uncertain) {
			return q.uncertain(e)
		}
		q.restore(oldEv, oldLeases)
		return e
	}
	if e := os.Remove(q.path); e != nil && !os.IsNotExist(e) {
		q.restore(oldEv, oldLeases)
		_ = q.save()
		return e
	}
	return nil
}

func (q *FileQueue) Lease(ctx context.Context, worker string, ttl time.Duration) (LeaseRecord, error) {
	if ttl <= 0 {
		return LeaseRecord{}, errors.New("lease ttl must be positive")
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	if err := q.poisonedErr(); err != nil {
		return LeaseRecord{}, err
	}
	if err := q.reapLocked(ctx, time.Now()); err != nil {
		return LeaseRecord{}, err
	}
	oldEv, oldLeases := q.snapshot()
	if err := ctx.Err(); err != nil {
		return LeaseRecord{}, err
	}
	e, ok, err := q.mem.Dequeue(ctx)
	if err != nil {
		return LeaseRecord{}, err
	}
	if !ok {
		return LeaseRecord{}, errors.New("queue empty")
	}
	rb := make([]byte, 16)
	if _, err := rand.Read(rb); err != nil {
		return LeaseRecord{}, err
	}
	tok := "lease-" + hex.EncodeToString(rb)
	l := LeaseRecord{Token: tok, Event: e, Worker: worker, ExpiresAt: time.Now().Add(ttl)}
	q.leases[tok] = l
	if err = q.save(); err != nil {
		var uncertain *CommitUncertainError
		if errors.As(err, &uncertain) {
			return LeaseRecord{}, q.uncertain(err)
		}
		q.restore(oldEv, oldLeases)
		delete(q.leases, tok)
		q.mem.Enqueue(context.Background(), e)
		return LeaseRecord{}, err
	}
	return l, nil
}
func (q *FileQueue) reapLocked(ctx context.Context, now time.Time) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	oldEv, oldLeases := q.snapshot()
	changed := false
	for tok, l := range q.leases {
		if !l.ExpiresAt.After(now) {
			delete(q.leases, tok)
			_, _ = q.mem.Enqueue(context.Background(), l.Event)
			changed = true
		}
	}
	if !changed {
		return nil
	}
	if err := q.save(); err != nil {
		var u *CommitUncertainError
		if errors.As(err, &u) {
			return q.uncertain(err)
		}
		q.restore(oldEv, oldLeases)
		return err
	}
	return nil
}
func (q *FileQueue) Ack(ctx context.Context, token string) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	if err := q.poisonedErr(); err != nil {
		return err
	}
	if err := q.reapLocked(ctx, time.Now()); err != nil {
		return err
	}
	oldEv, oldLeases := q.snapshot()
	if err := ctx.Err(); err != nil {
		return err
	}
	if _, ok := q.leases[token]; !ok {
		return errors.New("unknown lease")
	}
	delete(q.leases, token)
	if err := q.save(); err != nil {
		var uncertain *CommitUncertainError
		if errors.As(err, &uncertain) {
			return q.uncertain(err)
		}
		q.restore(oldEv, oldLeases)
		return err
	}
	return nil
}
func (q *FileQueue) Nack(ctx context.Context, token string) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	if err := q.poisonedErr(); err != nil {
		return err
	}
	if err := q.reapLocked(ctx, time.Now()); err != nil {
		return err
	}
	oldEv, oldLeases := q.snapshot()
	if err := ctx.Err(); err != nil {
		return err
	}
	l, ok := q.leases[token]
	if !ok {
		return errors.New("unknown lease")
	}
	delete(q.leases, token)
	q.mem.Enqueue(context.Background(), l.Event)
	if err := q.save(); err != nil {
		var uncertain *CommitUncertainError
		if errors.As(err, &uncertain) {
			return q.uncertain(err)
		}
		q.restore(oldEv, oldLeases)
		return err
	}
	return nil
}
