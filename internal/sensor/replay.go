package sensor

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type replayStore struct {
	mu   sync.Mutex
	path string
	key  []byte
	seen map[string]time.Time
}

func newReplayStore(path string, key []byte) (*replayStore, error) {
	if path == "" || len(key) != 32 {
		return nil, errors.New("invalid replay store")
	}
	r := &replayStore{path: path, key: append([]byte(nil), key...), seen: map[string]time.Time{}}
	if b, err := os.ReadFile(path); err == nil {
		plain, e := r.open(b)
		if e != nil {
			return nil, errors.New("replay store integrity failure")
		}
		if json.Unmarshal(plain, &r.seen) != nil {
			return nil, errors.New("replay store decode failure")
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	return r, nil
}
func (r *replayStore) open(b []byte) ([]byte, error) {
	c, e := aes.NewCipher(r.key)
	if e != nil {
		return nil, e
	}
	g, e := cipher.NewGCM(c)
	if e != nil || len(b) < g.NonceSize() {
		return nil, errors.New("corrupt")
	}
	return g.Open(nil, b[:g.NonceSize()], b[g.NonceSize():], nil)
}
func (r *replayStore) seal(b []byte) ([]byte, error) {
	c, e := aes.NewCipher(r.key)
	if e != nil {
		return nil, e
	}
	g, e := cipher.NewGCM(c)
	if e != nil {
		return nil, e
	}
	n := make([]byte, g.NonceSize())
	if _, e = rand.Read(n); e != nil {
		return nil, e
	}
	return g.Seal(n, n, b, nil), nil
}
func (r *replayStore) reserve(id string, now time.Time, ttl time.Duration) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for k, t := range r.seen {
		if now.Sub(t) > ttl {
			delete(r.seen, k)
		}
	}
	if _, ok := r.seen[id]; ok {
		return ErrReplay
	}
	r.seen[id] = now
	b, e := json.Marshal(r.seen)
	if e != nil {
		return e
	}
	sealed, e := r.seal(b)
	if e != nil {
		return e
	}
	if e = os.MkdirAll(filepath.Dir(r.path), 0700); e != nil {
		return e
	}
	tmp := r.path + ".tmp"
	if e = os.WriteFile(tmp, sealed, 0600); e != nil {
		return e
	}
	if e = os.Rename(tmp, r.path); e != nil {
		_ = os.Remove(tmp)
		return e
	}
	return nil
}
