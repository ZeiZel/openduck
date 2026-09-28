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
	"path/filepath"
	"sync"
)

// PersistentPseudonymStore keeps reversible mappings in a separate encrypted file.
// The key is supplied by the caller and is never persisted.
type PersistentPseudonymStore struct {
	mu       sync.Mutex
	path     string
	key      []byte
	data     map[string]map[string]string // scope -> token -> value
	poisoned bool
	persist  func(string, []byte) error
}
type pseudonymState struct {
	Mappings map[string]map[string]string `json:"mappings"`
}

func NewPersistentPseudonymStore(ctx context.Context, path string, key []byte) (*PersistentPseudonymStore, error) {
	return newPersistentPseudonymStore(ctx, path, key, nil)
}

func NewPersistentPseudonymStoreWithPersister(ctx context.Context, path string, key []byte, persist func(string, []byte) error) (*PersistentPseudonymStore, error) {
	return newPersistentPseudonymStore(ctx, path, key, persist)
}

func newPersistentPseudonymStore(ctx context.Context, path string, key []byte, persist func(string, []byte) error) (*PersistentPseudonymStore, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(key) != 32 {
		return nil, errors.New("pseudonym store key must be 32 bytes")
	}
	s := &PersistentPseudonymStore{path: path, key: append([]byte(nil), key...), data: map[string]map[string]string{}, persist: persist}
	if err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
}
func (s *PersistentPseudonymStore) seal(b []byte) ([]byte, error) {
	c, e := aes.NewCipher(s.key)
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
func (s *PersistentPseudonymStore) open(b []byte) ([]byte, error) {
	c, e := aes.NewCipher(s.key)
	if e != nil {
		return nil, e
	}
	g, e := cipher.NewGCM(c)
	if e != nil || len(b) < g.NonceSize() {
		return nil, errors.New("corrupt pseudonym store")
	}
	return g.Open(nil, b[:g.NonceSize()], b[g.NonceSize():], nil)
}
func (s *PersistentPseudonymStore) load() error {
	b, e := os.ReadFile(s.path)
	if os.IsNotExist(e) {
		return nil
	}
	if e != nil {
		return e
	}
	p, e := s.open(b)
	if e != nil {
		return errors.New("pseudonym store integrity failure")
	}
	var st pseudonymState
	if e = json.Unmarshal(p, &st); e != nil || st.Mappings == nil {
		return errors.New("pseudonym store decode failure")
	}
	s.data = st.Mappings
	return nil
}
func (s *PersistentPseudonymStore) check(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if s.poisoned {
		return errors.New("pseudonym store poisoned")
	}
	return nil
}
func (s *PersistentPseudonymStore) saveLocked() error {
	p, e := json.Marshal(pseudonymState{s.data})
	if e != nil {
		return e
	}
	enc, e := s.seal(p)
	if e != nil {
		return e
	}
	if s.persist != nil {
		return s.persist(s.path, enc)
	}
	dir := filepath.Dir(s.path)
	f, e := os.CreateTemp(dir, "."+filepath.Base(s.path)+".tmp-")
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
	if e = os.Rename(tmp, s.path); e != nil {
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
	return nil
}
func (s *PersistentPseudonymStore) poisonedErr() error {
	if s.poisoned {
		return errors.New("pseudonym store poisoned")
	}
	return nil
}
func (s *PersistentPseudonymStore) uncertainLocked(err error) error {
	s.poisoned = true
	if e := s.load(); e != nil {
		return &CommitUncertainError{Err: fmt.Errorf("%w; reload failed", err)}
	}
	return &CommitUncertainError{Err: err}
}
func (s *PersistentPseudonymStore) Put(ctx context.Context, scope, token, value string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := s.check(ctx); e != nil {
		return e
	}
	if scope == "" || token == "" || value == "" {
		return errors.New("scope, token and value required")
	}
	if s.data[scope] == nil {
		s.data[scope] = map[string]string{}
	}
	old := s.data[scope][token]
	s.data[scope][token] = value
	if e := s.saveLocked(); e != nil {
		var u *CommitUncertainError
		if errors.As(e, &u) {
			return s.uncertainLocked(e)
		}
		if old == "" {
			delete(s.data[scope], token)
		} else {
			s.data[scope][token] = old
		}
		return e
	}
	return nil
}

func (s *PersistentPseudonymStore) Get(ctx context.Context, scope, token string) (string, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.check(ctx); err != nil {
		return "", false, err
	}
	value, ok := s.data[scope][token]
	return value, ok, nil
}
func (s *PersistentPseudonymStore) RehydrateResponse(ctx context.Context, scope, text string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := s.check(ctx); e != nil {
		return "", e
	}
	if scope == "" {
		return "", errors.New("scope required")
	}
	out := text
	for tok, val := range s.data[scope] {
		if containsToken(out, tok) {
			out = replaceToken(out, tok, val)
		}
	}
	for _, tok := range extractTokens(text) {
		if _, ok := s.data[scope][tok]; !ok {
			return "", fmt.Errorf("unknown pseudonym token")
		}
	}
	return out, nil
}
func extractTokens(s string) []string {
	var out []string
	for i := 0; i+34 <= len(s); i++ {
		if s[i:i+2] == "P-" {
			t := s[i : i+34]
			if _, e := hex.DecodeString(t[2:]); e == nil {
				out = append(out, t)
			}
		}
	}
	return out
}
func containsToken(s, t string) bool {
	for i := 0; i+len(t) <= len(s); i++ {
		if s[i:i+len(t)] == t {
			return true
		}
	}
	return false
}
func replaceToken(s, t, v string) string {
	for {
		i := -1
		for j := 0; j+len(t) <= len(s); j++ {
			if s[j:j+len(t)] == t {
				i = j
				break
			}
		}
		if i < 0 {
			return s
		}
		s = s[:i] + v + s[i+len(t):]
	}
}
func (s *PersistentPseudonymStore) PurgeScope(ctx context.Context, scope string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := s.check(ctx); e != nil {
		return e
	}
	old := s.data[scope]
	delete(s.data, scope)
	if e := s.saveLocked(); e != nil {
		var u *CommitUncertainError
		if errors.As(e, &u) {
			return s.uncertainLocked(e)
		}
		s.data[scope] = old
		return e
	}
	return nil
}
func (s *PersistentPseudonymStore) Purge(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := s.check(ctx); e != nil {
		return e
	}
	old := s.data
	s.data = map[string]map[string]string{}
	if e := s.saveLocked(); e != nil {
		var u *CommitUncertainError
		if errors.As(e, &u) {
			return s.uncertainLocked(e)
		}
		s.data = old
		return e
	}
	return nil
}
