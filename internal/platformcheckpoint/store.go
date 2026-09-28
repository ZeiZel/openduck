package platformcheckpoint

import (
	"bytes"
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
	"sync"
	"syscall"
)

const retained = 1024

type replay struct {
	Fingerprint string   `json:"fingerprint"`
	Response    Response `json:"response"`
}
type diskState struct {
	SchemaVersion   string                   `json:"schema_version"`
	Generation      uint64                   `json:"generation"`
	ValueDigest     string                   `json:"value_digest"`
	Requests        map[string]replay        `json:"requests"`
	Order           []string                 `json:"order"`
	JournalRequests map[string]journalReplay `json:"journal_requests"`
	JournalOrder    []string                 `json:"journal_order"`
}

// legacyDiskState is accepted only during NewStore's one-way authenticated
// migration. It exactly describes the state file written before journal
// replay protection was added.
type legacyDiskState struct {
	SchemaVersion string            `json:"schema_version"`
	Generation    uint64            `json:"generation"`
	ValueDigest   string            `json:"value_digest"`
	Requests      map[string]replay `json:"requests"`
	Order         []string          `json:"order"`
}
type journalReplay struct {
	Fingerprint string          `json:"fingerprint"`
	Response    JournalResponse `json:"response"`
}
type record struct {
	SchemaVersion string `json:"schema_version"`
	Generation    uint64 `json:"generation"`
	Digest        string `json:"digest"`
	MAC           string `json:"mac"`
	StateMAC      string `json:"state_mac"`
}

// Store is an inode-checked, root-FD anchored checkpoint authority.
type Store struct {
	root      *os.Root
	lock      *os.File
	secret    []byte
	fresh     bool
	mu        sync.Mutex
	closeOnce sync.Once
	closeErr  error
}

func NewStore(dir string) (*Store, error) {
	if !filepath.IsAbs(dir) || filepath.Clean(dir) != dir {
		return nil, ErrUnavailable
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	i, e := os.Lstat(dir)
	if e != nil || i == nil || i.Mode()&os.ModeSymlink != 0 || !validPrivateDir(i) {
		if i == nil {
			return nil, ErrUnavailable
		}
		return nil, fmt.Errorf("%w: dir", ErrUnavailable)
	}
	r, e := os.OpenRoot(dir)
	if e != nil {
		return nil, e
	}
	rf, e := r.Open(".")
	if e != nil {
		_ = r.Close()
		return nil, ErrUnavailable
	}
	ri, re := rf.Stat()
	ce := rf.Close()
	if re != nil || ce != nil || !same(i, ri) || !validPrivateDir(ri) {
		_ = r.Close()
		return nil, fmt.Errorf("%w: root identity", ErrUnavailable)
	}
	l, e := r.OpenFile("checkpoint.lock", os.O_CREATE|os.O_RDWR, 0600)
	if e != nil {
		_ = r.Close()
		return nil, e
	}
	li, e := l.Stat()
	lpath, le := r.Lstat("checkpoint.lock")
	if e != nil || le != nil || lpath.Mode()&os.ModeSymlink != 0 || !same(li, lpath) || !validPrivateFile(li) {
		_ = l.Close()
		_ = r.Close()
		return nil, fmt.Errorf("%w: lock", ErrUnavailable)
	}
	s := &Store{root: r, lock: l}
	if e = s.secretInit(); e != nil {
		_ = s.Close()
		return nil, e
	}
	if e = s.initialise(); e != nil {
		_ = s.Close()
		return nil, e
	}
	return s, nil
}
func owned(i os.FileInfo) bool {
	st, ok := i.Sys().(*syscall.Stat_t)
	return ok && uint32(st.Uid) == uint32(os.Getuid()) && uint32(st.Gid) == uint32(os.Getgid())
}
func validPrivateFile(i os.FileInfo) bool {
	if i == nil || !i.Mode().IsRegular() || i.Mode().Perm() != 0600 || !owned(i) {
		return false
	}
	st, ok := i.Sys().(*syscall.Stat_t)
	// FileMode's special-bit representation differs from the kernel mode on
	// Darwin. Check the raw fstat/lstat bits, so both the opened descriptor and
	// the name are rejected when set-id or sticky bits are present.
	return ok && uint32(st.Mode)&07000 == 0
}
func validPrivateDir(i os.FileInfo) bool {
	if i == nil || !i.IsDir() || i.Mode().Perm() != 0700 || !owned(i) {
		return false
	}
	st, ok := i.Sys().(*syscall.Stat_t)
	return ok && uint32(st.Mode)&07000 == 0
}
func syncRoot(r *os.Root) error {
	f, e := r.Open(".")
	if e != nil {
		return e
	}
	e = f.Sync()
	c := f.Close()
	if e == nil {
		e = c
	}
	return e
}
func (s *Store) secretInit() error {
	si, se := s.root.Lstat("checkpoint.secret")
	if se == nil && (si.Mode()&os.ModeSymlink != 0 || !validPrivateFile(si)) {
		return ErrUnavailable
	}
	var b []byte
	var e error
	if errors.Is(se, os.ErrNotExist) {
		s.fresh = true
		b = make([]byte, 32)
		if _, e = rand.Read(b); e != nil {
			return e
		}
		f, x := s.root.OpenFile("checkpoint.secret", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if x != nil {
			return x
		}
		x = writeFull(f, b)
		if x == nil {
			x = f.Sync()
		}
		c := f.Close()
		if x == nil {
			x = c
		}
		if x != nil {
			return x
		}
		x = syncRoot(s.root)
		if x != nil {
			return x
		}
	} else if se != nil {
		return ErrUnavailable
	} else {
		b, e = readPrivateFile(s.root, "checkpoint.secret", 32, 32)
	}
	if e != nil || len(b) != 32 {
		return ErrUnavailable
	}
	s.secret = append([]byte(nil), b...)
	return nil
}
func empty() *diskState {
	return &diskState{SchemaVersion: SchemaVersion, Requests: map[string]replay{}, Order: []string{}, JournalRequests: map[string]journalReplay{}, JournalOrder: []string{}}
}
func (s *Store) initialise() error {
	for _, n := range []string{"checkpoint.next", "checkpoint.state.next", "checkpoint.json.next"} {
		if _, e := s.root.Lstat(n); e == nil {
			return ErrUnavailable
		}
	}
	_, e := s.root.Stat("checkpoint.json")
	if errors.Is(e, os.ErrNotExist) {
		if !s.fresh {
			return ErrUnavailable
		}
		if e := s.save(empty()); e != nil {
			return fmt.Errorf("initial save: %w", e)
		}
		return nil
	}
	if e != nil {
		return ErrUnavailable
	}
	if _, e = s.load(); e == nil {
		return nil
	}
	return s.migrateLegacy()
}
func (s *Store) mac(g uint64, d string) string {
	h := hmac.New(sha256.New, s.secret)
	fmt.Fprintf(h, "%d\x00%s", g, d)
	return hex.EncodeToString(h.Sum(nil))
}
func (s *Store) stateMAC(st *diskState) string {
	b, _ := json.Marshal(st)
	h := hmac.New(sha256.New, s.secret)
	_, _ = h.Write([]byte("state\x00"))
	_, _ = h.Write(b)
	return hex.EncodeToString(h.Sum(nil))
}
func (s *Store) legacyStateMAC(st *legacyDiskState) string {
	b, _ := json.Marshal(st)
	h := hmac.New(sha256.New, s.secret)
	_, _ = h.Write([]byte("state\x00"))
	_, _ = h.Write(b)
	return hex.EncodeToString(h.Sum(nil))
}
func isHex(s string) bool { _, e := hex.DecodeString(s); return e == nil }
func strictUnmarshal(b []byte, v any, required ...string) error {
	if len(b) == 0 || len(b) > 1<<20 || duplicate(b) {
		return ErrUnavailable
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(b, &fields); err != nil || len(fields) != len(required) {
		return ErrUnavailable
	}
	for _, name := range required {
		if _, ok := fields[name]; !ok {
			return ErrUnavailable
		}
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if e := d.Decode(v); e != nil {
		return e
	}
	var x any
	if e := d.Decode(&x); e != io.EOF {
		return ErrUnavailable
	}
	return nil
}

func readPrivateFile(root *os.Root, name string, maxSize, exactSize int64) ([]byte, error) {
	before, err := root.Lstat(name)
	if err != nil || before.Mode()&os.ModeSymlink != 0 || !validPrivateFile(before) || before.Size() <= 0 || before.Size() > maxSize || (exactSize > 0 && before.Size() != exactSize) {
		return nil, ErrUnavailable
	}
	f, err := root.Open(name)
	if err != nil {
		return nil, ErrUnavailable
	}
	opened, statErr := f.Stat()
	if statErr != nil || !same(before, opened) || !validPrivateFile(opened) || opened.Size() != before.Size() {
		_ = f.Close()
		return nil, ErrUnavailable
	}
	b, readErr := io.ReadAll(io.LimitReader(f, maxSize+1))
	after, afterErr := f.Stat()
	closeErr := f.Close()
	pathAfter, pathErr := root.Lstat(name)
	if readErr != nil || afterErr != nil || closeErr != nil || pathErr != nil || len(b) == 0 || int64(len(b)) != before.Size() || int64(len(b)) > maxSize || (exactSize > 0 && int64(len(b)) != exactSize) || !same(opened, after) || !same(opened, pathAfter) || pathAfter.Mode()&os.ModeSymlink != 0 || !validPrivateFile(after) || !validPrivateFile(pathAfter) {
		return nil, ErrUnavailable
	}
	return b, nil
}

func (s *Store) load() (*diskState, error) {
	b, e := readPrivateFile(s.root, "checkpoint.json", 1<<20, 0)
	if e != nil {
		return nil, ErrUnavailable
	}
	var r record
	if strictUnmarshal(b, &r, "schema_version", "generation", "digest", "mac", "state_mac") != nil || r.SchemaVersion != SchemaVersion || r.MAC == "" || r.StateMAC == "" || (r.Generation == 0 && r.Digest != "") || (r.Generation > 0 && !validDigest(r.Digest)) || !hmac.Equal([]byte(r.MAC), []byte(s.mac(r.Generation, r.Digest))) {
		return nil, ErrUnavailable
	}
	var st diskState
	b, e = readPrivateFile(s.root, "checkpoint.state", 1<<20, 0)
	if e != nil {
		return nil, ErrUnavailable
	}
	if strictUnmarshal(b, &st, "schema_version", "generation", "value_digest", "requests", "order", "journal_requests", "journal_order") != nil || st.SchemaVersion != SchemaVersion || st.Requests == nil || st.Order == nil || st.JournalRequests == nil || st.JournalOrder == nil || len(st.Order) > retained || len(st.Requests) != len(st.Order) || len(st.JournalOrder) > retained || len(st.JournalRequests) != len(st.JournalOrder) || (st.Generation == 0 && st.ValueDigest != "") || (st.Generation > 0 && !validDigest(st.ValueDigest)) {
		return nil, ErrUnavailable
	}
	if st.Generation != r.Generation || st.ValueDigest != r.Digest || !hmac.Equal([]byte(r.StateMAC), []byte(s.stateMAC(&st))) {
		return nil, ErrUnavailable
	}
	seen := make(map[string]bool, len(st.Order))
	for _, id := range st.Order {
		entry, ok := st.Requests[id]
		if id == "" || len(id) > maxID || seen[id] || !ok || len(entry.Fingerprint) != sha256.Size*2 || !isHex(entry.Fingerprint) || entry.Response.RequestID != id || entry.Response.validate() != nil || (!entry.Response.OK && entry.Response.Error != ErrCAS.Error()) {
			return nil, ErrUnavailable
		}
		seen[id] = true
	}
	seen = make(map[string]bool, len(st.JournalOrder))
	for _, id := range st.JournalOrder {
		entry, ok := st.JournalRequests[id]
		if !journalID(id) || seen[id] || !ok || !validDigest(entry.Fingerprint) || entry.Response.RequestID != id || entry.Response.Validate() != nil {
			return nil, ErrUnavailable
		}
		seen[id] = true
	}
	return &st, nil
}

// migrateLegacy upgrades only an exact, fully authenticated predecessor
// state. It runs under the same inode-checked advisory lock as mutations, and
// rewrites the state atomically before the Store is made available.
func (s *Store) migrateLegacy() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	before, err := s.lock.Stat()
	if err != nil || !validPrivateFile(before) {
		return ErrUnavailable
	}
	if err = syscall.Flock(int(s.lock.Fd()), syscall.LOCK_EX); err != nil {
		return ErrUnavailable
	}
	defer syscall.Flock(int(s.lock.Fd()), syscall.LOCK_UN)
	after, err := s.lock.Stat()
	path, pathErr := s.root.Lstat("checkpoint.lock")
	if err != nil || pathErr != nil || !same(before, after) || path.Mode()&os.ModeSymlink != 0 || !same(before, path) || !validPrivateFile(after) || !validPrivateFile(path) {
		return ErrUnavailable
	}
	old, err := s.loadLegacy()
	if err != nil {
		return ErrUnavailable
	}
	upgraded := &diskState{SchemaVersion: old.SchemaVersion, Generation: old.Generation, ValueDigest: old.ValueDigest, Requests: old.Requests, Order: old.Order, JournalRequests: map[string]journalReplay{}, JournalOrder: []string{}}
	if err = s.save(upgraded); err != nil {
		return fmt.Errorf("%w: migration", ErrUncertain)
	}
	if _, err = s.load(); err != nil {
		return ErrUncertain
	}
	return nil
}

func (s *Store) loadLegacy() (*legacyDiskState, error) {
	b, err := readPrivateFile(s.root, "checkpoint.json", 1<<20, 0)
	if err != nil {
		return nil, ErrUnavailable
	}
	var r record
	if strictUnmarshal(b, &r, "schema_version", "generation", "digest", "mac", "state_mac") != nil || r.SchemaVersion != SchemaVersion || r.MAC == "" || r.StateMAC == "" || (r.Generation == 0 && r.Digest != "") || (r.Generation > 0 && !validDigest(r.Digest)) || !hmac.Equal([]byte(r.MAC), []byte(s.mac(r.Generation, r.Digest))) {
		return nil, ErrUnavailable
	}
	b, err = readPrivateFile(s.root, "checkpoint.state", 1<<20, 0)
	if err != nil {
		return nil, ErrUnavailable
	}
	var st legacyDiskState
	if strictUnmarshal(b, &st, "schema_version", "generation", "value_digest", "requests", "order") != nil || st.SchemaVersion != SchemaVersion || st.Requests == nil || st.Order == nil || len(st.Order) > retained || len(st.Requests) != len(st.Order) || (st.Generation == 0 && st.ValueDigest != "") || (st.Generation > 0 && !validDigest(st.ValueDigest)) || st.Generation != r.Generation || st.ValueDigest != r.Digest || !hmac.Equal([]byte(r.StateMAC), []byte(s.legacyStateMAC(&st))) {
		return nil, ErrUnavailable
	}
	seen := make(map[string]bool, len(st.Order))
	for _, id := range st.Order {
		entry, ok := st.Requests[id]
		if id == "" || len(id) > maxID || seen[id] || !ok || len(entry.Fingerprint) != sha256.Size*2 || !isHex(entry.Fingerprint) || entry.Response.RequestID != id || entry.Response.validate() != nil || (!entry.Response.OK && entry.Response.Error != ErrCAS.Error()) {
			return nil, ErrUnavailable
		}
		seen[id] = true
	}
	return &st, nil
}
func (s *Store) save(st *diskState) error {
	st.SchemaVersion = SchemaVersion
	meta := record{SchemaVersion: SchemaVersion, Generation: st.Generation, Digest: st.ValueDigest, MAC: s.mac(st.Generation, st.ValueDigest), StateMAC: s.stateMAC(st)}
	mb, _ := json.Marshal(meta)
	b, _ := json.Marshal(st)
	if e := writeAtomic(s.root, "checkpoint.state", b); e != nil {
		return e
	}
	if e := writeAtomic(s.root, "checkpoint.json", mb); e != nil {
		return e
	}
	return syncRoot(s.root)
}
func writeAtomic(root *os.Root, name string, b []byte) error {
	tmp := name + ".next"
	_ = root.Remove(tmp)
	f, e := root.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	e = writeFull(f, b)
	if e == nil {
		e = f.Sync()
	}
	c := f.Close()
	if e == nil {
		e = c
	}
	if e != nil {
		_ = root.Remove(tmp)
		return e
	}
	if e = root.Rename(tmp, name); e != nil {
		return e
	}
	return nil
}
func (s *Store) withLock(fn func(*diskState) error, persist bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	before, e := s.lock.Stat()
	if e != nil {
		return ErrUnavailable
	}
	st, ok := before.Sys().(*syscall.Stat_t)
	if !ok || st.Mode&syscall.S_IFMT != syscall.S_IFREG || !validPrivateFile(before) {
		return ErrUnavailable
	}
	if e = syscall.Flock(int(s.lock.Fd()), syscall.LOCK_EX); e != nil {
		return e
	}
	defer syscall.Flock(int(s.lock.Fd()), syscall.LOCK_UN)
	after, e := s.lock.Stat()
	if e != nil || !same(before, after) {
		return ErrUnavailable
	}
	path, e := s.root.Lstat("checkpoint.lock")
	if e != nil || path.Mode()&os.ModeSymlink != 0 || !same(before, path) || !validPrivateFile(path) {
		return ErrUnavailable
	}
	cur, e := s.load()
	if e != nil {
		return e
	}
	if e = fn(cur); e != nil {
		return e
	}
	if !persist {
		return nil
	}
	if e = s.save(cur); e != nil {
		return fmt.Errorf("%w: %v", ErrUncertain, e)
	}
	check, e := s.load()
	if e != nil || check.Generation != cur.Generation || check.ValueDigest != cur.ValueDigest {
		return ErrUncertain
	}
	return nil
}
func same(a, b os.FileInfo) bool {
	if a == nil || b == nil {
		return false
	}
	x, ok := a.Sys().(*syscall.Stat_t)
	y, ok2 := b.Sys().(*syscall.Stat_t)
	return ok && ok2 && x.Dev == y.Dev && x.Ino == y.Ino
}
func (s *Store) Load() (uint64, string, error) {
	var g uint64
	var d string
	e := s.withLock(func(st *diskState) error { g, d = st.Generation, st.ValueDigest; return nil }, false)
	return g, d, e
}

// JournalSign signs one canonical installer-journal checkpoint and durably
// records the result. A request ID can only ever name this exact binding.
func (s *Store) JournalSign(r JournalRequest) (string, error) {
	if s == nil || r.Operation != "sign" || r.Validate() != nil {
		return "", ErrProtocol
	}
	response, err := s.journal(r)
	if err != nil {
		return "", err
	}
	return response.Signature, nil
}
func (s *Store) JournalVerify(r JournalRequest) error {
	if s == nil || r.Operation != "verify" || r.Validate() != nil {
		return ErrProtocol
	}
	_, err := s.journal(r)
	return err
}

func (s *Store) journal(r JournalRequest) (JournalResponse, error) {
	var out JournalResponse
	var operationErr error
	err := s.withLock(func(st *diskState) error {
		fp := JournalFingerprint(r)
		if old, ok := st.JournalRequests[r.RequestID]; ok {
			if old.Fingerprint != fp {
				return ErrReplay
			}
			out = old.Response
			operationErr = journalResponseError(out)
			return nil
		}
		out = JournalResponse{SchemaVersion: JournalSchemaVersion, RequestID: r.RequestID, Audience: JournalAudience, RequestDigest: fp}
		if r.Operation == "sign" {
			out.OK = true
			out.Signature = s.journalMAC(r)
		} else if !hmac.Equal([]byte(s.journalMAC(journalSignRequest(r))), []byte(r.Signature)) {
			out.Error = ErrReplay.Error()
		} else {
			out.OK = true
		}
		st.JournalRequests[r.RequestID] = journalReplay{Fingerprint: fp, Response: out}
		st.JournalOrder = append(st.JournalOrder, r.RequestID)
		if len(st.JournalOrder) > retained {
			delete(st.JournalRequests, st.JournalOrder[0])
			st.JournalOrder = st.JournalOrder[1:]
		}
		operationErr = journalResponseError(out)
		return nil
	}, true)
	if err != nil {
		return JournalResponse{}, err
	}
	return out, operationErr
}

func journalSignRequest(r JournalRequest) JournalRequest {
	r.Operation, r.Signature = "sign", ""
	return r
}

func (s *Store) journalMAC(r JournalRequest) string {
	// The operation and caller-supplied signature never become part of the
	// signed payload. All checkpoint identity fields remain bound.
	r = journalSignRequest(r)
	b, _ := json.Marshal(struct {
		SchemaVersion string `json:"schema_version"`
		Audience      string `json:"audience"`
		RunID         string `json:"run_id"`
		ReleaseDigest string `json:"release_digest"`
		Nonce         string `json:"nonce"`
		PayloadDigest string `json:"payload_digest"`
		Sequence      uint64 `json:"sequence"`
	}{r.SchemaVersion, r.Audience, r.RunID, r.ReleaseDigest, r.Nonce, r.PayloadDigest, r.Sequence})
	h := hmac.New(sha256.New, s.secret)
	_, _ = h.Write([]byte("openduck.platformcheckpoint.journal-sign.v1\x00"))
	_, _ = h.Write(b)
	return hex.EncodeToString(h.Sum(nil))
}

func journalResponseError(r JournalResponse) error {
	if r.OK {
		return nil
	}
	for _, candidate := range []error{ErrReplay, ErrProtocol, ErrUnavailable, ErrUncertain} {
		if r.Error == candidate.Error() {
			return candidate
		}
	}
	return ErrUnavailable
}
func (s *Store) CAS(id string, expected, next uint64, digest string) error {
	if id == "" {
		return ErrProtocol
	}
	req := Request{SchemaVersion: SchemaVersion, RequestID: id, Operation: "cas", Expected: expected, Next: next, Digest: digest}
	if e := req.validate(); e != nil {
		return e
	}
	var out error
	e := s.withLock(func(st *diskState) error {
		fp := Fingerprint(req)
		if old, ok := st.Requests[id]; ok {
			if old.Fingerprint != fp {
				return ErrReplay
			}
			out = decodeError(old.Response)
			return nil
		}
		if st.Generation != expected || next != expected+1 {
			out = ErrCAS
			resp := Response{SchemaVersion: SchemaVersion, RequestID: id, Error: ErrCAS.Error()}
			st.Requests[id] = replay{Fingerprint: fp, Response: resp}
			st.Order = append(st.Order, id)
			if len(st.Order) > retained {
				delete(st.Requests, st.Order[0])
				st.Order = st.Order[1:]
			}
			return nil
		}
		st.Generation = next
		st.ValueDigest = digest
		resp := Response{SchemaVersion: SchemaVersion, RequestID: id, OK: true, Generation: next, Digest: digest}
		st.Requests[id] = replay{Fingerprint: fp, Response: resp}
		st.Order = append(st.Order, id)
		if len(st.Order) > retained {
			delete(st.Requests, st.Order[0])
			st.Order = st.Order[1:]
		}
		return nil
	}, true)
	if e != nil {
		return e
	}
	return out
}
func decodeError(r Response) error {
	if r.OK {
		return nil
	}
	if r.Error == ErrCAS.Error() {
		return ErrCAS
	}
	return errors.New(r.Error)
}
func (s *Store) Close() error {
	if s == nil {
		return nil
	}
	s.closeOnce.Do(func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		for i := range s.secret {
			s.secret[i] = 0
		}
		s.secret = nil
		if s.lock != nil {
			s.closeErr = s.lock.Close()
		}
		if s.root != nil {
			if err := s.root.Close(); s.closeErr == nil {
				s.closeErr = err
			}
		}
	})
	return s.closeErr
}
