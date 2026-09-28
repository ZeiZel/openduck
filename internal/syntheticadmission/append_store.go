package syntheticadmission

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"openduck/internal/admission"
)

// appendStore is an independent synthetic append boundary. Its receipt key
// is distinct from the Controller admission key, so the authority cannot
// manufacture a receipt acceptable to its own ledger.
type appendStore struct {
	mu       sync.Mutex
	path     string
	lockPath string
	key      []byte
	records  map[string]admission.CloudAppendReceipt
	closed   bool
}
type appendSnapshot struct {
	Records map[string]admission.CloudAppendReceipt `json:"records"`
	MAC     string                                  `json:"mac"`
}

func newAppendStore(dir string) (*appendStore, error) {
	key, err := loadOrCreateKey(filepath.Join(dir, "append-runtime.key"))
	if err != nil {
		return nil, err
	}
	s := &appendStore{path: filepath.Join(dir, "append-store.json"), lockPath: filepath.Join(dir, "append-store.lock"), key: key, records: make(map[string]admission.CloudAppendReceipt)}
	if err := s.load(); err != nil {
		zeroBytes(key)
		return nil, err
	}
	return s, nil
}
func (s *appendStore) Append(p admission.CloudAdmittedPrompt) (admission.CloudAppendReceipt, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return admission.CloudAppendReceipt{}, errors.New("synthetic append store closed")
	}
	lock, err := os.OpenFile(s.lockPath, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return admission.CloudAppendReceipt{}, err
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		return admission.CloudAppendReceipt{}, err
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	if err := s.load(); err != nil {
		return admission.CloudAppendReceipt{}, err
	}
	if old, ok := s.records[p.IdempotencyKey]; ok {
		return old, nil
	}
	hashID := sha256.Sum256([]byte(p.IdempotencyKey))
	r := admission.CloudAppendReceipt{SchemaVersion: admission.CloudAppendReceiptV1, AdmissionID: p.AdmissionID, PromptDigest: p.Digest, ContentDigest: p.ContentDigest, DestinationStore: p.DSHAppendStore, DestinationRecord: "record_" + hex.EncodeToString(hashID[:8]), DestinationSchema: p.DSHAppendSchema, ObservedAppendRevision: 1, ObservedAt: time.Now().UTC(), SignerAttestationDigest: digest([]byte("synthetic-append-store"))}
	u := r
	u.ReceiptSignature = ""
	u.Digest = ""
	b, _ := json.Marshal(u)
	r.Digest, _ = admission.CanonicalDigest(json.RawMessage(b))
	r.ReceiptSignature = s.sign(b)
	if err := r.Validate(); err != nil {
		return admission.CloudAppendReceipt{}, err
	}
	s.records[p.IdempotencyKey] = r
	if err := s.persist(); err != nil {
		delete(s.records, p.IdempotencyKey)
		return admission.CloudAppendReceipt{}, err
	}
	return r, nil
}
func (s *appendStore) Query(idempotency string) (admission.CloudAppendReceipt, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return admission.CloudAppendReceipt{}, false, errors.New("synthetic append store closed")
	}
	r, ok := s.records[idempotency]
	return r, ok, nil
}
func (s *appendStore) Verify(r admission.CloudAppendReceipt) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return errors.New("synthetic append store closed")
	}
	u := r
	sig := u.ReceiptSignature
	d := u.Digest
	u.ReceiptSignature = ""
	u.Digest = ""
	b, _ := json.Marshal(u)
	expected, _ := admission.CanonicalDigest(json.RawMessage(b))
	if expected != d || !s.verify(b, sig) {
		return ErrSyntheticAuth
	}
	return nil
}

func (s *appendStore) Close() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	zeroBytes(s.key)
	s.key = nil
	s.closed = true
}
func (s *appendStore) sign(b []byte) string {
	h := hmac.New(sha256.New, s.key)
	_, _ = h.Write(b)
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}
func (s *appendStore) verify(b []byte, sig string) bool {
	raw, e := hex.DecodeString(stringsTrimPrefix(sig, "sha256:"))
	if e != nil {
		return false
	}
	h := hmac.New(sha256.New, s.key)
	_, _ = h.Write(b)
	return hmac.Equal(raw, h.Sum(nil))
}
func stringsTrimPrefix(s, p string) string {
	if len(s) >= len(p) && s[:len(p)] == p {
		return s[len(p):]
	}
	return s
}
func (s *appendStore) mac(v appendSnapshot) string {
	b, _ := json.Marshal(v.Records)
	h := hmac.New(sha256.New, s.key)
	_, _ = h.Write(b)
	return hex.EncodeToString(h.Sum(nil))
}
func (s *appendStore) load() error {
	b, e := os.ReadFile(s.path)
	if os.IsNotExist(e) {
		return nil
	}
	if e != nil {
		return e
	}
	var v appendSnapshot
	if admission.DecodeStrict(b, &v) != nil || v.Records == nil || v.MAC != s.mac(v) {
		return errors.New("synthetic append store integrity failure")
	}
	s.records = v.Records
	return nil
}
func (s *appendStore) persist() error {
	v := appendSnapshot{Records: s.records}
	v.MAC = s.mac(v)
	b, _ := json.Marshal(v)
	tmp, e := os.CreateTemp(filepath.Dir(s.path), ".append-store-*")
	if e != nil {
		return e
	}
	name := tmp.Name()
	defer os.Remove(name)
	if e = tmp.Chmod(0600); e == nil {
		_, e = tmp.Write(b)
	}
	if e == nil {
		e = tmp.Sync()
	}
	ce := tmp.Close()
	if e == nil {
		e = ce
	}
	if e != nil {
		return e
	}
	if e = os.Rename(name, s.path); e != nil {
		return e
	}
	d, e := os.Open(filepath.Dir(s.path))
	if e != nil {
		return e
	}
	defer d.Close()
	return d.Sync()
}
