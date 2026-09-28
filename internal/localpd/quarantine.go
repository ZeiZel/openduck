package localpd

// Synthetic quarantine is the only implementation currently available for
// personal-data payloads.  It stores bytes encrypted under a caller supplied
// test key, while every value crossing the package boundary is an opaque
// reference and a digest-bound metadata record.

import (
	"crypto/aes"
	"crypto/cipher"
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
	"sync"
	"syscall"
	"time"
)

var (
	ErrQuarantineCorrupt           = errors.New("local-pd quarantine integrity failure")
	ErrQuarantineReplay            = errors.New("local-pd quarantine dispatch already consumed")
	ErrQuarantineExpired           = errors.New("local-pd quarantine dispatch expired")
	ErrQuarantineUnsafePath        = errors.New("unsafe local-pd quarantine path")
	ErrQuarantineIsolationRequired = errors.New("attested local-pd isolation required")
	ErrQuarantineNotFound          = errors.New("local-pd quarantine payload not found")
	ErrQuarantineUncertain         = errors.New("local-pd quarantine dispatch outcome uncertain")
	ErrQuarantineLimit             = errors.New("local-pd quarantine capacity exceeded")
)

var payloadRefRE = regexp.MustCompile(`^quarantine://payload/[a-f0-9]{32}$`)

type QuarantineCheckpoint struct {
	Version     uint64
	StateDigest string
}
type QuarantineCheckpointStore interface {
	LoadCheckpoint() (QuarantineCheckpoint, error)
	CommitCheckpoint(uint64, QuarantineCheckpoint) error
}

// MemoryQuarantineCheckpointStore is test-only; production requires an
// external monotonic anchor, just like the high-water ledger.
type MemoryQuarantineCheckpointStore struct {
	mu sync.Mutex
	cp QuarantineCheckpoint
}

func NewMemoryQuarantineCheckpointStore() *MemoryQuarantineCheckpointStore {
	return &MemoryQuarantineCheckpointStore{}
}
func (s *MemoryQuarantineCheckpointStore) LoadCheckpoint() (QuarantineCheckpoint, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cp, nil
}
func (s *MemoryQuarantineCheckpointStore) CommitCheckpoint(expected uint64, next QuarantineCheckpoint) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cp.Version != expected || next.Version != expected+1 || !digestRE.MatchString(next.StateDigest) {
		return ErrQuarantineCorrupt
	}
	s.cp = next
	return nil
}

type PayloadBinding struct {
	HighWaterVersion  uint64
	HighWaterDigest   string
	IngressGateDigest string
	PDSessionDigest   string
	QwenRuntimeDigest string
	QwenConfigDigest  string
}

func (b PayloadBinding) valid() bool {
	return b.HighWaterVersion > 0 && allDigest(b.HighWaterDigest, b.IngressGateDigest, b.PDSessionDigest, b.QwenRuntimeDigest, b.QwenConfigDigest)
}

type quarantineRecord struct {
	Ref            string                    `json:"ref"`
	PayloadDigest  string                    `json:"payload_digest"`
	Binding        PayloadBinding            `json:"binding"`
	IssuedAt       time.Time                 `json:"issued_at"`
	ExpiresAt      time.Time                 `json:"expires_at"`
	Ciphertext     []byte                    `json:"ciphertext"`
	DecisionDigest string                    `json:"decision_digest"`
	DispatchID     string                    `json:"dispatch_id"`
	DispatchNonce  string                    `json:"dispatch_nonce"`
	State          string                    `json:"state"`
	AttemptID      string                    `json:"attempt_id"`
	Purged         bool                      `json:"purged"`
	PurgeState     string                    `json:"purge_state"`
	PurgeIntent    []byte                    `json:"purge_intent,omitempty"`
	PurgeReceipt   *QuarantineErasureReceipt `json:"purge_receipt,omitempty"`
}
type quarantineState struct {
	SchemaVersion string                      `json:"schema_version"`
	Version       uint64                      `json:"version"`
	Records       map[string]quarantineRecord `json:"records"`
}

type Quarantine struct {
	mu         sync.Mutex
	base       string
	key        []byte
	checkpoint QuarantineCheckpointStore
	root       *os.Root
	lockFile   *os.File
	closed     bool
}

const (
	maxQuarantinePayload = 1 << 20
	maxQuarantineRecords = 1024
	maxQuarantineTotal   = 8 << 20
)

type productionIsolationAttestation struct{}

func NewProductionQuarantine(path string, key []byte, _ productionIsolationAttestation, _ QuarantineCheckpointStore) (*Quarantine, error) {
	return nil, ErrQuarantineIsolationRequired
}

func NewTestQuarantine(path string, key []byte, cp QuarantineCheckpointStore) (*Quarantine, error) {
	if path == "" || !filepath.IsAbs(path) || len(key) != 32 || cp == nil {
		return nil, ErrQuarantineUnsafePath
	}
	clean := filepath.Clean(path)
	root, err := openTrustedPrivateRoot(filepath.Dir(clean))
	if err != nil {
		return nil, err
	}
	base := filepath.Base(clean)
	lf, err := root.OpenFile(base+".lock", os.O_CREATE|os.O_RDWR|syscall.O_CLOEXEC, 0600)
	if err != nil {
		root.Close()
		return nil, ErrQuarantineUnsafePath
	}
	if err = validatePrivateRegular(root, lf, base+".lock"); err != nil {
		lf.Close()
		root.Close()
		return nil, err
	}
	q := &Quarantine{base: base, key: append([]byte(nil), key...), checkpoint: cp, root: root, lockFile: lf}
	if err = q.withLock(func() error { _, e := q.load(); return e }); err != nil {
		q.Close()
		return nil, err
	}
	return q, nil
}

func (q *Quarantine) withLock(fn func() error) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed {
		return ErrQuarantineCorrupt
	}
	if err := syscall.Flock(int(q.lockFile.Fd()), syscall.LOCK_EX); err != nil {
		return err
	}
	defer syscall.Flock(int(q.lockFile.Fd()), syscall.LOCK_UN)
	if err := validatePrivateRegular(q.root, q.lockFile, q.base+".lock"); err != nil {
		return err
	}
	return fn()
}
func (q *Quarantine) seal(p []byte) ([]byte, error) {
	b, _ := aes.NewCipher(q.key)
	g, _ := cipher.NewGCM(b)
	n := make([]byte, g.NonceSize())
	if _, e := rand.Read(n); e != nil {
		return nil, e
	}
	return g.Seal(n, n, p, nil), nil
}
func (q *Quarantine) open(p []byte) ([]byte, error) {
	b, _ := aes.NewCipher(q.key)
	g, _ := cipher.NewGCM(b)
	if len(p) < g.NonceSize()+g.Overhead() {
		return nil, ErrQuarantineCorrupt
	}
	x, e := g.Open(nil, p[:g.NonceSize()], p[g.NonceSize():], nil)
	if e != nil {
		return nil, ErrQuarantineCorrupt
	}
	return x, nil
}
func (q *Quarantine) load() (quarantineState, error) {
	cp, e := q.checkpoint.LoadCheckpoint()
	if e != nil {
		return quarantineState{}, ErrQuarantineCorrupt
	}
	fi, se := q.root.Lstat(q.base)
	if se == nil && (fi.Mode()&os.ModeSymlink != 0 || !fi.Mode().IsRegular()) {
		return quarantineState{}, ErrQuarantineUnsafePath
	}
	if os.IsNotExist(se) {
		if cp.Version != 0 {
			return quarantineState{}, ErrQuarantineCorrupt
		}
		return quarantineState{SchemaVersion: "local-pd-quarantine.v1", Records: map[string]quarantineRecord{}}, nil
	}
	if se != nil {
		return quarantineState{}, se
	}
	f, e := q.root.OpenFile(q.base, os.O_RDONLY|syscall.O_CLOEXEC, 0)
	if e != nil {
		return quarantineState{}, e
	}
	defer f.Close()
	if e = validatePrivateRegular(q.root, f, q.base); e != nil {
		return quarantineState{}, e
	}
	enc, e := io.ReadAll(io.LimitReader(f, 16<<20+1))
	if e != nil || len(enc) > 16<<20 {
		return quarantineState{}, ErrQuarantineCorrupt
	}
	plain, e := q.open(enc)
	if e != nil {
		return quarantineState{}, e
	}
	var s quarantineState
	if DecodeStrict(plain, &s) != nil || s.SchemaVersion != "local-pd-quarantine.v1" || s.Records == nil || s.Version == 0 {
		return quarantineState{}, ErrQuarantineCorrupt
	}
	d := quarantineDigest(s)
	if cp.Version != s.Version || cp.StateDigest != d {
		return quarantineState{}, ErrQuarantineCorrupt
	}
	if len(s.Records) > maxQuarantineRecords {
		return quarantineState{}, ErrQuarantineCorrupt
	}
	total := 0
	for id, r := range s.Records {
		total += len(r.Ciphertext)
		stateOK := r.State == "pending" || r.State == "consuming" || r.State == "consumed" || r.State == "uncertain"
		boundOK := r.State == "pending" && r.DispatchID == "" && r.DispatchNonce == "" && r.DecisionDigest == "" && r.AttemptID == "" || r.State != "pending" && validID(r.DispatchID) && validID(r.DispatchNonce) && digestRE.MatchString(r.DecisionDigest) && validID(r.AttemptID)
		intentValid := false
		if len(r.PurgeIntent) > 0 {
			var ir QuarantineErasureReceipt
			if DecodeStrict(r.PurgeIntent, &ir) == nil && ir.ControllerSignature == "" && ir.Digest == "" && ir.validateUnsigned() == nil {
				u, _ := ir.CanonicalUnsigned()
				intentValid = string(u) == string(r.PurgeIntent)
			}
		}
		receiptMatches := false
		if r.PurgeReceipt != nil {
			u, _ := r.PurgeReceipt.CanonicalUnsigned()
			receiptMatches = string(u) == string(r.PurgeIntent)
		}
		purgeOK := r.PurgeState == "" && len(r.PurgeIntent) == 0 && r.PurgeReceipt == nil && !r.Purged || r.PurgeState == "pending" && intentValid && r.PurgeReceipt == nil && !r.Purged || r.PurgeState == "complete" && intentValid && r.PurgeReceipt != nil && r.Purged && r.PurgeReceipt.Validate() == nil && receiptMatches
		cipherOK := r.PurgeState == "pending" || !r.Purged && len(r.Ciphertext) > 0 || r.Purged && len(r.Ciphertext) == 0
		if id != r.Ref || !payloadRefRE.MatchString(id) || !digestRE.MatchString(r.PayloadDigest) || !r.Binding.valid() || !utc(r.IssuedAt) || !utc(r.ExpiresAt) || !r.ExpiresAt.After(r.IssuedAt) || !stateOK || !boundOK || !purgeOK || !cipherOK {
			return quarantineState{}, fmt.Errorf("%w: record metadata state=%t bound=%t purge=%t cipher=%t", ErrQuarantineCorrupt, stateOK, boundOK, purgeOK, cipherOK)
		}
	}
	if total > maxQuarantineTotal {
		return quarantineState{}, ErrQuarantineCorrupt
	}
	return s, nil
}
func quarantineDigest(s quarantineState) string {
	b, _ := json.Marshal(s)
	h := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(h[:])
}
func (q *Quarantine) persist(expected uint64, s quarantineState) error {
	if len(s.Records) > maxQuarantineRecords {
		return ErrQuarantineLimit
	}
	total := 0
	for _, r := range s.Records {
		total += len(r.Ciphertext)
	}
	if total > maxQuarantineTotal {
		return ErrQuarantineLimit
	}
	p, e := json.Marshal(s)
	if e != nil {
		return e
	}
	enc, e := q.seal(p)
	if e != nil {
		return e
	}
	if e = q.atomicWrite(enc); e != nil {
		return e
	}
	if e = q.checkpoint.CommitCheckpoint(expected, QuarantineCheckpoint{Version: s.Version, StateDigest: quarantineDigest(s)}); e != nil {
		return ErrQuarantineCorrupt
	}
	return nil
}
func (q *Quarantine) atomicWrite(enc []byte) error {
	n := make([]byte, 12)
	if _, e := rand.Read(n); e != nil {
		return e
	}
	tmp := "." + q.base + ".tmp-" + hex.EncodeToString(n)
	f, e := q.root.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_CLOEXEC, 0600)
	if e != nil {
		return e
	}
	ok := false
	defer func() {
		f.Close()
		if !ok {
			q.root.Remove(tmp)
		}
	}()
	if e = validatePrivateRegular(q.root, f, tmp); e != nil {
		return e
	}
	if _, e = f.Write(enc); e != nil {
		return e
	}
	if e = f.Sync(); e != nil {
		return e
	}
	if e = f.Close(); e != nil {
		return e
	}
	if e = q.root.Rename(tmp, q.base); e != nil {
		return e
	}
	d, e := q.root.Open(".")
	if e != nil {
		return e
	}
	e = d.Sync()
	d.Close()
	if e != nil {
		return e
	}
	ok = true
	return nil
}

// Put encrypts bytes immediately and returns only an opaque reference.
func (q *Quarantine) Put(content []byte, binding PayloadBinding, issued, expires time.Time) (string, error) {
	if len(content) == 0 || len(content) > maxQuarantinePayload || !binding.valid() || !utc(issued) || !utc(expires) || !expires.After(issued) {
		return "", ErrQuarantineCorrupt
	}
	sum := sha256.Sum256(content)
	var refBytes [16]byte
	if _, e := rand.Read(refBytes[:]); e != nil {
		return "", e
	}
	ref := "quarantine://payload/" + hex.EncodeToString(refBytes[:])
	enc, e := q.seal(content)
	if e != nil {
		return "", e
	}
	r := quarantineRecord{Ref: ref, PayloadDigest: "sha256:" + hex.EncodeToString(sum[:]), Binding: binding, IssuedAt: issued, ExpiresAt: expires, Ciphertext: enc, State: "pending"}
	var out string
	e = q.withLock(func() error {
		s, e := q.load()
		if e != nil {
			return e
		}
		s.Version++
		if s.Records == nil {
			s.Records = map[string]quarantineRecord{}
		}
		s.Records[ref] = r
		if e = q.persist(s.Version-1, s); e == nil {
			out = ref
		}
		return e
	})
	return out, e
}

// readForTest exists only for package-level conformance tests. Production
// callers cannot obtain plaintext from Quarantine.
func (q *Quarantine) readForTest(ref string, now time.Time) ([]byte, PayloadBinding, error) {
	if !payloadRefRE.MatchString(ref) {
		return nil, PayloadBinding{}, ErrQuarantineNotFound
	}
	var out []byte
	var b PayloadBinding
	e := q.withLock(func() error {
		s, e := q.load()
		if e != nil {
			return e
		}
		r, ok := s.Records[ref]
		if !ok || r.Purged {
			return ErrQuarantineNotFound
		}
		if !utc(now) || now.Before(r.IssuedAt) || !now.Before(r.ExpiresAt) {
			return ErrQuarantineExpired
		}
		if r.State != "pending" {
			if r.State == "uncertain" {
				return ErrQuarantineUncertain
			}
			return ErrQuarantineReplay
		}
		out, e = q.open(r.Ciphertext)
		if e != nil {
			return e
		}
		sum := sha256.Sum256(out)
		if "sha256:"+hex.EncodeToString(sum[:]) != r.PayloadDigest {
			return ErrQuarantineCorrupt
		}
		b = r.Binding
		return nil
	})
	return out, b, e
}

type payloadLease struct {
	payload      []byte
	binding      PayloadBinding
	ref, attempt string
}

func (l *payloadLease) bytes() []byte { return append([]byte(nil), l.payload...) }
func (l *payloadLease) close() {
	for i := range l.payload {
		l.payload[i] = 0
	}
	l.payload = nil
}

// acquireAndConsume is the sole plaintext lease boundary. It durably changes
// pending -> consuming before decrypting, so replay is rejected before any
// plaintext exists. Only this package can hold the lease.
func (q *Quarantine) acquireAndConsume(ref, dispatchID, nonce, decisionDigest string, expected PayloadBinding, issued, expires, now time.Time) (*payloadLease, error) {
	if !payloadRefRE.MatchString(ref) || !validID(dispatchID) || !validID(nonce) || !digestRE.MatchString(decisionDigest) || !expected.valid() || !utc(issued) || !utc(expires) || !utc(now) {
		return nil, ErrRuntimeBinding
	}
	var lease *payloadLease
	err := q.withLock(func() error {
		s, err := q.load()
		if err != nil {
			return err
		}
		r, ok := s.Records[ref]
		if !ok || r.Purged {
			return ErrQuarantineNotFound
		}
		if r.State != "pending" {
			if r.State == "uncertain" {
				return ErrQuarantineUncertain
			}
			return ErrQuarantineReplay
		}
		if now.Before(r.IssuedAt) || !now.Before(r.ExpiresAt) {
			return ErrQuarantineExpired
		}
		if r.Binding != expected || r.IssuedAt != issued || r.ExpiresAt != expires {
			return ErrRuntimeBinding
		}
		for otherRef, other := range s.Records {
			if otherRef != ref && (other.DispatchID == dispatchID || other.DispatchNonce == nonce) {
				return ErrQuarantineReplay
			}
		}
		attemptBytes := make([]byte, 16)
		if _, err = rand.Read(attemptBytes); err != nil {
			return err
		}
		r.DispatchID, r.DispatchNonce, r.DecisionDigest = dispatchID, nonce, decisionDigest
		r.AttemptID, r.State = hex.EncodeToString(attemptBytes), "consuming"
		s.Version++
		s.Records[ref] = r
		if err = q.persist(s.Version-1, s); err != nil {
			return err
		}
		plain, err := q.open(r.Ciphertext)
		if err != nil {
			r.State = "uncertain"
			s.Version++
			s.Records[ref] = r
			_ = q.persist(s.Version-1, s)
			return err
		}
		sum := sha256.Sum256(plain)
		if "sha256:"+hex.EncodeToString(sum[:]) != r.PayloadDigest {
			for i := range plain {
				plain[i] = 0
			}
			r.State = "uncertain"
			s.Version++
			s.Records[ref] = r
			_ = q.persist(s.Version-1, s)
			return ErrQuarantineCorrupt
		}
		lease = &payloadLease{payload: plain, binding: r.Binding, ref: ref, attempt: r.AttemptID}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return lease, nil
}

func (q *Quarantine) finishAttempt(ref, attempt string, success bool) error {
	return q.withLock(func() error {
		s, err := q.load()
		if err != nil {
			return err
		}
		r, ok := s.Records[ref]
		if !ok || r.Purged || r.State != "consuming" || r.AttemptID != attempt {
			return ErrQuarantineUncertain
		}
		if success {
			r.State = "consumed"
		} else {
			r.State = "uncertain"
		}
		s.Version++
		s.Records[ref] = r
		return q.persist(s.Version-1, s)
	})
}

// ReconcileInterrupted is fail-closed: a process lost while inference was in
// flight becomes terminal uncertain and can never be retried blindly.
func (q *Quarantine) ReconcileInterrupted() error {
	return q.withLock(func() error {
		s, err := q.load()
		if err != nil {
			return err
		}
		changed := false
		for k, r := range s.Records {
			if r.State == "consuming" {
				r.State = "uncertain"
				s.Records[k] = r
				changed = true
			}
		}
		if !changed {
			return nil
		}
		s.Version++
		return q.persist(s.Version-1, s)
	})
}

func (q *Quarantine) Purge(ref string, now time.Time, authority ErasureAuthority) (QuarantineErasureReceipt, error) {
	if !payloadRefRE.MatchString(ref) {
		return QuarantineErasureReceipt{}, ErrQuarantineNotFound
	}
	if authority == nil || !utc(now) {
		return QuarantineErasureReceipt{}, ErrQuarantineCorrupt
	}
	var rec QuarantineErasureReceipt
	var intent []byte
	e := q.withLock(func() error {
		s, e := q.load()
		if e != nil {
			return e
		}
		r, ok := s.Records[ref]
		if !ok {
			return ErrQuarantineNotFound
		}
		if r.PurgeState == "complete" && r.PurgeReceipt != nil {
			if !authority.Verify(r.PurgeIntent, r.PurgeReceipt.ControllerSignature) {
				return ErrQuarantineCorrupt
			}
			rec = *r.PurgeReceipt
			return nil
		}
		if r.PurgeState == "pending" {
			intent = append([]byte(nil), r.PurgeIntent...)
			return nil
		}
		if now.Before(r.ExpiresAt) {
			return ErrQuarantineExpired
		}
		target := r.PayloadDigest
		d, _ := CanonicalDigest(map[string]any{"ref": ref, "target": target, "version": s.Version + 1})
		rec = QuarantineErasureReceipt{SchemaVersion: QuarantineErasureReceiptV1, ReceiptID: "erasure-" + d[7:19], TargetDigest: target, SessionBindingDigest: r.Binding.PDSessionDigest, ErasureVersion: s.Version + 1, HighWater: r.Binding.HighWaterVersion, DeletionStatus: "partial", VerificationMethod: "quarantine_ciphertext_removed", CoverageComplete: false, ErasedAt: now, ExpiresAt: now.Add(24 * time.Hour), EvidenceDigest: d}
		intent, e = rec.CanonicalUnsigned()
		if e != nil {
			return e
		}
		r.PurgeState = "pending"
		r.PurgeIntent = append([]byte(nil), intent...)
		s.Version++
		s.Records[ref] = r
		return q.persist(s.Version-1, s)
	})
	if e != nil || rec.ControllerSignature != "" {
		return rec, e
	}
	var unsignedReceipt QuarantineErasureReceipt
	if DecodeStrict(intent, &unsignedReceipt) != nil {
		return QuarantineErasureReceipt{}, ErrQuarantineCorrupt
	}
	sig, e := authority.Sign(intent)
	if e != nil {
		return QuarantineErasureReceipt{}, e
	}
	if !authority.Verify(intent, sig) {
		return QuarantineErasureReceipt{}, ErrQuarantineCorrupt
	}
	unsignedReceipt.ControllerSignature = sig
	unsignedReceipt.Digest, e = CanonicalDigest(json.RawMessage(intent))
	if e != nil || unsignedReceipt.Validate() != nil {
		return QuarantineErasureReceipt{}, ErrQuarantineCorrupt
	}
	e = q.withLock(func() error {
		s, e := q.load()
		if e != nil {
			return e
		}
		r, ok := s.Records[ref]
		if !ok {
			return ErrQuarantineNotFound
		}
		if r.PurgeState == "complete" && r.PurgeReceipt != nil {
			if !authority.Verify(r.PurgeIntent, r.PurgeReceipt.ControllerSignature) {
				return ErrQuarantineCorrupt
			}
			rec = *r.PurgeReceipt
			return nil
		}
		if r.PurgeState != "pending" || string(r.PurgeIntent) != string(intent) {
			return ErrQuarantineCorrupt
		}
		r.Ciphertext = []byte{}
		r.Purged = true
		r.PurgeState = "complete"
		r.PurgeReceipt = &unsignedReceipt
		s.Version++
		s.Records[ref] = r
		if e = q.persist(s.Version-1, s); e == nil {
			rec = unsignedReceipt
		}
		return e
	})
	return rec, e
}

func (q *Quarantine) ReconcilePendingPurges(authority ErasureAuthority) ([]QuarantineErasureReceipt, error) {
	var refs []string
	err := q.withLock(func() error {
		s, e := q.load()
		if e != nil {
			return e
		}
		for ref, r := range s.Records {
			if r.PurgeState == "pending" {
				refs = append(refs, ref)
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC().Truncate(time.Second)
	out := make([]QuarantineErasureReceipt, 0, len(refs))
	for _, ref := range refs {
		r, e := q.Purge(ref, now, authority)
		if e != nil {
			return out, e
		}
		out = append(out, r)
	}
	return out, nil
}
func (q *Quarantine) Close() error {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed {
		return nil
	}
	q.closed = true
	q.lockFile.Close()
	return q.root.Close()
}
