package localpd

import (
	"context"
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
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"
)

var (
	ErrHighWaterCorrupt        = errors.New("local-pd high-water integrity failure")
	ErrHighWaterStale          = errors.New("local-pd high-water stale or conflicting event")
	ErrHighWaterGap            = errors.New("local-pd high-water gap or incomplete coverage")
	ErrCloudDecisionStale      = errors.New("local-pd cloud decision is stale")
	ErrHighWaterCheckpoint     = errors.New("local-pd high-water checkpoint mismatch")
	ErrHighWaterAnchorRequired = errors.New("attested high-water checkpoint required")
	ErrHighWaterUnsafePath     = errors.New("unsafe local-pd high-water path")
	digestRE                   = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	idRE                       = regexp.MustCompile(`^[A-Za-z0-9_.:/-]{1,512}$`)
)

type HighWaterRecord struct {
	ConversationID    string        `json:"conversation_id"`
	Class             Class         `json:"class"`
	Mode              DetectionMode `json:"mode"`
	State             string        `json:"state"`
	Revision          uint64        `json:"revision"`
	SourceSequence    uint64        `json:"source_sequence"`
	IngestOrdinal     uint64        `json:"ingest_ordinal"`
	ScannedThrough    uint64        `json:"scanned_through"`
	Complete          bool          `json:"complete"`
	Gap               bool          `json:"gap"`
	PendingParts      bool          `json:"pending_parts"`
	Backfill          bool          `json:"backfill"`
	Revoked           bool          `json:"revoked"`
	Deleted           bool          `json:"deleted"`
	ContentDigest     string        `json:"content_digest"`
	RevisionSetDigest string        `json:"revision_set_digest"`
	CoverageDigest    string        `json:"coverage_digest"`
	PolicyVersion     uint64        `json:"policy_version"`
	PolicyDigest      string        `json:"policy_digest"`
	Marker            bool          `json:"marker"`
	RuleIDs           []string      `json:"rule_ids"`
	Version           uint64        `json:"version"`
	UpdatedAt         time.Time     `json:"updated_at"`
}

type CloudDecisionBinding struct {
	ConversationID    string
	HighWaterVersion  uint64
	ContentDigest     string
	RevisionSetDigest string
	CoverageDigest    string
	PolicyVersion     uint64
	PolicyDigest      string
}

type highWaterState struct {
	SchemaVersion string                     `json:"schema_version"`
	Version       uint64                     `json:"version"`
	Records       map[string]HighWaterRecord `json:"records"`
}

type HighWaterCheckpoint struct {
	Version     uint64
	StateDigest string
}

type HighWaterCheckpointStore interface {
	LoadCheckpoint() (HighWaterCheckpoint, error)
	CommitCheckpoint(expectedVersion uint64, next HighWaterCheckpoint) error
}

// MemoryHighWaterCheckpointStore is test-only and deliberately does not
// provide production rollback resistance.
type MemoryHighWaterCheckpointStore struct {
	mu sync.Mutex
	cp HighWaterCheckpoint
}

func NewMemoryHighWaterCheckpointStore() *MemoryHighWaterCheckpointStore {
	return &MemoryHighWaterCheckpointStore{}
}
func (s *MemoryHighWaterCheckpointStore) LoadCheckpoint() (HighWaterCheckpoint, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cp, nil
}
func (s *MemoryHighWaterCheckpointStore) CommitCheckpoint(expected uint64, next HighWaterCheckpoint) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cp.Version != expected || next.Version != expected+1 || !digestRE.MatchString(next.StateDigest) {
		return ErrHighWaterCheckpoint
	}
	s.cp = next
	return nil
}

// HighWaterLedger persists only metadata and digests. The source text must
// never be placed in this structure or its encrypted file.
type HighWaterLedger struct {
	mu         sync.Mutex
	base       string
	key        []byte
	checkpoint HighWaterCheckpointStore
	root       *os.Root
	lockFile   *os.File
	closed     bool
}

// productionHighWaterCapability is deliberately unexported and currently has
// no minting function. Until a concrete, separately attested OS provider owns
// such a capability, the production constructor is uncallable outside this
// package and rejects even its zero value inside the package.
type productionHighWaterCapability struct{ token *struct{} }

// NewAnchoredHighWaterLedger is reserved for the future concrete anchor
// adapter. No caller can currently obtain its package-owned capability.
func NewAnchoredHighWaterLedger(path string, key []byte, capability productionHighWaterCapability, checkpoint HighWaterCheckpointStore) (*HighWaterLedger, error) {
	if capability.token == nil {
		return nil, ErrHighWaterAnchorRequired
	}
	return nil, ErrHighWaterAnchorRequired
}

// NewTestHighWaterLedger makes the non-production memory anchor explicit.
func NewTestHighWaterLedger(path string, key []byte, checkpoint HighWaterCheckpointStore) (*HighWaterLedger, error) {
	return newHighWaterLedger(path, key, checkpoint)
}

func newHighWaterLedger(path string, key []byte, checkpoint HighWaterCheckpointStore) (*HighWaterLedger, error) {
	if path == "" || len(key) != 32 || checkpoint == nil || !filepath.IsAbs(path) {
		return nil, errors.New("absolute high-water path, 32-byte key, and checkpoint required")
	}
	clean := filepath.Clean(path)
	dirPath := filepath.Dir(clean)
	root, err := openTrustedPrivateRoot(dirPath)
	if err != nil {
		return nil, err
	}
	lockName := filepath.Base(clean) + ".lock"
	if fi, statErr := root.Lstat(lockName); statErr == nil && (fi.Mode()&os.ModeSymlink != 0 || !fi.Mode().IsRegular()) {
		_ = root.Close()
		return nil, ErrHighWaterUnsafePath
	} else if statErr != nil && !os.IsNotExist(statErr) {
		_ = root.Close()
		return nil, statErr
	}
	lock, err := root.OpenFile(lockName, os.O_CREATE|os.O_RDWR|syscall.O_CLOEXEC, 0600)
	if err != nil {
		_ = root.Close()
		return nil, fmt.Errorf("%w: lock: %v", ErrHighWaterUnsafePath, err)
	}
	if err = validatePrivateRegular(root, lock, lockName); err != nil {
		_ = lock.Close()
		_ = root.Close()
		return nil, err
	}
	l := &HighWaterLedger{base: filepath.Base(clean), key: append([]byte(nil), key...), checkpoint: checkpoint, root: root, lockFile: lock}
	if err = l.withLock(func() error { _, e := l.loadVerified(); return e }); err != nil {
		_ = l.Close()
		return nil, err
	}
	return l, nil
}

func openTrustedPrivateRoot(path string) (*os.Root, error) {
	clean := filepath.Clean(path)
	// macOS exposes these two standard aliases as root-owned absolute links.
	// Canonicalize only those fixed prefixes; every remaining component is
	// opened from the preceding Root FD and must itself be a real directory.
	if clean == "/var" || strings.HasPrefix(clean, "/var/") {
		clean = "/private" + clean
	} else if clean == "/tmp" || strings.HasPrefix(clean, "/tmp/") {
		clean = "/private/tmp" + strings.TrimPrefix(clean, "/tmp")
	}
	if !filepath.IsAbs(clean) {
		return nil, ErrHighWaterUnsafePath
	}
	root, err := os.OpenRoot("/")
	if err != nil {
		return nil, err
	}
	components := strings.Split(strings.TrimPrefix(clean, "/"), string(filepath.Separator))
	for _, component := range components {
		if component == "" || component == "." || component == ".." {
			_ = root.Close()
			return nil, ErrHighWaterUnsafePath
		}
		fi, statErr := root.Lstat(component)
		if statErr != nil || !fi.IsDir() || fi.Mode()&os.ModeSymlink != 0 {
			_ = root.Close()
			return nil, fmt.Errorf("%w: directory component %q", ErrHighWaterUnsafePath, component)
		}
		next, openErr := root.OpenRoot(component)
		_ = root.Close()
		if openErr != nil {
			return nil, fmt.Errorf("%w: directory component %q", ErrHighWaterUnsafePath, component)
		}
		root = next
	}
	fi, err := root.Lstat(".")
	if err != nil || !fi.IsDir() || fi.Mode().Perm()&0077 != 0 {
		_ = root.Close()
		return nil, fmt.Errorf("%w: final directory must be owner-private", ErrHighWaterUnsafePath)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != uint32(os.Getuid()) {
		_ = root.Close()
		return nil, ErrHighWaterUnsafePath
	}
	return root, nil
}

func validatePrivateRegular(root *os.Root, f *os.File, name string) error {
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() || fi.Mode().Perm()&0077 != 0 {
		return ErrHighWaterUnsafePath
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != uint32(os.Getuid()) || st.Nlink != 1 {
		return ErrHighWaterUnsafePath
	}
	pathInfo, err := root.Lstat(name)
	if err != nil || pathInfo.Mode()&os.ModeSymlink != 0 || !os.SameFile(fi, pathInfo) {
		return ErrHighWaterUnsafePath
	}
	return nil
}

func (l *HighWaterLedger) withLock(fn func() error) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return errors.New("high-water ledger closed")
	}
	if err := syscall.Flock(int(l.lockFile.Fd()), syscall.LOCK_EX); err != nil {
		return err
	}
	defer func() { _ = syscall.Flock(int(l.lockFile.Fd()), syscall.LOCK_UN) }()
	if err := validatePrivateRegular(l.root, l.lockFile, l.base+".lock"); err != nil {
		return err
	}
	return fn()
}

func (l *HighWaterLedger) seal(p []byte) ([]byte, error) {
	b, err := aes.NewCipher(l.key)
	if err != nil {
		return nil, err
	}
	g, err := cipher.NewGCM(b)
	if err != nil {
		return nil, err
	}
	n := make([]byte, g.NonceSize())
	if _, err = rand.Read(n); err != nil {
		return nil, err
	}
	return g.Seal(n, n, p, nil), nil
}

func (l *HighWaterLedger) open(in []byte) ([]byte, error) {
	b, err := aes.NewCipher(l.key)
	if err != nil {
		return nil, err
	}
	g, err := cipher.NewGCM(b)
	if err != nil || len(in) < g.NonceSize()+g.Overhead() {
		return nil, ErrHighWaterCorrupt
	}
	p, err := g.Open(nil, in[:g.NonceSize()], in[g.NonceSize():], nil)
	if err != nil {
		return nil, ErrHighWaterCorrupt
	}
	return p, nil
}

func (l *HighWaterLedger) loadVerified() (highWaterState, error) {
	cp, err := l.checkpoint.LoadCheckpoint()
	if err != nil {
		return highWaterState{}, fmt.Errorf("%w: %v", ErrHighWaterCheckpoint, err)
	}
	fi, statErr := l.root.Lstat(l.base)
	if statErr == nil && (fi.Mode()&os.ModeSymlink != 0 || !fi.Mode().IsRegular()) {
		return highWaterState{}, ErrHighWaterUnsafePath
	}
	if statErr != nil && !os.IsNotExist(statErr) {
		return highWaterState{}, statErr
	}
	f, err := l.root.OpenFile(l.base, os.O_RDONLY|syscall.O_CLOEXEC, 0)
	if os.IsNotExist(err) {
		if cp.Version != 0 || cp.StateDigest != "" {
			return highWaterState{}, ErrHighWaterCheckpoint
		}
		return highWaterState{SchemaVersion: "local-pd-high-water.v2", Records: map[string]HighWaterRecord{}}, nil
	}
	if err != nil {
		return highWaterState{}, err
	}
	defer f.Close()
	if err = validatePrivateRegular(l.root, f, l.base); err != nil {
		return highWaterState{}, err
	}
	b, err := io.ReadAll(io.LimitReader(f, 16<<20+1))
	if err != nil || len(b) > 16<<20 {
		return highWaterState{}, ErrHighWaterCorrupt
	}
	p, err := l.open(b)
	if err != nil {
		return highWaterState{}, err
	}
	var s highWaterState
	if err = DecodeStrict(p, &s); err != nil || validateHighWaterState(s) != nil {
		return highWaterState{}, ErrHighWaterCorrupt
	}
	d, err := highWaterStateDigest(s)
	if err != nil || cp.Version != s.Version || cp.StateDigest != d {
		return highWaterState{}, ErrHighWaterCheckpoint
	}
	return s, nil
}

func validateHighWaterState(s highWaterState) error {
	if s.SchemaVersion != "local-pd-high-water.v2" || s.Version == 0 || s.Records == nil {
		return ErrHighWaterCorrupt
	}
	for id, r := range s.Records {
		if id == "" || r.ConversationID != id || !idRE.MatchString(id) || r.Version == 0 || r.Version > s.Version || r.Revision == 0 || r.SourceSequence == 0 || r.IngestOrdinal == 0 || r.ScannedThrough == 0 || r.PolicyVersion == 0 || !digestRE.MatchString(r.ContentDigest) || !digestRE.MatchString(r.RevisionSetDigest) || !digestRE.MatchString(r.CoverageDigest) || !digestRE.MatchString(r.PolicyDigest) || r.UpdatedAt.IsZero() || !r.UpdatedAt.Equal(r.UpdatedAt.UTC()) || r.RuleIDs == nil || len(r.RuleIDs) > 64 {
			return ErrHighWaterCorrupt
		}
		if r.Class != ClassL0 && r.Class != ClassL1 && r.Class != ClassL2 && r.Class != ClassL3 {
			return ErrHighWaterCorrupt
		}
		if r.Mode != ModeNormal && r.Mode != ModeQuarantine && r.Mode != ModePD && r.Mode != ModeClosed {
			return ErrHighWaterCorrupt
		}
		if r.State != "open" && r.State != "quarantine" && r.State != "closed" {
			return ErrHighWaterCorrupt
		}
		if r.State == "open" && (r.Mode != ModeNormal || classRank(string(r.Class)) > classRank(string(ClassL1)) || !r.Complete || r.Gap || r.PendingParts || r.Backfill || r.Revoked || r.Deleted) {
			return ErrHighWaterCorrupt
		}
		if r.State == "closed" && (!r.Revoked && !r.Deleted || r.Mode != ModeClosed) {
			return ErrHighWaterCorrupt
		}
		if r.Marker && (r.Class != ClassL3 || r.Mode != ModePD && r.Mode != ModeClosed) {
			return ErrHighWaterCorrupt
		}
		seen := map[string]bool{}
		for _, rule := range r.RuleIDs {
			if !idRE.MatchString(rule) || seen[rule] {
				return ErrHighWaterCorrupt
			}
			seen[rule] = true
		}
	}
	return nil
}

func (l *HighWaterLedger) Snapshot(ctx context.Context, conversationID string) (HighWaterRecord, bool, error) {
	if err := ctx.Err(); err != nil {
		return HighWaterRecord{}, false, err
	}
	if !idRE.MatchString(conversationID) {
		return HighWaterRecord{}, false, ErrInvalidSourceEvent
	}
	var r HighWaterRecord
	var ok bool
	err := l.withLock(func() error {
		s, err := l.loadVerified()
		if err != nil {
			return err
		}
		r, ok = s.Records[conversationID]
		r.RuleIDs = append([]string{}, r.RuleIDs...)
		return nil
	})
	return r, ok, err
}

// Observe durably advances the record even for invalid, incomplete, stale,
// edited, deleted, revoked or gapped input. The associated error is returned
// only after the quarantine/closed revision and external checkpoint commit.
func (l *HighWaterLedger) Observe(ctx context.Context, event SourceEvent, now time.Time) (HighWaterRecord, error) {
	if err := ctx.Err(); err != nil {
		return HighWaterRecord{}, err
	}
	if !idRE.MatchString(event.ConversationID) || now.IsZero() {
		return HighWaterRecord{}, ErrInvalidSourceEvent
	}
	var result HighWaterRecord
	var observationErr error
	err := l.withLock(func() error {
		s, err := l.loadVerified()
		if err != nil {
			return err
		}
		old, exists := s.Records[event.ConversationID]
		d := Detection{Class: ClassL3, Mode: ModeQuarantine, RuleIDs: []string{"invalid-or-uncertain-source-event"}, ContentDigest: digestContent(event.Content)}
		if validForDetection(event) {
			d, err = Detect(event)
			if err != nil {
				d = Detection{Class: ClassL3, Mode: ModeQuarantine, RuleIDs: []string{"detector-failure"}, ContentDigest: digestContent(event.Content)}
			}
		}
		state := "open"
		rules := append([]string{}, d.RuleIDs...)
		if event.Revoked || event.Deleted || exists && old.State == "closed" {
			state, d.Mode, d.Class = "closed", ModeClosed, ClassL3
			rules = append(rules, "source-revoked-or-deleted")
			observationErr = ErrInvalidSourceEvent
		} else if !validForDetection(event) {
			state = "quarantine"
			observationErr = ErrInvalidSourceEvent
		}
		if exists {
			contentChanged := d.ContentDigest != old.ContentDigest
			stale := event.Revision < old.Revision || event.SourceSequence < old.SourceSequence || event.IngestOrdinal <= old.IngestOrdinal || event.ScannedThrough < old.ScannedThrough
			replayOrEdit := event.Revision == old.Revision || event.SourceSequence == old.SourceSequence && contentChanged
			gap := event.SourceSequence > old.SourceSequence+1 || event.ScannedThrough > old.ScannedThrough+1
			if stale || replayOrEdit {
				state = "quarantine"
				rules = append(rules, "stale-replay-or-edit")
				observationErr = ErrHighWaterStale
			}
			if gap {
				state = "quarantine"
				rules = append(rules, "coverage-gap")
				observationErr = ErrHighWaterGap
			}
			if modeRank(d.Mode) < modeRank(old.Mode) {
				d.Mode = old.Mode
			}
			if classRank(string(d.Class)) < classRank(string(old.Class)) {
				d.Class = old.Class
			}
			if old.State == "quarantine" && state == "open" {
				state = "quarantine"
			}
			d.Marker = d.Marker || old.Marker
			rules = append(rules, old.RuleIDs...)
		}
		if state != "closed" && (d.Mode != ModeNormal || classRank(string(d.Class)) > classRank(string(ClassL1))) {
			state = "quarantine"
		}
		if d.Mode == ModePD && state != "closed" {
			state = "quarantine"
		}
		if state == "closed" {
			d.Mode = ModeClosed
		}
		r := HighWaterRecord{
			ConversationID: event.ConversationID, Class: d.Class, Mode: d.Mode, State: state,
			Revision: nonzeroMax(event.Revision, old.Revision), SourceSequence: nonzeroMax(event.SourceSequence, old.SourceSequence), IngestOrdinal: nextOrdinal(event.IngestOrdinal, old.IngestOrdinal), ScannedThrough: nonzeroMax(event.ScannedThrough, old.ScannedThrough),
			Complete: event.Complete && !event.Gap && !event.PendingParts && !event.Backfill, Gap: event.Gap, PendingParts: event.PendingParts, Backfill: event.Backfill, Revoked: event.Revoked || old.Revoked, Deleted: event.Deleted || old.Deleted,
			ContentDigest: d.ContentDigest, RevisionSetDigest: validOrSentinelDigest(event.RevisionSetDigest, "missing-revision-set"), CoverageDigest: validOrSentinelDigest(event.CoverageDigest, "missing-coverage"), PolicyVersion: nonzeroMax(event.PolicyVersion, old.PolicyVersion), PolicyDigest: validOrSentinelDigest(event.PolicyDigest, "missing-policy"),
			Marker: d.Marker, RuleIDs: normalizedRules(rules), Version: 1, UpdatedAt: now.UTC(),
		}
		if exists {
			r.Version = old.Version + 1
		}
		if state != "open" {
			r.Complete = false
		}
		if event.Gap || event.PendingParts || event.Backfill {
			r.Gap = event.Gap
			r.PendingParts = event.PendingParts
			r.Backfill = event.Backfill
		}
		working := highWaterState{SchemaVersion: "local-pd-high-water.v2", Version: s.Version + 1, Records: cloneRecords(s.Records, r)}
		if err = l.persistAndCheckpoint(s.Version, working); err != nil {
			return err
		}
		result = cloneHighWaterRecord(r)
		return nil
	})
	if err != nil {
		return HighWaterRecord{}, err
	}
	return result, observationErr
}

func validForDetection(e SourceEvent) bool {
	return e.Revision > 0 && e.SourceSequence > 0 && e.IngestOrdinal > 0 && e.ScannedThrough > 0 && e.Complete && !e.Gap && !e.PendingParts && !e.Backfill && !e.Revoked && !e.Deleted && e.PolicyVersion > 0 && digestRE.MatchString(e.PolicyDigest) && digestRE.MatchString(e.CoverageDigest) && digestRE.MatchString(e.RevisionSetDigest) && utf8.Valid(e.Content)
}

// ValidateCloudDecision performs the final lock/reload/checkpoint verification
// and accepts only the exact current normal/open, complete, gap-free <=L1
// record with matching policy, coverage and immutable revision-set bindings.
func (l *HighWaterLedger) ValidateCloudDecision(ctx context.Context, d CloudDecisionBinding) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !idRE.MatchString(d.ConversationID) || d.HighWaterVersion == 0 || d.PolicyVersion == 0 || !digestRE.MatchString(d.ContentDigest) || !digestRE.MatchString(d.RevisionSetDigest) || !digestRE.MatchString(d.CoverageDigest) || !digestRE.MatchString(d.PolicyDigest) {
		return ErrCloudDecisionStale
	}
	return l.withLock(func() error {
		s, err := l.loadVerified()
		if err != nil {
			return err
		}
		r, ok := s.Records[d.ConversationID]
		if !ok || r.State != "open" || r.Mode != ModeNormal || classRank(string(r.Class)) > classRank(string(ClassL1)) || !r.Complete || r.Gap || r.PendingParts || r.Backfill || r.Revoked || r.Deleted || r.Version != d.HighWaterVersion || r.ContentDigest != d.ContentDigest || r.RevisionSetDigest != d.RevisionSetDigest || r.CoverageDigest != d.CoverageDigest || r.PolicyVersion != d.PolicyVersion || r.PolicyDigest != d.PolicyDigest {
			return ErrCloudDecisionStale
		}
		return nil
	})
}

func (l *HighWaterLedger) persistAndCheckpoint(expected uint64, s highWaterState) error {
	normalizeState(&s)
	p, err := json.Marshal(s)
	if err != nil {
		return err
	}
	enc, err := l.seal(p)
	if err != nil {
		return err
	}
	if err = l.atomicWrite(enc); err != nil {
		return err
	}
	d, err := highWaterStateDigest(s)
	if err != nil {
		return err
	}
	if err = l.checkpoint.CommitCheckpoint(expected, HighWaterCheckpoint{Version: s.Version, StateDigest: d}); err != nil {
		return fmt.Errorf("%w: %v", ErrHighWaterCheckpoint, err)
	}
	return nil
}

func (l *HighWaterLedger) atomicWrite(enc []byte) error {
	if fi, err := l.root.Lstat(l.base); err == nil && (fi.Mode()&os.ModeSymlink != 0 || !fi.Mode().IsRegular()) {
		return ErrHighWaterUnsafePath
	} else if err != nil && !os.IsNotExist(err) {
		return err
	}
	random := make([]byte, 12)
	if _, err := rand.Read(random); err != nil {
		return err
	}
	tmpName := "." + l.base + ".tmp-" + hex.EncodeToString(random)
	f, err := l.root.OpenFile(tmpName, os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_CLOEXEC, 0600)
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		_ = f.Close()
		if !ok {
			_ = l.root.Remove(tmpName)
		}
	}()
	if err = validatePrivateRegular(l.root, f, tmpName); err != nil {
		return err
	}
	if _, err = f.Write(enc); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = l.root.Rename(tmpName, l.base); err != nil {
		return err
	}
	dirFile, err := l.root.Open(".")
	if err != nil {
		return err
	}
	if err = dirFile.Sync(); err != nil {
		_ = dirFile.Close()
		return fmt.Errorf("high-water directory sync: %w", err)
	}
	if err = dirFile.Close(); err != nil {
		return err
	}
	ok = true
	return nil
}

func highWaterStateDigest(s highWaterState) (string, error) {
	normalizeState(&s)
	b, err := json.Marshal(s)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(h[:]), nil
}

func normalizeState(s *highWaterState) {
	if s.Records == nil {
		s.Records = map[string]HighWaterRecord{}
	}
	for k, r := range s.Records {
		r.RuleIDs = normalizedRules(r.RuleIDs)
		s.Records[k] = r
	}
}

func cloneRecords(in map[string]HighWaterRecord, r HighWaterRecord) map[string]HighWaterRecord {
	out := make(map[string]HighWaterRecord, len(in)+1)
	for k, v := range in {
		out[k] = cloneHighWaterRecord(v)
	}
	out[r.ConversationID] = cloneHighWaterRecord(r)
	return out
}
func cloneHighWaterRecord(r HighWaterRecord) HighWaterRecord {
	r.RuleIDs = append([]string{}, r.RuleIDs...)
	return r
}

func normalizedRules(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, x := range in {
		if idRE.MatchString(x) {
			if _, ok := seen[x]; !ok {
				seen[x] = struct{}{}
				out = append(out, x)
			}
		}
	}
	sort.Strings(out)
	if len(out) > 64 {
		out = out[:64]
	}
	return out
}

func validOrSentinelDigest(v, label string) string {
	if digestRE.MatchString(v) {
		return v
	}
	h := sha256.Sum256([]byte(label))
	return "sha256:" + hex.EncodeToString(h[:])
}
func nonzeroMax(a, b uint64) uint64 {
	if a > b {
		return a
	}
	if b > 0 {
		return b
	}
	return 1
}
func nextOrdinal(got, old uint64) uint64 {
	if got > old {
		return got
	}
	if old == ^uint64(0) {
		return old
	}
	return old + 1
}
func modeRank(m DetectionMode) int {
	switch m {
	case ModeClosed:
		return 3
	case ModePD:
		return 2
	case ModeQuarantine:
		return 1
	default:
		return 0
	}
}

func (l *HighWaterLedger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return nil
	}
	l.closed = true
	for i := range l.key {
		l.key[i] = 0
	}
	l.key = nil
	var errs []string
	if err := l.lockFile.Close(); err != nil {
		errs = append(errs, err.Error())
	}
	if err := l.root.Close(); err != nil {
		errs = append(errs, err.Error())
	}
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}
