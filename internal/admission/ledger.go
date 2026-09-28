package admission

// This file contains the local-only admission state machine. It intentionally
// has no provider, HTTP, model, or credential dependencies. Persistence is an
// encrypted opaque snapshot; the Controller remains the only caller allowed
// to turn a consumed append into an egress reservation.

import (
	"bytes"
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
	"syscall"
	"time"
)

type AdmissionState string

const (
	StatePending   AdmissionState = "pending"
	StateConsuming AdmissionState = "consuming"
	StateConsumed  AdmissionState = "consumed"
	StateUncertain AdmissionState = "uncertain"
	StateExpired   AdmissionState = "expired"
	StateRevoked   AdmissionState = "revoked"
)

var (
	ErrAdmissionNotFound     = errors.New("admission not found")
	ErrAdmissionState        = errors.New("invalid admission state transition")
	ErrAdmissionReplay       = errors.New("admission already used")
	ErrAdmissionInvalidated  = errors.New("admission invalidated")
	ErrEgressReserved        = errors.New("egress already reserved")
	ErrReceiptMismatch       = errors.New("append receipt does not match admission")
	ErrLedgerCorrupt         = errors.New("admission ledger integrity failure")
	ErrCheckpointUnavailable = errors.New("admission ledger checkpoint unavailable")
	ErrCheckpointMismatch    = errors.New("admission ledger checkpoint mismatch")
)

type LedgerCheckpoint struct {
	Version     uint64
	StateDigest string
}
type CheckpointStore interface {
	LoadCheckpoint() (LedgerCheckpoint, error)
	CommitCheckpoint(expectedVersion uint64, next LedgerCheckpoint) error
}
type MemoryCheckpointStore struct {
	mu         sync.Mutex
	checkpoint LedgerCheckpoint
}

func NewMemoryCheckpointStore() *MemoryCheckpointStore { return &MemoryCheckpointStore{} }
func (s *MemoryCheckpointStore) LoadCheckpoint() (LedgerCheckpoint, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.checkpoint, nil
}
func (s *MemoryCheckpointStore) CommitCheckpoint(expected uint64, next LedgerCheckpoint) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.checkpoint.Version != expected || next.Version != expected+1 {
		return ErrCheckpointMismatch
	}
	s.checkpoint = next
	return nil
}

// ReceiptVerifier is supplied by the Controller's trusted signer adapter.
// Every constructed ledger starts with a rejecting verifier; callers must
// explicitly install a trusted verifier before receipts can reconcile.
type ReceiptVerifier func(CloudAppendReceipt) error

type AdmissionRecord struct {
	Version            uint64                     `json:"version"`
	Prompt             CloudAdmittedPrompt        `json:"prompt"`
	AuthorityVerified  bool                       `json:"authority_verified"`
	State              AdmissionState             `json:"state"`
	AppendAttemptID    string                     `json:"append_attempt_id,omitempty"`
	Consumption        *CloudAdmissionConsumption `json:"consumption,omitempty"`
	Receipt            *CloudAppendReceipt        `json:"receipt,omitempty"`
	Reservation        *CloudEgressReservation    `json:"reservation,omitempty"`
	InvalidationReason string                     `json:"invalidation_reason,omitempty"`
	UpdatedAt          time.Time                  `json:"updated_at"`
	RecordDigest       string                     `json:"record_digest"`
}

type ledgerSnapshot struct {
	SchemaVersion string                     `json:"schema_version"`
	Version       uint64                     `json:"version"`
	Records       map[string]AdmissionRecord `json:"records"`
}

type Ledger struct {
	mu          sync.Mutex
	path        string
	key         []byte
	persist     func(string, []byte) error
	snapshot    ledgerSnapshot
	checkpoint  CheckpointStore
	closed      bool
	verify      ReceiptVerifier
	verifierSet bool
	now         func() time.Time
}

func NewLedger(path string, key []byte, stores ...CheckpointStore) (*Ledger, error) {
	if path == "" || len(key) != 32 || len(stores) != 1 || stores[0] == nil {
		return nil, errors.New("ledger path and 32-byte key required")
	}
	l := &Ledger{path: path, key: append([]byte(nil), key...), checkpoint: stores[0], persist: atomicLedgerWrite, verify: func(CloudAppendReceipt) error { return ErrCloudOnly }, now: func() time.Time { return time.Now().UTC() }, snapshot: ledgerSnapshot{SchemaVersion: "admission-ledger.v1", Records: map[string]AdmissionRecord{}}}
	if err := l.load(); err != nil {
		return nil, err
	}
	return l, nil
}

func NewMemoryLedger() *Ledger {
	return &Ledger{snapshot: ledgerSnapshot{SchemaVersion: "admission-ledger.v1", Records: map[string]AdmissionRecord{}}, checkpoint: NewMemoryCheckpointStore(), verify: func(CloudAppendReceipt) error { return ErrCloudOnly }, now: func() time.Time { return time.Now().UTC() }}
}

func (l *Ledger) SetReceiptVerifier(v ReceiptVerifier) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.verifierSet {
		return
	}
	l.verifierSet = true
	if v == nil {
		l.verify = func(CloudAppendReceipt) error { return ErrCloudOnly }
		return
	}
	l.verify = v
}
func (l *Ledger) SetClock(now func() time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if now != nil {
		l.now = now
	}
}

// Admit verifies authority before creating any durable record. The contract
// consumer is staged (no external effects); the verified tuple is committed
// atomically as consuming only after authority succeeds.
func (l *Ledger) Admit(ctx context.Context, p CloudAdmittedPrompt, verifier SignatureVerifier) (AdmissionRecord, error) {
	if err := ctx.Err(); err != nil {
		return AdmissionRecord{}, err
	}
	if err := p.Validate(); err != nil {
		return AdmissionRecord{}, err
	}
	staged := &stagedAdmissionConsumer{}
	if err := p.Admit(l.clockNow(), verifier, staged); err != nil {
		return AdmissionRecord{}, err
	}
	return l.transact(ctx, func(s *ledgerSnapshot) (AdmissionRecord, error) {
		if _, ok := s.Records[p.AdmissionID]; ok {
			return AdmissionRecord{}, ErrAdmissionReplay
		}
		now := l.now()
		r := AdmissionRecord{Version: 1, Prompt: clonePrompt(p), AuthorityVerified: true, State: StateConsuming, AppendAttemptID: p.IdempotencyKey, UpdatedAt: now, Consumption: &CloudAdmissionConsumption{SchemaVersion: CloudAdmissionConsumptionV1, AdmissionID: p.AdmissionID, PromptDigest: p.Digest, AppendAttemptID: p.IdempotencyKey, Destination: p.DSHAppendStore, IdempotencyKey: p.IdempotencyKey, State: "consuming", Digest: p.Digest}}
		if err := l.sealRecord(&r); err != nil {
			return AdmissionRecord{}, err
		}
		s.Records[p.AdmissionID] = r
		return cloneRecord(r), nil
	})
}

type stagedAdmissionConsumer struct{ id, nonce string }

func (c *stagedAdmissionConsumer) Consume(id, nonce string) error {
	c.id, c.nonce = id, nonce
	return nil
}

func (l *Ledger) BeginConsumption(ctx context.Context, id, attempt string) (AdmissionRecord, error) {
	if err := ctx.Err(); err != nil {
		return AdmissionRecord{}, err
	}
	if attempt == "" {
		return AdmissionRecord{}, ErrInvalidContract
	}
	return l.transact(ctx, func(s *ledgerSnapshot) (AdmissionRecord, error) {
		r, ok := s.Records[id]
		if !ok {
			return AdmissionRecord{}, ErrAdmissionNotFound
		}
		if r.State != StatePending || !r.AuthorityVerified {
			return AdmissionRecord{}, ErrAdmissionState
		}
		now := l.now()
		if now.After(r.Prompt.ExpiresAt) {
			r.State = StateExpired
			r.InvalidationReason = "ttl"
			r.Version++
			r.UpdatedAt = now
			if err := l.sealRecord(&r); err != nil {
				return AdmissionRecord{}, err
			}
			s.Records[id] = r
			return cloneRecord(r), ErrAdmissionInvalidated
		}
		r.State = StateConsuming
		r.AppendAttemptID = attempt
		r.UpdatedAt = now
		r.Version++
		r.Consumption = &CloudAdmissionConsumption{SchemaVersion: CloudAdmissionConsumptionV1, AdmissionID: id, PromptDigest: r.Prompt.Digest, AppendAttemptID: attempt, Destination: r.Prompt.DSHAppendStore, IdempotencyKey: r.Prompt.IdempotencyKey, State: "consuming", Digest: r.Prompt.Digest}
		if err := l.sealRecord(&r); err != nil {
			return AdmissionRecord{}, err
		}
		s.Records[id] = r
		return cloneRecord(r), nil
	})
}

func (l *Ledger) Reconcile(ctx context.Context, id string, receipt CloudAppendReceipt) (AdmissionRecord, error) {
	if err := ctx.Err(); err != nil {
		return AdmissionRecord{}, err
	}
	if err := receipt.Validate(); err != nil {
		return AdmissionRecord{}, err
	}
	return l.transact(ctx, func(s *ledgerSnapshot) (AdmissionRecord, error) {
		r, ok := s.Records[id]
		if !ok {
			return AdmissionRecord{}, ErrAdmissionNotFound
		}
		if r.State != StateConsuming || receipt.AdmissionID != id || receipt.PromptDigest != r.Prompt.Digest || receipt.ContentDigest != r.Prompt.ContentDigest || receipt.DestinationStore != r.Prompt.DSHAppendStore || receipt.DestinationSchema != r.Prompt.DSHAppendSchema {
			return AdmissionRecord{}, ErrReceiptMismatch
		}
		if l.verify == nil {
			return AdmissionRecord{}, ErrCloudOnly
		}
		if err := l.verify(receipt); err != nil {
			return AdmissionRecord{}, fmt.Errorf("receipt signature: %w", err)
		}
		now := l.now()
		r.State = StateConsumed
		r.Receipt = cloneReceipt(&receipt)
		r.Consumption.State = "consumed"
		r.Consumption.ConsumedAt = now
		r.UpdatedAt = now
		r.Version++
		if err := l.sealRecord(&r); err != nil {
			return AdmissionRecord{}, err
		}
		s.Records[id] = r
		return cloneRecord(r), nil
	})
}

// MarkUncertain is terminal: a late receipt can only be quarantined by the
// caller and can never promote this record.
func (l *Ledger) MarkUncertain(ctx context.Context, id, reason string) (AdmissionRecord, error) {
	return l.invalidate(ctx, id, StateUncertain, reason)
}
func (l *Ledger) Revoke(ctx context.Context, id, reason string) (AdmissionRecord, error) {
	return l.invalidate(ctx, id, StateRevoked, reason)
}
func (l *Ledger) Expire(ctx context.Context, id, reason string) (AdmissionRecord, error) {
	return l.invalidate(ctx, id, StateExpired, reason)
}

// MarkRecoveryUncertain is the narrow crash-recovery transition. A consumed
// record without an egress reservation is not safe to retry blindly; it may
// only be quarantined, never promoted to an active route.
func (l *Ledger) MarkRecoveryUncertain(ctx context.Context, id, reason string) (AdmissionRecord, error) {
	if err := ctx.Err(); err != nil {
		return AdmissionRecord{}, err
	}
	return l.transact(ctx, func(s *ledgerSnapshot) (AdmissionRecord, error) {
		r, ok := s.Records[id]
		if !ok {
			return AdmissionRecord{}, ErrAdmissionNotFound
		}
		if r.State != StateConsumed || r.Reservation != nil {
			return AdmissionRecord{}, ErrAdmissionState
		}
		r.State = StateUncertain
		r.InvalidationReason = reason
		r.UpdatedAt = l.now()
		r.Version++
		if err := l.sealRecord(&r); err != nil {
			return AdmissionRecord{}, err
		}
		s.Records[id] = r
		return cloneRecord(r), nil
	})
}
func (l *Ledger) invalidate(ctx context.Context, id string, state AdmissionState, reason string) (AdmissionRecord, error) {
	if err := ctx.Err(); err != nil {
		return AdmissionRecord{}, err
	}
	if state != StateUncertain && state != StateRevoked && state != StateExpired {
		return AdmissionRecord{}, ErrAdmissionState
	}
	return l.transact(ctx, func(s *ledgerSnapshot) (AdmissionRecord, error) {
		r, ok := s.Records[id]
		if !ok {
			return AdmissionRecord{}, ErrAdmissionNotFound
		}
		if r.State == StateConsumed || r.State == StateUncertain || r.State == StateRevoked || r.State == StateExpired {
			return AdmissionRecord{}, ErrAdmissionState
		}
		r.State = state
		r.InvalidationReason = reason
		r.UpdatedAt = l.now()
		r.Version++
		if err := l.sealRecord(&r); err != nil {
			return AdmissionRecord{}, err
		}
		s.Records[id] = r
		return cloneRecord(r), nil
	})
}

// ReserveEgress performs the final single-use gate. The snapshot and all
// runtime/policy digests must still equal the admitted prompt.
type FinalGate struct {
	Snapshot                                                                                                                  AuthoritativeConversationSnapshot
	RuntimeDigest, DSHDistributionDigest, ProfileDigest, ModelTransportDigest, ToolsetDigest, ToolNetworkDigest, PolicyDigest string
	TargetSessionID, TargetCodexThreadID, ExpectedRunnerBinding                                                               string
}

func (l *Ledger) ReserveEgress(ctx context.Context, id string, gate FinalGate) (AdmissionRecord, error) {
	if err := ctx.Err(); err != nil {
		return AdmissionRecord{}, err
	}
	if err := gate.Snapshot.Validate(); err != nil {
		return AdmissionRecord{}, err
	}
	if !checkDigests(gate.RuntimeDigest, gate.DSHDistributionDigest, gate.ProfileDigest, gate.ModelTransportDigest, gate.ToolsetDigest, gate.ToolNetworkDigest, gate.PolicyDigest) {
		return AdmissionRecord{}, ErrInvalidContract
	}
	return l.transact(ctx, func(s *ledgerSnapshot) (AdmissionRecord, error) {
		r, ok := s.Records[id]
		if !ok {
			return AdmissionRecord{}, ErrAdmissionNotFound
		}
		if r.State != StateConsumed || r.Receipt == nil || r.Reservation != nil {
			return AdmissionRecord{}, ErrEgressReserved
		}
		p := r.Prompt
		if !l.now().Before(p.ExpiresAt) {
			return AdmissionRecord{}, ErrAdmissionInvalidated
		}
		if gate.TargetSessionID != p.TargetSessionID || gate.TargetCodexThreadID != p.TargetCodexThreadID || gate.ExpectedRunnerBinding != p.ExpectedRunnerBinding {
			return AdmissionRecord{}, ErrAdmissionInvalidated
		}
		if gate.Snapshot.ConversationScope != p.ConversationScope || gate.Snapshot.EventRevisionSetDigest != p.EventRevisionSetDigest || gate.Snapshot.CompleteThroughWatermark != p.CompleteThroughWatermark || gate.Snapshot.IngressGateStateDigest != p.IngressGateStateDigest || gate.Snapshot.AuthoritativeCoverageDigest != p.AuthoritativeCoverageDigest || gate.Snapshot.ClassHighWater != p.ClassHighWater || gate.Snapshot.ClassHighWaterVersion != p.ClassHighWaterVersion || gate.RuntimeDigest != p.TargetRuntimeAttestationDigest || gate.DSHDistributionDigest != p.TargetDSHDistributionAttestationDigest || gate.ProfileDigest != p.TargetCodexProfileAttestationDigest || gate.ModelTransportDigest != p.ModelTransportPolicyDigest || gate.ToolsetDigest != p.ToolsetDigest || gate.ToolNetworkDigest != p.ToolNetworkPolicyDigest || gate.PolicyDigest != p.PolicyDigest {
			return AdmissionRecord{}, ErrAdmissionInvalidated
		}
		nonce, err := randomID("egress_")
		if err != nil {
			return AdmissionRecord{}, err
		}
		now := l.now()
		d := CloudEgressReservation{SchemaVersion: CloudEgressReservationV1, ReservationID: randomText("res_"), AdmissionID: id, ConsumptionDigest: r.Consumption.Digest, AppendReceiptDigest: r.Receipt.Digest, EgressNonce: nonce, ReservedAt: now, ExpiresAt: now.Add(time.Hour), TargetRuntimeAttestationDigest: gate.RuntimeDigest, TargetProfileAttestationDigest: gate.ProfileDigest, ModelRoute: p.Route, State: "reserved", ControllerSignature: p.ControllerSignature}
		d.Digest, err = CanonicalDigest(d)
		if err != nil {
			return AdmissionRecord{}, err
		}
		r.Reservation = &d
		r.UpdatedAt = now
		r.Version++
		if err := l.sealRecord(&r); err != nil {
			return AdmissionRecord{}, err
		}
		s.Records[id] = r
		return cloneRecord(r), nil
	})
}

func (l *Ledger) Get(ctx context.Context, id string) (AdmissionRecord, error) {
	if err := ctx.Err(); err != nil {
		return AdmissionRecord{}, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.ready(); err != nil {
		return AdmissionRecord{}, err
	}
	if err := l.reloadForReadLocked(); err != nil {
		return AdmissionRecord{}, err
	}
	r, ok := l.snapshot.Records[id]
	if !ok {
		return AdmissionRecord{}, ErrAdmissionNotFound
	}
	if err := verifyRecord(r); err != nil {
		return AdmissionRecord{}, err
	}
	return cloneRecord(r), nil
}
func (l *Ledger) Snapshot(ctx context.Context) (map[string]AdmissionRecord, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.ready(); err != nil {
		return nil, err
	}
	if err := l.reloadForReadLocked(); err != nil {
		return nil, err
	}
	out := make(map[string]AdmissionRecord, len(l.snapshot.Records))
	for id, r := range l.snapshot.Records {
		if err := verifyRecord(r); err != nil {
			return nil, err
		}
		out[id] = cloneRecord(r)
	}
	return out, nil
}

func (l *Ledger) reloadForReadLocked() error {
	if l.path == "" {
		return nil
	}
	lock, err := ledgerLock(l.path)
	if err != nil {
		return err
	}
	defer func() { _ = syscall.Flock(int(lock.Fd()), syscall.LOCK_UN); _ = lock.Close() }()
	return l.load()
}
func (l *Ledger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return nil
	}
	for i := range l.key {
		l.key[i] = 0
	}
	l.key = nil
	l.closed = true
	return nil
}

func (l *Ledger) ready() error {
	if l.closed {
		return errors.New("admission ledger closed")
	}
	return nil
}

func (l *Ledger) clockNow() time.Time {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.now()
}

// transact is the only mutation path. The process mutex is acquired before
// the filesystem CAS lock; the durable snapshot is reloaded and verified
// while both are held, then persisted atomically before publishing memory.
func (l *Ledger) transact(ctx context.Context, mutate func(*ledgerSnapshot) (AdmissionRecord, error)) (AdmissionRecord, error) {
	if err := ctx.Err(); err != nil {
		return AdmissionRecord{}, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.ready(); err != nil {
		return AdmissionRecord{}, err
	}
	var lock *os.File
	if l.path != "" {
		var err error
		lock, err = ledgerLock(l.path)
		if err != nil {
			return AdmissionRecord{}, err
		}
		defer func() { _ = syscall.Flock(int(lock.Fd()), syscall.LOCK_UN); _ = lock.Close() }()
		if err = l.load(); err != nil {
			return AdmissionRecord{}, err
		}
	}
	working := cloneSnapshot(l.snapshot)
	for _, r := range working.Records {
		if err := verifyRecord(r); err != nil {
			return AdmissionRecord{}, err
		}
	}
	result, err := mutate(&working)
	if err != nil {
		// Expiry is a durable transition even though it returns an error.
		if result.Version == 0 {
			return AdmissionRecord{}, err
		}
	}
	working.Version = l.snapshot.Version + 1
	if err := l.saveSnapshot(working); err != nil {
		return AdmissionRecord{}, err
	}
	if l.path != "" {
		digest, digestErr := snapshotDigest(working)
		if digestErr != nil {
			return AdmissionRecord{}, digestErr
		}
		if err := l.checkpoint.CommitCheckpoint(l.snapshot.Version, LedgerCheckpoint{Version: working.Version, StateDigest: digest}); err != nil {
			return AdmissionRecord{}, fmt.Errorf("%w: %v", ErrCheckpointMismatch, err)
		}
	}
	l.snapshot = working
	if err != nil {
		return AdmissionRecord{}, err
	}
	return result, nil
}

func cloneSnapshot(s ledgerSnapshot) ledgerSnapshot {
	out := ledgerSnapshot{SchemaVersion: s.SchemaVersion, Records: make(map[string]AdmissionRecord, len(s.Records))}
	for id, r := range s.Records {
		out.Records[id] = cloneRecord(r)
	}
	return out
}

func (l *Ledger) sealRecord(r *AdmissionRecord) error {
	r.RecordDigest = ""
	d, err := CanonicalDigest(r)
	if err == nil {
		r.RecordDigest = d
	}
	return err
}
func verifyRecord(r AdmissionRecord) error {
	if r.Version == 0 || !r.AuthorityVerified {
		return ErrLedgerCorrupt
	}
	if r.State != StatePending && r.State != StateConsuming && r.State != StateConsumed && r.State != StateUncertain && r.State != StateExpired && r.State != StateRevoked {
		return ErrLedgerCorrupt
	}
	if r.Consumption == nil || r.Consumption.AdmissionID != r.Prompt.AdmissionID || r.Consumption.PromptDigest != r.Prompt.Digest {
		return ErrLedgerCorrupt
	}
	if r.Receipt != nil && (r.Receipt.AdmissionID != r.Prompt.AdmissionID || r.Receipt.PromptDigest != r.Prompt.Digest) {
		return ErrLedgerCorrupt
	}
	if r.Reservation != nil && (r.Reservation.AdmissionID != r.Prompt.AdmissionID || r.Reservation.ConsumptionDigest != r.Consumption.Digest) {
		return ErrLedgerCorrupt
	}
	d := r.RecordDigest
	r.RecordDigest = ""
	got, err := CanonicalDigest(r)
	if err != nil || got != d {
		return ErrLedgerCorrupt
	}
	return nil
}
func cloneRecord(r AdmissionRecord) AdmissionRecord {
	r.Prompt = clonePrompt(r.Prompt)
	r.Prompt.SafeCapsule.AllowedFields = append([]string(nil), r.Prompt.SafeCapsule.AllowedFields...)
	r.Prompt.SafeCapsule.Constraints = append([]string(nil), r.Prompt.SafeCapsule.Constraints...)
	if r.Prompt.SafeCapsule.Fields != nil {
		r.Prompt.SafeCapsule.Fields = make(map[string]string, len(r.Prompt.SafeCapsule.Fields))
		for k, v := range r.Prompt.SafeCapsule.Fields {
			r.Prompt.SafeCapsule.Fields[k] = v
		}
	}
	if r.Consumption != nil {
		x := *r.Consumption
		r.Consumption = &x
	}
	if r.Receipt != nil {
		x := *r.Receipt
		r.Receipt = &x
	}
	if r.Reservation != nil {
		x := *r.Reservation
		r.Reservation = &x
	}
	return r
}

func clonePrompt(p CloudAdmittedPrompt) CloudAdmittedPrompt {
	p.SourceRefs = append([]string(nil), p.SourceRefs...)
	p.SafeCapsule.AllowedFields = append([]string(nil), p.SafeCapsule.AllowedFields...)
	p.SafeCapsule.Constraints = append([]string(nil), p.SafeCapsule.Constraints...)
	if p.SafeCapsule.Fields != nil {
		p.SafeCapsule.Fields = make(map[string]string, len(p.SafeCapsule.Fields))
		for k, v := range p.SafeCapsule.Fields {
			p.SafeCapsule.Fields[k] = v
		}
	}
	return p
}
func cloneReceipt(r *CloudAppendReceipt) *CloudAppendReceipt {
	if r == nil {
		return nil
	}
	x := *r
	return &x
}

func (l *Ledger) load() error {
	l.snapshot = ledgerSnapshot{SchemaVersion: "admission-ledger.v1", Records: map[string]AdmissionRecord{}}
	if l.path == "" {
		return nil
	}
	b, err := os.ReadFile(l.path)
	if os.IsNotExist(err) {
		cp, cpErr := l.checkpoint.LoadCheckpoint()
		if cpErr != nil {
			return ErrCheckpointUnavailable
		}
		if cp.Version != 0 || cp.StateDigest != "" {
			return ErrCheckpointMismatch
		}
		return nil
	}
	if err != nil {
		return err
	}
	plain, err := l.open(b)
	if err != nil {
		return ErrLedgerCorrupt
	}
	dec := json.NewDecoder(bytes.NewReader(plain))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&l.snapshot); err != nil {
		return ErrLedgerCorrupt
	}
	if l.snapshot.SchemaVersion != "admission-ledger.v1" || l.snapshot.Records == nil {
		return ErrLedgerCorrupt
	}
	for _, r := range l.snapshot.Records {
		if err := verifyRecord(r); err != nil {
			return ErrLedgerCorrupt
		}
	}
	cp, cpErr := l.checkpoint.LoadCheckpoint()
	if cpErr != nil {
		return ErrCheckpointUnavailable
	}
	digest, digestErr := snapshotDigest(l.snapshot)
	if digestErr != nil {
		return ErrLedgerCorrupt
	}
	if cp.Version != l.snapshot.Version || cp.StateDigest != digest {
		return ErrCheckpointMismatch
	}
	return nil
}

func snapshotDigest(s ledgerSnapshot) (string, error) { return CanonicalDigest(s) }
func (l *Ledger) saveSnapshot(snapshot ledgerSnapshot) error {
	if l.path == "" {
		return nil
	}
	plain, err := jsonBytes(snapshot)
	if err != nil {
		return err
	}
	enc, err := l.seal(plain)
	if err != nil {
		return err
	}
	return l.persist(l.path, enc)
}
func (l *Ledger) seal(p []byte) ([]byte, error) {
	c, err := aes.NewCipher(l.key)
	if err != nil {
		return nil, err
	}
	g, err := cipher.NewGCM(c)
	if err != nil {
		return nil, err
	}
	n := make([]byte, g.NonceSize())
	if _, err = rand.Read(n); err != nil {
		return nil, err
	}
	return g.Seal(n, n, p, nil), nil
}
func (l *Ledger) open(in []byte) ([]byte, error) {
	c, err := aes.NewCipher(l.key)
	if err != nil {
		return nil, err
	}
	g, err := cipher.NewGCM(c)
	if err != nil || len(in) < g.NonceSize() {
		return nil, ErrLedgerCorrupt
	}
	return g.Open(nil, in[:g.NonceSize()], in[g.NonceSize():], nil)
}

func jsonBytes(v any) ([]byte, error) { return marshalJSON(v) }

// Variables keep serialization testable without introducing a package-level
// mutable service; marshalJSON is replaced only by tests in this package.
var marshalJSON = func(v any) ([]byte, error) { return json.Marshal(v) }

func randomText(prefix string) string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return prefix + hex.EncodeToString(b)
}
func randomID(prefix string) (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return prefix + hex.EncodeToString(b), nil
}
func atomicLedgerWrite(path string, b []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
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
	if e := f.Close(); err == nil {
		err = e
	}
	if err != nil {
		return err
	}
	if err = os.Rename(tmp, path); err != nil {
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
func ledgerLock(path string) (*os.File, error) {
	f, e := os.OpenFile(path+".cas.lock", os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if e == nil {
		e = syscall.Flock(int(f.Fd()), syscall.LOCK_EX)
	}
	return f, e
}
