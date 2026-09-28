package mesh

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type RunState string

const (
	RunProposed  RunState = "proposed"
	RunAdmitted  RunState = "admitted"
	RunStarting  RunState = "starting"
	RunRunning   RunState = "running"
	RunCompleted RunState = "completed"
	RunFailed    RunState = "failed"
	RunCancelled RunState = "cancelled"
	RunUncertain RunState = "uncertain"
)

func (s RunState) terminal() bool {
	return s == RunCompleted || s == RunFailed || s == RunCancelled || s == RunUncertain
}

type Run struct {
	ID, RootID, ParentRunID, ParentSessionID, SessionID, AttemptID, ProviderSessionID, ProfileID, Provider, Classification, WorkspaceGroupID string
	// ControlFence is an exact durable pending-receipt digest. It serializes
	// native input and cancellation without exposing provider payloads.
	ControlFence string `json:",omitempty"`
	Depth        uint64
	State        RunState
	CreatedAt    time.Time
	// TerminalAt begins the bounded recovery/retention horizon. A zero value is
	// accepted only for additive migration of legacy terminal snapshots.
	TerminalAt time.Time `json:",omitempty"`
}
type ProposalRecord struct {
	Key, Scope, Digest, BatchID, ProposalID, RunID, SessionID, OrderID, BindingID string
	CallerEndpointID, RootRunID                                                   string `json:",omitempty"`
	CallerGeneration                                                              uint64 `json:",omitempty"`
	State                                                                         string
	ResponseDigest                                                                string
	CreatedAt                                                                     time.Time
	Order                                                                         WorkOrderRecord `json:",omitempty"`
}
type BatchAttemptOutcome struct{ ProposalID, RunID, SessionID, AttemptID, StartReceipt, Status, PrimaryError, CompensationStatus, CompensationError, RecoveryState string }
type BatchRecord struct {
	Key, BatchID, Digest, State string
	ProposalKeys                []string
	Attempts                    []BatchAttemptOutcome
	CreatedAt                   time.Time
}
type DisclosureReservation struct {
	PlanID, FanoutGrantID, Destination string
	Consumed                           bool
}
type Snapshot struct {
	SchemaVersion    string
	Version          uint64
	Runs             map[string]Run
	Proposals        map[string]ProposalRecord
	Batches          map[string]BatchRecord
	NonceScopes      map[string]string
	Disclosures      map[string]DisclosureReservation
	EndpointBindings map[string]MeshEndpointBinding
	EndpointNonces   map[string]bool
	EndpointRevoked  map[string]bool
	SendReceipts     map[string]SendReceipt
	CancelReceipts   map[string]CancelReceipt
	Tombstones       map[string]JournalTombstone
	Events           []MeshEvent
}

func emptySnapshot() Snapshot {
	return Snapshot{SchemaVersion: SnapshotV2, Runs: map[string]Run{}, Proposals: map[string]ProposalRecord{}, Batches: map[string]BatchRecord{}, NonceScopes: map[string]string{}, Disclosures: map[string]DisclosureReservation{}, EndpointBindings: map[string]MeshEndpointBinding{}, EndpointNonces: map[string]bool{}, EndpointRevoked: map[string]bool{}, SendReceipts: map[string]SendReceipt{}, CancelReceipts: map[string]CancelReceipt{}, Tombstones: map[string]JournalTombstone{}}
}
func (s Snapshot) clone() Snapshot {
	n := emptySnapshot()
	n.Version = s.Version
	for k, v := range s.Runs {
		n.Runs[k] = v
	}
	for k, v := range s.Proposals {
		v.Order.Task.InputArtifactRefs = append([]string(nil), v.Order.Task.InputArtifactRefs...)
		v.Order.Requested.Tools = append([]string(nil), v.Order.Requested.Tools...)
		v.Order.Effective.Tools = append([]string(nil), v.Order.Effective.Tools...)
		n.Proposals[k] = v
	}
	for k, v := range s.Batches {
		v.ProposalKeys = append([]string(nil), v.ProposalKeys...)
		v.Attempts = append([]BatchAttemptOutcome(nil), v.Attempts...)
		n.Batches[k] = v
	}
	for k, v := range s.NonceScopes {
		n.NonceScopes[k] = v
	}
	for k, v := range s.Disclosures {
		n.Disclosures[k] = v
	}
	for k, v := range s.EndpointBindings {
		n.EndpointBindings[k] = v
	}
	for k, v := range s.EndpointNonces {
		n.EndpointNonces[k] = v
	}
	for k, v := range s.EndpointRevoked {
		n.EndpointRevoked[k] = v
	}
	for k, v := range s.SendReceipts {
		n.SendReceipts[k] = v
	}
	for k, v := range s.CancelReceipts {
		n.CancelReceipts[k] = v
	}
	for k, v := range s.Tombstones {
		n.Tombstones[k] = v
	}
	n.Events = append(n.Events, s.Events...)
	return n
}
func (s Snapshot) Validate() error {
	if s.SchemaVersion != SnapshotV2 || s.Runs == nil || s.Proposals == nil || s.Batches == nil || s.NonceScopes == nil || s.Disclosures == nil || s.EndpointBindings == nil || s.EndpointNonces == nil || s.EndpointRevoked == nil || s.SendReceipts == nil || s.CancelReceipts == nil || s.Tombstones == nil {
		return ErrInvalidContract
	}
	for id, r := range s.Runs {
		if id == "" || id != r.ID || !validID(r.RootID) || !validID(r.SessionID) || !validID(r.AttemptID) || (r.ProviderSessionID != "" && !validID(r.ProviderSessionID)) || (r.ControlFence != "" && !validControlFence(r.ControlFence)) || !knownRunState(r.State) || r.CreatedAt.IsZero() {
			return ErrInvalidContract
		}
		if (!r.State.terminal() && !r.TerminalAt.IsZero()) || (!r.TerminalAt.IsZero() && r.TerminalAt.Before(r.CreatedAt)) {
			return ErrInvalidContract
		}
		if r.ParentRunID != "" {
			p, ok := s.Runs[r.ParentRunID]
			if !ok || p.RootID != r.RootID || r.Depth != p.Depth+1 {
				return ErrInvalidContract
			}
		} else if r.RootID != r.ID || r.Depth != 0 {
			return ErrInvalidContract
		}
	}
	for key, tombstone := range s.Tombstones {
		if !validJournalTombstone(key, tombstone) {
			return ErrInvalidContract
		}
	}
	batchIDs := make(map[string]string, len(s.Batches))
	batchProposalKeys := make(map[string]string)
	for key, b := range s.Batches {
		if key == "" || key != b.Key || !validID(b.BatchID) || !isDigest(b.Digest) || b.CreatedAt.IsZero() || (b.State != "pending" && b.State != "admitted" && b.State != "partial" && b.State != "failed" && b.State != "uncertain") {
			return ErrInvalidContract
		}
		if prior, duplicate := batchIDs[b.BatchID]; duplicate && prior != key {
			return ErrInvalidContract
		}
		batchIDs[b.BatchID] = key
		if len(b.ProposalKeys) == 0 || len(b.ProposalKeys) > 16 {
			return ErrInvalidContract
		}
		seenKeys := make(map[string]struct{}, len(b.ProposalKeys))
		members := make(map[string]ProposalRecord, len(b.ProposalKeys))
		for _, proposalKey := range b.ProposalKeys {
			if _, duplicate := seenKeys[proposalKey]; duplicate {
				return ErrInvalidContract
			}
			seenKeys[proposalKey] = struct{}{}
			p, ok := s.Proposals[proposalKey]
			r, runOK := s.Runs[p.RunID]
			if !ok || !runOK || p.BatchID != b.BatchID || p.Key != proposalKey || p.RunID != r.ID || p.SessionID != r.SessionID || p.Scope == "" {
				return ErrInvalidContract
			}
			if previous, claimed := batchProposalKeys[proposalKey]; claimed && previous != key {
				return ErrInvalidContract
			}
			batchProposalKeys[proposalKey] = key
			members[p.RunID] = p
		}
		if b.State != "pending" && len(b.Attempts) != len(b.ProposalKeys) {
			return ErrInvalidContract
		}
		if len(b.Attempts) > len(b.ProposalKeys) {
			return ErrInvalidContract
		}
		seenAttempts := make(map[string]struct{}, len(b.Attempts))
		for _, a := range b.Attempts {
			p, member := members[a.RunID]
			if !member || !validID(a.ProposalID) || a.ProposalID != p.ProposalID || !validID(a.RunID) || !validID(a.SessionID) || a.SessionID != p.SessionID || !validID(a.AttemptID) || a.AttemptID != s.Runs[a.RunID].AttemptID || !knownBatchAttempt(a) {
				return ErrInvalidContract
			}
			if _, duplicate := seenAttempts[a.RunID]; duplicate {
				return ErrInvalidContract
			}
			seenAttempts[a.RunID] = struct{}{}
		}
	}
	for key, p := range s.Proposals {
		if key == "" || key != p.Key || !validID(p.ProposalID) || !validID(p.RunID) || !validID(p.SessionID) || !validID(p.OrderID) || !validID(p.BindingID) || !validID(p.BatchID) && p.BatchID != "" || (p.State != "pending" && p.State != "admitted" && p.State != "terminal") {
			return ErrInvalidContract
		}
		r, ok := s.Runs[p.RunID]
		if !ok || r.SessionID != p.SessionID || s.NonceScopes[p.Scope] != key {
			return ErrInvalidContract
		}
		if _, attributed := proposalCallerBinding(s, p); !attributed {
			return ErrInvalidContract
		}
		if p.BatchID != "" {
			found := false
			for _, b := range s.Batches {
				if b.BatchID == p.BatchID {
					found = true
				}
			}
			if !found {
				return ErrInvalidContract
			}
		}
	}
	for runID, d := range s.Disclosures {
		r, ok := s.Runs[runID]
		if !ok || !validID(d.PlanID) || !validID(d.FanoutGrantID) || d.Destination != r.Provider {
			return ErrInvalidContract
		}
	}
	for id, b := range s.EndpointBindings {
		r, ok := s.Runs[b.RunID]
		// Validate against issuance time: a retained, expired binding is still a
		// valid audit record, but it is never usable by AuthorizeOperation.
		if id != b.EndpointID || b.Validate(b.IssuedAt) != nil || !ok || r.RootID != b.RootRunID || r.SessionID != b.SessionID || r.AttemptID != b.AttemptID {
			return ErrInvalidContract
		}
	}
	activeRootBindings := map[string]uint64{}
	for endpointID, binding := range s.EndpointBindings {
		if binding.RootRunID != binding.RunID || s.EndpointRevoked[endpointID] {
			continue
		}
		// Root endpoint rotation is a single-successor transition per audience.
		// A root may have one mesh endpoint and one separately-bound UI endpoint.
		key := binding.RootRunID + "\x00" + binding.Audience
		if _, exists := activeRootBindings[key]; exists {
			return ErrInvalidContract
		}
		activeRootBindings[key] = binding.Generation
	}
	for key, used := range s.EndpointNonces {
		binding, generation, nonce, ok := endpointNonceReference(key, s.EndpointBindings)
		if !ok || !used || binding.Generation != generation || !validID(nonce) {
			return ErrInvalidContract
		}
	}
	for endpointID, revoked := range s.EndpointRevoked {
		if !revoked {
			return ErrInvalidContract
		}
		if _, ok := s.EndpointBindings[endpointID]; !ok {
			return ErrInvalidContract
		}
	}
	for key, receipt := range s.SendReceipts {
		if !validSendReceipt(key, receipt, s) {
			return ErrInvalidContract
		}
	}
	for key, receipt := range s.CancelReceipts {
		if !validCancelReceipt(key, receipt, s) {
			return ErrInvalidContract
		}
	}
	for _, run := range s.Runs {
		if run.ControlFence != "" && !controlFenceHasPendingReceipt(run, s) {
			return ErrInvalidContract
		}
	}
	seenEvents := make(map[string]struct{}, len(s.Events))
	for _, e := range s.Events {
		if !validMeshEvent(e, s.Runs) {
			return ErrInvalidContract
		}
		digest := hash(e)
		if _, duplicate := seenEvents[digest]; duplicate {
			return ErrInvalidContract
		}
		seenEvents[digest] = struct{}{}
	}
	return nil
}

func knownBatchAttempt(a BatchAttemptOutcome) bool {
	if a.RecoveryState != "active" && a.RecoveryState != "terminal" && a.RecoveryState != "uncertain" && a.RecoveryState != "compensated" && a.RecoveryState != "compensating" {
		return false
	}
	switch a.Status {
	case "started":
		return a.RecoveryState == "active" && validID(a.StartReceipt) && a.PrimaryError == "" && a.CompensationStatus == "" && a.CompensationError == ""
	case "compensated":
		return validID(a.StartReceipt) && a.CompensationStatus == "cancelled" && a.CompensationError == "" && a.RecoveryState == "terminal"
	case "cancelled":
		return a.StartReceipt == "" && a.CompensationStatus == "" && a.CompensationError == "" && a.RecoveryState == "terminal" && validID(a.PrimaryError)
	case "start_failed":
		return a.StartReceipt == "" && a.CompensationStatus == "" && a.CompensationError == "" && a.RecoveryState == "terminal" && validID(a.PrimaryError)
	case "uncertain":
		return a.RecoveryState == "uncertain" && validID(a.PrimaryError) && (a.CompensationStatus == "" || a.CompensationStatus == "failed") && (a.CompensationError == "" || validID(a.CompensationError))
	default:
		return false
	}
}

func knownRunState(state RunState) bool {
	switch state {
	case RunProposed, RunAdmitted, RunStarting, RunRunning, RunCompleted, RunFailed, RunCancelled, RunUncertain:
		return true
	default:
		return false
	}
}

// endpointNonceReference only accepts the exact key emitted by
// authorizePersistent. Endpoint IDs may contain colons, so parsing starts from
// the persisted binding IDs instead of splitting the complete key blindly.
func endpointNonceReference(key string, bindings map[string]MeshEndpointBinding) (MeshEndpointBinding, uint64, string, bool) {
	var matched MeshEndpointBinding
	var generation uint64
	var nonce string
	matchedCount := 0
	for endpointID, binding := range bindings {
		prefix := endpointID + ":"
		if !strings.HasPrefix(key, prefix) {
			continue
		}
		parts := strings.Split(strings.TrimPrefix(key, prefix), ":")
		if len(parts) != 2 {
			continue
		}
		parsed, err := strconv.ParseUint(parts[0], 10, 64)
		if err != nil || !validID(parts[1]) {
			continue
		}
		matched, generation, nonce = binding, parsed, parts[1]
		matchedCount++
	}
	return matched, generation, nonce, matchedCount == 1
}

func validSendReceipt(key string, receipt SendReceipt, s Snapshot) bool {
	if !validID(receipt.CallerRunID) || !validID(receipt.TargetRunID) || !validID(receipt.InputRef) || !isDigest(receipt.Digest) || (receipt.State != "pending" && receipt.State != "sent" && receipt.State != "failed" && receipt.State != "uncertain") {
		return false
	}
	if receipt.CallerEndpointID == "" && receipt.CallerGeneration == 0 && receipt.Operation == "" {
		matches := 0
		for _, binding := range s.EndpointBindings {
			for _, operation := range []string{"send", "steer"} {
				if legacySendReceiptMatchesBinding(key, receipt, s, binding, operation, receipt.InputRef) {
					matches++
				}
			}
		}
		return matches == 1
	}
	if !validID(receipt.CallerEndpointID) || receipt.CallerGeneration == 0 || (receipt.Operation != "send" && receipt.Operation != "steer") {
		return false
	}
	binding, bindingOK := s.EndpointBindings[receipt.CallerEndpointID]
	caller, callerOK := s.Runs[binding.RunID]
	target, targetOK := s.Runs[receipt.TargetRunID]
	if !bindingOK || !callerOK || !targetOK || binding.Generation != receipt.CallerGeneration || binding.RunID != receipt.CallerRunID || binding.RootRunID != target.RootID || target.ParentRunID != binding.RunID || caller.RootID != target.RootID || !contains(binding.AllowedOperations, receipt.Operation) || receipt.Digest != inputReceiptDigest(binding, receipt.TargetRunID, receipt.Operation, receipt.InputRef) || key != inputReceiptKey(binding, receipt.TargetRunID, receipt.Operation, receipt.InputRef) {
		return false
	}
	return validInputReceiptState(receipt, target, s, false)
}

func legacySendReceiptMatchesBinding(key string, receipt SendReceipt, s Snapshot, binding MeshEndpointBinding, operation, inputRef string) bool {
	if receipt.CallerEndpointID != "" || receipt.CallerGeneration != 0 || receipt.Operation != "" || receipt.TargetRunID == "" || receipt.InputRef != inputRef || key != legacyInputReceiptKey(binding.EndpointID, receipt.TargetRunID, operation, inputRef) || !contains(binding.AllowedOperations, operation) {
		return false
	}
	target, targetOK := s.Runs[receipt.TargetRunID]
	caller, callerOK := s.Runs[binding.RunID]
	if !targetOK || !callerOK || target.ParentRunID != binding.RunID || target.RootID != binding.RootRunID || caller.RootID != target.RootID {
		return false
	}
	request := OperationRequest{Target: TargetRequest{TargetRunID: receipt.TargetRunID, Operation: operation}, InputRef: receipt.InputRef}
	requestDigest, err := request.Digest()
	if err != nil || (receipt.Digest != requestDigest && receipt.Digest != legacySendReceiptDigest(receipt.TargetRunID, operation, receipt.InputRef)) {
		return false
	}
	return validInputReceiptState(receipt, target, s, true)
}

func validInputReceiptState(receipt SendReceipt, target Run, s Snapshot, legacy bool) bool {
	switch receipt.State {
	case "pending":
		if target.State != RunRunning {
			return false
		}
		return target.ControlFence == inputControlFence(receipt.Digest) || (legacy && target.ControlFence == "")
	case "uncertain":
		if target.State != RunUncertain || target.ControlFence != "" {
			return false
		}
		for endpointID, binding := range s.EndpointBindings {
			if binding.RunID == target.ID && !s.EndpointRevoked[endpointID] {
				return false
			}
		}
		return true
	case "sent", "failed":
		return true
	default:
		return false
	}
}

func validCancelReceipt(key string, receipt CancelReceipt, s Snapshot) bool {
	if !validID(receipt.CallerEndpointID) || receipt.CallerGeneration == 0 || !validID(receipt.TargetRunID) || !validID(receipt.RevisionRef) || !validID(receipt.ReasonRef) || !isDigest(receipt.Digest) {
		return false
	}
	if receipt.State != "pending" && receipt.State != "cancelled" && receipt.State != "uncertain" && receipt.State != "failed" {
		return false
	}
	if key != cancelReceiptKey(receipt.CallerEndpointID, receipt.CallerGeneration, receipt.TargetRunID) || receipt.Digest != cancelReceiptDigest(receipt.CallerEndpointID, receipt.CallerGeneration, receipt.TargetRunID, receipt.RevisionRef, receipt.ReasonRef) {
		return false
	}
	caller, callerOK := s.EndpointBindings[receipt.CallerEndpointID]
	target, targetOK := s.Runs[receipt.TargetRunID]
	if !callerOK || !targetOK || caller.Generation != receipt.CallerGeneration || !contains(caller.AllowedOperations, "cancel") || caller.RootRunID != target.RootID || target.ParentRunID != caller.RunID {
		return false
	}
	for endpointID, binding := range s.EndpointBindings {
		if binding.RunID == target.ID && !s.EndpointRevoked[endpointID] {
			return false
		}
	}
	switch receipt.State {
	case "pending":
		return target.State == RunRunning && target.ControlFence == cancelControlFence(receipt.Digest)
	case "cancelled":
		return target.State == RunCancelled && target.ControlFence == ""
	case "uncertain":
		return target.State == RunUncertain && target.ControlFence == ""
	case "failed":
		return target.State == RunFailed && target.ControlFence == ""
	default:
		return false
	}
}

func validMeshEvent(e MeshEvent, runs map[string]Run) bool {
	if e.SchemaVersion != "mesh-event.v1" || e.At.IsZero() {
		return false
	}
	if e.Event == "legacy_v1_migrated" {
		return e.Phase == "migration" && e.RecoveryState == "dual_read" && e.RootRunID == "" && e.RunID == "" && e.SessionID == "" && e.AttemptID == "" && e.ParentRunID == "" && e.Provider == "" && e.ProfileID == "" && e.Status == "" && e.Classification == "" && isDigest(e.ErrorCode)
	}
	if !knownMeshEvent(e.Event) || e.Phase != "controller" || e.RecoveryState != "" || (e.ErrorCode != "" && !validID(e.ErrorCode)) {
		return false
	}
	r, ok := runs[e.RunID]
	return ok && e.RootRunID == r.RootID && e.SessionID == r.SessionID && e.AttemptID == r.AttemptID && e.ParentRunID == r.ParentRunID && e.Provider == r.Provider && e.ProfileID == r.ProfileID && e.Classification == r.Classification && eventStatusMatchesName(e.Event, e.Status)
}

func knownMeshEvent(name string) bool {
	switch name {
	case "root_registered", "proposal_admitted", "batch_admitted", "run_running", "run_proposed", "run_admitted", "run_starting", "run_completed", "run_failed", "run_cancelled", "run_uncertain":
		return true
	default:
		return false
	}
}

// Events are an append-only history. Their status is the transition at the
// time of emission, not necessarily the run's current status.
func eventStatusMatchesName(name, status string) bool {
	switch name {
	case "root_registered", "run_running":
		return status == string(RunRunning)
	case "proposal_admitted", "batch_admitted", "run_admitted":
		return status == string(RunAdmitted)
	case "run_proposed":
		return status == string(RunProposed)
	case "run_starting":
		return status == string(RunStarting)
	case "run_completed":
		return status == string(RunCompleted)
	case "run_failed":
		return status == string(RunFailed)
	case "run_cancelled":
		return status == string(RunCancelled)
	case "run_uncertain":
		return status == string(RunUncertain)
	default:
		return false
	}
}

type Repository interface {
	Load(context.Context) (Snapshot, error)
	CompareAndSwap(context.Context, Snapshot, Snapshot) error
}
type MemoryRepository struct {
	mu     sync.Mutex
	state  Snapshot
	policy RetentionPolicy
	now    func() time.Time
}

func NewMemoryRepository() *MemoryRepository {
	return &MemoryRepository{state: emptySnapshot(), policy: defaultRetentionPolicy(), now: time.Now}
}
func (r *MemoryRepository) Load(ctx context.Context) (Snapshot, error) {
	if err := ctx.Err(); err != nil {
		return Snapshot{}, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.state.clone(), nil
}
func (r *MemoryRepository) CompareAndSwap(ctx context.Context, old, next Snapshot) error {
	return r.compareAndSwap(ctx, old, next, journalMutationNormal)
}

func (r *MemoryRepository) CompareAndSwapSafety(ctx context.Context, old, next Snapshot) error {
	return r.compareAndSwap(ctx, old, next, journalMutationSafety)
}

func (r *MemoryRepository) compareAndSwap(ctx context.Context, old, next Snapshot, class journalMutationClass) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.state.Version != old.Version || hash(r.state) != hash(old) {
		return ErrVersionConflict
	}
	policy := r.policy
	if policy.Validate() != nil {
		policy = defaultRetentionPolicy()
	}
	now := r.now
	if now == nil {
		now = time.Now
	}
	next.Version = old.Version + 1
	prepared, err := prepareJournalCommit(old, next, now().UTC(), policy, class)
	if err != nil {
		return err
	}
	r.state = prepared.clone()
	return nil
}

// EndpointAuthorizer has no credential material. A broker/IPC adapter may use
// this binding metadata after authenticating its peer; capability payloads stay
// outside mesh.
type EndpointAuthorizer struct {
	mu          sync.Mutex
	repo        Repository
	bindings    map[string]MeshEndpointBinding
	used        map[string]bool
	revoked     map[string]bool
	onUncertain func()
	blocked     func() bool
}

func NewEndpointAuthorizer() *EndpointAuthorizer {
	return &EndpointAuthorizer{bindings: map[string]MeshEndpointBinding{}, used: map[string]bool{}, revoked: map[string]bool{}}
}
func NewPersistentEndpointAuthorizer(repo Repository) (*EndpointAuthorizer, error) {
	if repo == nil {
		return nil, ErrInvalidContract
	}
	if _, err := repo.Load(context.Background()); err != nil {
		return nil, err
	}
	a := NewEndpointAuthorizer()
	a.repo = repo
	return a, nil
}
func (a *EndpointAuthorizer) Register(b MeshEndpointBinding, now time.Time) error {
	if a.blocked != nil && a.blocked() {
		return ErrRepositoryPoisoned
	}
	if err := b.Validate(now); err != nil {
		return err
	}
	if a.repo != nil {
		return a.registerPersistent(b, now)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, ok := a.bindings[b.EndpointID]; ok {
		return ErrDenied
	}
	a.bindings[b.EndpointID] = b
	return nil
}
func (a *EndpointAuthorizer) registerPersistent(b MeshEndpointBinding, now time.Time) error {
	for i := 0; i < 8; i++ {
		s, e := a.repo.Load(context.Background())
		if e != nil {
			return e
		}
		if _, ok := s.EndpointBindings[b.EndpointID]; ok {
			return ErrDenied
		}
		n := s.clone()
		n.EndpointBindings[b.EndpointID] = b
		if e = a.repo.CompareAndSwap(context.Background(), s, n); e == nil {
			return nil
		} else if errors.Is(e, ErrCommitUncertain) {
			if a.onUncertain != nil {
				a.onUncertain()
			}
			return ErrRepositoryPoisoned
		} else if !errors.Is(e, ErrVersionConflict) {
			return e
		}
	}
	return ErrVersionConflict
}
func (a *EndpointAuthorizer) Authorize(r EndpointRequest, now time.Time) (MeshEndpointBinding, error) {
	return a.AuthorizeOperation(r, now, "", r.MessageDigest)
}
func (a *EndpointAuthorizer) AuthorizeOperation(r EndpointRequest, now time.Time, operation, expectedDigest string) (MeshEndpointBinding, error) {
	return a.AuthorizeOperationForPolicy(r, now, operation, expectedDigest, "")
}

// AuthorizeOperationForPolicy rejects a stale policy binding before consuming
// its single-use nonce. Coordinator paths always use this method; the legacy
// policy-empty form remains only for standalone EndpointAuthorizer tests.
func (a *EndpointAuthorizer) AuthorizeOperationForPolicy(r EndpointRequest, now time.Time, operation, expectedDigest, policyVersion string) (MeshEndpointBinding, error) {
	if a.blocked != nil && a.blocked() {
		return MeshEndpointBinding{}, ErrRepositoryPoisoned
	}
	if a.repo != nil {
		return a.authorizePersistent(r, now, operation, expectedDigest, policyVersion)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	b, ok := a.bindings[r.EndpointID]
	if !ok || a.revoked[r.EndpointID] || b.Audience != r.Audience || b.PeerID != r.PeerID || !validID(r.Nonce) || r.MessageDigest != expectedDigest || !b.ExpiresAt.After(now) || (policyVersion != "" && b.PolicyVersion != policyVersion) || (operation != "" && !contains(b.AllowedOperations, operation)) {
		return MeshEndpointBinding{}, ErrUnauthorized
	}
	key := endpointNonceKey(b, r.Nonce)
	if a.used[key] {
		return MeshEndpointBinding{}, ErrReplay
	}
	a.used[key] = true
	return b, nil
}

// verifyOperationForPolicy authenticates a request without consuming its
// nonce. It is private because only Coordinator cancellation may combine nonce
// consumption with its safety-reserve receipt/fence CAS. Every other operation
// must use AuthorizeOperationForPolicy's standalone single-use commit.
func (a *EndpointAuthorizer) verifyOperationForPolicy(ctx context.Context, r EndpointRequest, now time.Time, operation, expectedDigest, policyVersion string) (MeshEndpointBinding, error) {
	if a.blocked != nil && a.blocked() {
		return MeshEndpointBinding{}, ErrRepositoryPoisoned
	}
	if a.repo != nil {
		s, err := a.repo.Load(ctx)
		if err != nil {
			return MeshEndpointBinding{}, err
		}
		b, ok := s.EndpointBindings[r.EndpointID]
		key := endpointNonceKey(b, r.Nonce)
		if !ok || s.EndpointRevoked[r.EndpointID] || b.Audience != r.Audience || b.PeerID != r.PeerID || !validID(r.Nonce) || r.MessageDigest != expectedDigest || !b.ExpiresAt.After(now) || b.PolicyVersion != policyVersion || !contains(b.AllowedOperations, operation) {
			return MeshEndpointBinding{}, ErrUnauthorized
		}
		if s.EndpointNonces[key] {
			return MeshEndpointBinding{}, ErrReplay
		}
		return b, nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	b, ok := a.bindings[r.EndpointID]
	key := endpointNonceKey(b, r.Nonce)
	if !ok || a.revoked[r.EndpointID] || b.Audience != r.Audience || b.PeerID != r.PeerID || !validID(r.Nonce) || r.MessageDigest != expectedDigest || !b.ExpiresAt.After(now) || b.PolicyVersion != policyVersion || !contains(b.AllowedOperations, operation) {
		return MeshEndpointBinding{}, ErrUnauthorized
	}
	if a.used[key] {
		return MeshEndpointBinding{}, ErrReplay
	}
	return b, nil
}

func endpointNonceKey(binding MeshEndpointBinding, nonce string) string {
	return binding.EndpointID + ":" + fmt.Sprint(binding.Generation) + ":" + nonce
}
func (a *EndpointAuthorizer) authorizePersistent(r EndpointRequest, now time.Time, operation, expectedDigest, policyVersion string) (MeshEndpointBinding, error) {
	for i := 0; i < 8; i++ {
		s, e := a.repo.Load(context.Background())
		if e != nil {
			return MeshEndpointBinding{}, e
		}
		b, ok := s.EndpointBindings[r.EndpointID]
		key := endpointNonceKey(b, r.Nonce)
		if !ok || s.EndpointRevoked[r.EndpointID] || b.Audience != r.Audience || b.PeerID != r.PeerID || !validID(r.Nonce) || r.MessageDigest != expectedDigest || !b.ExpiresAt.After(now) || (policyVersion != "" && b.PolicyVersion != policyVersion) || (operation != "" && !contains(b.AllowedOperations, operation)) {
			return MeshEndpointBinding{}, ErrUnauthorized
		}
		if s.EndpointNonces[key] {
			return MeshEndpointBinding{}, ErrReplay
		}
		n := s.clone()
		n.EndpointNonces[key] = true
		if e = a.repo.CompareAndSwap(context.Background(), s, n); e == nil {
			return b, nil
		} else if errors.Is(e, ErrCommitUncertain) {
			if a.onUncertain != nil {
				a.onUncertain()
			}
			return MeshEndpointBinding{}, ErrRepositoryPoisoned
		} else if !errors.Is(e, ErrVersionConflict) {
			return MeshEndpointBinding{}, e
		}
	}
	return MeshEndpointBinding{}, ErrVersionConflict
}
func (a *EndpointAuthorizer) Revoke(endpointID string) error {
	if a.blocked != nil && a.blocked() {
		return ErrRepositoryPoisoned
	}
	if a.repo != nil {
		for i := 0; i < 8; i++ {
			s, e := a.repo.Load(context.Background())
			if e != nil {
				return e
			}
			if _, ok := s.EndpointBindings[endpointID]; !ok {
				return ErrDenied
			}
			if s.EndpointRevoked[endpointID] {
				return nil
			}
			n := s.clone()
			n.EndpointRevoked[endpointID] = true
			if e = a.repo.CompareAndSwap(context.Background(), s, n); e == nil {
				return nil
			} else if errors.Is(e, ErrCommitUncertain) {
				if a.onUncertain != nil {
					a.onUncertain()
				}
				return ErrRepositoryPoisoned
			}
		}
		return ErrVersionConflict
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, ok := a.bindings[endpointID]; !ok {
		return ErrDenied
	}
	a.revoked[endpointID] = true
	return nil
}

type Coordinator struct {
	repo            Repository
	directory       ProfileDirectory
	starter         SessionStarter
	sessions        SessionController
	disclosure      DisclosureAuthorizer
	endpoints       *EndpointAuthorizer
	now             func() time.Time
	nextID          func() (string, error)
	policyVersion   string
	batchCaps       ExecutionLimits
	mu              sync.Mutex
	poisoned        atomic.Bool
	recoveryPending bool
}

func (c *Coordinator) cas(ctx context.Context, old, next Snapshot) error {
	if c.poisoned.Load() {
		return ErrRepositoryPoisoned
	}
	err := c.repo.CompareAndSwap(ctx, old, next)
	if errors.Is(err, ErrCommitUncertain) {
		c.poisoned.Store(true)
	}
	return err
}

type safetyRepository interface {
	CompareAndSwapSafety(context.Context, Snapshot, Snapshot) error
}

// casSafety is reachable only from closed Controller lifecycle paths. It lets
// an already-admitted native effect, cancellation fence, terminal transition,
// or revocation consume the repository's reserved recovery budget; callers
// cannot select this class through an RPC/request field.
func (c *Coordinator) casSafety(ctx context.Context, old, next Snapshot) error {
	if c.poisoned.Load() {
		return ErrRepositoryPoisoned
	}
	return c.casSafetyMonotone(ctx, old, next)
}

// casSafetyMonotone is reserved for fail-closing mutations (revoke, terminal,
// uncertain). Those mutations remain safe and necessary after a prior commit
// became uncertain; no admission or capability minting may call this helper.
func (c *Coordinator) casSafetyMonotone(ctx context.Context, old, next Snapshot) error {
	var err error
	if repo, ok := c.repo.(safetyRepository); ok {
		err = repo.CompareAndSwapSafety(ctx, old, next)
	} else {
		err = c.repo.CompareAndSwap(ctx, old, next)
	}
	if errors.Is(err, ErrCommitUncertain) {
		c.poisoned.Store(true)
	}
	return err
}

type CoordinatorOptions struct {
	Repository Repository
	Directory  ProfileDirectory
	Starter    SessionStarter
	Sessions   SessionController
	Disclosure DisclosureAuthorizer
	Endpoints  *EndpointAuthorizer
	Clock      func() time.Time
	ID         func() string
	// IDWithError is the preferred production seam. ID remains supported for
	// deterministic tests and existing composition, but both may not be set.
	IDWithError   func() (string, error)
	PolicyVersion string
	BatchCaps     ExecutionLimits
}

func NewCoordinator(o CoordinatorOptions) (*Coordinator, error) {
	if o.Repository == nil || o.Directory == nil || o.Endpoints == nil || o.PolicyVersion == "" {
		return nil, ErrInvalidContract
	}
	// A coordinator always has a journal, so endpoint authorization must use the
	// same journal as runs and receipts. Keeping an in-memory endpoint map here
	// would make a valid receipt unprovable after restart (and let nonce/revoke
	// state disappear). Standalone NewEndpointAuthorizer remains useful only for
	// isolated unit tests that do not construct a Coordinator.
	if o.Endpoints.repo == nil {
		persistent, err := NewPersistentEndpointAuthorizer(o.Repository)
		if err != nil {
			return nil, err
		}
		o.Endpoints = persistent
	}
	if o.Clock == nil {
		o.Clock = time.Now
	}
	if memory, ok := o.Repository.(*MemoryRepository); ok {
		memory.mu.Lock()
		memory.now = o.Clock
		memory.mu.Unlock()
	}
	if o.ID != nil && o.IDWithError != nil {
		return nil, ErrInvalidContract
	}
	nextID := o.IDWithError
	if nextID == nil && o.ID != nil {
		nextID = func() (string, error) { return o.ID(), nil }
	}
	if nextID == nil {
		nextID = randomID
	}
	if o.BatchCaps.Validate() != nil {
		o.BatchCaps = ExecutionLimits{SchemaVersion: ExecutionLimitsV1, MaxDepth: 1, MaxChildrenPerParent: 1, MaxConcurrentRuns: 1, MaxInputTokens: 1, MaxOutputTokens: 1, MaxWallMS: 1, MaxAttempts: 1, MaxResultBytes: 1, Cost: CostLimit{Kind: "non_monetary", Unit: "token", MaxQuantity: 1}}
	}
	c := &Coordinator{repo: o.Repository, directory: o.Directory, starter: o.Starter, sessions: o.Sessions, disclosure: o.Disclosure, endpoints: o.Endpoints, now: o.Clock, nextID: nextID, policyVersion: o.PolicyVersion, batchCaps: o.BatchCaps}
	o.Endpoints.onUncertain = func() { c.poisoned.Store(true) }
	o.Endpoints.blocked = func() bool { return c.poisoned.Load() }
	initial, err := o.Repository.Load(context.Background())
	if err != nil {
		return nil, err
	}
	if err = initial.Validate(); err != nil {
		return nil, ErrRepositoryPoisoned
	}
	c.recoveryPending = snapshotHasPersistedSessions(initial)
	if snapshotNeedsReconciliation(initial) || c.recoveryPending {
		c.poisoned.Store(true)
	}
	return c, nil
}

// verifyPersistedSessionRoutes fails closed: a durable Controller reference is
// not a native-route recovery proof. Root runs deliberately have no provider
// session and remain restartable without this verifier.
func snapshotHasPersistedSessions(s Snapshot) bool {
	for _, run := range s.Runs {
		if run.State == RunRunning && run.ProviderSessionID != "" {
			return true
		}
	}
	return false
}

func recoverPersistedSessionRoutes(ctx context.Context, s Snapshot, sessions SessionController) bool {
	var recoveries []PersistedSessionRecovery
	seenRoutes := make(map[string]struct{})
	for _, run := range s.Runs {
		if run.State == RunRunning && run.ProviderSessionID != "" {
			if _, duplicate := seenRoutes[run.ProviderSessionID]; duplicate {
				return false
			}
			seenRoutes[run.ProviderSessionID] = struct{}{}
			var selectedProposal *ProposalRecord
			for _, candidate := range s.Proposals {
				if candidate.RunID == run.ID && candidate.State == "admitted" {
					if selectedProposal != nil {
						return false
					}
					copy := candidate
					selectedProposal = &copy
				}
			}
			proposal := selectedProposal
			if proposal == nil || proposal.Order.RunID != run.ID || proposal.Order.RootRunID != run.RootID || proposal.Order.SessionID != run.SessionID || proposal.Order.AttemptID != run.AttemptID || proposal.Order.ProfileID != run.ProfileID || proposal.Order.Provider != run.Provider || proposal.Order.OrderID != proposal.OrderID || !validPersistedOrderHash(proposal.Order) {
				return false
			}
			var endpoint *MeshEndpointBinding
			for _, binding := range s.EndpointBindings {
				if binding.RunID == run.ID && binding.AttemptID == run.AttemptID && !s.EndpointRevoked[binding.EndpointID] {
					if endpoint != nil {
						return false
					}
					copy := binding
					endpoint = &copy
				}
			}
			if endpoint == nil || endpoint.RootRunID != run.RootID || endpoint.SessionID != run.SessionID || endpoint.ExpiresAt.IsZero() || endpoint.IssuedAt.IsZero() {
				return false
			}
			dispatch := RunDispatchBinding{SchemaVersion: RunDispatchBindingV2, BindingID: proposal.BindingID, OrderID: proposal.Order.OrderID, OrderHash: proposal.Order.OrderHash, RootRunID: run.RootID, RunID: run.ID, SessionID: run.SessionID, AttemptID: run.AttemptID, EndpointID: endpoint.EndpointID, Generation: endpoint.Generation, IssuedAt: endpoint.IssuedAt, ExpiresAt: endpoint.ExpiresAt}
			dispatch.BindingHash = hash(dispatch)
			recoveries = append(recoveries, PersistedSessionRecovery{ProviderSessionID: run.ProviderSessionID, Start: sealStartRequest(proposal.Order, dispatch)})
		}
	}
	if len(recoveries) == 0 {
		return true
	}
	verifier, ok := sessions.(PersistedSessionRecoveryVerifier)
	if !ok || verifier == nil {
		return false
	}
	sort.Slice(recoveries, func(i, j int) bool { return recoveries[i].ProviderSessionID < recoveries[j].ProviderSessionID })
	return verifier.RecoverPersistedSessions(ctx, recoveries) == nil
}

func validPersistedOrderHash(order WorkOrderRecord) bool {
	want := order.OrderHash
	order.OrderHash = ""
	return isDigest(want) && want == hash(order)
}

func snapshotNeedsReconciliation(s Snapshot) bool {
	for _, proposal := range s.Proposals {
		if proposal.State == "pending" {
			return true
		}
	}
	for _, batch := range s.Batches {
		if batch.State == "pending" || batch.State == "uncertain" {
			return true
		}
	}
	for _, run := range s.Runs {
		if run.State == RunStarting || run.State == RunUncertain || run.ControlFence != "" {
			return true
		}
	}
	for _, receipt := range s.SendReceipts {
		if receipt.State == "pending" || receipt.State == "uncertain" || receipt.State == "failed" {
			return true
		}
	}
	for _, receipt := range s.CancelReceipts {
		if receipt.State == "pending" || receipt.State == "uncertain" || receipt.State == "failed" {
			return true
		}
	}
	return false
}

// RegisterRoot is composition-only bootstrap for an already authenticated root
// session. It makes no provider call and grants only an explicit mesh endpoint.
func (c *Coordinator) RegisterRoot(ctx context.Context, rootID, sessionID, attemptID, peerID, classification, workspace string) (MeshEndpointBinding, error) {
	if !validID(rootID) || !validID(sessionID) || !validID(attemptID) || !validID(peerID) || !validID(classification) || !validID(workspace) {
		return MeshEndpointBinding{}, ErrInvalidContract
	}
	if c.poisoned.Load() {
		return MeshEndpointBinding{}, ErrRepositoryPoisoned
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now().UTC()
	run := Run{ID: rootID, RootID: rootID, SessionID: sessionID, AttemptID: attemptID, Classification: classification, WorkspaceGroupID: workspace, State: RunRunning, CreatedAt: now}
	rootOps := []string{"spawn", "spawnBatch", "listProfiles", "send", "steer", "wait", "collect", "cancel", "list", "status", "result"}
	var endpoint MeshEndpointBinding
	for tries := 0; tries < 8; tries++ {
		s, e := c.repo.Load(ctx)
		if e != nil {
			return MeshEndpointBinding{}, e
		}
		if e = s.Validate(); e != nil {
			c.poisoned.Store(true)
			return MeshEndpointBinding{}, ErrRepositoryPoisoned
		}
		if existing, ok := s.Runs[rootID]; ok {
			binding, exact := exactRootRegistration(s, existing, sessionID, attemptID, peerID, classification, workspace, c.policyVersion, rootOps, now)
			if !exact {
				return MeshEndpointBinding{}, ErrReconciliationNeeded
			}
			return binding, nil
		}
		if endpoint.EndpointID == "" {
			ids, allocErr := c.allocateIDs(s, 1)
			if allocErr != nil {
				return MeshEndpointBinding{}, allocErr
			}
			endpoint = MeshEndpointBinding{SchemaVersion: EndpointBindingV1, EndpointID: ids[0], Audience: "mesh", RootRunID: rootID, RunID: rootID, SessionID: sessionID, AttemptID: attemptID, ToolDigest: hash(sortedStrings(rootOps)), AllowedOperations: append([]string(nil), rootOps...), PeerID: peerID, PolicyVersion: c.policyVersion, IssuedAt: now, ExpiresAt: now.Add(15 * time.Minute), Generation: 1}
		} else if snapshotUsesID(s, endpoint.EndpointID) {
			return MeshEndpointBinding{}, ErrUnavailable
		}
		n := s.clone()
		n.Runs[rootID] = run
		n.EndpointBindings[endpoint.EndpointID] = endpoint
		n.Events = append(n.Events, event(now, "root_registered", run, ""))
		if e = c.cas(ctx, s, n); e == nil {
			return endpoint, nil
		}
		if !errors.Is(e, ErrVersionConflict) {
			return MeshEndpointBinding{}, e
		}
	}
	return MeshEndpointBinding{}, ErrVersionConflict
}

// MintUIEndpoint creates the second, UI-audience capability for an already
// registered root.  The UI channel never borrows the root's mesh audience: it
// gets its own durable endpoint, peer binding and nonce namespace.  The
// operation names are deliberately the same closed Coordinator union; target
// authorization still applies after endpoint authentication.
func (c *Coordinator) MintUIEndpoint(ctx context.Context, root MeshEndpointBinding) (MeshEndpointBinding, error) {
	if c == nil || c.poisoned.Load() || root.SchemaVersion != EndpointBindingV1 || root.Audience != "mesh" || root.RootRunID != root.RunID || root.Generation == 0 {
		return MeshEndpointBinding{}, ErrUnauthorized
	}
	if err := ctx.Err(); err != nil {
		return MeshEndpointBinding{}, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now().UTC()
	uiOps := canonicalUIOperations()
	uiDigest := hash(sortedStrings(uiOps))
	for tries := 0; tries < 8; tries++ {
		s, err := c.repo.Load(ctx)
		if err != nil {
			return MeshEndpointBinding{}, err
		}
		if err = s.Validate(); err != nil {
			c.poisoned.Store(true)
			return MeshEndpointBinding{}, ErrRepositoryPoisoned
		}
		if !bindingIsCurrent(s, root, c.policyVersion, now) {
			return MeshEndpointBinding{}, ErrUnauthorized
		}
		for _, candidate := range s.EndpointBindings {
			if candidate.Audience == "ui" && candidate.RootRunID == root.RootRunID && candidate.RunID == root.RunID && candidate.SessionID == root.SessionID && candidate.AttemptID == root.AttemptID && candidate.PeerID == root.PeerID && candidate.PolicyVersion == root.PolicyVersion && !s.EndpointRevoked[candidate.EndpointID] && candidate.ExpiresAt.After(now) {
				if candidate.ToolDigest != uiDigest || hash(sortedStrings(candidate.AllowedOperations)) != uiDigest {
					return MeshEndpointBinding{}, ErrReconciliationNeeded
				}
				return candidate, nil
			}
		}
		ids, err := c.allocateIDs(s, 1)
		if err != nil {
			return MeshEndpointBinding{}, err
		}
		ui := MeshEndpointBinding{SchemaVersion: EndpointBindingV1, EndpointID: ids[0], Audience: "ui", RootRunID: root.RootRunID, RunID: root.RunID, SessionID: root.SessionID, AttemptID: root.AttemptID, ToolDigest: uiDigest, AllowedOperations: uiOps, PeerID: root.PeerID, PolicyVersion: root.PolicyVersion, IssuedAt: now, ExpiresAt: root.ExpiresAt, Generation: 1}
		if ui.Validate(now) != nil {
			return MeshEndpointBinding{}, ErrUnavailable
		}
		n := s.clone()
		n.EndpointBindings[ui.EndpointID] = ui
		if err = c.cas(ctx, s, n); err == nil {
			return ui, nil
		}
		if !errors.Is(err, ErrVersionConflict) {
			return MeshEndpointBinding{}, err
		}
	}
	return MeshEndpointBinding{}, ErrVersionConflict
}

func canonicalUIOperations() []string {
	return []string{"selection-revision", "ui-session-graph", "run-compare", "run-synthesis", "provider-directory", "provider-diagnostics", "run-templates", "policy-approval-inspector", "deployment-diagnostics", "plugin-lifecycle", "mesh-spawn", "mesh-spawnBatch", "mesh-send", "mesh-steer", "mesh-wait", "mesh-collect", "mesh-cancel", "mesh-list", "mesh-status", "mesh-result", "mesh-listProfiles"}
}

func canonicalUIBinding(binding MeshEndpointBinding) bool {
	want := hash(sortedStrings(canonicalUIOperations()))
	return binding.Audience == "ui" && binding.ToolDigest == want && hash(sortedStrings(binding.AllowedOperations)) == want && len(binding.AllowedOperations) == len(canonicalUIOperations())
}

// AuthorizeUIOperation authenticates one high-level Controller UI operation,
// then returns the separately durable mesh/root capability used internally by
// the Controller. The UI endpoint never carries raw child-control operations,
// and the returned mesh capability is never serialized to the UI boundary.
func (c *Coordinator) AuthorizeUIOperation(ctx context.Context, request EndpointRequest, operation, digest string) (MeshEndpointBinding, error) {
	if c == nil || c.poisoned.Load() || request.Audience != "ui" || !validID(operation) || digest == "" {
		return MeshEndpointBinding{}, ErrUnauthorized
	}
	// Reject legacy or substituted UI matrices before the persistent
	// authorizer can consume the request nonce. The authorizer rereads the same
	// durable binding below, closing a concurrent revoke/rotation race.
	candidate, err := c.EndpointBinding(ctx, request.EndpointID)
	if err != nil || !canonicalUIBinding(candidate) {
		return MeshEndpointBinding{}, ErrUnauthorized
	}
	ui, err := c.endpoints.AuthorizeOperationForPolicy(request, c.now().UTC(), operation, digest, c.policyVersion)
	if err != nil || !canonicalUIBinding(ui) {
		return MeshEndpointBinding{}, ErrUnauthorized
	}
	if err = ctx.Err(); err != nil {
		return MeshEndpointBinding{}, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	s, err := c.repo.Load(ctx)
	if err != nil {
		return MeshEndpointBinding{}, err
	}
	if err = s.Validate(); err != nil {
		c.poisoned.Store(true)
		return MeshEndpointBinding{}, ErrRepositoryPoisoned
	}
	if !bindingIsCurrent(s, ui, c.policyVersion, c.now().UTC()) {
		return MeshEndpointBinding{}, ErrUnauthorized
	}
	var root MeshEndpointBinding
	count := 0
	for _, candidate := range s.EndpointBindings {
		if candidate.Audience != "mesh" || candidate.RootRunID != ui.RootRunID || candidate.RunID != ui.RunID || candidate.SessionID != ui.SessionID || candidate.AttemptID != ui.AttemptID || candidate.PeerID != ui.PeerID || !bindingIsCurrent(s, candidate, c.policyVersion, c.now().UTC()) {
			continue
		}
		root = candidate
		count++
	}
	if count != 1 || root.RootRunID != root.RunID {
		return MeshEndpointBinding{}, ErrUnauthorized
	}
	return root, nil
}

func exactRootRegistration(s Snapshot, run Run, sessionID, attemptID, peerID, classification, workspace, policyVersion string, operations []string, now time.Time) (MeshEndpointBinding, bool) {
	if run.ID != run.RootID || run.ParentRunID != "" || run.ParentSessionID != "" || run.SessionID != sessionID || run.AttemptID != attemptID || run.Classification != classification || run.WorkspaceGroupID != workspace || run.Depth != 0 || run.State != RunRunning || run.ControlFence != "" {
		return MeshEndpointBinding{}, false
	}
	wantTools := hash(sortedStrings(operations))
	var match MeshEndpointBinding
	count := 0
	for endpointID, binding := range s.EndpointBindings {
		if binding.RunID != run.ID || binding.Audience != "mesh" {
			continue
		}
		if endpointID != binding.EndpointID || s.EndpointRevoked[endpointID] || binding.SchemaVersion != EndpointBindingV1 || binding.RootRunID != run.ID || binding.SessionID != sessionID || binding.AttemptID != attemptID || binding.PeerID != peerID || binding.PolicyVersion != policyVersion || binding.Generation != 1 || binding.ToolDigest != wantTools || hash(sortedStrings(binding.AllowedOperations)) != wantTools || binding.Validate(now) != nil {
			return MeshEndpointBinding{}, false
		}
		match = binding
		count++
	}
	return match, count == 1
}

func bindingIsCurrent(s Snapshot, binding MeshEndpointBinding, policyVersion string, now time.Time) bool {
	stored, ok := s.EndpointBindings[binding.EndpointID]
	return ok && !s.EndpointRevoked[binding.EndpointID] && stored.Generation == binding.Generation && stored.PolicyVersion == policyVersion && stored.ExpiresAt.After(now) && hash(stored) == hash(binding)
}

// EndpointBinding is a composition-only, read-only view of a durable endpoint.
// It never mints a capability, consumes a nonce, or exposes mutable
// EndpointAuthorizer state. Controller UI binding uses it to compare a signed
// owner operation with an endpoint that was already minted by RegisterRoot.
func (c *Coordinator) EndpointBinding(ctx context.Context, endpointID string) (MeshEndpointBinding, error) {
	if c == nil || c.poisoned.Load() || !validID(endpointID) {
		return MeshEndpointBinding{}, ErrUnauthorized
	}
	if err := ctx.Err(); err != nil {
		return MeshEndpointBinding{}, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	s, err := c.repo.Load(ctx)
	if err != nil {
		return MeshEndpointBinding{}, err
	}
	if err = s.Validate(); err != nil {
		return MeshEndpointBinding{}, ErrRepositoryPoisoned
	}
	binding, found := s.EndpointBindings[endpointID]
	if !found || s.EndpointRevoked[endpointID] || binding.PolicyVersion != c.policyVersion || binding.Validate(c.now().UTC()) != nil {
		return MeshEndpointBinding{}, ErrUnauthorized
	}
	run, found := s.Runs[binding.RunID]
	if !found || run.RootID != binding.RootRunID || run.SessionID != binding.SessionID || run.AttemptID != binding.AttemptID {
		return MeshEndpointBinding{}, ErrUnauthorized
	}
	return MeshEndpointBinding{SchemaVersion: binding.SchemaVersion, EndpointID: binding.EndpointID, Audience: binding.Audience, RootRunID: binding.RootRunID, RunID: binding.RunID, SessionID: binding.SessionID, AttemptID: binding.AttemptID, ToolDigest: binding.ToolDigest, AllowedOperations: append([]string(nil), binding.AllowedOperations...), PeerID: binding.PeerID, PolicyVersion: binding.PolicyVersion, IssuedAt: binding.IssuedAt, ExpiresAt: binding.ExpiresAt, Generation: binding.Generation}, nil
}

// LifecycleRootBinding is a narrowly scoped Controller-lifecycle lookup for an
// exact historical root endpoint generation.  Unlike EndpointBinding it is
// intentionally available after expiry, revocation, terminalization, or an
// admission poison, so a signed owner rotate/close operation can converge after
// a crash or uncertainty.  It never authorizes a model operation, mints a
// capability, consumes a nonce, or returns a child endpoint.
func (c *Coordinator) LifecycleRootBinding(ctx context.Context, endpointID string, generation uint64) (MeshEndpointBinding, error) {
	if c == nil || !validID(endpointID) || generation == 0 {
		return MeshEndpointBinding{}, ErrUnauthorized
	}
	if err := ctx.Err(); err != nil {
		return MeshEndpointBinding{}, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	s, err := c.repo.Load(ctx)
	if err != nil {
		return MeshEndpointBinding{}, err
	}
	if err = s.Validate(); err != nil {
		return MeshEndpointBinding{}, ErrRepositoryPoisoned
	}
	binding, found := s.EndpointBindings[endpointID]
	if !found || binding.Generation != generation || binding.RootRunID != binding.RunID {
		return MeshEndpointBinding{}, ErrUnauthorized
	}
	run, found := s.Runs[binding.RunID]
	if !found || run.ID != run.RootID || run.RootID != binding.RootRunID || run.SessionID != binding.SessionID || run.AttemptID != binding.AttemptID {
		return MeshEndpointBinding{}, ErrUnauthorized
	}
	return MeshEndpointBinding{SchemaVersion: binding.SchemaVersion, EndpointID: binding.EndpointID, Audience: binding.Audience, RootRunID: binding.RootRunID, RunID: binding.RunID, SessionID: binding.SessionID, AttemptID: binding.AttemptID, ToolDigest: binding.ToolDigest, AllowedOperations: append([]string(nil), binding.AllowedOperations...), PeerID: binding.PeerID, PolicyVersion: binding.PolicyVersion, IssuedAt: binding.IssuedAt, ExpiresAt: binding.ExpiresAt, Generation: binding.Generation}, nil
}

// RevokeEndpoint is a composition-only lifecycle seam. Callers must supply
// the exact durable endpoint generation; an unknown or rotated binding is
// denied rather than allowing a stale UI/lifecycle callback to revoke a newer
// capability. Repeated revocation of that exact binding is idempotent.
func (c *Coordinator) RevokeEndpoint(ctx context.Context, endpointID string, generation uint64) error {
	if c == nil || !validID(endpointID) || generation == 0 {
		return ErrUnauthorized
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for i := 0; i < 8; i++ {
		s, err := c.repo.Load(ctx)
		if err != nil {
			return err
		}
		binding, ok := s.EndpointBindings[endpointID]
		if !ok || binding.Generation != generation {
			return ErrDenied
		}
		if s.EndpointRevoked[endpointID] {
			return nil
		}
		n := s.clone()
		n.EndpointRevoked[endpointID] = true
		if err = c.casSafetyMonotone(ctx, s, n); err == nil {
			return nil
		}
		if !errors.Is(err, ErrVersionConflict) {
			return err
		}
	}
	return ErrVersionConflict
}

// RotateRootEndpoint is a Controller-lifecycle seam for renewing a durable
// root capability after the previous exact generation has expired or been
// revoked.  It never accepts a caller-supplied lineage: the old binding must
// byte-for-byte match the live journal root, and the old generation is revoked
// in the same normal CAS that mints the replacement.  A signed UI association
// operation must still bind the returned endpoint before any UI can use it.
func (c *Coordinator) RotateRootEndpoint(ctx context.Context, previous MeshEndpointBinding) (MeshEndpointBinding, error) {
	if c == nil || c.poisoned.Load() || previous.SchemaVersion != EndpointBindingV1 || previous.Audience != "mesh" || previous.RootRunID != previous.RunID || previous.Generation == 0 || previous.Generation == ^uint64(0) {
		return MeshEndpointBinding{}, ErrUnauthorized
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for i := 0; i < 8; i++ {
		s, err := c.repo.Load(ctx)
		if err != nil {
			return MeshEndpointBinding{}, err
		}
		stored, found := s.EndpointBindings[previous.EndpointID]
		root, rootFound := s.Runs[previous.RootRunID]
		if !found || !rootFound || hash(stored) != hash(previous) || stored.PolicyVersion != c.policyVersion || root.ID != root.RootID || root.State != RunRunning || root.SessionID != stored.SessionID || root.AttemptID != stored.AttemptID {
			return MeshEndpointBinding{}, ErrUnauthorized
		}
		if s.EndpointRevoked[previous.EndpointID] {
			// The rotation CAS may have committed before the signed UI-association
			// update.  Return the one exact durable successor on retry; never mint
			// a second generation from a revoked predecessor. A separately durable
			// exact revoke has no successor, however; the owner-only rotate remains
			// the safe recovery path for that historical root generation.
			var successor MeshEndpointBinding
			matches := 0
			for endpointID, candidate := range s.EndpointBindings {
				if !s.EndpointRevoked[endpointID] && candidate.Audience == stored.Audience && candidate.RootRunID == stored.RootRunID && candidate.RunID == stored.RunID && candidate.SessionID == stored.SessionID && candidate.AttemptID == stored.AttemptID && candidate.PeerID == stored.PeerID && candidate.PolicyVersion == stored.PolicyVersion && candidate.Generation == stored.Generation+1 && candidate.ToolDigest == stored.ToolDigest && hash(candidate.AllowedOperations) == hash(stored.AllowedOperations) {
					successor = candidate
					matches++
				}
			}
			if matches == 1 {
				return successor, nil
			}
			if matches > 1 {
				return MeshEndpointBinding{}, ErrUnauthorized
			}
		}
		ids, err := c.allocateIDs(s, 1)
		if err != nil {
			return MeshEndpointBinding{}, err
		}
		now := c.now().UTC()
		nextBinding := stored
		nextBinding.EndpointID = ids[0]
		nextBinding.Generation = stored.Generation + 1
		nextBinding.IssuedAt = now
		nextBinding.ExpiresAt = now.Add(15 * time.Minute)
		if nextBinding.Validate(now) != nil {
			return MeshEndpointBinding{}, ErrUnavailable
		}
		n := s.clone()
		n.EndpointRevoked[stored.EndpointID] = true
		n.EndpointBindings[nextBinding.EndpointID] = nextBinding
		if err = c.cas(ctx, s, n); err == nil {
			return nextBinding, nil
		}
		if !errors.Is(err, ErrVersionConflict) {
			return MeshEndpointBinding{}, err
		}
	}
	return MeshEndpointBinding{}, ErrVersionConflict
}

// RotateUIEndpointPair renews the externally bound UI capability and the
// distinct internal mesh/root capability in one durable CAS. A replay of the
// exact predecessor returns the one committed UI successor only when the
// matching mesh successor also exists. No internal mesh endpoint is returned.
func (c *Coordinator) RotateUIEndpointPair(ctx context.Context, previous MeshEndpointBinding) (MeshEndpointBinding, error) {
	if c == nil || c.poisoned.Load() || previous.SchemaVersion != EndpointBindingV1 || previous.Audience != "ui" || previous.RootRunID != previous.RunID || previous.Generation == 0 || previous.Generation == ^uint64(0) {
		return MeshEndpointBinding{}, ErrUnauthorized
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for i := 0; i < 8; i++ {
		s, err := c.repo.Load(ctx)
		if err != nil {
			return MeshEndpointBinding{}, err
		}
		stored, found := s.EndpointBindings[previous.EndpointID]
		rootRun, runFound := s.Runs[previous.RootRunID]
		if !found || !runFound || hash(stored) != hash(previous) || stored.Audience != "ui" || stored.PolicyVersion != c.policyVersion || rootRun.ID != rootRun.RootID || rootRun.State != RunRunning || rootRun.SessionID != stored.SessionID || rootRun.AttemptID != stored.AttemptID {
			return MeshEndpointBinding{}, ErrUnauthorized
		}
		if !canonicalUIBinding(stored) {
			return MeshEndpointBinding{}, ErrReconciliationNeeded
		}
		findPair := func(generation uint64, activeOnly bool) (MeshEndpointBinding, MeshEndpointBinding, int) {
			var ui, meshRoot MeshEndpointBinding
			uiCount, meshCount := 0, 0
			for endpointID, candidate := range s.EndpointBindings {
				if candidate.RootRunID != stored.RootRunID || candidate.RunID != stored.RunID || candidate.SessionID != stored.SessionID || candidate.AttemptID != stored.AttemptID || candidate.PeerID != stored.PeerID || candidate.PolicyVersion != stored.PolicyVersion || candidate.Generation != generation || (activeOnly && s.EndpointRevoked[endpointID]) {
					continue
				}
				switch candidate.Audience {
				case "ui":
					if canonicalUIBinding(candidate) {
						ui, uiCount = candidate, uiCount+1
					}
				case "mesh":
					meshRoot, meshCount = candidate, meshCount+1
				}
			}
			if uiCount == 1 && meshCount == 1 {
				return ui, meshRoot, 1
			}
			if uiCount > 1 || meshCount > 1 {
				return MeshEndpointBinding{}, MeshEndpointBinding{}, 2
			}
			return MeshEndpointBinding{}, MeshEndpointBinding{}, 0
		}
		if s.EndpointRevoked[stored.EndpointID] {
			nextUI, _, matches := findPair(stored.Generation+1, true)
			if matches == 1 {
				return nextUI, nil
			}
			if matches > 1 {
				return MeshEndpointBinding{}, ErrUnauthorized
			}
		}
		_, oldMesh, matches := findPair(stored.Generation, false)
		if matches != 1 || s.EndpointRevoked[oldMesh.EndpointID] {
			return MeshEndpointBinding{}, ErrReconciliationNeeded
		}
		ids, err := c.allocateIDs(s, 2)
		if err != nil {
			return MeshEndpointBinding{}, err
		}
		now := c.now().UTC()
		nextUI, nextMesh := stored, oldMesh
		nextUI.EndpointID, nextMesh.EndpointID = ids[0], ids[1]
		nextUI.Generation, nextMesh.Generation = stored.Generation+1, oldMesh.Generation+1
		nextUI.IssuedAt, nextMesh.IssuedAt = now, now
		nextUI.ExpiresAt, nextMesh.ExpiresAt = now.Add(15*time.Minute), now.Add(15*time.Minute)
		if nextUI.Validate(now) != nil || nextMesh.Validate(now) != nil {
			return MeshEndpointBinding{}, ErrUnavailable
		}
		n := s.clone()
		n.EndpointRevoked[stored.EndpointID], n.EndpointRevoked[oldMesh.EndpointID] = true, true
		n.EndpointBindings[nextUI.EndpointID], n.EndpointBindings[nextMesh.EndpointID] = nextUI, nextMesh
		if err = c.cas(ctx, s, n); err == nil {
			return nextUI, nil
		}
		if !errors.Is(err, ErrVersionConflict) {
			return MeshEndpointBinding{}, err
		}
	}
	return MeshEndpointBinding{}, ErrVersionConflict
}

// CloseRootEndpoint is the fail-closing counterpart to rotation.  It permits
// only an exact current root binding and uses the monotone safety CAS, so an
// authenticated lifecycle shutdown can revoke the capability even while a
// prior uncertain provider effect has poisoned ordinary admission.
func (c *Coordinator) CloseRootEndpoint(ctx context.Context, binding MeshEndpointBinding) error {
	if c == nil || binding.SchemaVersion != EndpointBindingV1 || binding.RootRunID != binding.RunID || binding.Generation == 0 {
		return ErrUnauthorized
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for i := 0; i < 8; i++ {
		s, err := c.repo.Load(ctx)
		if err != nil {
			return err
		}
		stored, found := s.EndpointBindings[binding.EndpointID]
		root, rootFound := s.Runs[binding.RootRunID]
		if !found || !rootFound || hash(stored) != hash(binding) || root.ID != root.RootID || root.SessionID != stored.SessionID || root.AttemptID != stored.AttemptID {
			return ErrUnauthorized
		}
		if root.ControlFence != "" {
			return ErrReconciliationNeeded
		}
		for _, child := range s.Runs {
			if child.RootID == root.ID && child.ID != root.ID && (!child.State.terminal() || child.State == RunUncertain || child.ControlFence != "") {
				return ErrReconciliationNeeded
			}
		}
		for _, proposal := range s.Proposals {
			if proposalRoot(s, proposal) == root.ID && proposal.State == "pending" {
				return ErrReconciliationNeeded
			}
		}
		for _, batch := range s.Batches {
			if batchRoot(s, batch) == root.ID && (batch.State == "pending" || batch.State == "uncertain") {
				return ErrReconciliationNeeded
			}
		}
		for _, receipt := range s.SendReceipts {
			if receiptRoot(s, receipt.TargetRunID) == root.ID && (receipt.State == "pending" || receipt.State == "failed" || receipt.State == "uncertain") {
				return ErrReconciliationNeeded
			}
		}
		for _, receipt := range s.CancelReceipts {
			if receiptRoot(s, receipt.TargetRunID) == root.ID && (receipt.State == "pending" || receipt.State == "failed" || receipt.State == "uncertain") {
				return ErrReconciliationNeeded
			}
		}
		n := s.clone()
		changed := false
		for endpointID, endpoint := range n.EndpointBindings {
			if endpoint.RootRunID == root.ID && !n.EndpointRevoked[endpointID] {
				n.EndpointRevoked[endpointID] = true
				changed = true
			}
		}
		if !root.State.terminal() {
			root.State = RunCancelled
			root.TerminalAt = c.now().UTC()
			n.Runs[root.ID] = root
			n.Events = append(n.Events, event(root.TerminalAt, "run_cancelled", root, ""))
			changed = true
		}
		if !changed {
			return nil
		}
		if err = c.casSafetyMonotone(ctx, s, n); err == nil {
			return nil
		}
		if !errors.Is(err, ErrVersionConflict) {
			return err
		}
	}
	return ErrVersionConflict
}

type ProposalRequest struct {
	Endpoint EndpointRequest
	Proposal SpawnProposal
}
type ProposalResult struct {
	ProposalID, RunID, SessionID, OrderID, BindingID string
	Replayed                                         bool
}

const callerScopeV2 = "mesh-caller-scope.v2"

type callerScopeInput struct {
	SchemaVersion string `json:"schema_version"`
	Domain        string `json:"domain"`
	EndpointID    string `json:"endpoint_id"`
	Generation    uint64 `json:"generation"`
	RootRunID     string `json:"root_run_id"`
	RunID         string `json:"run_id"`
	SessionID     string `json:"session_id"`
	AttemptID     string `json:"attempt_id"`
	ClientNonce   string `json:"client_nonce"`
}

func proposalScope(binding MeshEndpointBinding, clientNonce, domain string) string {
	return hash(callerScopeInput{SchemaVersion: callerScopeV2, Domain: domain, EndpointID: binding.EndpointID, Generation: binding.Generation, RootRunID: binding.RootRunID, RunID: binding.RunID, SessionID: binding.SessionID, AttemptID: binding.AttemptID, ClientNonce: clientNonce})
}

func proposalRecordKey(scope, proposalDigest string) string {
	return hash(struct {
		SchemaVersion string `json:"schema_version"`
		Scope         string `json:"scope"`
		Digest        string `json:"digest"`
	}{SchemaVersion: callerScopeV2, Scope: scope, Digest: proposalDigest})
}

func legacyProposalScope(binding MeshEndpointBinding, clientNonce string) string {
	return fmt.Sprintf("%d:%s:%s:%s", binding.Generation, binding.SessionID, binding.AttemptID, clientNonce)
}

func proposalOwnedByBinding(snapshot Snapshot, proposal ProposalRecord, binding MeshEndpointBinding) bool {
	stored, endpointOK := snapshot.EndpointBindings[binding.EndpointID]
	child, childOK := snapshot.Runs[proposal.RunID]
	parent, parentOK := snapshot.Runs[binding.RunID]
	attributed, attributionOK := proposalCallerBinding(snapshot, proposal)
	return endpointOK && attributionOK && attributed.EndpointID == binding.EndpointID && attributed.Generation == binding.Generation && stored.EndpointID == binding.EndpointID && stored.Generation == binding.Generation && stored.RootRunID == binding.RootRunID && stored.RunID == binding.RunID && stored.SessionID == binding.SessionID && stored.AttemptID == binding.AttemptID && childOK && parentOK && child.RootID == binding.RootRunID && child.ParentRunID == binding.RunID && child.ParentSessionID == binding.SessionID && parent.RootID == binding.RootRunID && parent.SessionID == binding.SessionID && parent.AttemptID == binding.AttemptID
}

func proposalCallerBinding(snapshot Snapshot, proposal ProposalRecord) (MeshEndpointBinding, bool) {
	child, childOK := snapshot.Runs[proposal.RunID]
	if !childOK {
		return MeshEndpointBinding{}, false
	}
	if proposal.CallerEndpointID != "" || proposal.CallerGeneration != 0 || proposal.RootRunID != "" {
		binding, ok := snapshot.EndpointBindings[proposal.CallerEndpointID]
		return binding, ok && proposal.CallerGeneration != 0 && binding.Generation == proposal.CallerGeneration && proposal.RootRunID == binding.RootRunID && child.RootID == binding.RootRunID && child.ParentRunID == binding.RunID && child.ParentSessionID == binding.SessionID
	}
	// Legacy v2 records had no explicit caller attribution. Accept them only
	// when lineage identifies one and only one durable endpoint generation; a
	// second matching endpoint makes migration unprovable and fails closed.
	var match MeshEndpointBinding
	count := 0
	for _, binding := range snapshot.EndpointBindings {
		if child.RootID == binding.RootRunID && child.ParentRunID == binding.RunID && child.ParentSessionID == binding.SessionID {
			match = binding
			count++
		}
	}
	return match, count == 1
}

func (c *Coordinator) ProposeSpawn(ctx context.Context, req ProposalRequest) (ProposalResult, error) {
	if c.poisoned.Load() {
		return ProposalResult{}, ErrRepositoryPoisoned
	}
	if err := req.Proposal.Validate(); err != nil {
		return ProposalResult{}, err
	}
	if req.Endpoint.MessageDigest != hash(req.Proposal) {
		return ProposalResult{}, ErrUnauthorized
	}
	now := c.now().UTC()
	b, e := c.endpoints.AuthorizeOperationForPolicy(req.Endpoint, now, "spawn", hash(req.Proposal), c.policyVersion)
	if e != nil {
		return ProposalResult{}, e
	}
	if !operationAudience(b.Audience) {
		return ProposalResult{}, ErrUnauthorized
	}
	// Endpoint nonces are single use, while proposal retries use a separate
	// durable caller/nonce/digest key; a retry must present a fresh endpoint nonce.
	digest := hash(req.Proposal)
	scope := proposalScope(b, req.Proposal.ClientNonce, "spawn")
	key := proposalRecordKey(scope, digest)
	return c.propose(ctx, b, req.Proposal, digest, scope, key, legacyProposalScope(b, req.Proposal.ClientNonce), now)
}
func (c *Coordinator) poisonIfUncertain(err error) error {
	if errors.Is(err, ErrCommitUncertain) {
		c.poisoned.Store(true)
		return ErrRepositoryPoisoned
	}
	return err
}

// ReloadAndReplay is the only path that clears an uncertainty poison. It
// rereads durable state and refuses to clear when a pending proposal remains.
func (c *Coordinator) ReloadAndReplay(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	wasPoisoned := c.poisoned.Load()
	s, err := c.repo.Load(ctx)
	if err != nil {
		return err
	}
	if err = s.Validate(); err != nil {
		return err
	}
	for _, p := range s.Proposals {
		if p.State == "pending" {
			return ErrReconciliationNeeded
		}
	}
	for _, run := range s.Runs {
		if run.State == RunUncertain {
			return ErrReconciliationNeeded
		}
	}
	for _, batch := range s.Batches {
		if batch.State == "pending" || batch.State == "uncertain" {
			return ErrReconciliationNeeded
		}
	}
	for _, receipt := range s.CancelReceipts {
		if receipt.State == "pending" || receipt.State == "uncertain" || receipt.State == "failed" {
			return ErrReconciliationNeeded
		}
	}
	for _, receipt := range s.SendReceipts {
		if receipt.State == "pending" || receipt.State == "failed" || receipt.State == "uncertain" {
			return ErrReconciliationNeeded
		}
	}
	if !recoverPersistedSessionRoutes(ctx, s, c.sessions) {
		return ErrReconciliationNeeded
	}
	// A post-rename ErrCommitUncertain may have made the final batch state
	// durable while compensation remained unjournaled. A plain snapshot reload
	// cannot prove the provider sessions match that state, so it must not clear
	// the poison. An explicit provider-evidence reconciler is required.
	if wasPoisoned && !c.recoveryPending {
		return ErrReconciliationNeeded
	}
	c.recoveryPending = false
	c.poisoned.Store(false)
	return nil
}
func (c *Coordinator) propose(ctx context.Context, b MeshEndpointBinding, p SpawnProposal, digest, scope, key, legacyScope string, now time.Time) (ProposalResult, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	var allocated []string
	for tries := 0; tries < 8; tries++ {
		s, e := c.repo.Load(ctx)
		if e != nil {
			return ProposalResult{}, e
		}
		if existingKey, ok := s.NonceScopes[scope]; ok {
			r := s.Proposals[existingKey]
			if !proposalOwnedByBinding(s, r, b) {
				return ProposalResult{}, ErrRepositoryPoisoned
			}
			if r.Digest != digest {
				return ProposalResult{}, ErrIdempotencyConflict
			}
			if r.State == "pending" {
				return ProposalResult{}, ErrReconciliationNeeded
			}
			run, runOK := s.Runs[r.RunID]
			if !runOK {
				return ProposalResult{}, ErrReconciliationNeeded
			}
			if r.State == "terminal" {
				if run.State == RunUncertain {
					return ProposalResult{}, ErrReconciliationNeeded
				}
				return ProposalResult{}, ErrDenied
			}
			return ProposalResult{ProposalID: r.ProposalID, RunID: r.RunID, SessionID: r.SessionID, OrderID: r.OrderID, BindingID: r.BindingID, Replayed: true}, nil
		}
		if legacyKey, ok := s.NonceScopes[legacyScope]; ok {
			legacy, found := s.Proposals[legacyKey]
			if !found {
				return ProposalResult{}, ErrRepositoryPoisoned
			}
			if _, runFound := s.Runs[legacy.RunID]; !runFound {
				return ProposalResult{}, ErrReconciliationNeeded
			}
			if proposalOwnedByBinding(s, legacy, b) {
				if legacy.Digest != digest {
					return ProposalResult{}, ErrIdempotencyConflict
				}
				next := s.clone()
				delete(next.NonceScopes, legacyScope)
				next.NonceScopes[scope] = legacyKey
				legacy.Scope = scope
				legacy.CallerEndpointID = b.EndpointID
				legacy.CallerGeneration = b.Generation
				legacy.RootRunID = b.RootRunID
				next.Proposals[legacyKey] = legacy
				if e = c.cas(ctx, s, next); e == nil || errors.Is(e, ErrVersionConflict) {
					continue
				}
				return ProposalResult{}, e
			}
		}
		parent, ok := s.Runs[b.RunID]
		if !bindingIsCurrent(s, b, c.policyVersion, now) || !ok || parent.RootID != b.RootRunID || parent.SessionID != b.SessionID || parent.AttemptID != b.AttemptID || parent.State != RunRunning {
			return ProposalResult{}, ErrUnauthorized
		}
		profile, e := c.directory.Lookup(ctx, p.PreferredProfile)
		if e != nil || !profile.Eligible() {
			return ProposalResult{}, ErrDenied
		}
		if !p.RequestedLimits.Narrows(profile.Limits) {
			return ProposalResult{}, ErrDenied
		}
		if parent.Classification == "PD" || parent.Classification == "L3" {
			if !profile.LocalOnly {
				return ProposalResult{}, ErrPDCloudRoute
			}
		}
		if parent.Depth+1 > p.RequestedLimits.MaxDepth || activeChildren(s, parent.ID) >= p.RequestedLimits.MaxChildrenPerParent || activeRuns(s, parent.RootID) >= p.RequestedLimits.MaxConcurrentRuns {
			return ProposalResult{}, ErrCapacity
		}
		var disclosure CloudDisclosure
		if !profile.LocalOnly {
			if c.disclosure == nil || activeCloudReservations(s) >= 1 {
				return ProposalResult{}, ErrDisclosure
			}
			reqDisclosure := CloudDisclosureRequest{RootRunID: parent.RootID, ParentRunID: parent.ID, ProfileID: profile.ID, DestinationProvider: profile.Provider, AccountHandleRef: profile.AccountHandleRef, Model: profile.Model, Classification: parent.Classification, PayloadDigest: hash(p.InputArtifactRefs), Purpose: "mesh_child_task", PolicyVersion: c.policyVersion, InputRevision: 1, ExpiresAt: now.Add(time.Duration(p.RequestedLimits.MaxWallMS) * time.Millisecond)}
			disclosure, e = c.disclosure.AuthorizeCloudDisclosure(ctx, reqDisclosure)
			if e != nil || disclosure.ValidateFor(reqDisclosure, now) != nil {
				return ProposalResult{}, ErrDisclosure
			}
		}
		effective := IntersectCapabilities(CapabilityEnvelope{Tools: p.RequestedTools}, profile.Supported)
		if len(effective.Tools) == 0 && len(p.RequestedTools) > 0 {
			return ProposalResult{}, ErrDenied
		}
		if allocated == nil {
			allocated, e = c.allocateIDs(s, 8)
			if e != nil {
				return ProposalResult{}, e
			}
		} else if snapshotUsesAnyID(s, allocated) {
			return ProposalResult{}, ErrUnavailable
		}
		proposalID, runID, sessionID, attemptID, orderID, bindingID, leaseID, endpointID := allocated[0], allocated[1], allocated[2], allocated[3], allocated[4], allocated[5], allocated[6], allocated[7]
		order := WorkOrderRecord{SchemaVersion: WorkOrderV2, OrderID: orderID, RootRunID: parent.RootID, ParentRunID: parent.ID, ParentSessionID: parent.SessionID, RunID: runID, SessionID: sessionID, AttemptID: attemptID, ProfileID: profile.ID, Provider: profile.Provider, Model: profile.Model, WorkspaceGroupID: parent.WorkspaceGroupID, Classification: parent.Classification, IdempotencyKey: key, LeaseID: leaseID, PolicyVersion: c.policyVersion, Depth: parent.Depth + 1, Limits: p.RequestedLimits, Requested: CapabilityEnvelope{Tools: append([]string(nil), p.RequestedTools...)}, Effective: effective, DisclosurePlanID: disclosure.PlanID, FanoutGrantID: disclosure.FanoutGrantID, LeaseExpiry: now.Add(time.Duration(p.RequestedLimits.MaxWallMS) * time.Millisecond), Task: p.TaskEnvelope()}
		order.OrderHash = hash(order)
		rec := ProposalRecord{Key: key, Scope: scope, Digest: digest, ProposalID: proposalID, RunID: runID, SessionID: sessionID, OrderID: orderID, BindingID: bindingID, CallerEndpointID: b.EndpointID, CallerGeneration: b.Generation, RootRunID: b.RootRunID, State: "pending", CreatedAt: now, Order: order}
		n := s.clone()
		n.NonceScopes[scope] = key
		n.Proposals[key] = rec
		child := Run{ID: runID, RootID: parent.RootID, ParentRunID: parent.ID, ParentSessionID: parent.SessionID, SessionID: sessionID, AttemptID: attemptID, ProfileID: profile.ID, Provider: profile.Provider, Classification: parent.Classification, WorkspaceGroupID: parent.WorkspaceGroupID, Depth: parent.Depth + 1, State: RunAdmitted, CreatedAt: now}
		n.Runs[runID] = child
		if !profile.LocalOnly {
			n.Disclosures[runID] = DisclosureReservation{PlanID: disclosure.PlanID, FanoutGrantID: disclosure.FanoutGrantID, Destination: disclosure.DestinationProvider}
		}
		n.Events = append(n.Events, event(now, "proposal_admitted", child, ""))
		if e = c.cas(ctx, s, n); e != nil {
			if errors.Is(e, ErrVersionConflict) {
				continue
			}
			return ProposalResult{}, e
		}
		binding := RunDispatchBinding{SchemaVersion: RunDispatchBindingV2, BindingID: bindingID, OrderID: orderID, OrderHash: order.OrderHash, RootRunID: child.RootID, RunID: runID, SessionID: sessionID, AttemptID: attemptID, EndpointID: endpointID, Generation: 1, IssuedAt: now, ExpiresAt: order.LeaseExpiry}
		binding.BindingHash = hash(binding)
		// No starter is a safe, useful production default: the admission is durable
		// but dispatch is marked uncertain for recovery instead of inventing a run.
		if c.starter == nil {
			if e = c.markTerminal(ctx, key, runID, "terminal", RunUncertain, "starter_unconfigured"); e != nil {
				return ProposalResult{}, errors.Join(ErrReconciliationNeeded, e)
			}
			return ProposalResult{}, ErrReconciliationNeeded
		}
		ref, e := c.starter.Start(ctx, sealStartRequest(order, binding))
		if e != nil {
			uncertain := errors.Is(e, ErrStartUncertain) || errors.Is(e, ErrReconciliationNeeded)
			state, code := RunFailed, "start_failed"
			if uncertain {
				state, code = RunUncertain, "start_uncertain"
			}
			if terminalErr := c.markTerminal(ctx, key, runID, "terminal", state, code); terminalErr != nil {
				return ProposalResult{}, errors.Join(ErrReconciliationNeeded, e, terminalErr)
			}
			if uncertain {
				return ProposalResult{}, errors.Join(ErrReconciliationNeeded, ErrStartUncertain, e)
			}
			return ProposalResult{}, fmt.Errorf("start sealed run %s: %w", runID, e)
		}
		if e = c.markStarted(ctx, key, runID, ref.ProviderSessionID); e != nil {
			return ProposalResult{}, c.reconcileStartedFailure(ctx, key, runID, ref, "start_commit_failed", e)
		}
		endpoint := MeshEndpointBinding{SchemaVersion: EndpointBindingV1, EndpointID: binding.EndpointID, Audience: "mesh", RootRunID: child.RootID, RunID: runID, SessionID: sessionID, AttemptID: attemptID, ToolDigest: hash(sortedStrings(effective.Tools)), AllowedOperations: effective.Tools, PeerID: "broker:" + sessionID, PolicyVersion: c.policyVersion, IssuedAt: now, ExpiresAt: order.LeaseExpiry, Generation: 1}
		if e = c.activateStarted(ctx, key, runID, endpoint); e != nil {
			return ProposalResult{}, c.reconcileStartedFailure(ctx, key, runID, ref, "run_commit_failed", e)
		}
		return ProposalResult{ProposalID: proposalID, RunID: runID, SessionID: sessionID, OrderID: orderID, BindingID: bindingID}, nil
	}
	return ProposalResult{}, ErrVersionConflict
}

// activateStarted is the single post-Start capability commit. A child cannot
// be observed as Running without its exact endpoint, and an endpoint cannot be
// durable while the child remains Starting. Any ambiguous CAS is reconciled by
// the caller through endpoint revocation and exact Start compensation.
func (c *Coordinator) activateStarted(ctx context.Context, key, runID string, endpoint MeshEndpointBinding) error {
	if endpoint.RunID != runID || endpoint.Validate(c.now().UTC()) != nil {
		return ErrInvalidContract
	}
	for i := 0; i < 8; i++ {
		s, err := c.repo.Load(ctx)
		if err != nil {
			return err
		}
		n := s.clone()
		proposal, proposalOK := n.Proposals[key]
		run, runOK := n.Runs[runID]
		if !proposalOK || !runOK || proposal.RunID != runID || proposal.State != "pending" || run.State != RunStarting || run.ProviderSessionID == "" {
			return ErrInvalidContract
		}
		if _, exists := n.EndpointBindings[endpoint.EndpointID]; exists {
			return ErrInvalidContract
		}
		n.EndpointBindings[endpoint.EndpointID] = endpoint
		proposal.State = "admitted"
		proposal.ResponseDigest = hash(ProposalResult{ProposalID: proposal.ProposalID, RunID: proposal.RunID, SessionID: proposal.SessionID, OrderID: proposal.OrderID, BindingID: proposal.BindingID})
		n.Proposals[key] = proposal
		run.State = RunRunning
		n.Runs[runID] = run
		n.Events = append(n.Events, event(c.now().UTC(), "run_running", run, ""))
		if err = c.casSafety(ctx, s, n); err == nil {
			return nil
		}
		if !errors.Is(err, ErrVersionConflict) {
			return err
		}
	}
	return ErrVersionConflict
}

// markStarted durably records the provider session before any child endpoint
// is minted. It is deliberately distinct from the final Running transition:
// a crash between these writes remains a pending proposal and requires
// explicit reconciliation rather than exposing a controllable child.
func (c *Coordinator) markStarted(ctx context.Context, key, runID, providerSessionID string) error {
	if !validID(providerSessionID) {
		return ErrInvalidContract
	}
	for i := 0; i < 8; i++ {
		s, e := c.repo.Load(ctx)
		if e != nil {
			return e
		}
		n := s.clone()
		r, runOK := n.Runs[runID]
		p, proposalOK := n.Proposals[key]
		if !runOK || !proposalOK || p.RunID != runID || p.State != "pending" || r.State != RunAdmitted {
			return ErrInvalidContract
		}
		r.State = RunStarting
		r.ProviderSessionID = providerSessionID
		n.Runs[runID] = r
		n.Events = append(n.Events, event(c.now().UTC(), "run_starting", r, ""))
		if e = c.casSafety(ctx, s, n); e == nil {
			return nil
		}
		if !errors.Is(e, ErrVersionConflict) {
			return e
		}
	}
	return ErrVersionConflict
}

// markTerminal is the only single-run final transition writer. Terminal
// transitions revoke every retained endpoint bound to that child in the same
// CAS, so a durable failure can never leave a usable child capability behind.
func (c *Coordinator) markTerminal(ctx context.Context, key, runID, state string, runState RunState, code string) error {
	if (state != "admitted" || runState != RunRunning) && (state != "terminal" || !runState.terminal()) {
		return ErrInvalidContract
	}
	for i := 0; i < 8; i++ {
		s, e := c.repo.Load(ctx)
		if e != nil {
			return e
		}
		n := s.clone()
		r, proposalOK := n.Proposals[key]
		run, runOK := n.Runs[runID]
		if !proposalOK || !runOK || r.RunID != runID || (r.State != "pending" && r.State != "admitted") {
			return ErrInvalidContract
		}
		if state == "admitted" && (r.State != "pending" || run.State != RunStarting) {
			return ErrInvalidContract
		}
		r.State = state
		r.ResponseDigest = hash(ProposalResult{ProposalID: r.ProposalID, RunID: r.RunID, SessionID: r.SessionID, OrderID: r.OrderID, BindingID: r.BindingID})
		n.Proposals[key] = r
		run.State = runState
		transitionAt := c.now().UTC()
		if runState.terminal() {
			run.TerminalAt = transitionAt
		} else {
			run.TerminalAt = time.Time{}
		}
		n.Runs[runID] = run
		if runState.terminal() {
			for endpointID, binding := range n.EndpointBindings {
				if binding.RunID == runID {
					n.EndpointRevoked[endpointID] = true
				}
			}
		}
		n.Events = append(n.Events, event(transitionAt, "run_"+string(runState), run, code))
		commit := c.cas
		if runState.terminal() {
			commit = c.casSafetyMonotone
		}
		if e = commit(ctx, s, n); e == nil {
			return nil
		}
		if !errors.Is(e, ErrVersionConflict) {
			return e
		}
	}
	return ErrVersionConflict
}

// revokeRunEndpoints is safe before compensation: it changes no provider
// state, and it never touches the caller/root endpoint because it matches the
// exact target RunID only.
func (c *Coordinator) revokeRunEndpoints(ctx context.Context, runID string) error {
	for i := 0; i < 8; i++ {
		s, err := c.repo.Load(ctx)
		if err != nil {
			return err
		}
		n := s.clone()
		changed := false
		for endpointID, binding := range n.EndpointBindings {
			if binding.RunID == runID && !n.EndpointRevoked[endpointID] {
				n.EndpointRevoked[endpointID] = true
				changed = true
			}
		}
		if !changed {
			return nil
		}
		// Endpoint revocation is a monotone fail-safe operation. It remains
		// permitted while the coordinator is poisoned so a failed final run
		// transition can still close a just-minted child capability. No other
		// lifecycle transition bypasses the poison gate.
		if err = c.repo.CompareAndSwap(ctx, s, n); err == nil {
			return nil
		}
		if errors.Is(err, ErrCommitUncertain) {
			c.poisoned.Store(true)
		}
		if !errors.Is(err, ErrVersionConflict) {
			return err
		}
	}
	return ErrVersionConflict
}

// reconcileStartedFailure is used only after a native Start returned a session
// reference. It never mints or leaves a child endpoint usable, attempts the
// exact provider compensation once, and reports reconciliation regardless of
// whether the durable terminal write ultimately converges.
func (c *Coordinator) reconcileStartedFailure(ctx context.Context, key, runID string, ref SessionRef, code string, cause error) error {
	revokeErr := c.revokeRunEndpoints(ctx, runID)
	if revokeErr != nil {
		// The provider session exists and an endpoint might still be durable.
		// Block all further authorization until explicit replay/evidence can
		// establish whether the revocation committed.
		c.poisoned.Store(true)
	}
	var cancelErr error
	if c.sessions == nil || !validID(ref.ProviderSessionID) {
		cancelErr = ErrReconciliationNeeded
	} else {
		cancelErr = c.sessions.Cancel(ctx, ref, Cancellation{Mode: CancellationStartCompensation, ReasonRef: "start_commit_failed"})
	}
	terminalErr := c.markTerminal(ctx, key, runID, "terminal", RunUncertain, code)
	return errors.Join(ErrReconciliationNeeded, cause, revokeErr, cancelErr, terminalErr)
}
func (c *Coordinator) Replay(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	s, e := c.repo.Load(ctx)
	if e != nil {
		return e
	}
	if e = s.Validate(); e != nil {
		return e
	}
	for _, p := range s.Proposals {
		if p.State == "pending" {
			return ErrReconciliationNeeded
		}
	}
	for _, run := range s.Runs {
		if run.State == RunUncertain {
			return ErrReconciliationNeeded
		}
	}
	for _, batch := range s.Batches {
		// A pending batch may already have provider receipts after a crash between
		// child persistence and the final batch CAS. It must be reconciled, never
		// implicitly promoted or restarted by replay.
		if batch.State == "pending" || batch.State == "uncertain" {
			return ErrReconciliationNeeded
		}
	}
	for _, receipt := range s.CancelReceipts {
		if receipt.State == "pending" || receipt.State == "uncertain" || receipt.State == "failed" {
			return ErrReconciliationNeeded
		}
	}
	// Send and steer are native input effects.  A retained pending, failed, or
	// uncertain receipt is not proof that a previous input was absent; replay
	// must therefore stop before it can ever admit another control operation.
	// Only a durably "sent" receipt has a closed outcome.
	for _, receipt := range s.SendReceipts {
		if receipt.State == "pending" || receipt.State == "uncertain" || receipt.State == "failed" {
			return ErrReconciliationNeeded
		}
	}
	return nil
}

// MigrateV1 creates an additive v2 journal. It never rewrites legacy bytes:
// callers retain the old snapshot and persist this returned snapshot separately
// before switching to dual-read/single-write v2.
func MigrateV1(legacyDigest string, migratedAt time.Time) (Snapshot, error) {
	if !isDigest(legacyDigest) || migratedAt.IsZero() {
		return Snapshot{}, ErrInvalidContract
	}
	s := emptySnapshot()
	s.Events = append(s.Events, MeshEvent{SchemaVersion: "mesh-event.v1", Event: "legacy_v1_migrated", Phase: "migration", RecoveryState: "dual_read", At: migratedAt.UTC(), ErrorCode: legacyDigest})
	return s, nil
}

type TargetRequest struct {
	Endpoint               EndpointRequest
	TargetRunID, Operation string
}

// AuthorizeTarget authenticates the endpoint before applying the fail-closed
// caller-to-target matrix. A caller cannot supply a binding or lineage itself.
func (c *Coordinator) AuthorizeTarget(ctx context.Context, request TargetRequest) (Run, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	expected := hash(request.TargetRunID + ":" + request.Operation)
	binding, err := c.endpoints.AuthorizeOperationForPolicy(request.Endpoint, c.now().UTC(), request.Operation, expected, c.policyVersion)
	if err != nil {
		return Run{}, err
	}
	return c.authorizeTarget(ctx, binding, request.TargetRunID, request.Operation)
}

// authorizeTarget accepts a binding only after EndpointAuthorizer verification.
func (c *Coordinator) authorizeTarget(ctx context.Context, binding MeshEndpointBinding, targetRunID, operation string) (Run, error) {
	target, err := c.authorizeTargetLineage(ctx, binding, targetRunID, operation)
	if err != nil {
		return Run{}, err
	}
	if target.ControlFence != "" {
		return Run{}, ErrReconciliationNeeded
	}
	// This public authorization boundary is authoritative for native control,
	// not merely a lineage check. New input and native cancellation only target
	// a live running child. Observation/list operations preserve terminal
	// visibility. Cancel's exact receipt replay uses the private lineage helper
	// after authenticating its endpoint and may not create fresh control.
	if (operation == "send" || operation == "steer" || operation == "cancel") && target.State != RunRunning {
		return Run{}, ErrDenied
	}
	return target, nil
}

// authorizeTargetLineage is intentionally private. It supplies the one
// narrow exact-receipt cancel replay path without weakening the public
// AuthorizeTarget operation/state matrix above.
func (c *Coordinator) authorizeTargetLineage(ctx context.Context, binding MeshEndpointBinding, targetRunID, operation string) (Run, error) {
	if !operationAudience(binding.Audience) || !validID(targetRunID) {
		return Run{}, ErrUnauthorized
	}
	s, err := c.repo.Load(ctx)
	if err != nil {
		return Run{}, err
	}
	target, ok := s.Runs[targetRunID]
	if !bindingIsCurrent(s, binding, c.policyVersion, c.now().UTC()) || !ok || target.RootID != binding.RootRunID {
		return Run{}, ErrUnauthorized
	}
	if operation == "list" && target.ID == binding.RunID {
		return target, nil
	}
	switch operation {
	case "send", "steer", "wait", "collect", "status", "result", "cancel", "list":
		if target.ParentRunID == binding.RunID {
			return target, nil
		}
	}
	return Run{}, ErrUnauthorized
}

// operationAudience identifies endpoint audiences that may use the durable
// controller operation path.  UI is deliberately a distinct capability: the
// endpoint authorizer still requires the request to carry the exact audience
// stored on the binding, so a UI token cannot be replayed as a mesh token.
// It is admitted here because the controller's closed UI projection performs
// only its allowlisted operations through the same durable lineage checks.
func operationAudience(audience string) bool { return audience == "mesh" }
func event(at time.Time, name string, r Run, code string) MeshEvent {
	return MeshEvent{SchemaVersion: "mesh-event.v1", Event: name, RootRunID: r.RootID, RunID: r.ID, SessionID: r.SessionID, AttemptID: r.AttemptID, ParentRunID: r.ParentRunID, Provider: r.Provider, ProfileID: r.ProfileID, Phase: "controller", Status: string(r.State), Classification: r.Classification, ErrorCode: code, At: at}
}
func activeChildren(s Snapshot, parent string) uint64 {
	var n uint64
	for _, r := range s.Runs {
		if r.ParentRunID == parent && !r.State.terminal() {
			n++
		}
	}
	return n
}
func activeRuns(s Snapshot, root string) uint64 {
	var n uint64
	for _, r := range s.Runs {
		if r.RootID == root && !r.State.terminal() {
			n++
		}
	}
	return n
}
func activeCloudReservations(s Snapshot) uint64 {
	var n uint64
	for _, r := range s.Disclosures {
		if !r.Consumed {
			n++
		}
	}
	return n
}
func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
func (c *Coordinator) allocateIDs(snapshot Snapshot, count int) ([]string, error) {
	if c == nil || c.nextID == nil || count < 1 || count > 128 {
		return nil, ErrUnavailable
	}
	allocated := make([]string, 0, count)
	seen := make(map[string]struct{}, count)
	for len(allocated) < count {
		id, err := c.nextID()
		if err != nil || !validID(id) || snapshotUsesID(snapshot, id) {
			return nil, ErrUnavailable
		}
		if _, duplicate := seen[id]; duplicate {
			return nil, ErrUnavailable
		}
		seen[id] = struct{}{}
		allocated = append(allocated, id)
	}
	return allocated, nil
}

// snapshotUsesID treats Controller-generated identifiers as one namespace.
// This is deliberately stricter than individual schema maps: an injected or
// failed entropy source cannot alias a run with an endpoint, receipt, proposal,
// batch, disclosure, or provider session and create ambiguous recovery state.
func snapshotUsesID(s Snapshot, candidate string) bool {
	if candidate == "" {
		return false
	}
	used := func(values ...string) bool {
		for _, value := range values {
			if value == candidate {
				return true
			}
		}
		return false
	}
	for key, run := range s.Runs {
		if used(key, run.ID, run.RootID, run.ParentRunID, run.ParentSessionID, run.SessionID, run.AttemptID, run.ProviderSessionID) {
			return true
		}
	}
	for _, proposal := range s.Proposals {
		if used(proposal.BatchID, proposal.ProposalID, proposal.RunID, proposal.SessionID, proposal.OrderID, proposal.BindingID) {
			return true
		}
	}
	for _, batch := range s.Batches {
		if used(batch.BatchID) {
			return true
		}
		for _, attempt := range batch.Attempts {
			if used(attempt.ProposalID, attempt.RunID, attempt.SessionID, attempt.AttemptID, attempt.StartReceipt) {
				return true
			}
		}
	}
	for _, disclosure := range s.Disclosures {
		if used(disclosure.PlanID, disclosure.FanoutGrantID) {
			return true
		}
	}
	for key, binding := range s.EndpointBindings {
		if used(key, binding.EndpointID, binding.RootRunID, binding.RunID, binding.SessionID, binding.AttemptID, binding.PeerID) {
			return true
		}
	}
	for _, receipt := range s.SendReceipts {
		if used(receipt.CallerEndpointID, receipt.CallerRunID, receipt.TargetRunID) {
			return true
		}
	}
	for _, receipt := range s.CancelReceipts {
		if used(receipt.CallerEndpointID, receipt.TargetRunID) {
			return true
		}
	}
	for _, tombstone := range s.Tombstones {
		if used(tombstone.EndpointID, tombstone.RootRunID, tombstone.Scope) {
			return true
		}
	}
	return false
}

func snapshotUsesAnyID(s Snapshot, candidates []string) bool {
	for _, candidate := range candidates {
		if snapshotUsesID(s, candidate) {
			return true
		}
	}
	return false
}

func randomID() (string, error) {
	b := make([]byte, 16)
	if _, e := rand.Read(b); e != nil {
		return "", e
	}
	return "mesh-" + hex.EncodeToString(b), nil
}
func isDigest(s string) bool {
	if len(s) != 71 || s[:7] != "sha256:" {
		return false
	}
	_, err := hex.DecodeString(s[7:])
	return err == nil
}
