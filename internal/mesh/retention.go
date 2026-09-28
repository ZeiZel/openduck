package mesh

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

const (
	JournalTombstoneV1 = "mesh-journal-tombstone.v1"

	maxRetentionEntries       = 16 << 10
	maxRetentionEndpointItems = 512
	maxRetentionRootItems     = 4096
	maxRetentionWindow        = 90 * 24 * time.Hour
	// AES-GCM, as instantiated by repository.go with the Go standard library,
	// has a 12-byte nonce and a 16-byte authentication tag. Keep the sealed
	// journal arithmetic next to the policy rather than treating MaxSealedBytes
	// as a plaintext cap.
	aesGCMNonceBytes = 12
	aesGCMTagBytes   = 16
)

// JournalTombstone is a bounded commitment to a retired endpoint generation.
// Scope is the canonical domain-separated endpoint-generation commitment; Digest commits to the
// sorted proposal/receipt replay scopes that were compacted with it. No raw
// provider payload or endpoint capability is retained.
type JournalTombstone struct {
	SchemaVersion string
	Domain        string
	Scope         string
	Digest        string
	RootRunID     string
	EndpointID    string
	Commitment    string
	Generation    uint64
	Revoked       bool
	TerminalAt    time.Time
	ExpiresAt     time.Time
}

// RetentionPolicy keeps normal admission below the encrypted journal's hard
// limit. SafetyReserveBytes is reserved for terminal, revoke and uncertainty
// transitions; callers must use admissionBudgetAvailable before adding work.
type RetentionPolicy struct {
	MaxSealedBytes        int
	SafetyReserveBytes    int
	SafetyReserveEntries  int
	MaxEntries            int
	MaxEntriesPerEndpoint int
	MaxEntriesPerRoot     int
	RecoveryWindow        time.Duration
	TombstoneWindow       time.Duration
}

func defaultRetentionPolicy() RetentionPolicy {
	return RetentionPolicy{
		MaxSealedBytes:        maxJournalBytes,
		SafetyReserveBytes:    64 << 10,
		SafetyReserveEntries:  64,
		MaxEntries:            4096,
		MaxEntriesPerEndpoint: 128,
		MaxEntriesPerRoot:     1024,
		RecoveryWindow:        24 * time.Hour,
		TombstoneWindow:       7 * 24 * time.Hour,
	}
}

func (p RetentionPolicy) Validate() error {
	if p.MaxSealedBytes < 1024 || p.MaxSealedBytes > maxJournalBytes || p.SafetyReserveBytes < 0 || p.SafetyReserveBytes >= p.MaxSealedBytes || p.SafetyReserveEntries < 2 || p.MaxEntries < p.SafetyReserveEntries || p.MaxEntries > maxRetentionEntries || p.MaxEntriesPerEndpoint < 2 || p.MaxEntriesPerEndpoint > maxRetentionEndpointItems || p.MaxEntriesPerRoot < p.MaxEntriesPerEndpoint || p.MaxEntriesPerRoot > maxRetentionRootItems || p.MaxEntriesPerRoot > p.MaxEntries || p.RecoveryWindow <= 0 || p.RecoveryWindow > maxRetentionWindow || p.TombstoneWindow < p.RecoveryWindow || p.TombstoneWindow > maxRetentionWindow {
		return ErrInvalidContract
	}
	return nil
}

type journalMutationClass uint8

const (
	journalMutationNormal journalMutationClass = iota
	journalMutationSafety
)

func journalTombstoneLookupKey(domain, scope string) string {
	return hash("openduck.mesh.tombstone.lookup.v1\n" + domain + "\n" + scope)
}

func journalTombstoneCommitment(t JournalTombstone) string {
	return hash(strings.Join([]string{
		"openduck.mesh.tombstone.v1", t.SchemaVersion, t.Domain, t.Scope, t.Digest,
		t.RootRunID, t.EndpointID, t.CommitmentInputGeneration(), fmt.Sprint(t.Revoked),
		t.TerminalAt.UTC().Format(time.RFC3339Nano), t.ExpiresAt.UTC().Format(time.RFC3339Nano),
	}, "\n"))
}

func (t JournalTombstone) CommitmentInputGeneration() string { return fmt.Sprint(t.Generation) }

func validJournalTombstone(key string, t JournalTombstone) bool {
	if t.SchemaVersion != JournalTombstoneV1 || t.Domain != "endpoint_generation" || !validID(t.Scope) || !isDigest(t.Digest) || !validID(t.RootRunID) || !validID(t.EndpointID) || t.Generation == 0 || !t.Revoked || t.TerminalAt.IsZero() || !t.ExpiresAt.After(t.TerminalAt) || key != journalTombstoneLookupKey(t.Domain, t.Scope) || !isDigest(t.Commitment) {
		return false
	}
	without := t
	without.Commitment = ""
	return t.Commitment == journalTombstoneCommitment(without)
}

func tombstoneFor(s Snapshot, domain, scope string) (JournalTombstone, bool) {
	t, ok := s.Tombstones[journalTombstoneLookupKey(domain, scope)]
	return t, ok && validJournalTombstone(journalTombstoneLookupKey(domain, scope), t)
}

func endpointGenerationScope(endpointID string, generation uint64) string {
	return hash("openduck.mesh.endpoint-generation.v1\n" + endpointID + "\n" + fmt.Sprint(generation))
}

// prepareJournalCommit is pure: it produces the exact candidate that a CAS
// may persist, or rejects it before any atomicWrite. Both in-memory and file
// repositories use this function so fault/restart tests see identical bounds.
func prepareJournalCommit(old, next Snapshot, now time.Time, policy RetentionPolicy, class journalMutationClass) (Snapshot, error) {
	if policy.Validate() != nil || now.IsZero() || old.Validate() != nil || next.Validate() != nil {
		return Snapshot{}, fmt.Errorf("%w: retention preflight input", ErrUnavailable)
	}
	candidate, err := compactSnapshot(next, now.UTC(), policy)
	if err != nil {
		return Snapshot{}, fmt.Errorf("%w: retention compaction", ErrUnavailable)
	}
	if candidate.Validate() != nil {
		return Snapshot{}, fmt.Errorf("%w: retention candidate", ErrUnavailable)
	}
	if err := journalEntryBudget(candidate, policy, class); err != nil {
		return Snapshot{}, err
	}
	if err := sealedSnapshotBudget(candidate, policy, class); err != nil {
		return Snapshot{}, err
	}
	return candidate, nil
}

func sealedSnapshotBudget(s Snapshot, policy RetentionPolicy, class journalMutationClass) error {
	plain, err := json.Marshal(s)
	if err != nil {
		return ErrUnavailable
	}
	sealed := sealedJournalBytes(len(plain))
	limit := policy.MaxSealedBytes
	if class == journalMutationNormal {
		limit -= policy.SafetyReserveBytes
	}
	if sealed > limit {
		return ErrUnavailable
	}
	return nil
}

// sealedJournalBytes is the exact on-disk length emitted by
// EncryptedFileRepository.seal for a JSON plaintext of plainBytes. It is
// deliberately small and overflow-aware so preflight rejects impossible input
// before any persistence attempt.
func sealedJournalBytes(plainBytes int) int {
	if plainBytes < 0 || plainBytes > maxJournalBytes-aesGCMNonceBytes-aesGCMTagBytes {
		return maxJournalBytes + 1
	}
	return plainBytes + aesGCMNonceBytes + aesGCMTagBytes
}

func journalEntryBudget(s Snapshot, policy RetentionPolicy, class journalMutationClass) error {
	total := len(s.Runs) + len(s.Proposals) + len(s.Batches) + len(s.NonceScopes) + len(s.Disclosures) + len(s.EndpointBindings) + len(s.EndpointNonces) + len(s.EndpointRevoked) + len(s.SendReceipts) + len(s.CancelReceipts) + len(s.Events) + len(s.Tombstones)
	limit := policy.MaxEntries
	if class == journalMutationNormal {
		limit -= policy.SafetyReserveEntries
	}
	if total > limit {
		return ErrUnavailable
	}
	endpointCounts, rootCounts := map[string]int{}, map[string]int{}
	addRoot := func(rootID string) bool {
		if !validID(rootID) {
			return false
		}
		rootCounts[rootID]++
		return true
	}
	addEndpoint := func(endpointID string, generation uint64) bool {
		if !validID(endpointID) || generation == 0 {
			return false
		}
		endpointCounts[endpointGenerationScope(endpointID, generation)]++
		return true
	}
	rootForRun := func(runID string) (string, bool) {
		run, ok := s.Runs[runID]
		return run.RootID, ok
	}
	for _, run := range s.Runs {
		if !addRoot(run.RootID) {
			return ErrUnavailable
		}
	}
	for _, proposal := range s.Proposals {
		rootID := proposal.RootRunID
		if rootID == "" {
			var ok bool
			rootID, ok = rootForRun(proposal.RunID)
			if !ok {
				return ErrUnavailable
			}
		}
		if !addRoot(rootID) {
			return ErrUnavailable
		}
		binding, attributed := proposalCallerBinding(s, proposal)
		if !attributed || !addEndpoint(binding.EndpointID, binding.Generation) {
			return ErrUnavailable
		}
	}
	// NonceScopes are separate durable records. Charging only their paired
	// proposal would let one endpoint exhaust the global journal while bypassing
	// its own reservation. They must have a one-to-one authenticated proposal
	// owner; orphan scopes are corrupt for retention purposes even if a legacy
	// Snapshot.Validate implementation predates this stronger accounting rule.
	for scope, proposalKey := range s.NonceScopes {
		proposal, ok := s.Proposals[proposalKey]
		if !ok || proposal.Scope != scope {
			return ErrUnavailable
		}
		rootID := proposal.RootRunID
		if rootID == "" {
			var rootOK bool
			rootID, rootOK = rootForRun(proposal.RunID)
			if !rootOK {
				return ErrUnavailable
			}
		}
		if !addRoot(rootID) {
			return ErrUnavailable
		}
		binding, attributed := proposalCallerBinding(s, proposal)
		if !attributed || !addEndpoint(binding.EndpointID, binding.Generation) {
			return ErrUnavailable
		}
	}
	for _, batch := range s.Batches {
		rootID := batchRoot(s, batch)
		if !addRoot(rootID) {
			return ErrUnavailable
		}
		// A batch is created under one authenticated caller binding. Attribute its
		// durable envelope once to that generation so batching cannot bypass the
		// per-endpoint reserve. Multiple or legacy owners fail closed here.
		var owner MeshEndpointBinding
		for _, proposalKey := range batch.ProposalKeys {
			proposal, ok := s.Proposals[proposalKey]
			if !ok {
				return ErrUnavailable
			}
			binding, attributed := proposalCallerBinding(s, proposal)
			if !attributed || binding.RootRunID != rootID {
				return ErrUnavailable
			}
			if owner.EndpointID == "" {
				owner = binding
			} else if owner.EndpointID != binding.EndpointID || owner.Generation != binding.Generation {
				return ErrUnavailable
			}
		}
		if owner.EndpointID == "" || !addEndpoint(owner.EndpointID, owner.Generation) {
			return ErrUnavailable
		}
	}
	for runID := range s.Disclosures {
		rootID, ok := rootForRun(runID)
		if !ok || !addRoot(rootID) {
			return ErrUnavailable
		}
	}
	for endpointID, binding := range s.EndpointBindings {
		if !addRoot(binding.RootRunID) || !addEndpoint(endpointID, binding.Generation) {
			return ErrUnavailable
		}
	}
	for key := range s.EndpointNonces {
		binding, generation, _, ok := endpointNonceReference(key, s.EndpointBindings)
		if !ok || binding.Generation != generation || !addRoot(binding.RootRunID) || !addEndpoint(binding.EndpointID, generation) {
			return ErrUnavailable
		}
	}
	for endpointID := range s.EndpointRevoked {
		binding, ok := s.EndpointBindings[endpointID]
		if !ok || !addRoot(binding.RootRunID) || !addEndpoint(endpointID, binding.Generation) {
			return ErrUnavailable
		}
	}
	for _, receipt := range s.SendReceipts {
		rootID, ok := rootForRun(receipt.TargetRunID)
		if !ok || !addRoot(rootID) {
			return ErrUnavailable
		}
		if receipt.CallerEndpointID != "" || receipt.CallerGeneration != 0 {
			if !addEndpoint(receipt.CallerEndpointID, receipt.CallerGeneration) {
				return ErrUnavailable
			}
		}
	}
	for _, receipt := range s.CancelReceipts {
		rootID, ok := rootForRun(receipt.TargetRunID)
		if !ok || !addRoot(rootID) {
			return ErrUnavailable
		}
		if receipt.CallerEndpointID != "" || receipt.CallerGeneration != 0 {
			if !addEndpoint(receipt.CallerEndpointID, receipt.CallerGeneration) {
				return ErrUnavailable
			}
		}
	}
	for _, event := range s.Events {
		// MigrateV1 intentionally emits one journal-global audit event with no
		// root attribution. It is validated by Snapshot.Validate and counts
		// toward the global ceiling, but must not be charged to an invented root.
		if event.Event == "legacy_v1_migrated" {
			continue
		}
		if !addRoot(event.RootRunID) {
			return ErrUnavailable
		}
	}
	for _, tombstone := range s.Tombstones {
		if !addRoot(tombstone.RootRunID) || !addEndpoint(tombstone.EndpointID, tombstone.Generation) {
			return ErrUnavailable
		}
	}
	endpointLimit, rootLimit := policy.MaxEntriesPerEndpoint, policy.MaxEntriesPerRoot
	if class == journalMutationNormal {
		// Reserve enough local headroom for an atomic cancel to add its nonce and
		// receipt, and for an endpoint/root safety transition to add its durable
		// evidence. The safety class still cannot exceed the hard policy limits.
		endpointLimit -= localSafetyReserve(policy.MaxEntriesPerEndpoint, policy.SafetyReserveEntries, 4)
		rootLimit -= localSafetyReserve(policy.MaxEntriesPerRoot, policy.SafetyReserveEntries, 8)
	}
	for _, n := range endpointCounts {
		if n > endpointLimit {
			return ErrUnavailable
		}
	}
	for _, n := range rootCounts {
		if n > rootLimit {
			return ErrUnavailable
		}
	}
	return nil
}

func localSafetyReserve(hard, totalReserve, desired int) int {
	reserve := desired
	if reserve > totalReserve {
		reserve = totalReserve
	}
	if reserve >= hard {
		reserve = hard - 1
	}
	return reserve
}

// admissionBudgetAvailable is called by the Controller before it commits a
// new non-safety admission/nonce. It reserves bytes for a later revoke or
// terminalization; safety transitions are instead checked against the hard
// sealed cap by prepareJournalCommit.
func admissionBudgetAvailable(s Snapshot, policy RetentionPolicy) error {
	if policy.Validate() != nil || journalEntryBudget(s, policy, journalMutationNormal) != nil {
		return ErrUnavailable
	}
	plain, err := json.Marshal(s)
	if err != nil || len(plain)+12+16 > policy.MaxSealedBytes-policy.SafetyReserveBytes {
		return ErrUnavailable
	}
	return nil
}

// compactSnapshot performs no partial mutation. It can retire only an entire
// terminal root whose endpoint generations are all revoked or expired, so an
// active lineage, pending receipt, or live endpoint is never pruned.
func compactSnapshot(in Snapshot, now time.Time, policy RetentionPolicy) (Snapshot, error) {
	s := in.clone()
	for endpointID, binding := range s.EndpointBindings {
		if endpointEligibleForCompaction(s, endpointID, binding, now, policy.RecoveryWindow) {
			if err := compactEndpointGeneration(&s, endpointID, binding, now, policy); err != nil {
				return Snapshot{}, err
			}
		}
	}
	for rootID := range roots(s) {
		if markLegacyTerminalHorizon(&s, rootID, now) {
			// A pre-TerminalAt journal is deliberately retained for a complete
			// fresh recovery window after its first safe post-upgrade commit.
			continue
		}
		if !rootEligibleForCompaction(s, rootID, now, policy.RecoveryWindow) {
			continue
		}
		if err := compactRoot(&s, rootID, now, policy); err != nil {
			return Snapshot{}, err
		}
	}
	for key, t := range s.Tombstones {
		if !validJournalTombstone(key, t) {
			return Snapshot{}, ErrUnavailable
		}
		if !t.ExpiresAt.After(now) {
			delete(s.Tombstones, key)
		}
	}
	return s, nil
}

// endpointEligibleForCompaction allows a long-lived root to rotate one retired
// endpoint generation. It never prunes the root: every proposal subtree and
// every receipt reachable through the retired generation must already be
// terminal, certain, and past the configured recovery window.
func endpointEligibleForCompaction(s Snapshot, endpointID string, binding MeshEndpointBinding, now time.Time, window time.Duration) bool {
	if binding.EndpointID != endpointID || (!s.EndpointRevoked[endpointID] && binding.ExpiresAt.After(now)) {
		return false
	}
	// A live root may rotate an endpoint only after evidence attributable to
	// that generation has crossed the recovery horizon.  In particular, an
	// expired but otherwise unused endpoint has no trustworthy terminal clock:
	// treating its zero timestamp as a compaction error would make an unrelated
	// later CAS unavailable, while treating it as elapsed would erase replay
	// evidence prematurely.  A fully closed root supplies a root terminal clock
	// for that special case.
	if rootHasLegacyReplayEvidence(s, binding.RootRunID) {
		return false
	}
	terminalAt := endpointCompactionTerminalAt(s, binding, now)
	if terminalAt.IsZero() || now.Sub(terminalAt) < window {
		return false
	}
	for _, proposal := range s.Proposals {
		if proposalOwnedBy(proposal, binding) && !terminalSubtreeEligible(s, proposal.RunID, now, window) {
			return false
		}
	}
	for _, receipt := range s.SendReceipts {
		if receipt.CallerEndpointID == endpointID && receipt.CallerGeneration == binding.Generation && !terminalSubtreeEligible(s, receipt.TargetRunID, now, window) {
			return false
		}
		if receipt.CallerEndpointID == endpointID && receipt.CallerGeneration == binding.Generation && receipt.State != "sent" {
			return false
		}
	}
	for _, receipt := range s.CancelReceipts {
		if receipt.CallerEndpointID == endpointID && receipt.CallerGeneration == binding.Generation && (!terminalSubtreeEligible(s, receipt.TargetRunID, now, window) || receipt.State != "cancelled") {
			return false
		}
	}
	return true
}

func terminalSubtreeEligible(s Snapshot, runID string, now time.Time, window time.Duration) bool {
	run, ok := s.Runs[runID]
	if !ok || !run.State.terminal() || run.State == RunUncertain || run.TerminalAt.IsZero() || now.Sub(run.TerminalAt) < window {
		return false
	}
	for _, child := range s.Runs {
		if child.ParentRunID == runID && !terminalSubtreeEligible(s, child.ID, now, window) {
			return false
		}
	}
	return true
}

func compactEndpointGeneration(s *Snapshot, endpointID string, binding MeshEndpointBinding, now time.Time, policy RetentionPolicy) error {
	if s == nil || !endpointEligibleForCompaction(*s, endpointID, binding, now, policy.RecoveryWindow) {
		return ErrUnavailable
	}
	scope := endpointGenerationScope(endpointID, binding.Generation)
	t := JournalTombstone{
		SchemaVersion: JournalTombstoneV1,
		Domain:        "endpoint_generation",
		Scope:         scope,
		Digest:        rootReplayCommitment(*s, binding),
		RootRunID:     binding.RootRunID,
		EndpointID:    endpointID,
		Generation:    binding.Generation,
		Revoked:       true,
		TerminalAt:    endpointCompactionTerminalAt(*s, binding, now),
		ExpiresAt:     now.Add(policy.TombstoneWindow),
	}
	if t.TerminalAt.IsZero() {
		return ErrUnavailable
	}
	t.Commitment = journalTombstoneCommitment(t)
	s.Tombstones[journalTombstoneLookupKey(t.Domain, t.Scope)] = t
	for key, proposal := range s.Proposals {
		if proposalOwnedBy(proposal, binding) {
			delete(s.NonceScopes, proposal.Scope)
			delete(s.Proposals, key)
		}
	}
	for key, batch := range s.Batches {
		for _, proposalKey := range batch.ProposalKeys {
			if _, ok := s.Proposals[proposalKey]; !ok {
				delete(s.Batches, key)
				break
			}
		}
	}
	for key := range s.EndpointNonces {
		bound, generation, _, ok := endpointNonceReference(key, s.EndpointBindings)
		if ok && bound.EndpointID == endpointID && generation == binding.Generation {
			delete(s.EndpointNonces, key)
		}
	}
	for key, receipt := range s.SendReceipts {
		if receipt.CallerEndpointID == endpointID && receipt.CallerGeneration == binding.Generation {
			delete(s.SendReceipts, key)
		}
	}
	for key, receipt := range s.CancelReceipts {
		if receipt.CallerEndpointID == endpointID && receipt.CallerGeneration == binding.Generation {
			delete(s.CancelReceipts, key)
		}
	}
	delete(s.EndpointBindings, endpointID)
	delete(s.EndpointRevoked, endpointID)
	return nil
}

func latestEndpointTerminalAt(s Snapshot, binding MeshEndpointBinding) time.Time {
	latest := time.Time{}
	for _, proposal := range s.Proposals {
		if proposalOwnedBy(proposal, binding) {
			if run, ok := s.Runs[proposal.RunID]; ok && run.TerminalAt.After(latest) {
				latest = run.TerminalAt
			}
		}
	}
	for _, receipt := range s.SendReceipts {
		if receipt.CallerEndpointID == binding.EndpointID && receipt.CallerGeneration == binding.Generation {
			if run, ok := s.Runs[receipt.TargetRunID]; ok && run.TerminalAt.After(latest) {
				latest = run.TerminalAt
			}
		}
	}
	for _, receipt := range s.CancelReceipts {
		if receipt.CallerEndpointID == binding.EndpointID && receipt.CallerGeneration == binding.Generation {
			if run, ok := s.Runs[receipt.TargetRunID]; ok && run.TerminalAt.After(latest) {
				latest = run.TerminalAt
			}
		}
	}
	return latest
}

func endpointCompactionTerminalAt(s Snapshot, binding MeshEndpointBinding, now time.Time) time.Time {
	if terminalAt := latestEndpointTerminalAt(s, binding); !terminalAt.IsZero() {
		return terminalAt
	}
	// With no directly attributable effect, the only safe clock is a verified
	// closed root. Pure retention never closes a root itself.
	if rootEligibleForCompaction(s, binding.RootRunID, now, 0) {
		return rootTerminalAt(s, binding.RootRunID)
	}
	return time.Time{}
}

// rootHasLegacyReplayEvidence deliberately blocks compaction of pre-schema
// records. Their endpoint generation is not authenticated in the journal, so
// assigning them to any one endpoint during retention would weaken replay
// denial. A later migration may provide an explicit authenticated mapping;
// until then the durable evidence is retained.
func rootHasLegacyReplayEvidence(s Snapshot, rootID string) bool {
	for _, proposal := range s.Proposals {
		if proposalRoot(s, proposal) == rootID && (proposal.CallerEndpointID == "" || proposal.CallerGeneration == 0 || proposal.RootRunID == "") {
			return true
		}
	}
	for _, receipt := range s.SendReceipts {
		if receiptRoot(s, receipt.TargetRunID) == rootID && (receipt.CallerEndpointID == "" || receipt.CallerGeneration == 0) {
			return true
		}
	}
	for _, receipt := range s.CancelReceipts {
		if receiptRoot(s, receipt.TargetRunID) == rootID && (receipt.CallerEndpointID == "" || receipt.CallerGeneration == 0) {
			return true
		}
	}
	return false
}

func markLegacyTerminalHorizon(s *Snapshot, rootID string, now time.Time) bool {
	if s == nil {
		return false
	}
	changed := false
	for id, run := range s.Runs {
		if run.RootID == rootID && run.State.terminal() && run.TerminalAt.IsZero() {
			run.TerminalAt = now
			s.Runs[id] = run
			changed = true
		}
	}
	return changed
}

func roots(s Snapshot) map[string]struct{} {
	result := make(map[string]struct{}, len(s.Runs))
	for _, run := range s.Runs {
		result[run.RootID] = struct{}{}
	}
	return result
}

func rootEligibleForCompaction(s Snapshot, rootID string, now time.Time, window time.Duration) bool {
	if rootHasLegacyReplayEvidence(s, rootID) {
		return false
	}
	seen := false
	for _, run := range s.Runs {
		if run.RootID != rootID {
			continue
		}
		seen = true
		if !run.State.terminal() || run.State == RunUncertain || run.ControlFence != "" {
			return false
		}
		if run.TerminalAt.IsZero() || now.Sub(run.TerminalAt) < window {
			return false
		}
	}
	if !seen {
		return false
	}
	for endpointID, binding := range s.EndpointBindings {
		if binding.RootRunID == rootID && !s.EndpointRevoked[endpointID] && binding.ExpiresAt.After(now) {
			return false
		}
	}
	for _, proposal := range s.Proposals {
		if proposalRoot(s, proposal) == rootID && proposal.State != "terminal" {
			return false
		}
	}
	for _, batch := range s.Batches {
		if batchRoot(s, batch) == rootID && (batch.State == "pending" || batch.State == "uncertain") {
			return false
		}
	}
	for _, receipt := range s.SendReceipts {
		if receiptRoot(s, receipt.TargetRunID) == rootID && receipt.State != "sent" {
			return false
		}
	}
	for _, receipt := range s.CancelReceipts {
		if receiptRoot(s, receipt.TargetRunID) == rootID && receipt.State != "cancelled" {
			return false
		}
	}
	return true
}

func compactRoot(s *Snapshot, rootID string, now time.Time, policy RetentionPolicy) error {
	if s == nil || !rootEligibleForCompaction(*s, rootID, now, policy.RecoveryWindow) {
		return ErrUnavailable
	}
	retired := make(map[string]MeshEndpointBinding)
	for endpointID, binding := range s.EndpointBindings {
		if binding.RootRunID == rootID {
			retired[endpointID] = binding
		}
	}
	terminalAt := rootTerminalAt(*s, rootID)
	for endpointID, binding := range retired {
		scope := endpointGenerationScope(endpointID, binding.Generation)
		t := JournalTombstone{
			SchemaVersion: JournalTombstoneV1,
			Domain:        "endpoint_generation",
			Scope:         scope,
			Digest:        rootReplayCommitment(*s, binding),
			RootRunID:     rootID,
			EndpointID:    endpointID,
			Generation:    binding.Generation,
			Revoked:       true,
			TerminalAt:    terminalAt,
			ExpiresAt:     now.Add(policy.TombstoneWindow),
		}
		t.Commitment = journalTombstoneCommitment(t)
		s.Tombstones[journalTombstoneLookupKey(t.Domain, t.Scope)] = t
	}
	// Resolve every root association before removing Runs; validation of the
	// compacted candidate must never depend on already-deleted live records.
	proposalKeys := make(map[string]struct{})
	for key, proposal := range s.Proposals {
		if proposalRoot(*s, proposal) == rootID {
			proposalKeys[key] = struct{}{}
			delete(s.NonceScopes, proposal.Scope)
		}
	}
	batchKeys := make(map[string]struct{})
	for key, batch := range s.Batches {
		if batchRoot(*s, batch) == rootID {
			batchKeys[key] = struct{}{}
		}
	}
	for key, receipt := range s.SendReceipts {
		if receiptRoot(*s, receipt.TargetRunID) == rootID {
			delete(s.SendReceipts, key)
		}
	}
	for key, receipt := range s.CancelReceipts {
		if receiptRoot(*s, receipt.TargetRunID) == rootID {
			delete(s.CancelReceipts, key)
		}
	}
	for key := range s.EndpointNonces {
		bound, generation, _, ok := endpointNonceReference(key, s.EndpointBindings)
		if !ok {
			return ErrUnavailable
		}
		for endpointID, binding := range retired {
			if bound.EndpointID == endpointID && generation == binding.Generation {
				delete(s.EndpointNonces, key)
				break
			}
		}
	}
	for key := range proposalKeys {
		delete(s.Proposals, key)
	}
	for key := range batchKeys {
		delete(s.Batches, key)
	}
	for endpointID := range retired {
		delete(s.EndpointBindings, endpointID)
		delete(s.EndpointRevoked, endpointID)
	}
	for id, run := range s.Runs {
		if run.RootID == rootID {
			delete(s.Runs, id)
			delete(s.Disclosures, id)
		}
	}
	filtered := s.Events[:0]
	for _, event := range s.Events {
		if event.RootRunID != rootID {
			filtered = append(filtered, event)
		}
	}
	s.Events = filtered
	return nil
}

func rootTerminalAt(s Snapshot, rootID string) time.Time {
	var latest time.Time
	for _, run := range s.Runs {
		if run.RootID == rootID && run.TerminalAt.After(latest) {
			latest = run.TerminalAt
		}
	}
	return latest
}

func proposalRoot(s Snapshot, proposal ProposalRecord) string {
	run, ok := s.Runs[proposal.RunID]
	if !ok {
		return ""
	}
	return run.RootID
}

func batchRoot(s Snapshot, batch BatchRecord) string {
	for _, key := range batch.ProposalKeys {
		if proposal, ok := s.Proposals[key]; ok {
			return proposalRoot(s, proposal)
		}
	}
	return ""
}

func receiptRoot(s Snapshot, runID string) string {
	run, ok := s.Runs[runID]
	if !ok {
		return ""
	}
	return run.RootID
}

func rootReplayCommitment(s Snapshot, binding MeshEndpointBinding) string {
	items := make([]string, 0)
	for _, proposal := range s.Proposals {
		if proposalOwnedBy(proposal, binding) {
			items = append(items, "proposal:"+proposal.Scope+":"+proposal.Digest)
		}
	}
	for key, receipt := range s.SendReceipts {
		if receipt.CallerEndpointID == binding.EndpointID && receipt.CallerGeneration == binding.Generation {
			items = append(items, "send:"+key+":"+receipt.Digest)
		}
	}
	for key, receipt := range s.CancelReceipts {
		if receipt.CallerEndpointID == binding.EndpointID && receipt.CallerGeneration == binding.Generation {
			items = append(items, "cancel:"+key+":"+receipt.Digest)
		}
	}
	sort.Strings(items)
	return hash("openduck.mesh.retired-endpoint-replay.v1\n" + strings.Join(items, "\n"))
}

func proposalOwnedBy(proposal ProposalRecord, binding MeshEndpointBinding) bool {
	return proposal.CallerEndpointID == binding.EndpointID && proposal.CallerGeneration == binding.Generation && proposal.RootRunID == binding.RootRunID
}
