package mesh

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestRetentionMigrationEventCommitsAndReloads(t *testing.T) {
	t.Parallel()
	key := bytes.Repeat([]byte{0x6a}, 32)
	path := filepath.Join(t.TempDir(), "mesh.enc")
	repo, err := NewEncryptedFileRepository(path, key)
	if err != nil {
		t.Fatal(err)
	}
	old, err := repo.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	migratedAt := time.Date(2026, 8, 26, 10, 0, 0, 0, time.UTC)
	next, err := MigrateV1(hash("legacy-snapshot"), migratedAt)
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.CompareAndSwap(context.Background(), old, next); err != nil {
		t.Fatalf("normal migration CAS: %v", err)
	}
	if err := repo.Close(); err != nil {
		t.Fatal(err)
	}
	reloaded, err := NewEncryptedFileRepository(path, key)
	if err != nil {
		t.Fatal(err)
	}
	got, err := reloaded.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got.Version != 1 || len(got.Events) != 1 || got.Events[0].Event != "legacy_v1_migrated" || got.Events[0].RootRunID != "" {
		t.Fatalf("migration/reload lost global audit event: %#v", got)
	}
}

func TestRetentionNormalAdmissionReservesEndpointCapacityForSafety(t *testing.T) {
	c, binding, _, repo, _ := setup(t, testProfile(true))
	_ = c // setup creates the authenticated root and endpoint binding.
	policy := defaultRetentionPolicy()
	policy.MaxEntries = 64
	policy.SafetyReserveEntries = 2
	policy.MaxEntriesPerEndpoint = 4
	policy.MaxEntriesPerRoot = 16
	repo.mu.Lock()
	repo.policy = policy
	repo.mu.Unlock()

	old, err := repo.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	first := old.clone()
	first.EndpointNonces[endpointNonceKey(binding, "retention-nonce-1")] = true
	if err := repo.CompareAndSwap(context.Background(), old, first); err != nil {
		t.Fatalf("normal admission before reserve: %v", err)
	}
	prepared, err := repo.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	second := prepared.clone()
	second.EndpointNonces[endpointNonceKey(binding, "retention-nonce-2")] = true
	if err := repo.CompareAndSwap(context.Background(), prepared, second); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("normal admission consumed endpoint safety reserve: %v", err)
	}
	afterRejected, err := repo.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if afterRejected.Version != prepared.Version || afterRejected.EndpointNonces[endpointNonceKey(binding, "retention-nonce-2")] {
		t.Fatalf("rejected retention preflight partially mutated journal: %+v", afterRejected)
	}
	if err := repo.CompareAndSwapSafety(context.Background(), prepared, second); err != nil {
		t.Fatalf("closed safety CAS could not use reserved endpoint capacity: %v", err)
	}
	got, err := repo.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !got.EndpointNonces[endpointNonceKey(binding, "retention-nonce-2")] {
		t.Fatal("safety CAS did not persist its bounded mutation")
	}
}

func TestRetentionPolicyRejectsUnsafeLocalReserve(t *testing.T) {
	p := defaultRetentionPolicy()
	p.SafetyReserveEntries = 1
	if err := p.Validate(); !errors.Is(err, ErrInvalidContract) {
		t.Fatalf("unsafe single-entry reserve accepted: %v", err)
	}
	p = defaultRetentionPolicy()
	p.MaxEntriesPerEndpoint = 1
	if err := p.Validate(); !errors.Is(err, ErrInvalidContract) {
		t.Fatalf("endpoint cap without safety headroom accepted: %v", err)
	}
}

func TestRetentionChargesNonceScopeAndBatchEnvelopeToCallerGeneration(t *testing.T) {
	binding := MeshEndpointBinding{EndpointID: "endpoint-1", RootRunID: "root-1", Generation: 1}
	s := emptySnapshot()
	s.Runs["root-1"] = Run{ID: "root-1", RootID: "root-1"}
	s.Runs["child-1"] = Run{ID: "child-1", RootID: "root-1"}
	s.Runs["child-2"] = Run{ID: "child-2", RootID: "root-1"}
	s.EndpointBindings[binding.EndpointID] = binding
	for i, runID := range []string{"child-1", "child-2"} {
		key := "proposal-" + string(rune('1'+i))
		scope := "scope-" + string(rune('1'+i))
		s.Proposals[key] = ProposalRecord{Key: key, Scope: scope, RunID: runID, RootRunID: "root-1", CallerEndpointID: binding.EndpointID, CallerGeneration: binding.Generation}
		s.NonceScopes[scope] = key
	}
	s.Batches["batch-1"] = BatchRecord{Key: "batch-1", ProposalKeys: []string{"proposal-1", "proposal-2"}}

	p := defaultRetentionPolicy()
	p.MaxEntries = 128
	p.SafetyReserveEntries = 2
	p.MaxEntriesPerEndpoint = 8 // binding + 2 proposals + 2 scopes + batch = 6; normal cap is 6.
	p.MaxEntriesPerRoot = 32
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	if err := journalEntryBudget(s, p, journalMutationNormal); err != nil {
		t.Fatalf("exact normal caller accounting rejected: %v", err)
	}
	s.EndpointNonces[endpointNonceKey(binding, "extra-nonce")] = true
	if err := journalEntryBudget(s, p, journalMutationNormal); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("nonce-scope/batch local budget bypassed: %v", err)
	}
}

func TestRetentionRejectsOrphanNonceScopeBeforePersistence(t *testing.T) {
	s := emptySnapshot()
	s.NonceScopes["orphan-scope"] = "missing-proposal"
	p := defaultRetentionPolicy()
	if err := journalEntryBudget(s, p, journalMutationSafety); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("orphan nonce scope accepted into bounded journal: %v", err)
	}
}

func TestRetentionGCMSealedBudgetUsesExactOnDiskLength(t *testing.T) {
	key := bytes.Repeat([]byte{0x19}, 32)
	repo, err := NewEncryptedFileRepository(filepath.Join(t.TempDir(), "mesh.enc"), key)
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	s := emptySnapshot()
	// This function tests the size contract rather than the snapshot schema.
	// A large bounded field makes a non-trivial AES-GCM boundary without
	// broadening any persisted contract.
	s.Events = append(s.Events, MeshEvent{ErrorCode: string(bytes.Repeat([]byte{'x'}, 900))})
	plain, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := repo.seal(plain)
	if err != nil {
		t.Fatal(err)
	}
	if len(sealed) != sealedJournalBytes(len(plain)) {
		t.Fatalf("sealed size=%d, policy size=%d", len(sealed), sealedJournalBytes(len(plain)))
	}
	p := defaultRetentionPolicy()
	p.MaxSealedBytes = len(sealed) + 16
	p.SafetyReserveBytes = 16
	p.MaxEntries = 128
	p.SafetyReserveEntries = 2
	p.MaxEntriesPerRoot = 128
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	if err := sealedSnapshotBudget(s, p, journalMutationNormal); err != nil {
		t.Fatalf("exact normal GCM boundary rejected: %v", err)
	}
	p.MaxSealedBytes--
	if err := sealedSnapshotBudget(s, p, journalMutationNormal); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("normal GCM reserve boundary accepted: %v", err)
	}
}

func TestRetentionCompactsClosedRootToBoundedGenerationTombstoneAcrossReload(t *testing.T) {
	key := bytes.Repeat([]byte{0x31}, 32)
	path := filepath.Join(t.TempDir(), "mesh.enc")
	now := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
	p := defaultRetentionPolicy()
	p.RecoveryWindow = time.Hour
	p.TombstoneWindow = 2 * time.Hour
	repo, err := NewEncryptedFileRepositoryWithRetention(path, key, p)
	if err != nil {
		t.Fatal(err)
	}
	repo.now = func() time.Time { return now }
	directory, err := NewStaticDirectory(testProfile(true))
	if err != nil {
		t.Fatal(err)
	}
	endpoints, err := NewPersistentEndpointAuthorizer(repo)
	if err != nil {
		t.Fatal(err)
	}
	ids := &sequenceIDs{}
	coordinator, err := NewCoordinator(CoordinatorOptions{
		Repository: repo, Directory: directory, Starter: &fakeStarter{}, Sessions: &fakeSessions{}, Endpoints: endpoints,
		Clock: func() time.Time { return now.Add(-3 * time.Hour) }, ID: ids.Next, PolicyVersion: "retention-policy", BatchCaps: limits(),
	})
	if err != nil {
		t.Fatal(err)
	}
	binding, err := coordinator.RegisterRoot(context.Background(), "root-1", "session-root", "attempt-root", "peer-root", "L1", "workspace-1")
	if err != nil {
		t.Fatal(err)
	}
	old, err := repo.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	next := old.clone()
	root := next.Runs["root-1"]
	root.State = RunCompleted
	root.TerminalAt = now.Add(-2 * time.Hour)
	next.Runs[root.ID] = root
	next.EndpointRevoked[binding.EndpointID] = true
	if err := repo.CompareAndSwapSafety(context.Background(), old, next); err != nil {
		t.Fatalf("terminal root compaction: %v", err)
	}
	compacted, err := repo.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(compacted.Runs) != 0 || len(compacted.EndpointBindings) != 0 {
		t.Fatalf("closed root not compacted: %+v", compacted)
	}
	scope := endpointGenerationScope(binding.EndpointID, binding.Generation)
	tombstone, ok := tombstoneFor(compacted, "endpoint_generation", scope)
	if !ok || tombstone.EndpointID != binding.EndpointID || tombstone.Generation != binding.Generation || !tombstone.Revoked {
		t.Fatalf("missing exact retired-generation tombstone: %+v", compacted.Tombstones)
	}
	if err := repo.Close(); err != nil {
		t.Fatal(err)
	}
	reloaded, err := NewEncryptedFileRepositoryWithRetention(path, key, p)
	if err != nil {
		t.Fatal(err)
	}
	defer reloaded.Close()
	reloaded.now = func() time.Time { return now.Add(3 * time.Hour) }
	afterRestart, err := reloaded.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := tombstoneFor(afterRestart, "endpoint_generation", scope); !ok {
		t.Fatal("crash/reload lost retired-generation denial evidence")
	}
	if err := reloaded.CompareAndSwap(context.Background(), afterRestart, afterRestart.clone()); err != nil {
		t.Fatalf("expired tombstone cleanup CAS: %v", err)
	}
	bounded, err := reloaded.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(bounded.Tombstones) != 0 {
		t.Fatalf("expired tombstone remained unbounded: %+v", bounded.Tombstones)
	}
}

func TestRetentionRetainsUncertainRootAndBlocksAdmissionAfterRestart(t *testing.T) {
	key := bytes.Repeat([]byte{0x32}, 32)
	path := filepath.Join(t.TempDir(), "mesh.enc")
	now := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
	p := defaultRetentionPolicy()
	p.RecoveryWindow = time.Hour
	p.TombstoneWindow = 2 * time.Hour
	repo, err := NewEncryptedFileRepositoryWithRetention(path, key, p)
	if err != nil {
		t.Fatal(err)
	}
	repo.now = func() time.Time { return now }
	directory, err := NewStaticDirectory(testProfile(true))
	if err != nil {
		t.Fatal(err)
	}
	endpoints, err := NewPersistentEndpointAuthorizer(repo)
	if err != nil {
		t.Fatal(err)
	}
	ids := &sequenceIDs{}
	clock := func() time.Time { return now.Add(-3 * time.Hour) }
	coordinator, err := NewCoordinator(CoordinatorOptions{
		Repository: repo, Directory: directory, Starter: &fakeStarter{}, Sessions: &fakeSessions{}, Endpoints: endpoints,
		Clock: clock, ID: ids.Next, PolicyVersion: "retention-policy", BatchCaps: limits(),
	})
	if err != nil {
		t.Fatal(err)
	}
	binding, err := coordinator.RegisterRoot(context.Background(), "root-1", "session-root", "attempt-root", "peer-root", "L1", "workspace-1")
	if err != nil {
		t.Fatal(err)
	}
	old, err := repo.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	next := old.clone()
	root := next.Runs["root-1"]
	root.State = RunUncertain
	root.TerminalAt = now.Add(-2 * time.Hour)
	next.Runs[root.ID] = root
	next.EndpointRevoked[binding.EndpointID] = true
	if err := repo.CompareAndSwapSafety(context.Background(), old, next); err != nil {
		t.Fatalf("persist uncertain root: %v", err)
	}
	retained, err := repo.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if retained.Runs["root-1"].State != RunUncertain || len(retained.EndpointBindings) != 1 || len(retained.Tombstones) != 0 {
		t.Fatalf("retention erased uncertainty after recovery horizon: %+v", retained)
	}
	if err := repo.Close(); err != nil {
		t.Fatal(err)
	}
	reloaded, err := NewEncryptedFileRepositoryWithRetention(path, key, p)
	if err != nil {
		t.Fatal(err)
	}
	defer reloaded.Close()
	reloaded.now = func() time.Time { return now.Add(24 * time.Hour) }
	reloadedEndpoints, err := NewPersistentEndpointAuthorizer(reloaded)
	if err != nil {
		t.Fatal(err)
	}
	restarted, err := NewCoordinator(CoordinatorOptions{
		Repository: reloaded, Directory: directory, Starter: &fakeStarter{}, Sessions: &fakeSessions{}, Endpoints: reloadedEndpoints,
		Clock: reloaded.now, ID: (&sequenceIDs{}).Next, PolicyVersion: "retention-policy", BatchCaps: limits(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := restarted.RegisterRoot(context.Background(), "root-2", "session-2", "attempt-2", "peer-2", "L1", "workspace-1"); !errors.Is(err, ErrRepositoryPoisoned) {
		t.Fatalf("restart admitted work after retained uncertain native effect: %v", err)
	}
}
