package mesh

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEncryptedRepositoryPersistsAndReloads(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, 32)
	path := filepath.Join(t.TempDir(), "mesh.enc")
	repo, err := NewEncryptedFileRepository(path, key)
	if err != nil {
		t.Fatal(err)
	}
	old, err := repo.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	next := old.clone()
	next.Runs["root-1"] = Run{ID: "root-1", RootID: "root-1", SessionID: "session-1", AttemptID: "attempt-1", Classification: "L1", WorkspaceGroupID: "workspace-1", State: RunRunning, CreatedAt: time.Now().UTC()}
	if err := repo.CompareAndSwap(context.Background(), old, next); err != nil {
		t.Fatal(err)
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
	if got.Version != 1 || got.Runs["root-1"].RootID != "root-1" {
		t.Fatalf("reload lost journal: %#v", got)
	}
	plain, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(plain, []byte("root-1")) {
		t.Fatal("journal persisted plaintext")
	}
}
func TestEncryptedRepositoryRejectsCorruptionAndConflictingCAS(t *testing.T) {
	key := bytes.Repeat([]byte{0x13}, 32)
	path := filepath.Join(t.TempDir(), "mesh.enc")
	repo, err := NewEncryptedFileRepository(path, key)
	if err != nil {
		t.Fatal(err)
	}
	old, err := repo.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	next := old.clone()
	next.Runs["root-1"] = Run{ID: "root-1", RootID: "root-1", SessionID: "session-1", AttemptID: "attempt-1", Classification: "L1", WorkspaceGroupID: "workspace-1", State: RunRunning, CreatedAt: time.Now().UTC()}
	if err = repo.CompareAndSwap(context.Background(), old, next); err != nil {
		t.Fatal(err)
	}
	if err = repo.CompareAndSwap(context.Background(), old, next); !errors.Is(err, ErrVersionConflict) {
		t.Fatalf("stale CAS=%v", err)
	}
	if err = os.WriteFile(path, []byte("corrupt"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = repo.Load(context.Background()); !errors.Is(err, ErrRepositoryCorrupt) {
		t.Fatalf("corruption=%v", err)
	}
}
func TestEncryptedRepositoryCommitUncertainDoesNotClaimSuccess(t *testing.T) {
	key := bytes.Repeat([]byte{0x07}, 32)
	path := filepath.Join(t.TempDir(), "mesh.enc")
	repo, err := NewEncryptedFileRepositoryWithPersister(path, key, func(string, []byte) error { return ErrCommitUncertain })
	if err != nil {
		t.Fatal(err)
	}
	old, err := repo.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	next := old.clone()
	next.Runs["root-1"] = Run{ID: "root-1", RootID: "root-1", SessionID: "session-1", AttemptID: "attempt-1", Classification: "L1", WorkspaceGroupID: "workspace-1", State: RunRunning, CreatedAt: time.Now().UTC()}
	if err = repo.CompareAndSwap(context.Background(), old, next); !errors.Is(err, ErrCommitUncertain) {
		t.Fatalf("uncertain=%v", err)
	}
}

func TestEncryptedRepositoryMigratesLegacySnapshotWithoutCancelReceipts(t *testing.T) {
	key := bytes.Repeat([]byte{0x51}, 32)
	path := filepath.Join(t.TempDir(), "mesh.enc")
	repo, err := NewEncryptedFileRepository(path, key)
	if err != nil {
		t.Fatal(err)
	}
	legacy, err := repo.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	plain, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	// A mesh-snapshot.v2 journal written before CancelReceipt deliberately has
	// no field at all. Keep strict decoding for every other field and exercise
	// the explicit additive normalization path rather than accepting an
	// arbitrary map shape.
	plain = bytes.Replace(plain, []byte(`,"CancelReceipts":{}`), nil, 1)
	if bytes.Contains(plain, []byte(`"CancelReceipts"`)) {
		t.Fatalf("legacy fixture still carries new map: %s", plain)
	}
	sealed, err := repo.seal(plain)
	if err != nil {
		t.Fatal(err)
	}
	if err = repo.Close(); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, sealed, 0600); err != nil {
		t.Fatal(err)
	}
	reloaded, err := NewEncryptedFileRepository(path, key)
	if err != nil {
		t.Fatalf("legacy v2 snapshot rejected: %v", err)
	}
	got, err := reloaded.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got.CancelReceipts == nil || len(got.CancelReceipts) != 0 || got.SchemaVersion != SnapshotV2 {
		t.Fatalf("legacy cancel-receipt migration=%#v", got)
	}
}

func TestEncryptedRepositoryMigratesPreRetentionSnapshotWithoutTombstones(t *testing.T) {
	key := bytes.Repeat([]byte{0x52}, 32)
	path := filepath.Join(t.TempDir(), "mesh.enc")
	repo, err := NewEncryptedFileRepository(path, key)
	if err != nil {
		t.Fatal(err)
	}
	legacy, err := repo.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	plain, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	plain = bytes.Replace(plain, []byte(`,"Tombstones":{}`), nil, 1)
	if bytes.Contains(plain, []byte(`"Tombstones"`)) {
		t.Fatalf("legacy fixture still carries retention map: %s", plain)
	}
	sealed, err := repo.seal(plain)
	if err != nil {
		t.Fatal(err)
	}
	if err = repo.Close(); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, sealed, 0600); err != nil {
		t.Fatal(err)
	}
	reloaded, err := NewEncryptedFileRepository(path, key)
	if err != nil {
		t.Fatalf("pre-retention snapshot rejected: %v", err)
	}
	defer reloaded.Close()
	got, err := reloaded.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got.Tombstones == nil || len(got.Tombstones) != 0 || got.SchemaVersion != SnapshotV2 {
		t.Fatalf("pre-retention migration=%#v", got)
	}
}

func writeLegacySendReceiptFixture(t *testing.T, state, digestOverride string) (*EncryptedFileRepository, *Coordinator, *fakeSessions, OperationRequest, string) {
	t.Helper()
	key := bytes.Repeat([]byte{0x66}, 32)
	path := filepath.Join(t.TempDir(), "mesh.enc")
	repo, err := NewEncryptedFileRepository(path, key)
	if err != nil {
		t.Fatal(err)
	}
	directory, err := NewStaticDirectory(testProfile(true))
	if err != nil {
		t.Fatal(err)
	}
	endpoints, err := NewPersistentEndpointAuthorizer(repo)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 26, 0, 0, 0, 0, time.UTC)
	writerSessions := &fakeSessions{}
	writer, err := NewCoordinator(CoordinatorOptions{Repository: repo, Directory: directory, Starter: &fakeStarter{}, Sessions: writerSessions, Endpoints: endpoints, Clock: func() time.Time { return now }, ID: (&sequenceIDs{}).Next, PolicyVersion: "legacy-fixture", BatchCaps: limits()})
	if err != nil {
		t.Fatal(err)
	}
	binding, err := writer.RegisterRoot(context.Background(), "root-1", "session-root", "attempt-root", "peer-1", "L1", "workspace-1")
	if err != nil {
		t.Fatal(err)
	}
	child, err := writer.ProposeSpawn(context.Background(), request(binding, proposal(), "legacy-fixture-spawn"))
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := repo.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	inputRef := "input-1"
	legacy := snapshot.clone()
	legacyReceipt := SendReceipt{CallerRunID: child.RunID, TargetRunID: child.RunID, InputRef: inputRef, Digest: legacySendReceiptDigest(child.RunID, "send", inputRef), State: state}
	if digestOverride != "" {
		legacyReceipt.Digest = digestOverride
	}
	legacy.SendReceipts["send:"+binding.EndpointID+":"+child.RunID+":"+inputRef] = legacyReceipt
	plain, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(plain, []byte(`"RevisionRef":"input-1"`)) || bytes.Contains(plain, []byte(`"InputRef"`)) {
		t.Fatalf("legacy receipt wire compatibility lost: %s", plain)
	}
	sealed, err := repo.seal(plain)
	if err != nil {
		t.Fatal(err)
	}
	if err = repo.Close(); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, sealed, 0600); err != nil {
		t.Fatal(err)
	}
	reloaded, err := NewEncryptedFileRepository(path, key)
	if err != nil {
		t.Fatal(err)
	}
	reloadedEndpoints, err := NewPersistentEndpointAuthorizer(reloaded)
	if err != nil {
		t.Fatal(err)
	}
	sessions := &fakeSessions{}
	coordinator, err := NewCoordinator(CoordinatorOptions{Repository: reloaded, Directory: directory, Starter: &fakeStarter{}, Sessions: sessions, Endpoints: reloadedEndpoints, Clock: func() time.Time { return now }, ID: (&sequenceIDs{}).Next, PolicyVersion: "legacy-fixture", BatchCaps: limits()})
	if err != nil {
		t.Fatal(err)
	}
	req := OperationRequest{Target: TargetRequest{Endpoint: EndpointRequest{EndpointID: binding.EndpointID, PeerID: binding.PeerID, Audience: "mesh", Nonce: "legacy-replay"}, TargetRunID: child.RunID, Operation: "send"}, InputRef: inputRef}
	canonical, err := req.Digest()
	if err != nil {
		t.Fatal(err)
	}
	req.Target.Endpoint.MessageDigest = canonical
	return reloaded, coordinator, sessions, req, canonical
}

func TestEncryptedLegacySendReceiptMigratesSentAndFailsClosedAmbiguous(t *testing.T) {
	for _, state := range []string{"sent", "pending", "failed"} {
		t.Run(state, func(t *testing.T) {
			repo, coordinator, sessions, req, _ := writeLegacySendReceiptFixture(t, state, "")
			if repo == nil {
				t.Fatal("valid legacy encrypted journal did not reload")
			}
			if state == "sent" {
				if err := coordinator.ReloadAndReplay(context.Background()); err != nil {
					t.Fatalf("explicit route recovery failed: %v", err)
				}
			}
			err := coordinator.Send(context.Background(), req)
			if sessions.sends != 0 {
				t.Fatalf("legacy %s receipt re-dispatched provider input", state)
			}
			if state != "sent" {
				// A persisted ambiguous receipt has no native-route recovery proof
				// after restart. NewCoordinator therefore poisons admission rather
				// than migrating and guessing whether the provider observed input.
				if !errors.Is(err, ErrRepositoryPoisoned) {
					t.Fatalf("%s legacy replay was not fail-closed: %v", state, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("sent legacy replay=%v", err)
			}
			snapshot, err := repo.Load(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			binding := snapshot.EndpointBindings[req.Target.Endpoint.EndpointID]
			receipt := snapshot.SendReceipts[inputReceiptKey(binding, req.Target.TargetRunID, "send", req.InputRef)]
			if receipt.Digest != inputReceiptDigest(binding, req.Target.TargetRunID, "send", req.InputRef) || receipt.CallerEndpointID != binding.EndpointID || receipt.CallerGeneration != binding.Generation || receipt.CallerRunID != binding.RunID || receipt.Operation != "send" {
				t.Fatalf("legacy receipt was not one-way migrated: %+v", receipt)
			}
		})
	}
}

func TestEncryptedRepositoryRejectsForgedLegacySendReceipt(t *testing.T) {
	key := bytes.Repeat([]byte{0x66}, 32)
	path := filepath.Join(t.TempDir(), "mesh.enc")
	// Build the encrypted old-wire fixture directly so the loader, not a
	// current-schema CAS, decides whether it is admissible.
	repo, err := NewEncryptedFileRepository(path, key)
	if err != nil {
		t.Fatal(err)
	}
	directory, err := NewStaticDirectory(testProfile(true))
	if err != nil {
		t.Fatal(err)
	}
	endpoints, err := NewPersistentEndpointAuthorizer(repo)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 26, 0, 0, 0, 0, time.UTC)
	writer, err := NewCoordinator(CoordinatorOptions{Repository: repo, Directory: directory, Starter: &fakeStarter{}, Sessions: &fakeSessions{}, Endpoints: endpoints, Clock: func() time.Time { return now }, ID: (&sequenceIDs{}).Next, PolicyVersion: "legacy-fixture", BatchCaps: limits()})
	if err != nil {
		t.Fatal(err)
	}
	binding, err := writer.RegisterRoot(context.Background(), "root-1", "session-root", "attempt-root", "peer-1", "L1", "workspace-1")
	if err != nil {
		t.Fatal(err)
	}
	child, err := writer.ProposeSpawn(context.Background(), request(binding, proposal(), "forged-legacy-spawn"))
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := repo.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	snapshot.SendReceipts["send:"+binding.EndpointID+":"+child.RunID+":input-1"] = SendReceipt{CallerRunID: child.RunID, TargetRunID: child.RunID, InputRef: "input-1", Digest: hash("forged-legacy"), State: "sent"}
	plain, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := repo.seal(plain)
	if err != nil {
		t.Fatal(err)
	}
	if err = repo.Close(); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, sealed, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = NewEncryptedFileRepository(path, key); !errors.Is(err, ErrRepositoryCorrupt) {
		t.Fatalf("forged legacy receipt loaded: %v", err)
	}
}

func TestEncryptedRepositoryRejectsUnsafeJournalAndLockMetadata(t *testing.T) {
	key := bytes.Repeat([]byte{0x38}, 32)
	path := filepath.Join(t.TempDir(), "mesh.enc")
	writeJournal := func(t *testing.T) {
		t.Helper()
		repo, err := NewEncryptedFileRepository(path, key)
		if err != nil {
			t.Fatal(err)
		}
		old, err := repo.Load(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		next := old.clone()
		next.Runs["root-1"] = Run{ID: "root-1", RootID: "root-1", SessionID: "session-1", AttemptID: "attempt-1", Classification: "L1", WorkspaceGroupID: "workspace-1", State: RunRunning, CreatedAt: time.Now().UTC()}
		if err = repo.CompareAndSwap(context.Background(), old, next); err != nil {
			t.Fatal(err)
		}
		_ = repo.Close()
	}
	writeJournal(t)
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := NewEncryptedFileRepository(path, key); !errors.Is(err, ErrRepositoryCorrupt) {
		t.Fatalf("permissive journal accepted: %v", err)
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(path, path+".hardlink"); err != nil {
		t.Fatal(err)
	}
	if _, err := NewEncryptedFileRepository(path, key); !errors.Is(err, ErrRepositoryCorrupt) {
		t.Fatalf("multi-link journal accepted: %v", err)
	}
	if err := os.Remove(path + ".hardlink"); err != nil {
		t.Fatal(err)
	}
	repo, err := NewEncryptedFileRepository(path, key)
	if err != nil {
		t.Fatal(err)
	}
	old, err := repo.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(path+".cas.lock", 0644); err != nil {
		t.Fatal(err)
	}
	if err = repo.CompareAndSwap(context.Background(), old, old.clone()); !errors.Is(err, ErrRepositoryCorrupt) {
		t.Fatalf("unsafe lock accepted: %v", err)
	}
}

func TestPersistentEndpointAuthorizerReplaysNonceAndRevoke(t *testing.T) {
	key := bytes.Repeat([]byte{0x21}, 32)
	path := filepath.Join(t.TempDir(), "mesh.enc")
	repo, err := NewEncryptedFileRepository(path, key)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	// Current-schema endpoint bindings must always reference a canonical run.
	// Older fixtures should go through MigrateV1 instead of relying on an orphan
	// bootstrap exception.
	old, err := repo.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	next := old.clone()
	next.Runs["root-1"] = Run{ID: "root-1", RootID: "root-1", SessionID: "session-root", AttemptID: "attempt-root", Classification: "L1", WorkspaceGroupID: "workspace-1", State: RunRunning, CreatedAt: now}
	next.Runs["run-1"] = Run{ID: "run-1", RootID: "root-1", ParentRunID: "root-1", ParentSessionID: "session-root", SessionID: "session-1", AttemptID: "attempt-1", Classification: "L1", WorkspaceGroupID: "workspace-1", Depth: 1, State: RunRunning, CreatedAt: now}
	if err = repo.CompareAndSwap(context.Background(), old, next); err != nil {
		t.Fatal(err)
	}
	auth, err := NewPersistentEndpointAuthorizer(repo)
	if err != nil {
		t.Fatal(err)
	}
	binding := MeshEndpointBinding{SchemaVersion: EndpointBindingV1, EndpointID: "endpoint-1", Audience: "mesh", RootRunID: "root-1", RunID: "run-1", SessionID: "session-1", AttemptID: "attempt-1", AllowedOperations: []string{"status"}, ToolDigest: hash([]string{"status"}), PeerID: "peer-1", PolicyVersion: "policy-1", IssuedAt: now, ExpiresAt: now.Add(time.Hour), Generation: 1}
	if err = auth.Register(binding, now); err != nil {
		t.Fatal(err)
	}
	request := EndpointRequest{EndpointID: binding.EndpointID, PeerID: binding.PeerID, Audience: "mesh", Nonce: "nonce-1", MessageDigest: hash("run-1:status")}
	if _, err = auth.AuthorizeOperation(request, now, "status", request.MessageDigest); err != nil {
		t.Fatal(err)
	}
	if err = repo.Close(); err != nil {
		t.Fatal(err)
	}
	repo, err = NewEncryptedFileRepository(path, key)
	if err != nil {
		t.Fatal(err)
	}
	auth, err = NewPersistentEndpointAuthorizer(repo)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = auth.AuthorizeOperation(request, now, "status", request.MessageDigest); !errors.Is(err, ErrReplay) {
		t.Fatalf("nonce replay after restart=%v", err)
	}
	if err = auth.Revoke(binding.EndpointID); err != nil {
		t.Fatal(err)
	}
	fresh := request
	fresh.Nonce = "nonce-2"
	if _, err = auth.AuthorizeOperation(fresh, now, "status", fresh.MessageDigest); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("revoke after restart=%v", err)
	}
}
