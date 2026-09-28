package workspacegroup

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func fixture(t *testing.T) (string, string) {
	t.Helper()
	d := t.TempDir()
	root := filepath.Join(d, "project")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	root, _ = filepath.EvalSymlinks(root)
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		t.Fatal(err)
	}
	return root, string(k)
}
func key(s string) []byte { return []byte(s) }
func testRegistry(t *testing.T, root string) *Registry {
	t.Helper()
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		t.Fatal(err)
	}
	storeDir := filepath.Join(t.TempDir(), "store")
	if err := os.Mkdir(storeDir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(storeDir, "groups.enc")
	r, err := newTestRegistry(path, k, root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })
	return r
}
func TestCreateProjectionAndChatBinding(t *testing.T) {
	root, _ := fixture(t)
	r := testRegistry(t, root)
	g, e := r.Create(context.Background(), GroupSpec{DisplayLabel: "demo", Roots: []RootSpec{{Label: "app", Path: root, Mode: WriteMode}}, BeadsScopeRef: "project:demo", BeadsCapabilityRefs: []string{"memory:read"}})
	if e != nil {
		t.Fatal(e)
	}
	p, e := r.Projection(context.Background(), g.GroupID)
	if e != nil {
		t.Fatal(e)
	}
	b, _ := jsonMarshal(p)
	if strings.Contains(string(b), root) || strings.Contains(string(b), "canonical_path") {
		t.Fatalf("unsafe path leaked: %s", b)
	}
	if strings.Contains(string(b), "beads_scope_ref") || strings.Contains(string(b), "beads_capability_refs") {
		t.Fatalf("controller capability leaked: %s", b)
	}
	binding, e := r.BindChat(context.Background(), "chat-1", g.GroupID, g.Version, g.Digest)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = r.AuthorizeChatBinding(context.Background(), "chat-1", binding); e != nil {
		t.Fatal(e)
	}
}

func TestListProjectionsUsesLiveLockedStateAndUpdatedAt(t *testing.T) {
	root, _ := fixture(t)
	r := testRegistry(t, root)
	g, err := r.Create(context.Background(), GroupSpec{DisplayLabel: "demo", Roots: []RootSpec{{Label: "app", Path: root, Mode: ReadMode}}})
	if err != nil {
		t.Fatal(err)
	}
	projections, err := r.ListProjections(context.Background())
	if err != nil || len(projections) != 1 {
		t.Fatalf("projections=%+v err=%v", projections, err)
	}
	if projections[0].GroupID != g.GroupID || projections[0].UpdatedAt.IsZero() {
		t.Fatalf("projection=%+v", projections[0])
	}
}
func TestRejectUnsafeRoots(t *testing.T) {
	root, _ := fixture(t)
	cases := []string{"/", root + "/../", root + "/./x", filepath.Join(filepath.Dir(root), "alias")}
	if err := os.Symlink(root, cases[3]); err != nil {
		t.Fatal(err)
	}
	for _, p := range cases {
		if _, e := testRegistry(t, root).Create(context.Background(), GroupSpec{DisplayLabel: "x", Roots: []RootSpec{{Label: "r", Path: p, Mode: ReadMode}}}); !errors.Is(e, ErrUnsafePath) {
			t.Errorf("%q: got %v", p, e)
		}
	}
}

func TestRejectsRawTraversalBeforeCanonicalization(t *testing.T) {
	root, _ := fixture(t)
	child := filepath.Join(root, "child")
	if err := os.Mkdir(child, 0700); err != nil {
		t.Fatal(err)
	}
	r := testRegistry(t, root)
	for _, raw := range []string{root + "/child/..", root + "/./"} {
		if _, err := r.Create(context.Background(), GroupSpec{DisplayLabel: "x", Roots: []RootSpec{{Label: "a", Path: raw, Mode: ReadMode}}}); !errors.Is(err, ErrUnsafePath) {
			t.Fatalf("raw root %q: %v", raw, err)
		}
	}
	store := filepath.Join(t.TempDir(), "store")
	if err := os.Mkdir(store, 0700); err != nil {
		t.Fatal(err)
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	if _, err := newTestRegistry(store+"/nested/../groups.enc", key, root); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("raw store path: %v", err)
	}
}
func TestRejectOverlapAndStale(t *testing.T) {
	root, _ := fixture(t)
	sub := filepath.Join(root, "sub")
	if err := os.Mkdir(sub, 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := testRegistry(t, root).Create(context.Background(), GroupSpec{DisplayLabel: "sub", Roots: []RootSpec{{Label: "b", Path: sub, Mode: ReadMode}}}); err != nil {
		t.Fatalf("allowed descendant: %v", err)
	}
	r := testRegistry(t, root)
	_, e := r.Create(context.Background(), GroupSpec{DisplayLabel: "x", Roots: []RootSpec{{Label: "a", Path: root, Mode: ReadMode}, {Label: "b", Path: sub, Mode: ReadMode}}})
	if !errors.Is(e, ErrUnsafePath) {
		t.Fatal(e)
	}
	g, e := r.Create(context.Background(), GroupSpec{DisplayLabel: "x", Roots: []RootSpec{{Label: "a", Path: root, Mode: ReadMode}}})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = r.Update(context.Background(), g.GroupID, g.Version, "sha256:"+strings.Repeat("0", 64), GroupSpec{DisplayLabel: "y", Roots: []RootSpec{{Label: "a", Path: root, Mode: ReadMode}}}); !errors.Is(e, ErrDigestMismatch) {
		t.Fatal(e)
	}
}
func TestEncryptedRestartTamperAndConcurrentCAS(t *testing.T) {
	root, _ := fixture(t)
	d := t.TempDir()
	if e := os.Chmod(d, 0700); e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(d, "groups.enc")
	k := make([]byte, 32)
	if _, e := rand.Read(k); e != nil {
		t.Fatal(e)
	}
	r, e := newTestRegistry(path, k, root)
	if e != nil {
		t.Fatal(e)
	}
	g, e := r.Create(context.Background(), GroupSpec{DisplayLabel: "x", Roots: []RootSpec{{Label: "a", Path: root, Mode: ReadMode}}})
	if e != nil {
		t.Fatal(e)
	}
	r2, e := newTestRegistry(path, k, root)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = r2.Get(context.Background(), g.GroupID); e != nil {
		t.Fatal(e)
	}
	raw, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	if strings.Contains(string(raw), root) {
		t.Fatal("plaintext path persisted")
	}
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, e := r2.Update(context.Background(), g.GroupID, g.Version, g.Digest, GroupSpec{DisplayLabel: "x", Roots: []RootSpec{{Label: "a", Path: root, Mode: ReadMode}}})
			errs <- e
		}()
	}
	wg.Wait()
	close(errs)
	ok := 0
	for e := range errs {
		if e == nil {
			ok++
		} else if !errors.Is(e, ErrStaleVersion) {
			t.Fatal(e)
		}
	}
	if ok != 1 {
		t.Fatalf("CAS successes=%d", ok)
	}
	raw, e = os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(path, append(raw, 'x'), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = newTestRegistry(path, k, root); !errors.Is(e, ErrIntegrity) {
		t.Fatal(e)
	}
}

func TestBindingRejectsStaleSpliceAndForgery(t *testing.T) {
	root, _ := fixture(t)
	r := testRegistry(t, root)
	g, err := r.Create(context.Background(), GroupSpec{DisplayLabel: "x", Roots: []RootSpec{{Label: "a", Path: root, Mode: ReadMode}}})
	if err != nil {
		t.Fatal(err)
	}
	binding, err := r.BindChat(context.Background(), "chat-a", g.GroupID, g.Version, g.Digest)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = r.AuthorizeChatBinding(context.Background(), "chat-b", binding); !errors.Is(err, ErrBindingUnauthorized) {
		t.Fatalf("splice: %v", err)
	}
	forged := binding
	forged.Signature = "sha256:" + strings.Repeat("0", 64)
	if _, err = r.AuthorizeChatBinding(context.Background(), "chat-a", forged); !errors.Is(err, ErrBindingUnauthorized) {
		t.Fatalf("forged: %v", err)
	}
	if _, err = r.Update(context.Background(), g.GroupID, g.Version, g.Digest, GroupSpec{DisplayLabel: "new", Roots: []RootSpec{{Label: "a", Path: root, Mode: ReadMode}}}); err != nil {
		t.Fatal(err)
	}
	if _, err = r.AuthorizeChatBinding(context.Background(), "chat-a", binding); !errors.Is(err, ErrBindingUnauthorized) {
		t.Fatalf("stale: %v", err)
	}
}

func TestRollbackAndDeleteFailCheckpointVerification(t *testing.T) {
	root, _ := fixture(t)
	makeRegistry := func() (*Registry, string, []byte) {
		dir := t.TempDir()
		if err := os.Chmod(dir, 0700); err != nil {
			t.Fatal(err)
		}
		k := make([]byte, 32)
		if _, err := rand.Read(k); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, "groups.enc")
		r, err := newTestRegistry(path, k, root)
		if err != nil {
			t.Fatal(err)
		}
		return r, path, k
	}
	r, path, k := makeRegistry()
	g, err := r.Create(context.Background(), GroupSpec{DisplayLabel: "one", Roots: []RootSpec{{Label: "a", Path: root, Mode: ReadMode}}})
	if err != nil {
		t.Fatal(err)
	}
	old, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = r.Update(context.Background(), g.GroupID, g.Version, g.Digest, GroupSpec{DisplayLabel: "two", Roots: []RootSpec{{Label: "a", Path: root, Mode: ReadMode}}}); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, old, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = newTestRegistry(path, k, root); !errors.Is(err, ErrCheckpointMismatch) {
		t.Fatalf("rollback: %v", err)
	}

	r2, deletedPath, deletedKey := makeRegistry()
	if _, err = r2.Create(context.Background(), GroupSpec{DisplayLabel: "one", Roots: []RootSpec{{Label: "a", Path: root, Mode: ReadMode}}}); err != nil {
		t.Fatal(err)
	}
	if err = os.Remove(deletedPath); err != nil {
		t.Fatal(err)
	}
	if _, err = newTestRegistry(deletedPath, deletedKey, root); !errors.Is(err, ErrCheckpointMismatch) {
		t.Fatalf("delete: %v", err)
	}
}

func TestRejectsBroadConfiguredAndRequestedRoots(t *testing.T) {
	root, _ := fixture(t)
	storeDir := filepath.Join(t.TempDir(), "store")
	if err := os.Mkdir(storeDir, 0700); err != nil {
		t.Fatal(err)
	}
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		t.Fatal(err)
	}
	for _, broad := range []string{"/", "/System", "/private", "/var", "/dev", "/Volumes", "/Network", "/home", "/Users/example"} {
		if _, err := newTestRegistry(filepath.Join(storeDir, "groups.enc"), k, broad); !errors.Is(err, ErrUnsafePath) {
			t.Fatalf("configured %q: %v", broad, err)
		}
	}
	r := testRegistry(t, root)
	for _, broad := range []string{"/", "/System", "/private", "/var", "/dev", "/Volumes", "/Network", "/home", "/Users/example"} {
		if _, err := r.Create(context.Background(), GroupSpec{DisplayLabel: "x", Roots: []RootSpec{{Label: "a", Path: broad, Mode: ReadMode}}}); !errors.Is(err, ErrUnsafePath) {
			t.Fatalf("requested %q: %v", broad, err)
		}
	}
}

func TestLabelsUseASCIIByteContract(t *testing.T) {
	root, _ := fixture(t)
	r := testRegistry(t, root)
	for _, spec := range []GroupSpec{
		{DisplayLabel: strings.Repeat("a", MaxLabelBytes+1), Roots: []RootSpec{{Label: "a", Path: root, Mode: ReadMode}}},
		{DisplayLabel: "unicode-\u2603", Roots: []RootSpec{{Label: "a", Path: root, Mode: ReadMode}}},
		{DisplayLabel: "okay", Roots: []RootSpec{{Label: "\u2603", Path: root, Mode: ReadMode}}},
	} {
		if _, err := r.Create(context.Background(), spec); !errors.Is(err, ErrInvalidGroup) {
			t.Fatalf("label contract: %v", err)
		}
	}
	if _, err := r.Create(context.Background(), GroupSpec{DisplayLabel: strings.Repeat("a", MaxLabelBytes), Roots: []RootSpec{{Label: strings.Repeat("b", MaxLabelBytes), Path: root, Mode: ReadMode}}}); err != nil {
		t.Fatalf("ASCII byte limit should be accepted: %v", err)
	}
}

type failOnceCheckpointStore struct {
	mu   sync.Mutex
	c    Checkpoint
	fail bool
}

func (s *failOnceCheckpointStore) LoadCheckpoint() (Checkpoint, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.c, nil
}
func (s *failOnceCheckpointStore) CommitCheckpoint(expected uint64, next Checkpoint) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fail {
		s.fail = false
		return errors.New("checkpoint commit unavailable")
	}
	if s.c.Version != expected || next.Version != expected+1 {
		return ErrCheckpointMismatch
	}
	s.c = next
	return nil
}

func TestCheckpointCommitFailurePoisonsRegistryAndRestart(t *testing.T) {
	root, _ := fixture(t)
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "groups.enc")
	cp := &failOnceCheckpointStore{fail: true}
	r, err := newTestRegistryWithCheckpoint(path, key, cp, root)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if _, err = r.Create(context.Background(), GroupSpec{DisplayLabel: "x", Roots: []RootSpec{{Label: "a", Path: root, Mode: ReadMode}}}); err == nil {
		t.Fatal("checkpoint failure must be returned")
	}
	if _, err = r.Get(context.Background(), "missing"); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("registry was not poisoned: %v", err)
	}
	_ = r.Close()
	if _, err = newTestRegistryWithCheckpoint(path, key, cp, root); !errors.Is(err, ErrCheckpointMismatch) {
		t.Fatalf("restart after checkpoint failure: %v", err)
	}
}

func TestLockReplacementPoisonsBothRegistriesWithoutDualCommit(t *testing.T) {
	root, _ := fixture(t)
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "groups.enc")
	r, err := newTestRegistry(path, key, root)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	g, err := r.Create(context.Background(), GroupSpec{DisplayLabel: "before", Roots: []RootSpec{{Label: "a", Path: root, Mode: ReadMode}}})
	if err != nil {
		t.Fatal(err)
	}
	replaced := make(chan struct{})
	continueUpdate := make(chan struct{})
	r.beforePersist = func() {
		lock := filepath.Join(r.store.path, r.base+".lock")
		if err := os.Remove(lock); err != nil {
			t.Errorf("remove lock: %v", err)
		}
		if err := os.WriteFile(lock, nil, 0600); err != nil {
			t.Errorf("replace lock: %v", err)
		}
		close(replaced)
		<-continueUpdate
	}
	first := make(chan error, 1)
	go func() {
		_, err := r.Update(context.Background(), g.GroupID, g.Version, g.Digest, GroupSpec{DisplayLabel: "after", Roots: []RootSpec{{Label: "a", Path: root, Mode: ReadMode}}})
		first <- err
	}()
	<-replaced
	if _, err := newTestRegistry(path, key, root); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("replacement-lock registry transacted: %v", err)
	}
	close(continueUpdate)
	if err := <-first; !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("original registry did not poison: %v", err)
	}
	if _, err := r.Get(context.Background(), g.GroupID); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("original registry remains usable: %v", err)
	}
	cp, ok := testCheckpoints.Load(path)
	if !ok {
		t.Fatal("checkpoint missing")
	}
	checkpoint, err := cp.(*memoryCheckpointStore).LoadCheckpoint()
	if err != nil || checkpoint.Version != 1 {
		t.Fatalf("dual commit after lock replacement: checkpoint=%+v err=%v", checkpoint, err)
	}
}

func TestRejectsDirectoryAndLockReplacement(t *testing.T) {
	root, _ := fixture(t)
	r := testRegistry(t, root)
	if _, err := r.Create(context.Background(), GroupSpec{DisplayLabel: "x", Roots: []RootSpec{{Label: "a", Path: root, Mode: ReadMode}}}); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(root, root+".old"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Get(context.Background(), "missing"); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("directory replacement: %v", err)
	}

	root2, _ := fixture(t)
	r2 := testRegistry(t, root2)
	if err := os.Remove(filepath.Join(r2.store.path, r2.base+".lock")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(r2.store.path, r2.base+".lock"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := r2.Get(context.Background(), "missing"); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("lock replacement: %v", err)
	}
}

func TestSchemaAndContractParity(t *testing.T) {
	readSchema := func(name string) map[string]any {
		t.Helper()
		b, err := os.ReadFile(filepath.Join("..", "..", "schemas", "workspace-group", name))
		if err != nil {
			t.Fatal(err)
		}
		var schema map[string]any
		if err = json.Unmarshal(b, &schema); err != nil {
			t.Fatal(err)
		}
		return schema
	}
	group := readSchema("workspace-group.v1.json")
	if group["$id"] != "https://openduck.local/schemas/workspace-group.v1.json" {
		t.Fatal("workspace group schema id")
	}
	props := group["properties"].(map[string]any)
	for _, field := range []string{"schema_version", "group_id", "primary_root_id", "roots", "beads_scope_ref", "beads_capability_refs", "version", "digest", "updated_at"} {
		if _, ok := props[field]; !ok {
			t.Fatalf("missing group field %s", field)
		}
	}
	roots := group["$defs"].(map[string]any)["root"].(map[string]any)["properties"].(map[string]any)
	if modes := roots["mode"].(map[string]any)["enum"].([]any); len(modes) != 2 || modes[0] != string(ReadMode) || modes[1] != string(WriteMode) {
		t.Fatal("root modes")
	}
	binding := readSchema("chat-binding.v1.json")
	if binding["$id"] != "https://openduck.local/schemas/workspace-chat-binding.v1.json" {
		t.Fatal("binding schema id")
	}
	if _, ok := binding["properties"].(map[string]any)["signature"]; !ok {
		t.Fatal("binding signature missing")
	}
}

func jsonMarshal(v any) ([]byte, error) { return json.Marshal(v) }
