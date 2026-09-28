package localpd

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const testKey = "01234567890123456789012345678901"

func td(label string) string { return validOrSentinelDigest("", label) }

func privateDir(t *testing.T) string {
	t.Helper()
	d := t.TempDir()
	if err := os.Chmod(d, 0700); err != nil {
		t.Fatal(err)
	}
	return d
}

func event(text string, rev, seq, ord uint64) SourceEvent {
	return SourceEvent{
		ConversationID: "conversation-1", Revision: rev, SourceSequence: seq,
		IngestOrdinal: ord, ScannedThrough: seq, Complete: true,
		PolicyVersion: 1, PolicyDigest: td("policy-1"), CoverageDigest: td("coverage-1"),
		RevisionSetDigest: td("revision-set-" + string(rune('0'+rev))), Content: []byte(text),
	}
}

func testLedger(t *testing.T, path string, cp HighWaterCheckpointStore) *HighWaterLedger {
	t.Helper()
	l, err := NewTestHighWaterLedger(path, []byte(testKey), cp)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	return l
}

func decision(r HighWaterRecord) CloudDecisionBinding {
	return CloudDecisionBinding{ConversationID: r.ConversationID, HighWaterVersion: r.Version, ContentDigest: r.ContentDigest, RevisionSetDigest: r.RevisionSetDigest, CoverageDigest: r.CoverageDigest, PolicyVersion: r.PolicyVersion, PolicyDigest: r.PolicyDigest}
}

func TestDetectFrozenMarkerAndNormalizationQuarantine(t *testing.T) {
	cases := []struct {
		in     string
		marker bool
		mode   DetectionMode
	}{
		{"Это ПД\r\nобычное", true, ModePD},
		{"\ufeff \tЭто ПД\r\n", true, ModePD},
		{"\ufeffordinary", false, ModeQuarantine},
		{"Это ПД\n", false, ModeQuarantine},
		{"это ПД\r\n", false, ModeQuarantine},
		{"Это\u00a0ПД\r\n", false, ModeQuarantine},
		{"Е\u200bто ПД\r\n", false, ModeQuarantine},
		{"Это ПДx\r\n", false, ModeQuarantine},
		{"Eтo ПA\r\n", false, ModeQuarantine},
		{"Ｅｔｏ ＰＤ\r\n", false, ModeQuarantine},
		{"Э\u0301то ПД\r\n", false, ModeQuarantine},
		{"Э\u202eто ПД\r\n", false, ModeQuarantine},
		{"Это \ufeffПД\r\n", false, ModeQuarantine},
		{"ordinary\ufeffbody", false, ModeQuarantine},
	}
	for _, tc := range cases {
		d, err := Detect(event(tc.in, 1, 1, 1))
		if err != nil {
			t.Fatalf("%q: %v", tc.in, err)
		}
		if d.Marker != tc.marker || d.Mode != tc.mode {
			t.Fatalf("%q: marker=%v mode=%s", tc.in, d.Marker, d.Mode)
		}
	}
}

type spoofedMarkerCheckpoint struct {
	*MemoryHighWaterCheckpointStore
}

func (*spoofedMarkerCheckpoint) AttestedHighWaterCheckpoint() {}

func TestProductionConstructorIsDisabledWithoutPackageCapability(t *testing.T) {
	path := filepath.Join(privateDir(t), "ledger.enc")
	spoof := &spoofedMarkerCheckpoint{NewMemoryHighWaterCheckpointStore()}
	if _, err := NewAnchoredHighWaterLedger(path, []byte(testKey), productionHighWaterCapability{}, spoof); !errors.Is(err, ErrHighWaterAnchorRequired) {
		t.Fatalf("spoofed marker entered production path: %v", err)
	}
}

func TestHighWaterL0RestartExactCloudBindingAndNoRaw(t *testing.T) {
	dir := privateDir(t)
	path := filepath.Join(dir, "ledger.enc")
	cp := NewMemoryHighWaterCheckpointStore()
	l := testLedger(t, path, cp)
	now := time.Date(2026, 8, 19, 10, 0, 0, 0, time.UTC)
	r, err := l.Observe(context.Background(), event("ordinary RAW_PD_SENTINEL", 1, 1, 1), now)
	if err != nil {
		t.Fatal(err)
	}
	if r.Class != ClassL0 || r.Mode != ModeNormal || r.State != "open" || r.RuleIDs == nil {
		t.Fatalf("bad record: %+v", r)
	}
	if err = l.ValidateCloudDecision(context.Background(), decision(r)); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "RAW_PD_SENTINEL") {
		t.Fatal("raw content persisted")
	}
	_ = l.Close()
	l = testLedger(t, path, cp)
	r2, ok, err := l.Snapshot(context.Background(), r.ConversationID)
	if err != nil || !ok || r2.State != "open" || r2.RuleIDs == nil {
		t.Fatalf("restart: %+v %v %v", r2, ok, err)
	}
	if err = l.ValidateCloudDecision(context.Background(), decision(r)); err != nil {
		t.Fatal(err)
	}
	bad := decision(r)
	bad.PolicyDigest = td("new-policy")
	if err = l.ValidateCloudDecision(context.Background(), bad); !errors.Is(err, ErrCloudDecisionStale) {
		t.Fatalf("policy drift accepted: %v", err)
	}
}

func TestUncertaintyDurablyInvalidatesBeforeError(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*SourceEvent)
		want   error
		state  string
	}{
		{"gap", func(e *SourceEvent) { e.SourceSequence, e.ScannedThrough, e.Gap = 3, 3, true }, ErrHighWaterGap, "quarantine"},
		{"revoke", func(e *SourceEvent) { e.Revoked = true }, ErrInvalidSourceEvent, "closed"},
		{"delete", func(e *SourceEvent) { e.Deleted = true }, ErrInvalidSourceEvent, "closed"},
		{"backfill", func(e *SourceEvent) { e.Backfill = true }, ErrInvalidSourceEvent, "quarantine"},
		{"pending", func(e *SourceEvent) { e.PendingParts = true }, ErrInvalidSourceEvent, "quarantine"},
		{"incomplete", func(e *SourceEvent) { e.Complete = false }, ErrInvalidSourceEvent, "quarantine"},
		{"same-revision-edit", func(e *SourceEvent) { e.Revision = 1; e.Content = []byte("edited") }, ErrHighWaterStale, "quarantine"},
		{"old-revision", func(e *SourceEvent) { e.Revision = 0 }, ErrHighWaterStale, "quarantine"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := privateDir(t)
			path := filepath.Join(dir, "ledger")
			cp := NewMemoryHighWaterCheckpointStore()
			l := testLedger(t, path, cp)
			base, err := l.Observe(context.Background(), event("ordinary", 1, 1, 1), time.Now().UTC())
			if err != nil {
				t.Fatal(err)
			}
			e := event("ordinary-2", 2, 2, 2)
			tc.mutate(&e)
			r, err := l.Observe(context.Background(), e, time.Now().UTC().Add(time.Second))
			if !errors.Is(err, tc.want) {
				t.Fatalf("got %v want %v", err, tc.want)
			}
			if r.Version <= base.Version || r.State != tc.state {
				t.Fatalf("not durably advanced: %+v", r)
			}
			if err = l.ValidateCloudDecision(context.Background(), decision(base)); !errors.Is(err, ErrCloudDecisionStale) {
				t.Fatalf("prior decision remained valid: %v", err)
			}
			_ = l.Close()
			l = testLedger(t, path, cp)
			snap, ok, err := l.Snapshot(context.Background(), e.ConversationID)
			if err != nil || !ok || snap.Version != r.Version || snap.State != tc.state {
				t.Fatalf("restart lost quarantine: %+v %v %v", snap, ok, err)
			}
		})
	}
}

func TestPDHighWaterNeverDowngrades(t *testing.T) {
	l := testLedger(t, filepath.Join(privateDir(t), "ledger"), NewMemoryHighWaterCheckpointStore())
	r, err := l.Observe(context.Background(), event("Это ПД\r\nsecret", 1, 1, 1), time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if r.Class != ClassL3 || r.Mode != ModePD || r.State != "quarantine" {
		t.Fatalf("bad PD record: %+v", r)
	}
	r2, err := l.Observe(context.Background(), event("ordinary", 2, 2, 2), time.Now().UTC().Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if r2.Class != ClassL3 || r2.Mode != ModePD || r2.State != "quarantine" {
		t.Fatalf("downgraded: %+v", r2)
	}
	if err = l.ValidateCloudDecision(context.Background(), decision(r2)); !errors.Is(err, ErrCloudDecisionStale) {
		t.Fatalf("PD cloud accepted: %v", err)
	}
}

func TestCheckpointRejectsRollbackDeletionAndReset(t *testing.T) {
	dir := privateDir(t)
	path := filepath.Join(dir, "ledger")
	cp := NewMemoryHighWaterCheckpointStore()
	l := testLedger(t, path, cp)
	if _, err := l.Observe(context.Background(), event("one", 1, 1, 1), time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	old, _ := os.ReadFile(path)
	if _, err := l.Observe(context.Background(), event("two", 2, 2, 2), time.Now().UTC().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	_ = l.Close()
	if err := os.WriteFile(path, old, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewTestHighWaterLedger(path, []byte(testKey), cp); !errors.Is(err, ErrHighWaterCheckpoint) {
		t.Fatalf("rollback accepted: %v", err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if _, err := NewTestHighWaterLedger(path, []byte(testKey), cp); !errors.Is(err, ErrHighWaterCheckpoint) {
		t.Fatalf("deletion accepted: %v", err)
	}
	if err := os.WriteFile(path, old, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewTestHighWaterLedger(path, []byte(testKey), NewMemoryHighWaterCheckpointStore()); !errors.Is(err, ErrHighWaterCheckpoint) {
		t.Fatalf("checkpoint reset accepted: %v", err)
	}
}

type failingHWCheckpoint struct {
	mu   sync.Mutex
	cp   HighWaterCheckpoint
	fail bool
}

func (s *failingHWCheckpoint) LoadCheckpoint() (HighWaterCheckpoint, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cp, nil
}
func (s *failingHWCheckpoint) CommitCheckpoint(expected uint64, next HighWaterCheckpoint) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fail {
		return errors.New("fail")
	}
	if s.cp.Version != expected {
		return ErrHighWaterCheckpoint
	}
	s.cp = next
	return nil
}

func TestTornCheckpointCommitPoisonsAdvancedFile(t *testing.T) {
	cp := &failingHWCheckpoint{}
	path := filepath.Join(privateDir(t), "ledger")
	l := testLedger(t, path, cp)
	cp.fail = true
	if _, err := l.Observe(context.Background(), event("ordinary", 1, 1, 1), time.Now().UTC()); !errors.Is(err, ErrHighWaterCheckpoint) {
		t.Fatalf("torn commit accepted: %v", err)
	}
	_ = l.Close()
	cp.fail = false
	if _, err := NewTestHighWaterLedger(path, []byte(testKey), cp); !errors.Is(err, ErrHighWaterCheckpoint) {
		t.Fatalf("advanced file remained usable: %v", err)
	}
}

func TestFilesystemSymlinkAndLockSplitFailClosed(t *testing.T) {
	t.Run("symlink-ancestor", func(t *testing.T) {
		base := privateDir(t)
		realDir := filepath.Join(base, "real")
		if err := os.Mkdir(realDir, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("real", filepath.Join(base, "alias")); err != nil {
			t.Fatal(err)
		}
		if _, err := NewTestHighWaterLedger(filepath.Join(base, "alias", "ledger"), []byte(testKey), NewMemoryHighWaterCheckpointStore()); !errors.Is(err, ErrHighWaterUnsafePath) {
			t.Fatalf("symlink ancestor accepted: %v", err)
		}
	})
	t.Run("private-directory", func(t *testing.T) {
		dir := privateDir(t)
		if err := os.Chmod(dir, 0755); err != nil {
			t.Fatal(err)
		}
		if _, err := NewTestHighWaterLedger(filepath.Join(dir, "ledger"), []byte(testKey), NewMemoryHighWaterCheckpointStore()); !errors.Is(err, ErrHighWaterUnsafePath) {
			t.Fatalf("public dir accepted: %v", err)
		}
	})
	t.Run("data-symlink", func(t *testing.T) {
		dir := privateDir(t)
		path := filepath.Join(dir, "ledger")
		l := testLedger(t, path, NewMemoryHighWaterCheckpointStore())
		if _, err := l.Observe(context.Background(), event("ordinary", 1, 1, 1), time.Now().UTC()); err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(filepath.Join(dir, "target"), path); err != nil {
			t.Fatal(err)
		}
		if _, _, err := l.Snapshot(context.Background(), "conversation-1"); !errors.Is(err, ErrHighWaterUnsafePath) {
			t.Fatalf("symlink accepted: %v", err)
		}
	})
	t.Run("lock-split", func(t *testing.T) {
		dir := privateDir(t)
		path := filepath.Join(dir, "ledger")
		l := testLedger(t, path, NewMemoryHighWaterCheckpointStore())
		if err := os.Remove(path + ".lock"); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path+".lock", nil, 0600); err != nil {
			t.Fatal(err)
		}
		if _, _, err := l.Snapshot(context.Background(), "conversation-1"); !errors.Is(err, ErrHighWaterUnsafePath) {
			t.Fatalf("split lock accepted: %v", err)
		}
	})
	t.Run("directory-replacement-stays-on-root-fd", func(t *testing.T) {
		base := privateDir(t)
		dir := filepath.Join(base, "state")
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, "ledger")
		cp := NewMemoryHighWaterCheckpointStore()
		l := testLedger(t, path, cp)
		if _, err := l.Observe(context.Background(), event("one", 1, 1, 1), time.Now().UTC()); err != nil {
			t.Fatal(err)
		}
		moved := filepath.Join(base, "moved")
		if err := os.Rename(dir, moved); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
		if _, err := l.Observe(context.Background(), event("two", 2, 2, 2), time.Now().UTC().Add(time.Second)); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(filepath.Join(dir, "ledger")); !os.IsNotExist(err) {
			t.Fatalf("replacement directory received state: %v", err)
		}
		if _, err := os.Stat(filepath.Join(moved, "ledger")); err != nil {
			t.Fatalf("root-fd state missing: %v", err)
		}
		if _, err := NewTestHighWaterLedger(path, []byte(testKey), cp); !errors.Is(err, ErrHighWaterCheckpoint) {
			t.Fatalf("replacement root accepted against checkpoint: %v", err)
		}
	})
}

func TestCrossInstanceLockReloadCAS(t *testing.T) {
	dir := privateDir(t)
	path := filepath.Join(dir, "ledger")
	cp := NewMemoryHighWaterCheckpointStore()
	l1 := testLedger(t, path, cp)
	l2 := testLedger(t, path, cp)
	var wg sync.WaitGroup
	for i, l := range []*HighWaterLedger{l1, l2} {
		wg.Add(1)
		go func(i int, l *HighWaterLedger) {
			defer wg.Done()
			e := event("ordinary", uint64(i+1), uint64(i+1), uint64(i+1))
			_, _ = l.Observe(context.Background(), e, time.Now().UTC().Add(time.Duration(i)*time.Second))
		}(i, l)
	}
	wg.Wait()
	r, ok, err := l1.Snapshot(context.Background(), "conversation-1")
	if err != nil || !ok || r.Version != 2 || (r.State != "open" && r.State != "quarantine") {
		t.Fatalf("CAS/reload: %+v %v %v", r, ok, err)
	}
}

func TestStrictLoadedRecordValidationAndNilNormalization(t *testing.T) {
	dir := privateDir(t)
	path := filepath.Join(dir, "ledger")
	cp := NewMemoryHighWaterCheckpointStore()
	l := testLedger(t, path, cp)
	r, err := l.Observe(context.Background(), event("ordinary", 1, 1, 1), time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if r.RuleIDs == nil {
		t.Fatal("nil rule IDs escaped")
	}
	// A semantically impossible open/L3 record must be rejected even when the
	// attacker can re-encrypt and advance the cooperative test checkpoint.
	s, err := l.loadVerified()
	if err != nil {
		t.Fatal(err)
	}
	x := s.Records[r.ConversationID]
	x.Class = ClassL3
	s.Records[r.ConversationID] = x
	s.Version++
	p, _ := jsonMarshalForTest(s)
	enc, _ := l.seal(p)
	if err = l.atomicWrite(enc); err != nil {
		t.Fatal(err)
	}
	d, _ := highWaterStateDigest(s)
	if err = cp.CommitCheckpoint(s.Version-1, HighWaterCheckpoint{Version: s.Version, StateDigest: d}); err != nil {
		t.Fatal(err)
	}
	if _, _, err = l.Snapshot(context.Background(), r.ConversationID); !errors.Is(err, ErrHighWaterCorrupt) {
		t.Fatalf("invalid semantic record accepted: %v", err)
	}
}

func jsonMarshalForTest(v any) ([]byte, error) { return json.Marshal(v) }
