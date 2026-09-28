package macosinstall

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type journalFakeAuthority struct {
	anchors map[string]fakeJournalAnchor
	deny    bool
	lostCAS bool
}

func newJournalFakeAuthority() *journalFakeAuthority {
	return &journalFakeAuthority{anchors: map[string]fakeJournalAnchor{}}
}
func (a *journalFakeAuthority) valid() bool { return a != nil && !a.deny }
func (a *journalFakeAuthority) sign(_ context.Context, _, run, release, nonce, digest string, seq uint64) (string, error) {
	if !a.valid() {
		return "", errors.New("outage")
	}
	return fakeJournalSignature(run, release, nonce, digest, seq), nil
}
func (a *journalFakeAuthority) verify(_ context.Context, _, run, release, nonce, digest, sig string, seq uint64) error {
	if !a.valid() || sig != fakeJournalSignature(run, release, nonce, digest, seq) {
		return errors.New("signature")
	}
	return nil
}
func (a *journalFakeAuthority) load(_ context.Context, _, run, _, _ string) (uint64, string, error) {
	if !a.valid() {
		return 0, "", errors.New("outage")
	}
	x := a.anchors[run]
	return x.sequence, x.digest, nil
}
func (a *journalFakeAuthority) cas(_ context.Context, _, run, _, _ string, old, next uint64, oldD, newD string) error {
	if !a.valid() {
		return errors.New("outage")
	}
	x := a.anchors[run]
	if x.sequence != old || x.digest != oldD || next != old+1 {
		return errors.New("cas")
	}
	a.anchors[run] = fakeJournalAnchor{next, newD}
	if a.lostCAS {
		a.lostCAS = false
		return errors.New("lost response")
	}
	return nil
}

func openTestJournal(t *testing.T, authority journalAuthority) (*os.Root, *ProvisioningJournal) {
	t.Helper()
	r, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	j, err := OpenProvisioningJournal(r, "0123456789abcdef", testReleaseDigest, authority)
	if err != nil {
		_ = r.Close()
		t.Fatal(err)
	}
	return r, j
}
func TestDeploymentLockRejectsConcurrentHolder(t *testing.T) {
	p := filepath.Join(t.TempDir(), "deployment.lock")
	first, err := acquireDeploymentLock(p)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	if _, err := acquireDeploymentLock(p); err == nil {
		t.Fatal("concurrent deployment lock accepted")
	}
}

func TestProductionJournalBindingRejectsZeroClients(t *testing.T) {
	if _, err := NewProductionJournalBinding(nil, nil); err == nil {
		t.Fatal("zero production authority binding accepted")
	}
}

func TestProvisioningJournalWritesLocalChainWithoutAuthorities(t *testing.T) {
	r, j := openTestJournal(t, nil)
	defer r.Close()
	if err := j.Transition("apply", "preflight"); err != nil {
		t.Fatal(err)
	}
	path := j.dir() + "/journal.jsonl"
	b, err := r.ReadFile(path)
	if err != nil || !strings.HasSuffix(string(b), "\n") {
		t.Fatalf("local journal missing or open: %v", err)
	}
	if _, err := r.Lstat(j.dir() + "/checkpoint.json"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unprotected bootstrap checkpoint=%v", err)
	}
	if j.Protected() {
		t.Fatal("local-only journal claims protection")
	}
}
func TestProtectedCheckpointCoversHistoryAndRejectsRehashedMutation(t *testing.T) {
	a := newJournalFakeAuthority()
	r, j := openTestJournal(t, a)
	defer r.Close()
	for _, event := range []string{"preflight", "configure", "verify"} {
		if err := j.Transition("apply", event); err != nil {
			t.Fatal(err)
		}
	}
	if err := j.Promote(); err != nil {
		t.Fatal(err)
	}
	path := j.dir() + "/journal.jsonl"
	raw, err := r.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	var first JournalEntry
	if err = json.Unmarshal([]byte(lines[0]), &first); err != nil {
		t.Fatal(err)
	}
	first.Event = "changed"
	first.Hash = journalEntryHash(first)
	mutated, _ := json.Marshal(first)
	lines[0] = string(mutated)
	previous := first.Hash
	for n := 1; n < len(lines); n++ {
		var e JournalEntry
		if err = json.Unmarshal([]byte(lines[n]), &e); err != nil {
			t.Fatal(err)
		}
		e.PreviousHash = previous
		e.Hash = journalEntryHash(e)
		b, _ := json.Marshal(e)
		lines[n] = string(b)
		previous = e.Hash
	}
	if err = r.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = OpenProvisioningJournal(r, "0123456789abcdef", testReleaseDigest, a); err == nil {
		t.Fatal("rehashed historical mutation accepted")
	}
}
func TestProvisioningJournalRejectsWrongCheckpointBindingsAndAnchor(t *testing.T) {
	for name, mutate := range map[string]func(*JournalCheckpoint, *journalFakeAuthority){
		"wrong-run": func(c *JournalCheckpoint, _ *journalFakeAuthority) { c.RunID = "abcdef0123456789" },
		"wrong-release": func(c *JournalCheckpoint, _ *journalFakeAuthority) {
			c.ReleaseDigest = "sha256:" + strings.Repeat("a", 64)
		},
		"wrong-nonce":     func(c *JournalCheckpoint, _ *journalFakeAuthority) { c.Nonce = "abcdef0123456789" },
		"wrong-signature": func(c *JournalCheckpoint, _ *journalFakeAuthority) { c.Signature = strings.Repeat("0", 64) },
		"stale-anchor": func(c *JournalCheckpoint, a *journalFakeAuthority) {
			a.anchors[c.RunID] = fakeJournalAnchor{c.AnchorSequence - 1, c.PreviousDigest}
		},
		"wrong-generation": func(c *JournalCheckpoint, a *journalFakeAuthority) {
			a.anchors[c.RunID] = fakeJournalAnchor{c.AnchorSequence + 1, checkpointDigest(*c)}
		},
	} {
		t.Run(name, func(t *testing.T) {
			a := newJournalFakeAuthority()
			r, j := openTestJournal(t, a)
			defer r.Close()
			if err := j.Transition("apply", "configure"); err != nil {
				t.Fatal(err)
			}
			if err := j.Promote(); err != nil {
				t.Fatal(err)
			}
			b, err := r.ReadFile(j.dir() + "/checkpoint.json")
			if err != nil {
				t.Fatal(err)
			}
			var c JournalCheckpoint
			if err = json.Unmarshal(b, &c); err != nil {
				t.Fatal(err)
			}
			mutate(&c, a)
			b, _ = json.Marshal(c)
			if err = r.WriteFile(j.dir()+"/checkpoint.json", b, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err = OpenProvisioningJournal(r, "0123456789abcdef", testReleaseDigest, a); err == nil {
				t.Fatal("invalid checkpoint accepted")
			}
		})
	}
}
func TestProvisioningJournalLostCASResponseIsReplaySafe(t *testing.T) {
	a := newJournalFakeAuthority()
	r, j := openTestJournal(t, a)
	defer r.Close()
	if err := j.Transition("apply", "configure"); err != nil {
		t.Fatal(err)
	}
	a.lostCAS = true
	if err := j.Promote(); err == nil {
		t.Fatal("lost response unexpectedly accepted")
	}
	// Restart reconstructs the exact same checkpoint and only accepts the
	// already-advanced independent generation; no second CAS is issued.
	reopened, err := OpenProvisioningJournal(r, "0123456789abcdef", testReleaseDigest, a)
	if err != nil {
		t.Fatalf("restart after replay: %v", err)
	}
	if !reopened.Protected() || reopened.anchorSequence != 1 {
		t.Fatalf("recovered protection=%v generation=%d", reopened.Protected(), reopened.anchorSequence)
	}
}

func TestProvisioningJournalRestartRecoversEverySealBoundary(t *testing.T) {
	for _, point := range []string{"append-to-sign", "sign-to-pending-fsync", "pending-to-cas", "cas-to-rename", "rename-to-dir-fsync"} {
		t.Run(point, func(t *testing.T) {
			a := newJournalFakeAuthority()
			r, j := openTestJournal(t, a)
			defer r.Close()
			if err := j.Transition("apply", "configure"); err != nil {
				t.Fatal(err)
			}
			j.fault = func(got string) error {
				if got == point {
					return errors.New("injected crash boundary")
				}
				return nil
			}
			if err := j.Promote(); err == nil {
				t.Fatal("fault was not observed")
			}
			reopened, err := OpenProvisioningJournal(r, "0123456789abcdef", testReleaseDigest, a)
			if err != nil || !reopened.Protected() {
				t.Fatalf("restart protection=%v err=%v", reopened != nil && reopened.Protected(), err)
			}
			if _, err := r.Lstat(reopened.dir() + "/.checkpoint.pending"); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("pending checkpoint survived recovery: %v", err)
			}
		})
	}
}

func TestProtectedJournalRestartSealsExistingTailWithoutAppending(t *testing.T) {
	a := newJournalFakeAuthority()
	r, j := openTestJournal(t, a)
	defer r.Close()
	if err := j.Transition("apply", "configure"); err != nil {
		t.Fatal(err)
	}
	if err := j.Promote(); err != nil {
		t.Fatal(err)
	}
	before := j.sequence
	j.fault = func(point string) error {
		if point == "append-to-sign" {
			return errors.New("interrupted after append")
		}
		return nil
	}
	if err := j.Transition("activate", "preflight"); err == nil {
		t.Fatal("injected append interruption accepted")
	}
	reopened, err := OpenProvisioningJournal(r, "0123456789abcdef", testReleaseDigest, a)
	if err != nil || !reopened.Protected() {
		t.Fatalf("restart protection=%v err=%v", reopened != nil && reopened.Protected(), err)
	}
	if reopened.sequence != before+1 || reopened.anchorSequence != 2 {
		t.Fatalf("sequence=%d generation=%d, appended recovery event", reopened.sequence, reopened.anchorSequence)
	}
}

func TestProtectedJournalRestartFinalizesPendingAfterCAS(t *testing.T) {
	a := newJournalFakeAuthority()
	r, j := openTestJournal(t, a)
	defer r.Close()
	if err := j.Transition("apply", "configure"); err != nil {
		t.Fatal(err)
	}
	if err := j.Promote(); err != nil {
		t.Fatal(err)
	}
	j.fault = func(point string) error {
		if point == "cas-to-rename" {
			return errors.New("crash after cas")
		}
		return nil
	}
	if err := j.Transition("activate", "preflight"); err == nil {
		t.Fatal("injected CAS-to-rename fault accepted")
	}
	reopened, err := OpenProvisioningJournal(r, "0123456789abcdef", testReleaseDigest, a)
	if err != nil || !reopened.Protected() || reopened.anchorSequence != 2 {
		t.Fatalf("restart protected=%v generation=%d err=%v", reopened != nil && reopened.Protected(), reopened.anchorSequence, err)
	}
}
func TestProvisioningJournalUsesCanonicalTreeModes(t *testing.T) {
	r, j := openTestJournal(t, nil)
	defer r.Close()
	for path, want := range map[string]os.FileMode{"state": 0711, "state/controller": 0700, "state/controller/provisioning": 0700, j.dir(): 0700} {
		st, err := r.Lstat(path)
		if err != nil || st.Mode().Perm() != want {
			t.Fatalf("%s mode=%v err=%v want=%v", path, st.Mode().Perm(), err, want)
		}
	}
}
func TestProvisioningJournalRejectsUnsafeExistingTree(t *testing.T) {
	for name, setup := range map[string]func(*os.Root) error{"wrong-mode": func(r *os.Root) error { return r.Mkdir("state", 0700) }, "symlink": func(*os.Root) error { return nil }} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			r, err := os.OpenRoot(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			if name == "symlink" {
				if err = os.Symlink("/tmp", filepath.Join(dir, "state")); err != nil {
					t.Fatal(err)
				}
			} else if err = setup(r); err != nil {
				t.Fatal(err)
			}
			if _, err = OpenProvisioningJournal(r, "0123456789abcdef", testReleaseDigest, nil); err == nil {
				t.Fatal("unsafe tree accepted")
			}
		})
	}
}
