package macosinstall

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"syscall"
	"testing"

	"openduck/internal/modelegress"
)

type installRootStatFixture struct {
	os.FileInfo
	stat syscall.Stat_t
}

func (f installRootStatFixture) Sys() any { return &f.stat }

func writeStagedFixture(t *testing.T, root string) {
	t.Helper()
	bin := filepath.Join(root, "bin")
	if err := os.Mkdir(bin, 0755); err != nil {
		t.Fatal(err)
	}
	var manifest strings.Builder
	for n, name := range []string{"openduck-checkpoint", "openduck-anchor", "openduck-egress", "openduck-codex-broker", "openduck-codex-runtime", "openduck-controller", "codex", "openduck-owner-grant", "openduck-codex-login", "openduck-installer", "openduck-native-mcp", "openduck-provider-attestor", "openduck-readiness"} {
		body := []byte(strings.Repeat(name, n+1))
		if err := os.WriteFile(filepath.Join(bin, name), body, 0700); err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(body)
		manifest.WriteString(hex.EncodeToString(sum[:]) + " bin/" + name + "\n")
	}
	if err := os.WriteFile(filepath.Join(root, "release.manifest"), []byte(manifest.String()), 0600); err != nil {
		t.Fatal(err)
	}
}

func snapshotInstalledTree(t *testing.T, root string) map[string]string {
	t.Helper()
	out := map[string]string{}
	if err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		value := info.Mode().String()
		if info.Mode().IsRegular() {
			b, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			sum := sha256.Sum256(b)
			value += ":" + hex.EncodeToString(sum[:])
		}
		out[rel] = value
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestOpenOrNormalizeInstallRootCreatedAndIdempotent(t *testing.T) {
	parentPath := t.TempDir()
	parent, err := os.OpenRoot(parentPath)
	if err != nil {
		t.Fatal(err)
	}
	defer parent.Close()

	for attempt := 0; attempt < 2; attempt++ {
		root, err := openOrNormalizeInstallRoot(parent, "OpenDuck", os.Getuid(), os.Getgid())
		if err != nil {
			t.Fatalf("attempt %d: %v", attempt, err)
		}
		st, err := root.Lstat(".")
		if err != nil {
			root.Close()
			t.Fatal(err)
		}
		if !trustedInstallRoot(st, uint32(os.Getuid()), uint32(os.Getgid())) {
			root.Close()
			t.Fatalf("attempt %d left untrusted metadata: %v", attempt, st.Mode())
		}
		if err := root.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestOpenOrNormalizeInstallRootNormalizesSafeExistingDirectory(t *testing.T) {
	parentPath := t.TempDir()
	path := filepath.Join(parentPath, "OpenDuck")
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	parent, err := os.OpenRoot(parentPath)
	if err != nil {
		t.Fatal(err)
	}
	defer parent.Close()
	root, err := openOrNormalizeInstallRoot(parent, "OpenDuck", os.Getuid(), os.Getgid())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	st, err := root.Lstat(".")
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0711 || !ownedBy(st, uint32(os.Getuid()), uint32(os.Getgid())) {
		t.Fatalf("metadata was not normalized: mode=%v", st.Mode())
	}
}

func TestSafeInstallRootCandidateAllowsInheritedSafeGroup(t *testing.T) {
	path := t.TempDir()
	if err := os.Chmod(path, 0711); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat == nil {
		t.Fatal("missing unix metadata")
	}
	fixture := installRootStatFixture{FileInfo: info, stat: *stat}
	fixture.stat.Gid = 80 // macOS admin; normalization will replace it with wheel.
	if !safeInstallRootCandidate(fixture, uint32(os.Getuid())) {
		t.Fatal("safe root-owned inherited group was rejected before normalization")
	}
	if trustedInstallRoot(fixture, uint32(os.Getuid()), 0) {
		t.Fatal("inherited group was accepted without normalization")
	}
}

func TestOpenOrNormalizeInstallRootRejectsUnsafeExistingObjects(t *testing.T) {
	tests := []struct {
		name        string
		prepare     func(t *testing.T, parentPath string)
		expectedUID int
	}{
		{name: "regular file", prepare: func(t *testing.T, parentPath string) {
			if err := os.WriteFile(filepath.Join(parentPath, "OpenDuck"), []byte("not a directory"), 0600); err != nil {
				t.Fatal(err)
			}
		}, expectedUID: os.Getuid()},
		{name: "symlink", prepare: func(t *testing.T, parentPath string) {
			if err := os.Mkdir(filepath.Join(parentPath, "target"), 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("target", filepath.Join(parentPath, "OpenDuck")); err != nil {
				t.Fatal(err)
			}
		}, expectedUID: os.Getuid()},
		{name: "group writable", prepare: func(t *testing.T, parentPath string) {
			path := filepath.Join(parentPath, "OpenDuck")
			if err := os.Mkdir(path, 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(path, 0730); err != nil {
				t.Fatal(err)
			}
		}, expectedUID: os.Getuid()},
		{name: "special mode", prepare: func(t *testing.T, parentPath string) {
			path := filepath.Join(parentPath, "OpenDuck")
			if err := os.Mkdir(path, 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(path, 0711|os.ModeSticky); err != nil {
				t.Fatal(err)
			}
		}, expectedUID: os.Getuid()},
		{name: "wrong owner policy", prepare: func(t *testing.T, parentPath string) {
			if err := os.Mkdir(filepath.Join(parentPath, "OpenDuck"), 0700); err != nil {
				t.Fatal(err)
			}
		}, expectedUID: os.Getuid() + 1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			parentPath := t.TempDir()
			tc.prepare(t, parentPath)
			parent, err := os.OpenRoot(parentPath)
			if err != nil {
				t.Fatal(err)
			}
			defer parent.Close()
			root, err := openOrNormalizeInstallRoot(parent, "OpenDuck", tc.expectedUID, os.Getgid())
			if root != nil {
				root.Close()
			}
			if err == nil {
				t.Fatal("unsafe existing object accepted")
			}
		})
	}
}

func TestApplyEnforcesExactModesUnderRestrictiveUmask(t *testing.T) {
	i, root := fixture(t)
	old := syscall.Umask(0077)
	defer syscall.Umask(old)
	if err := i.Apply(); err != nil {
		t.Fatal(err)
	}
	for path, mode := range map[string]os.FileMode{"channels": 0711, "checkpoint-channel": 0711, "channels/platform-anchor": 0750, "launchd/com.openduck.anchor.plist": 0644, "releases/codex/" + i.cfg.ReleaseID: 0755, ".openduck-installer": 0700} {
		st, err := os.Lstat(filepath.Join(root, path))
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		if st.Mode().Perm() != mode {
			t.Fatalf("%s mode=%v", path, st.Mode().Perm())
		}
	}
}

func TestChannelTraversalParentsPermitOnlyTraversalToPrivateChildren(t *testing.T) {
	i, root := fixture(t)
	if err := i.Apply(); err != nil {
		t.Fatal(err)
	}
	if err := i.verifyChannelTraversalRoots(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, parent := range []string{"channels", "checkpoint-channel"} {
		info, err := os.Lstat(filepath.Join(root, parent))
		if err != nil || info.Mode().Perm() != 0711 {
			t.Fatalf("%s traversal parent metadata: info=%v err=%v", parent, info, err)
		}
		// A service principal that is neither root nor wheel receives only the
		// "other" execute bit: it can traverse but cannot list or write the
		// shared parent.
		if !posixDirectoryAccess(info.Mode().Perm(), 0, 0, 501, []uint32{501}, 1) || posixDirectoryAccess(info.Mode().Perm(), 0, 0, 501, []uint32{501}, 4) || posixDirectoryAccess(info.Mode().Perm(), 0, 0, 501, []uint32{501}, 2) {
			t.Fatalf("%s does not implement traversal-only access", parent)
		}
	}
	child, err := os.Lstat(filepath.Join(root, "channels", "platform-anchor"))
	if err != nil || child.Mode().Perm() != 0750 {
		t.Fatalf("private channel metadata: info=%v err=%v", child, err)
	}
	// The designated channel group may list/traverse its child, while a
	// principal outside that group is denied despite being able to traverse the
	// top-level parent.
	if !posixDirectoryAccess(child.Mode().Perm(), 100, 200, 501, []uint32{200}, 5) || posixDirectoryAccess(child.Mode().Perm(), 100, 200, 501, []uint32{501}, 1) {
		t.Fatal("private child access does not remain group-scoped")
	}
	if err := os.Chmod(filepath.Join(root, "channels"), 0750); err != nil {
		t.Fatal(err)
	}
	if err := i.verifyChannelTraversalRoots(context.Background()); err == nil {
		t.Fatal("non-traversable shared channel parent accepted")
	}
}

// posixDirectoryAccess is a small deterministic POSIX permission simulation
// for the mode/ownership contract above. It avoids mutating the test process'
// effective UID/GID while checking the exact owner/group/other bit selection.
func posixDirectoryAccess(mode os.FileMode, ownerUID, ownerGID, subjectUID uint32, subjectGroups []uint32, requested os.FileMode) bool {
	class := (mode.Perm() >> 0) & 0o7
	if subjectUID == ownerUID {
		class = (mode.Perm() >> 6) & 0o7
	} else {
		for _, group := range subjectGroups {
			if group == ownerGID {
				class = (mode.Perm() >> 3) & 0o7
				break
			}
		}
	}
	return class&requested == requested
}

func TestValidateStagedSnapshotMatchesShellLayout(t *testing.T) {
	stage := t.TempDir()
	writeStagedFixture(t, stage)
	if err := validateStagedSnapshot(stage); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(filepath.Join(stage, "bin/openduck-anchor"), filepath.Join(stage, "bin/extra-link")); err != nil {
		t.Fatal(err)
	}
	if err := validateStagedSnapshot(stage); err == nil {
		t.Fatal("hard-linked staged artifact accepted")
	}
}

func fixture(t *testing.T) (*Installer, string) {
	t.Helper()
	root := t.TempDir()
	src := t.TempDir()
	if err := os.WriteFile(filepath.Join(src, "openduck"), []byte("offline-binary"), 0755); err != nil {
		t.Fatal(err)
	}
	i, err := newFakeInstaller(root, "release-20260823", src)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		for _, s := range services {
			_ = os.Chmod(filepath.Join(root, "releases", s.Name, i.cfg.ReleaseID), 0700)
			_ = os.Chmod(filepath.Join(root, "releases", s.Name), 0700)
		}
		_ = os.Chmod(filepath.Join(root, "releases", "anchor-checkpoint", i.cfg.ReleaseID), 0700)
		_ = os.Chmod(filepath.Join(root, "releases", "anchor-checkpoint"), 0700)
		_ = i.Close()
	})
	return i, root
}

func upgradeInstaller(t *testing.T, current *Installer, root, releaseID string) *Installer {
	t.Helper()
	for _, service := range services {
		parent := filepath.Join(root, "releases", service.Name)
		if err := os.Chmod(parent, 0750); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(filepath.Join(parent, releaseID), 0750); err != nil && !errors.Is(err, os.ErrExist) {
			t.Fatal(err)
		}
		if err := os.Chmod(parent, 0550); err != nil {
			t.Fatal(err)
		}
	}
	anchorParent := filepath.Join(root, "releases", "anchor-checkpoint")
	if err := os.Chmod(anchorParent, 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(anchorParent, releaseID), 0750); err != nil && !errors.Is(err, os.ErrExist) {
		t.Fatal(err)
	}
	if err := os.Chmod(anchorParent, 0550); err != nil {
		t.Fatal(err)
	}
	next, err := newFakeInstaller(root, releaseID, current.cfg.BinaryDir)
	if err != nil {
		t.Fatal(err)
	}
	next.ops = current.ops
	t.Cleanup(func() {
		for _, service := range services {
			_ = os.Chmod(filepath.Join(root, "releases", service.Name, releaseID), 0700)
			_ = os.Chmod(filepath.Join(root, "releases", service.Name), 0700)
		}
		_ = os.Chmod(filepath.Join(root, "releases", "anchor-checkpoint", releaseID), 0700)
		_ = os.Chmod(filepath.Join(root, "releases", "anchor-checkpoint"), 0700)
		_ = next.Close()
	})
	return next
}

type lateApplyFailureOps struct {
	SystemOps
	onFailure func()
	failed    bool
}

func (o *lateApplyFailureOps) Chown(ctx context.Context, path, user, group string) error {
	if !o.failed && strings.HasSuffix(path, "/.openduck-installer") {
		o.failed = true
		if o.onFailure != nil {
			o.onFailure()
		}
		return errors.New("injected late Apply ownership failure")
	}
	return o.SystemOps.Chown(ctx, path, user, group)
}

func installLegacySharedPolicies(t *testing.T, root string) map[string][]byte {
	t.Helper()
	legacy := map[string][]byte{
		"pf/openduck.conf": []byte(legacyPFRules),
		"seatbelt/state":   []byte(legacyPFRules),
	}
	for path, raw := range legacy {
		if err := os.WriteFile(filepath.Join(root, path), raw, 0644); err != nil {
			t.Fatal(err)
		}
	}
	return legacy
}
func TestPlanHasSixPrincipalsAndDisabledPlists(t *testing.T) {
	i, _ := fixture(t)
	p := i.Plan()
	if len(p.Users) != 6 || len(p.Plists) != 6 {
		t.Fatalf("plan=%+v", p)
	}
	for _, s := range services {
		found := false
		for _, u := range p.Users {
			if u == s.User {
				found = true
			}
		}
		if !found {
			t.Fatalf("missing %s", s.User)
		}
	}
}

func TestPlanDeclaresFixedJournalAuthorityTopology(t *testing.T) {
	i, _ := fixture(t)
	p := i.Plan()
	groups := make(map[string]bool, len(p.Groups))
	for _, group := range p.Groups {
		groups[group] = true
	}
	for _, group := range []string{"_openduck_installer_checkpoint_channel", "_openduck_installer_anchor_channel"} {
		if !groups[group] {
			t.Fatalf("journal channel group is not planned: %s", group)
		}
	}
	paths := make(map[string]bool, len(p.Paths))
	for _, path := range p.Paths {
		paths[path] = true
	}
	for _, path := range []string{
		"channels/installer-checkpoint", "channels/installer-anchor",
		"releases/checkpoint-installer", "releases/checkpoint-installer/" + i.cfg.ReleaseID,
		"releases/anchor-installer", "releases/anchor-installer/" + i.cfg.ReleaseID,
		"releases/installer-checkpoint", "releases/installer-checkpoint/" + i.cfg.ReleaseID,
		"releases/installer-anchor", "releases/installer-anchor/" + i.cfg.ReleaseID,
	} {
		if !paths[path] {
			t.Fatalf("journal topology path is not planned: %s", path)
		}
	}
}
func TestApplyIsIdempotentAndVerify(t *testing.T) {
	i, root := fixture(t)
	if err := i.Apply(); err != nil {
		t.Fatal(err)
	}
	if err := i.FinalizePFEvidence(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := i.Verify(); err != nil {
		t.Fatal(err)
	}
	if err := i.Apply(); err != nil {
		t.Fatal(err)
	}
	for _, s := range services {
		label := serviceLabel(s.Name)
		b, err := os.ReadFile(filepath.Join(root, "launchd", "com.openduck."+label+".plist"))
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(b), "<key>Disabled</key><true/>") {
			t.Fatalf("enabled plist %s", s.Name)
		}
	}
}

func TestApplyKeepsActivePointerUntilActivationCommit(t *testing.T) {
	i, root := fixture(t)
	if err := i.Apply(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(root, "active.release")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Apply published active.release: %v", err)
	}
	for _, path := range []string{"candidate.release", "configured.release"} {
		got, err := os.ReadFile(filepath.Join(root, path))
		if err != nil || string(got) != i.cfg.ReleaseID+"\n" {
			t.Fatalf("%s=%q err=%v", path, got, err)
		}
	}
	if err := i.Activate(context.Background()); err != nil {
		t.Fatal(err)
	}
	if i.journal == nil || !i.journal.Protected() {
		t.Fatal("activation published pointers without a protected journal")
	}
	if _, err := os.Lstat(filepath.Join(root, "state", "controller", "provisioning", i.runID, "checkpoint.json")); err != nil {
		t.Fatalf("activation did not persist protected checkpoint: %v", err)
	}
	active, err := os.ReadFile(filepath.Join(root, "active.release"))
	if err != nil || string(active) != i.cfg.ReleaseID+"\n" {
		t.Fatalf("activation did not publish active pointer: %q err=%v", active, err)
	}
}

func TestActivateRecoveryStartsAuthoritiesPromotesThenPublishesPointer(t *testing.T) {
	i, root := fixture(t)
	if err := i.Apply(); err != nil {
		t.Fatal(err)
	}
	// This models a crash after a previously valid activation had already
	// promoted the chain, rather than allowing recovery to forge protection.
	if err := i.promoteJournal(); err != nil {
		t.Fatal(err)
	}
	// Simulate process death after immutable marker/activated state but before
	// the final active.release pointer commit.
	if err := i.writeActivatedMarker(i.cfg.ReleaseID); err != nil {
		t.Fatal(err)
	}
	if err := i.writeReleaseState("activated.release", i.cfg.ReleaseID); err != nil {
		t.Fatal(err)
	}
	if err := i.Activate(context.Background()); err != nil {
		t.Fatal(err)
	}
	f := i.ops.(*fakeSystemOps)
	for _, label := range []string{"checkpoint", "anchor"} {
		if !f.loaded["com.openduck."+label] || !f.booted["com.openduck."+label] {
			t.Fatalf("recovery did not start and verify journal authority %s", label)
		}
	}
	for _, label := range []string{"egress", "codex-runtime", "codex-broker", "controller"} {
		if f.loaded["com.openduck."+label] || f.booted["com.openduck."+label] {
			t.Fatalf("recovery started non-authority service %s", label)
		}
	}
	if i.journal == nil || !i.journal.Protected() {
		t.Fatal("recovery published a pointer without protected journal evidence")
	}
	active, err := os.ReadFile(filepath.Join(root, "active.release"))
	if err != nil || string(active) != i.cfg.ReleaseID+"\n" {
		t.Fatalf("pointer recovery=%q err=%v", active, err)
	}
	if _, err := os.Lstat(filepath.Join(root, "activation.intent")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("recovery left intent: %v", err)
	}
}

func TestActivationRecoveryOutageDoesNotPublishPointer(t *testing.T) {
	i, root := fixture(t)
	if err := i.Apply(); err != nil {
		t.Fatal(err)
	}
	if err := i.writeActivatedMarker(i.cfg.ReleaseID); err != nil {
		t.Fatal(err)
	}
	if err := i.writeReleaseState("activated.release", i.cfg.ReleaseID); err != nil {
		t.Fatal(err)
	}
	i.journalAuthority = &journalFakeAuthority{deny: true}
	if err := i.Activate(context.Background()); err == nil {
		t.Fatal("recovery accepted protected-authority outage")
	}
	if _, err := os.Lstat(filepath.Join(root, "active.release")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("authority outage published active pointer: %v", err)
	}
	if i.journal != nil && i.journal.Protected() {
		t.Fatal("authority outage marked recovery journal protected")
	}
}

func TestActivateOutageBlocksMarkerAndPointers(t *testing.T) {
	i, root := fixture(t)
	if err := i.Apply(); err != nil {
		t.Fatal(err)
	}
	// Keep the fake installer wiring valid while making the journal's live
	// authority unavailable at the explicit seal gate.
	i.journal.authority = &journalFakeAuthority{deny: true}
	if err := i.Activate(context.Background()); err == nil {
		t.Fatal("activation accepted an authority outage")
	}
	for _, path := range []string{"active.release", "activated.release", "releases/controller/" + i.cfg.ReleaseID + "/activated"} {
		if _, err := os.Lstat(filepath.Join(root, path)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("outage published %s: %v", path, err)
		}
	}
}

func TestApplyAtomicallyMigratesLegacySharedPolicies(t *testing.T) {
	if len(legacyPFRules) != 339 || len(fixedPFRules) != 355 {
		t.Fatalf("unexpected PF migration fixture lengths: old=%d new=%d", len(legacyPFRules), len(fixedPFRules))
	}
	i, root := fixture(t)
	if err := i.Apply(); err != nil {
		t.Fatal(err)
	}
	installLegacySharedPolicies(t, root)
	if err := i.Apply(); err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string]string{"pf/openduck.conf": fixedPFRules, "seatbelt/state": fixedPFRules, "seatbelt/codex.sb": fixedCodexSeatbelt, "seatbelt/egress.sb": fixedEgressSeatbelt} {
		got, err := os.ReadFile(filepath.Join(root, path))
		if err != nil || !bytes.Equal(got, []byte(want)) {
			t.Fatalf("shared policy %s was not migrated: %v", path, err)
		}
	}
}

func TestFailedApplyRestoresLegacyPoliciesAndRemovedMarkersExactly(t *testing.T) {
	i, root := fixture(t)
	if err := i.Apply(); err != nil {
		t.Fatal(err)
	}
	legacy := installLegacySharedPolicies(t, root)
	markers := map[string][]byte{"pending.rollback": []byte("legacy-pending\n"), "previous.release": []byte("legacy-previous\n")}
	for path, raw := range markers {
		if err := os.WriteFile(filepath.Join(root, path), raw, 0644); err != nil {
			t.Fatal(err)
		}
	}
	i.ops = &lateApplyFailureOps{SystemOps: i.ops}
	err := i.Apply()
	if err == nil || !strings.Contains(err.Error(), "injected late Apply ownership failure") {
		t.Fatalf("late Apply failure not returned: %v", err)
	}
	for path, want := range legacy {
		got, readErr := os.ReadFile(filepath.Join(root, path))
		if readErr != nil || !bytes.Equal(got, want) {
			t.Fatalf("legacy policy %s not restored exactly: %v", path, readErr)
		}
	}
	for path, want := range markers {
		got, readErr := os.ReadFile(filepath.Join(root, path))
		if readErr != nil || !bytes.Equal(got, want) {
			t.Fatalf("removed marker %s not restored exactly: %v", path, readErr)
		}
	}
}

func TestApplyCompensationFailureIsManualReview(t *testing.T) {
	i, root := fixture(t)
	if err := i.Apply(); err != nil {
		t.Fatal(err)
	}
	installLegacySharedPolicies(t, root)
	pfDir := filepath.Join(root, "pf")
	i.ops = &lateApplyFailureOps{SystemOps: i.ops, onFailure: func() { _ = os.Chmod(pfDir, 0500) }}
	err := i.Apply()
	_ = os.Chmod(pfDir, 0700)
	var tx *ProvisioningTransactionError
	if err == nil || !errors.As(err, &tx) || !strings.Contains(err.Error(), "apply compensation failed") || safeReasonCode(err) != ErrorReasonProvisioningFailed {
		t.Fatalf("Apply compensation failure classification=%q err=%v", safeReasonCode(err), err)
	}
	var safe ProvisioningError
	if jsonErr := json.Unmarshal(SafeProvisioningError([]string{"--apply", "--error-json"}, err), &safe); jsonErr != nil || safe.ReasonCode != ErrorReasonProvisioningFailed || safe.PrimaryReasonCode != ErrorReasonProvisioningFailed || safe.CompensationReasonCode != ErrorReasonApplyRestoreFailed || safe.RecoveryState != "manual_review" {
		t.Fatalf("unsafe Apply recovery classification: %+v jsonErr=%v", safe, jsonErr)
	}
}

func TestApplyRejectsUnsafeSharedPolicyMetadataWithClosedReason(t *testing.T) {
	i, root := fixture(t)
	if err := i.Apply(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "pf", "openduck.conf")
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	err := i.Apply()
	if err == nil || safeReasonCode(err) != ErrorReasonPolicyUpgradeFailed {
		t.Fatalf("unsafe shared policy classification=%q err=%v", safeReasonCode(err), err)
	}
}

func TestApplyRejectsUnknownSharedPolicyContentWithoutChangingIt(t *testing.T) {
	for _, path := range []string{"pf/openduck.conf", "seatbelt/state", "seatbelt/codex.sb", "seatbelt/egress.sb"} {
		t.Run(strings.ReplaceAll(path, "/", "-"), func(t *testing.T) {
			i, root := fixture(t)
			if err := i.Apply(); err != nil {
				t.Fatal(err)
			}
			unknown := []byte("unknown-but-safe-metadata-policy\n")
			full := filepath.Join(root, path)
			if err := os.WriteFile(full, unknown, 0644); err != nil {
				t.Fatal(err)
			}
			err := i.Apply()
			if err == nil || safeReasonCode(err) != ErrorReasonPolicyUpgradeFailed {
				t.Fatalf("unknown content classification=%q err=%v", safeReasonCode(err), err)
			}
			got, readErr := os.ReadFile(full)
			if readErr != nil || !bytes.Equal(got, unknown) {
				t.Fatalf("unknown content was modified: %q err=%v", got, readErr)
			}
			st, statErr := os.Lstat(full)
			if statErr != nil || st.Mode().Perm() != 0644 {
				t.Fatalf("unknown content metadata changed: %v", statErr)
			}
		})
	}
}

func TestFreshApplyAllowsBothPFPinnedPlistsToRemainPending(t *testing.T) {
	for _, service := range []string{"broker", "runtime"} {
		if !pendingPFPlistAllowed(service, true) {
			t.Fatalf("fresh apply did not allow pending %s plist", service)
		}
		if pendingPFPlistAllowed(service, false) {
			t.Fatalf("final ownership verification allowed pending %s plist", service)
		}
	}
	if pendingPFPlistAllowed("egress", true) {
		t.Fatal("non-PF-pinned plist was allowed to remain missing")
	}
}

func TestLoadedOldJobRequiresStopBeforeApplyFinalizeOrActivateWithoutMutation(t *testing.T) {
	for _, operation := range []string{"apply", "finalize", "activate"} {
		t.Run(operation, func(t *testing.T) {
			current, root := fixture(t)
			if err := current.Apply(); err != nil {
				t.Fatal(err)
			}
			activeBefore, _ := os.ReadFile(filepath.Join(root, "active.release"))
			policyBefore, _ := os.ReadFile(filepath.Join(root, "pf", "egress-policy.json"))
			treeBefore := snapshotInstalledTree(t, root)
			f := current.ops.(*fakeSystemOps)
			f.loaded["com.openduck.anchor"] = true
			f.pfLoaded = true
			var err error
			switch operation {
			case "apply":
				next, openErr := newFakeInstaller(root, "release-20260824", current.cfg.BinaryDir)
				if openErr != nil {
					t.Fatal(openErr)
				}
				next.ops = f
				err = next.Apply()
				_ = next.Close()
			case "finalize":
				err = current.FinalizePFEvidence(context.Background())
			case "activate":
				err = current.Activate(context.Background())
			}
			if err == nil || !strings.Contains(err.Error(), "STOP_REQUIRED") {
				t.Fatalf("loaded job did not stop %s: %v", operation, err)
			}
			activeAfter, _ := os.ReadFile(filepath.Join(root, "active.release"))
			policyAfter, _ := os.ReadFile(filepath.Join(root, "pf", "egress-policy.json"))
			if !bytes.Equal(activeBefore, activeAfter) || !bytes.Equal(policyBefore, policyAfter) || !reflect.DeepEqual(treeBefore, snapshotInstalledTree(t, root)) || !f.pfLoaded || f.pfUnloadCount != 0 || !f.loaded["com.openduck.anchor"] {
				t.Fatalf("%s mutated active release, policy, PF, or job state", operation)
			}
			if _, statErr := os.Lstat(filepath.Join(root, "releases", "anchor", "release-20260824")); !errors.Is(statErr, os.ErrNotExist) {
				t.Fatalf("%s created new release before STOP_REQUIRED", operation)
			}
		})
	}
}

func TestLoadedDisabledJobIsAContradictionBeforeMutation(t *testing.T) {
	current, _ := fixture(t)
	f := current.ops.(*fakeSystemOps)
	f.loaded["com.openduck.anchor"] = true
	f.booted["disabled:com.openduck.anchor"] = true
	if err := current.requireJobsUnloaded(context.Background()); err == nil || !strings.Contains(err.Error(), "contradictory launchd state") {
		t.Fatalf("contradictory state was not rejected: %v", err)
	}
}
func TestSymlinkPreflightRejected(t *testing.T) {
	i, root := fixture(t)
	target := t.TempDir()
	if err := os.Symlink(target, filepath.Join(root, "state")); err != nil {
		t.Fatal(err)
	}
	if err := i.Apply(); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("err=%v", err)
	}
}

func TestSpecialBitsPreflightRejected(t *testing.T) {
	i, root := fixture(t)
	if err := os.Mkdir(filepath.Join(root, "state"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(root, "state"), 0700|os.ModeSetgid); err != nil {
		t.Fatal(err)
	}
	st, err := os.Lstat(filepath.Join(root, "state"))
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode()&os.ModeSetgid == 0 {
		t.Skip("test filesystem did not retain setgid metadata")
	}
	if err := i.Apply(); err == nil || !strings.Contains(err.Error(), "special bits") {
		t.Fatalf("err=%v", err)
	}
}
func TestRollbackRetainsState(t *testing.T) {
	i, root := fixture(t)
	if err := i.Apply(); err != nil {
		t.Fatal(err)
	}
	if err := i.Stop(); err != nil {
		t.Fatal(err)
	}
	for _, s := range services {
		if !i.ops.(*fakeSystemOps).booted["disabled:com.openduck."+serviceLabel(s.Name)] {
			t.Fatalf("stop did not disable %s", s.Name)
		}
	}
	if err := i.Rollback(); err == nil {
		t.Fatal("rollback without verified previous release must fail")
	}
	if _, err := os.Stat(filepath.Join(root, "state", "anchor")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "keys", "anchor", "service.key")); err != nil {
		t.Fatal(err)
	}
}

func TestPrincipalJournalRemovesOnlyCreatedObjectsOnFailure(t *testing.T) {
	i, _ := fixture(t)
	f := i.ops.(*fakeSystemOps)
	// A pre-existing group and membership must survive a failed transaction.
	f.groups["_openduck"] = true
	f.users["_openduck"] = true
	f.members["_openduck_channel:_openduck"] = true
	f.failAt = "member:_openduck_egress_channel:_openduck_broker"
	f.failErr = errors.New("/usr/bin/dscl args=[redacted] failed: exit status 40")
	if err := i.provisionPrincipals(context.Background()); err == nil || !strings.Contains(err.Error(), "exit status 40") {
		t.Fatalf("expected injected dscl failure, got %v", err)
	}
	i.rollbackPrincipals(context.Background())
	if !f.groups["_openduck"] || !f.users["_openduck"] || !f.members["_openduck_channel:_openduck"] {
		t.Fatal("pre-existing principal state was removed")
	}
	if f.groups["_openduck_anchor"] || f.users["_openduck_anchor"] || f.members["_openduck_channel:_openduck_anchor"] {
		t.Fatal("created state was not rolled back")
	}
}

func TestApplyReturnsMembershipFailureAndRollsBackOnlyCurrentAdditions(t *testing.T) {
	i, _ := fixture(t)
	f := i.ops.(*fakeSystemOps)
	f.groups["_openduck"] = true
	f.users["_openduck"] = true
	f.members["_openduck_channel:_openduck"] = true
	f.failAt = "member:_openduck_egress_channel:_openduck_broker"
	f.failErr = errors.New("/usr/bin/dscl args=[redacted] failed: exit status 40")

	err := i.Apply()
	if err == nil || !strings.Contains(err.Error(), "exit status 40") {
		t.Fatalf("Apply did not preserve the production failure: %v", err)
	}
	if !f.groups["_openduck"] || !f.users["_openduck"] || !f.members["_openduck_channel:_openduck"] {
		t.Fatal("Apply rollback removed pre-existing principal state")
	}
	if f.groups["_openduck_anchor"] || f.users["_openduck_anchor"] || f.members["_openduck_channel:_openduck_anchor"] {
		t.Fatal("Apply rollback retained principal state created by the failed transaction")
	}
}
func TestRenderPlistIsDisabledAndExactUsers(t *testing.T) {
	for _, s := range services {
		p := renderPlist(s, "r")
		if !strings.Contains(p, "<key>UserName</key><string>"+s.User+"</string>") || !strings.Contains(p, "<key>GroupName</key><string>"+s.Group+"</string>") {
			t.Fatal(s.Name)
		}
		if !strings.Contains(p, "<key>Disabled</key><true/>") {
			t.Fatal("not disabled")
		}
	}
}

func TestAllStaticPlistsMatchCanonicalRenderer(t *testing.T) {
	for _, service := range services {
		label := serviceLabel(service.Name)
		path := filepath.Join("..", "..", "deploy", "macos", "com.openduck."+label+".plist")
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		want := renderPlist(service, "RELEASE_ID")
		if string(got) != want {
			t.Fatalf("static plist drift: %s", label)
		}
	}
}

func TestRenderPlistUsesCanonicalBinaryPathsAndFlags(t *testing.T) {
	for _, s := range services {
		p := renderPlist(s, "release-20260823")
		name := s.Name
		if name == "broker" {
			name = "codex-broker"
		} else if name == "runtime" {
			name = "codex-runtime"
		}
		if !strings.Contains(p, SystemRoot+"/releases/"+s.Name+"/release-20260823/openduck-"+name) {
			t.Fatalf("binary path %s", s.Name)
		}
		if !strings.Contains(p, "<key>Disabled</key><true/>") || !strings.Contains(p, "<key>RunAtLoad</key><false/>") {
			t.Fatalf("lifecycle %s", s.Name)
		}
		for _, flag := range map[string][]string{"checkpoint": {"-state", "-socket-root", "-key-root", "-release-root", "-journal-socket-root", "-journal-socket", "-journal-key-root", "-journal-key-file", "-journal-release-root", "-journal-local-role", "-journal-peer-role", "-journal-local-release", "-journal-local-binary-digest", "-journal-local-socket-digest", "-journal-local-manifest-digest", "-journal-peer-release", "-journal-peer-binary-digest", "-journal-peer-socket-digest", "-journal-peer-manifest-digest", "-journal-peer-uid", "-journal-peer-gid", "-journal-channel-gid"}, "anchor": {"-state", "-socket-root", "-checkpoint-release-root", "-channel", "-journal-socket-root", "-journal-socket", "-journal-key-root", "-journal-key-file", "-journal-release-root", "-journal-local-role", "-journal-peer-role", "-journal-local-release", "-journal-local-binary-digest", "-journal-local-socket-digest", "-journal-local-manifest-digest", "-journal-peer-release", "-journal-peer-binary-digest", "-journal-peer-socket-digest", "-journal-peer-manifest-digest", "-journal-peer-uid", "-journal-peer-gid", "-journal-channel-gid"}, "egress": {"-production-admission", "-policy", "-peer-uid", "-epoch"}, "broker": {"-production-admission", "-runtime-channel", "-runtime-local-release", "-runtime-uid", "-egress-uid"}, "runtime": {"-production-admission", "-codex-release-root", "-codex-binary-name", "-codex-home", "-runtime-channel", "-key-epoch"}, "controller": {"-production-admission", "-anchor-socket", "-controller-release-root", "-anchor-key-epoch"}}[s.Name] {
			if !strings.Contains(p, "<string>"+flag+"</string>") {
				t.Fatalf("flag %s %s", s.Name, flag)
			}
		}
		if s.Name == "checkpoint" {
			for _, value := range []string{SystemRoot + "/channels/installer-checkpoint", SystemRoot + "/keys/checkpoint-installer", SystemRoot + "/releases/checkpoint-installer/release-20260823", "checkpoint", "installer"} {
				if !strings.Contains(p, "<string>"+value+"</string>") {
					t.Fatalf("checkpoint journal value %q", value)
				}
			}
		}
		if s.Name == "anchor" {
			for _, value := range []string{SystemRoot + "/channels/installer-anchor", SystemRoot + "/keys/anchor-installer", SystemRoot + "/releases/anchor-installer/release-20260823", "anchor", "installer"} {
				if !strings.Contains(p, "<string>"+value+"</string>") {
					t.Fatalf("anchor journal value %q", value)
				}
			}
		}
	}
}

func TestChannelKeyCopiesAreIdentical(t *testing.T) {
	i, root := fixture(t)
	if err := i.Apply(); err != nil {
		t.Fatal(err)
	}
	for _, group := range [][]string{{"anchor/service.key", "controller/service.key", "controller-anchor/service.key"}, {"anchor-checkpoint/checkpoint.key", "checkpoint/service.key"}} {
		var first []byte
		for n, p := range group {
			b, e := os.ReadFile(filepath.Join(root, "keys", p))
			if e != nil {
				t.Fatal(e)
			}
			if n == 0 {
				first = b
			} else if string(first) != string(b) {
				t.Fatalf("key copy differs: %s", p)
			}
		}
	}
	for _, pair := range [][]string{{"egress/service.key", "broker-egress/service.key"}, {"broker-controller/service.key", "controller-broker/service.key"}, {"runtime/service.key", "broker-runtime/service.key"}} {
		a, _ := os.ReadFile(filepath.Join(root, "keys", pair[0]))
		b, _ := os.ReadFile(filepath.Join(root, "keys", pair[1]))
		if string(a) != string(b) {
			t.Fatalf("endpoint pair differs: %v", pair)
		}
	}
	for pi, a := range []string{"egress/service.key", "broker-controller/service.key", "runtime/service.key"} {
		for pj, b := range []string{"broker-egress/service.key", "controller-broker/service.key", "broker-runtime/service.key"} {
			if pi == pj {
				continue
			}
			x, _ := os.ReadFile(filepath.Join(root, "keys", a))
			y, _ := os.ReadFile(filepath.Join(root, "keys", b))
			if string(x) == string(y) {
				t.Fatalf("cross-endpoint key reused: %s %s", a, b)
			}
		}
	}
}

func TestJournalAuthorityTopologyIsPinnedAndPhysicallyDisjoint(t *testing.T) {
	i, root := fixture(t)
	if err := i.Apply(); err != nil {
		t.Fatal(err)
	}
	if err := i.verifyJournalTopology(); err != nil {
		t.Fatalf("fixed journal topology did not verify: %v", err)
	}
	paths := []string{
		"releases/checkpoint-installer/" + i.cfg.ReleaseID,
		"releases/anchor-installer/" + i.cfg.ReleaseID,
		"releases/installer-checkpoint/" + i.cfg.ReleaseID,
		"releases/installer-anchor/" + i.cfg.ReleaseID,
		"channels/installer-checkpoint", "channels/installer-anchor",
		"keys/checkpoint-installer", "keys/installer-checkpoint", "keys/anchor-installer", "keys/installer-anchor",
	}
	infos := make([]os.FileInfo, 0, len(paths))
	for _, path := range paths {
		info, err := os.Lstat(filepath.Join(root, path))
		if err != nil {
			t.Fatal(err)
		}
		infos = append(infos, info)
	}
	for left := range infos {
		for right := left + 1; right < len(infos); right++ {
			if sameFileIdentity(infos[left], infos[right]) {
				t.Fatalf("journal descriptor roots overlap: %s and %s", paths[left], paths[right])
			}
		}
	}
	for _, pair := range [][]string{{"checkpoint-installer/journal.key", "installer-checkpoint/journal.key"}, {"anchor-installer/journal.key", "installer-anchor/journal.key"}} {
		first, err := os.ReadFile(filepath.Join(root, "keys", pair[0]))
		if err != nil || !validCanonicalServiceKey(first, "installer-journal", 1) {
			t.Fatalf("invalid journal key %s: %v", pair[0], err)
		}
		second, err := os.ReadFile(filepath.Join(root, "keys", pair[1]))
		if err != nil || !bytes.Equal(first, second) {
			t.Fatalf("journal key copies differ: %v err=%v", pair, err)
		}
	}
	checkpointKey, err := os.ReadFile(filepath.Join(root, "keys", "checkpoint-installer", "journal.key"))
	if err != nil {
		t.Fatal(err)
	}
	anchorKey, err := os.ReadFile(filepath.Join(root, "keys", "anchor-installer", "journal.key"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(checkpointKey, anchorKey) {
		t.Fatal("checkpoint and anchor journal channels reused one service key")
	}
}

func TestJournalAuthorityTopologyRejectsDescriptorReuseAndPinDrift(t *testing.T) {
	t.Run("socket root overlap", func(t *testing.T) {
		i, root := fixture(t)
		if err := i.Apply(); err != nil {
			t.Fatal(err)
		}
		anchor := filepath.Join(root, "channels", "installer-anchor")
		if err := os.Remove(anchor); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("installer-checkpoint", anchor); err != nil {
			t.Fatal(err)
		}
		if err := i.verifyJournalTopology(); err == nil {
			t.Fatal("overlapping journal socket roots were accepted")
		}
	})
	t.Run("channel key reuse", func(t *testing.T) {
		i, root := fixture(t)
		if err := i.Apply(); err != nil {
			t.Fatal(err)
		}
		reused, err := os.ReadFile(filepath.Join(root, "keys", "checkpoint-installer", "journal.key"))
		if err != nil {
			t.Fatal(err)
		}
		for _, path := range []string{"anchor-installer/journal.key", "installer-anchor/journal.key"} {
			if err := os.WriteFile(filepath.Join(root, "keys", path), reused, 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(filepath.Join(root, "keys", path), 0600); err != nil {
				t.Fatal(err)
			}
		}
		if err := i.verifyJournalTopology(); err == nil {
			t.Fatal("reused journal key accepted")
		}
	})
	t.Run("descriptor pin drift", func(t *testing.T) {
		i, root := fixture(t)
		if err := i.Apply(); err != nil {
			t.Fatal(err)
		}
		manifest := filepath.Join(root, "releases", "installer-checkpoint", i.cfg.ReleaseID, "manifest.json")
		if err := os.Chmod(manifest, 0644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(manifest, []byte(`{"release_id":"`+i.cfg.ReleaseID+`","binary":"openduck-anchor","socket":"journal.sock","binary_digest":"`+strings.Repeat("0", 64)+`","socket_digest":"`+strings.Repeat("0", 64)+`"}\n`), 0644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(manifest, 0440); err != nil {
			t.Fatal(err)
		}
		if err := i.verifyJournalTopology(); err == nil {
			t.Fatal("wrong journal release role/pin accepted")
		}
	})
}

func TestCanonicalKeyTopologyCoversEveryOwnedKeyFile(t *testing.T) {
	created := make(map[string]int)
	for _, topology := range canonicalChannelKeyTopologies() {
		for _, path := range topology.paths {
			created[path]++
		}
	}
	owned := make(map[string]keyFileOwnership)
	for _, ownership := range canonicalServiceKeyOwnership() {
		if created[ownership.path] != 1 {
			t.Fatalf("owned key file is not created by channel topology: %s", ownership.path)
		}
		if previous, ok := owned[ownership.path]; ok && previous != ownership {
			t.Fatalf("conflicting key ownership: %s", ownership.path)
		}
		owned[ownership.path] = ownership
		if strings.Contains(ownership.path, "controller-runtime") {
			t.Fatalf("orphan controller-runtime key path remains owned: %s", ownership.path)
		}
	}
	if len(owned) != len(created) {
		t.Fatalf("key topology/ownership inventory differs: created=%d owned=%d", len(created), len(owned))
	}
	rootOwnership := make(map[string]keyRootOwnership)
	for _, ownership := range canonicalKeyRootOwnership() {
		if previous, ok := rootOwnership[ownership.path]; ok && previous != ownership {
			t.Fatalf("conflicting key-root ownership: %s", ownership.path)
		}
		rootOwnership[ownership.path] = ownership
		if strings.Contains(ownership.path, "controller-runtime") {
			t.Fatalf("orphan controller-runtime key root remains owned: %s", ownership.path)
		}
	}
	plan := (&Installer{cfg: Config{Root: "/tmp/openduck", ReleaseID: "release"}}).Plan()
	planned := make(map[string]bool, len(plan.Paths))
	for _, path := range plan.Paths {
		planned[path] = true
		if path == "keys/controller-runtime" {
			t.Fatal("orphan controller-runtime key root remains in plan")
		}
	}
	for path := range rootOwnership {
		if !planned[path] {
			t.Fatalf("owned key root is not planned: %s", path)
		}
	}
}

func TestEndpointReleasePinCopiesNameTheCorrectPrincipal(t *testing.T) {
	i, root := fixture(t)
	if err := i.Apply(); err != nil {
		t.Fatal(err)
	}
	for path, service := range map[string]string{
		"releases/egress/" + i.cfg.ReleaseID + "/local-release.json":      "egress",
		"releases/egress/" + i.cfg.ReleaseID + "/peer-release.json":       "broker",
		"releases/broker/" + i.cfg.ReleaseID + "/local-release.json":      "broker",
		"releases/broker/" + i.cfg.ReleaseID + "/egress-release.json":     "egress",
		"releases/broker/" + i.cfg.ReleaseID + "/runtime-release.json":    "runtime",
		"releases/broker/" + i.cfg.ReleaseID + "/controller-release.json": "controller",
		"releases/controller/" + i.cfg.ReleaseID + "/local-release.json":  "controller",
		"releases/controller/" + i.cfg.ReleaseID + "/broker-release.json": "broker",
		"releases/runtime/" + i.cfg.ReleaseID + "/local-release.json":     "runtime",
		"releases/runtime/" + i.cfg.ReleaseID + "/broker-release.json":    "broker",
	} {
		raw, err := os.ReadFile(filepath.Join(root, path))
		if err != nil {
			t.Fatal(err)
		}
		var pin struct {
			BinaryDigest   string `json:"binary_digest"`
			ManifestDigest string `json:"manifest_digest"`
		}
		if json.Unmarshal(raw, &pin) != nil {
			t.Fatalf("invalid pin %s", path)
		}
		manifest, err := os.ReadFile(filepath.Join(root, "releases", service, i.cfg.ReleaseID, "manifest.json"))
		if err != nil || pin.ManifestDigest != Digest(manifest) {
			t.Fatalf("%s does not pin %s", path, service)
		}
	}
}

func TestChannelKeysUseCanonicalEpochAndRejectExistingMismatch(t *testing.T) {
	i, root := fixture(t)
	if err := i.Apply(); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(root, "keys", "anchor", "service.key")
	record, err := os.ReadFile(p)
	if err != nil || !validCanonicalServiceKey(record, "platform-anchor", 1) {
		t.Fatalf("canonical service key rejected: %v", err)
	}
	record[len(record)-1] ^= 1
	if err := os.WriteFile(p, record, 0600); err != nil {
		t.Fatal(err)
	}
	if err := i.Apply(); err == nil || !strings.Contains(err.Error(), "copies differ") {
		t.Fatalf("mismatched endpoint copy accepted: %v", err)
	}
}

func TestOwnerApprovalUsesAsymmetricDeploymentKeys(t *testing.T) {
	i, root := fixture(t)
	if err := i.Apply(); err != nil {
		t.Fatal(err)
	}
	private, err := os.ReadFile(filepath.Join(root, "operator/owner-ed25519.key"))
	if err != nil {
		t.Fatal(err)
	}
	public, err := os.ReadFile(filepath.Join(root, "keys/controller-anchor/owner.public"))
	if err != nil {
		t.Fatal(err)
	}
	if len(private) != 64 || len(public) != 32 || string(private[:32]) == string(public) {
		t.Fatal("invalid asymmetric owner key deployment")
	}
	p := renderPlist(Service{Name: "controller", User: "_openduck", Group: "_openduck"}, "r")
	if !strings.Contains(p, "<string>-owner-public-key-file</string>") || strings.Contains(p, "<string>-owner-key-file</string>") {
		t.Fatal("controller uses obsolete owner key contract")
	}
}

func TestAppliedPlistsContainNoUnresolvedPins(t *testing.T) {
	i, root := fixture(t)
	if err := i.Apply(); err != nil {
		t.Fatal(err)
	}
	if err := i.FinalizePFEvidence(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"checkpoint", "anchor", "egress", "controller", "codex-broker", "codex-runtime"} {
		b, e := os.ReadFile(filepath.Join(root, "launchd", "com.openduck."+n+".plist"))
		if e != nil {
			t.Fatal(e)
		}
		if strings.Contains(string(b), "_DIGEST") || strings.Contains(string(b), "_UID") || strings.Contains(string(b), "_GID") || strings.Contains(string(b), "MODEL_ID") {
			t.Fatalf("unresolved pins in %s", n)
		}
	}
}

func TestFinalizeRejectsWrongActiveReleaseBeforePFMutation(t *testing.T) {
	i, root := fixture(t)
	if err := i.Apply(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "active.release"), []byte("wrong-release\n"), 0644); err != nil {
		t.Fatal(err)
	}
	f := i.ops.(*fakeSystemOps)
	if err := i.FinalizePFEvidence(context.Background()); err == nil {
		t.Fatal("wrong active release accepted")
	}
	if f.pfLoaded || f.pfUnloadCount != 0 {
		t.Fatal("PF mutated before active release validation")
	}
}

func TestFinalizeRestoresExternalPlistsAndUnloadsPFOnInstallFailure(t *testing.T) {
	i, _ := fixture(t)
	if err := i.Apply(); err != nil {
		t.Fatal(err)
	}
	f := i.ops.(*fakeSystemOps)
	f.plists["com.openduck.anchor.plist"] = true
	f.failAt = "plist:com.openduck.codex-broker.plist"
	if err := i.FinalizePFEvidence(context.Background()); err == nil {
		t.Fatal("injected plist failure accepted")
	}
	if f.pfLoaded || f.pfUnloadCount != 1 {
		t.Fatal("PF mutation was not unwound")
	}
	if !f.plists["com.openduck.anchor.plist"] {
		t.Fatal("prior plist was not restored")
	}
	for _, s := range services {
		name := "com.openduck." + serviceLabel(s.Name) + ".plist"
		if name != "com.openduck.anchor.plist" && f.plists[name] {
			t.Fatalf("new external plist survived rollback: %s", name)
		}
	}
}

func TestFinalizeFailureRestoresPreviouslyActivePFProtection(t *testing.T) {
	i, _ := fixture(t)
	if err := i.Apply(); err != nil {
		t.Fatal(err)
	}
	if err := i.FinalizePFEvidence(context.Background()); err != nil {
		t.Fatal(err)
	}
	f := i.ops.(*fakeSystemOps)
	f.failAt = "plist:com.openduck.codex-broker.plist"
	if err := i.FinalizePFEvidence(context.Background()); err == nil {
		t.Fatal("injected upgrade finalization failure accepted")
	}
	if !f.pfLoaded || f.pfUnloadCount != 1 {
		t.Fatal("previously active PF anchor was not restored")
	}
	for _, event := range f.pfEvents {
		if event == "release:123" {
			t.Fatal("failed re-finalization released the prior completed lease")
		}
	}
}

func TestUpgradeAndRollbackSwitchReleaseScopedPolicyAtomically(t *testing.T) {
	current, root := fixture(t)
	if err := current.Apply(); err != nil {
		t.Fatal(err)
	}
	if err := current.Activate(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := current.Stop(); err != nil {
		t.Fatal(err)
	}
	oldPolicy, err := os.ReadFile(filepath.Join(root, "pf", "egress-policy.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, service := range services {
		if err := os.Chmod(filepath.Join(root, "releases", service.Name), 0750); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(filepath.Join(root, "releases", service.Name, "release-20260824"), 0750); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(filepath.Join(root, "releases", service.Name), 0550); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(filepath.Join(root, "releases", "anchor-checkpoint"), 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "releases", "anchor-checkpoint", "release-20260824"), 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(root, "releases", "anchor-checkpoint"), 0550); err != nil {
		t.Fatal(err)
	}
	next, err := newFakeInstaller(root, "release-20260824", current.cfg.BinaryDir)
	if err != nil {
		t.Fatal(err)
	}
	next.ops = current.ops
	t.Cleanup(func() {
		for _, service := range services {
			_ = os.Chmod(filepath.Join(root, "releases", service.Name, next.cfg.ReleaseID), 0700)
			_ = os.Chmod(filepath.Join(root, "releases", service.Name), 0700)
		}
		_ = os.Chmod(filepath.Join(root, "releases", "anchor-checkpoint", next.cfg.ReleaseID), 0700)
		_ = os.Chmod(filepath.Join(root, "releases", "anchor-checkpoint"), 0700)
		_ = next.Close()
	})
	if err := next.Apply(); err != nil {
		t.Fatal(err)
	}
	newPolicy, err := os.ReadFile(filepath.Join(root, "pf", "egress-policy.json"))
	if err != nil || bytes.Equal(oldPolicy, newPolicy) {
		t.Fatal("upgrade did not atomically switch release policy")
	}
	if scoped, err := os.ReadFile(filepath.Join(root, "releases", "egress", next.cfg.ReleaseID, "egress-policy.json")); err != nil || !bytes.Equal(scoped, newPolicy) {
		t.Fatal("new release-scoped policy missing")
	}
	if err := next.Activate(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := next.Rollback(); err != nil {
		t.Fatal(err)
	}
	rolledBack, err := os.ReadFile(filepath.Join(root, "pf", "egress-policy.json"))
	if err != nil || !bytes.Equal(rolledBack, oldPolicy) {
		t.Fatal("rollback did not restore previous release policy")
	}
	active, _ := os.ReadFile(filepath.Join(root, "active.release"))
	if strings.TrimSpace(string(active)) != current.cfg.ReleaseID {
		t.Fatal("rollback did not restore active release")
	}
	plist, _ := os.ReadFile(filepath.Join(root, "launchd", "com.openduck.egress.plist"))
	if !bytes.Contains(plist, []byte("<string>-policy</string><string>sha256:")) {
		t.Fatal("egress plist policy digest is not canonical sha256-prefixed form")
	}
}

func TestPFRulesAllowOnlyRuntimeUIDToLoopbackProxy(t *testing.T) {
	want := "pass out quick on lo0 inet proto tcp from any to 127.0.0.1 port 8790 user _openduck_codex keep state\nblock out quick on lo0 inet proto tcp from any to 127.0.0.1 port 8790\n"
	raw, err := os.ReadFile(filepath.Join("..", "..", "deploy", "macos", "pf", "openduck.conf"))
	if err != nil || !bytes.Contains(raw, []byte(want)) {
		t.Fatal("PF proxy allow/block ordering is not fail-closed")
	}
	canonical := "pass out quick inet proto { tcp udp } from any to any user _openduck_egress keep state\n"
	if !bytes.Contains(raw, []byte(canonical)) {
		t.Fatal("PF egress rule is not canonical macOS grammar")
	}
}

func TestPFCanonicalEgressRuleIsPortable(t *testing.T) {
	rule := "pass out quick inet proto { tcp udp } from any to any user _openduck_egress keep state"
	if strings.Contains(rule, "on lo0") || !strings.Contains(rule, "from any to any user _openduck_egress") {
		t.Fatal("PF egress rule changed from the portable canonical form")
	}
}

func TestResolvedEgressPlistExactlyMatchesCanonicalPolicyPins(t *testing.T) {
	i, root := fixture(t)
	if err := i.Apply(); err != nil {
		t.Fatal(err)
	}
	policyRaw, err := os.ReadFile(filepath.Join(root, "pf", "egress-policy.json"))
	if err != nil {
		t.Fatal(err)
	}
	var policy modelegress.Policy
	if json.Unmarshal(policyRaw, &policy) != nil {
		t.Fatal("installed egress policy is not parseable")
	}
	policyDigest, err := policy.Digest()
	if err != nil {
		t.Fatal(err)
	}
	plist, err := os.ReadFile(filepath.Join(root, "launchd", "com.openduck.egress.plist"))
	if err != nil {
		t.Fatal(err)
	}
	for flag, want := range map[string]string{"-policy": policyDigest, "-release-digest": policy.ReleaseDigest, "-socket-digest": policy.SocketDigest} {
		needle := []byte("<string>" + flag + "</string><string>" + want + "</string>")
		if !bytes.Contains(plist, needle) {
			t.Fatalf("resolved egress plist %s does not match canonical policy pin %s", flag, want)
		}
	}
}

func TestRollbackRestoresSixInternalAndExternalPlistsOnMidFailure(t *testing.T) {
	i, root := fixture(t)
	if err := i.Apply(); err != nil {
		t.Fatal(err)
	}
	if err := i.FinalizePFEvidence(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "previous.release"), []byte(i.cfg.ReleaseID+"\n"), 0644); err != nil {
		t.Fatal(err)
	}
	before := map[string][]byte{}
	for _, s := range services {
		name := "com.openduck." + serviceLabel(s.Name) + ".plist"
		b, err := os.ReadFile(filepath.Join(root, "launchd", name))
		if err != nil {
			t.Fatal(err)
		}
		before[name] = b
	}
	f := i.ops.(*fakeSystemOps)
	f.failAt = "plist:com.openduck.codex-broker.plist"
	if err := i.Rollback(); err == nil {
		t.Fatal("injected rollback plist failure accepted")
	}
	for name, want := range before {
		got, err := os.ReadFile(filepath.Join(root, "launchd", name))
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("internal plist was not restored: %s", name)
		}
		if !f.plists[name] {
			t.Fatalf("external plist was not restored: %s", name)
		}
	}
}

func TestRollbackJoinsExternalCompensationFailureAndRestoresInternalState(t *testing.T) {
	a, root := fixture(t)
	if err := a.Apply(); err != nil {
		t.Fatal(err)
	}
	if err := a.Activate(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := a.Stop(); err != nil {
		t.Fatal(err)
	}
	b := upgradeInstaller(t, a, root, "release-20260824")
	if err := b.Apply(); err != nil {
		t.Fatal(err)
	}
	if err := b.Activate(context.Background()); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(filepath.Join(root, "launchd", "com.openduck.anchor.plist"))
	if err != nil {
		t.Fatal(err)
	}
	f := b.ops.(*fakeSystemOps)
	f.failAt = "plist:com.openduck.codex-broker.plist"
	f.restorePlistFailAt = "com.openduck.codex-broker.plist"
	err = b.Rollback()
	if err == nil || !strings.Contains(err.Error(), "injected plist failure") || !strings.Contains(err.Error(), "rollback compensation failed") || !strings.Contains(err.Error(), "injected plist compensation failure") {
		t.Fatalf("rollback compensation failure was not joined: %v", err)
	}
	var tx *ProvisioningTransactionError
	if !errors.As(err, &tx) || safeReasonCode(err) != ErrorReasonProvisioningFailed {
		t.Fatalf("reason=%q err=%v", safeReasonCode(err), err)
	}
	var safe ProvisioningError
	if jsonErr := json.Unmarshal(SafeProvisioningError([]string{"--rollback", "--error-json"}, err), &safe); jsonErr != nil || safe.ReasonCode != ErrorReasonProvisioningFailed || safe.PrimaryReasonCode != ErrorReasonProvisioningFailed || safe.CompensationReasonCode != ErrorReasonRollbackRestoreFailed || safe.RecoveryState != "manual_review" {
		t.Fatalf("unsafe rollback recovery classification: %+v jsonErr=%v", safe, jsonErr)
	}
	after, readErr := os.ReadFile(filepath.Join(root, "launchd", "com.openduck.anchor.plist"))
	if readErr != nil || !bytes.Equal(after, before) {
		t.Fatalf("internal plist journal was not restored: %v", readErr)
	}
	active, _ := os.ReadFile(filepath.Join(root, "active.release"))
	if strings.TrimSpace(string(active)) != b.cfg.ReleaseID {
		t.Fatalf("failed rollback changed active release: %q", active)
	}
}

func TestRollbackClosureRejectsImmutableArtifactOwnershipTamper(t *testing.T) {
	i, root := fixture(t)
	if err := i.Apply(); err != nil {
		t.Fatal(err)
	}
	if err := i.Activate(context.Background()); err != nil {
		t.Fatal(err)
	}
	groups, err := os.Getgroups()
	if err != nil {
		t.Fatal(err)
	}
	tamperedGID := -1
	for _, gid := range groups {
		if gid != i.cfg.GID {
			tamperedGID = gid
			break
		}
	}
	if tamperedGID < 0 {
		t.Skip("no supplementary group available for ownership tamper")
	}
	path := filepath.Join(root, "releases", "anchor", i.cfg.ReleaseID, "manifest.json")
	if err := os.Chown(path, -1, tamperedGID); err != nil {
		t.Skipf("filesystem does not permit supplementary-group tamper: %v", err)
	}
	if err := i.validateRollbackRelease(i.cfg.ReleaseID); err == nil || !strings.Contains(err.Error(), "metadata invalid") {
		t.Fatalf("immutable artifact ownership tamper accepted: %v", err)
	}
}

func TestServiceLoginUsesFixedConfigAndDropsToController(t *testing.T) {
	i, _ := fixture(t)
	if err := i.Apply(); err != nil {
		t.Fatal(err)
	}
	// The login wrapper is an active-release operation. Apply deliberately leaves
	// only a candidate; activation first proves protected journal state before
	// publishing the active selector.
	if err := i.Activate(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := i.ServiceLogin(context.Background()); err != nil {
		t.Fatal(err)
	}
	f := i.ops.(*fakeSystemOps)
	wuid, wgid, _ := f.PrincipalIDs(context.Background(), "_openduck", "_openduck")
	_, channelGID, _ := f.PrincipalIDs(context.Background(), "_openduck", "_openduck_broker_channel")
	if f.execUID != wuid || f.execGID != wgid || len(f.execGroups) != 2 || f.execGroups[0] != wgid || f.execGroups[1] != channelGID || f.execPath != SystemRoot+"/home/controller/bin/openduck-codex-login" {
		t.Fatal("service login privilege-drop plan mismatch")
	}
	joined := strings.Join(f.execArgs, " ")
	if strings.Contains(joined, "owner-ed25519") || strings.Contains(joined, "auth.json") || !strings.Contains(joined, "-production-admission") {
		t.Fatal("unsafe service login arguments")
	}
}

func TestServiceLoginRejectsTamperedResolvedConfig(t *testing.T) {
	i, root := fixture(t)
	if err := i.Apply(); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(root, "operator/codex-login.json")
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	b[len(b)-2] ^= 1
	if err := os.WriteFile(p, b, 0644); err != nil {
		t.Fatal(err)
	}
	if err := i.ServiceLogin(context.Background()); err == nil {
		t.Fatal("tampered service login config accepted")
	}
	if i.ops.(*fakeSystemOps).execPath != "" {
		t.Fatal("tampered config reached privilege drop")
	}
}

func TestActivateRollsBackStartedJobsAndPF(t *testing.T) {
	i, _ := fixture(t)
	if err := i.Apply(); err != nil {
		t.Fatal(err)
	}
	f := i.ops.(*fakeSystemOps)
	f.failAt = "health:com.openduck.codex-broker"
	if err := i.Activate(context.Background()); err == nil {
		t.Fatal("injected activation failure accepted")
	}
	if f.pfLoaded || f.pfUnloadCount != 1 {
		t.Fatal("activation failure did not unload PF")
	}
	for _, label := range []string{"checkpoint", "anchor", "egress", "codex-runtime", "codex-broker"} {
		if !f.booted["com.openduck."+label] {
			t.Fatalf("started job was not booted out: %s", label)
		}
		if !f.booted["disabled:com.openduck."+label] {
			t.Fatalf("enabled job was not disabled: %s", label)
		}
	}
}

func TestActivateJournalsEnableAndBootstrapBeforeLaterFailures(t *testing.T) {
	for _, tc := range []struct {
		name         string
		failAt       string
		disabled     []string
		bootedOut    []string
		notBootedOut []string
	}{
		{"enable", "enable:com.openduck.egress", []string{"checkpoint", "anchor"}, []string{"checkpoint", "anchor"}, []string{"egress"}},
		{"bootstrap", "bootstrap:com.openduck.egress.plist", []string{"checkpoint", "anchor", "egress"}, []string{"checkpoint", "anchor", "egress"}, nil},
		{"kickstart", "kickstart:com.openduck.egress", []string{"checkpoint", "anchor", "egress"}, []string{"checkpoint", "anchor", "egress"}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			i, _ := fixture(t)
			if err := i.Apply(); err != nil {
				t.Fatal(err)
			}
			f := i.ops.(*fakeSystemOps)
			f.failAt = tc.failAt
			if err := i.Activate(context.Background()); err == nil {
				t.Fatal("injected activation failure accepted")
			}
			if f.pfLoaded || f.pfUnloadCount != 1 {
				t.Fatal("activation failure did not unload PF")
			}
			for _, label := range tc.disabled {
				if !f.booted["disabled:com.openduck."+label] {
					t.Fatalf("enabled job was not disabled: %s", label)
				}
			}
			for _, label := range tc.bootedOut {
				if !f.booted["com.openduck."+label] {
					t.Fatalf("bootstrapped job was not booted out: %s", label)
				}
			}
			for _, label := range tc.notBootedOut {
				if f.booted["com.openduck."+label] {
					t.Fatalf("unbootstrapped job was booted out: %s", label)
				}
			}
		})
	}
}

func TestActivatedMarkerIsExactAndGatesRollbackClosure(t *testing.T) {
	i, root := fixture(t)
	if err := i.Apply(); err != nil {
		t.Fatal(err)
	}
	if len(i.created) != 0 || len(i.backups) != 0 {
		t.Fatal("successful Apply retained a rollback journal")
	}
	if err := i.Activate(context.Background()); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "releases", "controller", i.cfg.ReleaseID, "activated")
	raw, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(raw, []byte(i.cfg.ReleaseID+"\n")) {
		t.Fatalf("marker=%q err=%v", raw, err)
	}
	st, err := os.Lstat(path)
	if err != nil || !safeExistingRegular(st, 0440, int64(len(raw))) || !ownedBy(st, uint32(i.cfg.UID), uint32(i.cfg.GID)) {
		t.Fatalf("unsafe activated marker: %v", err)
	}
	if err := i.validateRollbackRelease(i.cfg.ReleaseID); err != nil {
		t.Fatal(err)
	}
	if err := i.Stop(); err != nil {
		t.Fatal(err)
	}
	f := i.ops.(*fakeSystemOps)
	f.failAt = "health:com.openduck.egress"
	if err := i.Activate(context.Background()); err == nil {
		t.Fatal("injected reactivation failure accepted")
	}
	preserved, preservedErr := os.ReadFile(path)
	if preservedErr != nil || !bytes.Equal(preserved, raw) {
		t.Fatalf("existing activation marker was not preserved: %q %v", preserved, preservedErr)
	}
	preservedInfo, preservedStatErr := os.Lstat(path)
	if preservedStatErr != nil || !sameFileIdentity(st, preservedInfo) {
		t.Fatal("existing activation marker was replaced during failed reactivation")
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if err := i.validateRollbackRelease(i.cfg.ReleaseID); err == nil {
		t.Fatal("marker metadata was not part of rollback closure")
	}
}

func TestApplyRetryAndLaterCandidatePreserveLastActivatedRelease(t *testing.T) {
	t.Run("failed B retries then promotes A", func(t *testing.T) {
		a, root := fixture(t)
		if err := a.Apply(); err != nil {
			t.Fatal(err)
		}
		if err := a.Activate(context.Background()); err != nil {
			t.Fatal(err)
		}
		if err := a.Stop(); err != nil {
			t.Fatal(err)
		}
		b := upgradeInstaller(t, a, root, "release-20260824")
		if err := b.Apply(); err != nil {
			t.Fatal(err)
		}
		f := b.ops.(*fakeSystemOps)
		f.failAt = "health:com.openduck.egress"
		if err := b.Activate(context.Background()); err == nil {
			t.Fatal("injected B activation failure accepted")
		}
		pending, _ := os.ReadFile(filepath.Join(root, "pending.rollback"))
		if strings.TrimSpace(string(pending)) != a.cfg.ReleaseID {
			t.Fatalf("last activated release lost after B failure: %q", pending)
		}
		if _, err := os.Lstat(filepath.Join(root, "releases", "controller", b.cfg.ReleaseID, "activated")); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("failed activation left a B marker")
		}
		f.failAt = ""
		if err := b.Activate(context.Background()); err != nil {
			t.Fatal(err)
		}
		previous, _ := os.ReadFile(filepath.Join(root, "previous.release"))
		if strings.TrimSpace(string(previous)) != a.cfg.ReleaseID {
			t.Fatalf("B activation did not promote A: %q", previous)
		}
		if err := b.Rollback(); err != nil {
			t.Fatal(err)
		}
		active, _ := os.ReadFile(filepath.Join(root, "active.release"))
		if strings.TrimSpace(string(active)) != a.cfg.ReleaseID {
			t.Fatalf("rollback did not restore A: %q", active)
		}
	})

	t.Run("unactivated B followed by C keeps A", func(t *testing.T) {
		a, root := fixture(t)
		if err := a.Apply(); err != nil {
			t.Fatal(err)
		}
		if err := a.Activate(context.Background()); err != nil {
			t.Fatal(err)
		}
		if err := a.Stop(); err != nil {
			t.Fatal(err)
		}
		b := upgradeInstaller(t, a, root, "release-20260824")
		if err := b.Apply(); err != nil {
			t.Fatal(err)
		}
		c := upgradeInstaller(t, b, root, "release-20260825")
		if err := c.Apply(); err != nil {
			t.Fatal(err)
		}
		pending, _ := os.ReadFile(filepath.Join(root, "pending.rollback"))
		if strings.TrimSpace(string(pending)) != a.cfg.ReleaseID {
			t.Fatalf("C replaced last activated A with unactivated B: %q", pending)
		}
		if err := c.Rollback(); err != nil {
			t.Fatal(err)
		}
		active, _ := os.ReadFile(filepath.Join(root, "active.release"))
		if strings.TrimSpace(string(active)) != a.cfg.ReleaseID {
			t.Fatalf("C rollback did not restore A: %q", active)
		}
	})
}

func TestActivateUnwindsBootstrapThatMutatesThenErrors(t *testing.T) {
	i, root := fixture(t)
	if err := i.Apply(); err != nil {
		t.Fatal(err)
	}
	f := i.ops.(*fakeSystemOps)
	f.mutateThenFailAt = "bootstrap:com.openduck.egress.plist"
	if err := i.Activate(context.Background()); err == nil {
		t.Fatal("mutate-then-error bootstrap accepted")
	}
	if f.loaded["com.openduck.egress"] || !f.booted["com.openduck.egress"] {
		t.Fatal("mutated bootstrap was not booted out and proven unloaded")
	}
	if f.pfLoaded {
		t.Fatal("PF was not restored after proven launchd unwind")
	}
	if _, err := os.Lstat(filepath.Join(root, "pf", "enable.token")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("released PF lease token survived compensation")
	}
}

func TestActivateShutdownUncertaintyRetainsCurrentProtection(t *testing.T) {
	i, root := fixture(t)
	if err := i.Apply(); err != nil {
		t.Fatal(err)
	}
	f := i.ops.(*fakeSystemOps)
	f.mutateThenFailAt = "bootstrap:com.openduck.egress.plist"
	f.bootoutFailAt = "com.openduck.egress"
	err := i.Activate(context.Background())
	var tx *ProvisioningTransactionError
	if err == nil || !errors.As(err, &tx) || safeReasonCode(err) != ErrorReasonLaunchdBootstrapFailed {
		t.Fatalf("shutdown uncertainty classification=%q err=%v", safeReasonCode(err), err)
	}
	var safe ProvisioningError
	if jsonErr := json.Unmarshal(SafeProvisioningError([]string{"--activate", "--error-json"}, err), &safe); jsonErr != nil || safe.ReasonCode != ErrorReasonLaunchdBootstrapFailed || safe.PrimaryReasonCode != ErrorReasonLaunchdBootstrapFailed || safe.CompensationReasonCode != ErrorReasonLaunchdShutdownFailed || safe.RecoveryState != "manual_review" {
		t.Fatalf("unsafe shutdown uncertainty classification: %+v jsonErr=%v", safe, jsonErr)
	}
	if !f.loaded["com.openduck.egress"] || !f.pfLoaded {
		t.Fatal("uncertain shutdown did not retain current launchd/PF state")
	}
	token, tokenErr := os.ReadFile(filepath.Join(root, "pf", "enable.token"))
	if tokenErr != nil || strings.TrimSpace(string(token)) != "123" {
		t.Fatalf("current PF lease was not retained: %q %v", token, tokenErr)
	}
	if len(f.pfEvents) != 0 {
		t.Fatalf("PF compensation ran despite uncertain launchd shutdown: %v", f.pfEvents)
	}
}

func TestActivateRequiresEveryJobExplicitlyDisabledBeforePFMutation(t *testing.T) {
	i, _ := fixture(t)
	if err := i.Apply(); err != nil {
		t.Fatal(err)
	}
	f := i.ops.(*fakeSystemOps)
	f.booted["disabled:com.openduck.anchor"] = false
	err := i.Activate(context.Background())
	if err == nil || safeReasonCode(err) != ErrorReasonStopRequired {
		t.Fatalf("enabled job precondition=%q err=%v", safeReasonCode(err), err)
	}
	if f.pfLoaded || f.pfUnloadCount != 0 {
		t.Fatal("enabled job precondition mutated PF")
	}
}

func TestActivateRejectsExternalPlistReadbackMismatchBeforeBootstrap(t *testing.T) {
	i, _ := fixture(t)
	if err := i.Apply(); err != nil {
		t.Fatal(err)
	}
	f := i.ops.(*fakeSystemOps)
	f.readPlistTamperAt = "com.openduck.anchor.plist"
	err := i.Activate(context.Background())
	if err == nil || !strings.Contains(err.Error(), "external plist verification failed") {
		t.Fatalf("external plist mismatch accepted: %v", err)
	}
	for key := range f.booted {
		if strings.HasPrefix(key, "bootstrap:") {
			t.Fatalf("bootstrap occurred before exact plist readback: %s", key)
		}
	}
}

func TestActivationErrorSchemaPreservesPrimaryAndCompensationReasons(t *testing.T) {
	i, _ := fixture(t)
	if err := i.Apply(); err != nil {
		t.Fatal(err)
	}
	f := i.ops.(*fakeSystemOps)
	f.failAt = "health:com.openduck.codex-broker"
	f.pfRestoreErr = errors.New("injected PF restore failure")
	err := i.Activate(context.Background())
	var tx *ProvisioningTransactionError
	if err == nil || !errors.As(err, &tx) {
		t.Fatalf("typed transaction error missing: %v", err)
	}
	var safe ProvisioningError
	jsonErr := json.Unmarshal(SafeProvisioningError([]string{"--activate", "--error-json"}, err), &safe)
	if jsonErr != nil || safe.ReasonCode != ErrorReasonLaunchdHealthFailed || safe.PrimaryReasonCode != ErrorReasonLaunchdHealthFailed || safe.CompensationReasonCode != ErrorReasonPFRestoreFailed || safe.RecoveryState != "manual_review" {
		t.Fatalf("primary/compensation schema lost: %+v err=%v", safe, jsonErr)
	}
}

func TestFinalizeCompensationRetainsLeaseOnPFRestoreOrReleaseFailure(t *testing.T) {
	for _, tc := range []struct {
		name       string
		restoreErr error
		releaseErr error
		wantEvents []string
	}{
		{name: "restore", restoreErr: errors.New("injected restore failure"), wantEvents: []string{"restore"}},
		{name: "release", releaseErr: errors.New("injected release failure"), wantEvents: []string{"restore", "release:123"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			i, root := fixture(t)
			if err := i.Apply(); err != nil {
				t.Fatal(err)
			}
			f := i.ops.(*fakeSystemOps)
			f.failAt = "plist:com.openduck.codex-broker.plist"
			f.pfRestoreErr = tc.restoreErr
			f.pfReleaseErr = tc.releaseErr
			err := i.FinalizePFEvidence(context.Background())
			var tx *ProvisioningTransactionError
			if err == nil || !errors.As(err, &tx) || safeReasonCode(err) != ErrorReasonProvisioningFailed {
				t.Fatalf("classification=%q err=%v", safeReasonCode(err), err)
			}
			var safe ProvisioningError
			if jsonErr := json.Unmarshal(SafeProvisioningError([]string{"--finalize-pf", "--error-json"}, err), &safe); jsonErr != nil || safe.ReasonCode != ErrorReasonProvisioningFailed || safe.PrimaryReasonCode != ErrorReasonProvisioningFailed || safe.CompensationReasonCode != ErrorReasonPFRestoreFailed || safe.RecoveryState != "manual_review" {
				t.Fatalf("unsafe Finalize recovery classification: %+v jsonErr=%v", safe, jsonErr)
			}
			if !reflect.DeepEqual(f.pfEvents, tc.wantEvents) {
				t.Fatalf("PF compensation order=%v want=%v", f.pfEvents, tc.wantEvents)
			}
			token, tokenErr := os.ReadFile(filepath.Join(root, "pf", "enable.token"))
			if tokenErr != nil || strings.TrimSpace(string(token)) != "123" {
				t.Fatalf("current lease not retained: %q %v", token, tokenErr)
			}
		})
	}
}

func TestFinalizeRequiresEveryJobExplicitlyDisabledBeforePFMutation(t *testing.T) {
	i, _ := fixture(t)
	if err := i.Apply(); err != nil {
		t.Fatal(err)
	}
	f := i.ops.(*fakeSystemOps)
	f.booted["disabled:com.openduck.anchor"] = false
	err := i.FinalizePFEvidence(context.Background())
	if err == nil || safeReasonCode(err) != ErrorReasonStopRequired {
		t.Fatalf("enabled job precondition=%q err=%v", safeReasonCode(err), err)
	}
	if f.pfLoaded || f.pfUnloadCount != 0 || len(f.pfEvents) != 0 {
		t.Fatalf("enabled job precondition mutated PF: loaded=%v unloads=%d events=%v", f.pfLoaded, f.pfUnloadCount, f.pfEvents)
	}
}

func TestFinalizeRechecksEveryJobDisabledAfterMutation(t *testing.T) {
	i, root := fixture(t)
	if err := i.Apply(); err != nil {
		t.Fatal(err)
	}
	f := i.ops.(*fakeSystemOps)
	f.jobDisabledFalseAfter = len(services)
	f.jobDisabledFalseLabel = "com.openduck.anchor"
	err := i.FinalizePFEvidence(context.Background())
	if err == nil || safeReasonCode(err) != ErrorReasonStopRequired {
		t.Fatalf("post-finalize enabled job accepted: reason=%q err=%v", safeReasonCode(err), err)
	}
	if !reflect.DeepEqual(f.pfEvents, []string{"restore", "release:123"}) {
		t.Fatalf("postcondition compensation order=%v", f.pfEvents)
	}
	if _, statErr := os.Lstat(filepath.Join(root, "pf", "enable.token")); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatal("postcondition compensation left stale PF lease token")
	}
}

func TestFinalizeCompensationReleasesLeaseLastWithoutStaleToken(t *testing.T) {
	i, root := fixture(t)
	if err := i.Apply(); err != nil {
		t.Fatal(err)
	}
	f := i.ops.(*fakeSystemOps)
	f.failAt = "plist:com.openduck.codex-broker.plist"
	if err := i.FinalizePFEvidence(context.Background()); err == nil {
		t.Fatal("injected finalization failure accepted")
	}
	if !reflect.DeepEqual(f.pfEvents, []string{"restore", "release:123"}) {
		t.Fatalf("PF compensation order=%v", f.pfEvents)
	}
	if _, err := os.Lstat(filepath.Join(root, "pf", "enable.token")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("successful compensation left a stale PF token")
	}
}

func TestSeatbeltProfilesCompileAndDenyOutsideWrite(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("sandbox-exec is Darwin-only")
	}
	for _, profile := range []string{"codex.sb", "egress.sb"} {
		path := filepath.Join("..", "..", "deploy", "macos", "seatbelt", profile)
		if out, err := exec.Command("/usr/bin/sandbox-exec", "-f", path, "/usr/bin/true").CombinedOutput(); err != nil {
			// The desktop harness can itself be sandboxed, which prevents nested
			// sandbox-exec profiles from loading. Keep the compile assertion active
			// wherever the host allows this rootless kernel facility.
			if strings.Contains(string(out), "Operation not permitted") {
				t.Skipf("sandbox-exec unavailable in current execution sandbox: %s", out)
			}
			t.Fatalf("%s compile: %v: %s", profile, err, out)
		}
		denied := filepath.Join(t.TempDir(), "must-not-exist")
		if err := exec.Command("/usr/bin/sandbox-exec", "-f", path, "/bin/sh", "-c", "echo denied > \"$1\"", "sandbox-probe", denied).Run(); err == nil {
			t.Fatalf("%s allowed outside write", profile)
		}
		if _, err := os.Lstat(denied); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s created denied file", profile)
		}
	}
}

func TestRenderedDaemonContractsMatchCurrentParsers(t *testing.T) {
	for _, s := range services {
		p := renderPlist(s, "release-20260823")
		if s.Name == "broker" && (strings.Contains(p, "runtime-binary") || strings.Contains(p, "codex-home") || strings.Contains(p, "<string>-cwd</string>") || strings.Contains(p, "<string>-proxy</string>")) {
			t.Fatalf("obsolete broker/runtime contract in %s", s.Name)
		}
	}
	r := renderPlist(Service{Name: "runtime", User: "_openduck_codex", Group: "_openduck_codex"}, "r")
	for _, flag := range []string{"-codex-release-root", "-codex-binary-name", "-runtime-channel", "-runtime-release-root", "-runtime-key-root", "-pf-state-file", "-pf-evidence-file", "-seatbelt-profile", "-key-epoch"} {
		if !strings.Contains(r, "<string>"+flag+"</string>") {
			t.Fatalf("runtime missing %s", flag)
		}
	}
	if !strings.Contains(r, "<string>state</string>") || !strings.Contains(r, "<string>codex.sb</string>") {
		t.Fatal("runtime evidence leaves must be basenames")
	}
	b := renderPlist(Service{Name: "broker", User: "_openduck_broker", Group: "_openduck_broker"}, "r")
	for _, flag := range []string{"-controller-key-root", "-controller-key-file", "-egress-key-root", "-egress-key-file", "-runtime-key-root", "-runtime-key-file", "-broker-local-release", "-controller-local-release", "-broker-egress-release", "-egress-local-release", "-broker-runtime-release", "-runtime-local-release"} {
		if !strings.Contains(b, "<string>"+flag+"</string>") {
			t.Fatalf("broker missing %s", flag)
		}
	}
	if strings.Contains(b, "<string>-key-root</string>") || strings.Contains(b, "<string>-key-file</string>") {
		t.Fatal("legacy broker key flags")
	}
}

func TestControllerPlistContainsBrokerContract(t *testing.T) {
	p := renderPlist(Service{Name: "controller", User: "_openduck", Group: "_openduck"}, "r")
	for _, flag := range []string{"broker-socket", "broker-socket-root", "broker-key-root", "broker-key-file", "broker-release-root", "broker-channel", "broker-local-role", "broker-peer-role", "broker-runtime-id", "broker-runtime-digest", "broker-policy-digest", "broker-release-digest", "broker-socket-digest", "broker-egress-release-digest", "broker-egress-socket-digest", "broker-uid", "broker-gid", "broker-channel-gid", "egress-uid", "egress-gid", "broker-key-epoch", "owner-capability-file", "owner-public-key-file"} {
		if !strings.Contains(p, "<string>-"+flag+"</string>") {
			t.Fatalf("missing controller flag %s", flag)
		}
	}
}
