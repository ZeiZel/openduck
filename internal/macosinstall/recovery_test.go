package macosinstall

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestPartialInstallRecoveryQuarantinesOnlyExactClosedHelperTree(t *testing.T) {
	parent, request := partialRecoveryFixture(t)
	evidence, err := inspectPartialInstallAt(parent, partialInstallRootName, request, os.Getuid(), os.Getgid())
	if err != nil {
		t.Fatalf("inspect exact partial tree: %v", err)
	}
	if evidence.State != "eligible" || evidence.QuarantineName != "" {
		t.Fatalf("unexpected read-only evidence: %+v", evidence)
	}
	if _, err := os.Lstat(filepath.Join(parent, partialInstallRootName)); err != nil {
		t.Fatalf("read-only inspection mutated fixed root: %v", err)
	}
	evidence, err = recoverPartialInstallAt(parent, partialInstallRootName, request, os.Getuid(), os.Getgid())
	if err != nil {
		t.Fatalf("recover exact partial tree: %v", err)
	}
	if evidence.State != "quarantined" || !validPartialQuarantineName(evidence.QuarantineName) {
		t.Fatalf("unexpected recovery evidence: %+v", evidence)
	}
	if _, err := os.Lstat(filepath.Join(parent, partialInstallRootName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("partial root remains after atomic quarantine: %v", err)
	}
	for name, want := range map[string]string{".openduck-installer": "pretrusted helper\n", ".openduck-readiness": "independently catalogued readiness\n"} {
		body, err := os.ReadFile(filepath.Join(parent, evidence.QuarantineName, name))
		if err != nil || string(body) != want {
			t.Fatalf("quarantine did not preserve %s exactly: %q, %v", name, body, err)
		}
	}
	if _, err := evidence.JSON(); err != nil {
		t.Fatalf("bounded evidence failed JSON validation: %v", err)
	}
	receipt := readRecoveryReceiptFixture(t, parent)
	if receipt.State != "quarantined" || receipt.QuarantineName != evidence.QuarantineName || !isDigest(receipt.BootstrapHelperSHA256) || !isDigest(receipt.ReadinessHelperSHA256) {
		t.Fatalf("successful recovery lacks committed durable receipt: %+v", receipt)
	}
}

func TestPartialInstallRecoveryRejectsUnsafeOrNonemptyStateWithoutMutation(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(t *testing.T, parent string, request *PartialInstallRecoveryRequest)
	}{
		{"wrong explicit intent", func(_ *testing.T, _ string, request *PartialInstallRecoveryRequest) { request.Intent = "repair" }},
		{"wrong bootstrap digest", func(_ *testing.T, _ string, request *PartialInstallRecoveryRequest) {
			request.BootstrapHelperSHA256 = strings.Repeat("0", 64)
		}},
		{"symlink helper", func(t *testing.T, parent string, _ *PartialInstallRecoveryRequest) {
			path := filepath.Join(parent, partialInstallRootName, ".openduck-readiness")
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(".openduck-installer", path); err != nil {
				t.Fatal(err)
			}
		}},
		{"hardlinked helper", func(t *testing.T, parent string, _ *PartialInstallRecoveryRequest) {
			path := filepath.Join(parent, partialInstallRootName, ".openduck-readiness")
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if err := os.Link(filepath.Join(parent, partialInstallRootName, ".openduck-installer"), path); err != nil {
				t.Fatal(err)
			}
		}},
		{"readiness substitution", func(t *testing.T, parent string, _ *PartialInstallRecoveryRequest) {
			if err := os.WriteFile(filepath.Join(parent, partialInstallRootName, ".openduck-readiness"), []byte("substituted"), 0700); err != nil {
				t.Fatal(err)
			}
		}},
		{"service-login substitution", func(t *testing.T, parent string, _ *PartialInstallRecoveryRequest) {
			if err := os.WriteFile(filepath.Join(parent, partialInstallRootName, ".openduck-service-login"), []byte("extra helper"), 0700); err != nil {
				t.Fatal(err)
			}
		}},
		{"configured selector", func(t *testing.T, parent string, _ *PartialInstallRecoveryRequest) {
			if err := os.WriteFile(filepath.Join(parent, partialInstallRootName, "configured.release"), []byte("release-a\n"), 0644); err != nil {
				t.Fatal(err)
			}
		}},
		{"provider state", func(t *testing.T, parent string, _ *PartialInstallRecoveryRequest) {
			if err := os.Mkdir(filepath.Join(parent, partialInstallRootName, "providers"), 0700); err != nil {
				t.Fatal(err)
			}
		}},
		{"bad root mode", func(t *testing.T, parent string, _ *PartialInstallRecoveryRequest) {
			if err := os.Chmod(filepath.Join(parent, partialInstallRootName), 0771); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			parent, request := partialRecoveryFixture(t)
			tc.mutate(t, parent, &request)
			_, err := recoverPartialInstallAt(parent, partialInstallRootName, request, os.Getuid(), os.Getgid())
			if err == nil {
				t.Fatal("unsafe partial install was accepted")
			}
			if _, statErr := os.Lstat(filepath.Join(parent, partialInstallRootName)); statErr != nil {
				t.Fatalf("rejected recovery deleted or moved partial root: %v", statErr)
			}
			entries, readErr := os.ReadDir(parent)
			if readErr != nil || len(entries) != 2 { // source helper + original root
				t.Fatalf("rejected recovery created quarantine: entries=%v err=%v", entries, readErr)
			}
		})
	}
}

func TestPartialInstallRecoveryRevalidatesCandidateImmediatelyBeforeRename(t *testing.T) {
	// Model a mutation after the first eligibility validation but before the
	// rename boundary. The second descriptor-rooted check must reject it and
	// leave the original root where it was.
	parent, request := partialRecoveryFixture(t)
	root := filepath.Join(parent, partialInstallRootName)
	_, err := recoverPartialInstallWithFaults(parent, partialInstallRootName, request, os.Getuid(), os.Getgid(), partialRecoveryFaults{BeforeRename: func() error {
		return os.WriteFile(filepath.Join(root, "candidate.release"), []byte("r\n"), 0644)
	}})
	if err == nil {
		t.Fatal("candidate added before final validation was quarantined")
	}
	if _, err := os.Lstat(root); err != nil {
		t.Fatalf("failed recovery changed original root: %v", err)
	}
}

func TestPartialInstallRecoveryDurableReceiptReconcilesEveryCrashBoundary(t *testing.T) {
	for _, tc := range []struct {
		name          string
		faults        partialRecoveryFaults
		sourceRemains bool
		uncertain     bool
	}{
		{"before rename", partialRecoveryFaults{BeforeRename: func() error { return errors.New("injected before rename") }}, true, false},
		{"after rename before parent fsync", partialRecoveryFaults{AfterRenameBeforeParentSync: func() error { return errors.New("injected after rename") }}, false, true},
		{"after parent fsync before receipt commit", partialRecoveryFaults{AfterParentSyncBeforeCommit: func() error { return errors.New("injected before commit") }}, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			parent, request := partialRecoveryFixture(t)
			_, firstErr := recoverPartialInstallWithFaults(parent, partialInstallRootName, request, os.Getuid(), os.Getgid(), tc.faults)
			if firstErr == nil {
				t.Fatal("fault injection unexpectedly completed recovery")
			}
			if tc.uncertain && !errors.Is(firstErr, ErrPartialInstallRecoveryUncertain) {
				t.Fatalf("post-rename fault was not manual-review uncertainty: %v", firstErr)
			}
			if tc.uncertain {
				var safe ProvisioningError
				if err := json.Unmarshal(SafeProvisioningError([]string{"--recover-partial-install"}, firstErr), &safe); err != nil || safe.Phase != "partial_install_recovery" || safe.ReasonCode != ErrorReasonPartialRecoveryUncertain || safe.RecoveryState != "manual_review" {
					t.Fatalf("post-rename uncertainty was not projected as manual review: %+v err=%v", safe, err)
				}
			}
			receipt := readRecoveryReceiptFixture(t, parent)
			if receipt.State != "pending" || !validPartialQuarantineName(receipt.QuarantineName) {
				t.Fatalf("fault did not preserve exact pending receipt: %+v", receipt)
			}
			_, sourceErr := os.Lstat(filepath.Join(parent, partialInstallRootName))
			if (sourceErr == nil) != tc.sourceRemains {
				t.Fatalf("unexpected source state after fault: %v", sourceErr)
			}
			evidence, retryErr := recoverPartialInstallAt(parent, partialInstallRootName, request, os.Getuid(), os.Getgid())
			if retryErr != nil {
				t.Fatalf("exact explicit reconcile failed: %v", retryErr)
			}
			if evidence.QuarantineName != receipt.QuarantineName || countRecoveryQuarantines(t, parent) != 1 {
				t.Fatalf("reconcile allocated a second quarantine: evidence=%+v receipt=%+v", evidence, receipt)
			}
			committed := readRecoveryReceiptFixture(t, parent)
			if committed.State != "quarantined" || committed.QuarantineName != receipt.QuarantineName || committed.SourceDevice != receipt.SourceDevice || committed.SourceInode != receipt.SourceInode {
				t.Fatalf("receipt did not atomically commit exact identity: %+v", committed)
			}
			again, againErr := recoverPartialInstallAt(parent, partialInstallRootName, request, os.Getuid(), os.Getgid())
			if againErr != nil || again.QuarantineName != receipt.QuarantineName || countRecoveryQuarantines(t, parent) != 1 {
				t.Fatalf("committed retry violated one-quarantine invariant: %+v %v", again, againErr)
			}
		})
	}
}

func TestPartialInstallRecoveryReceiptOrDestinationCollisionFailsClosed(t *testing.T) {
	t.Run("new quarantine collision", func(t *testing.T) {
		parent, request := partialRecoveryFixture(t)
		name := "OpenDuck.quarantine-00000000000000000000000000000002"
		if err := os.Mkdir(filepath.Join(parent, name), 0711); err != nil {
			t.Fatal(err)
		}
		_, err := recoverPartialInstallWithFaults(parent, partialInstallRootName, request, os.Getuid(), os.Getgid(), partialRecoveryFaults{QuarantineName: func() (string, error) { return name, nil }})
		if !errors.Is(err, ErrPartialInstallRecoveryUncertain) {
			t.Fatalf("new quarantine collision was not rejected before receipt: %v", err)
		}
		if _, err := os.Lstat(filepath.Join(parent, partialInstallRootName)); err != nil {
			t.Fatalf("new quarantine collision moved source: %v", err)
		}
		if _, err := os.Lstat(filepath.Join(parent, partialRecoveryReceiptName)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("new quarantine collision wrote receipt: %v", err)
		}
	})
	t.Run("receipt temp collision", func(t *testing.T) {
		parent, request := partialRecoveryFixture(t)
		if err := os.WriteFile(filepath.Join(parent, partialRecoveryReceiptTemp), []byte("collision"), 0600); err != nil {
			t.Fatal(err)
		}
		_, err := recoverPartialInstallAt(parent, partialInstallRootName, request, os.Getuid(), os.Getgid())
		if !errors.Is(err, ErrPartialInstallRecoveryUncertain) {
			t.Fatalf("receipt collision did not fail uncertain: %v", err)
		}
		if _, err := os.Lstat(filepath.Join(parent, partialInstallRootName)); err != nil || countRecoveryQuarantines(t, parent) != 0 {
			t.Fatalf("receipt collision mutated source: %v", err)
		}
	})
	t.Run("pending destination collision", func(t *testing.T) {
		parent, request := partialRecoveryFixture(t)
		source, err := os.Lstat(filepath.Join(parent, partialInstallRootName))
		if err != nil {
			t.Fatal(err)
		}
		device, inode, ok := recoveryFileIdentity(source)
		if !ok {
			t.Fatal("source identity unavailable")
		}
		receipt := partialRecoveryReceipt{Schema: partialRecoveryReceiptSchema, Version: 1, State: "pending", SourceName: partialInstallRootName, QuarantineName: "OpenDuck.quarantine-00000000000000000000000000000001", SourceDevice: device, SourceInode: inode, BootstrapHelperSHA256: request.BootstrapHelperSHA256, ReadinessHelperSHA256: request.ReadinessHelperSHA256}
		parentRoot, err := os.OpenRoot(parent)
		if err != nil {
			t.Fatal(err)
		}
		if err := writePartialRecoveryReceipt(parentRoot, receipt, nil, os.Getuid(), os.Getgid()); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(filepath.Join(parent, receipt.QuarantineName), 0711); err != nil {
			t.Fatal(err)
		}
		_ = parentRoot.Close()
		_, err = recoverPartialInstallAt(parent, partialInstallRootName, request, os.Getuid(), os.Getgid())
		if !errors.Is(err, ErrPartialInstallRecoveryUncertain) {
			t.Fatalf("destination collision did not fail uncertain: %v", err)
		}
		if countRecoveryQuarantines(t, parent) != 1 {
			t.Fatal("collision allocated a second quarantine")
		}
	})
}

func TestPartialInstallRecoveryRejectsAnyPriorExactQuarantineWithoutReceipt(t *testing.T) {
	for _, tc := range []struct {
		name  string
		make  func(t *testing.T, parent, name string)
		count int
	}{
		{"single directory", func(t *testing.T, parent, name string) {
			if err := os.Mkdir(filepath.Join(parent, name), 0711); err != nil {
				t.Fatal(err)
			}
		}, 1},
		{"single symlink", func(t *testing.T, parent, name string) {
			if err := os.Symlink("OpenDuck", filepath.Join(parent, name)); err != nil {
				t.Fatal(err)
			}
		}, 1},
		{"multiple exact", func(t *testing.T, parent, name string) {
			if err := os.Mkdir(filepath.Join(parent, name), 0711); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(filepath.Join(parent, "OpenDuck.quarantine-22222222222222222222222222222222"), 0711); err != nil {
				t.Fatal(err)
			}
		}, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			parent, request := partialRecoveryFixture(t)
			name := "OpenDuck.quarantine-11111111111111111111111111111111"
			tc.make(t, parent, name)
			_, err := recoverPartialInstallAt(parent, partialInstallRootName, request, os.Getuid(), os.Getgid())
			if !errors.Is(err, ErrPartialInstallRecoveryUncertain) {
				t.Fatalf("prior exact quarantine did not fail manual review: %v", err)
			}
			if _, err := os.Lstat(filepath.Join(parent, partialInstallRootName)); err != nil || countRecoveryQuarantines(t, parent) != tc.count {
				t.Fatalf("prior quarantine admission mutated source or siblings: %v", err)
			}
			if _, err := os.Lstat(filepath.Join(parent, partialRecoveryReceiptName)); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("prior quarantine admission wrote receipt: %v", err)
			}
		})
	}
}

func TestPartialInstallRecoverySiblingScanUsesExactLowercaseGrammar(t *testing.T) {
	parent, request := partialRecoveryFixture(t)
	for _, name := range []string{
		"OpenDuck.quarantine-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		"OpenDuck.quarantine-1111111111111111111111111111111",
		"OpenDuck.quarantine-111111111111111111111111111111111",
		"OpenDuck.quarantine_11111111111111111111111111111111",
		"OpenDuck.quarantine-1111111111111111111111111111111g",
	} {
		if err := os.WriteFile(filepath.Join(parent, name), []byte("lookalike"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	evidence, err := recoverPartialInstallAt(parent, partialInstallRootName, request, os.Getuid(), os.Getgid())
	if err != nil || !validPartialQuarantineName(evidence.QuarantineName) || countRecoveryQuarantines(t, parent) != 1 {
		t.Fatalf("lookalike sibling incorrectly affected exact scan: %+v err=%v", evidence, err)
	}
}

func TestPartialInstallRecoveryRescansBeforeReceiptAndRename(t *testing.T) {
	t.Run("race before pending receipt", func(t *testing.T) {
		parent, request := partialRecoveryFixture(t)
		foreign := "OpenDuck.quarantine-33333333333333333333333333333333"
		_, err := recoverPartialInstallWithFaults(parent, partialInstallRootName, request, os.Getuid(), os.Getgid(), partialRecoveryFaults{BeforePendingReceipt: func() error {
			return os.Mkdir(filepath.Join(parent, foreign), 0711)
		}})
		if !errors.Is(err, ErrPartialInstallRecoveryUncertain) {
			t.Fatalf("pre-receipt quarantine race accepted: %v", err)
		}
		if _, err := os.Lstat(filepath.Join(parent, partialRecoveryReceiptName)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("pre-receipt race wrote receipt: %v", err)
		}
		if _, err := os.Lstat(filepath.Join(parent, partialInstallRootName)); err != nil {
			t.Fatalf("pre-receipt race moved source: %v", err)
		}
	})
	t.Run("race before rename", func(t *testing.T) {
		parent, request := partialRecoveryFixture(t)
		foreign := "OpenDuck.quarantine-44444444444444444444444444444444"
		_, err := recoverPartialInstallWithFaults(parent, partialInstallRootName, request, os.Getuid(), os.Getgid(), partialRecoveryFaults{BeforeRename: func() error {
			return os.Symlink("OpenDuck", filepath.Join(parent, foreign))
		}})
		if !errors.Is(err, ErrPartialInstallRecoveryUncertain) {
			t.Fatalf("pre-rename quarantine race accepted: %v", err)
		}
		if receipt := readRecoveryReceiptFixture(t, parent); receipt.State != "pending" || receipt.QuarantineName == foreign {
			t.Fatalf("pre-rename race corrupted canonical receipt: %+v", receipt)
		}
		if _, err := os.Lstat(filepath.Join(parent, partialInstallRootName)); err != nil {
			t.Fatalf("pre-rename race moved source: %v", err)
		}
	})
}

func TestPartialInstallRecoverySiblingScanIsBoundedAndFailsOnEnumerationError(t *testing.T) {
	parent := t.TempDir()
	for n := 0; n <= maxPartialRecoverySiblings; n++ {
		if err := os.WriteFile(filepath.Join(parent, fmt.Sprintf("entry-%04d", n)), nil, 0600); err != nil {
			t.Fatal(err)
		}
	}
	root, err := os.OpenRoot(parent)
	if err != nil {
		t.Fatal(err)
	}
	if err := scanPartialRecoveryQuarantines(root, ""); err == nil {
		t.Fatal("bounded sibling scan accepted oversized enumeration")
	}
	if err := root.Close(); err != nil {
		t.Fatal(err)
	}
	if err := scanPartialRecoveryQuarantines(root, ""); err == nil {
		t.Fatal("sibling scan accepted descriptor enumeration error")
	}
}

func TestPartialInstallRecoveryExclusiveRenameRejectsLastMomentDestination(t *testing.T) {
	parent, request := partialRecoveryFixture(t)
	sourcePath := filepath.Join(parent, partialInstallRootName)
	before, err := os.Lstat(sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	var collision string
	_, err = recoverPartialInstallWithFaults(parent, partialInstallRootName, request, os.Getuid(), os.Getgid(), partialRecoveryFaults{ImmediatelyBeforeRenameSyscall: func() error {
		receipt := readRecoveryReceiptFixture(t, parent)
		collision = filepath.Join(parent, receipt.QuarantineName)
		return os.Symlink("OpenDuck", collision)
	}})
	if !errors.Is(err, ErrPartialInstallRecoveryUncertain) {
		t.Fatalf("last-moment destination collision did not fail uncertain: %v", err)
	}
	after, err := os.Lstat(sourcePath)
	if err != nil || !sameFileIdentity(before, after) {
		t.Fatalf("exclusive collision changed source: before=%v after=%v err=%v", before, after, err)
	}
	collisionInfo, err := os.Lstat(collision)
	if err != nil || collisionInfo.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("exclusive collision replaced target: %v err=%v", collisionInfo, err)
	}
	if receipt := readRecoveryReceiptFixture(t, parent); receipt.State != "pending" {
		t.Fatalf("exclusive collision falsely committed receipt: %+v", receipt)
	}
}

func TestPartialInstallRecoveryUnsupportedExclusiveRenameHasNoFallback(t *testing.T) {
	for _, injected := range []error{syscall.EINVAL, syscall.ENOTSUP} {
		t.Run(injected.Error(), func(t *testing.T) {
			parent, request := partialRecoveryFixture(t)
			before, err := os.Lstat(filepath.Join(parent, partialInstallRootName))
			if err != nil {
				t.Fatal(err)
			}
			prior := recoveryRenameatx
			recoveryRenameatx = func(_ int, _, _ string) error { return injected }
			t.Cleanup(func() { recoveryRenameatx = prior })
			_, err = recoverPartialInstallAt(parent, partialInstallRootName, request, os.Getuid(), os.Getgid())
			if !errors.Is(err, ErrPartialInstallRecoveryUncertain) {
				t.Fatalf("unsupported exclusive rename was not manual review: %v", err)
			}
			after, statErr := os.Lstat(filepath.Join(parent, partialInstallRootName))
			if statErr != nil || !sameFileIdentity(before, after) || countRecoveryQuarantines(t, parent) != 0 {
				t.Fatalf("unsupported exclusive rename used fallback: after=%v err=%v", after, statErr)
			}
			if receipt := readRecoveryReceiptFixture(t, parent); receipt.State != "pending" {
				t.Fatalf("unsupported exclusive rename falsely committed receipt: %+v", receipt)
			}
		})
	}
}

func TestPartialInstallRecoveryConcurrentOperationsCreateOneQuarantine(t *testing.T) {
	parent, request := partialRecoveryFixture(t)
	entered := make(chan struct{})
	release := make(chan struct{})
	firstResult := make(chan error, 1)
	go func() {
		_, err := recoverPartialInstallWithFaults(parent, partialInstallRootName, request, os.Getuid(), os.Getgid(), partialRecoveryFaults{BeforeRename: func() error {
			close(entered)
			<-release
			return nil
		}})
		firstResult <- err
	}()
	<-entered
	second, secondErr := recoverPartialInstallAt(parent, partialInstallRootName, request, os.Getuid(), os.Getgid())
	close(release)
	firstErr := <-firstResult
	if secondErr != nil || second.State != "quarantined" {
		t.Fatalf("concurrent reconciler did not complete canonical receipt: %+v err=%v", second, secondErr)
	}
	if firstErr == nil || countRecoveryQuarantines(t, parent) != 1 {
		t.Fatalf("concurrent operations created ambiguous result: first=%v quarantines=%d", firstErr, countRecoveryQuarantines(t, parent))
	}
	if receipt := readRecoveryReceiptFixture(t, parent); receipt.State != "quarantined" || receipt.QuarantineName != second.QuarantineName {
		t.Fatalf("concurrent operations lost canonical receipt: %+v", receipt)
	}
}

func readRecoveryReceiptFixture(t *testing.T, parent string) partialRecoveryReceipt {
	t.Helper()
	root, err := os.OpenRoot(parent)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	receipt, err := readPartialRecoveryReceipt(root, os.Getuid(), os.Getgid())
	if err != nil {
		t.Fatal(err)
	}
	return receipt
}

func countRecoveryQuarantines(t *testing.T, parent string) int {
	t.Helper()
	entries, err := os.ReadDir(parent)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, entry := range entries {
		if validPartialQuarantineName(entry.Name()) {
			count++
		}
	}
	return count
}

func partialRecoveryFixture(t *testing.T) (string, PartialInstallRecoveryRequest) {
	t.Helper()
	parent := t.TempDir()
	helper := filepath.Join(parent, "pretrusted-installer")
	bootstrap := []byte("pretrusted helper\n")
	readiness := []byte("independently catalogued readiness\n")
	if err := os.WriteFile(helper, bootstrap, 0700); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(parent, partialInstallRootName)
	if err := os.Mkdir(root, 0711); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".openduck-installer"), bootstrap, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".openduck-readiness"), readiness, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "releases"), 0711); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "releases", "controller"), 0750); err != nil {
		t.Fatal(err)
	}
	return parent, PartialInstallRecoveryRequest{
		Intent:                PartialInstallRecoveryIntent,
		BootstrapHelperPath:   helper,
		BootstrapHelperSHA256: Digest(bootstrap),
		ReadinessHelperSHA256: Digest(readiness),
	}
}
