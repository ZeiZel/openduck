package macosinstall

import (
	"context"
	"encoding/json"
	"errors"
	"openduck/internal/macosrelease"
	"openduck/internal/providertransport"
	"openduck/internal/releasecatalog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func admittedDeploymentFixture(t *testing.T) (macosrelease.Admission, macosrelease.Snapshot, macosrelease.DeploymentInput) {
	t.Helper()
	admission := admittedPlanFixture(t, canonicalInstallerArtifacts()...)
	snapshot, err := admission.MaterializeSnapshot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	input, err := admission.DeploymentInput(snapshot)
	if err != nil {
		_ = snapshot.Remove()
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = snapshot.Remove() })
	return admission, snapshot, input
}

func admittedProviderDeploymentFixture(t *testing.T, groups ...string) (macosrelease.Admission, macosrelease.Snapshot, macosrelease.DeploymentInput) {
	t.Helper()
	specs := append([]planArtifactSpec(nil), canonicalInstallerArtifacts()...)
	for _, group := range groups {
		specs = append(specs, catalogGroupArtifactSpecs(group)...)
	}
	sort.Slice(specs, func(i, j int) bool { return specs[i].path < specs[j].path })
	admission := admittedPlanFixture(t, specs...)
	snapshot, err := admission.MaterializeSnapshot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	input, err := admission.DeploymentInput(snapshot)
	if err != nil {
		_ = snapshot.Remove()
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = snapshot.Remove() })
	return admission, snapshot, input
}

func TestAdmittedSnapshotDeploysWithoutLegacyManifestOrDigestReleaseID(t *testing.T) {
	_, snapshot, input := admittedDeploymentFixture(t)
	if admissionID, source, err := input.InstallerBinding(); err != nil || admissionID.ReleaseID == admissionID.ReleaseDigest || source != snapshot.Path() {
		t.Fatalf("invalid sealed binding: manifest=%+v source=%q err=%v", admissionID, source, err)
	}
	if _, err := os.Lstat(filepath.Join(snapshot.Path(), "release.manifest")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("snapshot unexpectedly has legacy manifest: %v", err)
	}
	root := t.TempDir()
	t.Cleanup(func() { unsealFixtureReleaseTree(root, "release-a") })
	installer, err := newFakeAdmittedInstaller(root, input)
	if err != nil {
		t.Fatal(err)
	}
	defer installer.Close()
	if err := installer.SetAuditRun("0123456789abcdef", testReleaseDigest); err != nil {
		t.Fatal(err)
	}
	evidence, err := installer.Deploy(context.Background(), false)
	if err != nil {
		t.Fatal(err)
	}
	if !evidence.Configured || evidence.Activated || evidence.ReleaseID != "release-a" {
		t.Fatalf("deployment evidence=%+v", evidence)
	}
	path := filepath.Join(installer.cfg.Root, "releases", "controller", "release-a", "release-manifest.v2.json")
	if _, err := os.Lstat(path); err != nil {
		t.Fatalf("installed manifest metadata missing: %v", err)
	}
}

func unsealFixtureReleaseTree(root, release string) {
	for _, service := range []string{"checkpoint", "anchor", "egress", "runtime", "broker", "controller", "anchor-checkpoint", "codex"} {
		_ = os.Chmod(filepath.Join(root, "releases", service), 0700)
		_ = os.Chmod(filepath.Join(root, "releases", service, release), 0700)
	}
	_ = os.Chmod(filepath.Join(root, "releases"), 0700)
}

func TestAdmittedSnapshotPreflightRejectsTamperMissingAndUnresolvedArtifacts(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*testing.T, string)
	}{
		{"tampered", func(t *testing.T, root string) {
			t.Helper()
			path := filepath.Join(root, "bin", "openduck-controller")
			if err := os.Chmod(path, 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte("tampered"), 0500); err != nil {
				t.Fatal(err)
			}
		}},
		{"missing mandatory", func(t *testing.T, root string) {
			t.Helper()
			if err := os.Remove(filepath.Join(root, "bin", "openduck-controller")); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, snapshot, input := admittedDeploymentFixture(t)
			tc.mutate(t, snapshot.Path())
			installer, err := newFakeAdmittedInstaller(t.TempDir(), input)
			if err != nil {
				t.Fatal(err)
			}
			defer installer.Close()
			if err := installer.preflight(); err == nil {
				t.Fatal("unsafe admitted snapshot accepted")
			}
		})
	}
	// A forged external input cannot carry macosrelease's private deployment
	// seal, so it is rejected before a fake or production root is opened.
	if _, err := newFakeAdmittedInstaller(t.TempDir(), macosrelease.DeploymentInput{}); err == nil {
		t.Fatal("forged deployment input accepted")
	}
}

func TestAdmittedSnapshotRejectsResolverCollisionsAndIntentDrift(t *testing.T) {
	_, _, input := admittedDeploymentFixture(t)
	manifest, source, err := input.InstallerBinding()
	if err != nil {
		t.Fatal(err)
	}
	manifest.Artifacts = append(manifest.Artifacts, manifest.Artifacts[0])
	root, err := os.OpenRoot(source)
	if err != nil {
		t.Fatal(err)
	}
	validationTime, timeErr := input.InstallerValidationTime()
	if timeErr != nil {
		_ = root.Close()
		t.Fatal(timeErr)
	}
	_, validationErr := validateAdmittedSnapshotRoot(root, manifest, validationTime)
	_ = root.Close()
	if validationErr == nil {
		t.Fatal("source/target collision accepted")
	}
	installer, err := newFakeAdmittedInstaller(t.TempDir(), input)
	if err != nil {
		t.Fatal(err)
	}
	defer installer.Close()
	if _, err := installer.Deploy(context.Background(), true); err == nil {
		t.Fatal("activation different from sealed envelope accepted")
	}
	installer.releaseDigest = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if err := installer.preflight(); err == nil {
		t.Fatal("release digest drift accepted")
	}
	installer.releaseDigest = manifest.ReleaseDigest
	installer.admitted.Version = "9.9.9"
	if err := installer.preflight(); err == nil {
		t.Fatal("release version drift accepted")
	}
}

func TestAdmittedProviderGroupsCopyInactiveAndPersistManifest(t *testing.T) {
	_, snapshot, input := admittedProviderDeploymentFixture(t, "provider-policy", "provider-codex", "provider-claude", "provider-kimi", "provider-deepseek")
	manifest, _, err := input.InstallerBinding()
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	t.Cleanup(func() { unsealFixtureReleaseTree(root, manifest.ReleaseID) })
	installer, err := newFakeAdmittedInstaller(root, input)
	if err != nil {
		t.Fatal(err)
	}
	defer installer.Close()
	if err := installer.SetAuditRun("0123456789abcdef", testReleaseDigest); err != nil {
		t.Fatal(err)
	}
	if _, err := installer.Deploy(context.Background(), false); err != nil {
		t.Fatalf("inactive provider deployment failed: %v", err)
	}
	providerCount := 0
	for _, artifact := range manifest.Artifacts {
		entry, known := releasecatalog.EntryFor(artifact.Path)
		if !known || entry.Mandatory {
			continue
		}
		providerCount++
		mappings, ok := resolvePlanArtifacts(artifact, manifest.ReleaseID)
		if !ok || len(mappings) != 1 {
			t.Fatalf("provider mapping unavailable for %s", artifact.Path)
		}
		installed := filepath.Join(root, mappings[0].target)
		info, statErr := os.Lstat(installed)
		wantMode := inactiveProviderMode(mappings[0])
		if statErr != nil || !safeExistingRegular(info, wantMode, info.Size()) {
			t.Fatalf("unsafe inactive provider artifact %s: %v", installed, statErr)
		}
		got, readErr := os.ReadFile(installed)
		want, stageErr := os.ReadFile(filepath.Join(snapshot.Path(), artifact.Path))
		if readErr != nil || stageErr != nil || string(got) != string(want) {
			t.Fatalf("provider copy mismatch for %s", artifact.Path)
		}
	}
	if providerCount == 0 {
		t.Fatal("fixture omitted provider artifacts")
	}
	for _, forbidden := range []string{"providers/inactive/provider-lifecycle-operation.json", "providers/inactive/controller-owner-ed25519.json", "providers/inactive/deepseek/subscription.json"} {
		if _, err := os.Lstat(filepath.Join(root, forbidden)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("forbidden standing provider authorization present: %s (%v)", forbidden, err)
		}
	}
	installedManifest, readErr := os.ReadFile(filepath.Join(root, "releases", "controller", manifest.ReleaseID, "release-manifest.v2.json"))
	if readErr != nil {
		t.Fatal(readErr)
	}
	for _, required := range []string{"provider-bundle.json", "providers/codex/runtime-descriptor.json", "providers/deepseek/dsh-adapter-descriptor.json"} {
		if !containsString(string(installedManifest), required) {
			t.Fatalf("installed ManifestV2 omitted optional artifact %q", required)
		}
	}
}

func TestAdmittedSnapshotRejectsSyntheticQwenClosureFixture(t *testing.T) {
	_, _, input := admittedProviderDeploymentFixture(t, "provider-policy", "provider-qwen")
	installer, err := newFakeAdmittedInstaller(t.TempDir(), input)
	if err != nil {
		t.Fatal(err)
	}
	defer installer.Close()
	if err := installer.SetAuditRun("0123456789abcdef", testReleaseDigest); err != nil {
		t.Fatal(err)
	}
	if _, err := installer.Deploy(context.Background(), false); err == nil {
		t.Fatal("synthetic Qwen closure fixture admitted")
	}
}

func TestAdmittedProviderSnapshotAndRootsRejectUnsafeMutation(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*testing.T, string)
	}{
		{"extra snapshot leaf", func(t *testing.T, root string) {
			t.Helper()
			if err := os.WriteFile(filepath.Join(root, "provider-lifecycle-operation.json"), []byte("forbidden"), 0400); err != nil {
				t.Fatal(err)
			}
		}},
		{"metadata executable", func(t *testing.T, root string) {
			t.Helper()
			if err := os.Chmod(filepath.Join(root, "provider-bundle.json"), 0500); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, snapshot, input := admittedProviderDeploymentFixture(t, "provider-policy", "provider-codex")
			tc.mutate(t, snapshot.Path())
			installer, err := newFakeAdmittedInstaller(t.TempDir(), input)
			if err != nil {
				t.Fatal(err)
			}
			defer installer.Close()
			if err := installer.preflight(); err == nil {
				t.Fatal("unsafe provider snapshot accepted")
			}
		})
	}
}

func TestAdmittedProviderSnapshotRejectsInactiveDescriptorSubstitutionAndSpecialBits(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*testing.T, string)
	}{
		{"inactive mapping substitution", func(t *testing.T, snapshot string) {
			path := filepath.Join(snapshot, "providers", "codex", "runtime-descriptor.json")
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			descriptor, err := providertransport.DecodeInactiveDescriptor(raw)
			if err != nil {
				t.Fatal(err)
			}
			descriptor.MappingDigest = "sha256:" + strings.Repeat("d", 64)
			if err := descriptor.Seal(); err != nil {
				t.Fatal(err)
			}
			replacement, err := json.Marshal(descriptor)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(path, 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, replacement, 0400); err != nil {
				t.Fatal(err)
			}
		}},
		{"special descriptor mode", func(t *testing.T, snapshot string) {
			path := filepath.Join(snapshot, "providers", "codex", "runtime-descriptor.json")
			if err := os.Chmod(path, 0400|os.ModeSetgid); err != nil {
				t.Fatal(err)
			}
			info, err := os.Lstat(path)
			if err != nil {
				t.Fatal(err)
			}
			if info.Mode()&os.ModeSetgid == 0 {
				t.Skip("test filesystem did not retain setgid metadata")
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, snapshot, input := admittedProviderDeploymentFixture(t, "provider-policy", "provider-codex")
			tc.mutate(t, snapshot.Path())
			installer, err := newFakeAdmittedInstaller(t.TempDir(), input)
			if err != nil {
				t.Fatal(err)
			}
			defer installer.Close()
			if err := installer.preflight(); err == nil {
				t.Fatal("unsafe provider descriptor snapshot accepted")
			}
		})
	}
}

func TestInactiveProviderRootsRejectWritableAndSubstitutedAncestorsAndRollback(t *testing.T) {
	_, _, input := admittedProviderDeploymentFixture(t, "provider-policy", "provider-codex")
	for _, tc := range []struct {
		name  string
		alter func(*testing.T, string)
	}{
		{"symlink parent", func(t *testing.T, root string) {
			t.Helper()
			if err := os.Symlink(t.TempDir(), filepath.Join(root, "providers")); err != nil {
				t.Fatal(err)
			}
		}},
		{"writable parent", func(t *testing.T, root string) {
			t.Helper()
			if err := os.Mkdir(filepath.Join(root, "providers"), 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(filepath.Join(root, "providers"), 0777); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			installer, err := newFakeAdmittedInstaller(root, input)
			if err != nil {
				t.Fatal(err)
			}
			defer installer.Close()
			if err := installer.preflight(); err != nil {
				t.Fatal(err)
			}
			tc.alter(t, root)
			if err := installer.prepareInactiveProviderRoots(); err == nil {
				t.Fatal("unsafe provider ancestor accepted")
			}
		})
	}

	t.Run("substitution", func(t *testing.T) {
		root := t.TempDir()
		installer, err := newFakeAdmittedInstaller(root, input)
		if err != nil {
			t.Fatal(err)
		}
		defer installer.Close()
		if err := installer.preflight(); err != nil || installer.prepareInactiveProviderRoots() != nil {
			t.Fatalf("prepare inactive provider roots: %v", err)
		}
		if err := os.Rename(filepath.Join(root, "providers"), filepath.Join(root, "providers-old")); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(filepath.Join(root, "providers"), 0711); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(filepath.Join(root, "providers", "inactive"), 0750); err != nil {
			t.Fatal(err)
		}
		if err := installer.copyInactiveProviderArtifacts(); err == nil {
			t.Fatal("substituted inactive provider root accepted")
		}
	})

	t.Run("rollback", func(t *testing.T) {
		root := t.TempDir()
		installer, err := newFakeAdmittedInstaller(root, input)
		if err != nil {
			t.Fatal(err)
		}
		defer installer.Close()
		if err := installer.preflight(); err != nil {
			t.Fatal(err)
		}
		if err := installer.prepareInactiveProviderRoots(); err != nil {
			t.Fatal(err)
		}
		if err := installer.copyInactiveProviderArtifacts(); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Lstat(filepath.Join(root, "providers", "inactive", "provider-bundle.json")); err != nil {
			t.Fatal(err)
		}
		if err := installer.cleanupWithError(); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Lstat(filepath.Join(root, "providers", "inactive", "provider-bundle.json")); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("provider rollback left artifact: %v", err)
		}
	})
}

func TestProviderTransportPrerequisitesRejectPostPrincipalStateWithoutP7Descriptor(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*testing.T, string)
		wantOK bool
	}{
		{"formerly exact selected codex", func(t *testing.T, root string) { writePostPrincipalCodexFixture(t, root) }, false},
		{"missing key", func(t *testing.T, root string) {
			if err := os.Mkdir(filepath.Join(root, "channels", "providers", "codex"), 0750); err != nil {
				t.Fatal(err)
			}
		}, false},
		{"unknown channel", func(t *testing.T, root string) {
			writePostPrincipalCodexFixture(t, root)
			if err := os.Mkdir(filepath.Join(root, "channels", "providers", "unknown"), 0750); err != nil {
				t.Fatal(err)
			}
		}, false},
		{"unknown key", func(t *testing.T, root string) {
			writePostPrincipalCodexFixture(t, root)
			if err := os.WriteFile(filepath.Join(root, "keys", "controller-provider", "unknown.key"), []byte("x"), 0600); err != nil {
				t.Fatal(err)
			}
		}, false},
		{"link key", func(t *testing.T, root string) {
			writePostPrincipalCodexFixture(t, root)
			key := filepath.Join(root, "keys", "controller-provider", providertransport.KeyLeaves()["codex.chatgpt.app-server"])
			if err := os.Remove(key); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("/dev/null", key); err != nil {
				t.Fatal(err)
			}
		}, false},
		{"short key record", func(t *testing.T, root string) {
			writePostPrincipalCodexFixture(t, root)
			key := filepath.Join(root, "keys", "controller-provider", providertransport.KeyLeaves()["codex.chatgpt.app-server"])
			if err := os.WriteFile(key, make([]byte, providertransport.ServiceKeyRecordSize-1), 0600); err != nil {
				t.Fatal(err)
			}
		}, false},
		{"oversize key record", func(t *testing.T, root string) {
			writePostPrincipalCodexFixture(t, root)
			key := filepath.Join(root, "keys", "controller-provider", providertransport.KeyLeaves()["codex.chatgpt.app-server"])
			if err := os.WriteFile(key, make([]byte, providertransport.ServiceKeyRecordSize+1), 0600); err != nil {
				t.Fatal(err)
			}
		}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, input := admittedProviderDeploymentFixture(t, "provider-policy", "provider-codex")
			root := t.TempDir()
			first, err := newFakeAdmittedInstaller(root, input)
			if err != nil {
				t.Fatal(err)
			}
			prepareProviderTransportFixture(t, first)
			if first.providerTransportPostPrincipal {
				t.Fatal("pristine base prerequisites classified as provisioned")
			}
			if err := first.Close(); err != nil {
				t.Fatal(err)
			}
			tc.mutate(t, root)

			rerun, err := newFakeAdmittedInstaller(root, input)
			if err != nil {
				t.Fatal(err)
			}
			defer rerun.Close()
			if err := rerun.preflight(); err != nil {
				t.Fatal(err)
			}
			if err := rerun.mkdir("channels", 0711); err != nil {
				t.Fatal(err)
			}
			if err := rerun.mkdir("keys", 0711); err != nil {
				t.Fatal(err)
			}
			err = rerun.prepareProviderTransportPrerequisites()
			if tc.wantOK {
				if err != nil || !rerun.providerTransportPostPrincipal {
					t.Fatalf("exact post-principal rerun rejected: post=%v err=%v", rerun.providerTransportPostPrincipal, err)
				}
				if err := rerun.applyProviderTransportPrerequisiteOwnership(context.Background()); err != nil {
					t.Fatal(err)
				}
				if err := rerun.verifyProviderTransportPrerequisites(context.Background()); err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil {
				t.Fatal("unsafe post-principal rerun accepted")
			}
		})
	}
}

func TestProviderTransportPlanDeclaresOnlyPristineBaseRoots(t *testing.T) {
	_, _, input := admittedProviderDeploymentFixture(t, "provider-policy", "provider-codex")
	installer, err := newFakeAdmittedInstaller(t.TempDir(), input)
	if err != nil {
		t.Fatal(err)
	}
	defer installer.Close()
	paths := map[string]bool{}
	for _, path := range installer.Plan().Paths {
		paths[path] = true
	}
	for _, path := range []string{"channels/providers", "keys/controller-provider"} {
		if !paths[path] {
			t.Fatalf("missing safe provider transport base path %q", path)
		}
	}
	for _, forbidden := range []string{"releases/controller", "channels/providers/codex", "keys/controller-provider/codex.key"} {
		if paths[forbidden] {
			t.Fatalf("post-principal/provider release state was planned by base installer: %q", forbidden)
		}
	}
	prepareProviderTransportFixture(t, installer)
	for path, mode := range map[string]os.FileMode{"channels": 0711, "channels/providers": 0711, "keys/controller-provider": 0700} {
		info, statErr := os.Lstat(filepath.Join(installer.cfg.Root, path))
		if statErr != nil || info.Mode().Perm() != mode {
			t.Fatalf("base prerequisite %s metadata: info=%v err=%v", path, info, statErr)
		}
	}
}

func prepareProviderTransportFixture(t *testing.T, installer *Installer) {
	t.Helper()
	if err := installer.preflight(); err != nil {
		t.Fatal(err)
	}
	for _, directory := range []struct {
		path string
		mode os.FileMode
	}{{"channels", 0711}, {"keys", 0711}} {
		if err := installer.mkdir(directory.path, directory.mode); err != nil {
			t.Fatal(err)
		}
	}
	if err := installer.prepareProviderTransportPrerequisites(); err != nil {
		t.Fatal(err)
	}
}

func writePostPrincipalCodexFixture(t *testing.T, root string) {
	t.Helper()
	if err := os.Mkdir(filepath.Join(root, "channels", "providers", "codex"), 0750); err != nil {
		t.Fatal(err)
	}
	key := providertransport.KeyLeaves()["codex.chatgpt.app-server"]
	if key == "" {
		t.Fatal("missing closed codex provider key leaf")
	}
	if err := os.WriteFile(filepath.Join(root, "keys", "controller-provider", key), make([]byte, providertransport.ServiceKeyRecordSize), 0600); err != nil {
		t.Fatal(err)
	}
}

func containsString(value, want string) bool {
	return len(want) > 0 && len(value) >= len(want) && strings.Contains(value, want)
}
