package macosrelease

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestTrustAnchorBootstrapNoReplaceAndStrictInputs(t *testing.T) {
	root, source, body := trustAnchorFixture(t)
	anchor := filepath.Join(root, "release-trust.v1.json")
	if err := bootstrapTrustAnchorFixture(anchor, source, digestBytes(body)); err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	info, err := os.Lstat(anchor)
	if err != nil || info.Mode().Perm() != 0444 || info.Mode()&os.ModeSymlink != 0 {
		t.Fatalf("unsafe installed anchor: %#v, %v", info, err)
	}
	if err := bootstrapTrustAnchorFixture(anchor, source, digestBytes(body)); err == nil {
		t.Fatal("second bootstrap replaced existing anchor")
	}
	installed, err := os.ReadFile(anchor)
	if err != nil || string(installed) != string(body) {
		t.Fatalf("collision changed anchor: %q, %v", installed, err)
	}

	for _, tc := range []struct {
		name   string
		mutate func(t *testing.T, source string)
	}{
		{"wrong digest", func(t *testing.T, _ string) {}},
		{"uppercase digest", func(t *testing.T, _ string) {}},
		{"symlink", func(t *testing.T, source string) {
			if err := os.Remove(source); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("/dev/null", source); err != nil {
				t.Fatal(err)
			}
		}},
		{"hardlink", func(t *testing.T, source string) {
			if err := os.Link(source, source+".link"); err != nil {
				t.Fatal(err)
			}
		}},
		{"writable mode", func(t *testing.T, source string) {
			if err := os.Chmod(source, 0666); err != nil {
				t.Fatal(err)
			}
		}},
		{"malformed", func(t *testing.T, source string) {
			if err := os.WriteFile(source, []byte(`{"schema":"openduck.release-trust.v1","keys":{},"extra":true}`), 0600); err != nil {
				t.Fatal(err)
			}
		}},
		{"empty", func(t *testing.T, source string) {
			writeTrustBytes(t, source, TrustBundle{Schema: TrustBundleSchema, Keys: map[string]string{}})
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			candidateRoot, candidateSource, candidateBody := trustAnchorFixture(t)
			tc.mutate(t, candidateSource)
			if changed, err := os.ReadFile(candidateSource); err == nil {
				candidateBody = changed
			}
			digest := digestBytes(candidateBody)
			if tc.name == "wrong digest" {
				replacement := byte('0')
				if digest[0] == replacement {
					replacement = '1'
				}
				digest = string(replacement) + digest[1:]
			}
			if tc.name == "uppercase digest" {
				digest = strings.Repeat("A", 64)
			}
			if err := bootstrapTrustAnchorFixture(filepath.Join(candidateRoot, "release-trust.v1.json"), candidateSource, digest); err == nil {
				t.Fatal("unsafe bootstrap input accepted")
			}
		})
	}
}

func TestTrustAnchorRejectsStagedSubstitutionAndUnsafeInstalledMetadata(t *testing.T) {
	root, source, body := trustAnchorFixture(t)
	anchor := filepath.Join(root, "release-trust.v1.json")
	if err := bootstrapTrustAnchorFixture(anchor, source, digestBytes(body)); err != nil {
		t.Fatal(err)
	}
	if err := resolveTrustAnchorFixture(anchor, source); err != nil {
		t.Fatalf("identical staged copy rejected: %v", err)
	}
	other := filepath.Join(root, "other.json")
	writeTrustBytes(t, other, TrustBundle{Schema: TrustBundleSchema, Keys: map[string]string{"other": hex.EncodeToString(make(ed25519.PublicKey, ed25519.PublicKeySize))}})
	if err := resolveTrustAnchorFixture(anchor, other); err == nil {
		t.Fatal("staged substitution accepted")
	}
	if err := os.Link(anchor, anchor+".link"); err != nil {
		t.Fatal(err)
	}
	if err := resolveTrustAnchorFixture(anchor, source); err == nil {
		t.Fatal("hardlinked installed anchor accepted")
	}

	root, source, body = trustAnchorFixture(t)
	anchor = filepath.Join(root, "release-trust.v1.json")
	if err := bootstrapTrustAnchorFixture(anchor, source, digestBytes(body)); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(anchor, 0644); err != nil {
		t.Fatal(err)
	}
	if err := resolveTrustAnchorFixture(anchor, source); err == nil {
		t.Fatal("writable installed anchor accepted")
	}

	root, source, body = trustAnchorFixture(t)
	anchor = filepath.Join(root, "release-trust.v1.json")
	if err := bootstrapTrustAnchorFixture(anchor, source, digestBytes(body)); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(anchor); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(source, anchor); err != nil {
		t.Fatal(err)
	}
	if err := resolveTrustAnchorFixture(anchor, source); err == nil {
		t.Fatal("symlinked installed anchor accepted")
	}
}

func trustAnchorFixture(t *testing.T) (string, string, []byte) {
	t.Helper()
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	pub := make(ed25519.PublicKey, ed25519.PublicKeySize)
	if _, err := rand.Read(pub); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(root, "source.json")
	writeTrustBytes(t, source, TrustBundle{Schema: TrustBundleSchema, Keys: map[string]string{"release": hex.EncodeToString(pub)}})
	body, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	return root, source, body
}

func writeTrustBytes(t *testing.T, path string, value any) {
	t.Helper()
	body, err := CanonicalJSON(value)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, body, 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
}

// TestTrustAnchorBootstrapUnderForeignParentGroup pins the macOS behaviour that
// broke the real ceremony: BSD gives a new file the group of its parent
// directory, and stock macOS ships /Library/Application Support as root:admin,
// not root:wheel. The parent must therefore be trusted on owner and write bits
// alone, and the anchor must be bound to the policy group explicitly instead of
// inheriting one.
func TestTrustAnchorBootstrapUnderForeignParentGroup(t *testing.T) {
	groups, err := os.Getgroups()
	if err != nil {
		t.Fatalf("getgroups: %v", err)
	}
	foreign := -1
	for _, gid := range groups {
		if gid != os.Getegid() {
			foreign = gid
			break
		}
	}
	if foreign < 0 {
		t.Skip("no secondary group available to model a foreign parent group")
	}
	root, source, body := trustAnchorFixture(t)
	if err := os.Chown(root, os.Geteuid(), foreign); err != nil {
		t.Skipf("cannot regroup fixture parent: %v", err)
	}
	anchor := filepath.Join(root, "release-trust.v1.json")
	if err := bootstrapTrustAnchorFixture(anchor, source, digestBytes(body)); err != nil {
		t.Fatalf("bootstrap under foreign parent group: %v", err)
	}
	info, err := os.Lstat(anchor)
	if err != nil {
		t.Fatalf("installed anchor: %v", err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat == nil {
		t.Fatal("installed anchor has no stat")
	}
	if int(stat.Gid) != os.Getegid() {
		t.Fatalf("anchor inherited parent group %d instead of policy group %d", stat.Gid, os.Getegid())
	}
	if err := resolveTrustAnchorFixture(anchor, source); err != nil {
		t.Fatalf("installed anchor not resolvable after bootstrap: %v", err)
	}
}
