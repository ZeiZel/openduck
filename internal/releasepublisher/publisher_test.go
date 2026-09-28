package releasepublisher

import (
	"os"
	"path/filepath"
	"testing"
)

func TestValidatePathsRequiresSiblingAbsoluteLeaves(t *testing.T) {
	root := t.TempDir()
	if _, _, err := ValidatePaths(filepath.Join(root, "a"), filepath.Join(root, "b")); err != nil {
		t.Fatalf("valid sibling paths rejected: %v", err)
	}
	if _, _, err := ValidatePaths("relative", filepath.Join(root, "b")); err == nil {
		t.Fatal("relative staging path accepted")
	}
	if _, _, err := ValidatePaths(filepath.Join(root, "a"), filepath.Join(root, "nested", "b")); err == nil {
		t.Fatal("different parents accepted")
	}
	if _, _, err := ValidatePaths(filepath.Join(root, "a", ".."), filepath.Join(root, "b")); err == nil {
		t.Fatal("unclean staging path accepted")
	}
	for _, leaf := range []string{"", ".", "..", "a/b", `a\\b`} {
		if _, _, err := ValidatePaths(filepath.Join(root, leaf), filepath.Join(root, "b")); err == nil {
			t.Fatalf("unsafe leaf accepted: %q", leaf)
		}
	}
}

func TestPublishDirectoryCollisionAndSymlinkParent(t *testing.T) {
	root := t.TempDir()
	staging := filepath.Join(root, ".stage")
	if err := os.Mkdir(staging, 0700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(root, "release")
	if err := PublishDirectory(staging, target); err != nil {
		t.Fatalf("publish failed: %v", err)
	}
	if _, err := os.Stat(target); err != nil {
		t.Fatal(err)
	}
	second := filepath.Join(root, ".second")
	if err := os.Mkdir(second, 0700); err != nil {
		t.Fatal(err)
	}
	if err := PublishDirectory(second, target); err == nil {
		t.Fatal("existing target was replaced")
	}
	realParent := filepath.Join(root, "real")
	if err := os.Mkdir(realParent, 0700); err != nil {
		t.Fatal(err)
	}
	linkParent := filepath.Join(root, "link")
	if err := os.Symlink(realParent, linkParent); err != nil {
		t.Fatal(err)
	}
	third := filepath.Join(root, ".third")
	if err := os.Mkdir(third, 0700); err != nil {
		t.Fatal(err)
	}
	if err := PublishDirectory(third, filepath.Join(linkParent, "release")); err == nil {
		t.Fatal("symlink parent was accepted")
	}
}
