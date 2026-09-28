//go:build darwin

package releasepublisher

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestPublishRejectsDestinationCreatedImmediatelyBeforeRename(t *testing.T) {
	root := t.TempDir()
	staging := filepath.Join(root, "stage")
	target := filepath.Join(root, "release")
	if err := os.Mkdir(staging, 0700); err != nil {
		t.Fatal(err)
	}
	original := renameDirectory
	defer func() { renameDirectory = original }()
	var firstFlags uint32
	renameDirectory = func(parentFD int, source, destination string, flags uint32) error {
		firstFlags = flags
		if err := os.Mkdir(target, 0700); err != nil {
			return err
		}
		return original(parentFD, source, destination, flags)
	}
	if err := PublishDirectory(staging, target); err == nil {
		t.Fatal("publication succeeded after destination appeared")
	}
	if firstFlags&(unix.RENAME_EXCL|unix.RENAME_NOFOLLOW_ANY) != unix.RENAME_EXCL|unix.RENAME_NOFOLLOW_ANY || firstFlags&0x20 == 0 {
		t.Fatalf("rename flags do not enforce exclusive no-follow resolve: %#x", firstFlags)
	}
	if _, err := os.Stat(target); err != nil {
		t.Fatalf("race-created destination was overwritten or removed: %v", err)
	}
	if _, err := os.Stat(staging); err != nil {
		t.Fatalf("staging tree was nested/removed by failed publication: %v", err)
	}
	if _, err := os.Stat(filepath.Join(target, filepath.Base(staging))); !os.IsNotExist(err) {
		t.Fatal("staging tree was nested under destination")
	}
}
