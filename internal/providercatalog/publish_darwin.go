//go:build darwin

package providercatalog

import (
	"errors"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// PublishNewDirectory is an atomic no-replace publication of a complete
// private staging tree.  The caller retains/removes the staging tree on error.
func PublishNewDirectory(staging, target string) error {
	if !filepath.IsAbs(staging) || !filepath.IsAbs(target) || filepath.Dir(staging) != filepath.Dir(target) || staging == target {
		return ErrInvalid
	}
	info, err := os.Lstat(staging)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return ErrInvalid
	}
	if err := unix.RenamexNp(staging, target, unix.RENAME_EXCL|unix.RENAME_NOFOLLOW_ANY); err != nil {
		return errors.New("provider catalog: publication rejected")
	}
	return nil
}
