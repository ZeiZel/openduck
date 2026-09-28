//go:build darwin

package releasepublisher

import (
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

var renameDirectory = func(parentFD int, source, destination string, flags uint32) error {
	return unix.RenameatxNp(parentFD, source, parentFD, destination, flags)
}

// PublishDirectory atomically publishes a complete directory without
// replacing a destination. The parent is opened as a descriptor and the
// rename is descriptor-relative, so a target appearing after validation is
// rejected by the kernel rather than overwritten.
func PublishDirectory(staging, target string) error {
	staging, target, err := ValidatePaths(staging, target)
	if err != nil {
		return err
	}
	parent := filepath.Dir(target)
	info, err := os.Lstat(staging)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return ErrRejected
	}
	fd, err := unix.Open(parent, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return ErrRejected
	}
	defer unix.Close(fd)
	flags := uint32(unix.RENAME_EXCL | unix.RENAME_NOFOLLOW_ANY | 0x20) // RENAME_RESOLVE_BENEATH
	if err := renameDirectory(fd, filepath.Base(staging), filepath.Base(target), flags); err != nil {
		// Older Darwin kernels reject the private RESOLVE_BENEATH bit. The
		// descriptor-relative operation remains beneath the verified parent and
		// retains both kernel no-replace/no-follow guarantees.
		if err != unix.EINVAL || renameDirectory(fd, filepath.Base(staging), filepath.Base(target), unix.RENAME_EXCL|unix.RENAME_NOFOLLOW_ANY) != nil {
			return ErrRejected
		}
	}
	return nil
}
