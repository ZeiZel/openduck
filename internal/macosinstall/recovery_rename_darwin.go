//go:build darwin

package macosinstall

import "golang.org/x/sys/unix"

const recoveryRenameResolveBeneath = 0x20

var recoveryRenameatx = func(parentFD int, source, destination string) error {
	flags := uint32(unix.RENAME_EXCL | unix.RENAME_NOFOLLOW_ANY | recoveryRenameResolveBeneath)
	return unix.RenameatxNp(parentFD, source, parentFD, destination, flags)
}
