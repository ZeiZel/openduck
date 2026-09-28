//go:build darwin

package macosattest

import "golang.org/x/sys/unix"

func renameNoReplace(oldPath, newPath string) error {
	return unix.RenamexNp(oldPath, newPath, unix.RENAME_EXCL|unix.RENAME_NOFOLLOW_ANY)
}
