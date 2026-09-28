//go:build !darwin

package macosinstall

import "syscall"

var recoveryRenameatx = func(_ int, _, _ string) error { return syscall.ENOTSUP }
