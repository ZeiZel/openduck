//go:build darwin

package macoschannel

import (
	"net"
	"syscall"
	"unsafe"
)

func platformAvailable() bool { return true }

// Darwin's LOCAL_PEERCRED is the kernel credential boundary. Executable
// identity is deliberately not inferred from it.
func peerCredentials(c net.Conn) (Peer, error) {
	sc, ok := c.(syscall.Conn)
	if !ok {
		return Peer{}, ErrUnavailable
	}
	var out Peer
	var callErr error
	raw, e := sc.SyscallConn()
	if e != nil {
		return Peer{}, ErrUnavailable
	}
	err := raw.Control(func(fd uintptr) {
		var u xucred
		nlen := uint32(unsafeSizeofXucred)
		_, _, e := syscall.Syscall6(syscall.SYS_GETSOCKOPT, fd, solLocal, localPeerCred, uintptr(unsafe.Pointer(&u)), uintptr(unsafe.Pointer(&nlen)), 0)
		if e != 0 {
			callErr = e
			return
		}
		if nlen != uint32(unsafeSizeofXucred) || u.Version != xucredVersion || u.NGroups < 1 || u.NGroups > 16 {
			callErr = syscall.EINVAL
			return
		}
		out = Peer{UID: u.UID, GID: u.Groups[0]}
	})
	if err != nil || callErr != nil {
		return Peer{}, ErrUnavailable
	}
	return out, nil
}

// Layout of struct xucred on Darwin. Kept private and checked by the kernel
// through getsockopt; this is not an executable code-signing assertion.
type xucred struct {
	Version uint32
	UID     uint32
	NGroups int16
	_       int16
	Groups  [16]uint32
}

const (
	xucredVersion      = 0
	unsafeSizeofXucred = 4 + 4 + 2 + 2 + 4*16 // exactly 76 bytes on Darwin
	solLocal           = 0
	localPeerCred      = 0x001
)
