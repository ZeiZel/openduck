//go:build darwin

package macosattest

import (
	"net"
	"syscall"
	"unsafe"
)

const (
	solLocal      = 0
	localPeerCred = 1
	localPeerPID  = 2
)

type socketXucred struct {
	Version, UID uint32
	NGroups      int16
	_            int16
	Groups       [16]uint32
}

func socketPeer(c net.Conn) (Process, error) {
	sc, ok := c.(syscall.Conn)
	if !ok {
		return Process{}, ErrUnavailable
	}
	raw, err := sc.SyscallConn()
	if err != nil {
		return Process{}, ErrUnavailable
	}
	var uid, gid uint32
	var pid int32
	var callErr error
	err = raw.Control(func(fd uintptr) {
		var cred socketXucred
		n := uint32(unsafe.Sizeof(cred))
		_, _, e := syscall.Syscall6(syscall.SYS_GETSOCKOPT, fd, solLocal, localPeerCred, uintptr(unsafe.Pointer(&cred)), uintptr(unsafe.Pointer(&n)), 0)
		if e != 0 || n != uint32(unsafe.Sizeof(cred)) || cred.NGroups < 1 || cred.NGroups > 16 {
			callErr = ErrUnavailable
			return
		}
		n = uint32(unsafe.Sizeof(pid))
		_, _, e = syscall.Syscall6(syscall.SYS_GETSOCKOPT, fd, solLocal, localPeerPID, uintptr(unsafe.Pointer(&pid)), uintptr(unsafe.Pointer(&n)), 0)
		if e != 0 || n != uint32(unsafe.Sizeof(pid)) || pid <= 0 {
			callErr = ErrUnavailable
			return
		}
		uid, gid = cred.UID, cred.Groups[0]
	})
	if err != nil || callErr != nil {
		return Process{}, ErrUnavailable
	}
	p, err := SampleProcess(int(pid))
	if err != nil || p.UID != uid || p.GID != gid {
		return Process{}, ErrUnavailable
	}
	return p, nil
}
