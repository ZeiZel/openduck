//go:build darwin

package macosattest

import (
	"golang.org/x/sys/unix"
	"syscall"
	"unsafe"
)

const csOpsCDHash = 5

// SampleProcess obtains identity from the kernel only. csops(CS_OPS_CDHASH)
// identifies the executing code object; no executable pathname is consulted.
func SampleProcess(pid int) (Process, error) {
	if pid <= 0 {
		return Process{}, ErrUnavailable
	}
	kp, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	if err != nil || kp == nil || int(kp.Proc.P_pid) != pid {
		return Process{}, ErrUnavailable
	}
	var cdhash [20]byte
	_, _, errno := syscall.Syscall6(unix.SYS_CSOPS, uintptr(pid), csOpsCDHash, uintptr(unsafe.Pointer(&cdhash[0])), uintptr(len(cdhash)), 0, 0)
	if errno != 0 {
		return Process{}, ErrUnavailable
	}
	zero := true
	for _, value := range cdhash {
		zero = zero && value == 0
	}
	if zero {
		return Process{}, ErrUnavailable
	}
	return Process{PID: pid, ParentPID: int(kp.Eproc.Ppid), StartSec: kp.Proc.P_starttime.Sec, StartUsec: int64(kp.Proc.P_starttime.Usec), UID: kp.Eproc.Pcred.P_ruid, GID: kp.Eproc.Pcred.P_rgid, CDHash: cdhash}, nil
}
