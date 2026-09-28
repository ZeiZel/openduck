package macosattest

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"syscall"

	"openduck/internal/nativemcp"
)

func (l *FixedListener) IdentityDigest(generation uint64) (string, error) {
	if l == nil || generation == 0 {
		return "", ErrUnavailable
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return "", ErrUnavailable
	}
	parent, pe := os.Lstat(filepath.Dir(nativemcp.ShimSocketPath))
	socket, se := os.Lstat(nativemcp.ShimSocketPath)
	pd, pi, pok := identity(parent)
	sd, si, sok := identity(socket)
	if pe != nil || se != nil || !pok || !sok || pd != l.parentDev || pi != l.parentIno || sd != l.socketDev || si != l.socketIno {
		return "", ErrUnavailable
	}
	sum := sha256.Sum256([]byte(fmt.Sprintf("native-mcp-socket-v1|%d|%d|%d|%d|%d", generation, pd, pi, sd, si)))
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

type SocketBoundary struct {
	RootUID, RootGID, SocketUID, SocketGID uint32
	RootMode, SocketMode                   os.FileMode
}
type FixedListener struct {
	mu                                         sync.Mutex
	listener                                   *net.UnixListener
	parentDev, parentIno, socketDev, socketIno uint64
	closed                                     bool
}

// ListenFixed refuses existing paths and binds only beneath the fixed physical
// parent. The installer owns creation of that parent; base inactive deploy does
// not create it, so absence is intentionally unavailable.
func ListenFixed(boundary SocketBoundary) (*FixedListener, error) {
	path := nativemcp.ShimSocketPath
	parent := filepath.Dir(path)
	before, err := os.Lstat(parent)
	if err != nil || before.Mode()&os.ModeSymlink != 0 || !before.IsDir() || before.Mode().Perm() != boundary.RootMode.Perm() || !owned(before, boundary.RootUID, boundary.RootGID) {
		return nil, ErrUnavailable
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		return nil, ErrUnavailable
	}
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, ErrUnavailable
	}
	fail := func() (*FixedListener, error) { _ = ln.Close(); return nil, ErrUnavailable }
	if err := os.Chmod(path, boundary.SocketMode.Perm()); err != nil {
		return fail()
	}
	after, e1 := os.Lstat(parent)
	socket, e2 := os.Lstat(path)
	bd, bi, bok := identity(before)
	ad, ai, aok := identity(after)
	sd, si, sok := identity(socket)
	if e1 != nil || e2 != nil || !bok || !aok || !sok || bd != ad || bi != ai || socket.Mode()&os.ModeSymlink != 0 || socket.Mode()&os.ModeSocket == 0 || socket.Mode().Perm() != boundary.SocketMode.Perm() || !owned(socket, boundary.SocketUID, boundary.SocketGID) {
		return fail()
	}
	return &FixedListener{listener: ln, parentDev: bd, parentIno: bi, socketDev: sd, socketIno: si}, nil
}
func (l *FixedListener) Accept() (net.Conn, error) {
	if l == nil || l.listener == nil {
		return nil, ErrUnavailable
	}
	return l.listener.Accept()
}
func (l *FixedListener) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return nil
	}
	l.closed = true
	if l.listener == nil {
		return nil
	}
	err := l.listener.Close()
	if removeSameSocket(nativemcp.ShimSocketPath, l.socketDev, l.socketIno) != nil && err == nil {
		err = ErrUnavailable
	}
	return err
}
func removeSameSocket(path string, dev, ino uint64) error {
	st, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	d, i, ok := identity(st)
	if !ok || dev != 0 && (d != dev || i != ino) {
		return ErrUnavailable
	}
	return os.Remove(path)
}
func identity(info os.FileInfo) (uint64, uint64, bool) {
	if info == nil {
		return 0, 0, false
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st == nil {
		return 0, 0, false
	}
	return uint64(st.Dev), uint64(st.Ino), true
}
func owned(info os.FileInfo, uid, gid uint32) bool {
	st, ok := info.Sys().(*syscall.Stat_t)
	return ok && st != nil && st.Uid == uid && st.Gid == gid
}
