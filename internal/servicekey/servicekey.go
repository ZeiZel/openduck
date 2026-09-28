// Package servicekey reads the channel key from an already-open, trusted
// directory.  It deliberately has no pathname-opening constructor and no
// context-free loading API.
package servicekey

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"syscall"
)

var (
	ErrUnavailable = errors.New("servicekey: unavailable")
	ErrInvalid     = errors.New("servicekey: invalid record")
)

const (
	version       = byte(1)
	maxChannelLen = 64
	keyLen        = 32
	recordSize    = 8 + 1 + 1 + 2 + maxChannelLen + 8 + keyLen
)

var magic = [8]byte{'O', 'D', 'K', 'E', 'Y', 'F', 'D', 1}

// Policy describes the exact directory and file metadata accepted by Source.
// FileName is a single leaf name and is resolved only beneath Root.
type Policy struct {
	FileName           string
	Channel            string
	OwnerUID, OwnerGID uint32
	Mode               os.FileMode
	RootUID, RootGID   uint32
	RootMode           os.FileMode
}

// Source is a context-only service key source backed by Root's descriptor.
type Source struct {
	root     *os.Root
	name     string
	policy   Policy
	dev, ino uint64
}

func New(root *os.Root, policy Policy) (*Source, error) {
	if root == nil || !validPolicy(policy) || !safeLeaf(policy.FileName) {
		return nil, ErrUnavailable
	}
	st, err := root.Lstat(".")
	if err != nil || !validRoot(st, policy) {
		return nil, ErrUnavailable
	}
	x, ok := statOf(st)
	if !ok {
		return nil, ErrUnavailable
	}
	return &Source{root: root, name: policy.FileName, policy: policy, dev: uint64(x.Dev), ino: x.Ino}, nil
}

func (s *Source) LoadContext(ctx context.Context, channel string) ([]byte, uint64, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, 0, ErrUnavailable
	}
	if s == nil || s.root == nil || channel == "" || channel != s.policy.Channel {
		return nil, 0, ErrUnavailable
	}
	rootInfo, err := s.root.Lstat(".")
	if err != nil || !validRoot(rootInfo, s.policy) || !sameIdentity(rootInfo, s.dev, s.ino) {
		return nil, 0, ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		return nil, 0, ErrUnavailable
	}
	info, err := s.root.Lstat(s.name)
	if err != nil || !validKeyFile(info, s.policy, recordSize) {
		return nil, 0, ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		return nil, 0, ErrUnavailable
	}
	f, err := s.root.Open(s.name)
	if err != nil {
		return nil, 0, ErrUnavailable
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !validKeyFile(opened, s.policy, recordSize) || !sameIdentity(opened, statDev(info), statIno(info)) {
		return nil, 0, ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		return nil, 0, ErrUnavailable
	}
	raw := make([]byte, recordSize)
	if _, err := io.ReadFull(f, raw); err != nil {
		zero(raw)
		return nil, 0, ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		zero(raw)
		return nil, 0, ErrUnavailable
	}
	if err := f.Close(); err != nil {
		zero(raw)
		return nil, 0, ErrUnavailable
	}
	key, epoch, ok := parse(raw, channel)
	zero(raw)
	if !ok {
		if key != nil {
			zero(key)
		}
		return nil, 0, ErrInvalid
	}
	return key, epoch, nil
}

func parse(raw []byte, channel string) ([]byte, uint64, bool) {
	if len(raw) != recordSize || string(raw[:8]) != string(magic[:]) || raw[8] != version || raw[10] != 0 || raw[11] != 0 {
		return nil, 0, false
	}
	n := int(raw[9])
	if n == 0 || n > maxChannelLen || string(raw[12:12+n]) != channel {
		return nil, 0, false
	}
	for _, b := range raw[12+n : 12+maxChannelLen] {
		if b != 0 {
			return nil, 0, false
		}
	}
	epoch := binary.BigEndian.Uint64(raw[12+maxChannelLen : 20+maxChannelLen])
	if epoch == 0 {
		return nil, 0, false
	}
	key := append([]byte(nil), raw[20+maxChannelLen:]...)
	return key, epoch, len(key) == keyLen
}

func validPolicy(p Policy) bool {
	return p.Channel != "" && len(p.Channel) <= maxChannelLen && validMode(p.Mode) && validMode(p.RootMode)
}
func safeLeaf(s string) bool { return s != "" && s != "." && s != ".." && !containsSlash(s) }
func containsSlash(s string) bool {
	for _, r := range s {
		if r == '/' || r == '\\' {
			return true
		}
	}
	return false
}
func validMode(m os.FileMode) bool {
	return m.Perm() != 0 && m&^os.FileMode(0777) == 0 && m.Perm()&0007 == 0
}
func validRoot(i os.FileInfo, p Policy) bool {
	return i != nil && i.IsDir() && i.Mode()&os.ModeSymlink == 0 && !infoHasSecurityModeBits(i) && i.Mode().Perm() == p.RootMode.Perm() && statMatches(i, p.RootUID, p.RootGID)
}
func validKeyFile(i os.FileInfo, p Policy, size int64) bool {
	return i != nil && i.Mode().IsRegular() && i.Mode()&os.ModeSymlink == 0 && !infoHasSecurityModeBits(i) && i.Mode().Perm() == p.Mode.Perm() && i.Size() == size && statMatches(i, p.OwnerUID, p.OwnerGID) && statNlink(i) == 1
}
func hasSecurityModeBits(m os.FileMode) bool {
	return m&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0
}
func infoHasSecurityModeBits(i os.FileInfo) bool {
	if hasSecurityModeBits(i.Mode()) {
		return true
	}
	x, ok := statOf(i)
	return ok && uint32(x.Mode)&07000 != 0
}
func statMatches(i os.FileInfo, uid, gid uint32) bool {
	x, ok := statOf(i)
	return ok && uint32(x.Uid) == uid && uint32(x.Gid) == gid
}
func statNlink(i os.FileInfo) uint64 {
	x, ok := statOf(i)
	if !ok {
		return 0
	}
	return uint64(x.Nlink)
}
func statDev(i os.FileInfo) uint64 {
	x, _ := statOf(i)
	if x == nil {
		return 0
	}
	return uint64(x.Dev)
}
func statIno(i os.FileInfo) uint64 {
	x, _ := statOf(i)
	if x == nil {
		return 0
	}
	return x.Ino
}
func sameIdentity(i os.FileInfo, dev, ino uint64) bool { return statDev(i) == dev && statIno(i) == ino }
func statOf(i os.FileInfo) (*syscall.Stat_t, bool) {
	if i == nil {
		return nil, false
	}
	x, ok := i.Sys().(*syscall.Stat_t)
	return x, ok && x != nil
}
func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
