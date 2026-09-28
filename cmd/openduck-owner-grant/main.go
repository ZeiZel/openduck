// openduck-owner-grant is the only interactive issuer of owner approvals.
// It intentionally retains EUID 0 until the private signing bytes are read,
// signs one capability, zeroes those bytes, and never runs Controller code.
package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"openduck/internal/ownergrant"
)

const (
	systemRoot     = "/Library/Application Support/OpenDuck"
	operatorRoot   = systemRoot + "/operator"
	privateKeyLeaf = "owner-ed25519.key"
	capabilityRoot = operatorRoot + "/owner-capabilities"
	maxTTYLine     = 512
)

func main() {
	if err := run(context.Background()); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run(_ context.Context) error {
	if os.Geteuid() != 0 {
		return errors.New("owner grant requires root")
	}
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return errors.New("owner grant requires a TTY")
	}
	defer tty.Close()
	if st, err := tty.Stat(); err != nil || st.Mode()&os.ModeCharDevice == 0 {
		return errors.New("owner grant requires a TTY")
	}
	uid, gid, err := serviceIDs("_openduck")
	if err != nil {
		return err
	}
	queue := filepath.Join(systemRoot, "state/controller/owner-queue")
	store, err := ownergrant.OpenStore(queue, uid, gid)
	if err != nil {
		return errors.New("owner approval unavailable")
	}
	defer store.Close()
	pending, err := store.Active(time.Now().UTC())
	if err != nil || pending.RequestID == "" {
		return errors.New("no pending owner approval")
	}
	phrase := ownergrant.Phrase(pending)
	if len(phrase) > maxTTYLine-32 {
		return errors.New("owner approval rejected")
	}
	if _, err := fmt.Fprintf(tty, "Approve OpenDuck owner chat %s (%s)? Type %q: ", pending.ChatID, pending.OrderDigest, phrase); err != nil {
		return errors.New("owner approval rejected")
	}
	line, err := readTTYLine(tty, maxTTYLine)
	if err != nil || line != phrase {
		return errors.New("owner approval rejected")
	}
	private, err := readPrivateKey()
	if err != nil {
		return errors.New("owner approval key unavailable")
	}
	defer zero(private)
	if err := validateCapabilityRoot(gid); err != nil {
		return errors.New("owner approval unavailable")
	}
	if err := store.Consume(pending.RequestID, capabilityRoot, "owner.capability", private, uid, gid, time.Now().UTC()); err != nil {
		return errors.New("owner approval failed")
	}
	_, _ = fmt.Fprintln(tty, "Owner approval granted.")
	return nil
}

// readPrivateKey is FD-anchored under the fixed operator root. The root and
// leaf metadata are checked before and after the no-follow open, including
// inode identity, so a path replacement cannot select a different key.
func readPrivateKey() (ed25519.PrivateKey, error) {
	root, err := os.OpenRoot(operatorRoot)
	if err != nil {
		return nil, errors.New("operator root unavailable")
	}
	defer root.Close()
	wheel, err := wheelGID()
	if err != nil {
		return nil, errors.New("operator root unavailable")
	}
	st, err := root.Lstat(".")
	if err != nil || !rootMetadata(st, wheel, 0700) {
		return nil, errors.New("operator root unavailable")
	}
	before, err := root.Lstat(privateKeyLeaf)
	if err != nil || !keyMetadata(before) {
		return nil, errors.New("operator key unavailable")
	}
	f, err := root.OpenFile(privateKeyLeaf, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, errors.New("operator key unavailable")
	}
	defer f.Close()
	after, err := f.Stat()
	if err != nil || !keyMetadata(after) || !sameInode(before, after) {
		return nil, errors.New("operator key unavailable")
	}
	raw := make([]byte, ed25519.PrivateKeySize)
	if _, err := io.ReadFull(f, raw); err != nil {
		zero(raw)
		return nil, errors.New("operator key unavailable")
	}
	var extra [1]byte
	if n, err := f.Read(extra[:]); err != io.EOF || n != 0 {
		zero(raw)
		return nil, errors.New("operator key unavailable")
	}
	return ed25519.PrivateKey(raw), nil
}
func validateCapabilityRoot(controllerGID int) error {
	root, err := os.OpenRoot(capabilityRoot)
	if err != nil {
		return err
	}
	defer root.Close()
	st, err := root.Lstat(".")
	if err != nil || !rootMetadata(st, controllerGID, 0710) {
		return errors.New("unsafe capability root")
	}
	return nil
}
func readTTYLine(r io.Reader, max int) (string, error) {
	if max < 2 {
		return "", errors.New("invalid limit")
	}
	buf := make([]byte, 0, max)
	one := []byte{0}
	for len(buf) < max {
		n, err := r.Read(one)
		if n == 1 {
			if one[0] == '\n' {
				return string(buf), nil
			}
			if one[0] != '\r' {
				buf = append(buf, one[0])
			}
			continue
		}
		if err != nil {
			return "", err
		}
	}
	return "", errors.New("TTY line too long")
}
func serviceIDs(name string) (int, int, error) {
	u, err := user.Lookup(name)
	if err != nil {
		return 0, 0, errors.New("owner service unavailable")
	}
	uid, uerr := strconv.Atoi(u.Uid)
	gid, gerr := strconv.Atoi(u.Gid)
	if uerr != nil || gerr != nil || uid <= 0 || gid <= 0 {
		return 0, 0, errors.New("owner service unavailable")
	}
	return uid, gid, nil
}
func wheelGID() (int, error) {
	group, err := user.LookupGroup("wheel")
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(group.Gid)
}
func rootMetadata(i os.FileInfo, gid int, mode os.FileMode) bool {
	st, ok := i.Sys().(*syscall.Stat_t)
	return i != nil && ok && i.IsDir() && i.Mode()&os.ModeSymlink == 0 && i.Mode().Perm() == mode && st.Uid == 0 && int(st.Gid) == gid
}
func keyMetadata(i os.FileInfo) bool {
	st, ok := i.Sys().(*syscall.Stat_t)
	return i != nil && ok && i.Mode().IsRegular() && i.Mode()&os.ModeSymlink == 0 && i.Mode().Perm() == 0600 && st.Uid == 0 && st.Gid == 0 && st.Nlink == 1
}
func sameInode(a, b os.FileInfo) bool {
	x, ok := a.Sys().(*syscall.Stat_t)
	y, yok := b.Sys().(*syscall.Stat_t)
	return ok && yok && x.Dev == y.Dev && x.Ino == y.Ino
}
func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
