package servicekey

import (
	"context"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func testPolicy(t *testing.T, dir string) (*os.Root, Policy) {
	t.Helper()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	st, err := os.Lstat(dir)
	if err != nil {
		t.Fatal(err)
	}
	x := st.Sys().(*syscall.Stat_t)
	p := Policy{FileName: "anchor.key", Channel: "anchor", OwnerUID: uint32(os.Geteuid()), OwnerGID: uint32(os.Getegid()), Mode: 0600, RootUID: uint32(x.Uid), RootGID: uint32(x.Gid), RootMode: st.Mode().Perm()}
	r, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !validRoot(st, p) {
		t.Fatalf("root invalid mode=%#o uid=%d gid=%d want mode=%#o uid=%d gid=%d sys=%T", st.Mode().Perm(), x.Uid, x.Gid, p.RootMode.Perm(), p.RootUID, p.RootGID, st.Sys())
	}
	t.Cleanup(func() { _ = r.Close() })
	return r, p
}

func writeRecord(t *testing.T, dir, channel string, epoch uint64, key []byte) {
	t.Helper()
	raw := make([]byte, recordSize)
	copy(raw[:8], magic[:])
	raw[8] = version
	raw[9] = byte(len(channel))
	copy(raw[12:12+len(channel)], channel)
	binary.BigEndian.PutUint64(raw[12+maxChannelLen:], epoch)
	copy(raw[20+maxChannelLen:], key)
	if err := os.WriteFile(filepath.Join(dir, "anchor.key"), raw, 0600); err != nil {
		t.Fatal(err)
	}
}

func TestSourceReadsFixedRecordFromRootFD(t *testing.T) {
	d := t.TempDir()
	key := []byte("01234567890123456789012345678901")
	writeRecord(t, d, "anchor", 9, key)
	r, p := testPolicy(t, d)
	s, err := New(r, p)
	if err != nil {
		t.Fatalf("%v policy=%+v valid=%v safe=%v", err, p, validPolicy(p), safeLeaf(p.FileName))
	}
	got, epoch, err := s.LoadContext(context.Background(), "anchor")
	if err != nil || epoch != 9 || string(got) != string(key) {
		t.Fatalf("got epoch=%d key=%q err=%v", epoch, got, err)
	}
	got[0] = 'x'
	got2, _, err := s.LoadContext(context.Background(), "anchor")
	if err != nil || got2[0] != key[0] {
		t.Fatal("returned key aliases source")
	}
}

func TestSourceRejectsRecordAndMetadataViolations(t *testing.T) {
	key := []byte("01234567890123456789012345678901")
	cases := []struct {
		name   string
		mutate func(string)
	}{
		{"wrong-channel", func(d string) { writeRecord(t, d, "other", 1, key) }},
		{"zero-epoch", func(d string) { writeRecord(t, d, "anchor", 0, key) }},
		{"truncated", func(d string) { _ = os.WriteFile(filepath.Join(d, "anchor.key"), make([]byte, recordSize-1), 0600) }},
		{"oversized", func(d string) { _ = os.WriteFile(filepath.Join(d, "anchor.key"), make([]byte, recordSize+1), 0600) }},
		{"symlink", func(d string) {
			_ = os.WriteFile(filepath.Join(d, "other"), make([]byte, recordSize), 0600)
			_ = os.Symlink("other", filepath.Join(d, "anchor.key"))
		}},
		{"hardlink", func(d string) {
			writeRecord(t, d, "anchor", 1, key)
			_ = os.Link(filepath.Join(d, "anchor.key"), filepath.Join(d, "other"))
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := t.TempDir()
			tc.mutate(d)
			r, p := testPolicy(t, d)
			s, err := New(r, p)
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := s.LoadContext(context.Background(), "anchor"); !errors.Is(err, ErrUnavailable) && !errors.Is(err, ErrInvalid) {
				t.Fatalf("err=%v", err)
			}
		})
	}
}

func TestSourceRejectsSecurityModeBits(t *testing.T) {
	for _, bit := range []os.FileMode{os.ModeSetuid, os.ModeSetgid, os.ModeSticky} {
		if !hasSecurityModeBits(bit) {
			t.Fatalf("security bit %#o not detected", bit)
		}
	}
}

func TestFilesystemValidatorRejectsRetainedSpecialBits(t *testing.T) {
	key := []byte("01234567890123456789012345678901")
	t.Run("key-setuid", func(t *testing.T) {
		d := t.TempDir()
		if err := syscall.Chmod(d, 0700); err != nil {
			t.Fatal(err)
		}
		writeRecord(t, d, "anchor", 1, key)
		name := filepath.Join(d, "anchor.key")
		if err := syscall.Chmod(name, 04600); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = syscall.Chmod(name, 0600) })
		st, err := os.Lstat(name)
		if err != nil {
			t.Fatal(err)
		}
		if uint32(st.Sys().(*syscall.Stat_t).Mode)&07000 == 0 {
			t.Skip("filesystem does not retain special mode bits")
		}
		r, p := testPolicy(t, d)
		s, err := New(r, p)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := s.LoadContext(context.Background(), "anchor"); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("err=%v", err)
		}
	})
	t.Run("root-sticky", func(t *testing.T) {
		d := t.TempDir()
		if err := syscall.Chmod(d, 01700); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = syscall.Chmod(d, 0700) })
		writeRecord(t, d, "anchor", 1, key)
		st, err := os.Lstat(d)
		if err != nil {
			t.Fatal(err)
		}
		if uint32(st.Sys().(*syscall.Stat_t).Mode)&07000 == 0 {
			t.Skip("filesystem does not retain special mode bits")
		}
		x := st.Sys().(*syscall.Stat_t)
		p := Policy{FileName: "anchor.key", Channel: "anchor", OwnerUID: uint32(os.Geteuid()), OwnerGID: uint32(os.Getegid()), Mode: 0600, RootUID: uint32(x.Uid), RootGID: uint32(x.Gid), RootMode: 0700}
		r, err := os.OpenRoot(d)
		if err != nil {
			t.Fatal(err)
		}
		defer r.Close()
		if _, err := New(r, p); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("err=%v", err)
		}
	})
}

func TestSourceHonorsCancellationBeforeAndAfterChecks(t *testing.T) {
	d := t.TempDir()
	writeRecord(t, d, "anchor", 1, []byte("01234567890123456789012345678901"))
	r, p := testPolicy(t, d)
	s, err := New(r, p)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := s.LoadContext(ctx, "anchor"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("err=%v", err)
	}
	if _, _, err := s.LoadContext(context.Background(), "other"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("err=%v", err)
	}
}
