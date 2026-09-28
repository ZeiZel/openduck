package verifiedroot

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func requirement(t *testing.T, name, path string, mode os.FileMode) Requirement {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	st := info.Sys().(*syscall.Stat_t)
	return Requirement{Name: name, Path: path, UID: uint32(st.Uid), GID: uint32(st.Gid), Mode: mode}
}

func TestOpenAllRejectsAliasNestedSymlinkAndModeMismatch(t *testing.T) {
	base := privateTemp(t)
	one := filepath.Join(base, "one")
	two := filepath.Join(base, "two")
	if err := os.Mkdir(one, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(two, 0750); err != nil {
		t.Fatal(err)
	}
	valid := []Requirement{requirement(t, "one", one, 0700), requirement(t, "two", two, 0750)}
	roots, err := OpenAll(valid)
	if err != nil {
		t.Fatalf("valid roots rejected: %v", err)
	}
	CloseAll(roots)

	if roots, err = OpenAll([]Requirement{valid[0], valid[0]}); err == nil {
		CloseAll(roots)
		t.Fatal("physical alias accepted")
	}
	nested := filepath.Join(one, "nested")
	if err := os.Mkdir(nested, 0700); err != nil {
		t.Fatal(err)
	}
	if roots, err = OpenAll([]Requirement{valid[0], requirement(t, "nested", nested, 0700)}); err == nil {
		CloseAll(roots)
		t.Fatal("nested roots accepted")
	}
	alias := filepath.Join(base, "alias")
	if err := os.Symlink(one, alias); err != nil {
		t.Fatal(err)
	}
	if roots, err = OpenAll([]Requirement{requirement(t, "alias", alias, 0700)}); err == nil {
		CloseAll(roots)
		t.Fatal("symlink root accepted")
	}
	wrongMode := valid[0]
	wrongMode.Mode = 0750
	if roots, err = OpenAll([]Requirement{wrongMode}); err == nil {
		CloseAll(roots)
		t.Fatal("mode mismatch accepted")
	}
}

func TestOpenAllBindsFinalPathToOpenedDescriptor(t *testing.T) {
	path := filepath.Join(privateTemp(t), "root")
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	roots, err := OpenAll([]Requirement{requirement(t, "root", path, 0700)})
	if err != nil {
		t.Fatal(err)
	}
	defer CloseAll(roots)
	pathInfo, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	fdInfo, err := roots[0].Handle().Lstat(".")
	if err != nil {
		t.Fatal(err)
	}
	pathID, _ := identityOf(pathInfo)
	fdID, _ := identityOf(fdInfo)
	if pathID != fdID {
		t.Fatal("pathname and descriptor identities differ")
	}
}

func TestRootRevalidateRejectsPathReplacement(t *testing.T) {
	base := privateTemp(t)
	path := filepath.Join(base, "state")
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	roots, err := OpenAll([]Requirement{requirement(t, "state", path, 0700)})
	if err != nil {
		t.Fatal(err)
	}
	defer CloseAll(roots)
	if err := roots[0].Revalidate(); err != nil {
		t.Fatalf("unchanged root rejected: %v", err)
	}
	moved := filepath.Join(base, "old-state")
	if err := os.Rename(path, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	if err := roots[0].Revalidate(); err == nil {
		t.Fatal("replacement pathname accepted")
	}
}

func privateTemp(t *testing.T) string {
	t.Helper()
	path, err := os.MkdirTemp("/private/tmp", "od-verified-root-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(path) })
	return path
}
