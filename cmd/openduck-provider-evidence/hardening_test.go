package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
)

func TestReadDescriptorRejectsSymlinkHardlinkAndOversize(t *testing.T) {
	dir := t.TempDir()
	regular := filepath.Join(dir, "record.json")
	if err := os.WriteFile(regular, []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	if got, err := readDescriptor(regular); err != nil || !bytes.Equal(got, []byte("{}")) {
		t.Fatalf("regular=%q err=%v", got, err)
	}
	symlink := filepath.Join(dir, "link.json")
	if err := os.Symlink(regular, symlink); err != nil {
		t.Fatal(err)
	}
	if _, err := readDescriptor(symlink); err == nil {
		t.Fatal("symlink accepted")
	}
	hardlink := filepath.Join(dir, "hardlink.json")
	if err := os.Link(regular, hardlink); err != nil {
		t.Fatal(err)
	}
	if _, err := readDescriptor(regular); err == nil {
		t.Fatal("hardlinked descriptor accepted")
	}
	large := filepath.Join(dir, "large.json")
	f, err := os.OpenFile(large, os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(maxDescriptorBytes + 1); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := readDescriptor(large); err == nil {
		t.Fatal("oversize descriptor accepted")
	}
}

func TestOpenedDescriptorIsNotReplacedByPathSwap(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "record.json")
	if err := os.WriteFile(path, []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	moved, replacement := filepath.Join(dir, "moved.json"), filepath.Join(dir, "replacement.json")
	if err := os.WriteFile(replacement, []byte("replacement"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(replacement, path); err != nil {
		t.Fatal(err)
	}
	got, err := readOpenedDescriptor(f)
	if err != nil || string(got) != "original" {
		t.Fatalf("got=%q err=%v", got, err)
	}
}

func TestWriteNoOverwriteIsAtomicAndSafe(t *testing.T) {
	dir := t.TempDir()
	output := filepath.Join(dir, "request.json")
	if err := writeNoOverwrite(output, []byte("first")); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(output)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("mode=%o", info.Mode().Perm())
	}
	if err := writeNoOverwrite(output, []byte("second")); err == nil {
		t.Fatal("overwrite accepted")
	}
	got, err := os.ReadFile(output)
	if err != nil || string(got) != "first" {
		t.Fatalf("output=%q err=%v", got, err)
	}
	target := filepath.Join(dir, "target.json")
	if err := os.WriteFile(target, []byte("target"), 0600); err != nil {
		t.Fatal(err)
	}
	symlink := filepath.Join(dir, "symlink-output.json")
	if err := os.Symlink(target, symlink); err != nil {
		t.Fatal(err)
	}
	if err := writeNoOverwrite(symlink, []byte("changed")); err == nil {
		t.Fatal("symlink output accepted")
	}
	if got, _ := os.ReadFile(target); string(got) != "target" {
		t.Fatal("symlink target changed")
	}
	matches, err := filepath.Glob(filepath.Join(dir, ".openduck-provider-evidence-*"))
	if err != nil || len(matches) != 0 {
		t.Fatalf("temporary cleanup=%v err=%v", matches, err)
	}
}

func TestWriteNoOverwriteRaceHasSingleWinner(t *testing.T) {
	dir := t.TempDir()
	output := filepath.Join(dir, "race.json")
	var wg sync.WaitGroup
	results := make(chan error, 16)
	for i := 0; i < cap(results); i++ {
		wg.Add(1)
		go func() { defer wg.Done(); results <- writeNoOverwrite(output, []byte("request")) }()
	}
	wg.Wait()
	close(results)
	successes := 0
	for err := range results {
		if err == nil {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("successes=%d", successes)
	}
}

func TestWriteNoOverwriteRollsBackAfterLinkFailure(t *testing.T) {
	dir := t.TempDir()
	output := filepath.Join(dir, "request.json")
	err := writeNoOverwriteWithHooks(output, []byte("request"), publicationHooks{afterLink: func() error { return errors.New("forced") }})
	if err == nil {
		t.Fatal("post-link failure accepted")
	}
	if _, err := os.Lstat(output); !os.IsNotExist(err) {
		t.Fatalf("published output survived: %v", err)
	}
	matches, err := filepath.Glob(filepath.Join(dir, ".openduck-provider-evidence-*"))
	if err != nil || len(matches) != 0 {
		t.Fatalf("temporary cleanup=%v err=%v", matches, err)
	}
}

func TestWriteNoOverwriteRollsBackWhenParentIsReplaced(t *testing.T) {
	base := t.TempDir()
	parent := filepath.Join(base, "parent")
	if err := os.Mkdir(parent, 0700); err != nil {
		t.Fatal(err)
	}
	moved := filepath.Join(base, "moved")
	output := filepath.Join(parent, "request.json")
	var hookErr error
	err := writeNoOverwriteWithHooks(output, []byte("request"), publicationHooks{afterLink: func() error {
		if err := os.Rename(parent, moved); err != nil {
			hookErr = err
			return err
		}
		if err := os.Mkdir(parent, 0700); err != nil {
			hookErr = err
			return err
		}
		return nil
	}})
	if hookErr != nil {
		t.Fatal(hookErr)
	}
	if err == nil {
		t.Fatal("replaced parent accepted")
	}
	for _, path := range []string{filepath.Join(parent, "request.json"), filepath.Join(moved, "request.json")} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatalf("output survived at %q: %v", path, err)
		}
	}
	matches, err := filepath.Glob(filepath.Join(moved, ".openduck-provider-evidence-*"))
	if err != nil || len(matches) != 0 {
		t.Fatalf("moved cleanup=%v err=%v", matches, err)
	}
}
