package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"openduck/internal/qwenclosure"
)

func main() {
	root := flag.String("root", "", "absolute extracted closure root (used only to obtain the observed Node signature)")
	archive := flag.String("archive", "", "absolute pinned Qwen archive")
	hostIdentity := flag.String("host-identity", "", "absolute canonical Qwen host identity")
	cdhash := flag.String("node-cdhash", "", "observed 40-character Node CDHash")
	teamID := flag.String("node-team-id", "", "observed Node TeamIdentifier")
	out := flag.String("out", "", "absolute output manifest")
	flag.Parse()
	if err := run(*root, *archive, *hostIdentity, *cdhash, *teamID, *out); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
}

func run(root, archive, hostIdentity, cdhash, teamID, out string) error {
	if !filepath.IsAbs(root) || !filepath.IsAbs(archive) || !filepath.IsAbs(hostIdentity) || !filepath.IsAbs(out) || filepath.Clean(root) != root || filepath.Clean(archive) != archive || filepath.Clean(hostIdentity) != hostIdentity || filepath.Clean(out) != out {
		return errors.New("invalid path")
	}
	rootInfo, err := os.Lstat(root)
	if err != nil || !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 || strings.TrimSpace(cdhash) != cdhash || strings.TrimSpace(teamID) != teamID {
		return errors.New("untrusted closure input")
	}
	identity, err := os.ReadFile(hostIdentity)
	if err != nil {
		return errors.New("host identity read failed")
	}
	manifest, raw, err := qwenclosure.BuildArchive(archive, cdhash, teamID, identity)
	if err != nil || qwenclosure.FileDigest(filepath.Join(root, "node/bin/node")) != manifest.NodeDigest {
		return errors.New("closure archive does not match pinned schema")
	}
	tmp, err := os.CreateTemp(filepath.Dir(out), ".closure-manifest-")
	if err != nil {
		return err
	}
	name := tmp.Name()
	ok := false
	defer func() {
		_ = tmp.Close()
		if !ok {
			_ = os.Remove(name)
		}
	}()
	if _, err = tmp.Write(raw); err != nil {
		return err
	}
	if tmp.Sync() != nil || tmp.Close() != nil || os.Chmod(name, 0440) != nil {
		return errors.New("manifest finalize failed")
	}
	// Publish through an already-open parent descriptor. Link is an atomic
	// create-only operation: unlike a check followed by rename it cannot replace
	// a concurrently created output or follow a destination symlink.
	publishRoot, err := os.OpenRoot(filepath.Dir(out))
	if err != nil {
		return errors.New("manifest publish root failed")
	}
	defer publishRoot.Close()
	if err := publishRoot.Link(filepath.Base(name), filepath.Base(out)); err != nil {
		return errors.New("manifest exists or publish failed")
	}
	if err := publishRoot.Remove(filepath.Base(name)); err != nil {
		return errors.New("manifest cleanup after publish failed")
	}
	ok = true
	return nil
}
