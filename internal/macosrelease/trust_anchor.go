package macosrelease

// The release trust anchor is deliberately separate from a staged release.
// A release envelope can be supplied by an operator, but its verification key
// must already be installed below the fixed root by a distinct root operation.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
)

const (
	// ReleaseTrustAnchorPath is the only trust input accepted by privileged
	// release admission.  It is public key material, not a secret.
	ReleaseTrustAnchorPath = "/Library/Application Support/OpenDuck.release-trust.v1.json"
)

type trustAnchorPolicy struct {
	uid     uint32
	gid     uint32
	dirMode os.FileMode
}

func installedTrustAnchorPolicy() trustAnchorPolicy { return trustAnchorPolicy{uid: 0, gid: 0} }
func fixtureTrustAnchorPolicy() trustAnchorPolicy {
	return trustAnchorPolicy{uid: uint32(os.Geteuid()), gid: uint32(os.Getegid()), dirMode: 0700}
}

// BootstrapInstalledTrustAnchor performs the one-time explicit trust
// ceremony.  The expected digest is an out-of-band operator value and is
// checked inside the privileged executable before any fixed-root write.
func BootstrapInstalledTrustAnchor(sourcePath, expectedDigest string) error {
	if runtime.GOOS != "darwin" || os.Geteuid() != 0 {
		return errRejected
	}
	return bootstrapTrustAnchorAt(ReleaseTrustAnchorPath, sourcePath, expectedDigest)
}

// ResolveInstalledTrustAnchor returns the immutable fixed trust path only
// after optionally comparing a staged operator copy byte-for-byte.  Callers
// must pass the returned path to admission; they must never use the staged
// path as authority.
func ResolveInstalledTrustAnchor(stagedCopyPath string) (string, error) {
	if _, err := resolveTrustAnchorWithPolicy(ReleaseTrustAnchorPath, stagedCopyPath, installedTrustAnchorPolicy(), true); err != nil {
		return "", errRejected
	}
	return ReleaseTrustAnchorPath, nil
}

// ValidateTrustBundleFile applies the exact gates the privileged anchor
// ceremony applies to a trust bundle before it opens the fixed root: bounded
// strict file bytes, canonical encoding, and a parseable key set. It is
// unprivileged and read-only, so an operator can reject a malformed bundle
// offline instead of discovering it as an opaque non-zero helper exit under a
// no_log Ansible task.
func ValidateTrustBundleFile(path string) error {
	body, err := strictTrustBytes(path)
	if err != nil {
		return errors.New("trust bundle is not a bounded strict file")
	}
	var trust TrustBundle
	if decodeStrictTrust(body, &trust) != nil {
		return errors.New("trust bundle is not canonical: expected exactly the encoding of schema, then keys, then revoked, with no unknown, duplicate or reordered members")
	}
	if _, _, err = ParseTrust(trust); err != nil {
		return errors.New("trust bundle key set is not admissible")
	}
	return nil
}

func resolveTrustAnchorFixture(anchorPath, stagedCopyPath string) error {
	_, err := resolveTrustAnchorWithPolicy(anchorPath, stagedCopyPath, fixtureTrustAnchorPolicy(), false)
	return err
}

func resolveTrustAnchorWithPolicy(anchorPath, stagedCopyPath string, policy trustAnchorPolicy, production bool) ([]byte, error) {
	anchor, err := readTrustAnchorWithPolicy(anchorPath, policy, production)
	if err != nil {
		return nil, errRejected
	}
	if stagedCopyPath != "" {
		staged, err := strictTrustBytes(stagedCopyPath)
		if err != nil || !bytes.Equal(anchor, staged) || digestBytes(anchor) != digestBytes(staged) {
			return nil, errRejected
		}
	}
	return anchor, nil
}

func bootstrapTrustAnchorAt(anchorPath, sourcePath, expectedDigest string) error {
	return bootstrapTrustAnchorWithPolicy(anchorPath, sourcePath, expectedDigest, installedTrustAnchorPolicy(), true)
}

// bootstrapTrustAnchorFixture is intentionally package-private.  It gives
// filesystem tests the same no-replace transaction without weakening the
// fixed production path or root ownership policy.
func bootstrapTrustAnchorFixture(anchorPath, sourcePath, expectedDigest string) error {
	return bootstrapTrustAnchorWithPolicy(anchorPath, sourcePath, expectedDigest, fixtureTrustAnchorPolicy(), false)
}

func bootstrapTrustAnchorWithPolicy(anchorPath, sourcePath, expectedDigest string, policy trustAnchorPolicy, production bool) error {
	if !validDigest(expectedDigest) {
		return errRejected
	}
	body, err := strictTrustBytes(sourcePath)
	if err != nil || digestBytes(body) != expectedDigest {
		return errRejected
	}
	var trust TrustBundle
	if decodeStrictTrust(body, &trust) != nil {
		return errRejected
	}
	if _, _, err = ParseTrust(trust); err != nil {
		return errRejected
	}
	parent, leaf, err := openTrustAnchorParent(anchorPath, true, policy, production)
	if err != nil {
		return errRejected
	}
	defer parent.Close()
	if _, err = parent.Lstat(leaf); !errors.Is(err, os.ErrNotExist) {
		return errRejected
	}
	return writeNewTrustAnchor(parent, leaf, body, policy)
}

func loadTrustAnchorAt(path string) (TrustBundle, error) {
	body, err := readTrustAnchorWithPolicy(path, installedTrustAnchorPolicy(), true)
	if err != nil {
		return TrustBundle{}, errRejected
	}
	var trust TrustBundle
	if decodeStrictTrust(body, &trust) != nil {
		return TrustBundle{}, errRejected
	}
	if _, _, err := ParseTrust(trust); err != nil {
		return TrustBundle{}, errRejected
	}
	return trust, nil
}

func readTrustAnchorWithPolicy(path string, policy trustAnchorPolicy, production bool) ([]byte, error) {
	parent, leaf, err := openTrustAnchorParent(path, false, policy, production)
	if err != nil {
		return nil, errRejected
	}
	defer parent.Close()
	body, err := readRootStrictFile(parent, leaf, policy)
	if err != nil {
		return nil, errRejected
	}
	var trust TrustBundle
	if decodeStrictTrust(body, &trust) != nil {
		return nil, errRejected
	}
	if _, _, err := ParseTrust(trust); err != nil {
		return nil, errRejected
	}
	return body, nil
}

func strictTrustBytes(path string) ([]byte, error) {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errRejected
	}
	return readStrictFile(path, maxInputBytes)
}

func decodeStrictTrust(body []byte, trust *TrustBundle) error {
	if trust == nil || rejectDuplicateJSONKeys(body) != nil {
		return errRejected
	}
	d := json.NewDecoder(bytes.NewReader(body))
	d.DisallowUnknownFields()
	if d.Decode(trust) != nil || d.Decode(&struct{}{}) != io.EOF {
		return errRejected
	}
	canonical, err := CanonicalJSON(*trust)
	if err != nil || !bytes.Equal(body, canonical) {
		return errRejected
	}
	return nil
}

func openTrustAnchorParent(anchorPath string, create bool, policy trustAnchorPolicy, production bool) (*os.Root, string, error) {
	if !filepath.IsAbs(anchorPath) || filepath.Clean(anchorPath) != anchorPath {
		return nil, "", errRejected
	}
	if !production {
		if filepath.Base(anchorPath) != "release-trust.v1.json" {
			return nil, "", errRejected
		}
		if safeDirectory(filepath.Dir(anchorPath)) != nil {
			return nil, "", errRejected
		}
		root, err := os.OpenRoot(filepath.Dir(anchorPath))
		if err != nil {
			return nil, "", errRejected
		}
		info, err := root.Open(".")
		if err != nil {
			_ = root.Close()
			return nil, "", errRejected
		}
		stat, statErr := info.Stat()
		closeErr := info.Close()
		if statErr != nil || closeErr != nil || !trustedAnchorDirectory(stat, policy) {
			_ = root.Close()
			return nil, "", errRejected
		}
		return root, filepath.Base(anchorPath), nil
	}
	if create && anchorPath != ReleaseTrustAnchorPath {
		return nil, "", errRejected
	}
	if anchorPath != ReleaseTrustAnchorPath || filepath.Dir(anchorPath) != "/Library/Application Support" || filepath.Base(anchorPath) != "OpenDuck.release-trust.v1.json" {
		return nil, "", errRejected
	}
	// Never begin the fixed-root ceremony through caller-controlled ancestry.
	// /Library and Application Support are system-owned on supported macOS;
	// checking them before descriptor-relative work rejects local substitution.
	for _, ancestor := range []string{"/Library", "/Library/Application Support"} {
		if safeDirectory(ancestor) != nil {
			return nil, "", errRejected
		}
	}
	parent, err := os.OpenRoot("/Library/Application Support")
	if err != nil {
		return nil, "", errRejected
	}
	opened, err := parent.Open(".")
	if err != nil {
		_ = parent.Close()
		return nil, "", errRejected
	}
	openedInfo, statErr := opened.Stat()
	closeErr := opened.Close()
	if statErr != nil || closeErr != nil || !trustedAnchorDirectory(openedInfo, policy) {
		_ = parent.Close()
		return nil, "", errRejected
	}
	return parent, filepath.Base(anchorPath), nil
}

// trustedAnchorDirectory deliberately binds the owner and the absence of group
// and other write bits, but not the group identity. Stock macOS ships
// /Library/Application Support as root:admin 0755, and a directory no one but
// root may modify is trusted regardless of which system group names it. This
// matches safeDirectory, which guards the same ancestry.
func trustedAnchorDirectory(info os.FileInfo, policy trustAnchorPolicy) bool {
	if info == nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || unsafeSpecialMode(info) || info.Mode().Perm()&0022 != 0 || (policy.dirMode != 0 && info.Mode().Perm() != policy.dirMode) {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat != nil && stat.Uid == policy.uid
}

func writeNewTrustAnchor(root *os.Root, leaf string, body []byte, policy trustAnchorPolicy) error {
	if root == nil || leaf != filepath.Base(leaf) || len(body) == 0 {
		return errRejected
	}
	f, err := root.OpenFile(leaf, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0444)
	if err != nil {
		return errRejected
	}
	if _, err = f.Write(body); err == nil {
		// macOS gives a new file the group of its parent directory, so the
		// anchor would inherit the parent's group and fail its own
		// safeAnchorRegular check. Bind the intended owner explicitly through
		// the open descriptor rather than by path.
		err = f.Chown(int(policy.uid), int(policy.gid))
	}
	if err == nil {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		_ = root.Remove(leaf)
		return errRejected
	}
	if err = syncTrustRoot(root); err != nil {
		return errRejected
	}
	installed, err := readRootStrictFile(root, leaf, policy)
	if err != nil || !bytes.Equal(installed, body) {
		return errRejected
	}
	return nil
}

func readRootStrictFile(root *os.Root, leaf string, policy trustAnchorPolicy) ([]byte, error) {
	if root == nil || leaf != filepath.Base(leaf) {
		return nil, errRejected
	}
	info, err := root.Lstat(leaf)
	if err != nil || !safeAnchorRegular(info, policy) {
		return nil, errRejected
	}
	f, err := root.OpenFile(leaf, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, errRejected
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !sameFile(info, opened) || !safeAnchorRegular(opened, policy) {
		return nil, errRejected
	}
	body, err := io.ReadAll(io.LimitReader(f, maxInputBytes+1))
	if err != nil || len(body) == 0 || len(body) > maxInputBytes || int64(len(body)) != info.Size() {
		return nil, errRejected
	}
	return body, nil
}

func safeAnchorRegular(info os.FileInfo, policy trustAnchorPolicy) bool {
	if info == nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || unsafeSpecialMode(info) || info.Mode().Perm() != 0444 || info.Size() < 1 || info.Size() > maxInputBytes {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat != nil && stat.Uid == policy.uid && stat.Gid == policy.gid && stat.Nlink == 1
}

func syncTrustRoot(root *os.Root) error {
	if root == nil {
		return errRejected
	}
	f, err := root.Open(".")
	if err != nil {
		return errRejected
	}
	err = f.Sync()
	closeErr := f.Close()
	if err != nil || closeErr != nil {
		return fmt.Errorf("trust anchor sync: %w", errors.Join(err, closeErr))
	}
	return nil
}
