package macoschannel

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

type releaseManifest struct {
	ReleaseID    string `json:"release_id"`
	Binary       string `json:"binary"`
	Socket       string `json:"socket"`
	BinaryDigest string `json:"binary_digest"`
	SocketDigest string `json:"socket_digest"`
}

// VerifyRelease applies the conservative default policy for direct callers.
// Config validation uses the same FD-rooted verifier with its explicit policy.
func VerifyRelease(root *os.Root, pin ReleasePin, binaryName string) error {
	// Keep the public default aligned with the production Config defaults:
	// manifest is 0600 while the executable and release root are 0700.
	return verifyRelease(root, pin, binaryName, uint32(os.Geteuid()), uint32(os.Getegid()), 0600, 0700, 0700)
}

// VerifyReleaseOwned verifies an immutable release under an already-open root
// whose owner is intentionally different from the consuming service. It is
// used for the root-owned Codex artifact: the runtime may execute it but
// cannot replace its manifest or binary.
func VerifyReleaseOwned(root *os.Root, pin ReleasePin, binaryName string, uid, gid uint32, manifestMode, binaryMode, rootMode os.FileMode) error {
	return verifyRelease(root, pin, binaryName, uid, gid, manifestMode, binaryMode, rootMode)
}

func verifyReleaseRoot(cfg Config) error {
	if cfg.ReleaseRoot == nil {
		return ErrRelease
	}
	fi, err := cfg.ReleaseRoot.Lstat(".")
	if err != nil || !fi.IsDir() || fi.Mode()&os.ModeSymlink != 0 || !matchesFile(fi, cfg.ExpectedReleaseRootUID, cfg.ExpectedReleaseRootGID, cfg.ExpectedReleaseRootMode) {
		return ErrRelease
	}
	return nil
}

// verifyRelease never opens a component through a pathname outside root. The
// manifest, binary and socket names are leaves, so there is no unchecked
// intermediate component or symlink to follow.
func verifyRelease(root *os.Root, pin ReleasePin, binaryName string, uid, gid uint32, manifestMode, binaryMode, rootMode os.FileMode) error {
	if root == nil || pin.validate() != nil || !safeLeaf(binaryName) || !validMode(manifestMode, false) || !validMode(binaryMode, false) {
		return ErrRelease
	}
	rootInfo, err := root.Lstat(".")
	if err != nil || !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 || !matchesFile(rootInfo, uid, gid, rootMode) {
		return ErrRelease
	}
	mst, err := root.Lstat("manifest.json")
	if err != nil || !mst.Mode().IsRegular() || mst.Mode()&os.ModeSymlink != 0 || !matchesFile(mst, uid, gid, manifestMode) {
		return ErrRelease
	}
	m, err := root.Open("manifest.json")
	if err != nil {
		return ErrRelease
	}
	defer m.Close()
	raw, err := readLimitedExact(m, 64<<10)
	if err != nil {
		return ErrRelease
	}
	if hexDigest(raw) != pin.ManifestDigest {
		return ErrRelease
	}
	var man releaseManifest
	if err := decodeManifest(raw, &man); err != nil {
		return ErrRelease
	}
	if man.ReleaseID != pin.ReleaseID || man.Binary != binaryName || man.BinaryDigest != pin.BinaryDigest || man.SocketDigest != pin.SocketDigest || !safeLeaf(man.Socket) {
		return ErrRelease
	}
	return verifyRegular(root, binaryName, pin.BinaryDigest, uid, gid, binaryMode)
}

func safeLeaf(name string) bool {
	return name != "" && !filepath.IsAbs(name) && filepath.Base(name) == name && filepath.Clean(name) == name && name != "."
}
func readLimitedExact(r io.Reader, max int64) ([]byte, error) {
	lr := &io.LimitedReader{R: r, N: max + 1}
	b, err := io.ReadAll(lr)
	if err != nil || int64(len(b)) > max {
		return nil, ErrRelease
	}
	return b, nil
}
func decodeManifest(raw []byte, out *releaseManifest) error {
	// Use the handshake's exact-object parser so duplicate, unknown, missing,
	// null and trailing JSON are all rejected before typed decoding.
	return decodeExactJSON(raw, out, []string{"release_id", "binary", "socket", "binary_digest", "socket_digest"})
}
func verifyRegular(root *os.Root, name, digest string, uid, gid uint32, mode os.FileMode) error {
	if !safeLeaf(name) {
		return ErrRelease
	}
	st, err := root.Lstat(name)
	if err != nil || !st.Mode().IsRegular() || st.Mode()&os.ModeSymlink != 0 || !matchesFile(st, uid, gid, mode) {
		return ErrRelease
	}
	f, err := root.Open(name)
	if err != nil {
		return ErrRelease
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !opened.Mode().IsRegular() || !matchesFile(opened, uid, gid, mode) {
		return ErrRelease
	}
	b, err := readLimitedExact(f, 64<<20)
	if err != nil || hexDigest(b) != digest {
		return ErrRelease
	}
	return nil
}

func SocketMetadataDigest(root *os.Root, name string) (string, error) {
	if root == nil || !safeLeaf(name) {
		return "", ErrRelease
	}
	fi, err := root.Lstat(name)
	if err != nil || fi.Mode()&os.ModeSocket == 0 {
		return "", ErrRelease
	}
	return SocketMetadataDigestFromInfo(fi, name)
}
func SocketMetadataDigestFromInfo(fi os.FileInfo, name string) (string, error) {
	if fi == nil || !safeLeaf(name) || fi.Mode()&os.ModeSocket == 0 || hasSecurityModeBits(fi.Mode()) {
		return "", ErrRelease
	}
	x, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return "", ErrRelease
	}
	return socketDigest(name, uint32(x.Uid), uint32(x.Gid), fi.Mode().Perm()), nil
}

// SocketMetadataDigestForContract computes the same canonical digest used by
// live socket verification for an offline planned endpoint.
func SocketMetadataDigestForContract(name string, uid, gid uint32, mode os.FileMode) (string, error) {
	if !safeLeaf(name) || hasSecurityModeBits(mode) || mode.Perm() == 0 {
		return "", ErrRelease
	}
	return socketDigest(name, uid, gid, mode), nil
}

func socketDigest(name string, uid, gid uint32, mode os.FileMode) string {
	h := sha256.New()
	_, _ = h.Write([]byte(name))
	_, _ = h.Write([]byte{0})
	var modeBytes [4]byte
	binary.BigEndian.PutUint32(modeBytes[:], uint32(mode.Perm()|(mode&securityModeBits)))
	_, _ = h.Write(modeBytes[:])
	var ids [8]byte
	binary.BigEndian.PutUint32(ids[:4], uid)
	binary.BigEndian.PutUint32(ids[4:], gid)
	_, _ = h.Write(ids[:])
	return hex.EncodeToString(h.Sum(nil))
}

func decodeExactJSON(raw []byte, out any, fields []string) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	tok, err := dec.Token()
	if err != nil {
		return ErrProtocol
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return ErrProtocol
	}
	want, got := map[string]struct{}{}, map[string]struct{}{}
	for _, f := range fields {
		want[f] = struct{}{}
	}
	for dec.More() {
		t, err := dec.Token()
		if err != nil {
			return ErrProtocol
		}
		key, ok := t.(string)
		if !ok {
			return ErrProtocol
		}
		if _, ok = want[key]; !ok {
			return ErrProtocol
		}
		if _, ok = got[key]; ok {
			return ErrProtocol
		}
		var value json.RawMessage
		if dec.Decode(&value) != nil || bytes.Equal(value, []byte("null")) {
			return ErrProtocol
		}
		got[key] = struct{}{}
	}
	if tok, err = dec.Token(); err != nil || tok != json.Delim('}') || len(got) != len(want) {
		return ErrProtocol
	}
	var extra any
	if dec.Decode(&extra) != io.EOF {
		return ErrProtocol
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(out) != nil {
		return ErrProtocol
	}
	return nil
}
