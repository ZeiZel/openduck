package macosattest

import (
	"errors"
	"os"
	"path/filepath"

	"openduck/internal/qwenclosure"
)

// MaterializeQwenClosure is the privileged activation boundary for the signed
// inactive Qwen archive. Base deployment never calls it. It admits only the
// fixed qwen-code root, directories and regular files, applies closed modes
// and ownership, verifies the full signed inventory, then atomically publishes.
func MaterializeQwenClosure(archivePath, target, manifestPath, manifestDigest string, uid, gid int) error {
	if !filepath.IsAbs(archivePath) || !filepath.IsAbs(target) || !filepath.IsAbs(manifestPath) || filepath.Dir(target) != filepath.Dir(archivePath) || filepath.Dir(manifestPath) != filepath.Dir(archivePath) || !trustedRegularPath(archivePath) || !trustedRegularPath(manifestPath) {
		return ErrUnavailable
	}
	if _, err := os.Lstat(target); !errors.Is(err, os.ErrNotExist) {
		return ErrUnavailable
	}
	parent := filepath.Dir(target)
	if !trustedTreePath(parent) {
		return ErrUnavailable
	}
	tmp, err := os.MkdirTemp(parent, ".qwen-closure-")
	if err != nil {
		return ErrUnavailable
	}
	published := false
	defer func() {
		if !published {
			_ = os.RemoveAll(tmp)
		}
	}()
	if os.Chown(tmp, uid, gid) != nil || os.Chmod(tmp, 0750) != nil {
		return ErrUnavailable
	}
	manifestRaw, readErr := os.ReadFile(manifestPath)
	manifest, decodeErr := qwenclosure.Decode(manifestRaw)
	if readErr != nil || decodeErr != nil || qwenclosure.DigestBytes(manifestRaw) != manifestDigest || qwenclosure.ExtractArchive(archivePath, tmp, manifest, uid, gid) != nil || VerifyQwenClosure(tmp, manifestPath, manifestDigest, uint32(uid), uint32(gid)) != nil || renameNoReplace(tmp, target) != nil {
		return ErrUnavailable
	}
	published = true
	return nil
}
