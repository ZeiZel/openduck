// openduck-provider-evidence verifies sanitized offline evidence artifacts.
// It never contacts a provider, reads environment variables, credentials, or keys.
package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"openduck/internal/providerbridge"
)

const maxDescriptorBytes = 8 << 20

var (
	errDescriptor = errors.New("invalid descriptor")
	errOutput     = errors.New("unable to create output")
)

type evidenceReviewRequest struct {
	SchemaVersion       string                                 `json:"schema_version"`
	CompatibilityRecord providerbridge.CompatibilityRecord     `json:"compatibility_record"`
	CompatibilityDigest string                                 `json:"compatibility_digest"`
	Evidence            *providerbridge.ProviderEvidenceRecord `json:"evidence,omitempty"`
	EvidenceDigest      string                                 `json:"evidence_digest,omitempty"`
	RequiredRoles       []string                               `json:"required_roles"`
}

func main() {
	var recordPath, evidencePath, trustPath, runtimePath, protocolPath, toolsPath, transcriptPath, outputPath, at string
	var verifyEvidence bool
	flag.StringVar(&recordPath, "record", "", "canonical compatibility record JSON")
	flag.StringVar(&evidencePath, "evidence", "", "canonical provider evidence JSON")
	flag.StringVar(&trustPath, "trust", "", "canonical Ed25519 public trust JSON")
	flag.StringVar(&runtimePath, "runtime", "", "sanitized runtime artifact descriptor")
	flag.StringVar(&protocolPath, "protocol-schema", "", "sanitized protocol schema descriptor")
	flag.StringVar(&toolsPath, "tool-schema", "", "sanitized mesh tool schema descriptor")
	flag.StringVar(&transcriptPath, "transcript", "", "sanitized transcript descriptor")
	flag.StringVar(&outputPath, "output", "", "new unsigned review request output")
	flag.StringVar(&at, "at", "", "RFC3339 verification instant")
	flag.BoolVar(&verifyEvidence, "verify-evidence", false, "verify evidence with -trust at -at")
	flag.Parse()
	if recordPath == "" {
		fail(errors.New("record required"))
	}
	recordBytes, err := readDescriptor(recordPath)
	if err != nil {
		fail(err)
	}
	compatibility, err := providerbridge.DecodeCompatibilityRecord(recordBytes)
	if err != nil {
		fail(err)
	}
	descriptors := []struct{ path, want string }{{runtimePath, compatibility.RuntimeArtifactDigest}, {protocolPath, compatibility.ProtocolSchemaDigest}, {toolsPath, compatibility.MeshToolSchemaDigest}, {transcriptPath, compatibility.TranscriptDigest}}
	provided := 0
	for _, check := range descriptors {
		if check.path != "" {
			provided++
		}
	}
	if (provided != 0 && provided != len(descriptors)) || (outputPath != "" && provided != len(descriptors)) {
		fail(errors.New("all sanitized descriptors required for review output"))
	}
	for _, check := range descriptors {
		if check.path == "" {
			continue
		}
		bytes, err := readDescriptor(check.path)
		if err != nil || hash(bytes) != check.want {
			fail(errDescriptor)
		}
	}
	var evidence *providerbridge.ProviderEvidenceRecord
	if evidencePath != "" {
		bytes, err := readDescriptor(evidencePath)
		if err != nil {
			fail(err)
		}
		parsed, err := providerbridge.DecodeProviderEvidenceRecord(bytes)
		if err != nil || !providerbridge.EvidenceMatchesCompatibility(parsed, compatibility) {
			fail(errors.New("evidence does not bind compatibility"))
		}
		if outputPath != "" && len(parsed.Approvals) != 0 {
			fail(errors.New("review output requires unsigned evidence"))
		}
		evidence = &parsed
	}
	if verifyEvidence {
		if evidence == nil || trustPath == "" || at == "" {
			fail(errors.New("evidence, trust, and verification instant required"))
		}
		trustBytes, err := readDescriptor(trustPath)
		if err != nil {
			fail(err)
		}
		trust, err := providerbridge.DecodeEd25519TrustBundle(trustBytes)
		if err != nil {
			fail(err)
		}
		verifier, err := trust.Verifier()
		if err != nil {
			fail(err)
		}
		now, err := time.Parse(time.RFC3339, at)
		if err != nil || providerbridge.VerifyEvidence(*evidence, trust.TrustRegistry(), verifier, now.UTC()) != nil {
			fail(errors.New("evidence verification failed"))
		}
	}
	if outputPath == "" {
		return
	}
	request := evidenceReviewRequest{SchemaVersion: "provider-compatibility-review-request.v1", CompatibilityRecord: compatibility, CompatibilityDigest: compatibility.Digest, RequiredRoles: []string{"technical", "security"}}
	if evidence != nil {
		request.SchemaVersion = "provider-evidence-review-request.v1"
		request.Evidence, request.EvidenceDigest = evidence, evidence.Digest
	}
	bytes, err := json.Marshal(request)
	if err != nil || writeNoOverwrite(outputPath, bytes) != nil {
		fail(errOutput)
	}
}

// readDescriptor opens exactly one non-symlinked, single-link regular file
// and reads from that descriptor, avoiding Lstat/ReadFile TOCTOU windows.
func readDescriptor(path string) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, errDescriptor
	}
	defer f.Close()
	return readOpenedDescriptor(f)
}

func readOpenedDescriptor(f *os.File) ([]byte, error) {
	if f == nil {
		return nil, errDescriptor
	}
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > maxDescriptorBytes {
		return nil, errDescriptor
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Nlink != 1 {
		return nil, errDescriptor
	}
	bytes, err := io.ReadAll(io.LimitReader(f, maxDescriptorBytes+1))
	if err != nil || len(bytes) == 0 || len(bytes) > maxDescriptorBytes {
		return nil, errDescriptor
	}
	return bytes, nil
}

// writeNoOverwrite materializes a complete 0600 file first and atomically
// links it into place, so an existing or symlink output is never replaced.
func writeNoOverwrite(outputPath string, bytes []byte) error {
	return writeNoOverwriteWithHooks(outputPath, bytes, publicationHooks{})
}

// publicationHooks makes post-link cleanup and parent-replacement defenses
// deterministically testable. Production always supplies zero hooks.
type publicationHooks struct {
	beforeLink func()
	afterLink  func() error
}

func writeNoOverwriteWithHooks(outputPath string, bytes []byte, hooks publicationHooks) error {
	if outputPath == "" || len(bytes) == 0 {
		return errOutput
	}
	dir := filepath.Dir(outputPath)
	target := filepath.Base(filepath.Clean(outputPath))
	if target == "." || target == ".." || target == string(filepath.Separator) {
		return errOutput
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return errOutput
	}
	defer root.Close()
	parentInfo, err := rootParentInfo(root)
	if err != nil || !sameNamedParent(dir, parentInfo) {
		return errOutput
	}
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return errOutput
	}
	temp := ".openduck-provider-evidence-" + hex.EncodeToString(random[:])
	f, err := root.OpenFile(temp, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
	if err != nil {
		return errOutput
	}
	var expected os.FileInfo
	published := false
	success := false
	defer func() {
		if !success {
			if published {
				_ = removeIfSame(root, target, expected)
			}
			_ = removeIfSame(root, temp, expected)
			_ = syncRoot(root)
		}
	}()
	expected, err = f.Stat()
	if err != nil || !validPublishedFile(expected, 0, 1) {
		_ = f.Close()
		return errOutput
	}
	if err := f.Chmod(0600); err != nil {
		_ = f.Close()
		return errOutput
	}
	if err := writeAll(f, bytes); err != nil {
		_ = f.Close()
		return errOutput
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return errOutput
	}
	expected, err = f.Stat()
	if err != nil || !validPublishedFile(expected, int64(len(bytes)), 1) {
		_ = f.Close()
		return errOutput
	}
	if hooks.beforeLink != nil {
		hooks.beforeLink()
	}
	if !sameNamedParent(dir, parentInfo) {
		_ = f.Close()
		return errOutput
	}
	if err := f.Close(); err != nil {
		return errOutput
	}
	if err := root.Link(temp, target); err != nil {
		return errOutput
	}
	published = true
	if hooks.afterLink != nil && hooks.afterLink() != nil {
		return errOutput
	}
	if !sameNamedParent(dir, parentInfo) || syncRoot(root) != nil {
		return errOutput
	}
	if err := root.Remove(temp); err != nil {
		return errOutput
	}
	if !sameNamedParent(dir, parentInfo) || syncRoot(root) != nil {
		return errOutput
	}
	finalInfo, err := root.Lstat(target)
	if err != nil || !os.SameFile(finalInfo, expected) || !validPublishedFile(finalInfo, int64(len(bytes)), 1) {
		return errOutput
	}
	success = true
	return nil
}

func rootParentInfo(root *os.Root) (os.FileInfo, error) {
	dir, err := root.Open(".")
	if err != nil {
		return nil, errOutput
	}
	defer dir.Close()
	info, err := dir.Stat()
	if err != nil || !info.IsDir() {
		return nil, errOutput
	}
	return info, nil
}

func sameNamedParent(path string, expected os.FileInfo) bool {
	actual, err := os.Stat(path)
	return err == nil && actual.IsDir() && os.SameFile(actual, expected)
}

func syncRoot(root *os.Root) error {
	dir, err := root.Open(".")
	if err != nil {
		return errOutput
	}
	err = dir.Sync()
	closeErr := dir.Close()
	if err != nil || closeErr != nil {
		return errOutput
	}
	return nil
}

func removeIfSame(root *os.Root, name string, expected os.FileInfo) error {
	if expected == nil {
		return errOutput
	}
	info, err := root.Lstat(name)
	if err != nil || !os.SameFile(info, expected) || !info.Mode().IsRegular() {
		return errOutput
	}
	return root.Remove(name)
}

func validPublishedFile(info os.FileInfo, size int64, links uint64) bool {
	if info == nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() != size {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && uint64(stat.Nlink) == links
}

func hash(value []byte) string {
	return providerbridge.DigestBytes(value)
}

func writeAll(file *os.File, bytes []byte) error {
	for len(bytes) > 0 {
		count, err := file.Write(bytes)
		if err != nil || count <= 0 {
			return errOutput
		}
		bytes = bytes[count:]
	}
	return nil
}
func fail(err error) { fmt.Fprintln(os.Stderr, "openduck-provider-evidence:", err); os.Exit(2) }
