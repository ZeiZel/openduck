package macosinstall

// This file implements the only supported escape hatch for a specific failed
// bootstrap shape. It intentionally does not repair an installation in place:
// when (and only when) the old root is a closed, independently authenticated
// installer/readiness tree plus its empty controller-release ancestry, it is
// atomically renamed to a sibling quarantine. The next
// deployment is therefore an ordinary fresh bootstrap rather than an upgrade
// over unknown state.

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"syscall"
)

const (
	PartialInstallRecoveryIntent = "quarantine-partial-install-v1"
	partialInstallRootName       = "OpenDuck"
	partialRecoverySchema        = "openduck.partial-install-recovery.v1"
	partialRecoveryReceiptSchema = "openduck.partial-install-receipt.v1"
	partialRecoveryReceiptName   = ".OpenDuck.partial-recovery.json"
	partialRecoveryReceiptTemp   = ".OpenDuck.partial-recovery.json.tmp"
	maxPartialRecoverySiblings   = 4096
)

var ErrPartialInstallRecoveryUncertain = errors.New("partial-install recovery uncertain; manual review required")

type partialRecoveryReceipt struct {
	Schema                string `json:"schema"`
	Version               int    `json:"version"`
	State                 string `json:"state"`
	SourceName            string `json:"source_name"`
	QuarantineName        string `json:"quarantine_name"`
	SourceDevice          uint64 `json:"source_device"`
	SourceInode           uint64 `json:"source_inode"`
	BootstrapHelperSHA256 string `json:"bootstrap_helper_sha256"`
	ReadinessHelperSHA256 string `json:"readiness_helper_sha256"`
}

type partialRecoveryFaults struct {
	QuarantineName                 func() (string, error)
	BeforePendingReceipt           func() error
	BeforeRename                   func() error
	ImmediatelyBeforeRenameSyscall func() error
	AfterRenameBeforeParentSync    func() error
	AfterParentSyncBeforeCommit    func() error
}

// PartialInstallRecoveryRequest contains only independent operator authority.
// It is deliberately unrelated to release admission: a recovery must not
// consume or replay a release nonce, and it must finish before a new signed
// deployment can bootstrap the now-absent root.
type PartialInstallRecoveryRequest struct {
	Intent                string
	BootstrapHelperPath   string
	BootstrapHelperSHA256 string
	ReadinessHelperSHA256 string
}

// PartialInstallRecoveryEvidence is bounded and safe to place in a recovery
// audit log. QuarantineName is a sibling leaf, never a caller-controlled path.
type PartialInstallRecoveryEvidence struct {
	Schema         string `json:"schema"`
	Version        int    `json:"version"`
	State          string `json:"state"`
	QuarantineName string `json:"quarantine_name,omitempty"`
}

func (e PartialInstallRecoveryEvidence) JSON() ([]byte, error) {
	if e.Schema != partialRecoverySchema || e.Version != 1 || (e.State != "eligible" && e.State != "quarantined") || (e.State == "eligible" && e.QuarantineName != "") || (e.State == "quarantined" && !validPartialQuarantineName(e.QuarantineName)) {
		return nil, errors.New("invalid partial-install recovery evidence")
	}
	return json.Marshal(e)
}

// InspectProductionPartialInstall is read-only. It is used by recovery check
// mode and never opens a deployment lock, creates a root, consumes a nonce, or
// normalizes filesystem metadata.
func InspectProductionPartialInstall(request PartialInstallRecoveryRequest) (PartialInstallRecoveryEvidence, error) {
	if runtime.GOOS != "darwin" || os.Geteuid() != 0 {
		return PartialInstallRecoveryEvidence{}, errors.New("partial-install recovery requires root on macOS")
	}
	return inspectPartialInstallAt("/Library/Application Support", partialInstallRootName, request, 0, 0)
}

// RecoverProductionPartialInstall is an explicit operator operation. It never
// runs as part of Deploy/NewProduction and it does not delete any bytes.
func RecoverProductionPartialInstall(request PartialInstallRecoveryRequest) (PartialInstallRecoveryEvidence, error) {
	if runtime.GOOS != "darwin" || os.Geteuid() != 0 {
		return PartialInstallRecoveryEvidence{}, errors.New("partial-install recovery requires root on macOS")
	}
	if err := validateRecoveryParent("/Library/Application Support", 0, 0); err != nil {
		return PartialInstallRecoveryEvidence{}, err
	}
	return recoverPartialInstallAt("/Library/Application Support", partialInstallRootName, request, 0, 0)
}

func inspectPartialInstallAt(parentPath, rootName string, request PartialInstallRecoveryRequest, uid, gid int) (PartialInstallRecoveryEvidence, error) {
	if err := validatePartialRecoveryRequest(request); err != nil {
		return PartialInstallRecoveryEvidence{}, err
	}
	parent, err := os.OpenRoot(parentPath)
	if err != nil {
		return PartialInstallRecoveryEvidence{}, errors.New("partial-install recovery parent unavailable")
	}
	defer parent.Close()
	if err := validatePartialInstallCandidate(parent, rootName, request, uid, gid); err != nil {
		return PartialInstallRecoveryEvidence{}, err
	}
	return PartialInstallRecoveryEvidence{Schema: partialRecoverySchema, Version: 1, State: "eligible"}, nil
}

func recoverPartialInstallAt(parentPath, rootName string, request PartialInstallRecoveryRequest, uid, gid int) (PartialInstallRecoveryEvidence, error) {
	return recoverPartialInstallWithFaults(parentPath, rootName, request, uid, gid, partialRecoveryFaults{})
}

// recoverPartialInstallWithFaults keeps crash seams private to package tests.
// Production supplies no faults. A durable receipt is authoritative across
// every restart, so no fault can allocate a second quarantine name.
func recoverPartialInstallWithFaults(parentPath, rootName string, request PartialInstallRecoveryRequest, uid, gid int, faults partialRecoveryFaults) (PartialInstallRecoveryEvidence, error) {
	if err := validatePartialRecoveryRequest(request); err != nil {
		return PartialInstallRecoveryEvidence{}, err
	}
	parent, err := os.OpenRoot(parentPath)
	if err != nil {
		return PartialInstallRecoveryEvidence{}, errors.New("partial-install recovery parent unavailable")
	}
	defer parent.Close()
	receipt, receiptErr := readPartialRecoveryReceipt(parent, uid, gid)
	if receiptErr != nil && !errors.Is(receiptErr, os.ErrNotExist) {
		return PartialInstallRecoveryEvidence{}, ErrPartialInstallRecoveryUncertain
	}
	if receiptErr == nil {
		return reconcilePartialRecovery(parent, rootName, request, receipt, uid, gid, faults)
	}
	if err := scanPartialRecoveryQuarantines(parent, ""); err != nil {
		return PartialInstallRecoveryEvidence{}, ErrPartialInstallRecoveryUncertain
	}
	if _, err := parent.Lstat(partialRecoveryReceiptTemp); !errors.Is(err, os.ErrNotExist) {
		return PartialInstallRecoveryEvidence{}, ErrPartialInstallRecoveryUncertain
	}
	if err := validatePartialInstallCandidate(parent, rootName, request, uid, gid); err != nil {
		return PartialInstallRecoveryEvidence{}, err
	}
	source, err := parent.Lstat(rootName)
	if err != nil {
		return PartialInstallRecoveryEvidence{}, err
	}
	device, inode, ok := recoveryFileIdentity(source)
	if !ok {
		return PartialInstallRecoveryEvidence{}, errors.New("partial-install recovery source identity unavailable")
	}
	nameGenerator := newPartialQuarantineName
	if faults.QuarantineName != nil {
		nameGenerator = faults.QuarantineName
	}
	name, err := nameGenerator()
	if err != nil {
		return PartialInstallRecoveryEvidence{}, err
	}
	if existing, statErr := parent.Lstat(name); statErr == nil || !errors.Is(statErr, os.ErrNotExist) || existing != nil {
		return PartialInstallRecoveryEvidence{}, errors.New("partial-install recovery quarantine collision")
	}
	if faults.BeforePendingReceipt != nil {
		if err := faults.BeforePendingReceipt(); err != nil {
			return PartialInstallRecoveryEvidence{}, err
		}
	}
	if err := scanPartialRecoveryQuarantines(parent, ""); err != nil {
		return PartialInstallRecoveryEvidence{}, ErrPartialInstallRecoveryUncertain
	}
	receipt = partialRecoveryReceipt{
		Schema: partialRecoveryReceiptSchema, Version: 1, State: "pending",
		SourceName: rootName, QuarantineName: name, SourceDevice: device, SourceInode: inode,
		BootstrapHelperSHA256: request.BootstrapHelperSHA256, ReadinessHelperSHA256: request.ReadinessHelperSHA256,
	}
	if err := writePartialRecoveryReceipt(parent, receipt, nil, uid, gid); err != nil {
		return PartialInstallRecoveryEvidence{}, err
	}
	return reconcilePartialRecovery(parent, rootName, request, receipt, uid, gid, faults)
}

func reconcilePartialRecovery(parent *os.Root, rootName string, request PartialInstallRecoveryRequest, receipt partialRecoveryReceipt, uid, gid int, faults partialRecoveryFaults) (PartialInstallRecoveryEvidence, error) {
	if !validPartialRecoveryReceipt(receipt, request, rootName) {
		return PartialInstallRecoveryEvidence{}, ErrPartialInstallRecoveryUncertain
	}
	if err := scanPartialRecoveryQuarantines(parent, receipt.QuarantineName); err != nil {
		return PartialInstallRecoveryEvidence{}, ErrPartialInstallRecoveryUncertain
	}
	source, sourceErr := parent.Lstat(rootName)
	destination, destinationErr := parent.Lstat(receipt.QuarantineName)
	sourceExists, destinationExists := sourceErr == nil, destinationErr == nil
	if sourceErr != nil && !errors.Is(sourceErr, os.ErrNotExist) || destinationErr != nil && !errors.Is(destinationErr, os.ErrNotExist) {
		return PartialInstallRecoveryEvidence{}, ErrPartialInstallRecoveryUncertain
	}
	if receipt.State == "quarantined" {
		if sourceExists || !destinationExists || !receiptMatchesIdentity(receipt, destination) || validatePartialInstallCandidate(parent, receipt.QuarantineName, request, uid, gid) != nil {
			return PartialInstallRecoveryEvidence{}, ErrPartialInstallRecoveryUncertain
		}
		return PartialInstallRecoveryEvidence{Schema: partialRecoverySchema, Version: 1, State: "quarantined", QuarantineName: receipt.QuarantineName}, nil
	}
	if receipt.State != "pending" {
		return PartialInstallRecoveryEvidence{}, ErrPartialInstallRecoveryUncertain
	}
	if sourceExists && destinationExists || !sourceExists && !destinationExists {
		return PartialInstallRecoveryEvidence{}, ErrPartialInstallRecoveryUncertain
	}
	if sourceExists {
		if !receiptMatchesIdentity(receipt, source) || validatePartialInstallCandidate(parent, rootName, request, uid, gid) != nil {
			return PartialInstallRecoveryEvidence{}, ErrPartialInstallRecoveryUncertain
		}
		if faults.BeforeRename != nil {
			if err := faults.BeforeRename(); err != nil {
				return PartialInstallRecoveryEvidence{}, err
			}
		}
		if err := scanPartialRecoveryQuarantines(parent, receipt.QuarantineName); err != nil {
			return PartialInstallRecoveryEvidence{}, ErrPartialInstallRecoveryUncertain
		}
		// Revalidate the exact receipt-bound source immediately before rename.
		source, sourceErr = parent.Lstat(rootName)
		if sourceErr != nil || !receiptMatchesIdentity(receipt, source) || validatePartialInstallCandidate(parent, rootName, request, uid, gid) != nil {
			return PartialInstallRecoveryEvidence{}, ErrPartialInstallRecoveryUncertain
		}
		if faults.ImmediatelyBeforeRenameSyscall != nil {
			if err := faults.ImmediatelyBeforeRenameSyscall(); err != nil {
				return PartialInstallRecoveryEvidence{}, err
			}
		}
		if err := renamePartialRecoveryExclusive(parent, rootName, receipt.QuarantineName, uid, gid); err != nil {
			return PartialInstallRecoveryEvidence{}, ErrPartialInstallRecoveryUncertain
		}
		if faults.AfterRenameBeforeParentSync != nil {
			if err := faults.AfterRenameBeforeParentSync(); err != nil {
				return PartialInstallRecoveryEvidence{}, ErrPartialInstallRecoveryUncertain
			}
		}
	}
	if err := syncRecoveryParent(parent); err != nil {
		return PartialInstallRecoveryEvidence{}, ErrPartialInstallRecoveryUncertain
	}
	if faults.AfterParentSyncBeforeCommit != nil {
		if err := faults.AfterParentSyncBeforeCommit(); err != nil {
			return PartialInstallRecoveryEvidence{}, ErrPartialInstallRecoveryUncertain
		}
	}
	if _, err := parent.Lstat(rootName); !errors.Is(err, os.ErrNotExist) {
		return PartialInstallRecoveryEvidence{}, ErrPartialInstallRecoveryUncertain
	}
	destination, err := parent.Lstat(receipt.QuarantineName)
	if err != nil || !receiptMatchesIdentity(receipt, destination) || validatePartialInstallCandidate(parent, receipt.QuarantineName, request, uid, gid) != nil {
		return PartialInstallRecoveryEvidence{}, ErrPartialInstallRecoveryUncertain
	}
	committed := receipt
	committed.State = "quarantined"
	if err := writePartialRecoveryReceipt(parent, committed, &receipt, uid, gid); err != nil {
		return PartialInstallRecoveryEvidence{}, ErrPartialInstallRecoveryUncertain
	}
	return PartialInstallRecoveryEvidence{Schema: partialRecoverySchema, Version: 1, State: "quarantined", QuarantineName: receipt.QuarantineName}, nil
}

func readPartialRecoveryReceipt(parent *os.Root, uid, gid int) (partialRecoveryReceipt, error) {
	info, err := parent.Lstat(partialRecoveryReceiptName)
	if err != nil {
		return partialRecoveryReceipt{}, err
	}
	if !safeRecoveryReceipt(info, uid, gid) {
		return partialRecoveryReceipt{}, errors.New("partial-install recovery receipt unsafe")
	}
	raw, err := parent.ReadFile(partialRecoveryReceiptName)
	if err != nil || len(raw) == 0 || len(raw) > 4096 {
		return partialRecoveryReceipt{}, errors.New("partial-install recovery receipt unavailable")
	}
	var receipt partialRecoveryReceipt
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&receipt); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return partialRecoveryReceipt{}, errors.New("partial-install recovery receipt malformed")
	}
	canonical, err := marshalPartialRecoveryReceipt(receipt)
	if err != nil || !bytes.Equal(raw, canonical) {
		return partialRecoveryReceipt{}, errors.New("partial-install recovery receipt noncanonical")
	}
	return receipt, nil
}

func writePartialRecoveryReceipt(parent *os.Root, receipt partialRecoveryReceipt, expected *partialRecoveryReceipt, uid, gid int) (resultErr error) {
	raw, err := marshalPartialRecoveryReceipt(receipt)
	if err != nil {
		return err
	}
	if _, err := parent.Lstat(partialRecoveryReceiptTemp); !errors.Is(err, os.ErrNotExist) {
		return errors.New("partial-install recovery receipt collision")
	}
	f, err := parent.OpenFile(partialRecoveryReceiptTemp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return errors.New("partial-install recovery receipt create failed")
	}
	defer func() {
		if resultErr != nil {
			_ = parent.Remove(partialRecoveryReceiptTemp)
		}
	}()
	if err = f.Chown(uid, gid); err == nil {
		err = f.Chmod(0600)
	}
	if err == nil {
		_, err = f.Write(raw)
	}
	if err == nil {
		err = f.Sync()
	}
	info, statErr := f.Stat()
	closeErr := f.Close()
	if err != nil || statErr != nil || closeErr != nil || !safeRecoveryReceipt(info, uid, gid) || info.Size() != int64(len(raw)) {
		return errors.New("partial-install recovery receipt durability failed")
	}
	if expected == nil {
		if _, err := parent.Lstat(partialRecoveryReceiptName); !errors.Is(err, os.ErrNotExist) {
			return errors.New("partial-install recovery receipt collision")
		}
	} else {
		current, err := readPartialRecoveryReceipt(parent, uid, gid)
		if err != nil || current != *expected {
			return ErrPartialInstallRecoveryUncertain
		}
	}
	if err := parent.Rename(partialRecoveryReceiptTemp, partialRecoveryReceiptName); err != nil {
		return errors.New("partial-install recovery receipt commit failed")
	}
	if err := syncRecoveryParent(parent); err != nil {
		return errors.New("partial-install recovery receipt parent sync failed")
	}
	return nil
}

func marshalPartialRecoveryReceipt(receipt partialRecoveryReceipt) ([]byte, error) {
	if receipt.Schema != partialRecoveryReceiptSchema || receipt.Version != 1 || receipt.SourceName != partialInstallRootName || !validPartialQuarantineName(receipt.QuarantineName) || receipt.SourceDevice == 0 || receipt.SourceInode == 0 || !isDigest(receipt.BootstrapHelperSHA256) || !isDigest(receipt.ReadinessHelperSHA256) || (receipt.State != "pending" && receipt.State != "quarantined") {
		return nil, errors.New("invalid partial-install recovery receipt")
	}
	raw, err := json.Marshal(receipt)
	if err != nil {
		return nil, err
	}
	return append(raw, '\n'), nil
}

func validPartialRecoveryReceipt(receipt partialRecoveryReceipt, request PartialInstallRecoveryRequest, rootName string) bool {
	_, err := marshalPartialRecoveryReceipt(receipt)
	return err == nil && receipt.SourceName == rootName && receipt.BootstrapHelperSHA256 == request.BootstrapHelperSHA256 && receipt.ReadinessHelperSHA256 == request.ReadinessHelperSHA256
}

func safeRecoveryReceipt(info os.FileInfo, uid, gid int) bool {
	if info == nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 || info.Mode().Perm() != 0600 || info.Size() <= 0 || info.Size() > 4096 {
		return false
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	return ok && st != nil && st.Nlink == 1 && int(st.Uid) == uid && int(st.Gid) == gid
}

func syncRecoveryParent(parent *os.Root) error {
	f, err := parent.Open(".")
	if err != nil {
		return err
	}
	syncErr := f.Sync()
	closeErr := f.Close()
	return errors.Join(syncErr, closeErr)
}

func renamePartialRecoveryExclusive(parent *os.Root, source, destination string, uid, gid int) error {
	if parent == nil || source != partialInstallRootName || !validPartialQuarantineName(destination) {
		return ErrPartialInstallRecoveryUncertain
	}
	pathInfo, err := parent.Lstat(".")
	if err != nil || !trustedRecoveryParentInfo(pathInfo, uid, gid) {
		return ErrPartialInstallRecoveryUncertain
	}
	dir, err := parent.Open(".")
	if err != nil {
		return ErrPartialInstallRecoveryUncertain
	}
	openedInfo, statErr := dir.Stat()
	if statErr != nil || !sameFileIdentity(pathInfo, openedInfo) || pathInfo.Mode() != openedInfo.Mode() || !trustedRecoveryParentInfo(openedInfo, uid, gid) {
		_ = dir.Close()
		return ErrPartialInstallRecoveryUncertain
	}
	renameErr := recoveryRenameatx(int(dir.Fd()), source, destination)
	closeErr := dir.Close()
	if renameErr != nil || closeErr != nil {
		return ErrPartialInstallRecoveryUncertain
	}
	return nil
}

func trustedRecoveryParentInfo(info os.FileInfo, uid, gid int) bool {
	if info == nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 || info.Mode().Perm()&0022 != 0 {
		return false
	}
	return ownedBy(info, uint32(uid), uint32(gid))
}

// scanPartialRecoveryQuarantines enumerates sibling names through the already
// opened trusted parent. ReadDir does not follow entries. The bound prevents a
// hostile or corrupted parent from turning recovery admission into unbounded
// work; any exact quarantine other than the receipt-authorized leaf fails
// closed regardless of entry type.
func scanPartialRecoveryQuarantines(parent *os.Root, allowed string) error {
	if parent == nil || allowed != "" && !validPartialQuarantineName(allowed) {
		return errors.New("partial-install recovery sibling scan invalid")
	}
	dir, err := parent.Open(".")
	if err != nil {
		return errors.New("partial-install recovery sibling scan unavailable")
	}
	entries, readErr := dir.ReadDir(maxPartialRecoverySiblings + 1)
	closeErr := dir.Close()
	if readErr != nil && !errors.Is(readErr, io.EOF) || closeErr != nil || len(entries) > maxPartialRecoverySiblings {
		return errors.New("partial-install recovery sibling scan failed")
	}
	for _, entry := range entries {
		if validPartialQuarantineName(entry.Name()) && entry.Name() != allowed {
			return ErrPartialInstallRecoveryUncertain
		}
	}
	return nil
}

func recoveryFileIdentity(info os.FileInfo) (uint64, uint64, bool) {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st == nil {
		return 0, 0, false
	}
	return uint64(st.Dev), uint64(st.Ino), true
}

func receiptMatchesIdentity(receipt partialRecoveryReceipt, info os.FileInfo) bool {
	device, inode, ok := recoveryFileIdentity(info)
	return ok && device == receipt.SourceDevice && inode == receipt.SourceInode
}

func validatePartialRecoveryRequest(request PartialInstallRecoveryRequest) error {
	if request.Intent != PartialInstallRecoveryIntent || !filepath.IsAbs(request.BootstrapHelperPath) || !isDigest(request.BootstrapHelperSHA256) || !isDigest(request.ReadinessHelperSHA256) || strings.HasPrefix(filepath.Clean(request.BootstrapHelperPath), SystemRoot+string(filepath.Separator)) || filepath.Clean(request.BootstrapHelperPath) == SystemRoot {
		return errors.New("explicit independent partial-install recovery authority required")
	}
	info, err := os.Lstat(request.BootstrapHelperPath)
	if err != nil || !safeRecoveryHelper(info, -1, -1) {
		return errors.New("independent partial-install recovery helper unsafe")
	}
	f, err := os.Open(request.BootstrapHelperPath)
	if err != nil {
		return errors.New("independent partial-install recovery helper unavailable")
	}
	hash := sha256.New()
	written, copyErr := io.Copy(hash, io.LimitReader(f, (64<<20)+1))
	closeErr := f.Close()
	if copyErr != nil || closeErr != nil || written > 64<<20 || hex.EncodeToString(hash.Sum(nil)) != request.BootstrapHelperSHA256 {
		return errors.New("independent partial-install recovery helper digest mismatch")
	}
	return nil
}

func validatePartialInstallCandidate(parent *os.Root, rootName string, request PartialInstallRecoveryRequest, uid, gid int) error {
	if parent == nil || (rootName != partialInstallRootName && !validPartialQuarantineName(rootName)) {
		return errors.New("partial-install recovery root contract invalid")
	}
	before, err := parent.Lstat(rootName)
	if err != nil || !trustedInstallRoot(before, uint32(uid), uint32(gid)) {
		return errors.New("partial-install recovery root unsafe")
	}
	root, err := parent.OpenRoot(rootName)
	if err != nil {
		return errors.New("partial-install recovery root unavailable")
	}
	defer root.Close()
	f, err := root.Open(".")
	if err != nil {
		return errors.New("partial-install recovery root unavailable")
	}
	opened, statErr := f.Stat()
	entries, readErr := f.ReadDir(8)
	closeErr := f.Close()
	if statErr != nil || readErr != nil || closeErr != nil || !sameFileIdentity(before, opened) || !trustedInstallRoot(opened, uint32(uid), uint32(gid)) {
		return errors.New("partial-install recovery root changed")
	}
	if len(entries) != 3 {
		return errors.New("partial-install recovery root is not the closed helper tree")
	}
	names := []string{entries[0].Name(), entries[1].Name(), entries[2].Name()}
	sort.Strings(names)
	if strings.Join(names, ",") != ".openduck-installer,.openduck-readiness,releases" {
		return errors.New("partial-install recovery root has unexpected state")
	}
	for _, name := range []string{".openduck-installer", ".openduck-readiness"} {
		info, statErr := root.Lstat(name)
		if statErr != nil || !safeRecoveryHelper(info, uid, gid) {
			return errors.New("partial-install recovery helper unsafe")
		}
		body, readErr := root.ReadFile(name)
		expected := request.BootstrapHelperSHA256
		if name == ".openduck-readiness" {
			expected = request.ReadinessHelperSHA256
		}
		if readErr != nil || len(body) == 0 || len(body) > 64<<20 || Digest(body) != expected {
			return errors.New("partial-install recovery helper digest mismatch")
		}
	}
	releases, releaseErr := root.OpenRoot("releases")
	if releaseErr != nil {
		return errors.New("partial-install recovery releases ancestry unsafe")
	}
	defer releases.Close()
	releasesInfo, releasesStatErr := root.Lstat("releases")
	controllerInfo, controllerStatErr := releases.Lstat("controller")
	releaseDir, openErr := releases.Open(".")
	if releasesStatErr != nil || controllerStatErr != nil || openErr != nil || !trustedInstallRoot(releasesInfo, uint32(uid), uint32(gid)) || releasesInfo.Mode().Perm() != 0711 || !trustedRecoveryDirectory(controllerInfo, uid, gid, 0750) {
		if releaseDir != nil {
			_ = releaseDir.Close()
		}
		return errors.New("partial-install recovery releases ancestry unsafe")
	}
	releaseEntries, releaseReadErr := releaseDir.ReadDir(2)
	releaseCloseErr := releaseDir.Close()
	if (releaseReadErr != nil && !errors.Is(releaseReadErr, io.EOF)) || releaseCloseErr != nil || len(releaseEntries) != 1 || releaseEntries[0].Name() != "controller" {
		return errors.New("partial-install recovery releases ancestry unsafe")
	}
	controller, controllerOpenErr := releases.Open("controller")
	if controllerOpenErr != nil {
		return errors.New("partial-install recovery releases ancestry unsafe")
	}
	controllerEntries, controllerReadErr := controller.ReadDir(1)
	controllerCloseErr := controller.Close()
	if (controllerReadErr != nil && !errors.Is(controllerReadErr, io.EOF)) || controllerCloseErr != nil || len(controllerEntries) != 0 {
		return errors.New("partial-install recovery releases ancestry unsafe")
	}
	after, err := parent.Lstat(rootName)
	if err != nil || !sameFileIdentity(before, after) || !trustedInstallRoot(after, uint32(uid), uint32(gid)) {
		return errors.New("partial-install recovery root changed")
	}
	return nil
}

func trustedRecoveryDirectory(info os.FileInfo, uid, gid int, mode os.FileMode) bool {
	return info != nil && info.IsDir() && info.Mode()&os.ModeSymlink == 0 && info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) == 0 && info.Mode().Perm() == mode && ownedBy(info, uint32(uid), uint32(gid))
}

func safeRecoveryHelper(info os.FileInfo, uid, gid int) bool {
	if info == nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 || info.Mode().Perm() != 0700 || info.Size() <= 0 || info.Size() > 64<<20 {
		return false
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st == nil || st.Nlink != 1 {
		return false
	}
	return (uid < 0 || int(st.Uid) == uid) && (gid < 0 || int(st.Gid) == gid)
}

func validateRecoveryParent(parentPath string, uid, gid int) error {
	for _, path := range []string{"/Library", parentPath} {
		info, err := os.Lstat(path)
		if err != nil || info == nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 || info.Mode().Perm()&0022 != 0 || !ownedBy(info, uint32(uid), uint32(gid)) {
			return errors.New("partial-install recovery trusted parent unsafe")
		}
	}
	return nil
}

func newPartialQuarantineName() (string, error) {
	b := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", fmt.Errorf("partial-install recovery random unavailable: %w", err)
	}
	return "OpenDuck.quarantine-" + hex.EncodeToString(b), nil
}

func validPartialQuarantineName(value string) bool {
	if !strings.HasPrefix(value, "OpenDuck.quarantine-") || len(value) != len("OpenDuck.quarantine-")+32 {
		return false
	}
	suffix := strings.TrimPrefix(value, "OpenDuck.quarantine-")
	if strings.Trim(suffix, "0123456789abcdef") != "" {
		return false
	}
	_, err := hex.DecodeString(suffix)
	return err == nil
}
