// Package macosrelease admits a signed, staged macOS release before any
// privileged installer action. It deliberately has no controller or installer
// dependency: composition supplies its expected release and a nonce store.
package macosrelease

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"openduck/internal/releasecatalog"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

const (
	EnvelopeSchema      = "openduck.release-envelope.v1"
	ManifestSchema      = "openduck.release-manifest.v2"
	TrustBundleSchema   = "openduck.release-trust.v1"
	nonceStateSchema    = "openduck.release-nonce-state.v1"
	maxInputBytes       = 1 << 20
	maxArtifactBytes    = 64 << 20
	maxArtifactSetBytes = 256 << 20
	maxArtifacts        = 256
	maxNonces           = 1024
)

var errRejected = errors.New("release admission rejected")

// Artifact identifies one content-addressed staged payload. The target is
// unique, typed, and platform specific; arbitrary file names are not accepted.
type Artifact struct {
	Type            string `json:"type"`
	Path            string `json:"path"`
	Digest          string `json:"digest"`
	Platform        string `json:"platform"`
	Arch            string `json:"arch"`
	Version         string `json:"version"`
	ActivationGroup string `json:"activation_group"`
	Required        bool   `json:"required"`
}

type ManifestV2 struct {
	Schema        string     `json:"schema"`
	ReleaseID     string     `json:"release_id"`
	ReleaseDigest string     `json:"release_digest"`
	Version       string     `json:"version"`
	TargetRoot    string     `json:"target_root"`
	Artifacts     []Artifact `json:"artifacts"`
}

type EnvelopeV1 struct {
	Schema string `json:"schema"`
	KeyID  string `json:"key_id"`
	// ReleaseID is emitted by the offline packager. It remains omitted for
	// legacy envelopes so existing admission artifacts retain their bytes.
	ReleaseID         string    `json:"release_id,omitempty"`
	ManifestDigest    string    `json:"manifest_digest"`
	ArtifactSetDigest string    `json:"artifact_set_digest"`
	ReleaseDigest     string    `json:"release_digest"`
	ReleaseVersion    string    `json:"release_version"`
	TargetRoot        string    `json:"target_root"`
	Platform          string    `json:"platform"`
	Arch              string    `json:"arch"`
	MinInstaller      string    `json:"min_installer"`
	Operation         string    `json:"operation"`
	RunID             string    `json:"run_id"`
	Activation        string    `json:"activation"`
	Nonce             string    `json:"nonce"`
	Signature         string    `json:"signature"`
	Sequence          uint64    `json:"sequence"`
	IssuedAt          time.Time `json:"issued_at"`
	ExpiresAt         time.Time `json:"expires_at"`
}

type TrustBundle struct {
	Schema  string            `json:"schema"`
	Keys    map[string]string `json:"keys"`
	Revoked []string          `json:"revoked"`
}

// AdmissionRequest is the complete composition-time binding. Every expected
// value is explicit, so a valid envelope cannot be replayed for another root,
// release, platform, or installer version.
type AdmissionRequest struct {
	EnvelopePath           string
	ManifestPath           string
	TrustBundlePath        string
	StagedRoot             string
	ExpectedReleaseID      string
	ExpectedReleaseDigest  string
	ExpectedReleaseVersion string
	ExpectedTargetRoot     string
	ExpectedPlatform       string
	ExpectedArch           string
	ExpectedOperation      string
	ExpectedRunID          string
	ExpectedActivation     bool
	InstallerVersion       string
	Now                    time.Time
}

type Admission struct {
	envelope  EnvelopeV1
	manifest  ManifestV2
	artifacts []verifiedArtifact
	seal      *admissionSeal
}

// admissionSeal is deliberately unexported. Callers can name Admission but
// cannot manufacture a value that exposes an admitted manifest or consumes a
// nonce: both operations require the seal installed only by ValidateAdmission.
type admissionSeal struct{}

type verifiedArtifact struct {
	Artifact
	body []byte
	dev  uint64
	ino  uint64
}

// Snapshot is a root-owned materialization of the verified artifact bytes.
// Its filesystem location remains private so a caller cannot retarget a valid
// seal at another directory.
type Snapshot struct {
	path      string
	bindingID string
	seal      *snapshotSeal
}

type snapshotSeal struct{}

// DeploymentInput is the sole production hand-off from release admission to
// macOS installation. Its private seal prevents callers from fabricating a
// release/manifest/snapshot tuple out of arbitrary files.
type DeploymentInput struct {
	manifest   ManifestV2
	snapshot   Snapshot
	operation  string
	runID      string
	activation bool
	issuedAt   time.Time
	seal       *deploymentSeal
}

type deploymentSeal struct{}

type NonceStore interface{ ConsumeReleaseNonce(uint64, string) error }

// LoadStrict reads a bounded JSON file without accepting links, hardlinks,
// unsafe permissions, unknown fields, or trailing JSON values.
func LoadStrict(path string, out any) error {
	b, err := readStrictFile(path, maxInputBytes)
	if err != nil {
		return errRejected
	}
	if rejectDuplicateJSONKeys(b) != nil {
		return errRejected
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(out) != nil || d.Decode(&struct{}{}) != io.EOF {
		return errRejected
	}
	return nil
}

func rejectDuplicateJSONKeys(b []byte) error {
	d := json.NewDecoder(bytes.NewReader(b))
	if err := scanJSONValue(d); err != nil {
		return errRejected
	}
	if _, err := d.Token(); err != io.EOF {
		return errRejected
	}
	return nil
}

func scanJSONValue(d *json.Decoder) error {
	token, err := d.Token()
	if err != nil {
		return err
	}
	delim, isDelim := token.(json.Delim)
	if !isDelim {
		return nil
	}
	switch delim {
	case '{':
		keys := make(map[string]bool)
		for d.More() {
			key, err := d.Token()
			if err != nil {
				return err
			}
			name, ok := key.(string)
			if !ok || keys[name] {
				return errRejected
			}
			keys[name] = true
			if err := scanJSONValue(d); err != nil {
				return err
			}
		}
		end, err := d.Token()
		if err != nil || end != json.Delim('}') {
			return errRejected
		}
	case '[':
		for d.More() {
			if err := scanJSONValue(d); err != nil {
				return err
			}
		}
		end, err := d.Token()
		if err != nil || end != json.Delim(']') {
			return errRejected
		}
	default:
		return errRejected
	}
	return nil
}

// ValidateAdmission is side-effect free. Call Admit to consume a nonce only
// after all signature, release binding, and staged-file checks have succeeded.
func ValidateAdmission(r AdmissionRequest) (Admission, error) {
	if !validID(r.ExpectedReleaseID) || !validDigest(r.ExpectedReleaseDigest) || !validVersion(r.ExpectedReleaseVersion) || !safeTargetRoot(r.ExpectedTargetRoot) ||
		!validID(r.ExpectedPlatform) || !validID(r.ExpectedArch) || !validVersion(r.InstallerVersion) || r.Now.IsZero() {
		return Admission{}, errRejected
	}
	if !validReleaseOperation(r.ExpectedOperation) || !validRunID(r.ExpectedRunID) {
		return Admission{}, errRejected
	}
	if err := safeStagedDirectory(r.StagedRoot); err != nil {
		return Admission{}, errRejected
	}
	var envelope EnvelopeV1
	var manifest ManifestV2
	var trust TrustBundle
	if LoadStrict(r.EnvelopePath, &envelope) != nil || LoadStrict(r.ManifestPath, &manifest) != nil || LoadStrict(r.TrustBundlePath, &trust) != nil {
		return Admission{}, errRejected
	}
	keys, revoked, err := ParseTrust(trust)
	if err != nil || validateEnvelope(envelope, manifest, keys, revoked, r.ExpectedPlatform, r.ExpectedArch, r.ExpectedOperation, r.ExpectedRunID, r.ExpectedActivation, r.InstallerVersion, r.Now) != nil {
		return Admission{}, errRejected
	}
	if manifest.ReleaseID != r.ExpectedReleaseID || manifest.ReleaseDigest != r.ExpectedReleaseDigest || envelope.ReleaseDigest != r.ExpectedReleaseDigest ||
		manifest.Version != r.ExpectedReleaseVersion || envelope.ReleaseVersion != r.ExpectedReleaseVersion ||
		manifest.TargetRoot != r.ExpectedTargetRoot || envelope.TargetRoot != r.ExpectedTargetRoot {
		return Admission{}, errRejected
	}
	artifacts, err := validateArtifacts(r.StagedRoot, manifest, r.ExpectedPlatform, r.ExpectedArch)
	if err != nil {
		return Admission{}, errRejected
	}
	return Admission{envelope: envelope, manifest: manifest, artifacts: artifacts, seal: &admissionSeal{}}, nil
}

func Admit(r AdmissionRequest, nonces NonceStore) (Admission, error) {
	a, err := ValidateAdmission(r)
	if err != nil || a.ConsumeReleaseNonce(nonces) != nil {
		return Admission{}, errRejected
	}
	return a, nil
}

// PlanManifest returns a detached, verified manifest projection suitable only
// for the exact signed deploy/run/activation intent. It never reads the staged
// root. The returned value is unavailable on a zero-value or caller-forged
// Admission, and cannot be reused to make a plan with a different intent.
func (a Admission) PlanManifest(runID string, activation bool) (ManifestV2, error) {
	if !a.verified() || a.envelope.Operation != "deploy" || a.envelope.RunID != runID || a.envelope.Activation != activationIntent(activation) {
		return ManifestV2{}, errRejected
	}
	return cloneManifest(a.manifest), nil
}

// ValidationTime returns the immutable envelope issuance instant selected by
// release admission. Consumers use it when validating release payloads whose
// compatibility is time-bound; they must not substitute their local clock.
func (a Admission) ValidationTime() (time.Time, error) {
	if !a.verified() || a.envelope.IssuedAt.IsZero() {
		return time.Time{}, errRejected
	}
	return a.envelope.IssuedAt.UTC(), nil
}

// ConsumeReleaseNonce is the sole nonce capability on an admission. It is
// intentionally separate from PlanManifest so a read-only plan cannot spend
// an envelope nonce.
func (a Admission) ConsumeReleaseNonce(nonces NonceStore) error {
	if !a.verified() || nonces == nil || nonces.ConsumeReleaseNonce(a.envelope.Sequence, a.envelope.Nonce) != nil {
		return errRejected
	}
	return nil
}

// DeploymentInput binds a sealed snapshot to this exact admitted release.
// It is intentionally available only after pure validation; consuming the
// nonce remains the caller's separate, locked transaction step.
func (a Admission) DeploymentInput(snapshot Snapshot) (DeploymentInput, error) {
	if !a.verified() || !snapshot.verifiedFor(a) {
		return DeploymentInput{}, errRejected
	}
	return DeploymentInput{manifest: cloneManifest(a.manifest), snapshot: snapshot, operation: a.envelope.Operation, runID: a.envelope.RunID, activation: a.envelope.Activation == "true", issuedAt: a.envelope.IssuedAt.UTC(), seal: &deploymentSeal{}}, nil
}

// InstallerBinding returns detached release metadata and the sealed snapshot
// path for a production constructor. A zero-value or fabricated input fails
// closed. The installer must still open and verify the returned descriptor
// root before copying any bytes.
func (d DeploymentInput) InstallerBinding() (ManifestV2, string, error) {
	if d.seal == nil || d.snapshot.seal == nil || !validManifest(d.manifest) || d.snapshot.bindingID != deploymentBindingID(d.manifest) || d.snapshot.path == "" || !filepath.IsAbs(d.snapshot.path) || filepath.Clean(d.snapshot.path) != d.snapshot.path || !validReleaseOperation(d.operation) || !validRunID(d.runID) || d.issuedAt.IsZero() {
		return ManifestV2{}, "", errRejected
	}
	return cloneManifest(d.manifest), d.snapshot.path, nil
}

// InstallerValidationTime carries the verified envelope IssuedAt through the
// sealed deployment hand-off. It is intentionally separate from local wall
// time so post-admission catalog validation cannot drift from packaging.
func (d DeploymentInput) InstallerValidationTime() (time.Time, error) {
	if _, _, err := d.InstallerBinding(); err != nil {
		return time.Time{}, err
	}
	return d.issuedAt.UTC(), nil
}

// InstallerIntent returns the operation-bound transaction intent that was
// signed with the envelope. It is a separate accessor so constructors cannot
// accidentally infer activation from mutable CLI flags.
func (d DeploymentInput) InstallerIntent() (operation, runID string, activation bool, err error) {
	if _, _, err = d.InstallerBinding(); err != nil {
		return "", "", false, err
	}
	return d.operation, d.runID, d.activation, nil
}

func (a Admission) verified() bool {
	if a.seal == nil || !validManifest(a.manifest) || len(a.artifacts) != len(a.manifest.Artifacts) || len(a.artifacts) == 0 {
		return false
	}
	var total int
	for n, verified := range a.artifacts {
		if verified.Artifact != a.manifest.Artifacts[n] || !safeStagedRegularInfo(verified.body) || digestBytes(verified.body) != verified.Digest {
			return false
		}
		total += len(verified.body)
		if total > maxArtifactSetBytes {
			return false
		}
	}
	return (a.envelope.ReleaseID == "" || a.envelope.ReleaseID == a.manifest.ReleaseID) && a.envelope.ReleaseDigest == a.manifest.ReleaseDigest && a.envelope.ReleaseVersion == a.manifest.Version && a.envelope.TargetRoot == a.manifest.TargetRoot && a.envelope.ManifestDigest == digest(a.manifest) && a.envelope.ArtifactSetDigest == artifactSetDigest(a.manifest.Artifacts) && a.envelope.Sequence != 0 && validID(a.envelope.Nonce) && validReleaseOperation(a.envelope.Operation) && validRunID(a.envelope.RunID) && validActivationIntent(a.envelope.Activation)
}

func (s Snapshot) verifiedFor(a Admission) bool {
	return s.seal != nil && s.path != "" && filepath.IsAbs(s.path) && filepath.Clean(s.path) == s.path && s.bindingID == deploymentBindingID(a.manifest)
}

func deploymentBindingID(manifest ManifestV2) string { return digest(manifest) }

func safeStagedRegularInfo(body []byte) bool { return len(body) > 0 && len(body) <= maxArtifactBytes }

func cloneManifest(in ManifestV2) ManifestV2 {
	out := in
	out.Artifacts = append([]Artifact(nil), in.Artifacts...)
	return out
}

// ParseTrust accepts only a closed, non-empty trust bundle. Revocation is
// intentionally checked before signature verification by validateEnvelope.
func ParseTrust(b TrustBundle) (map[string]ed25519.PublicKey, map[string]bool, error) {
	if b.Schema != TrustBundleSchema || len(b.Keys) == 0 || len(b.Keys) > maxArtifacts || len(b.Revoked) > maxArtifacts {
		return nil, nil, errRejected
	}
	keys := make(map[string]ed25519.PublicKey, len(b.Keys))
	for id, encoded := range b.Keys {
		decoded, err := hex.DecodeString(encoded)
		if !validID(id) || err != nil || len(decoded) != ed25519.PublicKeySize || hex.EncodeToString(decoded) != encoded {
			return nil, nil, errRejected
		}
		keys[id] = ed25519.PublicKey(decoded)
	}
	revoked := make(map[string]bool, len(b.Revoked))
	for _, id := range b.Revoked {
		if !validID(id) || revoked[id] || keys[id] == nil {
			return nil, nil, errRejected
		}
		revoked[id] = true
	}
	return keys, revoked, nil
}

// Validate remains for callers which already independently bind a manifest.
// Production admission must use ValidateAdmission/Admit because only those
// functions bind the staged root and installer version.
func Validate(e EnvelopeV1, m ManifestV2, keys map[string]ed25519.PublicKey, revoked map[string]bool, now time.Time) error {
	// The old API cannot bind the caller-selected target root or installer
	// version. Refusing it is safer than silently treating validation as
	// admission; production callers must use ValidateAdmission.
	_ = e
	_ = m
	_ = keys
	_ = revoked
	_ = now
	return errRejected
}

func validateEnvelope(e EnvelopeV1, m ManifestV2, keys map[string]ed25519.PublicKey, revoked map[string]bool, platform, arch, operation, runID string, activation bool, installer string, now time.Time) error {
	if !validManifest(m) || e.Schema != EnvelopeSchema || !validID(e.KeyID) || (e.ReleaseID != "" && (!validID(e.ReleaseID) || e.ReleaseID != m.ReleaseID)) || e.Sequence == 0 || !validID(e.Nonce) ||
		e.Platform != platform || e.Arch != arch || !validDigest(e.ReleaseDigest) || !validDigest(e.ManifestDigest) || !validDigest(e.ArtifactSetDigest) ||
		!safeTargetRoot(e.TargetRoot) || !validVersion(e.ReleaseVersion) || !validVersion(e.MinInstaller) || !validVersion(installer) || e.ReleaseDigest != m.ReleaseDigest || e.ReleaseVersion != m.Version || e.TargetRoot != m.TargetRoot || e.ManifestDigest != digest(m) ||
		e.ArtifactSetDigest != artifactSetDigest(m.Artifacts) || e.Operation != operation || e.RunID != runID || e.Activation != activationIntent(activation) || !validReleaseOperation(e.Operation) || !validRunID(e.RunID) || !validActivationIntent(e.Activation) || revoked[e.KeyID] || now.Before(e.IssuedAt) || !now.Before(e.ExpiresAt) || !versionAtLeast(installer, e.MinInstaller) {
		return errRejected
	}
	key := keys[e.KeyID]
	sig, err := hex.DecodeString(e.Signature)
	if len(key) != ed25519.PublicKeySize || err != nil || len(sig) != ed25519.SignatureSize {
		return errRejected
	}
	payload, err := UnsignedEnvelopePayload(e)
	if err != nil || !ed25519.Verify(key, payload, sig) {
		return errRejected
	}
	return nil
}

func validReleaseOperation(value string) bool { return value == "deploy" || value == "rollback" }

func validRunID(value string) bool {
	if len(value) < 8 || len(value) > 128 {
		return false
	}
	for _, r := range value {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f' || r == '-') {
			return false
		}
	}
	return true
}

func validActivationIntent(value string) bool { return value == "true" || value == "false" }

func activationIntent(value bool) string {
	if value {
		return "true"
	}
	return "false"
}

func validManifest(m ManifestV2) bool {
	if m.Schema != ManifestSchema || !validID(m.ReleaseID) || !validDigest(m.ReleaseDigest) || !validVersion(m.Version) || !safeTargetRoot(m.TargetRoot) || len(m.Artifacts) == 0 || len(m.Artifacts) > maxArtifacts {
		return false
	}
	seen := make(map[string]bool, len(m.Artifacts))
	paths := make(map[string]bool, len(m.Artifacts))
	for _, a := range m.Artifacts {
		if !validArtifactType(a.Type) || !safeRelativePath(a.Path) || !validDigest(a.Digest) || !validID(a.Platform) || !validID(a.Arch) || !validVersion(a.Version) || !validID(a.ActivationGroup) || seen[a.Type+"\x00"+a.Path] || paths[a.Path] {
			return false
		}
		seen[a.Type+"\x00"+a.Path] = true
		paths[a.Path] = true
	}
	return true
}

func validateArtifacts(root string, m ManifestV2, platform, arch string) ([]verifiedArtifact, error) {
	if !validManifest(m) {
		return nil, errRejected
	}
	artifacts := make([]verifiedArtifact, 0, len(m.Artifacts))
	var total int64
	for _, a := range m.Artifacts {
		if a.Platform != platform || a.Arch != arch {
			return nil, errRejected
		}
		path, err := containedPath(root, a.Path)
		if err != nil {
			return nil, errRejected
		}
		body, dev, ino, err := readStagedFile(path, maxArtifactBytes)
		if err != nil || digestBytes(body) != a.Digest {
			return nil, errRejected
		}
		total += int64(len(body))
		if total > maxArtifactSetBytes {
			return nil, errRejected
		}
		artifacts = append(artifacts, verifiedArtifact{Artifact: a, body: body, dev: dev, ino: ino})
	}
	return artifacts, nil
}

func validArtifactType(t string) bool {
	switch t {
	case "core", "provider_runtime", "provider_plugin", "provider_daemon", "provider_topology", "provider_host_runtime", "provider_host_closure", "provider_host_identity", "policy", "helper":
		return true
	default:
		return false
	}
}

func safeRelativePath(path string) bool {
	if path == "" || len(path) > 512 || filepath.IsAbs(path) || filepath.Clean(path) != path || path == "." || strings.HasPrefix(path, "../") {
		return false
	}
	for _, part := range strings.Split(path, string(filepath.Separator)) {
		if part == "" || part == "." || part == ".." {
			return false
		}
	}
	return true
}

func safeTargetRoot(path string) bool {
	return path != "" && filepath.IsAbs(path) && filepath.Clean(path) == path && path != string(filepath.Separator) && len(path) <= 512
}

func containedPath(root, rel string) (string, error) {
	if !safeRelativePath(rel) {
		return "", errRejected
	}
	root = filepath.Clean(root)
	path := filepath.Join(root, rel)
	check, err := filepath.Rel(root, path)
	if err != nil || check == "." || strings.HasPrefix(check, ".."+string(filepath.Separator)) || check == ".." {
		return "", errRejected
	}
	// A clean lexical path is not enough: an intermediate link could otherwise
	// redirect an apparently contained artifact outside the fixed staging root.
	dir := root
	parts := strings.Split(rel, string(filepath.Separator))
	for _, part := range parts[:len(parts)-1] {
		dir = filepath.Join(dir, part)
		st, statErr := os.Lstat(dir)
		if statErr != nil || st.Mode()&os.ModeSymlink != 0 || !st.IsDir() || st.Mode().Perm()&0o022 != 0 || st.Sys() == nil {
			return "", errRejected
		}
		if _, ok := st.Sys().(*syscall.Stat_t); !ok {
			return "", errRejected
		}
	}
	return path, nil
}

func readStrictFile(path string, limit int64) ([]byte, error) {
	if safeDirectory(filepath.Dir(path)) != nil {
		return nil, errRejected
	}
	st, err := os.Lstat(path)
	if err != nil || !safeRegular(st, limit) {
		return nil, errRejected
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, errRejected
	}
	f := os.NewFile(uintptr(fd), path)
	if f == nil {
		_ = syscall.Close(fd)
		return nil, errRejected
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !sameFile(st, opened) || !safeRegular(opened, limit) {
		return nil, errRejected
	}
	body, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(body)) != st.Size() || int64(len(body)) > limit {
		return nil, errRejected
	}
	return body, nil
}

// readStagedFile deliberately permits a non-root source owner: its bytes are
// signature-checked and immediately copied into a root-owned Snapshot. It
// still rejects links, hardlinks and writable modes, and pins the opened inode.
func readStagedFile(path string, limit int64) ([]byte, uint64, uint64, error) {
	parent := filepath.Dir(path)
	if err := safeStagedDirectory(parent); err != nil {
		return nil, 0, 0, errRejected
	}
	st, err := os.Lstat(path)
	if err != nil || !safeStagedRegular(st, limit) {
		return nil, 0, 0, errRejected
	}
	before, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		return nil, 0, 0, errRejected
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, 0, 0, errRejected
	}
	f := os.NewFile(uintptr(fd), path)
	if f == nil {
		_ = syscall.Close(fd)
		return nil, 0, 0, errRejected
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !sameFile(st, opened) || !safeStagedRegular(opened, limit) {
		return nil, 0, 0, errRejected
	}
	body, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(body)) != st.Size() || int64(len(body)) > limit {
		return nil, 0, 0, errRejected
	}
	return body, uint64(before.Dev), uint64(before.Ino), nil
}

func safeRegular(st os.FileInfo, limit int64) bool {
	if st == nil || st.Mode()&os.ModeSymlink != 0 || !st.Mode().IsRegular() || st.Size() < 1 || st.Size() > limit || st.Mode().Perm()&0o022 != 0 || st.Sys() == nil {
		return false
	}
	s, ok := st.Sys().(*syscall.Stat_t)
	return ok && s.Nlink == 1 && safeOwner(s.Uid)
}

func safeDirectory(path string) error {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errRejected
	}
	st, err := os.Lstat(path)
	if err != nil || st.Mode()&os.ModeSymlink != 0 || !st.IsDir() || st.Mode().Perm()&0o022 != 0 || unsafeSpecialMode(st) || st.Sys() == nil {
		return errRejected
	}
	s, ok := st.Sys().(*syscall.Stat_t)
	if !ok || !safeOwner(s.Uid) {
		return errRejected
	}
	return nil
}

func safeStagedDirectory(path string) error {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errRejected
	}
	st, err := os.Lstat(path)
	if err != nil || st.Mode()&os.ModeSymlink != 0 || !st.IsDir() || st.Mode().Perm()&0o022 != 0 || unsafeSpecialMode(st) || st.Sys() == nil {
		return errRejected
	}
	_, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		return errRejected
	}
	return nil
}

func safeStagedRegular(st os.FileInfo, limit int64) bool {
	if st == nil || st.Mode()&os.ModeSymlink != 0 || !st.Mode().IsRegular() || st.Size() < 1 || st.Size() > limit || st.Mode().Perm()&0o022 != 0 || unsafeSpecialMode(st) || st.Sys() == nil {
		return false
	}
	s, ok := st.Sys().(*syscall.Stat_t)
	return ok && s.Nlink == 1
}

// unsafeSpecialMode rejects setuid, setgid, and sticky metadata both through
// Go's portable mode flags and the raw Darwin/POSIX stat bits. The latter is
// necessary because filesystems do not all project special bits identically.
func unsafeSpecialMode(info os.FileInfo) bool {
	if info == nil || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		return true
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return !ok || stat == nil || uint32(stat.Mode)&0o7000 != 0
}

func safeOwner(uid uint32) bool { return uid == uint32(os.Geteuid()) || uid == 0 }

// MaterializeSnapshot writes already verified bytes to a new root-owned,
// private directory. It never reopens the mutable staged source.
func (a Admission) MaterializeSnapshot(parent string) (Snapshot, error) {
	if !a.verified() || safeDirectory(parent) != nil {
		return Snapshot{}, errRejected
	}
	dir, err := os.MkdirTemp(parent, "openduck-release-")
	if err != nil {
		return Snapshot{}, errRejected
	}
	failed := true
	defer func() {
		if failed {
			_ = os.RemoveAll(dir)
		}
	}()
	if err := os.Chmod(dir, 0700); err != nil {
		return Snapshot{}, errRejected
	}
	for _, verified := range a.artifacts {
		if !safeRelativePath(verified.Path) {
			return Snapshot{}, errRejected
		}
		path := filepath.Join(dir, verified.Path)
		if err = os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			return Snapshot{}, errRejected
		}
		if path, err = containedPath(dir, verified.Path); err != nil {
			return Snapshot{}, errRejected
		}
		mode := os.FileMode(0500)
		if entry, known := releasecatalog.EntryFor(verified.Path); known && !entry.Executable {
			mode = 0400
		}
		f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
		if err != nil {
			return Snapshot{}, errRejected
		}
		_, writeErr := f.Write(verified.body)
		if writeErr == nil {
			writeErr = f.Sync()
		}
		closeErr := f.Close()
		if writeErr != nil || closeErr != nil {
			return Snapshot{}, errRejected
		}
		body, _, _, readErr := readStagedFile(path, maxArtifactBytes)
		if readErr != nil || digestBytes(body) != verified.Digest {
			return Snapshot{}, errRejected
		}
	}
	root, err := os.Open(dir)
	if err != nil {
		return Snapshot{}, errRejected
	}
	err = root.Sync()
	closeErr := root.Close()
	if err != nil || closeErr != nil {
		return Snapshot{}, errRejected
	}
	failed = false
	return Snapshot{path: dir, bindingID: deploymentBindingID(a.manifest), seal: &snapshotSeal{}}, nil
}

// Path returns the fixed sealed snapshot location for diagnostics or test
// cleanup. Callers cannot mutate the internal path used by DeploymentInput.
func (s Snapshot) Path() string {
	if s.seal == nil {
		return ""
	}
	return s.path
}

func (s Snapshot) Remove() error {
	if s.seal == nil || s.path == "" || !filepath.IsAbs(s.path) || !strings.HasPrefix(filepath.Base(s.path), "openduck-release-") {
		return errRejected
	}
	return os.RemoveAll(s.path)
}

func sameFile(a, b os.FileInfo) bool {
	x, xok := a.Sys().(*syscall.Stat_t)
	y, yok := b.Sys().(*syscall.Stat_t)
	return xok && yok && x.Dev == y.Dev && x.Ino == y.Ino
}

func digest(v any) string {
	b, err := CanonicalJSON(v)
	if err != nil {
		return ""
	}
	return digestBytes(b)
}

// CanonicalJSON is the sole serialization used by release digests and
// envelope signatures. The release structs contain no maps, so encoding/json
// provides a stable closed field order; callers must not sign a re-encoded
// value using another serializer.
func CanonicalJSON(v any) ([]byte, error) { return json.Marshal(v) }

// CanonicalDigest returns the lowercase SHA-256 digest of CanonicalJSON(v).
func CanonicalDigest(v any) (string, error) {
	b, err := CanonicalJSON(v)
	if err != nil {
		return "", err
	}
	return digestBytes(b), nil
}

// ManifestDigest and ArtifactSetDigest are exported so an offline packager
// cannot accidentally use a serialization that differs from admission.
func ManifestDigest(m ManifestV2) string    { return digest(m) }
func ArtifactSetDigest(a []Artifact) string { return artifactSetDigest(a) }

// UnsignedEnvelopePayload returns exactly the bytes ValidateAdmission
// verifies. It deliberately clears only Signature.
func UnsignedEnvelopePayload(e EnvelopeV1) ([]byte, error) {
	e.Signature = ""
	return CanonicalJSON(e)
}

func digestBytes(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func artifactSetDigest(a []Artifact) string { return digest(a) }

func validDigest(s string) bool {
	if len(s) != sha256.Size*2 || strings.ToLower(s) != s {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

func validID(s string) bool {
	if s == "" || len(s) > 128 {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '_' || r == '-') {
			return false
		}
	}
	return true
}

func validVersion(v string) bool {
	parts := strings.Split(v, ".")
	if len(parts) != 3 {
		return false
	}
	for _, p := range parts {
		if p == "" || len(p) > 9 || (len(p) > 1 && p[0] == '0') {
			return false
		}
		for _, c := range p {
			if c < '0' || c > '9' {
				return false
			}
		}
	}
	return true
}

func versionAtLeast(got, min string) bool {
	g, m := strings.Split(got, "."), strings.Split(min, ".")
	for i := range g {
		var gv, mv uint64
		for _, c := range g[i] {
			gv = gv*10 + uint64(c-'0')
		}
		for _, c := range m[i] {
			mv = mv*10 + uint64(c-'0')
		}
		if gv != mv {
			return gv > mv
		}
	}
	return true
}

type FileNonceStore struct{ Path string }

type nonceState struct {
	Schema   string   `json:"schema"`
	Sequence uint64   `json:"sequence"`
	Nonces   []string `json:"nonces"`
}

// ConsumeReleaseNonce serializes a durable, bounded anti-replay state. A
// corrupt state, a leftover temporary state, or any unsafe link is a hard
// failure, never an invitation to reset replay protection.
func (s FileNonceStore) ConsumeReleaseNonce(seq uint64, nonce string) error {
	if seq == 0 || !validID(nonce) || s.Path == "" || !filepath.IsAbs(s.Path) || filepath.Clean(s.Path) != s.Path || safeDirectory(filepath.Dir(s.Path)) != nil {
		return errRejected
	}
	lock, err := openNonceLock(s.Path + ".lock")
	if err != nil {
		return errRejected
	}
	defer lock.Close()
	if syscall.Flock(int(lock.Fd()), syscall.LOCK_EX) != nil {
		return errRejected
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	if _, err := os.Lstat(s.Path + ".next"); err == nil || !errors.Is(err, os.ErrNotExist) {
		return errRejected
	}
	state, err := loadNonceState(s.Path)
	if err != nil {
		return errRejected
	}
	h := sha256.Sum256([]byte(nonce))
	d := hex.EncodeToString(h[:])
	if seq <= state.Sequence || len(state.Nonces) >= maxNonces {
		return errRejected
	}
	for _, prior := range state.Nonces {
		if prior == d {
			return errRejected
		}
	}
	state.Sequence, state.Nonces = seq, append(state.Nonces, d)
	out, err := json.Marshal(state)
	if err != nil || int64(len(out)) > maxInputBytes {
		return errRejected
	}
	tmp := s.Path + ".next"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return errRejected
	}
	if _, err = f.Write(out); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil || closeErr != nil {
		return errRejected
	}
	if err = os.Rename(tmp, s.Path); err != nil {
		return errRejected
	}
	dir, err := os.Open(filepath.Dir(s.Path))
	if err != nil {
		return errRejected
	}
	defer dir.Close()
	if err = dir.Sync(); err != nil {
		return errRejected
	}
	return nil
}

func openNonceLock(path string) (*os.File, error) {
	if st, err := os.Lstat(path); err == nil {
		if !safeLock(st) {
			return nil, errRejected
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, errRejected
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, errRejected
	}
	st, err := f.Stat()
	if err != nil || !safeLock(st) {
		f.Close()
		return nil, errRejected
	}
	return f, nil
}

func safeLock(st os.FileInfo) bool {
	if st == nil || st.Mode()&os.ModeSymlink != 0 || !st.Mode().IsRegular() || st.Size() != 0 || st.Mode().Perm()&0o022 != 0 || st.Sys() == nil {
		return false
	}
	s, ok := st.Sys().(*syscall.Stat_t)
	return ok && s.Nlink == 1 && safeOwner(s.Uid)
}

func loadNonceState(path string) (nonceState, error) {
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return nonceState{Schema: nonceStateSchema}, nil
	}
	var state nonceState
	if LoadStrict(path, &state) != nil || state.Schema != nonceStateSchema || len(state.Nonces) > maxNonces {
		return nonceState{}, errRejected
	}
	seen := make(map[string]bool, len(state.Nonces))
	for _, nonce := range state.Nonces {
		if !validDigest(nonce) || seen[nonce] {
			return nonceState{}, errRejected
		}
		seen[nonce] = true
	}
	return state, nil
}
