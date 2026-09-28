package macosrelease

// This file is intentionally unprivileged. It builds the material an offline
// signer needs, but contains no private-key, environment, or network support.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"openduck/internal/providerbridge"
	"openduck/internal/providerrevision"
	"openduck/internal/providertransport"
	"openduck/internal/qwenclosure"
	"openduck/internal/releasecatalog"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
)

const (
	SigningRequestSchema = "openduck.release-signing-request.v1"
	SignatureSchema      = "openduck.release-signature.v1"
)

// beforeOutputPublishForTest makes parent-rename assertions deterministic. It
// is nil in production and is only set by same-package tests.
var beforeOutputPublishForTest func()

// PackageInput contains every release binding. Time and nonce values are
// explicit human inputs, making request output reproducible.
type PackageInput struct {
	StageRoot    string
	ReleaseID    string
	Version      string
	TargetRoot   string
	Platform     string
	Arch         string
	KeyID        string
	Operation    string
	RunID        string
	Activation   bool
	Sequence     uint64
	Nonce        string
	IssuedAt     time.Time
	ExpiresAt    time.Time
	MinInstaller string
}

// SigningRequestV1 binds an external signature to one exact canonical
// unsigned EnvelopeV1 payload. It contains no key material.
type SigningRequestV1 struct {
	Schema            string    `json:"schema"`
	Algorithm         string    `json:"algorithm"`
	KeyID             string    `json:"key_id"`
	ReleaseID         string    `json:"release_id"`
	ManifestDigest    string    `json:"manifest_digest"`
	ArtifactSetDigest string    `json:"artifact_set_digest"`
	ReleaseDigest     string    `json:"release_digest"`
	ReleaseVersion    string    `json:"release_version"`
	TargetRoot        string    `json:"target_root"`
	Platform          string    `json:"platform"`
	Arch              string    `json:"arch"`
	PayloadDigest     string    `json:"payload_digest"`
	UnsignedPayload   string    `json:"unsigned_payload_b64"`
	Operation         string    `json:"operation"`
	RunID             string    `json:"run_id"`
	Activation        string    `json:"activation"`
	Sequence          uint64    `json:"sequence"`
	Nonce             string    `json:"nonce"`
	IssuedAt          time.Time `json:"issued_at"`
	ExpiresAt         time.Time `json:"expires_at"`
	MinInstaller      string    `json:"min_installer"`
}

// ExternalSignatureV1 is the only format accepted from the separate signing
// system. Hex signature bytes are not secret.
type ExternalSignatureV1 struct {
	Schema        string `json:"schema"`
	Algorithm     string `json:"algorithm"`
	KeyID         string `json:"key_id"`
	PayloadDigest string `json:"payload_digest"`
	Signature     string `json:"signature"`
}

type FinalizeInput struct {
	RequestPath     string
	SignaturePath   string
	TrustBundlePath string
	EnvelopeOutput  string
	Now             time.Time
}

type releaseDigestProjection struct {
	Schema     string     `json:"schema"`
	ReleaseID  string     `json:"release_id"`
	Version    string     `json:"version"`
	TargetRoot string     `json:"target_root"`
	Artifacts  []Artifact `json:"artifacts"`
}

// BuildManifest descriptor-reads the complete staged root against the shared
// closed catalog. Mandatory artifacts are always present; optional provider
// groups are exact all-or-none sets that remain inactive after installation.
// Arbitrary staged leaves and destinations are never admitted here.
func BuildManifest(in PackageInput) (ManifestV2, error) {
	if !validPackageInput(in) || in.ReleaseID == "" || in.StageRoot == "" {
		return ManifestV2{}, errRejected
	}
	if in.Platform != runtime.GOOS || in.Arch != runtime.GOARCH {
		return ManifestV2{}, errRejected
	}
	root, err := openStageRoot(in.StageRoot)
	if err != nil {
		return ManifestV2{}, errRejected
	}
	defer root.Close()
	selected, err := releasecatalog.SelectedEntries(func(stagePath string) (bool, error) {
		_, statErr := root.Lstat(stagePath)
		if statErr == nil {
			return true, nil
		}
		if os.IsNotExist(statErr) {
			return false, nil
		}
		return false, statErr
	})
	if err != nil || verifyStageInventory(root, selected) != nil {
		return ManifestV2{}, errRejected
	}
	artifacts := make([]Artifact, 0, len(selected))
	payloads := make(map[string][]byte, len(selected))
	for _, spec := range selected {
		body, err := readStageArtifact(root, spec.Path, spec.Executable, catalogArtifactMaxBytes(spec))
		if err != nil {
			return ManifestV2{}, errRejected
		}
		payloads[spec.Path] = body
		artifacts = append(artifacts, Artifact{Type: spec.Type, Path: spec.Path, Digest: digestBytes(body), Platform: in.Platform, Arch: in.Arch, Version: in.Version, ActivationGroup: spec.ActivationGroup, Required: spec.Required})
	}
	if ValidateCatalogPayloads(payloads, in.IssuedAt.UTC()) != nil {
		return ManifestV2{}, errRejected
	}
	sort.Slice(artifacts, func(i, j int) bool { return artifacts[i].Path < artifacts[j].Path })
	releaseDigest, err := computedReleaseDigest(in.ReleaseID, in.Version, in.TargetRoot, artifacts)
	if err != nil || releaseDigest == in.ReleaseID {
		return ManifestV2{}, errRejected
	}
	manifest := ManifestV2{Schema: ManifestSchema, ReleaseID: in.ReleaseID, ReleaseDigest: releaseDigest, Version: in.Version, TargetRoot: in.TargetRoot, Artifacts: artifacts}
	if !validManifest(manifest) || !canonicalCatalog(manifest.Artifacts) {
		return ManifestV2{}, errRejected
	}
	return manifest, nil
}

// ValidateCatalogStage rechecks a signed manifest against the descriptor-safe
// closed stage catalog. It is deliberately separate from generic admission so
// migration callers can retain their existing sealed inputs, while production
// packager/installer composition can require exact leaves, groups, modes, and
// digests before snapshot materialization.
func ValidateCatalogStage(stageRoot string, manifest ManifestV2, validationTime time.Time) error {
	if stageRoot == "" || validationTime.IsZero() || !validManifest(manifest) || !canonicalCatalog(manifest.Artifacts) {
		return errRejected
	}
	root, err := openStageRoot(stageRoot)
	if err != nil {
		return errRejected
	}
	defer root.Close()
	selected, err := releasecatalog.SelectedEntries(func(stagePath string) (bool, error) {
		_, statErr := root.Lstat(stagePath)
		if statErr == nil {
			return true, nil
		}
		if os.IsNotExist(statErr) {
			return false, nil
		}
		return false, statErr
	})
	if err != nil || verifyStageInventory(root, selected) != nil || len(selected) != len(manifest.Artifacts) {
		return errRejected
	}
	byPath := make(map[string]Artifact, len(manifest.Artifacts))
	payloads := make(map[string][]byte, len(manifest.Artifacts))
	for _, artifact := range manifest.Artifacts {
		byPath[artifact.Path] = artifact
	}
	for _, entry := range selected {
		artifact, found := byPath[entry.Path]
		if !found || artifact.Type != entry.Type || artifact.ActivationGroup != entry.ActivationGroup || artifact.Required != entry.Required {
			return errRejected
		}
		body, readErr := readStageArtifact(root, entry.Path, entry.Executable, catalogArtifactMaxBytes(entry))
		if readErr != nil || digestBytes(body) != artifact.Digest {
			return errRejected
		}
		payloads[entry.Path] = body
	}
	if ValidateCatalogPayloads(payloads, validationTime.UTC()) != nil {
		return errRejected
	}
	return nil
}

// ValidateCatalogPayloads validates the non-executable optional payload
// formats after descriptor-safe reads. It deliberately has no signing,
// credential, network, or lifecycle behavior: the signed manifest authorizes
// delivery, while a later owner lifecycle operation is the only enable gate.
func ValidateCatalogPayloads(payloads map[string][]byte, validationTime time.Time) error {
	if len(payloads) == 0 || validationTime.IsZero() {
		return errRejected
	}
	selected, err := releasecatalog.SelectedEntries(func(stagePath string) (bool, error) {
		_, found := payloads[stagePath]
		return found, nil
	})
	if err != nil || len(selected) != len(payloads) {
		return errRejected
	}
	var bundleRaw, trustRaw []byte
	expectedRuntimeProfiles := make(map[string]releasecatalog.Entry)
	daemonProfiles := make(map[string]releasecatalog.Entry)
	hostProfiles := make(map[string]releasecatalog.Entry)
	hostIdentities := make(map[string]releasecatalog.ProviderHostIdentity)
	qwenClosure := make(map[string][]byte)
	topologyProfiles := make(map[string]releasecatalog.ProviderTopology)
	for _, entry := range selected {
		body, found := payloads[entry.Path]
		if !found || len(body) == 0 || int64(len(body)) > catalogArtifactMaxBytes(entry) {
			return errRejected
		}
		if entry.Mandatory {
			continue
		}
		switch entry.Type {
		case "policy":
			switch entry.Path {
			case "provider-bundle.json":
				bundleRaw = body
			case "provider-trust.json":
				trustRaw = body
			default:
				return errRejected
			}
		case "provider_runtime":
			// A release contains only the symbolic pre-activation declaration.
			// The active Descriptor has UID/GID/socket/key epoch observations and
			// must be constructed by the owner-authorized P7 boundary, never by
			// packaging a manifest (which would create a self-reference).
			descriptor, decodeErr := providertransport.DecodeInactiveDescriptor(body)
			if decodeErr != nil || descriptor.Provider != entry.Provider || descriptor.ProfileID != entry.ProfileID || descriptor.ProfileRevision != entry.ProfileRevision {
				return errRejected
			}
			expectedRuntimeProfiles[entry.ProfileID] = entry
		case "provider_plugin":
			metadata, decodeErr := releasecatalog.DecodePluginMetadata(body)
			if decodeErr != nil || metadata.Provider != entry.Provider || metadata.ProfileID != entry.ProfileID || metadata.ProfileRevision != entry.ProfileRevision || !metadata.Disabled {
				return errRejected
			}
		case "provider_daemon":
			// Exact bytes and executable mode were already verified against the
			// closed catalog. There is intentionally no daemon configuration,
			// listener, account, or activation payload to parse here.
			daemonProfiles[entry.ProfileID] = entry
		case "provider_host_runtime":
			// The artifact digest, executable bit and closed output are already
			// manifest/catalog-bound. Activation remains a separate transaction.
			hostProfiles[entry.ProfileID] = entry
		case "provider_host_closure":
			if entry.Provider != "qwen" {
				return errRejected
			}
			qwenClosure[path.Base(entry.Path)] = body
		case "provider_host_identity":
			identity, identityErr := releasecatalog.DecodeProviderHostIdentity(body)
			if identityErr != nil || identity.Provider != entry.Provider {
				return errRejected
			}
			hostIdentities[entry.ProfileID] = identity
		case "provider_topology":
			topology, decodeErr := releasecatalog.DecodeProviderTopology(body)
			if decodeErr != nil || topology.Provider != entry.Provider || topology.ProfileID != entry.ProfileID || topology.ProfileRevision != entry.ProfileRevision || topology.ActivationState != "inactive" || topology.Provisioned {
				return errRejected
			}
			topologyProfiles[entry.ProfileID] = topology
		default:
			return errRejected
		}
	}
	if (bundleRaw == nil) != (trustRaw == nil) {
		return errRejected
	}
	if bundleRaw != nil && validateDisabledProviderPolicy(bundleRaw, trustRaw, expectedRuntimeProfiles, validationTime.UTC()) != nil {
		return errRejected
	}
	if len(expectedRuntimeProfiles) != len(daemonProfiles) || len(expectedRuntimeProfiles) != len(topologyProfiles) {
		return errRejected
	}
	for profileID, runtimeEntry := range expectedRuntimeProfiles {
		daemonEntry, daemonOK := daemonProfiles[profileID]
		topology, topologyOK := topologyProfiles[profileID]
		if !daemonOK || !topologyOK || daemonEntry.Provider != runtimeEntry.Provider || daemonEntry.ProfileRevision != runtimeEntry.ProfileRevision || topology.ExpectedDaemonLeaf != path.Base(daemonEntry.Outputs[0].TargetTemplate) || topology.ExpectedRuntimeDescriptorLeaf != path.Base(runtimeEntry.Outputs[0].TargetTemplate) {
			return errRejected
		}
		if runtimeEntry.Provider != "deepseek" {
			host, ok := hostProfiles[profileID]
			identity, identityOK := hostIdentities[profileID]
			hostBody := payloads[host.Path]
			hostSum := sha256.Sum256(hostBody)
			if !ok || !identityOK || host.Provider != runtimeEntry.Provider || host.ProfileRevision != runtimeEntry.ProfileRevision || topology.ExpectedHostExecutableLeaf != path.Base(host.Outputs[0].TargetTemplate) || topology.ExpectedHostIdentityLeaf != "host-identity.json" || topology.ExpectedHostTeamID != identity.TeamID || identity.ArtifactDigest != "sha256:"+hex.EncodeToString(hostSum[:]) {
				return errRejected
			}
		}
		if runtimeEntry.Provider == "qwen" {
			m, err := qwenclosure.Decode(qwenClosure["qwen-closure.sha256"])
			archive := qwenClosure["qwen-code-darwin-arm64.tar.gz"]
			identity := hostIdentities[profileID]
			if err != nil || providerbridge.DigestBytes(archive) != m.ArchiveDigest || providerbridge.DigestBytes(payloads["providers/qwen/host/host-identity.json"]) != m.HostIdentityDigest || m.NodeDigest != identity.ArtifactDigest || qwenclosure.ImageIdentityForCDHash(m.NodeCDHash) != identity.ImageIdentity || m.NodeTeamID != identity.TeamID {
				return errRejected
			}
		}
	}
	return nil
}

func validateDisabledProviderPolicy(bundleRaw, trustRaw []byte, expectedRuntimeProfiles map[string]releasecatalog.Entry, validationTime time.Time) error {
	trust, err := providerbridge.DecodeEd25519TrustBundle(trustRaw)
	if err != nil {
		return errRejected
	}
	// Decode already establishes a canonical closed BundleV1 shape. The packager
	// adds the release-specific invariant that a distributable policy can only
	// declare disabled profiles; activation requires a separately signed owner
	// lifecycle operation outside the release catalog.
	bundle, err := providerrevision.Decode(bundleRaw)
	if err != nil || bundle.TrustBundleDigest != providerbridge.DigestBytes(trustRaw) {
		return errRejected
	}
	if providerrevision.ValidateBundle(bundle, trust, validationTime) != nil || !disabledKnownProfiles(bundle, expectedRuntimeProfiles) {
		return errRejected
	}
	return nil
}

func disabledKnownProfiles(bundle providerrevision.Bundle, expectedRuntimeProfiles map[string]releasecatalog.Entry) bool {
	known := make(map[string]providerbridge.Profile, len(providerbridge.DeclaredProfiles()))
	for _, profile := range providerbridge.DeclaredProfiles() {
		known[profile.ID] = profile
	}
	if len(expectedRuntimeProfiles) == 0 || len(bundle.Profiles) != len(expectedRuntimeProfiles) {
		return false
	}
	last := ""
	for _, profileBundle := range bundle.Profiles {
		profile := profileBundle.Profile
		expected, found := known[profile.ID]
		catalogEntry, selected := expectedRuntimeProfiles[profile.ID]
		if !found || !selected || profile.ID <= last || profile.Provider != expected.Provider || string(profile.Provider) != catalogEntry.Provider || profile.Model != expected.Model || profile.RuntimeKind != expected.RuntimeKind || profile.AuthModality != expected.AuthModality || profile.LocalOnly != expected.LocalOnly || profile.Revision != expected.Revision || profile.Revision != catalogEntry.ProfileRevision || profile.Status != providerbridge.StatusDisabled || profile.MeshSpawnEnabled || profileBundle.ActivationIntent {
			return false
		}
		last = profile.ID
	}
	return len(bundle.Profiles) > 0
}

func catalogArtifactMaxBytes(entry releasecatalog.Entry) int64 {
	if entry.MaxBytes > 0 && entry.MaxBytes <= maxArtifactBytes {
		return entry.MaxBytes
	}
	return maxArtifactBytes
}

// BuildSigningRequest creates the exact unsigned bytes later accepted by
// ValidateAdmission. Callers can safely transport this JSON to a separate
// offline signer.
func BuildSigningRequest(in PackageInput, manifest ManifestV2) (SigningRequestV1, error) {
	releaseDigest, err := computedReleaseDigest(manifest.ReleaseID, manifest.Version, manifest.TargetRoot, manifest.Artifacts)
	if !validPackageInput(in) || !validManifest(manifest) || !canonicalCatalog(manifest.Artifacts) || !manifestMatchesPackage(manifest, in) || err != nil || manifest.ReleaseID != in.ReleaseID || manifest.Version != in.Version || manifest.TargetRoot != in.TargetRoot || manifest.ReleaseDigest != releaseDigest || manifest.ReleaseDigest == in.ReleaseID {
		return SigningRequestV1{}, errRejected
	}
	envelope := EnvelopeV1{Schema: EnvelopeSchema, KeyID: in.KeyID, ReleaseID: manifest.ReleaseID, ManifestDigest: ManifestDigest(manifest), ArtifactSetDigest: ArtifactSetDigest(manifest.Artifacts), ReleaseDigest: manifest.ReleaseDigest, ReleaseVersion: manifest.Version, TargetRoot: manifest.TargetRoot, Platform: in.Platform, Arch: in.Arch, MinInstaller: in.MinInstaller, Operation: in.Operation, RunID: in.RunID, Activation: activationIntent(in.Activation), Nonce: in.Nonce, Sequence: in.Sequence, IssuedAt: in.IssuedAt.UTC(), ExpiresAt: in.ExpiresAt.UTC()}
	payload, err := UnsignedEnvelopePayload(envelope)
	if err != nil {
		return SigningRequestV1{}, errRejected
	}
	request := SigningRequestV1{Schema: SigningRequestSchema, Algorithm: "ed25519", KeyID: in.KeyID, ReleaseID: manifest.ReleaseID, ManifestDigest: envelope.ManifestDigest, ArtifactSetDigest: envelope.ArtifactSetDigest, ReleaseDigest: envelope.ReleaseDigest, ReleaseVersion: envelope.ReleaseVersion, TargetRoot: envelope.TargetRoot, Platform: envelope.Platform, Arch: envelope.Arch, PayloadDigest: digestBytes(payload), UnsignedPayload: base64.StdEncoding.EncodeToString(payload), Operation: envelope.Operation, RunID: envelope.RunID, Activation: envelope.Activation, Sequence: envelope.Sequence, Nonce: envelope.Nonce, IssuedAt: envelope.IssuedAt, ExpiresAt: envelope.ExpiresAt, MinInstaller: envelope.MinInstaller}
	if !validSigningRequest(request) {
		return SigningRequestV1{}, errRejected
	}
	return request, nil
}

// Finalize verifies an external signature against a pinned trust bundle and
// writes a new canonical envelope. It never sees or accepts a private key.
func Finalize(in FinalizeInput) (EnvelopeV1, error) {
	if in.Now.IsZero() || !safeDistinctOutputs(in.EnvelopeOutput, in.RequestPath, in.SignaturePath, in.TrustBundlePath) {
		return EnvelopeV1{}, errRejected
	}
	var request SigningRequestV1
	var signature ExternalSignatureV1
	var trust TrustBundle
	if LoadStrict(in.RequestPath, &request) != nil || LoadStrict(in.SignaturePath, &signature) != nil || LoadStrict(in.TrustBundlePath, &trust) != nil || !validSigningRequest(request) || !validExternalSignature(signature) {
		return EnvelopeV1{}, errRejected
	}
	keys, revoked, err := ParseTrust(trust)
	if err != nil || revoked[request.KeyID] || signature.KeyID != request.KeyID || signature.PayloadDigest != request.PayloadDigest {
		return EnvelopeV1{}, errRejected
	}
	payload, err := base64.StdEncoding.DecodeString(request.UnsignedPayload)
	if err != nil || digestBytes(payload) != request.PayloadDigest || len(payload) > maxInputBytes {
		return EnvelopeV1{}, errRejected
	}
	sig, err := hex.DecodeString(signature.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize || !ed25519.Verify(keys[request.KeyID], payload, sig) {
		return EnvelopeV1{}, errRejected
	}
	var envelope EnvelopeV1
	if strictDecode(payload, &envelope) != nil || envelope.Signature != "" || !requestMatchesEnvelope(request, envelope) || in.Now.Before(envelope.IssuedAt) || !in.Now.Before(envelope.ExpiresAt) {
		return EnvelopeV1{}, errRejected
	}
	canonical, err := UnsignedEnvelopePayload(envelope)
	if err != nil || string(canonical) != string(payload) {
		return EnvelopeV1{}, errRejected
	}
	envelope.Signature = signature.Signature
	if err := WriteNewCanonical(in.EnvelopeOutput, envelope); err != nil {
		return EnvelopeV1{}, errRejected
	}
	return envelope, nil
}

// WriteNewCanonical makes release material durable without ever replacing an
// existing file. A same-directory hard-link publication is the no-replace
// primitive: unlike check-then-Rename, Link fails atomically if a concurrent
// writer publishes the destination first.
func WriteNewCanonical(path string, value any) error {
	return writeNewCanonical(path, value, "")
}

// WriteNewCanonicalOutsideStage publishes a packaging output only when its
// resolved parent remains physically outside the descriptor-resolved stage.
// It is the required writer for manifest and signing-request output.
func WriteNewCanonicalOutsideStage(stageRoot, path string, value any) error {
	physicalStage, err := resolvePhysicalStagePath(stageRoot)
	if err != nil {
		return errRejected
	}
	return writeNewCanonical(path, value, physicalStage)
}

func writeNewCanonical(path string, value any, forbiddenStage string) error {
	parent, name, err := openSafeOutputParent(path)
	if err != nil {
		return errRejected
	}
	defer parent.root.Close()
	if forbiddenStage != "" && physicalWithin(forbiddenStage, filepath.Join(parent.path, name)) {
		return errRejected
	}
	body, err := CanonicalJSON(value)
	if err != nil || len(body) == 0 || len(body) > maxInputBytes {
		return errRejected
	}
	temp, file, err := createOutputTemp(parent.root, name)
	if err != nil {
		return errRejected
	}
	tempPresent := true
	linked := false
	completed := false
	defer func() {
		if !completed {
			if linked {
				_ = parent.root.Remove(name)
			}
			if tempPresent {
				_ = parent.root.Remove(temp)
			}
			_ = syncRoot(parent.root)
		}
	}()
	if _, err = file.Write(body); err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil || closeErr != nil {
		return errRejected
	}
	if beforeOutputPublishForTest != nil {
		beforeOutputPublishForTest()
	}
	// Link is atomic and succeeds only when name does not yet exist. The temp
	// and target are under the same already-open directory descriptor.
	if validateOutputParent(parent) != nil || (forbiddenStage != "" && physicalWithin(forbiddenStage, filepath.Join(parent.path, name))) || parent.root.Link(temp, name) != nil {
		return errRejected
	}
	linked = true
	if err = parent.root.Remove(temp); err != nil {
		return errRejected
	}
	tempPresent = false
	if err = syncRoot(parent.root); err != nil || validateOutputParent(parent) != nil {
		return errRejected
	}
	info, err := parent.root.Lstat(name)
	if err != nil || !safeRegular(info, maxInputBytes) || info.Mode().Perm() != 0600 {
		return errRejected
	}
	completed = true
	return nil
}

func createOutputTemp(parent *os.Root, name string) (string, *os.File, error) {
	for range 16 {
		random := make([]byte, 16)
		if _, err := rand.Read(random); err != nil {
			return "", nil, errRejected
		}
		temp := "." + name + ".openduck-tmp-" + hex.EncodeToString(random)
		file, err := parent.OpenFile(temp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err == nil {
			if err = file.Chmod(0600); err != nil {
				_ = file.Close()
				_ = parent.Remove(temp)
				return "", nil, errRejected
			}
			return temp, file, nil
		}
	}
	return "", nil, errRejected
}

func syncRoot(root *os.Root) error {
	dir, err := root.Open(".")
	if err != nil {
		return errRejected
	}
	defer dir.Close()
	if err = dir.Sync(); err != nil {
		return errRejected
	}
	return nil
}

// ResolvePackagePaths resolves every directory alias before packaging. The
// returned paths are anchored at the physical stage and output parents, so a
// symlinked output parent cannot point back into the staged release.
func ResolvePackagePaths(stage string, outputs ...string) (string, []string, error) {
	physicalStage, err := resolvePhysicalStagePath(stage)
	if err != nil {
		return "", nil, errRejected
	}
	resolved := make([]string, 0, len(outputs))
	seen := make(map[string]bool, len(outputs))
	for _, output := range outputs {
		physicalOutput, err := resolveOutputPath(output)
		if err != nil || seen[physicalOutput] || physicalWithin(physicalStage, physicalOutput) {
			return "", nil, errRejected
		}
		seen[physicalOutput] = true
		resolved = append(resolved, physicalOutput)
	}
	return physicalStage, resolved, nil
}

func resolvePhysicalStagePath(path string) (string, error) {
	physical, info, err := resolvePhysicalDirectory(path)
	if err != nil || info.Mode().Perm()&0o022 != 0 {
		return "", errRejected
	}
	return physical, nil
}

func resolveOutputPath(path string) (string, error) {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return "", errRejected
	}
	name := filepath.Base(path)
	if name == "." || name == ".." || strings.ContainsRune(name, filepath.Separator) {
		return "", errRejected
	}
	parent, info, err := resolvePhysicalDirectory(filepath.Dir(path))
	if err != nil || info.Mode().Perm()&0o022 != 0 || safeDirectory(parent) != nil {
		return "", errRejected
	}
	return filepath.Join(parent, name), nil
}

func resolvePhysicalDirectory(path string) (string, os.FileInfo, error) {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return "", nil, errRejected
	}
	physical, err := filepath.EvalSymlinks(path)
	if err != nil || !filepath.IsAbs(physical) || filepath.Clean(physical) != physical {
		return "", nil, errRejected
	}
	info, err := os.Lstat(physical)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return "", nil, errRejected
	}
	return physical, info, nil
}

func physicalWithin(root, path string) bool {
	rel, err := filepath.Rel(root, path)
	return err == nil && (rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))))
}

type outputParent struct {
	root *os.Root
	path string
	info os.FileInfo
}

func openSafeOutputParent(path string) (outputParent, string, error) {
	physical, err := resolveOutputPath(path)
	if err != nil {
		return outputParent{}, "", errRejected
	}
	parentPath := filepath.Dir(physical)
	before, err := os.Lstat(parentPath)
	if err != nil || safeDirectory(parentPath) != nil {
		return outputParent{}, "", errRejected
	}
	root, err := os.OpenRoot(parentPath)
	if err != nil {
		return outputParent{}, "", errRejected
	}
	after, err := root.Stat(".")
	if err != nil || !sameFile(before, after) || safeDirectory(parentPath) != nil {
		_ = root.Close()
		return outputParent{}, "", errRejected
	}
	return outputParent{root: root, path: parentPath, info: before}, filepath.Base(physical), nil
}

func validateOutputParent(parent outputParent) error {
	if parent.root == nil || parent.path == "" || parent.info == nil || safeDirectory(parent.path) != nil {
		return errRejected
	}
	named, err := os.Lstat(parent.path)
	if err != nil || !sameFile(parent.info, named) {
		return errRejected
	}
	opened, err := parent.root.Stat(".")
	if err != nil || !sameFile(parent.info, opened) || !sameFile(named, opened) {
		return errRejected
	}
	return nil
}

func strictDecode(body []byte, out any) error {
	if rejectDuplicateJSONKeys(body) != nil {
		return errRejected
	}
	d := json.NewDecoder(bytes.NewReader(body))
	d.DisallowUnknownFields()
	if d.Decode(out) != nil || d.Decode(&struct{}{}) != io.EOF {
		return errRejected
	}
	return nil
}

func canonicalCatalog(artifacts []Artifact) bool {
	if len(artifacts) == 0 {
		return false
	}
	projected := make([]releasecatalog.Artifact, 0, len(artifacts))
	for _, artifact := range artifacts {
		projected = append(projected, releasecatalog.Artifact{Type: artifact.Type, Path: artifact.Path, Platform: artifact.Platform, Arch: artifact.Arch, Version: artifact.Version, ActivationGroup: artifact.ActivationGroup, Required: artifact.Required})
	}
	first := artifacts[0]
	return releasecatalog.Validate(projected, first.Platform, first.Arch, first.Version) == nil
}

func manifestMatchesPackage(manifest ManifestV2, in PackageInput) bool {
	for _, artifact := range manifest.Artifacts {
		if artifact.Platform != in.Platform || artifact.Arch != in.Arch || artifact.Version != in.Version {
			return false
		}
	}
	return true
}

func computedReleaseDigest(releaseID, version, targetRoot string, artifacts []Artifact) (string, error) {
	return CanonicalDigest(releaseDigestProjection{Schema: ManifestSchema, ReleaseID: releaseID, Version: version, TargetRoot: targetRoot, Artifacts: artifacts})
}

func validPackageInput(in PackageInput) bool {
	return validID(in.ReleaseID) && validVersion(in.Version) && safeTargetRoot(in.TargetRoot) && validID(in.Platform) && validID(in.Arch) && validID(in.KeyID) && validReleaseOperation(in.Operation) && validRunID(in.RunID) && in.Sequence != 0 && validID(in.Nonce) && !in.IssuedAt.IsZero() && !in.ExpiresAt.IsZero() && in.IssuedAt.Before(in.ExpiresAt) && validVersion(in.MinInstaller)
}

func validSigningRequest(r SigningRequestV1) bool {
	if r.Schema != SigningRequestSchema || r.Algorithm != "ed25519" || !validID(r.KeyID) || !validID(r.ReleaseID) || !validDigest(r.ManifestDigest) || !validDigest(r.ArtifactSetDigest) || !validDigest(r.ReleaseDigest) || !validVersion(r.ReleaseVersion) || !safeTargetRoot(r.TargetRoot) || !validID(r.Platform) || !validID(r.Arch) || !validDigest(r.PayloadDigest) || !validReleaseOperation(r.Operation) || !validRunID(r.RunID) || !validActivationIntent(r.Activation) || r.Sequence == 0 || !validID(r.Nonce) || r.IssuedAt.IsZero() || r.ExpiresAt.IsZero() || !r.IssuedAt.Before(r.ExpiresAt) || !validVersion(r.MinInstaller) {
		return false
	}
	payload, err := base64.StdEncoding.DecodeString(r.UnsignedPayload)
	if err != nil || len(payload) == 0 || len(payload) > maxInputBytes || base64.StdEncoding.EncodeToString(payload) != r.UnsignedPayload || digestBytes(payload) != r.PayloadDigest {
		return false
	}
	var envelope EnvelopeV1
	if strictDecode(payload, &envelope) != nil || envelope.Signature != "" || !requestMatchesEnvelope(r, envelope) {
		return false
	}
	canonical, err := UnsignedEnvelopePayload(envelope)
	return err == nil && string(canonical) == string(payload)
}

func validExternalSignature(s ExternalSignatureV1) bool {
	if s.Schema != SignatureSchema || s.Algorithm != "ed25519" || !validID(s.KeyID) || !validDigest(s.PayloadDigest) {
		return false
	}
	b, err := hex.DecodeString(s.Signature)
	return err == nil && len(b) == ed25519.SignatureSize && hex.EncodeToString(b) == s.Signature
}

func requestMatchesEnvelope(r SigningRequestV1, e EnvelopeV1) bool {
	return e.Schema == EnvelopeSchema && e.KeyID == r.KeyID && e.ReleaseID == r.ReleaseID && e.ManifestDigest == r.ManifestDigest && e.ArtifactSetDigest == r.ArtifactSetDigest && e.ReleaseDigest == r.ReleaseDigest && e.ReleaseVersion == r.ReleaseVersion && e.TargetRoot == r.TargetRoot && e.Platform == r.Platform && e.Arch == r.Arch && e.Operation == r.Operation && e.RunID == r.RunID && e.Activation == r.Activation && e.Sequence == r.Sequence && e.Nonce == r.Nonce && e.IssuedAt.Equal(r.IssuedAt) && e.ExpiresAt.Equal(r.ExpiresAt) && e.MinInstaller == r.MinInstaller
}

func safeDistinctOutputs(out string, inputs ...string) bool {
	physicalOut, err := resolveOutputPath(out)
	if err != nil {
		return false
	}
	for _, p := range inputs {
		if p == "" || !filepath.IsAbs(p) || filepath.Clean(p) != p {
			return false
		}
		physicalInput, err := filepath.EvalSymlinks(p)
		if err != nil || physicalInput == physicalOut {
			return false
		}
	}
	return true
}

func openStageRoot(path string) (*os.Root, error) {
	physical, err := resolvePhysicalStagePath(path)
	if err != nil {
		return nil, errRejected
	}
	before, err := os.Lstat(physical)
	if err != nil {
		return nil, errRejected
	}
	root, err := os.OpenRoot(physical)
	if err != nil {
		return nil, errRejected
	}
	after, err := root.Stat(".")
	if err != nil || before.Mode()&os.ModeSymlink != 0 || !before.IsDir() || unsafeSpecialMode(before) || !sameFile(before, after) || !after.IsDir() || unsafeSpecialMode(after) || after.Mode().Perm()&0o022 != 0 {
		root.Close()
		return nil, errRejected
	}
	return root, nil
}

func verifyStageInventory(root *os.Root, selected []releasecatalog.Entry) error {
	expected := releasecatalog.ExpectedChildren(selected)
	for directory, children := range expected {
		names, err := descriptorNames(root, directory)
		if err != nil || len(names) != len(children) {
			return errRejected
		}
		for index, name := range names {
			if !children[name] || (index > 0 && names[index-1] >= name) {
				return errRejected
			}
		}
	}
	return nil
}

func descriptorNames(root *os.Root, name string) ([]string, error) {
	before, err := root.Lstat(name)
	if err != nil || before.Mode()&os.ModeSymlink != 0 || !before.IsDir() || unsafeSpecialMode(before) || before.Mode().Perm()&0o022 != 0 {
		return nil, errRejected
	}
	f, err := root.Open(name)
	if err != nil {
		return nil, errRejected
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !sameFile(before, opened) || !opened.IsDir() || unsafeSpecialMode(opened) || opened.Mode().Perm()&0o022 != 0 {
		return nil, errRejected
	}
	entries, err := f.ReadDir(-1)
	if err != nil {
		return nil, errRejected
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.Name() == "." || e.Name() == ".." || e.Type()&os.ModeSymlink != 0 {
			return nil, errRejected
		}
		names = append(names, e.Name())
	}
	after, err := root.Lstat(name)
	if err != nil || !sameFile(before, after) || after.Mode()&os.ModeSymlink != 0 || !after.IsDir() || unsafeSpecialMode(after) || after.Mode().Perm()&0o022 != 0 {
		return nil, errRejected
	}
	sort.Strings(names)
	return names, nil
}

// afterStageReadForTest makes concurrent-mutation assertions deterministic.
// It is nil in production and is only set by same-package tests.
var afterStageReadForTest func(string)

func readStageArtifact(root *os.Root, rel string, executable bool, maxBytes int64) ([]byte, error) {
	if maxBytes <= 0 || maxBytes > maxArtifactBytes {
		return nil, errRejected
	}
	parts := strings.Split(rel, "/")
	if validateStageParents(root, parts) != nil {
		return nil, errRejected
	}
	before, err := root.Lstat(rel)
	if err != nil || !safeCatalogStagedRegular(before, executable, maxBytes) {
		return nil, errRejected
	}
	f, err := root.Open(rel)
	if err != nil {
		return nil, errRejected
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !sameFile(before, info) || !safeCatalogStagedRegular(info, executable, maxBytes) {
		return nil, errRejected
	}
	body, err := io.ReadAll(io.LimitReader(f, maxBytes+1))
	if err != nil || len(body) < 1 || int64(len(body)) > maxBytes {
		return nil, errRejected
	}
	if afterStageReadForTest != nil {
		afterStageReadForTest(rel)
	}
	afterOpened, err := f.Stat()
	afterNamed, namedErr := root.Lstat(rel)
	if err != nil || namedErr != nil || !sameFile(before, afterOpened) || !sameFile(before, afterNamed) || !safeCatalogStagedRegular(afterOpened, executable, maxBytes) || !safeCatalogStagedRegular(afterNamed, executable, maxBytes) || afterOpened.Size() != before.Size() || afterNamed.Size() != before.Size() || int64(len(body)) != before.Size() || validateStageParents(root, parts) != nil {
		return nil, errRejected
	}
	return body, nil
}

func safeCatalogStagedRegular(info os.FileInfo, executable bool, maxBytes int64) bool {
	if !safeStagedRegular(info, maxBytes) {
		return false
	}
	hasExecutableBit := info.Mode().Perm()&0o111 != 0
	return hasExecutableBit == executable
}

func validateStageParents(root *os.Root, parts []string) error {
	for i := range parts[:len(parts)-1] {
		parent := strings.Join(parts[:i+1], "/")
		info, err := root.Lstat(parent)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || unsafeSpecialMode(info) || info.Mode().Perm()&0o022 != 0 {
			return errRejected
		}
	}
	return nil
}
