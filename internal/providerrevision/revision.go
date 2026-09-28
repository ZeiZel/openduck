// Package providerrevision owns the Controller's installed provider metadata.
// It deliberately has no provider executable, credential, or network surface.
package providerrevision

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"openduck/internal/providerbridge"
)

const (
	BundleV1           = "controller-provider-bundle.v1"
	RepositoryV1       = "controller-provider-revisions.v1"
	maxBundleBytes     = 512 << 10
	maxTrustBytes      = 32 << 10
	maxStateBytes      = 2 << 20
	maxRevisions       = 32
	maxReceipts        = 256
	maxOperationBytes  = 64 << 10
	maxAssociations    = 256
	maxPreparedEffects = 64
	maxUISelections    = 256
	maxUISnapshots     = 64
	safetyReceiptSlots = 32
)

var (
	ErrInvalid      = errors.New("invalid provider revision")
	ErrUnavailable  = errors.New("provider revision unavailable")
	ErrConflict     = errors.New("provider revision conflict")
	ErrUnauthorized = errors.New("provider revision unauthorized")
	ErrReplay       = errors.New("provider revision replay")
	ErrCorrupt      = errors.New("provider revision repository corrupt")
)

// Bundle is a closed canonical artifact. TrustBundleDigest is a binding, not a
// trust source: the key material is loaded separately from a root-owned path
// selected by Controller configuration.
type Bundle struct {
	SchemaVersion     string          `json:"schema_version"`
	BundleID          string          `json:"bundle_id"`
	RevisionID        string          `json:"revision_id"`
	TrustBundleDigest string          `json:"trust_bundle_digest"`
	Profiles          []ProfileBundle `json:"profiles"`
	Digest            string          `json:"digest"`
}

type ProfileBundle struct {
	Profile          ProfileDTO                            `json:"profile"`
	Limits           providerbridge.ExecutionLimits        `json:"limits"`
	Mapping          providerbridge.Mapping                `json:"mapping"`
	Compatibility    providerbridge.CompatibilityRecord    `json:"compatibility"`
	Evidence         providerbridge.ProviderEvidenceRecord `json:"evidence"`
	ActivationIntent bool                                  `json:"activation_intent"`
}

// ProfileDTO keeps the external bundle schema exact. providerbridge.Profile
// intentionally has no JSON tags and must never be decoded directly because
// encoding/json accepts case-insensitive aliases for its exported fields.
type ProfileDTO struct {
	ID                     string                  `json:"id"`
	Provider               providerbridge.Provider `json:"provider"`
	Model                  string                  `json:"model"`
	RuntimeKind            string                  `json:"runtime_kind"`
	AuthModality           string                  `json:"auth_modality"`
	AccountRef             string                  `json:"account_ref"`
	LocalOnly              bool                    `json:"local_only"`
	MeshSpawnEnabled       bool                    `json:"mesh_spawn_enabled"`
	ExecutionLimitsDigest  string                  `json:"execution_limits_digest"`
	MappingDigest          string                  `json:"mapping_digest"`
	ProviderEvidenceDigest string                  `json:"provider_evidence_digest"`
	Revision               string                  `json:"revision"`
	Status                 providerbridge.Status   `json:"status"`
}

func (p ProfileDTO) bridge() providerbridge.Profile {
	return providerbridge.Profile{ID: p.ID, Provider: p.Provider, Model: p.Model, RuntimeKind: p.RuntimeKind, AuthModality: p.AuthModality, AccountRef: p.AccountRef, LocalOnly: p.LocalOnly, MeshSpawnEnabled: p.MeshSpawnEnabled, ExecutionLimitsDigest: p.ExecutionLimitsDigest, MappingDigest: p.MappingDigest, ProviderEvidenceDigest: p.ProviderEvidenceDigest, Revision: p.Revision, Status: p.Status}
}

type LoadConfig struct {
	RootPath             string
	ManifestLeaf         string
	TrustLeaf            string
	ExpectedBundleDigest string
	ExpectedTrustDigest  string
	OwnerUID             uint32
	OwnerGID             uint32
}

// Load reads only fixed leaves below an already configured root. It opens the
// root as a descriptor, rejects links/special files/hardlinks and binds both
// independently selected artifacts to exact content digests.
func Load(config LoadConfig, now time.Time) (Bundle, providerbridge.Ed25519TrustBundle, error) {
	if !validLoadConfig(config) {
		return Bundle{}, providerbridge.Ed25519TrustBundle{}, ErrInvalid
	}
	rootInfo, err := os.Lstat(config.RootPath)
	if err != nil || !safeArtifactDir(rootInfo, config.OwnerUID, config.OwnerGID) {
		return Bundle{}, providerbridge.Ed25519TrustBundle{}, ErrUnavailable
	}
	root, err := os.OpenRoot(config.RootPath)
	if err != nil {
		return Bundle{}, providerbridge.Ed25519TrustBundle{}, ErrUnavailable
	}
	defer root.Close()
	openedRoot, err := root.Stat(".")
	if err != nil || !safeArtifactDir(openedRoot, config.OwnerUID, config.OwnerGID) || !sameFile(rootInfo, openedRoot) {
		return Bundle{}, providerbridge.Ed25519TrustBundle{}, ErrUnavailable
	}
	manifest, err := secureRead(root, config.ManifestLeaf, config.OwnerUID, config.OwnerGID, maxBundleBytes)
	if err != nil || digestBytes(manifest) != config.ExpectedBundleDigest {
		return Bundle{}, providerbridge.Ed25519TrustBundle{}, ErrUnavailable
	}
	trustRaw, err := secureRead(root, config.TrustLeaf, config.OwnerUID, config.OwnerGID, maxTrustBytes)
	if err != nil || digestBytes(trustRaw) != config.ExpectedTrustDigest {
		return Bundle{}, providerbridge.Ed25519TrustBundle{}, ErrUnavailable
	}
	afterRoot, err := root.Stat(".")
	namedAfter, namedErr := os.Lstat(config.RootPath)
	if err != nil || namedErr != nil || !safeArtifactDir(afterRoot, config.OwnerUID, config.OwnerGID) || !safeArtifactDir(namedAfter, config.OwnerUID, config.OwnerGID) || !sameFile(openedRoot, afterRoot) || !sameFile(rootInfo, namedAfter) {
		return Bundle{}, providerbridge.Ed25519TrustBundle{}, ErrUnavailable
	}
	trust, err := providerbridge.DecodeEd25519TrustBundle(trustRaw)
	if err != nil {
		return Bundle{}, providerbridge.Ed25519TrustBundle{}, ErrInvalid
	}
	bundle, err := Decode(manifest)
	if err != nil || bundle.TrustBundleDigest != config.ExpectedTrustDigest || validateBundle(bundle, trust, now) != nil {
		return Bundle{}, providerbridge.Ed25519TrustBundle{}, ErrInvalid
	}
	return bundle, trust, nil
}

func Decode(raw []byte) (Bundle, error) {
	if len(raw) == 0 || len(raw) > maxBundleBytes || !json.Valid(raw) || duplicateKeys(raw) {
		return Bundle{}, ErrInvalid
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var bundle Bundle
	if err := dec.Decode(&bundle); err != nil || dec.Decode(&struct{}{}) != io.EOF {
		return Bundle{}, ErrInvalid
	}
	canonical, err := json.Marshal(bundle)
	if err != nil || !bytes.Equal(canonical, raw) || validateBundleShape(bundle) != nil {
		return Bundle{}, ErrInvalid
	}
	return bundle, nil
}

// ValidateBundle applies the complete read-only bundle/trust compatibility
// validation used by the Controller loader. Callers must supply the explicit
// signed validation instant; this package never substitutes wall-clock time
// for release admission or offline packaging.
func ValidateBundle(bundle Bundle, trust providerbridge.Ed25519TrustBundle, now time.Time) error {
	if now.IsZero() {
		return ErrInvalid
	}
	return validateBundle(bundle, trust, now.UTC())
}

func (b *Bundle) Seal() error {
	if b == nil {
		return ErrInvalid
	}
	b.Digest = sealedBundleDigest(*b)
	return nil
}

func validateBundle(bundle Bundle, trust providerbridge.Ed25519TrustBundle, now time.Time) error {
	if bundle.SchemaVersion != BundleV1 || !safeID(bundle.BundleID) || !safeID(bundle.RevisionID) || !isDigest(bundle.TrustBundleDigest) || !isDigest(bundle.Digest) || len(bundle.Profiles) == 0 || len(bundle.Profiles) > 16 || bundle.Digest != sealedBundleDigest(bundle) {
		return ErrInvalid
	}
	profiles := make([]providerbridge.Profile, 0, len(bundle.Profiles))
	limits := make(map[string]providerbridge.ExecutionLimits, len(bundle.Profiles))
	mappings := make([]providerbridge.Mapping, 0, len(bundle.Profiles))
	evidence := make([]providerbridge.ProviderEvidenceRecord, 0, len(bundle.Profiles))
	compatibility := make([]providerbridge.CompatibilityRecord, 0, len(bundle.Profiles))
	seen := make(map[string]bool, len(bundle.Profiles))
	previousID := ""
	for _, entry := range bundle.Profiles {
		p := entry.Profile.bridge()
		if seen[p.ID] || p.ID <= previousID || p.MeshSpawnEnabled != entry.ActivationIntent || (!p.LocalOnly && entry.ActivationIntent && p.AccountRef == "") || entry.Limits.SchemaVersion != providerbridge.ExecutionLimitsV1 || entry.Limits.Validate() != nil || entry.Mapping.ProfileID != p.ID || entry.Compatibility.ProfileID != p.ID || entry.Evidence.ProfileID != p.ID {
			return ErrInvalid
		}
		// Each object must retain its own canonical representation; top-level
		// canonical JSON alone cannot prove a future decoder uses the same rules.
		if canonical(entry.Mapping) == nil || canonical(entry.Compatibility) == nil || canonical(entry.Evidence) == nil {
			return ErrInvalid
		}
		seen[p.ID] = true
		previousID = p.ID
		profiles = append(profiles, p)
		limits[p.ID] = entry.Limits
		mappings = append(mappings, entry.Mapping)
		evidence = append(evidence, entry.Evidence)
		compatibility = append(compatibility, entry.Compatibility)
	}
	verifier, err := trust.Verifier()
	if err != nil {
		return ErrInvalid
	}
	registry, err := providerbridge.NewRegistryWithCompatibility(profiles, limits, mappings, evidence, compatibility, trust.TrustRegistry(), verifier)
	if err != nil {
		return ErrInvalid
	}
	for _, entry := range bundle.Profiles {
		resolution, err := registry.Resolve(context.Background(), entry.Profile.ID, now.UTC())
		if entry.ActivationIntent {
			if err != nil || !resolution.MeshSpawnEnabled() {
				return ErrInvalid
			}
		} else if err != nil && !errors.Is(err, providerbridge.ErrProfileIncompatible) {
			return ErrInvalid
		}
	}
	return nil
}

func canonical(v any) []byte                  { b, _ := json.Marshal(v); return b }
func sealedBundleDigest(bundle Bundle) string { bundle.Digest = ""; return digestValue(bundle) }
func digestValue(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	return digestBytes(b)
}
func digestBytes(v []byte) string {
	sum := sha256.Sum256(v)
	return "sha256:" + hex.EncodeToString(sum[:])
}
func isDigest(v string) bool {
	return len(v) == 71 && strings.HasPrefix(v, "sha256:") && strings.ToLower(v) == v && func() bool { _, err := hex.DecodeString(v[7:]); return err == nil }()
}
func safeID(v string) bool {
	if len(v) == 0 || len(v) > 160 {
		return false
	}
	for _, r := range v {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || strings.ContainsRune("._:-", r)) {
			return false
		}
	}
	return true
}
func safeLeaf(v string) bool { return safeID(v) && !strings.Contains(v, "/") && v != "." && v != ".." }
func validLoadConfig(c LoadConfig) bool {
	return filepath.IsAbs(c.RootPath) && filepath.Clean(c.RootPath) == c.RootPath && safeLeaf(c.ManifestLeaf) && safeLeaf(c.TrustLeaf) && c.ManifestLeaf != c.TrustLeaf && isDigest(c.ExpectedBundleDigest) && isDigest(c.ExpectedTrustDigest)
}
func safeDir(info os.FileInfo, uid uint32) bool {
	if info == nil || !info.IsDir() || info.Mode()&^(os.ModeDir|0700) != 0 {
		return false
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	return ok && st != nil && st.Uid == uid
}
func safeArtifactDir(info os.FileInfo, uid, gid uint32) bool {
	if info == nil || !info.IsDir() || info.Mode()&^(os.ModeDir|0750) != 0 {
		return false
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	return ok && st != nil && st.Uid == uid && st.Gid == gid
}
func safeFile(info os.FileInfo, uid, gid uint32) bool {
	if info == nil || !info.Mode().IsRegular() || info.Mode()&^0440 != 0 {
		return false
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	return ok && st != nil && st.Uid == uid && st.Gid == gid && st.Nlink == 1
}
func secureRead(root *os.Root, leaf string, uid, gid uint32, max int64) ([]byte, error) {
	if root == nil || !safeLeaf(leaf) || max < 1 {
		return nil, ErrInvalid
	}
	before, err := root.Lstat(leaf)
	if err != nil || !safeFile(before, uid, gid) {
		return nil, ErrInvalid
	}
	f, err := root.Open(leaf)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	after, err := f.Stat()
	if err != nil || !safeFile(after, uid, gid) || !sameFile(before, after) || after.Size() < 1 || after.Size() > max {
		return nil, ErrInvalid
	}
	out, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil || int64(len(out)) != after.Size() || len(out) == 0 || int64(len(out)) > max {
		return nil, ErrInvalid
	}
	namedAfter, err := root.Lstat(leaf)
	if err != nil || !safeFile(namedAfter, uid, gid) || !sameFile(before, namedAfter) {
		return nil, ErrInvalid
	}
	return out, nil
}
func sameFile(a, b os.FileInfo) bool {
	x, ok1 := a.Sys().(*syscall.Stat_t)
	y, ok2 := b.Sys().(*syscall.Stat_t)
	return ok1 && ok2 && x != nil && y != nil && x.Dev == y.Dev && x.Ino == y.Ino
}

// Operation is an exact Controller authority seam. Evidence approvals are not
// operations and can never satisfy this interface by themselves.
type Operation struct {
	SchemaVersion, Action, RevisionID, BundleDigest, TrustDigest, ProfileID, ProfileRevision string
	BaseVersion, ExpectedVersion                                                             uint64
	Nonce, PayloadDigest, ApprovalID, Digest                                                 string
	IssuedAt, ExpiresAt                                                                      time.Time
}

func (o *Operation) Seal() { o.Digest = ""; o.Digest = digestValue(*o) }
func (o Operation) valid(now time.Time) bool {
	c := o
	c.Digest = ""
	return o.SchemaVersion == "provider-revision-operation.v1" && (o.Action == "install" || o.Action == "set-enabled") && safeID(o.RevisionID) && isDigest(o.BundleDigest) && isDigest(o.TrustDigest) && safeID(o.Nonce) && isDigest(o.PayloadDigest) && safeID(o.ApprovalID) && isDigest(o.Digest) && o.Digest == digestValue(c) && !o.IssuedAt.IsZero() && !o.IssuedAt.After(now) && o.ExpiresAt.After(o.IssuedAt) && o.ExpiresAt.After(now) && o.ExpiresAt.Sub(o.IssuedAt) <= 5*time.Minute && ((o.Action == "install" && o.ProfileID == "" && o.ProfileRevision == "") || (o.Action == "set-enabled" && safeID(o.ProfileID) && safeID(o.ProfileRevision)))
}

type OperationAuthorizer interface {
	Authorize(context.Context, Operation) error
}
type TrustSource interface {
	Current(context.Context, string) (providerbridge.Ed25519TrustBundle, error)
}
type TrustSourceFunc func(context.Context, string) (providerbridge.Ed25519TrustBundle, error)

func (f TrustSourceFunc) Current(ctx context.Context, digest string) (providerbridge.Ed25519TrustBundle, error) {
	return f(ctx, digest)
}

type ArtifactTrustSource struct {
	RootPath, TrustLeaf, ExpectedDigest string
	OwnerUID                            uint32
	OwnerGID                            uint32
}

func (s ArtifactTrustSource) Current(_ context.Context, expected string) (providerbridge.Ed25519TrustBundle, error) {
	if !filepath.IsAbs(s.RootPath) || filepath.Clean(s.RootPath) != s.RootPath || !safeLeaf(s.TrustLeaf) || !isDigest(expected) || expected != s.ExpectedDigest {
		return providerbridge.Ed25519TrustBundle{}, ErrUnavailable
	}
	info, err := os.Lstat(s.RootPath)
	if err != nil || !safeArtifactDir(info, s.OwnerUID, s.OwnerGID) {
		return providerbridge.Ed25519TrustBundle{}, ErrUnavailable
	}
	root, err := os.OpenRoot(s.RootPath)
	if err != nil {
		return providerbridge.Ed25519TrustBundle{}, ErrUnavailable
	}
	defer root.Close()
	opened, err := root.Stat(".")
	if err != nil || !safeArtifactDir(opened, s.OwnerUID, s.OwnerGID) || !sameFile(info, opened) {
		return providerbridge.Ed25519TrustBundle{}, ErrUnavailable
	}
	raw, err := secureRead(root, s.TrustLeaf, s.OwnerUID, s.OwnerGID, maxTrustBytes)
	if err != nil || digestBytes(raw) != expected {
		return providerbridge.Ed25519TrustBundle{}, ErrUnavailable
	}
	openedAfter, err := root.Stat(".")
	namedAfter, namedErr := os.Lstat(s.RootPath)
	if err != nil || namedErr != nil || !safeArtifactDir(openedAfter, s.OwnerUID, s.OwnerGID) || !safeArtifactDir(namedAfter, s.OwnerUID, s.OwnerGID) || !sameFile(opened, openedAfter) || !sameFile(info, namedAfter) {
		return providerbridge.Ed25519TrustBundle{}, ErrUnavailable
	}
	return providerbridge.DecodeEd25519TrustBundle(raw)
}

const ProviderLifecycleOperationV1 = "provider-lifecycle-operation.v1"
const lifecyclePurpose = "controller-provider-lifecycle.v1"

// OwnerTrust is independently installed Controller authority. It is neither a
// provider evidence key nor bundle-controlled material.
type OwnerTrust struct {
	SchemaVersion string `json:"schema_version"`
	KeyID         string `json:"key_id"`
	PublicKey     string `json:"public_key"`
	Revoked       bool   `json:"revoked"`
}

// ProviderLifecycleOperation is a closed, signed Controller operation. UI
// bearer sessions cannot construct authority because this envelope requires an
// owner key and exact root/endpoint fields for association operations.
type ProviderLifecycleOperation struct {
	SchemaVersion       string    `json:"schema_version"`
	Purpose             string    `json:"purpose"`
	Action              string    `json:"action"`
	RevisionID          string    `json:"revision_id"`
	BundleDigest        string    `json:"bundle_digest"`
	TrustDigest         string    `json:"trust_digest"`
	ProfileID           string    `json:"profile_id"`
	ProfileRevision     string    `json:"profile_revision"`
	BaseVersion         uint64    `json:"base_version"`
	BaseCurrentRevision string    `json:"base_current_revision"`
	SessionID           string    `json:"session_id"`
	ChannelID           string    `json:"channel_id"`
	RootRunID           string    `json:"root_run_id"`
	RunID               string    `json:"run_id"`
	MeshSessionID       string    `json:"mesh_session_id"`
	AttemptID           string    `json:"attempt_id"`
	PeerID              string    `json:"peer_id"`
	EndpointID          string    `json:"endpoint_id"`
	AssociationDigest   string    `json:"association_digest"`
	DecisionID          string    `json:"decision_id"`
	Nonce               string    `json:"nonce"`
	KeyID               string    `json:"key_id"`
	Digest              string    `json:"digest"`
	Signature           string    `json:"signature"`
	EndpointGeneration  uint64    `json:"endpoint_generation"`
	Enabled             bool      `json:"enabled"`
	Classification      string    `json:"classification"`
	WorkspaceGroupID    string    `json:"workspace_group_id"`
	IssuedAt            time.Time `json:"issued_at"`
	ExpiresAt           time.Time `json:"operation_expires_at"`
	EndpointExpiresAt   time.Time `json:"endpoint_expires_at"`
}

func (o *ProviderLifecycleOperation) Seal() {
	o.Digest = ""
	o.Signature = ""
	o.Digest = digestValue(*o)
}
func (o ProviderLifecycleOperation) valid(now time.Time) bool {
	c := o
	actual := c.Digest
	sig := c.Signature
	c.Digest = ""
	c.Signature = ""
	if o.SchemaVersion != ProviderLifecycleOperationV1 || o.Purpose != lifecyclePurpose || !validLifecycleAction(o.Action) || !safeID(o.RevisionID) || !isDigest(o.BundleDigest) || !isDigest(o.TrustDigest) || !safeID(o.DecisionID) || !safeID(o.Nonce) || !safeID(o.KeyID) || !isDigest(actual) || actual != digestValue(c) || !lowerHex(sig, ed25519.SignatureSize) || o.IssuedAt.IsZero() || o.IssuedAt.After(now) || !o.ExpiresAt.After(o.IssuedAt) || !o.ExpiresAt.After(now) || o.ExpiresAt.Sub(o.IssuedAt) > 5*time.Minute {
		return false
	}
	switch o.Action {
	case "install":
		return validBaseBinding(o, true, false) && !o.Enabled && noProfileFields(o) && noUIFields(o)
	case "activate":
		return validBaseBinding(o, false, true) && !o.Enabled && noProfileFields(o) && noUIFields(o)
	case "profile-enable":
		return validBaseBinding(o, false, false) && o.Enabled && safeID(o.ProfileID) && safeID(o.ProfileRevision) && noUIFields(o)
	case "profile-disable":
		return validBaseBinding(o, false, false) && !o.Enabled && safeID(o.ProfileID) && safeID(o.ProfileRevision) && noUIFields(o)
	case "ui-register":
		return validBaseBinding(o, false, false) && o.BaseCurrentRevision == o.RevisionID && !o.Enabled && noProfileFields(o) && validUIRegistrationRequest(o)
	case "ui-bind":
		return validBaseBinding(o, false, false) && o.BaseCurrentRevision == o.RevisionID && !o.Enabled && noProfileFields(o) && o.AssociationDigest == "" && safeUIBinding(o) && !o.EndpointExpiresAt.IsZero() && o.EndpointExpiresAt.After(o.IssuedAt)
	case "ui-revoke":
		// A revoke may target a prior revision or an expired association so a
		// stale binding cannot occupy bounded durable state forever. The
		// apply path nevertheless requires exact association identity, digest,
		// revision, and expiry before it can remove anything.
		return validBaseBinding(o, false, false) && !o.Enabled && noProfileFields(o) && safeUIBinding(o) && isDigest(o.AssociationDigest) && !o.EndpointExpiresAt.IsZero()
	case "ui-rotate":
		// Rotation can affect the active association only: its result becomes
		// the next UI capability for the current revision.
		return validBaseBinding(o, false, false) && o.BaseCurrentRevision == o.RevisionID && !o.Enabled && noProfileFields(o) && safeUIBinding(o) && isDigest(o.AssociationDigest) && !o.EndpointExpiresAt.IsZero()
	case "root-close":
		// Closing is a monotone safety operation.  It can target an exact
		// association from a prior revision after activation changed the current
		// pointer, but every association field/digest remains bound below.
		return validBaseBinding(o, false, false) && !o.Enabled && noProfileFields(o) && safeUIBinding(o) && isDigest(o.AssociationDigest) && !o.EndpointExpiresAt.IsZero()
	default:
		return false
	}
}

// validBaseBinding makes every mutation bind the exact durable snapshot it was
// approved against. The initial candidate install and the first explicit
// activation may bind no active revision; profile and UI operations always
// require an existing active revision.
func validBaseBinding(o ProviderLifecycleOperation, allowInitial, allowNoCurrent bool) bool {
	if o.BaseVersion == 0 {
		return allowInitial && o.BaseCurrentRevision == ""
	}
	if o.BaseCurrentRevision == "" {
		return allowNoCurrent
	}
	return safeID(o.BaseCurrentRevision)
}

func noProfileFields(o ProviderLifecycleOperation) bool {
	return o.ProfileID == "" && o.ProfileRevision == ""
}

func noUIFields(o ProviderLifecycleOperation) bool {
	return o.SessionID == "" && o.ChannelID == "" && o.RootRunID == "" && o.RunID == "" && o.MeshSessionID == "" && o.AttemptID == "" && o.PeerID == "" && o.EndpointID == "" && o.AssociationDigest == "" && o.EndpointGeneration == 0 && o.Classification == "" && o.WorkspaceGroupID == "" && o.EndpointExpiresAt.IsZero()
}
func validLifecycleAction(v string) bool {
	return v == "install" || v == "activate" || v == "profile-enable" || v == "profile-disable" || v == "ui-register" || v == "ui-bind" || v == "ui-revoke" || v == "ui-rotate" || v == "root-close"
}
func safeUIBinding(o ProviderLifecycleOperation) bool {
	return safeID(o.SessionID) && safeID(o.ChannelID) && safeID(o.RootRunID) && safeID(o.RunID) && safeID(o.MeshSessionID) && safeID(o.AttemptID) && safeID(o.PeerID) && safeID(o.EndpointID) && o.EndpointGeneration > 0 && o.Classification == "" && o.WorkspaceGroupID == ""
}

func validUIRegistrationRequest(o ProviderLifecycleOperation) bool {
	return safeID(o.SessionID) && safeID(o.ChannelID) && safeID(o.RootRunID) && o.RunID == o.RootRunID && safeID(o.MeshSessionID) && safeID(o.AttemptID) && safeID(o.PeerID) && safeID(o.Classification) && safeID(o.WorkspaceGroupID) && o.EndpointID == "" && o.AssociationDigest == "" && o.EndpointGeneration == 0 && o.EndpointExpiresAt.IsZero()
}

type UIAssociation struct {
	SessionID, ChannelID, RootRunID, RunID, MeshSessionID, AttemptID, PeerID, EndpointID, RevisionID string
	EndpointGeneration                                                                               uint64
	ExpiresAt                                                                                        time.Time
	Revoked                                                                                          bool
}

// UIRegistration is the durable owner-authorized pre-bind result. It is not
// an association and cannot authorize UI traffic: a separate owner-signed
// ui-bind operation is still required before the endpoint is usable.
type UIRegistration struct {
	RequestNonce, RequestDigest                                                                      string
	SessionID, ChannelID, RootRunID, RunID, MeshSessionID, AttemptID, PeerID, EndpointID, RevisionID string
	EndpointGeneration                                                                               uint64
	ExpiresAt                                                                                        time.Time
}

func (r UIRegistration) valid(now time.Time) bool {
	return safeID(r.RequestNonce) && isDigest(r.RequestDigest) && safeID(r.SessionID) && safeID(r.ChannelID) && safeID(r.RootRunID) && r.RunID == r.RootRunID && safeID(r.MeshSessionID) && safeID(r.AttemptID) && safeID(r.PeerID) && safeID(r.EndpointID) && safeID(r.RevisionID) && r.EndpointGeneration > 0 && !r.ExpiresAt.IsZero() && r.ExpiresAt.After(now)
}

// UIRevokeTarget is the only capability detail given to the composition
// callback. It is derived from a signed, exact durable association and cannot
// name a replacement endpoint generation.
type UIRevokeTarget struct {
	EndpointID string
	Generation uint64
}

type UIRotateTarget struct{ Association UIAssociation }
type UIRotateResult struct {
	EndpointID string
	Generation uint64
	ExpiresAt  time.Time
}

func (r UIRotateResult) valid(now time.Time, previous UIAssociation) bool {
	return safeID(r.EndpointID) && r.EndpointID != previous.EndpointID && r.Generation == previous.EndpointGeneration+1 && !r.ExpiresAt.IsZero() && r.ExpiresAt.After(now)
}

func (a UIAssociation) valid(now time.Time) bool {
	return !a.Revoked && safeID(a.SessionID) && safeID(a.ChannelID) && safeID(a.RootRunID) && safeID(a.RunID) && safeID(a.MeshSessionID) && safeID(a.AttemptID) && safeID(a.PeerID) && safeID(a.EndpointID) && safeID(a.RevisionID) && a.EndpointGeneration > 0 && !a.ExpiresAt.IsZero() && a.ExpiresAt.After(now)
}
func associationKey(session, channel string) string { return session + ":" + channel }

type OperationLoadConfig struct {
	RootPath, OperationLeaf, OwnerTrustLeaf, ExpectedOwnerTrustDigest string
	OwnerUID                                                          uint32
	OwnerGID                                                          uint32
}

func (c OperationLoadConfig) valid() bool {
	return filepath.IsAbs(c.RootPath) && filepath.Clean(c.RootPath) == c.RootPath && safeLeaf(c.OperationLeaf) && safeLeaf(c.OwnerTrustLeaf) && c.OperationLeaf != c.OwnerTrustLeaf && isDigest(c.ExpectedOwnerTrustDigest)
}
func LoadLifecycleOperation(c OperationLoadConfig, now time.Time) (ProviderLifecycleOperation, error) {
	if !c.valid() {
		return ProviderLifecycleOperation{}, ErrInvalid
	}
	rootInfo, err := os.Lstat(c.RootPath)
	if err != nil || !safeArtifactDir(rootInfo, c.OwnerUID, c.OwnerGID) {
		return ProviderLifecycleOperation{}, ErrUnavailable
	}
	root, err := os.OpenRoot(c.RootPath)
	if err != nil {
		return ProviderLifecycleOperation{}, ErrUnavailable
	}
	defer root.Close()
	opened, err := root.Stat(".")
	if err != nil || !safeArtifactDir(opened, c.OwnerUID, c.OwnerGID) || !sameFile(rootInfo, opened) {
		return ProviderLifecycleOperation{}, ErrUnavailable
	}
	trustRaw, err := secureRead(root, c.OwnerTrustLeaf, c.OwnerUID, c.OwnerGID, maxTrustBytes)
	if err != nil || digestBytes(trustRaw) != c.ExpectedOwnerTrustDigest {
		return ProviderLifecycleOperation{}, ErrUnavailable
	}
	trust, err := decodeOwnerTrust(trustRaw)
	if err != nil {
		return ProviderLifecycleOperation{}, ErrInvalid
	}
	raw, err := secureRead(root, c.OperationLeaf, c.OwnerUID, c.OwnerGID, maxOperationBytes)
	if err != nil {
		return ProviderLifecycleOperation{}, ErrUnavailable
	}
	op, err := DecodeLifecycleOperation(raw)
	if err != nil || !verifyOwnerOperation(op, trust, now.UTC()) {
		return ProviderLifecycleOperation{}, ErrUnauthorized
	}
	after, err := root.Stat(".")
	namedAfter, namedErr := os.Lstat(c.RootPath)
	if err != nil || namedErr != nil || !safeArtifactDir(after, c.OwnerUID, c.OwnerGID) || !safeArtifactDir(namedAfter, c.OwnerUID, c.OwnerGID) || !sameFile(opened, after) || !sameFile(rootInfo, namedAfter) {
		return ProviderLifecycleOperation{}, ErrUnavailable
	}
	return op, nil
}
func decodeOwnerTrust(raw []byte) (OwnerTrust, error) {
	if len(raw) == 0 || len(raw) > maxTrustBytes || !json.Valid(raw) || duplicateKeys(raw) {
		return OwnerTrust{}, ErrInvalid
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var trust OwnerTrust
	if dec.Decode(&trust) != nil || dec.Decode(&struct{}{}) != io.EOF {
		return OwnerTrust{}, ErrInvalid
	}
	canon, err := json.Marshal(trust)
	if err != nil || !bytes.Equal(canon, raw) || trust.SchemaVersion != "controller-owner-ed25519.v1" || !safeID(trust.KeyID) || !lowerHex(trust.PublicKey, ed25519.PublicKeySize) {
		return OwnerTrust{}, ErrInvalid
	}
	return trust, nil
}
func DecodeLifecycleOperation(raw []byte) (ProviderLifecycleOperation, error) {
	if len(raw) == 0 || len(raw) > maxOperationBytes || !json.Valid(raw) || duplicateKeys(raw) {
		return ProviderLifecycleOperation{}, ErrInvalid
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var op ProviderLifecycleOperation
	if dec.Decode(&op) != nil || dec.Decode(&struct{}{}) != io.EOF {
		return ProviderLifecycleOperation{}, ErrInvalid
	}
	canon, err := json.Marshal(op)
	if err != nil || !bytes.Equal(canon, raw) {
		return ProviderLifecycleOperation{}, ErrInvalid
	}
	return op, nil
}
func verifyOwnerOperation(op ProviderLifecycleOperation, trust OwnerTrust, now time.Time) bool {
	if trust.Revoked || op.KeyID != trust.KeyID || !op.valid(now) {
		return false
	}
	key, err := hex.DecodeString(trust.PublicKey)
	sig, err2 := hex.DecodeString(op.Signature)
	return err == nil && err2 == nil && ed25519.Verify(ed25519.PublicKey(key), []byte(op.Digest), sig)
}
func lowerHex(v string, bytes int) bool {
	if len(v) != bytes*2 {
		return false
	}
	_, err := hex.DecodeString(v)
	return err == nil && v == strings.ToLower(v)
}

type Snapshot struct {
	SchemaVersion string                             `json:"schema_version"`
	Version       uint64                             `json:"version"`
	CurrentID     string                             `json:"current_id"`
	Revisions     map[string]Installed               `json:"revisions"`
	Receipts      map[string]Receipt                 `json:"receipts"`
	Associations  map[string]UIAssociation           `json:"associations"`
	Registrations map[string]UIRegistration          `json:"registrations"`
	Prepared      map[string]PreparedLifecycleEffect `json:"prepared"`
	UX            UXState                            `json:"ux"`
}

// UXState is encrypted Controller-owned presentation state.  It deliberately
// contains only opaque identifiers and digest-bound facts: no provider output,
// credential, prompt, transport handle, or mutable active-turn state is ever
// represented here.  It is additive to the provider revision journal so a
// Controller restart preserves an accepted immutable selection.
type UXState struct {
	Selections map[string]UISelectionRevision `json:"selections"`
	Templates  []UITemplateSnapshot           `json:"templates"`
	Approvals  []UIApprovalSnapshot           `json:"approvals"`
}

type UISelectionRevision struct {
	RevisionID, BaseRevisionID, ProfileID, Operation, AssociationDigest string
	CreatedAt                                                           time.Time
}
type UITemplateSnapshot struct{ TemplateID, Version string }
type UIApprovalSnapshot struct {
	DecisionType, Status string
	ExpiresAt            time.Time
}
type Receipt struct {
	Action, PayloadDigest, ResultDigest string
	BaseVersion, ResultVersion          uint64
	IssuedAt, ExpiresAt                 time.Time
}

// PreparedLifecycleEffect is a bounded durable intent for owner-only effects
// which span the provider-revision and mesh journals. It is not an endpoint
// capability: every retry rechecks the signed operation and association.
type PreparedLifecycleEffect struct {
	Action, PayloadDigest string
	Association           UIAssociation
	IssuedAt, ExpiresAt   time.Time
}
type Installed struct {
	Bundle      Bundle                            `json:"bundle"`
	Trust       providerbridge.Ed25519TrustBundle `json:"trust"`
	Enabled     map[string]bool                   `json:"enabled"`
	InstalledAt time.Time                         `json:"installed_at"`
}

type Repository struct {
	mu     sync.Mutex
	path   string
	key    []byte
	closed bool
}

func NewRepository(path string, key []byte) (*Repository, error) {
	if path == "" || len(key) != 32 {
		return nil, ErrInvalid
	}
	r := &Repository{path: path, key: append([]byte(nil), key...)}
	if _, err := r.Load(context.Background()); err != nil {
		return nil, err
	}
	return r, nil
}
func (r *Repository) Close() error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for i := range r.key {
		r.key[i] = 0
	}
	r.key = nil
	r.closed = true
	return nil
}
func emptySnapshot() Snapshot {
	return Snapshot{SchemaVersion: RepositoryV1, Revisions: map[string]Installed{}, Receipts: map[string]Receipt{}, Associations: map[string]UIAssociation{}, Registrations: map[string]UIRegistration{}, Prepared: map[string]PreparedLifecycleEffect{}, UX: emptyUXState()}
}
func emptyUXState() UXState {
	return UXState{Selections: map[string]UISelectionRevision{}, Templates: []UITemplateSnapshot{}, Approvals: []UIApprovalSnapshot{}}
}
func (r *Repository) Load(ctx context.Context) (Snapshot, error) {
	if err := ctx.Err(); err != nil {
		return Snapshot{}, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return Snapshot{}, ErrUnavailable
	}
	return r.loadLocked()
}
func (r *Repository) loadLocked() (Snapshot, error) {
	raw, err := secureStateRead(r.path)
	if errors.Is(err, os.ErrNotExist) {
		return emptySnapshot(), nil
	}
	if err != nil {
		return Snapshot{}, ErrCorrupt
	}
	plain, err := r.open(raw)
	if err != nil {
		return Snapshot{}, ErrCorrupt
	}
	var s Snapshot
	dec := json.NewDecoder(bytes.NewReader(plain))
	dec.DisallowUnknownFields()
	if err = dec.Decode(&s); err != nil || dec.Decode(&struct{}{}) != io.EOF {
		return Snapshot{}, ErrCorrupt
	}
	// Existing encrypted journals predate prepared effects. A missing field is
	// the canonical empty intent map and is rewritten on the next CAS.
	if s.Prepared == nil {
		s.Prepared = map[string]PreparedLifecycleEffect{}
	}
	if s.Registrations == nil {
		s.Registrations = map[string]UIRegistration{}
	}
	// UX fields are additive.  Older encrypted journals have no presentation
	// state and therefore normalize to the canonical empty Controller state;
	// this never fabricates a selection, receipt, approval, or deployment fact.
	if s.UX.Selections == nil {
		s.UX.Selections = map[string]UISelectionRevision{}
	}
	if s.UX.Templates == nil {
		s.UX.Templates = []UITemplateSnapshot{}
	}
	if s.UX.Approvals == nil {
		s.UX.Approvals = []UIApprovalSnapshot{}
	}
	if validateSnapshot(s) != nil {
		return Snapshot{}, ErrCorrupt
	}
	return cloneSnapshot(s), nil
}
func (r *Repository) CompareAndSwap(ctx context.Context, old, next Snapshot) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if validateSnapshot(next) != nil {
		return ErrInvalid
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return ErrUnavailable
	}
	current, err := r.loadLocked()
	if err != nil {
		return err
	}
	if digestValue(current) != digestValue(old) {
		return ErrConflict
	}
	next.Version = old.Version + 1
	plain, err := json.Marshal(next)
	if err != nil {
		return ErrInvalid
	}
	sealed, err := r.seal(plain)
	if err != nil {
		return err
	}
	return atomicStateWrite(r.path, sealed)
}
func cloneSnapshot(s Snapshot) Snapshot {
	out := emptySnapshot()
	out.Version = s.Version
	out.CurrentID = s.CurrentID
	for k, v := range s.Revisions {
		v.Enabled = mapsCopy(v.Enabled)
		out.Revisions[k] = v
	}
	for k, v := range s.Receipts {
		out.Receipts[k] = v
	}
	for k, v := range s.Associations {
		out.Associations[k] = v
	}
	for k, v := range s.Registrations {
		out.Registrations[k] = v
	}
	for k, v := range s.Prepared {
		out.Prepared[k] = v
	}
	for k, v := range s.UX.Selections {
		out.UX.Selections[k] = v
	}
	out.UX.Templates = append(out.UX.Templates, s.UX.Templates...)
	out.UX.Approvals = append(out.UX.Approvals, s.UX.Approvals...)
	return out
}
func mapsCopy(in map[string]bool) map[string]bool {
	out := make(map[string]bool, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
func validateSnapshot(s Snapshot) error {
	if s.SchemaVersion != RepositoryV1 || s.Revisions == nil || s.Receipts == nil || s.Associations == nil || s.Registrations == nil || s.Prepared == nil || s.UX.Selections == nil || s.UX.Templates == nil || s.UX.Approvals == nil || len(s.Revisions) > maxRevisions || len(s.Receipts) > maxReceipts || len(s.Associations) > maxAssociations || len(s.Registrations) > maxAssociations || len(s.Prepared) > maxPreparedEffects || len(s.Receipts)+len(s.Prepared) > maxReceipts || len(s.UX.Selections) > maxUISelections || len(s.UX.Templates) > maxUISnapshots || len(s.UX.Approvals) > maxUISnapshots {
		return ErrInvalid
	}
	if s.CurrentID != "" {
		if _, ok := s.Revisions[s.CurrentID]; !ok {
			return ErrInvalid
		}
	}
	for id, v := range s.Revisions {
		if id != v.Bundle.RevisionID || v.InstalledAt.IsZero() || validateBundleShape(v.Bundle) != nil {
			return ErrInvalid
		}
		for _, p := range v.Bundle.Profiles {
			if _, ok := v.Enabled[p.Profile.ID]; !ok {
				return ErrInvalid
			}
		}
	}
	for nonce, receipt := range s.Receipts {
		if !safeID(nonce) || !(receipt.Action == "set-enabled" || validLifecycleAction(receipt.Action)) || !isDigest(receipt.PayloadDigest) || !isDigest(receipt.ResultDigest) || receipt.ResultVersion != receipt.BaseVersion+1 || (!receipt.IssuedAt.IsZero() && (!receipt.ExpiresAt.After(receipt.IssuedAt) || receipt.ExpiresAt.Sub(receipt.IssuedAt) > 5*time.Minute)) || (receipt.IssuedAt.IsZero() != receipt.ExpiresAt.IsZero()) {
			return ErrInvalid
		}
	}
	for key, association := range s.Associations {
		if key != associationKey(association.SessionID, association.ChannelID) || !association.valid(time.Unix(0, 0).UTC()) {
			return ErrInvalid
		}
	}
	for key, registration := range s.Registrations {
		if key != associationKey(registration.SessionID, registration.ChannelID) || !registration.valid(time.Unix(0, 0).UTC()) {
			return ErrInvalid
		}
	}
	preparedAssociations := make(map[string]struct{}, len(s.Prepared))
	for nonce, prepared := range s.Prepared {
		key := associationKey(prepared.Association.SessionID, prepared.Association.ChannelID)
		if !safeID(nonce) || (prepared.Action != "ui-revoke" && prepared.Action != "ui-rotate" && prepared.Action != "root-close") || !isDigest(prepared.PayloadDigest) || !prepared.Association.valid(time.Unix(0, 0).UTC()) || ((prepared.Action == "ui-rotate" || prepared.Action == "root-close") && prepared.Association.RootRunID != prepared.Association.RunID) || prepared.Association.Revoked || prepared.IssuedAt.IsZero() || !prepared.ExpiresAt.After(prepared.IssuedAt) || prepared.ExpiresAt.Sub(prepared.IssuedAt) > 5*time.Minute {
			return ErrInvalid
		}
		if _, receiptExists := s.Receipts[nonce]; receiptExists {
			return ErrInvalid
		}
		if _, duplicate := preparedAssociations[key]; duplicate {
			return ErrInvalid
		}
		preparedAssociations[key] = struct{}{}
	}
	for key, selection := range s.UX.Selections {
		if key != selection.RevisionID || !safeID(selection.RevisionID) || !safeID(selection.BaseRevisionID) || !safeID(selection.ProfileID) || !uiSelectionOperation(selection.Operation) || !isDigest(selection.AssociationDigest) || selection.CreatedAt.IsZero() {
			return ErrInvalid
		}
	}
	seenTemplates := map[string]struct{}{}
	for _, template := range s.UX.Templates {
		key := template.TemplateID + "\x00" + template.Version
		if !safeID(template.TemplateID) || !safeID(template.Version) {
			return ErrInvalid
		}
		if _, found := seenTemplates[key]; found {
			return ErrInvalid
		}
		seenTemplates[key] = struct{}{}
	}
	seenApprovals := map[string]struct{}{}
	for _, approval := range s.UX.Approvals {
		key := approval.DecisionType + "\x00" + approval.Status + "\x00" + approval.ExpiresAt.UTC().Format(time.RFC3339Nano)
		if !uiDecisionType(approval.DecisionType) || !uiApprovalStatus(approval.Status) || approval.ExpiresAt.IsZero() {
			return ErrInvalid
		}
		if _, found := seenApprovals[key]; found {
			return ErrInvalid
		}
		seenApprovals[key] = struct{}{}
	}
	return nil
}

func uiSelectionOperation(v string) bool {
	return v == "new-root" || v == "new-child" || v == "clean-fork" || v == "model-only-new-session"
}
func uiDecisionType(v string) bool {
	return v == "provider-switch" || v == "fanout-grant" || v == "cloud-disclosure" || v == "plugin-lifecycle" || v == "deployment"
}
func uiApprovalStatus(v string) bool {
	return v == "pending" || v == "approved" || v == "denied" || v == "revoked" || v == "expired"
}
func validateBundleShape(b Bundle) error {
	if b.SchemaVersion != BundleV1 || !safeID(b.BundleID) || !safeID(b.RevisionID) || !isDigest(b.TrustBundleDigest) || !isDigest(b.Digest) || b.Digest != sealedBundleDigest(b) || len(b.Profiles) == 0 || len(b.Profiles) > 16 {
		return ErrInvalid
	}
	return nil
}
func secureStateRead(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !safeStateFile(info) {
		return nil, ErrCorrupt
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	after, err := f.Stat()
	if err != nil || !safeStateFile(after) || !sameFile(info, after) || after.Size() < 1 || after.Size() > maxStateBytes {
		return nil, ErrCorrupt
	}
	out, err := io.ReadAll(io.LimitReader(f, maxStateBytes+1))
	if err != nil || len(out) == 0 || len(out) > maxStateBytes {
		return nil, ErrCorrupt
	}
	return out, nil
}
func safeStateFile(info os.FileInfo) bool {
	if info == nil || !info.Mode().IsRegular() || info.Mode()&^0600 != 0 {
		return false
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	return ok && st != nil && st.Nlink == 1 && st.Uid == uint32(os.Geteuid())
}
func (r *Repository) seal(plain []byte) ([]byte, error) {
	block, err := aes.NewCipher(r.key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plain, nil), nil
}
func (r *Repository) open(raw []byte) ([]byte, error) {
	block, err := aes.NewCipher(r.key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil || len(raw) < gcm.NonceSize() {
		return nil, ErrCorrupt
	}
	return gcm.Open(nil, raw[:gcm.NonceSize()], raw[gcm.NonceSize():], nil)
}
func atomicStateWrite(path string, raw []byte) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(raw)
	}
	if err == nil {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err = os.Rename(name, path); err != nil {
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

type Service struct {
	repo      *Repository
	authority OperationAuthorizer
	trust     TrustSource
	now       func() time.Time
}

func NewService(repo *Repository, authority OperationAuthorizer, trust TrustSource) (*Service, error) {
	if repo == nil || authority == nil || trust == nil {
		return nil, ErrInvalid
	}
	return &Service{repo: repo, authority: authority, trust: trust, now: time.Now}, nil
}
func (s *Service) Install(ctx context.Context, b Bundle, nonce, approval string, base uint64) (Installed, bool, error) {
	t, err := s.trust.Current(ctx, b.TrustBundleDigest)
	if err != nil || !safeID(nonce) || !safeID(approval) || validateBundle(b, t, s.now().UTC()) != nil {
		return Installed{}, false, ErrInvalid
	}
	now := s.now().UTC()
	op := Operation{SchemaVersion: "provider-revision-operation.v1", Action: "install", RevisionID: b.RevisionID, BundleDigest: b.Digest, TrustDigest: b.TrustBundleDigest, BaseVersion: base, ExpectedVersion: base + 1, Nonce: nonce, PayloadDigest: b.Digest, ApprovalID: approval, IssuedAt: now, ExpiresAt: now.Add(5 * time.Minute)}
	op.Seal()
	if !op.valid(now) || s.authority.Authorize(ctx, op) != nil {
		return Installed{}, false, ErrUnauthorized
	}
	for i := 0; i < 8; i++ {
		old, err := s.repo.Load(ctx)
		if err != nil {
			return Installed{}, false, err
		}
		if prior, ok := old.Receipts[nonce]; ok {
			if prior.Action != "install" || prior.PayloadDigest != b.Digest {
				return Installed{}, false, ErrReplay
			}
			v, ok := old.Revisions[b.RevisionID]
			if !ok {
				return Installed{}, false, ErrCorrupt
			}
			return v, true, nil
		}
		if old.Version != base {
			return Installed{}, false, ErrConflict
		}
		if len(old.Revisions) >= maxRevisions || lifecycleSlots(old, s.now().UTC()) >= lifecycleReceiptLimit("install") {
			return Installed{}, false, ErrUnavailable
		}
		if existing, ok := old.Revisions[b.RevisionID]; ok {
			if existing.Bundle.Digest != b.Digest {
				return Installed{}, false, ErrConflict
			}
			return Installed{}, false, ErrConflict
		}
		enabled := map[string]bool{}
		for _, p := range b.Profiles {
			enabled[p.Profile.ID] = false
		}
		next := cloneSnapshot(old)
		pruneExpiredLifecycleEntries(&next, s.now().UTC())
		v := Installed{Bundle: b, Trust: t, Enabled: enabled, InstalledAt: s.now().UTC()}
		next.Revisions[b.RevisionID] = v
		next.Receipts[nonce] = Receipt{Action: "install", PayloadDigest: b.Digest, ResultDigest: digestValue(v), BaseVersion: old.Version, ResultVersion: old.Version + 1, IssuedAt: op.IssuedAt, ExpiresAt: op.ExpiresAt}
		if err = s.repo.CompareAndSwap(ctx, old, next); errors.Is(err, ErrConflict) {
			continue
		} else if err != nil {
			return Installed{}, false, err
		}
		return v, false, nil
	}
	return Installed{}, false, ErrConflict
}
func (s *Service) SetEnabled(ctx context.Context, revision, profile string, enabled bool, nonce, approval string, base uint64) error {
	if !safeID(revision) || !safeID(profile) || !safeID(nonce) || !safeID(approval) {
		return ErrInvalid
	}
	digest := digestValue(struct {
		Revision, Profile string
		Enabled           bool
	}{revision, profile, enabled})
	for i := 0; i < 8; i++ {
		old, err := s.repo.Load(ctx)
		if err != nil {
			return err
		}
		if prior, ok := old.Receipts[nonce]; ok {
			if prior.Action != "set-enabled" || prior.PayloadDigest != digest || old.Version != prior.ResultVersion {
				return ErrReplay
			}
			return nil
		}
		if old.Version != base || lifecycleSlots(old, s.now().UTC()) >= lifecycleReceiptLimit("profile-enable") {
			return ErrConflict
		}
		// Candidate installation is deliberately non-activating.  The legacy
		// compatibility seam must therefore not be able to enable a profile on
		// an installed-but-not-current revision; only an explicit signed
		// activate operation selects the current revision first.
		if old.CurrentID != revision {
			return ErrConflict
		}
		v, ok := old.Revisions[revision]
		if !ok {
			return ErrUnavailable
		}
		found := false
		intent := false
		for _, p := range v.Bundle.Profiles {
			if p.Profile.ID == profile {
				found = true
				intent = p.ActivationIntent
			}
		}
		if !found || (enabled && !intent) {
			return ErrInvalid
		}
		trust, trustErr := s.trust.Current(ctx, v.Bundle.TrustBundleDigest)
		if trustErr != nil || validateBundle(v.Bundle, trust, s.now().UTC()) != nil {
			return ErrUnavailable
		}
		now := s.now().UTC()
		op := Operation{SchemaVersion: "provider-revision-operation.v1", Action: "set-enabled", RevisionID: revision, BundleDigest: v.Bundle.Digest, TrustDigest: v.Bundle.TrustBundleDigest, ProfileID: profile, ProfileRevision: v.Bundle.Profiles[0].Profile.Revision, BaseVersion: base, ExpectedVersion: base + 1, Nonce: nonce, PayloadDigest: digest, ApprovalID: approval, IssuedAt: now, ExpiresAt: now.Add(5 * time.Minute)}
		for _, p := range v.Bundle.Profiles {
			if p.Profile.ID == profile {
				op.ProfileRevision = p.Profile.Revision
			}
		}
		op.Seal()
		if !op.valid(now) || s.authority.Authorize(ctx, op) != nil {
			return ErrUnauthorized
		}
		next := cloneSnapshot(old)
		pruneExpiredLifecycleEntries(&next, s.now().UTC())
		v = next.Revisions[revision]
		v.Enabled[profile] = enabled
		next.Revisions[revision] = v
		next.Receipts[nonce] = Receipt{Action: "set-enabled", PayloadDigest: digest, ResultDigest: digestValue(v.Enabled), BaseVersion: old.Version, ResultVersion: old.Version + 1, IssuedAt: op.IssuedAt, ExpiresAt: op.ExpiresAt}
		if err = s.repo.CompareAndSwap(ctx, old, next); errors.Is(err, ErrConflict) {
			continue
		} else {
			return err
		}
	}
	return ErrConflict
}
func (s *Service) Active(ctx context.Context) (Installed, error) {
	snp, err := s.repo.Load(ctx)
	if err != nil {
		return Installed{}, err
	}
	if snp.CurrentID == "" {
		return Installed{}, ErrUnavailable
	}
	return snp.Revisions[snp.CurrentID], nil
}

// prevalidateUIRegistration fences a signed registration before the
// composition callback creates a root. The callback itself is retry-safe
// (RegisterRoot/MintUIEndpoint are exact replays), while this check prevents a
// stale owner approval from minting after the active revision moved.
func (s *Service) prevalidateUIRegistration(ctx context.Context, op ProviderLifecycleOperation) (Receipt, bool, error) {
	if s == nil || op.Action != "ui-register" || !op.valid(s.now().UTC()) {
		return Receipt{}, false, ErrUnauthorized
	}
	snapshot, err := s.repo.Load(ctx)
	if err != nil {
		return Receipt{}, false, err
	}
	if receipt, ok := snapshot.Receipts[op.Nonce]; ok {
		if receipt.Action != op.Action || receipt.PayloadDigest != op.Digest {
			return Receipt{}, false, ErrReplay
		}
		return receipt, true, nil
	}
	if snapshot.Version != op.BaseVersion || snapshot.CurrentID != op.BaseCurrentRevision || snapshot.CurrentID != op.RevisionID {
		return Receipt{}, false, ErrConflict
	}
	v, ok := snapshot.Revisions[op.RevisionID]
	if !ok || v.Bundle.Digest != op.BundleDigest || v.Bundle.TrustBundleDigest != op.TrustDigest {
		return Receipt{}, false, ErrUnavailable
	}
	key := associationKey(op.SessionID, op.ChannelID)
	if _, ok := snapshot.Associations[key]; ok {
		return Receipt{}, false, ErrConflict
	}
	if existing, ok := snapshot.Registrations[key]; ok && existing.RequestDigest != op.Digest {
		return Receipt{}, false, ErrConflict
	}
	return Receipt{}, false, nil
}

func registrationMatchesOperation(registration UIRegistration, op ProviderLifecycleOperation) bool {
	return registration.valid(op.IssuedAt) && registration.RequestNonce == op.Nonce && registration.RequestDigest == op.Digest && registration.SessionID == op.SessionID && registration.ChannelID == op.ChannelID && registration.RootRunID == op.RootRunID && registration.RunID == op.RunID && registration.MeshSessionID == op.MeshSessionID && registration.AttemptID == op.AttemptID && registration.PeerID == op.PeerID && registration.RevisionID == op.RevisionID
}

func (s *Service) applyUIRegistration(ctx context.Context, op ProviderLifecycleOperation, registration UIRegistration) (Receipt, bool, error) {
	if s == nil || !registrationMatchesOperation(registration, op) || !op.valid(s.now().UTC()) {
		return Receipt{}, false, ErrUnauthorized
	}
	for i := 0; i < 8; i++ {
		old, err := s.repo.Load(ctx)
		if err != nil {
			return Receipt{}, false, err
		}
		if receipt, ok := old.Receipts[op.Nonce]; ok {
			if receipt.Action != op.Action || receipt.PayloadDigest != op.Digest {
				return Receipt{}, false, ErrReplay
			}
			return receipt, true, nil
		}
		if old.Version != op.BaseVersion || old.CurrentID != op.BaseCurrentRevision || old.CurrentID != op.RevisionID {
			return Receipt{}, false, ErrConflict
		}
		current, ok := old.Revisions[op.RevisionID]
		if !ok || current.Bundle.Digest != op.BundleDigest || current.Bundle.TrustBundleDigest != op.TrustDigest {
			return Receipt{}, false, ErrUnavailable
		}
		next := cloneSnapshot(old)
		now := s.now().UTC()
		for key, pending := range next.Registrations {
			if !pending.ExpiresAt.After(now) {
				delete(next.Registrations, key)
			}
		}
		key := associationKey(op.SessionID, op.ChannelID)
		if _, exists := next.Associations[key]; exists || (next.Registrations[key].RequestDigest != "" && next.Registrations[key].RequestDigest != op.Digest) || len(next.Registrations) >= maxAssociations {
			return Receipt{}, false, ErrConflict
		}
		next.Registrations[key] = registration
		receipt := Receipt{Action: op.Action, PayloadDigest: op.Digest, ResultDigest: digestValue(registration), BaseVersion: old.Version, ResultVersion: old.Version + 1, IssuedAt: op.IssuedAt, ExpiresAt: op.ExpiresAt}
		next.Receipts[op.Nonce] = receipt
		if err = s.repo.CompareAndSwap(ctx, old, next); errors.Is(err, ErrConflict) {
			continue
		} else if err != nil {
			return Receipt{}, false, err
		}
		return receipt, false, nil
	}
	return Receipt{}, false, ErrConflict
}

// Registration returns a pending owner-authorized binding request. It is
// intentionally distinct from Association, so callers cannot treat it as UI
// authority before a second signed ui-bind operation commits.
func (s *Service) Registration(ctx context.Context, session, channel string) (UIRegistration, error) {
	if s == nil {
		return UIRegistration{}, ErrUnavailable
	}
	snapshot, err := s.repo.Load(ctx)
	if err != nil {
		return UIRegistration{}, err
	}
	registration, ok := snapshot.Registrations[associationKey(session, channel)]
	if !ok || !registration.valid(s.now().UTC()) || snapshot.CurrentID != registration.RevisionID {
		return UIRegistration{}, ErrUnavailable
	}
	return registration, nil
}

// RegistrationForBinding returns a pending registration together with the one
// current snapshot version a subsequent ui-bind must sign. A concurrent
// revision mutation invalidates that base at apply time; no caller can choose
// a historical version.
func (s *Service) RegistrationForBinding(ctx context.Context, session, channel string) (UIRegistration, uint64, error) {
	if s == nil {
		return UIRegistration{}, 0, ErrUnavailable
	}
	snapshot, err := s.repo.Load(ctx)
	if err != nil {
		return UIRegistration{}, 0, err
	}
	registration, ok := snapshot.Registrations[associationKey(session, channel)]
	if !ok || !registration.valid(s.now().UTC()) || snapshot.CurrentID != registration.RevisionID {
		return UIRegistration{}, 0, ErrUnavailable
	}
	return registration, snapshot.Version, nil
}

// applyVerified applies an already verified owner envelope. It is deliberately
// unexported: Dispatcher is the sole composition entrypoint.
func (s *Service) applyVerified(ctx context.Context, op ProviderLifecycleOperation, bundle *Bundle, confirmedRevoke *UIRevokeTarget, rotateArgs ...*UIRotateResult) (Receipt, bool, error) {
	if len(rotateArgs) > 1 {
		return Receipt{}, false, ErrUnauthorized
	}
	var confirmedRotate *UIRotateResult
	if len(rotateArgs) == 1 {
		confirmedRotate = rotateArgs[0]
	}
	if !op.valid(s.now().UTC()) {
		return Receipt{}, false, ErrUnauthorized
	}
	if op.Action == "ui-revoke" || op.Action == "root-close" {
		if confirmedRevoke == nil || confirmedRevoke.EndpointID != op.EndpointID || confirmedRevoke.Generation != op.EndpointGeneration {
			return Receipt{}, false, ErrUnauthorized
		}
	} else if confirmedRevoke != nil {
		return Receipt{}, false, ErrUnauthorized
	}
	if op.Action == "ui-rotate" {
		if confirmedRotate == nil {
			return Receipt{}, false, ErrUnauthorized
		}
	} else if confirmedRotate != nil {
		return Receipt{}, false, ErrUnauthorized
	}
	for i := 0; i < 8; i++ {
		old, err := s.repo.Load(ctx)
		if err != nil {
			return Receipt{}, false, err
		}
		if receipt, ok := old.Receipts[op.Nonce]; ok {
			if receipt.Action != op.Action || receipt.PayloadDigest != op.Digest {
				return Receipt{}, false, ErrReplay
			}
			if op.Action == "activate" && old.CurrentID != op.RevisionID {
				// A later activation changed the durable current pointer. The
				// historical receipt remains immutable audit evidence but cannot
				// be replayed as a successful current selection.
				return Receipt{}, false, ErrConflict
			}
			return receipt, true, nil
		}
		prepared, hasPrepared := old.Prepared[op.Nonce]
		preparedMatches := hasPrepared && prepared.Action == op.Action && prepared.PayloadDigest == op.Digest
		if op.Action == "activate" && preparedActivationFenced(old, op, s.now().UTC()) {
			return Receipt{}, false, ErrConflict
		}
		if lifecycleAssociationOperation(op.Action) && preparedAssociationFenced(old, op, preparedMatches, s.now().UTC()) {
			return Receipt{}, false, ErrConflict
		}
		if (op.Action == "ui-revoke" || op.Action == "ui-rotate" || op.Action == "root-close") && !preparedMatches {
			// Mesh effects are permitted only after a durable exact intent. This
			// makes a cross-journal crash retryable without accepting an arbitrary
			// stale lifecycle envelope.
			return Receipt{}, false, ErrConflict
		}
		if (old.Version != op.BaseVersion || old.CurrentID != op.BaseCurrentRevision) && !(preparedMatches && (op.Action == "ui-revoke" || op.Action == "ui-rotate" || op.Action == "root-close")) {
			return Receipt{}, false, ErrConflict
		}
		if !preparedMatches && lifecycleSlots(old, s.now().UTC()) >= lifecycleReceiptLimit(op.Action) {
			return Receipt{}, false, ErrConflict
		}
		next := cloneSnapshot(old)
		pruneExpiredLifecycleEntries(&next, s.now().UTC())
		var resultDigest string
		switch op.Action {
		case "install":
			if bundle == nil || bundle.Digest != op.BundleDigest || bundle.TrustBundleDigest != op.TrustDigest || bundle.RevisionID != op.RevisionID || len(next.Revisions) >= maxRevisions {
				return Receipt{}, false, ErrInvalid
			}
			trust, err := s.trust.Current(ctx, op.TrustDigest)
			if err != nil || validateBundle(*bundle, trust, s.now().UTC()) != nil {
				return Receipt{}, false, ErrUnavailable
			}
			if _, exists := next.Revisions[op.RevisionID]; exists {
				return Receipt{}, false, ErrConflict
			}
			enabled := map[string]bool{}
			for _, p := range bundle.Profiles {
				enabled[p.Profile.ID] = false
			}
			v := Installed{Bundle: *bundle, Trust: trust, Enabled: enabled, InstalledAt: s.now().UTC()}
			next.Revisions[op.RevisionID] = v
			resultDigest = digestValue(v)
		case "activate":
			v, ok := next.Revisions[op.RevisionID]
			if !ok || v.Bundle.Digest != op.BundleDigest || v.Bundle.TrustBundleDigest != op.TrustDigest {
				return Receipt{}, false, ErrUnavailable
			}
			trust, err := s.trust.Current(ctx, op.TrustDigest)
			if err != nil || validateBundle(v.Bundle, trust, s.now().UTC()) != nil {
				return Receipt{}, false, ErrUnavailable
			}
			next.CurrentID = op.RevisionID
			resultDigest = digestValue(v)
		case "profile-enable", "profile-disable":
			// Profile intent belongs to the selected revision.  A signed profile
			// operation may bind a real current base, but it must not use that
			// base to alter a different installed candidate.
			if next.CurrentID != op.RevisionID {
				return Receipt{}, false, ErrConflict
			}
			v, ok := next.Revisions[op.RevisionID]
			if !ok || v.Bundle.Digest != op.BundleDigest || v.Bundle.TrustBundleDigest != op.TrustDigest {
				return Receipt{}, false, ErrUnavailable
			}
			trust, err := s.trust.Current(ctx, op.TrustDigest)
			if err != nil || validateBundle(v.Bundle, trust, s.now().UTC()) != nil {
				return Receipt{}, false, ErrUnavailable
			}
			found := false
			intent := false
			for _, p := range v.Bundle.Profiles {
				if p.Profile.ID == op.ProfileID {
					found = p.Profile.Revision == op.ProfileRevision
					intent = p.ActivationIntent
				}
			}
			if !found || (op.Action == "profile-enable" && !intent) {
				return Receipt{}, false, ErrInvalid
			}
			v.Enabled[op.ProfileID] = op.Action == "profile-enable"
			next.Revisions[op.RevisionID] = v
			resultDigest = digestValue(v.Enabled)
		case "ui-bind":
			// Expired bindings cannot be used, so prune them only while making a
			// new binding. A signed revoke is still allowed to target an exact
			// expired binding until it is pruned, which preserves auditable
			// receipt semantics without allowing stale entries to exhaust slots.
			now := s.now().UTC()
			for key, association := range next.Associations {
				if association.Revoked || !association.ExpiresAt.After(now) {
					delete(next.Associations, key)
				}
			}
			if len(next.Associations) >= maxAssociations {
				return Receipt{}, false, ErrUnavailable
			}
			current, ok := next.Revisions[next.CurrentID]
			if !ok || current.Bundle.Digest != op.BundleDigest || current.Bundle.TrustBundleDigest != op.TrustDigest {
				return Receipt{}, false, ErrUnavailable
			}
			association := UIAssociation{SessionID: op.SessionID, ChannelID: op.ChannelID, RootRunID: op.RootRunID, RunID: op.RunID, MeshSessionID: op.MeshSessionID, AttemptID: op.AttemptID, PeerID: op.PeerID, EndpointID: op.EndpointID, EndpointGeneration: op.EndpointGeneration, RevisionID: op.RevisionID, ExpiresAt: op.EndpointExpiresAt}
			if !association.valid(now) || next.CurrentID != op.RevisionID {
				return Receipt{}, false, ErrInvalid
			}
			next.Associations[associationKey(association.SessionID, association.ChannelID)] = association
			resultDigest = digestValue(association)
		case "ui-revoke":
			association, err := validateUIRevoke(next, op)
			if err != nil {
				return Receipt{}, false, err
			}
			association.Revoked = true
			delete(next.Associations, associationKey(op.SessionID, op.ChannelID))
			resultDigest = digestValue(association)
		case "ui-rotate":
			association, err := validateUIRevoke(next, op)
			if err != nil || confirmedRotate == nil || !confirmedRotate.valid(s.now().UTC(), association) || next.CurrentID != op.RevisionID {
				return Receipt{}, false, ErrUnauthorized
			}
			association.EndpointID = confirmedRotate.EndpointID
			association.EndpointGeneration = confirmedRotate.Generation
			association.ExpiresAt = confirmedRotate.ExpiresAt
			if !association.valid(s.now().UTC()) {
				return Receipt{}, false, ErrInvalid
			}
			next.Associations[associationKey(association.SessionID, association.ChannelID)] = association
			resultDigest = digestValue(association)
		case "root-close":
			association, err := validateUIRevoke(next, op)
			if err != nil {
				return Receipt{}, false, err
			}
			association.Revoked = true
			delete(next.Associations, associationKey(op.SessionID, op.ChannelID))
			resultDigest = digestValue(association)
		}
		receipt := Receipt{Action: op.Action, PayloadDigest: op.Digest, ResultDigest: resultDigest, BaseVersion: old.Version, ResultVersion: old.Version + 1, IssuedAt: op.IssuedAt, ExpiresAt: op.ExpiresAt}
		next.Receipts[op.Nonce] = receipt
		delete(next.Prepared, op.Nonce)
		if err = s.repo.CompareAndSwap(ctx, old, next); errors.Is(err, ErrConflict) {
			continue
		} else if err != nil {
			return Receipt{}, false, err
		}
		return receipt, false, nil
	}
	return Receipt{}, false, ErrConflict
}

func lifecycleAssociationOperation(action string) bool {
	return action == "ui-bind" || action == "ui-revoke" || action == "ui-rotate" || action == "root-close"
}

func preparedAssociationFenced(snapshot Snapshot, op ProviderLifecycleOperation, allowOwn bool, now time.Time) bool {
	if !lifecycleAssociationOperation(op.Action) {
		return false
	}
	key := associationKey(op.SessionID, op.ChannelID)
	for nonce, prepared := range snapshot.Prepared {
		if !prepared.ExpiresAt.After(now) {
			continue
		}
		if associationKey(prepared.Association.SessionID, prepared.Association.ChannelID) == key && !(allowOwn && nonce == op.Nonce && prepared.Action == op.Action && prepared.PayloadDigest == op.Digest) {
			return true
		}
	}
	return false
}

func preparedActivationFenced(snapshot Snapshot, op ProviderLifecycleOperation, now time.Time) bool {
	for _, prepared := range snapshot.Prepared {
		if prepared.ExpiresAt.After(now) && prepared.Action == "ui-rotate" && prepared.Association.RevisionID != op.RevisionID {
			return true
		}
	}
	return false
}

func lifecycleReceiptLimit(action string) int {
	if action == "ui-revoke" || action == "root-close" {
		return maxReceipts
	}
	// Reserve a bounded shared pool for concurrent monotone revoke/close
	// recovery across independent UI associations; normal lifecycle churn never
	// consumes these slots.
	return maxReceipts - safetyReceiptSlots
}

func lifecycleSlots(snapshot Snapshot, now time.Time) int {
	used := 0
	for _, receipt := range snapshot.Receipts {
		if receipt.ExpiresAt.IsZero() || receipt.ExpiresAt.After(now) {
			used++
		}
	}
	for _, prepared := range snapshot.Prepared {
		if prepared.ExpiresAt.After(now) {
			used++
		}
	}
	return used
}

func pruneExpiredLifecycleEntries(snapshot *Snapshot, now time.Time) {
	if snapshot == nil {
		return
	}
	for nonce, receipt := range snapshot.Receipts {
		if !receipt.ExpiresAt.IsZero() && !receipt.ExpiresAt.After(now) {
			delete(snapshot.Receipts, nonce)
		}
	}
	for nonce, prepared := range snapshot.Prepared {
		if !prepared.ExpiresAt.After(now) {
			delete(snapshot.Prepared, nonce)
		}
	}
}

// prevalidateUIRevoke verifies the exact current state before the Dispatcher
// asks the mesh repository to revoke a capability. A matching receipt is a
// replay, but still returns the signed target so Dispatcher reasserts endpoint
// revocation before returning the idempotent receipt.
func (s *Service) prevalidateUIRevoke(ctx context.Context, op ProviderLifecycleOperation) (UIRevokeTarget, bool, error) {
	if s == nil || op.Action != "ui-revoke" || !op.valid(s.now().UTC()) {
		return UIRevokeTarget{}, false, ErrUnauthorized
	}
	snapshot, err := s.repo.Load(ctx)
	if err != nil {
		return UIRevokeTarget{}, false, err
	}
	target := UIRevokeTarget{EndpointID: op.EndpointID, Generation: op.EndpointGeneration}
	if receipt, ok := snapshot.Receipts[op.Nonce]; ok {
		if receipt.Action != op.Action || receipt.PayloadDigest != op.Digest {
			return UIRevokeTarget{}, false, ErrReplay
		}
		return target, true, nil
	}
	if snapshot.Version != op.BaseVersion || snapshot.CurrentID != op.BaseCurrentRevision {
		return UIRevokeTarget{}, false, ErrConflict
	}
	if preparedAssociationFenced(snapshot, op, false, s.now().UTC()) {
		return UIRevokeTarget{}, false, ErrConflict
	}
	if _, err := validateUIRevoke(snapshot, op); err != nil {
		return UIRevokeTarget{}, false, err
	}
	return target, false, nil
}

// prepareUIEffect first records the exact association selected by a signed
// revoke/rotate/close envelope. The subsequent mesh callback can therefore be
// retried after a crash or an unrelated provider-revision CAS without opening
// a stale-operation path. A prepared record is inert and bounded; it cannot be
// consumed by a different nonce or payload.
func (s *Service) prepareUIEffect(ctx context.Context, op ProviderLifecycleOperation) (UIRotateTarget, bool, error) {
	if s == nil || (op.Action != "ui-revoke" && op.Action != "ui-rotate" && op.Action != "root-close") || !op.valid(s.now().UTC()) {
		return UIRotateTarget{}, false, ErrUnauthorized
	}
	for i := 0; i < 8; i++ {
		snapshot, err := s.repo.Load(ctx)
		if err != nil {
			return UIRotateTarget{}, false, err
		}
		if receipt, ok := snapshot.Receipts[op.Nonce]; ok {
			if receipt.Action != op.Action || receipt.PayloadDigest != op.Digest {
				return UIRotateTarget{}, false, ErrReplay
			}
			return UIRotateTarget{}, true, nil
		}
		if prepared, ok := snapshot.Prepared[op.Nonce]; ok {
			if prepared.Action != op.Action || prepared.PayloadDigest != op.Digest || !prepared.IssuedAt.Equal(op.IssuedAt) || !prepared.ExpiresAt.Equal(op.ExpiresAt) {
				return UIRotateTarget{}, false, ErrReplay
			}
			association, validationErr := validateUIRevoke(snapshot, op)
			if validationErr != nil || digestValue(association) != digestValue(prepared.Association) {
				return UIRotateTarget{}, false, ErrConflict
			}
			if op.Action == "ui-rotate" && snapshot.CurrentID != op.RevisionID {
				return UIRotateTarget{}, false, ErrConflict
			}
			return UIRotateTarget{Association: association}, false, nil
		}
		if preparedAssociationFenced(snapshot, op, false, s.now().UTC()) {
			return UIRotateTarget{}, false, ErrConflict
		}
		if snapshot.Version != op.BaseVersion || snapshot.CurrentID != op.BaseCurrentRevision {
			return UIRotateTarget{}, false, ErrConflict
		}
		association, validationErr := validateUIRevoke(snapshot, op)
		if validationErr != nil || ((op.Action == "ui-rotate" || op.Action == "root-close") && association.RootRunID != association.RunID) {
			if validationErr != nil {
				return UIRotateTarget{}, false, validationErr
			}
			return UIRotateTarget{}, false, ErrUnauthorized
		}
		next := cloneSnapshot(snapshot)
		// Expired intents are inert journal records. Their callback may have
		// committed before a crash, but pruning executes nothing; a later freshly
		// signed recovery action must re-derive exact mesh state.
		pruneExpiredLifecycleEntries(&next, s.now().UTC())
		if len(next.Prepared) >= maxPreparedEffects || lifecycleSlots(next, s.now().UTC()) >= lifecycleReceiptLimit(op.Action) {
			return UIRotateTarget{}, false, ErrConflict
		}
		next.Prepared[op.Nonce] = PreparedLifecycleEffect{Action: op.Action, PayloadDigest: op.Digest, Association: association, IssuedAt: op.IssuedAt, ExpiresAt: op.ExpiresAt}
		if err = s.repo.CompareAndSwap(ctx, snapshot, next); errors.Is(err, ErrConflict) {
			continue
		} else if err != nil {
			return UIRotateTarget{}, false, err
		}
		return UIRotateTarget{Association: association}, false, nil
	}
	return UIRotateTarget{}, false, ErrConflict
}

// revalidatePreparedUIEffect is the last check before a mesh mutation. It
// closes the expiry and competing-CAS window between durable preparation and
// callback execution.
func (s *Service) revalidatePreparedUIEffect(ctx context.Context, op ProviderLifecycleOperation) error {
	if s == nil || !op.valid(s.now().UTC()) {
		return ErrUnauthorized
	}
	snapshot, err := s.repo.Load(ctx)
	if err != nil {
		return err
	}
	prepared, ok := snapshot.Prepared[op.Nonce]
	if !ok || prepared.Action != op.Action || prepared.PayloadDigest != op.Digest || !prepared.IssuedAt.Equal(op.IssuedAt) || !prepared.ExpiresAt.Equal(op.ExpiresAt) {
		return ErrConflict
	}
	association, err := validateUIRevoke(snapshot, op)
	if err != nil || digestValue(association) != digestValue(prepared.Association) {
		return ErrConflict
	}
	if op.Action == "ui-rotate" && snapshot.CurrentID != op.RevisionID {
		return ErrConflict
	}
	return nil
}

func validateUIRevoke(snapshot Snapshot, op ProviderLifecycleOperation) (UIAssociation, error) {
	association, ok := snapshot.Associations[associationKey(op.SessionID, op.ChannelID)]
	if !ok {
		return UIAssociation{}, ErrUnavailable
	}
	revision, ok := snapshot.Revisions[association.RevisionID]
	if !ok || association.Revoked || association.SessionID != op.SessionID || association.ChannelID != op.ChannelID || association.RevisionID != op.RevisionID || revision.Bundle.Digest != op.BundleDigest || revision.Bundle.TrustBundleDigest != op.TrustDigest || association.RootRunID != op.RootRunID || association.RunID != op.RunID || association.MeshSessionID != op.MeshSessionID || association.AttemptID != op.AttemptID || association.PeerID != op.PeerID || association.EndpointID != op.EndpointID || association.EndpointGeneration != op.EndpointGeneration || !association.ExpiresAt.Equal(op.EndpointExpiresAt) || digestValue(association) != op.AssociationDigest {
		return UIAssociation{}, ErrUnauthorized
	}
	return association, nil
}
func (s *Service) Association(ctx context.Context, session, channel string) (UIAssociation, error) {
	snapshot, err := s.repo.Load(ctx)
	if err != nil {
		return UIAssociation{}, err
	}
	a, ok := snapshot.Associations[associationKey(session, channel)]
	if !ok || a.Revoked || !a.ExpiresAt.After(s.now().UTC()) {
		return UIAssociation{}, ErrUnavailable
	}
	if snapshot.CurrentID != a.RevisionID {
		return UIAssociation{}, ErrUnavailable
	}
	return a, nil
}

// SelectUI creates an immutable Controller-owned session-selection revision.
// It intentionally does not update CurrentID or any provider transport: an
// active turn remains on its already sealed route.  Repeating the exact
// association/base/profile/operation combination returns the original durable
// revision after restart; changing any member creates a distinct immutable
// record rather than mutating the old one.
func (s *Service) SelectUI(ctx context.Context, association UIAssociation, profileID, operation, baseRevisionID string) (UISelectionRevision, bool, error) {
	if s == nil || !association.valid(s.now().UTC()) || !safeID(profileID) || !uiSelectionOperation(operation) || !safeID(baseRevisionID) {
		return UISelectionRevision{}, false, ErrInvalid
	}
	associationDigest := digestValue(association)
	digest := digestValue(struct {
		AssociationDigest, BaseRevisionID, ProfileID, Operation string
	}{associationDigest, baseRevisionID, profileID, operation})
	if !isDigest(digest) {
		return UISelectionRevision{}, false, ErrInvalid
	}
	revisionID := "ui-selection-" + digest[7:39]
	for i := 0; i < 8; i++ {
		old, err := s.repo.Load(ctx)
		if err != nil {
			return UISelectionRevision{}, false, err
		}
		if old.CurrentID != baseRevisionID {
			return UISelectionRevision{}, false, ErrConflict
		}
		stored, ok := old.Associations[associationKey(association.SessionID, association.ChannelID)]
		if !ok || stored.Revoked || digestValue(stored) != associationDigest || !stored.ExpiresAt.After(s.now().UTC()) {
			return UISelectionRevision{}, false, ErrUnavailable
		}
		// Revalidate the active trust-backed registry on every CAS attempt. A
		// concurrent owner profile disable or revision activation must never be
		// bypassed by eligibility observed before the winning journal snapshot.
		registry, installed, registryErr := s.Registry(ctx)
		if registryErr != nil || installed.Bundle.RevisionID != baseRevisionID {
			return UISelectionRevision{}, false, ErrUnavailable
		}
		resolution, resolveErr := registry.Resolve(ctx, profileID, s.now().UTC())
		if resolveErr != nil || !resolution.MeshSpawnEnabled() {
			return UISelectionRevision{}, false, ErrUnavailable
		}
		if prior, ok := old.UX.Selections[revisionID]; ok {
			if prior.AssociationDigest != associationDigest || prior.BaseRevisionID != baseRevisionID || prior.ProfileID != profileID || prior.Operation != operation {
				return UISelectionRevision{}, false, ErrReplay
			}
			return prior, true, nil
		}
		if len(old.UX.Selections) >= maxUISelections {
			return UISelectionRevision{}, false, ErrUnavailable
		}
		next := cloneSnapshot(old)
		selection := UISelectionRevision{RevisionID: revisionID, BaseRevisionID: baseRevisionID, ProfileID: profileID, Operation: operation, AssociationDigest: associationDigest, CreatedAt: s.now().UTC()}
		next.UX.Selections[revisionID] = selection
		if err = s.repo.CompareAndSwap(ctx, old, next); errors.Is(err, ErrConflict) {
			continue
		} else if err != nil {
			return UISelectionRevision{}, false, err
		}
		return selection, false, nil
	}
	return UISelectionRevision{}, false, ErrConflict
}

// UXSnapshot returns a fresh, bounded copy of durable UI metadata.  Empty
// template/approval lists are authoritative absence, not locally fabricated
// fixtures; deployment evidence has no default and must be reported as
// unavailable by the caller until a separate signed deployment source exists.
func (s *Service) UXSnapshot(ctx context.Context) (UXState, error) {
	if s == nil {
		return UXState{}, ErrUnavailable
	}
	snapshot, err := s.repo.Load(ctx)
	if err != nil || snapshot.CurrentID == "" {
		return UXState{}, ErrUnavailable
	}
	return cloneSnapshot(snapshot).UX, nil
}

type Dispatcher struct {
	Service           *Service
	Operations        OperationLoadConfig
	Bundle            LoadConfig
	now               func() time.Time
	VerifyUIBinding   func(context.Context, ProviderLifecycleOperation) error
	RegisterUIRoot    func(context.Context, ProviderLifecycleOperation) (UIRegistration, error)
	RevokeUIEndpoint  func(context.Context, string, uint64) error
	RotateUIEndpoint  func(context.Context, UIRotateTarget) (UIRotateResult, error)
	CloseRootEndpoint func(context.Context, UIRotateTarget) error
	// beforeLifecycleCallback is an unexported adversarial-test seam. Production
	// composition leaves it nil. The second revalidation below is intentional:
	// expiry may be crossed after durable preparation but before a callback can
	// touch the mesh journal.
	beforeLifecycleCallback func()
}

// ReadPending distinguishes an absent fixed inbox leaf from a malformed or
// unauthorized present operation. Absence is the sole steady-state no-op.
func (d *Dispatcher) ReadPending(ctx context.Context) (ProviderLifecycleOperation, bool, error) {
	if d == nil {
		return ProviderLifecycleOperation{}, false, ErrUnavailable
	}
	if _, err := os.Lstat(filepath.Join(d.Operations.RootPath, d.Operations.OperationLeaf)); errors.Is(err, os.ErrNotExist) {
		return ProviderLifecycleOperation{}, false, nil
	} else if err != nil {
		return ProviderLifecycleOperation{}, false, ErrUnavailable
	}
	now := time.Now
	if d.now != nil {
		now = d.now
	}
	op, err := LoadLifecycleOperation(d.Operations, now().UTC())
	return op, err == nil, err
}

func (d *Dispatcher) Dispatch(ctx context.Context) (Receipt, bool, error) {
	if d == nil || d.Service == nil {
		return Receipt{}, false, ErrUnavailable
	}
	now := time.Now
	if d.now != nil {
		now = d.now
	}
	op, err := LoadLifecycleOperation(d.Operations, now().UTC())
	if err != nil {
		return Receipt{}, false, err
	}
	var bundle *Bundle
	if op.Action == "install" {
		b, _, err := Load(d.Bundle, now().UTC())
		if err != nil {
			return Receipt{}, false, err
		}
		bundle = &b
		if b.Digest != op.BundleDigest || b.TrustBundleDigest != op.TrustDigest {
			return Receipt{}, false, ErrUnauthorized
		}
	}
	return d.dispatchVerified(ctx, op, bundle)
}

// dispatchVerified is split from fixed-leaf loading so its prevalidation and
// endpoint-revoke ordering can be adversarially tested without an artifact
// loader. Dispatch remains the only exported production entrypoint.
func (d *Dispatcher) dispatchVerified(ctx context.Context, op ProviderLifecycleOperation, bundle *Bundle) (Receipt, bool, error) {
	if d == nil || d.Service == nil {
		return Receipt{}, false, ErrUnavailable
	}
	if op.Action == "ui-bind" && (d.VerifyUIBinding == nil || d.VerifyUIBinding(ctx, op) != nil) {
		return Receipt{}, false, ErrUnauthorized
	}
	if op.Action == "ui-register" {
		if d.RegisterUIRoot == nil {
			return Receipt{}, false, ErrUnavailable
		}
		if receipt, replay, err := d.Service.prevalidateUIRegistration(ctx, op); err != nil || replay {
			return receipt, replay, err
		}
		registration, err := d.RegisterUIRoot(ctx, op)
		if err != nil {
			return Receipt{}, false, ErrUnavailable
		}
		return d.Service.applyUIRegistration(ctx, op, registration)
	}
	var confirmedRevoke *UIRevokeTarget
	var confirmedRotate *UIRotateResult
	if op.Action == "ui-revoke" {
		if d.RevokeUIEndpoint == nil {
			return Receipt{}, false, ErrUnavailable
		}
		target, replay, err := d.Service.prepareUIEffect(ctx, op)
		if err != nil {
			return Receipt{}, false, err
		}
		if replay {
			snapshot, loadErr := d.Service.repo.Load(ctx)
			if loadErr != nil {
				return Receipt{}, false, loadErr
			}
			return snapshot.Receipts[op.Nonce], true, nil
		}
		if err := d.revalidateBeforeLifecycleCallback(ctx, op); err != nil {
			return Receipt{}, false, err
		}
		if err := d.RevokeUIEndpoint(ctx, target.Association.EndpointID, target.Association.EndpointGeneration); err != nil {
			return Receipt{}, false, ErrUnavailable
		}
		confirmedRevoke = &UIRevokeTarget{EndpointID: target.Association.EndpointID, Generation: target.Association.EndpointGeneration}
	}
	if op.Action == "ui-rotate" {
		target, replay, err := d.Service.prepareUIEffect(ctx, op)
		if err != nil {
			return Receipt{}, false, err
		}
		if replay {
			snapshot, loadErr := d.Service.repo.Load(ctx)
			if loadErr != nil {
				return Receipt{}, false, loadErr
			}
			return snapshot.Receipts[op.Nonce], true, nil
		}
		if d.RotateUIEndpoint == nil {
			return Receipt{}, false, ErrUnavailable
		}
		if err := d.revalidateBeforeLifecycleCallback(ctx, op); err != nil {
			return Receipt{}, false, err
		}
		result, err := d.RotateUIEndpoint(ctx, target)
		if err != nil {
			return Receipt{}, false, ErrUnavailable
		}
		confirmedRotate = &result
	}
	if op.Action == "root-close" {
		target, replay, err := d.Service.prepareUIEffect(ctx, op)
		if err != nil {
			return Receipt{}, false, err
		}
		if replay {
			snapshot, loadErr := d.Service.repo.Load(ctx)
			if loadErr != nil {
				return Receipt{}, false, loadErr
			}
			return snapshot.Receipts[op.Nonce], true, nil
		}
		if err := d.revalidateBeforeLifecycleCallback(ctx, op); err != nil {
			return Receipt{}, false, err
		}
		if d.CloseRootEndpoint == nil || d.CloseRootEndpoint(ctx, target) != nil {
			return Receipt{}, false, ErrUnavailable
		}
		confirmedRevoke = &UIRevokeTarget{EndpointID: target.Association.EndpointID, Generation: target.Association.EndpointGeneration}
	}
	return d.Service.applyVerified(ctx, op, bundle, confirmedRevoke, confirmedRotate)
}

func (d *Dispatcher) revalidateBeforeLifecycleCallback(ctx context.Context, op ProviderLifecycleOperation) error {
	if err := d.Service.revalidatePreparedUIEffect(ctx, op); err != nil {
		return err
	}
	if d.beforeLifecycleCallback != nil {
		d.beforeLifecycleCallback()
	}
	return d.Service.revalidatePreparedUIEffect(ctx, op)
}
func (s *Service) Registry(ctx context.Context) (*providerbridge.Registry, Installed, error) {
	v, err := s.Active(ctx)
	if err != nil {
		return nil, Installed{}, err
	}
	trust, err := s.trust.Current(ctx, v.Bundle.TrustBundleDigest)
	if err != nil || validateBundle(v.Bundle, trust, s.now().UTC()) != nil {
		return nil, Installed{}, ErrUnavailable
	}
	v.Trust = trust
	profiles := make([]providerbridge.Profile, 0, len(v.Bundle.Profiles))
	limits := map[string]providerbridge.ExecutionLimits{}
	mappings := make([]providerbridge.Mapping, 0, len(v.Bundle.Profiles))
	evidence := make([]providerbridge.ProviderEvidenceRecord, 0, len(v.Bundle.Profiles))
	compat := make([]providerbridge.CompatibilityRecord, 0, len(v.Bundle.Profiles))
	for _, entry := range v.Bundle.Profiles {
		p := entry.Profile.bridge()
		p.MeshSpawnEnabled = v.Enabled[p.ID]
		profiles = append(profiles, p)
		limits[p.ID] = entry.Limits
		mappings = append(mappings, entry.Mapping)
		evidence = append(evidence, entry.Evidence)
		compat = append(compat, entry.Compatibility)
	}
	verifier, err := v.Trust.Verifier()
	if err != nil {
		return nil, Installed{}, ErrCorrupt
	}
	registry, err := providerbridge.NewRegistryWithCompatibility(profiles, limits, mappings, evidence, compat, v.Trust.TrustRegistry(), verifier)
	if err != nil {
		return nil, Installed{}, ErrCorrupt
	}
	return registry, v, nil
}

func duplicateKeys(raw []byte) bool {
	var walk func(*json.Decoder) bool
	walk = func(dec *json.Decoder) bool {
		tok, err := dec.Token()
		if err != nil {
			return true
		}
		if d, ok := tok.(json.Delim); ok && d == '{' {
			seen := map[string]bool{}
			for dec.More() {
				k, err := dec.Token()
				if err != nil {
					return true
				}
				key, ok := k.(string)
				if !ok || seen[key] {
					return true
				}
				seen[key] = true
				if walk(dec) {
					return true
				}
			}
			_, err = dec.Token()
			return err != nil
		}
		if d, ok := tok.(json.Delim); ok && d == '[' {
			for dec.More() {
				if walk(dec) {
					return true
				}
			}
			_, err = dec.Token()
			return err != nil
		}
		return false
	}
	return walk(json.NewDecoder(bytes.NewReader(raw)))
}

// Profiles returns a deterministic, metadata-only view used by composition.
func (v Installed) Profiles() []providerbridge.Profile {
	out := make([]providerbridge.Profile, 0, len(v.Bundle.Profiles))
	for _, entry := range v.Bundle.Profiles {
		p := entry.Profile.bridge()
		p.MeshSpawnEnabled = v.Enabled[p.ID]
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
