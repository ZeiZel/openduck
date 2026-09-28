// Package providercatalog builds disabled provider release material from a
// verified import.  It is deliberately an offline compiler: it has no
// provider process, credentials, network, owner key, or activation surface.
package providercatalog

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"path"
	"sort"
	"time"

	"openduck/internal/macosrelease"
	"openduck/internal/providerbridge"
	"openduck/internal/providerrevision"
	"openduck/internal/providertransport"
	"openduck/internal/qwenclosure"
	"openduck/internal/releasecatalog"
)

var ErrInvalid = errors.New("provider catalog: invalid input")

const (
	MaterialV1       = "openduck-provider-catalog-material.v1"
	SigningRequestV1 = "openduck-provider-evidence-signing-request.v1"
)

// Import is imported, previously verified content for exactly one known
// provider.  The binary identity must come from the trusted importer; this
// package validates its byte digest but deliberately cannot derive CDHash.
type Import struct {
	Provider                         string
	Compatibility, Evidence, Limits  []byte
	Daemon, HostBinary, HostIdentity []byte
	HostClosure                      map[string][]byte
}

type GenerateInput struct {
	BundleID, RevisionID string
	Imports              []Import
}

// Material is portable, canonical, non-secret handoff data.  It is kept out
// of the stage catalog; FinalizeEvidence consumes it together with the actual
// approvals and trust bundle to make provider-bundle/provider-trust leaves.
type Material struct {
	SchemaVersion string         `json:"schema_version"`
	BundleID      string         `json:"bundle_id"`
	RevisionID    string         `json:"revision_id"`
	Providers     []MaterialItem `json:"providers"`
}
type MaterialItem struct {
	Provider      string                                `json:"provider"`
	Compatibility providerbridge.CompatibilityRecord    `json:"compatibility"`
	Evidence      providerbridge.ProviderEvidenceRecord `json:"evidence"`
	Limits        providerbridge.ExecutionLimits        `json:"limits"`
}

type SigningRequest struct {
	SchemaVersion   string    `json:"schema_version"`
	Role            string    `json:"role"`
	Provider        string    `json:"provider"`
	ProfileID       string    `json:"profile_id"`
	ProfileRevision string    `json:"profile_revision"`
	EvidenceDigest  string    `json:"evidence_digest"`
	FreshUntil      time.Time `json:"fresh_until"`
}

type GenerateOutput struct {
	Artifacts map[string][]byte
	Material  Material
	Requests  []SigningRequest
}

// Generate converts real compatibility/evidence/limits inputs into the
// canonical disabled catalog leaves.  It never calls PinnedMappings and it
// cannot construct an active descriptor because no observed binding is
// representable in Import.
func Generate(in GenerateInput) (GenerateOutput, error) {
	if !safeID(in.BundleID) || !safeID(in.RevisionID) || len(in.Imports) == 0 || len(in.Imports) > 5 {
		return GenerateOutput{}, ErrInvalid
	}
	out := GenerateOutput{Artifacts: map[string][]byte{}, Material: Material{SchemaVersion: MaterialV1, BundleID: in.BundleID, RevisionID: in.RevisionID}}
	seen := map[string]bool{}
	for _, imported := range in.Imports {
		if seen[imported.Provider] {
			return GenerateOutput{}, ErrInvalid
		}
		seen[imported.Provider] = true
		item, artifacts, request, err := generateOne(imported)
		if err != nil {
			return GenerateOutput{}, ErrInvalid
		}
		for name, value := range artifacts {
			out.Artifacts[name] = value
		}
		out.Material.Providers = append(out.Material.Providers, item)
		out.Requests = append(out.Requests,
			SigningRequest{SchemaVersion: request.SchemaVersion, Role: "technical", Provider: request.Provider, ProfileID: request.ProfileID, ProfileRevision: request.ProfileRevision, EvidenceDigest: request.EvidenceDigest, FreshUntil: request.FreshUntil},
			SigningRequest{SchemaVersion: request.SchemaVersion, Role: "security", Provider: request.Provider, ProfileID: request.ProfileID, ProfileRevision: request.ProfileRevision, EvidenceDigest: request.EvidenceDigest, FreshUntil: request.FreshUntil},
		)
	}
	sort.Slice(out.Material.Providers, func(i, j int) bool { return out.Material.Providers[i].Provider < out.Material.Providers[j].Provider })
	sort.Slice(out.Requests, func(i, j int) bool {
		if out.Requests[i].ProfileID == out.Requests[j].ProfileID {
			return out.Requests[i].Role < out.Requests[j].Role
		}
		return out.Requests[i].ProfileID < out.Requests[j].ProfileID
	})
	if _, err := json.Marshal(out.Material); err != nil {
		return GenerateOutput{}, ErrInvalid
	}
	return out, nil
}

func generateOne(imported Import) (MaterialItem, map[string][]byte, SigningRequest, error) {
	compat, err := providerbridge.DecodeCompatibilityRecord(imported.Compatibility)
	if err != nil || compat.Maturity != providerbridge.CompatibilityPinned {
		return MaterialItem{}, nil, SigningRequest{}, ErrInvalid
	}
	evidence, err := providerbridge.DecodeProviderEvidenceRecord(imported.Evidence)
	if err != nil || len(evidence.Approvals) != 0 || !providerbridge.EvidenceMatchesCompatibility(evidence, compat) {
		return MaterialItem{}, nil, SigningRequest{}, ErrInvalid
	}
	limits, err := decodeLimits(imported.Limits)
	if err != nil {
		return MaterialItem{}, nil, SigningRequest{}, ErrInvalid
	}
	mapping, err := providerbridge.MappingFromCompatibility(compat)
	if err != nil {
		return MaterialItem{}, nil, SigningRequest{}, ErrInvalid
	}
	entries := releasecatalog.Entries()
	var runtime, topology, plugin releasecatalog.Entry
	for _, entry := range entries {
		if entry.Provider != imported.Provider || entry.ProfileID != compat.ProfileID {
			continue
		}
		switch entry.Type {
		case "provider_runtime":
			runtime = entry
		case "provider_topology":
			topology = entry
		case "provider_plugin":
			plugin = entry
		}
	}
	if runtime.Path == "" || topology.Path == "" || len(imported.Daemon) == 0 {
		return MaterialItem{}, nil, SigningRequest{}, ErrInvalid
	}
	if string(compat.Provider) != imported.Provider || runtime.ProfileRevision != compat.ProfileRevision || topology.ProfileRevision != compat.ProfileRevision {
		return MaterialItem{}, nil, SigningRequest{}, ErrInvalid
	}
	d := providertransport.InactiveDescriptor{Provider: imported.Provider, ProfileID: compat.ProfileID, ProfileRevision: compat.ProfileRevision, MappingDigest: mapping.Digest, RuntimeDigest: mapping.RuntimeDigest, ProtocolDigest: mapping.ProtocolDigest, Audience: "mesh"}
	if d.Seal() != nil {
		return MaterialItem{}, nil, SigningRequest{}, ErrInvalid
	}
	dRaw, _ := json.Marshal(d)
	artifacts := map[string][]byte{runtime.Path: dRaw}
	for _, entry := range entries {
		if entry.Provider == imported.Provider && entry.Type == "provider_daemon" && entry.ProfileID == compat.ProfileID {
			artifacts[entry.Path] = append([]byte(nil), imported.Daemon...)
		}
	}
	if len(plugin.Outputs) != 0 {
		raw, e := releasecatalog.CanonicalPluginMetadata(plugin)
		if e != nil {
			return MaterialItem{}, nil, SigningRequest{}, ErrInvalid
		}
		artifacts[plugin.Path] = raw
	}
	var identity *releasecatalog.ProviderHostIdentity
	if imported.Provider == "deepseek" {
		if len(imported.HostBinary) != 0 || len(imported.HostIdentity) != 0 {
			return MaterialItem{}, nil, SigningRequest{}, ErrInvalid
		}
	} else {
		parsed, e := releasecatalog.DecodeProviderHostIdentity(imported.HostIdentity)
		if e != nil || len(imported.HostBinary) == 0 {
			return MaterialItem{}, nil, SigningRequest{}, ErrInvalid
		}
		sum := sha256.Sum256(imported.HostBinary)
		if parsed.Provider != imported.Provider || parsed.ArtifactDigest != "sha256:"+hex.EncodeToString(sum[:]) {
			return MaterialItem{}, nil, SigningRequest{}, ErrInvalid
		}
		identity = &parsed
		for _, entry := range entries {
			if entry.Provider != imported.Provider || entry.ProfileID != compat.ProfileID {
				continue
			}
			if entry.Type == "provider_host_runtime" {
				artifacts[entry.Path] = append([]byte(nil), imported.HostBinary...)
			}
			if entry.Type == "provider_host_identity" {
				artifacts[entry.Path] = append([]byte(nil), imported.HostIdentity...)
			}
			if entry.Type == "provider_host_closure" {
				closure := imported.HostClosure[path.Base(entry.Path)]
				if len(closure) == 0 {
					return MaterialItem{}, nil, SigningRequest{}, ErrInvalid
				}
				artifacts[entry.Path] = append([]byte(nil), closure...)
			}
		}
		if imported.Provider == "qwen" {
			manifestRaw := imported.HostClosure["qwen-closure.sha256"]
			archive := imported.HostClosure["qwen-code-darwin-arm64.tar.gz"]
			manifest, manifestErr := qwenclosure.Decode(manifestRaw)
			if manifestErr != nil || providerbridge.DigestBytes(archive) != manifest.ArchiveDigest || providerbridge.DigestBytes(imported.HostIdentity) != manifest.HostIdentityDigest || manifest.NodeDigest != identity.ArtifactDigest || qwenclosure.ImageIdentityForCDHash(manifest.NodeCDHash) != identity.ImageIdentity || manifest.NodeTeamID != identity.TeamID {
				return MaterialItem{}, nil, SigningRequest{}, ErrInvalid
			}
		}
	}
	topologyRaw, e := releasecatalog.CanonicalProviderTopologyFromIdentity(topology, identity)
	if e != nil {
		return MaterialItem{}, nil, SigningRequest{}, ErrInvalid
	}
	artifacts[topology.Path] = topologyRaw
	return MaterialItem{Provider: imported.Provider, Compatibility: compat, Evidence: evidence, Limits: limits}, artifacts, SigningRequest{SchemaVersion: SigningRequestV1, Provider: imported.Provider, ProfileID: compat.ProfileID, ProfileRevision: compat.ProfileRevision, EvidenceDigest: evidence.Digest, FreshUntil: evidence.FreshUntil.UTC()}, nil
}

// FinalizeEvidence verifies the independently trusted technical and security
// approvals, builds a disabled Provider Bundle, and validates the final
// catalog payload as the release packager will.  Evidence trust is distinct
// from providerrevision.OwnerTrust/lifecycle activation authority.
func FinalizeEvidence(material Material, trustRaw []byte, approved map[string][]byte, now time.Time, existing map[string][]byte) (map[string][]byte, error) {
	if now.IsZero() || material.SchemaVersion != MaterialV1 || !safeID(material.BundleID) || !safeID(material.RevisionID) || len(material.Providers) == 0 {
		return nil, ErrInvalid
	}
	trust, err := providerbridge.DecodeEd25519TrustBundle(trustRaw)
	if err != nil {
		return nil, ErrInvalid
	}
	verifier, err := trust.Verifier()
	if err != nil {
		return nil, ErrInvalid
	}
	bundle := providerrevision.Bundle{SchemaVersion: providerrevision.BundleV1, BundleID: material.BundleID, RevisionID: material.RevisionID, TrustBundleDigest: providerbridge.DigestBytes(trustRaw)}
	last := ""
	for _, item := range material.Providers {
		if item.Provider <= last || item.Compatibility.ProfileID == "" || string(item.Compatibility.Provider) != item.Provider || item.Evidence.ProfileID != item.Compatibility.ProfileID || item.Evidence.ProfileRevision != item.Compatibility.ProfileRevision || item.Evidence.Digest == "" {
			return nil, ErrInvalid
		}
		last = item.Provider
		raw, found := approved[item.Compatibility.ProfileID]
		if !found {
			return nil, ErrInvalid
		}
		evidence, e := providerbridge.DecodeProviderEvidenceRecord(raw)
		if e != nil || evidence.Digest != item.Evidence.Digest || !providerbridge.EvidenceMatchesCompatibility(evidence, item.Compatibility) || providerbridge.VerifyEvidence(evidence, trust.TrustRegistry(), verifier, now.UTC()) != nil {
			return nil, ErrInvalid
		}
		mapping, e := providerbridge.MappingFromCompatibility(item.Compatibility)
		if e != nil {
			return nil, ErrInvalid
		}
		limitsDigest, e := item.Limits.Digest()
		if e != nil {
			return nil, ErrInvalid
		}
		profile := providerrevision.ProfileDTO{ID: item.Compatibility.ProfileID, Provider: item.Compatibility.Provider, Model: item.Compatibility.Model, RuntimeKind: runtimeKind(item.Compatibility.ProfileID), AuthModality: item.Compatibility.AuthModality, LocalOnly: item.Compatibility.ProfileID == providerbridge.ProfileQwenLocalPD, ExecutionLimitsDigest: limitsDigest, MappingDigest: mapping.Digest, ProviderEvidenceDigest: evidence.Digest, Revision: item.Compatibility.ProfileRevision, Status: providerbridge.StatusDisabled}
		bundle.Profiles = append(bundle.Profiles, providerrevision.ProfileBundle{Profile: profile, Limits: item.Limits, Mapping: mapping, Compatibility: item.Compatibility, Evidence: evidence, ActivationIntent: false})
	}
	if bundle.Seal() != nil || providerrevision.ValidateBundle(bundle, trust, now.UTC()) != nil {
		return nil, ErrInvalid
	}
	bundleRaw, _ := json.Marshal(bundle)
	out := make(map[string][]byte, len(existing)+2)
	for p, b := range existing {
		out[p] = append([]byte(nil), b...)
	}
	if _, exists := out["provider-bundle.json"]; exists {
		return nil, ErrInvalid
	}
	if _, exists := out["provider-trust.json"]; exists {
		return nil, ErrInvalid
	}
	out["provider-bundle.json"] = bundleRaw
	out["provider-trust.json"] = append([]byte(nil), trustRaw...)
	if err := macosReleaseValidate(out, now.UTC()); err != nil {
		return nil, ErrInvalid
	}
	return out, nil
}

// Kept behind a tiny wrapper so this package's caller contract remains clear.
func macosReleaseValidate(payloads map[string][]byte, now time.Time) error {
	return macosrelease.ValidateCatalogPayloads(payloads, now)
}

func decodeLimits(raw []byte) (providerbridge.ExecutionLimits, error) {
	var value providerbridge.ExecutionLimits
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if len(raw) == 0 || dec.Decode(&value) != nil || dec.Decode(&struct{}{}) == nil || value.Validate() != nil {
		return providerbridge.ExecutionLimits{}, ErrInvalid
	}
	canonical, _ := json.Marshal(value)
	if !bytes.Equal(raw, canonical) {
		return providerbridge.ExecutionLimits{}, ErrInvalid
	}
	return value, nil
}

func runtimeKind(profile string) string {
	for _, p := range providerbridge.DeclaredProfiles() {
		if p.ID == profile {
			return p.RuntimeKind
		}
	}
	return ""
}
func safeID(s string) bool {
	if len(s) == 0 || len(s) > 160 {
		return false
	}
	for _, r := range s {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || bytes.ContainsRune([]byte("._:-"), r)) {
			return false
		}
	}
	return true
}
