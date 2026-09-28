package providerbridge

import (
	"context"
	"errors"
	"sort"
	"time"
)

// Registry is a read-only bridge directory. It provides stable profile and
// mapping semantics for a future `mesh.ProfileDirectory` composition adapter.
type Registry struct {
	profiles      map[string]Profile
	limits        map[string]ExecutionLimits
	mappings      map[string]Mapping
	evidence      map[string]ProviderEvidenceRecord
	compatibility map[string]CompatibilityRecord
	trust         TrustRegistry
	verifier      SignatureVerifier
}

func NewRegistry(profiles []Profile, limits map[string]ExecutionLimits, mappings []Mapping, evidence []ProviderEvidenceRecord, trust TrustRegistry, verifier SignatureVerifier) (*Registry, error) {
	return newRegistry(profiles, limits, mappings, evidence, nil, trust, verifier)
}

// NewRegistryWithCompatibility is the production construction path. It binds
// each mapping to the exact canonical record it was derived from.
func NewRegistryWithCompatibility(profiles []Profile, limits map[string]ExecutionLimits, mappings []Mapping, evidence []ProviderEvidenceRecord, compatibility []CompatibilityRecord, trust TrustRegistry, verifier SignatureVerifier) (*Registry, error) {
	return newRegistry(profiles, limits, mappings, evidence, compatibility, trust, verifier)
}

func newRegistry(profiles []Profile, limits map[string]ExecutionLimits, mappings []Mapping, evidence []ProviderEvidenceRecord, compatibility []CompatibilityRecord, trust TrustRegistry, verifier SignatureVerifier) (*Registry, error) {
	r := &Registry{profiles: map[string]Profile{}, limits: map[string]ExecutionLimits{}, mappings: map[string]Mapping{}, evidence: map[string]ProviderEvidenceRecord{}, compatibility: map[string]CompatibilityRecord{}, trust: cloneTrust(trust), verifier: verifier}
	for _, profile := range profiles {
		if !validProfileIdentity(profile) || r.profiles[profile.ID].ID != "" {
			return nil, ErrUnknownProfile
		}
		if profile.MeshSpawnEnabled && !profile.LocalOnly && profile.AccountRef == "" {
			return nil, ErrProfileIncompatible
		}
		r.profiles[profile.ID] = profile
	}
	for id, limit := range limits {
		if _, found := r.profiles[id]; !found || !finite(limit) {
			return nil, ErrLimitsMissing
		}
		r.limits[id] = limit
	}
	for _, mapping := range mappings {
		if err := mapping.Validate(); err != nil {
			return nil, err
		}
		profile, found := r.profiles[mapping.ProfileID]
		if !found || profile.Provider != mapping.Provider || r.mappings[mapping.ProfileID].ProfileID != "" {
			return nil, ErrMappingMissing
		}
		r.mappings[mapping.ProfileID] = cloneMapping(mapping)
	}
	for _, record := range evidence {
		profile, found := r.profiles[record.ProfileID]
		if !found || profile.Provider != record.Provider || profile.AuthModality != record.AuthModality || r.evidence[record.ProfileID].ProfileID != "" {
			return nil, ErrEvidenceInvalid
		}
		r.evidence[record.ProfileID] = cloneEvidence(record)
	}
	for _, record := range compatibility {
		if record.Validate() != nil || record.Maturity != CompatibilityPinned || r.compatibility[record.ProfileID].ProfileID != "" {
			return nil, ErrCompatibilityInvalid
		}
		profile, found := r.profiles[record.ProfileID]
		if !found || profile.Provider != record.Provider {
			return nil, ErrCompatibilityInvalid
		}
		r.compatibility[record.ProfileID] = cloneCompatibility(record)
	}
	return r, nil
}

func (r *Registry) Profiles(context.Context) []Profile {
	if r == nil {
		return nil
	}
	profiles := make([]Profile, 0, len(r.profiles))
	for _, profile := range r.profiles {
		profiles = append(profiles, profile)
	}
	sort.Slice(profiles, func(i, j int) bool { return profiles[i].ID < profiles[j].ID })
	return profiles
}

func (r *Registry) Lookup(ctx context.Context, profileID string, now time.Time) (Profile, error) {
	if err := ctx.Err(); err != nil {
		return Profile{}, err
	}
	if r == nil {
		return Profile{}, ErrUnknownProfile
	}
	profile, found := r.profiles[profileID]
	if !found {
		return Profile{}, ErrUnknownProfile
	}
	resolution, err := r.Resolve(ctx, profileID, now)
	profile = resolution.Profile
	profile.MeshSpawnEnabled = resolution.MeshSpawnEnabled()
	// Preserve the persisted, signed readiness status. Eligibility is derived
	// independently and false on every Resolve error; replacing a compatible,
	// ready, or degraded status with a synthesized one would hide the actual
	// lifecycle state from a UI/operator.
	return profile, err
}

// Resolve returns the exact profile-scoped input that a Controller composition
// adapter needs. It never changes Registry state or promotes a profile: an
// enabled bit comes from an already persisted Controller revision and is
// revalidated here against limits, mapping and current signed evidence.
func (r *Registry) Resolve(ctx context.Context, profileID string, now time.Time) (ProfileResolution, error) {
	if err := ctx.Err(); err != nil {
		return ProfileResolution{}, err
	}
	if r == nil {
		return ProfileResolution{}, ErrUnknownProfile
	}
	profile, found := r.profiles[profileID]
	if !found {
		return ProfileResolution{}, ErrUnknownProfile
	}
	resolution := ProfileResolution{Profile: profile}
	limit, limitsFound := r.limits[profileID]
	resolution.Limits = limit
	limitsDigest, limitsErr := limit.Digest()
	resolution.LimitsVerified = limitsFound && limitsErr == nil && profile.ExecutionLimitsDigest == limitsDigest
	mapping, mappingFound := r.mappings[profileID]
	resolution.Mapping = cloneMapping(mapping)
	compatibility, compatibilityFound := r.compatibility[profileID]
	resolution.MappingVerified = mappingFound && compatibilityFound && compatibility.Validate() == nil && compatibility.Maturity == CompatibilityPinned && mapping.Validate() == nil && mapping.Maturity == CompatibilityPinned && profile.MappingDigest == mapping.Digest && mapping.CompatibilityRecordDigest == compatibility.Digest && mapping.Provider == compatibility.Provider && mapping.ProfileID == compatibility.ProfileID && mapping.ProfileRevision == profile.Revision && mapping.ProfileRevision == compatibility.ProfileRevision && mapping.RuntimeVersion == compatibility.RuntimeVersion && mapping.ProtocolVersion == compatibility.ProtocolVersion && mapping.RuntimeDigest == compatibility.RuntimeArtifactDigest && mapping.ProtocolDigest == compatibility.ProtocolSchemaDigest && mapping.ToolSchemaDigest == compatibility.MeshToolSchemaDigest
	record, evidenceFound := r.evidence[profileID]
	resolution.Evidence = cloneEvidence(record)
	evidenceBound := resolution.MappingVerified && EvidenceMatchesCompatibility(record, compatibility) && record.RuntimeArtifactDigest == mapping.RuntimeDigest && record.ProtocolSchemaDigest == mapping.ProtocolDigest && record.SchemaDigest == mapping.ProtocolDigest && record.MeshToolSchemaDigest == mapping.ToolSchemaDigest && record.RuntimeVersion == mapping.RuntimeVersion && record.ProtocolVersion == mapping.ProtocolVersion
	resolution.EvidenceCurrent = evidenceFound && profile.ProviderEvidenceDigest == record.Digest && evidenceBound && VerifyEvidence(record, r.trust, r.verifier, now) == nil
	if !resolution.LimitsVerified {
		return resolution, ErrLimitsMissing
	}
	if !resolution.MappingVerified {
		return resolution, ErrMappingMissing
	}
	if !resolution.EvidenceCurrent {
		if !evidenceFound || profile.ProviderEvidenceDigest != record.Digest || !evidenceBound {
			return resolution, ErrEvidenceDigestMismatch
		}
		return resolution, evidenceAsProfileError(VerifyEvidence(record, r.trust, r.verifier, now))
	}
	if profile.Status != StatusCompatible || !profile.MeshSpawnEnabled {
		return resolution, ErrProfileIncompatible
	}
	return resolution, nil
}

// MeshSpawnEnabled reports readiness only after Resolve has independently
// checked every prerequisite. It cannot turn a stored false value into true.
func (r ProfileResolution) MeshSpawnEnabled() bool {
	return r.Profile.Status == StatusCompatible && r.Profile.MeshSpawnEnabled && r.LimitsVerified && r.MappingVerified && r.EvidenceCurrent
}

// Directory returns the redacted, deterministic view for the Controller UI.
// It preserves the persisted status while deriving mesh eligibility and
// evidence freshness from the same fail-closed verification path as admission.
// A cancelled context has no trustworthy partial projection, so it returns the
// zero snapshot and callers retain their disabled baseline.
func (r *Registry) Directory(ctx context.Context, now time.Time) DirectorySnapshot {
	if r == nil || ctx.Err() != nil {
		return DirectorySnapshot{}
	}
	profiles := r.Profiles(ctx)
	out := make([]DirectoryProfile, 0, len(profiles))
	for _, profile := range profiles {
		if ctx.Err() != nil {
			return DirectorySnapshot{}
		}
		resolution, _ := r.Resolve(ctx, profile.ID, now)
		out = append(out, DirectoryProfile{
			ProfileID: profile.ID,
			Provider:  profile.Provider,
			Model:     profile.Model,
			Status:    profile.Status,
			MeshSpawn: resolution.MeshSpawnEnabled(),
			LocalOnly: profile.LocalOnly,
			Freshness: r.evidenceFreshness(profile, now),
		})
	}
	return DirectorySnapshot{profiles: out}
}

func (r *Registry) evidenceFreshness(profile Profile, now time.Time) EvidenceFreshness {
	record, found := r.evidence[profile.ID]
	if !found || profile.ProviderEvidenceDigest != record.Digest || record.FreshUntil.IsZero() {
		return EvidenceFreshnessUnknown
	}
	// A stale state is emitted only when the record was fully trustworthy at
	// its own freshness boundary. Revocation, malformed shape, a bad digest,
	// or an approval mismatch is unknown, not a guessed "stale" verdict.
	if !record.FreshUntil.After(now.UTC()) {
		if VerifyEvidence(record, r.trust, r.verifier, record.FreshUntil.Add(-time.Nanosecond)) == nil {
			return EvidenceFreshnessStale
		}
		return EvidenceFreshnessUnknown
	}
	if VerifyEvidence(record, r.trust, r.verifier, now) == nil {
		return EvidenceFreshnessCurrent
	}
	return EvidenceFreshnessUnknown
}

// MeshEligible has no promotion path: callers can observe eligibility but
// cannot turn it on. Only a Controller-owned immutable profile revision may
// publish a true value after all inputs have been checked.
func (r *Registry) MeshEligible(profileID string, now time.Time) (bool, error) {
	resolution, err := r.Resolve(context.Background(), profileID, now)
	return resolution.MeshSpawnEnabled(), err
}

func (r *Registry) Mapping(profileID string) (Mapping, error) {
	if r == nil {
		return Mapping{}, ErrUnknownProfile
	}
	mapping, found := r.mappings[profileID]
	if !found {
		return Mapping{}, ErrMappingMissing
	}
	return cloneMapping(mapping), nil
}

func finite(l ExecutionLimits) bool { return l.Validate() == nil }

func evidenceAsProfileError(err error) error {
	if err == nil {
		return nil
	}
	if evidenceErrorIsIncompatible(err) {
		return err
	}
	return errors.Join(ErrProfileIncompatible, err)
}

func cloneTrust(value TrustRegistry) TrustRegistry {
	copyMap := func(input map[string]bool) map[string]bool {
		out := make(map[string]bool, len(input))
		for key, present := range input {
			out[key] = present
		}
		return out
	}
	return TrustRegistry{TrustedTechnical: copyMap(value.TrustedTechnical), TrustedSecurity: copyMap(value.TrustedSecurity), Revoked: copyMap(value.Revoked)}
}
