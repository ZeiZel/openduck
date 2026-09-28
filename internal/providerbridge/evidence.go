package providerbridge

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"time"
)

const maxEvidenceRecordBytes = 64 << 10

// DecodeProviderEvidenceRecord accepts exactly one canonical v1 JSON record.
// An unsigned record can be decoded for an offline review request, but it can
// never pass VerifyEvidence.
func DecodeProviderEvidenceRecord(input []byte) (ProviderEvidenceRecord, error) {
	if len(input) == 0 || len(input) > maxEvidenceRecordBytes || !json.Valid(input) || duplicateJSONKeys(input) {
		return ProviderEvidenceRecord{}, ErrEvidenceInvalid
	}
	dec := json.NewDecoder(bytes.NewReader(input))
	dec.DisallowUnknownFields()
	var record ProviderEvidenceRecord
	if err := dec.Decode(&record); err != nil || dec.Decode(&struct{}{}) != io.EOF || !validEvidenceShape(record, false) || !evidenceDigestMatches(record) {
		return ProviderEvidenceRecord{}, ErrEvidenceInvalid
	}
	canonical, err := json.Marshal(record)
	if err != nil || !bytes.Equal(input, canonical) {
		return ProviderEvidenceRecord{}, ErrEvidenceInvalid
	}
	return record, nil
}

// CanonicalProviderEvidenceJSON returns exact v1 JSON for an already sealed,
// potentially unsigned evidence review artifact.
func CanonicalProviderEvidenceJSON(record ProviderEvidenceRecord) ([]byte, error) {
	if !validEvidenceShape(record, false) || !evidenceDigestMatches(record) {
		return nil, ErrEvidenceInvalid
	}
	b, err := json.Marshal(record)
	if err != nil || len(b) > maxEvidenceRecordBytes {
		return nil, ErrEvidenceInvalid
	}
	return b, nil
}

// Seal computes the reproducible decision digest. Callers attach signatures
// after sealing because they authenticate this exact digest.
func (r *ProviderEvidenceRecord) Seal() error {
	copy := *r
	copy.Digest = ""
	copy.Approvals = nil
	d, err := digest(copy)
	if err != nil {
		return err
	}
	r.Digest = d
	return nil
}

// VerifyEvidence validates freshness, reviewer roles, revocation, the sealed
// record digest, and both signatures. It makes no network calls.
func VerifyEvidence(record ProviderEvidenceRecord, trust TrustRegistry, verifier SignatureVerifier, now time.Time) error {
	if !record.FreshUntil.IsZero() && !record.FreshUntil.After(now.UTC()) {
		return ErrEvidenceStale
	}
	if !validEvidenceShape(record, true) || record.RetrievedAt.After(now.UTC()) || !record.RetrievedAt.Before(record.FreshUntil) {
		return ErrEvidenceInvalid
	}
	if !evidenceDigestMatches(record) {
		return ErrEvidenceDigestMismatch
	}
	if verifier == nil {
		return ErrEvidenceUntrusted
	}
	if trustedRoleSetsOverlap(trust) {
		return ErrEvidenceUntrusted
	}
	required := map[string]bool{"technical": false, "security": false}
	reviewerKeys := map[string]bool{}
	decisionRefs := map[string]bool{}
	for _, approval := range record.Approvals {
		if !validApproval(approval, record) || trust.Revoked[approval.ReviewerKeyID] || reviewerKeys[approval.ReviewerKeyID] || decisionRefs[approval.DecisionRef] {
			return ErrEvidenceUntrusted
		}
		trusted := (approval.Role == "technical" && trust.TrustedTechnical[approval.ReviewerKeyID]) || (approval.Role == "security" && trust.TrustedSecurity[approval.ReviewerKeyID])
		if !trusted || !verifier.Verify(approval.ReviewerKeyID, record.Digest, approval.Signature) || required[approval.Role] {
			return ErrEvidenceUntrusted
		}
		required[approval.Role] = true
		reviewerKeys[approval.ReviewerKeyID] = true
		decisionRefs[approval.DecisionRef] = true
	}
	for _, found := range required {
		if !found {
			return ErrEvidenceUntrusted
		}
	}
	return nil
}

func trustedRoleSetsOverlap(trust TrustRegistry) bool {
	for key, technical := range trust.TrustedTechnical {
		if technical && trust.TrustedSecurity[key] {
			return true
		}
	}
	return false
}

func validEvidenceShape(record ProviderEvidenceRecord, requireApprovals bool) bool {
	if record.SchemaVersion != EvidenceRecordV1 || !validEvidenceIdentity(record) || !validSafeToken(record.EvidenceGeneratorVersion, maxMetadataBytes) || record.RetrievedAt.IsZero() || record.FreshUntil.IsZero() || !record.RetrievedAt.Before(record.FreshUntil) || !validEvidenceSlices(record) || !validDigest(record.SourceContentDigest) || !validDigest(record.RuntimeArtifactDigest) || !validDigest(record.SchemaDigest) || !validDigest(record.CompatibilityRecordDigest) || !validDigest(record.ProtocolSchemaDigest) || !validDigest(record.MeshToolSchemaDigest) || record.SchemaDigest != record.ProtocolSchemaDigest || !validDigest(record.Digest) {
		return false
	}
	if requireApprovals {
		if len(record.Approvals) > 2 {
			return false
		}
	} else if len(record.Approvals) > 2 {
		return false
	}
	for _, approval := range record.Approvals {
		if !validApprovalMetadata(approval) {
			return false
		}
	}
	return true
}

func evidenceDigestMatches(record ProviderEvidenceRecord) bool {
	copy := record
	actual := copy.Digest
	copy.Digest = ""
	copy.Approvals = nil
	expected, err := digest(copy)
	return err == nil && actual == expected
}

func cloneEvidence(value ProviderEvidenceRecord) ProviderEvidenceRecord {
	value.OfficialURLs = append([]string(nil), value.OfficialURLs...)
	value.Approvals = append([]EvidenceApproval(nil), value.Approvals...)
	if value.ClaimModalities != nil {
		claims := make(map[string]string, len(value.ClaimModalities))
		for key, claim := range value.ClaimModalities {
			claims[key] = claim
		}
		value.ClaimModalities = claims
	}
	return value
}

func validEvidenceSlices(record ProviderEvidenceRecord) bool {
	if len(record.OfficialURLs) == 0 || len(record.OfficialURLs) > 8 || len(record.ClaimModalities) == 0 || len(record.ClaimModalities) > 8 || len(record.Approvals) > 2 {
		return false
	}
	for i, value := range record.OfficialURLs {
		if !validHTTPSURL(value) || (i > 0 && record.OfficialURLs[i-1] >= value) {
			return false
		}
	}
	for claim, modality := range record.ClaimModalities {
		if !validSafeToken(claim, maxMetadataBytes) || !validSafeToken(modality, maxMetadataBytes) {
			return false
		}
	}
	return true
}

func validApproval(approval EvidenceApproval, record ProviderEvidenceRecord) bool {
	return validApprovalMetadata(approval) && approval.ProfileID == record.ProfileID && approval.ProfileRevision == record.ProfileRevision && approval.EvidenceDigest == record.Digest && approval.FreshUntil.Equal(record.FreshUntil)
}

func validApprovalMetadata(approval EvidenceApproval) bool {
	return approval.SchemaVersion == "provider-evidence-approval.v1" && (approval.Role == "technical" || approval.Role == "security") && validSafeToken(approval.ReviewerKeyID, 128) && validSafeToken(approval.ProfileID, maxMetadataBytes) && validSafeToken(approval.ProfileRevision, maxMetadataBytes) && validDigest(approval.EvidenceDigest) && !approval.FreshUntil.IsZero() && validDecisionReference(approval.DecisionRef) && validSafeToken(approval.Signature, 1024)
}

func validEvidenceIdentity(record ProviderEvidenceRecord) bool {
	definition, found := definitionFor(record.ProfileID)
	if !found {
		return false
	}
	return definition.Provider == record.Provider && definition.Model == record.Model && definition.AuthModality == record.AuthModality && definition.Revision == record.ProfileRevision && validCompatibilityVersion(record.RuntimeVersion, CompatibilityPinned) && validCompatibilityVersion(record.ProtocolVersion, CompatibilityPinned)
}

func knownProvider(provider Provider) bool {
	switch provider {
	case ProviderCodex, ProviderClaude, ProviderQwen, ProviderKimi, ProviderDeepSeek:
		return true
	default:
		return false
	}
}

func evidenceErrorIsIncompatible(err error) bool {
	return errors.Is(err, ErrEvidenceInvalid) || errors.Is(err, ErrEvidenceDigestMismatch) || errors.Is(err, ErrEvidenceStale) || errors.Is(err, ErrEvidenceUntrusted)
}
