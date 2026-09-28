package providerbridge

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
)

const maxCompatibilityRecordBytes = 64 << 10

const maxCompatibilityDescriptorBytes = 8 << 20

// GenerateCompatibilityRecord hashes sanitized descriptors into an unsigned,
// canonical compatibility record. It accepts no credentials, prompts, tokens,
// stdout, stderr, or private keys and never performs a provider action.
func GenerateCompatibilityRecord(draft CompatibilityRecord, runtimeArtifact, protocolSchema, meshToolSchema, transcript []byte) (CompatibilityRecord, error) {
	if len(runtimeArtifact) == 0 || len(protocolSchema) == 0 || len(meshToolSchema) == 0 || len(transcript) == 0 || len(runtimeArtifact) > maxCompatibilityDescriptorBytes || len(protocolSchema) > maxCompatibilityDescriptorBytes || len(meshToolSchema) > maxCompatibilityDescriptorBytes || len(transcript) > maxCompatibilityDescriptorBytes || draft.RuntimeArtifactDigest != "" || draft.ProtocolSchemaDigest != "" || draft.MeshToolSchemaDigest != "" || draft.TranscriptDigest != "" || draft.Digest != "" {
		return CompatibilityRecord{}, ErrCompatibilityInvalid
	}
	draft.RuntimeArtifactDigest = DigestBytes(runtimeArtifact)
	draft.ProtocolSchemaDigest = DigestBytes(protocolSchema)
	draft.MeshToolSchemaDigest = DigestBytes(meshToolSchema)
	draft.TranscriptDigest = DigestBytes(transcript)
	if err := draft.Seal(); err != nil || draft.Validate() != nil {
		return CompatibilityRecord{}, ErrCompatibilityInvalid
	}
	return draft, nil
}

// DecodeCompatibilityRecord accepts only canonical JSON with known, unique fields.
func DecodeCompatibilityRecord(input []byte) (CompatibilityRecord, error) {
	if len(input) == 0 || len(input) > maxCompatibilityRecordBytes || !json.Valid(input) || duplicateJSONKeys(input) {
		return CompatibilityRecord{}, ErrCompatibilityInvalid
	}
	dec := json.NewDecoder(bytes.NewReader(input))
	dec.DisallowUnknownFields()
	var record CompatibilityRecord
	if err := dec.Decode(&record); err != nil || dec.Decode(&struct{}{}) != io.EOF {
		return CompatibilityRecord{}, ErrCompatibilityInvalid
	}
	canonical, err := json.Marshal(record)
	if err != nil || !bytes.Equal(input, canonical) || record.Validate() != nil {
		return CompatibilityRecord{}, ErrCompatibilityInvalid
	}
	return record, nil
}

func (r *CompatibilityRecord) Seal() error {
	copy := *r
	copy.Digest = ""
	d, err := digest(copy)
	if err != nil {
		return err
	}
	r.Digest = d
	return nil
}

func (r CompatibilityRecord) Validate() error {
	definition, found := definitionFor(r.ProfileID)
	if r.SchemaVersion != CompatibilityRecordV1 || !found || !knownProvider(r.Provider) || r.Provider != definition.Provider || r.ProfileRevision != definition.Revision || r.Model != definition.Model || r.AuthModality != definition.AuthModality || !validCompatibilityVersion(r.RuntimeVersion, r.Maturity) || !validCompatibilityVersion(r.ProtocolVersion, r.Maturity) || !validSafeToken(r.GeneratorVersion, maxMetadataBytes) || r.GeneratedAt.IsZero() || !validDigest(r.RuntimeArtifactDigest) || !validDigest(r.ProtocolSchemaDigest) || !validDigest(r.MeshToolSchemaDigest) || !validDigest(r.TranscriptDigest) || !validDigest(r.Digest) || (r.Maturity != CompatibilitySynthetic && r.Maturity != CompatibilityPinned) || !validResultCategory(r.Handshake) || !validResultCategory(r.Start) || !validResultCategory(r.Stream) || !validResultCategory(r.Cancel) || !validResultCategory(r.Teardown) || !validResultCategory(r.Health) || !validOperations(r.Operations) || len(r.SourceReferences) == 0 || len(r.SourceReferences) > 16 {
		return ErrCompatibilityInvalid
	}
	for i, source := range r.SourceReferences {
		if !validSourceReference(source.Reference, r.Maturity) || !validDigest(source.Digest) || (i > 0 && r.SourceReferences[i-1].Reference >= source.Reference) {
			return ErrCompatibilityInvalid
		}
	}
	copy := r
	actual := copy.Digest
	copy.Digest = ""
	expected, err := digest(copy)
	if err != nil || actual != expected {
		return ErrCompatibilityInvalid
	}
	return nil
}

func validResultCategory(value string) bool {
	switch value {
	case "success", "rejected", "timeout", "cancelled", "quiescent", "unavailable":
		return true
	}
	return false
}
func validOperations(operations []OperationMapping) bool {
	if len(operations) != len(requiredMeshOperations) {
		return false
	}
	seen := map[string]bool{}
	for index, operation := range operations {
		if operation.Operation != requiredMeshOperations[index] || !validSafeEvent(operation.RequestEvent) || !validSafeEvent(operation.ResultEvent) || !validSafeEvent(operation.CancelEvent) || seen[operation.Operation] {
			return false
		}
		seen[operation.Operation] = true
	}
	for _, operation := range requiredMeshOperations {
		if !seen[operation] {
			return false
		}
	}
	return true
}

// MappingFromCompatibility binds all route metadata to one validated record.
func MappingFromCompatibility(record CompatibilityRecord) (Mapping, error) {
	if err := record.Validate(); err != nil {
		return Mapping{}, err
	}
	mapping := Mapping{SchemaVersion: MappingV1, Provider: record.Provider, ProfileID: record.ProfileID, ProfileRevision: record.ProfileRevision, RuntimeVersion: record.RuntimeVersion, ProtocolVersion: record.ProtocolVersion, RuntimeDigest: record.RuntimeArtifactDigest, ProtocolDigest: record.ProtocolSchemaDigest, ToolSchemaDigest: record.MeshToolSchemaDigest, CompatibilityRecordDigest: record.Digest, Maturity: record.Maturity, EndpointAuthMode: "controller-bound-mcp.v1", Cancellation: "bounded-cancel-then-quiescence", Teardown: "bounded-teardown", Operations: append([]OperationMapping(nil), record.Operations...)}
	if err := mapping.Seal(); err != nil {
		return Mapping{}, fmt.Errorf("seal mapping: %w", err)
	}
	return mapping, nil
}

// EvidenceMatchesCompatibility is the exact digest/version/revision binding
// checked before a signed evidence record can promote a mapping.
func EvidenceMatchesCompatibility(evidence ProviderEvidenceRecord, compatibility CompatibilityRecord) bool {
	return evidence.Provider == compatibility.Provider && evidence.ProfileID == compatibility.ProfileID && evidence.ProfileRevision == compatibility.ProfileRevision && evidence.Model == compatibility.Model && evidence.AuthModality == compatibility.AuthModality && evidence.CompatibilityRecordDigest == compatibility.Digest && evidence.RuntimeArtifactDigest == compatibility.RuntimeArtifactDigest && evidence.ProtocolSchemaDigest == compatibility.ProtocolSchemaDigest && evidence.SchemaDigest == compatibility.ProtocolSchemaDigest && evidence.MeshToolSchemaDigest == compatibility.MeshToolSchemaDigest && evidence.RuntimeVersion == compatibility.RuntimeVersion && evidence.ProtocolVersion == compatibility.ProtocolVersion
}

func cloneCompatibility(value CompatibilityRecord) CompatibilityRecord {
	value.Operations = append([]OperationMapping(nil), value.Operations...)
	value.SourceReferences = append([]CompatibilitySource(nil), value.SourceReferences...)
	return value
}

func duplicateJSONKeys(input []byte) bool {
	var walk func(*json.Decoder) bool
	walk = func(dec *json.Decoder) bool {
		token, err := dec.Token()
		if err != nil {
			return true
		}
		switch token := token.(type) {
		case json.Delim:
			if token == '{' {
				seen := map[string]bool{}
				for dec.More() {
					key, err := dec.Token()
					if err != nil {
						return true
					}
					name, ok := key.(string)
					if !ok || seen[name] {
						return true
					}
					seen[name] = true
					if walk(dec) {
						return true
					}
				}
				_, err := dec.Token()
				return err != nil
			}
			if token == '[' {
				for dec.More() {
					if walk(dec) {
						return true
					}
				}
				_, err := dec.Token()
				return err != nil
			}
		}
		return false
	}
	return walk(json.NewDecoder(bytes.NewReader(input)))
}

// CanonicalCompatibilityJSON is provided for rootless offline generators.
func CanonicalCompatibilityJSON(record CompatibilityRecord) ([]byte, error) {
	if err := record.Validate(); err != nil {
		return nil, err
	}
	b, err := json.Marshal(record)
	if err != nil || len(b) > maxCompatibilityRecordBytes {
		return nil, ErrCompatibilityInvalid
	}
	return b, nil
}
