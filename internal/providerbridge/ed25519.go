package providerbridge

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"io"
)

const (
	Ed25519TrustBundleV1 = "provider-evidence-ed25519-trust.v1"
	maxTrustBundleBytes  = 32 << 10
)

// Ed25519TrustBundle is a canonical, public-only verifier input. It never
// contains a private key and can be supplied by a Controller-owned approval
// store or the offline verifier CLI.
type Ed25519TrustBundle struct {
	SchemaVersion    string            `json:"schema_version"`
	PublicKeys       map[string]string `json:"public_keys"`
	TrustedTechnical []string          `json:"trusted_technical"`
	TrustedSecurity  []string          `json:"trusted_security"`
	Revoked          []string          `json:"revoked"`
}

// Ed25519Verifier verifies lowercase hexadecimal Ed25519 signatures over the
// exact ASCII evidence digest. It is safe to retain after the input maps are
// discarded because it copies each public key.
type Ed25519Verifier struct{ publicKeys map[string]ed25519.PublicKey }

func NewEd25519Verifier(publicKeys map[string]string) (*Ed25519Verifier, error) {
	if len(publicKeys) == 0 || len(publicKeys) > 64 {
		return nil, ErrEvidenceUntrusted
	}
	keys := make(map[string]ed25519.PublicKey, len(publicKeys))
	for id, encoded := range publicKeys {
		if !validSafeToken(id, 128) || !validLowerHex(encoded, ed25519.PublicKeySize) {
			return nil, ErrEvidenceUntrusted
		}
		decoded, err := hex.DecodeString(encoded)
		if err != nil || len(decoded) != ed25519.PublicKeySize {
			return nil, ErrEvidenceUntrusted
		}
		keys[id] = append(ed25519.PublicKey(nil), decoded...)
	}
	return &Ed25519Verifier{publicKeys: keys}, nil
}

func (v *Ed25519Verifier) Verify(signerKeyID, payloadDigest, signature string) bool {
	if v == nil || !validSafeToken(signerKeyID, 128) || !validDigest(payloadDigest) || !validLowerHex(signature, ed25519.SignatureSize) {
		return false
	}
	key, found := v.publicKeys[signerKeyID]
	if !found {
		return false
	}
	decoded, err := hex.DecodeString(signature)
	return err == nil && ed25519.Verify(key, []byte(payloadDigest), decoded)
}

func DecodeEd25519TrustBundle(input []byte) (Ed25519TrustBundle, error) {
	if len(input) == 0 || len(input) > maxTrustBundleBytes || !json.Valid(input) || duplicateJSONKeys(input) {
		return Ed25519TrustBundle{}, ErrEvidenceUntrusted
	}
	dec := json.NewDecoder(bytes.NewReader(input))
	dec.DisallowUnknownFields()
	var bundle Ed25519TrustBundle
	if err := dec.Decode(&bundle); err != nil || dec.Decode(&struct{}{}) != io.EOF || !bundle.valid() {
		return Ed25519TrustBundle{}, ErrEvidenceUntrusted
	}
	canonical, err := json.Marshal(bundle)
	if err != nil || !bytes.Equal(input, canonical) {
		return Ed25519TrustBundle{}, ErrEvidenceUntrusted
	}
	return bundle, nil
}

func (b Ed25519TrustBundle) Verifier() (*Ed25519Verifier, error) {
	return NewEd25519Verifier(b.PublicKeys)
}

func (b Ed25519TrustBundle) TrustRegistry() TrustRegistry {
	trust := TrustRegistry{TrustedTechnical: map[string]bool{}, TrustedSecurity: map[string]bool{}, Revoked: map[string]bool{}}
	for _, id := range b.TrustedTechnical {
		trust.TrustedTechnical[id] = true
	}
	for _, id := range b.TrustedSecurity {
		trust.TrustedSecurity[id] = true
	}
	for _, id := range b.Revoked {
		trust.Revoked[id] = true
	}
	return trust
}

func (b Ed25519TrustBundle) valid() bool {
	if b.SchemaVersion != Ed25519TrustBundleV1 || len(b.PublicKeys) == 0 || len(b.PublicKeys) > 64 || len(b.TrustedTechnical) == 0 || len(b.TrustedSecurity) == 0 || !sortedUniqueTokens(b.TrustedTechnical, 64) || !sortedUniqueTokens(b.TrustedSecurity, 64) || !sortedUniqueTokens(b.Revoked, 64) {
		return false
	}
	if _, err := NewEd25519Verifier(b.PublicKeys); err != nil {
		return false
	}
	for _, ids := range [][]string{b.TrustedTechnical, b.TrustedSecurity, b.Revoked} {
		for _, id := range ids {
			if _, found := b.PublicKeys[id]; !found {
				return false
			}
		}
	}
	for _, id := range b.TrustedTechnical {
		for _, other := range b.TrustedSecurity {
			if id == other {
				return false
			}
		}
	}
	return true
}

func sortedUniqueTokens(values []string, max int) bool {
	if len(values) > max {
		return false
	}
	for index, value := range values {
		if !validSafeToken(value, 128) || (index > 0 && values[index-1] >= value) {
			return false
		}
	}
	return true
}

func validLowerHex(value string, byteLength int) bool {
	if len(value) != byteLength*2 {
		return false
	}
	for _, r := range value {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
			return false
		}
	}
	return true
}
