package macosattest

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"time"
)

const LifecycleProjectionSchema = "openduck.native-mcp-lifecycle.v1"

type LifecycleProjection struct {
	Schema                 string    `json:"schema"`
	ReleaseID              string    `json:"release_id"`
	ReleaseDigest          string    `json:"release_digest"`
	ManifestDigest         string    `json:"manifest_digest"`
	ShimArtifactDigest     string    `json:"shim_artifact_digest"`
	SocketGeneration       uint64    `json:"socket_generation"`
	SocketIdentityDigest   string    `json:"socket_identity_digest"`
	HostCatalogGeneration  uint64    `json:"host_catalog_generation"`
	ProviderTopologyDigest string    `json:"provider_topology_digest"`
	HostArtifactDigest     string    `json:"host_artifact_digest"`
	HostTeamID             string    `json:"host_team_id"`
	HostImageIdentity      string    `json:"host_image_identity"`
	ObservedAt             time.Time `json:"observed_at"`
	ExpiresAt              time.Time `json:"expires_at"`
	SignerKeyID            string    `json:"signer_key_id"`
	Digest                 string    `json:"digest"`
	Signature              string    `json:"signature"`
}

func (p LifecycleProjection) unsigned() LifecycleProjection {
	p.Digest = ""
	p.Signature = ""
	return p
}
func (p LifecycleProjection) signingBytes() ([]byte, error) { return json.Marshal(p.unsigned()) }
func (p *LifecycleProjection) Seal(key ed25519.PrivateKey) error {
	if p == nil || len(key) != ed25519.PrivateKeySize || p.validateShape(false) != nil {
		return ErrUnavailable
	}
	raw, _ := p.signingBytes()
	sum := sha256.Sum256(raw)
	p.Digest = "sha256:" + hex.EncodeToString(sum[:])
	p.Signature = hex.EncodeToString(ed25519.Sign(key, []byte(p.Digest)))
	return nil
}
func (p LifecycleProjection) Verify(key ed25519.PublicKey, now time.Time) error {
	if len(key) != ed25519.PublicKeySize || p.validateShape(true) != nil || now.Before(p.ObservedAt) || !now.Before(p.ExpiresAt) {
		return ErrUnavailable
	}
	raw, _ := p.signingBytes()
	sum := sha256.Sum256(raw)
	if p.Digest != "sha256:"+hex.EncodeToString(sum[:]) {
		return ErrUnavailable
	}
	sig, e := hex.DecodeString(p.Signature)
	if e != nil || !ed25519.Verify(key, []byte(p.Digest), sig) {
		return ErrUnavailable
	}
	return nil
}
func (p LifecycleProjection) validateShape(sealed bool) error {
	if p.Schema != LifecycleProjectionSchema || p.ReleaseID == "" || !shaDigest(p.ReleaseDigest) || !shaDigest(p.ManifestDigest) || !shaDigest(p.ShimArtifactDigest) || p.SocketGeneration == 0 || !shaDigest(p.SocketIdentityDigest) || p.HostCatalogGeneration == 0 || !shaDigest(p.ProviderTopologyDigest) || !shaDigest(p.HostArtifactDigest) || p.HostTeamID == "" || !shaDigest(p.HostImageIdentity) || p.ObservedAt.IsZero() || p.ExpiresAt.IsZero() || !p.ExpiresAt.After(p.ObservedAt) || p.ExpiresAt.Sub(p.ObservedAt) > 15*time.Minute || p.SignerKeyID == "" {
		return ErrUnavailable
	}
	if sealed && (!shaDigest(p.Digest) || len(p.Signature) != ed25519.SignatureSize*2) {
		return ErrUnavailable
	}
	return nil
}
func (p LifecycleProjection) Canonical() ([]byte, error) {
	if p.validateShape(true) != nil {
		return nil, ErrUnavailable
	}
	return json.Marshal(p)
}
func DecodeLifecycleProjection(raw []byte) (LifecycleProjection, error) {
	if len(raw) == 0 || len(raw) > 16<<10 {
		return LifecycleProjection{}, ErrUnavailable
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	var p LifecycleProjection
	if d.Decode(&p) != nil || d.Decode(&struct{}{}) != io.EOF {
		return LifecycleProjection{}, ErrUnavailable
	}
	canonical, e := p.Canonical()
	if e != nil || !bytes.Equal(raw, canonical) {
		return LifecycleProjection{}, ErrUnavailable
	}
	return p, nil
}
func shaDigest(v string) bool {
	if len(v) != 71 || v[:7] != "sha256:" {
		return false
	}
	_, e := hex.DecodeString(v[7:])
	return e == nil
}
