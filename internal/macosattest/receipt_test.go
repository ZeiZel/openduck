package macosattest

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestVerifyNativeReceiptChainBindsProjectionAndSignature(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	_, projectionPriv, _ := ed25519.GenerateKey(rand.Reader)
	d := "sha256:" + strings.Repeat("a", 64)
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	p := LifecycleProjection{Schema: LifecycleProjectionSchema, ReleaseID: "release", ReleaseDigest: d, ManifestDigest: d, ShimArtifactDigest: d, SocketGeneration: 2, SocketIdentityDigest: d, HostCatalogGeneration: 3, ProviderTopologyDigest: d, HostArtifactDigest: d, HostTeamID: "TEAM", HostImageIdentity: d, ObservedAt: now, ExpiresAt: now.Add(time.Minute), SignerKeyID: "key"}
	if p.Seal(projectionPriv) != nil {
		t.Fatal("seal")
	}
	r := map[string]any{}
	for _, k := range receiptKeys {
		r[k] = ""
	}
	r["schema_version"] = "openduck-native-package-lifecycle-receipt.v1"
	r["package_id"] = "openduck-mesh"
	r["key_id"] = "key"
	r["action"] = "enable"
	r["provider"] = "codex"
	r["receipt_id"] = "r1"
	r["issued_at"] = now.Add(-time.Minute).Format(time.RFC3339Nano)
	r["expires_at"] = now.Add(time.Minute).Format(time.RFC3339Nano)
	r["endpoint_expires_at"] = now.Add(time.Minute).Format(time.RFC3339Nano)
	r["native_release_id"] = p.ReleaseID
	r["native_release_digest"] = strings.TrimPrefix(p.ReleaseDigest, "sha256:")
	r["native_manifest_digest"] = strings.TrimPrefix(p.ManifestDigest, "sha256:")
	r["native_shim_artifact_digest"] = strings.TrimPrefix(p.ShimArtifactDigest, "sha256:")
	r["native_socket_generation"] = json.Number("2")
	r["native_socket_identity_digest"] = strings.TrimPrefix(p.SocketIdentityDigest, "sha256:")
	r["native_host_catalog_generation"] = json.Number("3")
	r["native_provider_topology_digest"] = strings.TrimPrefix(p.ProviderTopologyDigest, "sha256:")
	r["native_host_artifact_digest"] = strings.TrimPrefix(p.HostArtifactDigest, "sha256:")
	r["native_host_team_id"] = p.HostTeamID
	r["native_host_image_identity"] = strings.TrimPrefix(p.HostImageIdentity, "sha256:")
	r["native_lifecycle_projection_digest"] = strings.TrimPrefix(p.Digest, "sha256:")
	r["native_lifecycle_expires_at"] = p.ExpiresAt.Format(time.RFC3339Nano)
	caps := make([]any, len(childCapabilities))
	for i, v := range childCapabilities {
		caps[i] = v
	}
	r["capabilities"] = caps
	capRaw, _ := canonicalJSON(caps)
	capSum := sha256.Sum256(capRaw)
	r["capability_digest"] = hex.EncodeToString(capSum[:])
	unsigned := map[string]any{}
	for k, v := range r {
		if k != "receipt_digest" && k != "signature" {
			unsigned[k] = v
		}
	}
	canonical, _ := canonicalJSON(unsigned)
	sum := sha256.Sum256(canonical)
	r["receipt_digest"] = hex.EncodeToString(sum[:])
	r["signature"] = base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, canonical))
	raw, _ := json.Marshal([]any{r})
	if _, err := VerifyNativeReceiptChain(raw, pub, p, now); err != nil {
		t.Fatal(err)
	}
	r["native_host_team_id"] = "OTHER"
	bad, _ := json.Marshal([]any{r})
	if _, err := VerifyNativeReceiptChain(bad, pub, p, now); err == nil {
		t.Fatal("substitution accepted")
	}
}
