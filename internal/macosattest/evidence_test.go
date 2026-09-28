package macosattest

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"strings"
	"testing"
	"time"
)

func TestGenerateLifecycleGolden(t *testing.T) {
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	key := ed25519.NewKeyFromSeed(seed)
	d := "sha256:" + strings.Repeat("a", 64)
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	p := LifecycleProjection{Schema: LifecycleProjectionSchema, ReleaseID: "release-golden", ReleaseDigest: d, ManifestDigest: d, ShimArtifactDigest: d, SocketGeneration: 7, SocketIdentityDigest: d, HostCatalogGeneration: 9, ProviderTopologyDigest: d, HostArtifactDigest: d, HostTeamID: "2DC432GLL2", HostImageIdentity: d, ObservedAt: now, ExpiresAt: now.Add(5 * time.Minute), SignerKeyID: "controller-golden"}
	if err := p.Seal(key); err != nil {
		t.Fatal(err)
	}
	raw, _ := p.Canonical()
	want, err := os.ReadFile("testdata/lifecycle-projection.golden.json")
	if err != nil || !bytes.Equal(raw, bytes.TrimSpace(want)) {
		t.Fatalf("golden drift: %v", err)
	}
	if p.Verify(key.Public().(ed25519.PublicKey), now) != nil {
		t.Fatal("golden signature invalid")
	}
}

func TestLifecycleProjectionSignatureBindsEveryAuthorityFacet(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Unix(100, 0).UTC()
	d := "sha256:" + strings.Repeat("a", 64)
	p := LifecycleProjection{Schema: LifecycleProjectionSchema, ReleaseID: "release", ReleaseDigest: d, ManifestDigest: d, ShimArtifactDigest: d, SocketGeneration: 1, SocketIdentityDigest: d, HostCatalogGeneration: 1, ProviderTopologyDigest: d, HostArtifactDigest: d, HostTeamID: "TEAM", HostImageIdentity: d, ObservedAt: now, ExpiresAt: now.Add(time.Minute), SignerKeyID: "controller"}
	if p.Seal(priv) != nil || p.Verify(pub, now) != nil {
		t.Fatal("valid projection rejected")
	}
	raw, _ := p.Canonical()
	if _, e := DecodeLifecycleProjection(raw); e != nil {
		t.Fatal(e)
	}
	mutations := []func(*LifecycleProjection){func(v *LifecycleProjection) { v.ReleaseID = "other" }, func(v *LifecycleProjection) { v.ManifestDigest = "sha256:" + strings.Repeat("b", 64) }, func(v *LifecycleProjection) { v.ShimArtifactDigest = "sha256:" + strings.Repeat("b", 64) }, func(v *LifecycleProjection) { v.SocketGeneration++ }, func(v *LifecycleProjection) { v.SocketIdentityDigest = "sha256:" + strings.Repeat("b", 64) }, func(v *LifecycleProjection) { v.HostCatalogGeneration++ }, func(v *LifecycleProjection) { v.ProviderTopologyDigest = "sha256:" + strings.Repeat("b", 64) }, func(v *LifecycleProjection) { v.HostArtifactDigest = "sha256:" + strings.Repeat("b", 64) }, func(v *LifecycleProjection) { v.HostTeamID = "OTHER" }, func(v *LifecycleProjection) { v.HostImageIdentity = "sha256:" + strings.Repeat("b", 64) }, func(v *LifecycleProjection) { v.ExpiresAt = v.ExpiresAt.Add(time.Second) }, func(v *LifecycleProjection) { v.ReleaseDigest = "sha256:" + strings.Repeat("b", 64) }}
	for _, mutate := range mutations {
		v := p
		mutate(&v)
		if v.Verify(pub, now) == nil {
			t.Fatal("authority substitution accepted")
		}
	}
}
