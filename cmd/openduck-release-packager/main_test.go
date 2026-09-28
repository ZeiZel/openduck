package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"openduck/internal/macosrelease"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestPackageThenFinalizeOffline(t *testing.T) {
	d := t.TempDir()
	stage := filepath.Join(d, "stage")
	if err := os.MkdirAll(filepath.Join(stage, "bin"), 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"codex", "openduck-anchor", "openduck-checkpoint", "openduck-codex-broker", "openduck-codex-login", "openduck-codex-runtime", "openduck-controller", "openduck-egress", "openduck-installer", "openduck-native-mcp", "openduck-owner-grant", "openduck-provider-attestor", "openduck-readiness"} {
		if err := os.WriteFile(filepath.Join(stage, "bin", name), []byte(name), 0500); err != nil {
			t.Fatal(err)
		}
	}
	manifest, request := filepath.Join(d, "manifest.json"), filepath.Join(d, "request.json")
	args := []string{"package", "--stage-root", stage, "--manifest-out", manifest, "--signing-request-out", request, "--release-id", "release-20260826", "--version", "1.2.3", "--target-root", "/opt/openduck", "--platform", runtime.GOOS, "--arch", runtime.GOARCH, "--key-id", "release-key", "--operation", "deploy", "--run-id", "aaaaaaaa-1111", "--activation", "false", "--sequence", "42", "--nonce", "release-nonce", "--issued-at", "2025-06-15T15:06:40Z", "--expires-at", "2025-06-15T17:06:40Z", "--min-installer", "1.0.0"}
	if err := run(args); err != nil {
		t.Fatal(err)
	}
	var r macosrelease.SigningRequestV1
	if err := macosrelease.LoadStrict(request, &r); err != nil {
		t.Fatal(err)
	}
	payload, err := base64.StdEncoding.DecodeString(r.UnsignedPayload)
	if err != nil {
		t.Fatal(err)
	}
	pub, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signature, trust, envelope := filepath.Join(d, "signature.json"), filepath.Join(d, "trust.json"), filepath.Join(d, "envelope.json")
	if err := macosrelease.WriteNewCanonical(signature, macosrelease.ExternalSignatureV1{Schema: macosrelease.SignatureSchema, Algorithm: "ed25519", KeyID: r.KeyID, PayloadDigest: r.PayloadDigest, Signature: hex.EncodeToString(ed25519.Sign(private, payload))}); err != nil {
		t.Fatal(err)
	}
	if err := macosrelease.WriteNewCanonical(trust, macosrelease.TrustBundle{Schema: macosrelease.TrustBundleSchema, Keys: map[string]string{r.KeyID: hex.EncodeToString(pub)}}); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"finalize", "--signing-request", request, "--signature", signature, "--trust-bundle", trust, "--envelope-out", envelope, "--now", "2025-06-15T16:06:40Z"}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(envelope); err != nil {
		t.Fatal(err)
	}
	if err := run(append(args, "--private-key", "nope")); err == nil {
		t.Fatal("private-key flag accepted")
	}
}

func TestPackageOutputCollisionPolicy(t *testing.T) {
	stage := filepath.Join(t.TempDir(), "stage")
	if err := os.Mkdir(stage, 0700); err != nil {
		t.Fatal(err)
	}
	if _, _, err := macosrelease.ResolvePackagePaths(stage, stage); err == nil {
		t.Fatal("staged-root output collision accepted")
	}
	if _, _, err := macosrelease.ResolvePackagePaths(stage, filepath.Join(stage, "manifest.json")); err == nil {
		t.Fatal("staged-root output collision accepted")
	}
	if _, _, err := macosrelease.ResolvePackagePaths(stage, filepath.Join(filepath.Dir(stage), "manifest.json")); err != nil {
		t.Fatal("external output rejected")
	}
}
