// Command openduck-release-packager prepares an unsigned, offline-signable
// release. It deliberately has no private-key, credential, network, or
// environment configuration support.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"openduck/internal/macosrelease"
	"os"
	"time"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "openduck-release-packager:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return errors.New("operation required: package, finalize or verify-trust")
	}
	switch args[0] {
	case "package":
		return runPackage(args[1:])
	case "finalize":
		return runFinalize(args[1:])
	case "verify-trust":
		return runVerifyTrust(args[1:])
	default:
		return errors.New("operation required: package, finalize or verify-trust")
	}
}

func runPackage(args []string) error {
	fs := flag.NewFlagSet("package", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	stage := fs.String("stage-root", "", "absolute staged release root")
	manifestOut := fs.String("manifest-out", "", "new manifest output path")
	requestOut := fs.String("signing-request-out", "", "new signing request output path")
	releaseID := fs.String("release-id", "", "human release identifier")
	version := fs.String("version", "", "release semantic version")
	target := fs.String("target-root", "", "installer target root")
	platform := fs.String("platform", "", "exact target platform")
	arch := fs.String("arch", "", "exact target architecture")
	keyID := fs.String("key-id", "", "public signing key identifier")
	operation := fs.String("operation", "", "deploy or rollback")
	runID := fs.String("run-id", "", "exact installer run identifier")
	activation := fs.String("activation", "", "true or false (required)")
	sequence := fs.Uint64("sequence", 0, "monotonic signer sequence")
	nonce := fs.String("nonce", "", "single-use nonce")
	issued := fs.String("issued-at", "", "RFC3339 signing issuance time")
	expires := fs.String("expires-at", "", "RFC3339 signing expiry time")
	minInstaller := fs.String("min-installer", "", "minimum installer semantic version")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 {
		return errors.New("invalid package arguments")
	}
	active, ok := parseBool(*activation)
	physicalStage, outputs, pathErr := macosrelease.ResolvePackagePaths(*stage, *manifestOut, *requestOut)
	if !ok || pathErr != nil {
		return errors.New("unsafe package inputs or output collision")
	}
	issuedAt, err := time.Parse(time.RFC3339, *issued)
	if err != nil {
		return errors.New("invalid --issued-at")
	}
	expiresAt, err := time.Parse(time.RFC3339, *expires)
	if err != nil {
		return errors.New("invalid --expires-at")
	}
	in := macosrelease.PackageInput{StageRoot: physicalStage, ReleaseID: *releaseID, Version: *version, TargetRoot: *target, Platform: *platform, Arch: *arch, KeyID: *keyID, Operation: *operation, RunID: *runID, Activation: active, Sequence: *sequence, Nonce: *nonce, IssuedAt: issuedAt.UTC(), ExpiresAt: expiresAt.UTC(), MinInstaller: *minInstaller}
	manifest, err := macosrelease.BuildManifest(in)
	if err != nil {
		return errors.New("staged release rejected")
	}
	request, err := macosrelease.BuildSigningRequest(in, manifest)
	if err != nil {
		return errors.New("signing request rejected")
	}
	if err := macosrelease.WriteNewCanonicalOutsideStage(physicalStage, outputs[0], manifest); err != nil {
		return errors.New("manifest output rejected")
	}
	if err := macosrelease.WriteNewCanonicalOutsideStage(physicalStage, outputs[1], request); err != nil {
		return errors.New("signing request output rejected")
	}
	fmt.Printf("release_id=%s\nrelease_digest=%s\nmanifest=%s\nsigning_request=%s\n", manifest.ReleaseID, manifest.ReleaseDigest, outputs[0], outputs[1])
	return nil
}

func runFinalize(args []string) error {
	fs := flag.NewFlagSet("finalize", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	request := fs.String("signing-request", "", "strict signing request")
	signature := fs.String("signature", "", "external signature response")
	trust := fs.String("trust-bundle", "", "pinned public trust bundle")
	envelopeOut := fs.String("envelope-out", "", "new signed envelope output")
	now := fs.String("now", "", "RFC3339 current time for expiry validation")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 {
		return errors.New("invalid finalize arguments")
	}
	nowAt, err := time.Parse(time.RFC3339, *now)
	if err != nil {
		return errors.New("invalid --now")
	}
	if _, err := macosrelease.Finalize(macosrelease.FinalizeInput{RequestPath: *request, SignaturePath: *signature, TrustBundlePath: *trust, EnvelopeOutput: *envelopeOut, Now: nowAt.UTC()}); err != nil {
		return errors.New("signature finalization rejected")
	}
	fmt.Printf("release_envelope=%s\n", *envelopeOut)
	return nil
}

func parseBool(value string) (bool, bool) {
	if value == "true" {
		return true, true
	}
	if value == "false" {
		return false, true
	}
	return false, false
}

// runVerifyTrust is unprivileged and read-only. It never writes, signs, or
// touches the fixed install root.
func runVerifyTrust(args []string) error {
	fs := flag.NewFlagSet("verify-trust", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	trust := fs.String("trust-bundle", "", "release trust bundle to validate")
	if err := fs.Parse(args); err != nil || *trust == "" || fs.NArg() != 0 {
		return errors.New("invalid verify-trust arguments")
	}
	if err := macosrelease.ValidateTrustBundleFile(*trust); err != nil {
		return err
	}
	fmt.Printf("trust_bundle=%s\ntrust_bundle_state=canonical\n", *trust)
	return nil
}
