package main

import (
	"io"
	"openduck/internal/macosinstall"
	"os"
	"testing"
)

func TestPartialInstallRecoveryRejectsMixedOrUnboundInvocationBeforeProductionRecovery(t *testing.T) {
	for _, args := range [][]string{
		{"--recover-partial-install", "--deploy"},
		{"--partial-install-recovery-plan", "--release-id", "release-a"},
		{"--recover-partial-install", "--release-nonce-store", "/private/tmp/nonce"},
		{"--recover-partial-install", "--activation=false"},
	} {
		if err := run(args); err == nil {
			t.Fatalf("unsafe mixed recovery invocation accepted: %v", args)
		}
	}
}

func TestPartialInstallRecoveryRequiresExplicitAuthority(t *testing.T) {
	if err := run([]string{"--partial-install-recovery-plan"}); err == nil {
		t.Fatal("unbound partial recovery plan accepted")
	}
}

func TestPartialInstallRecoveryPlanBindsBothIndependentDigestsBeforeAnyMutation(t *testing.T) {
	priorInspect, priorQuarantine, priorOut := inspectPartialInstallRecovery, quarantinePartialInstallRecovery, os.Stdout
	t.Cleanup(func() {
		inspectPartialInstallRecovery, quarantinePartialInstallRecovery, os.Stdout = priorInspect, priorQuarantine, priorOut
	})
	called := false
	inspectPartialInstallRecovery = func(request macosinstall.PartialInstallRecoveryRequest) (macosinstall.PartialInstallRecoveryEvidence, error) {
		called = true
		if request.Intent != macosinstall.PartialInstallRecoveryIntent || request.BootstrapHelperPath != "/private/tmp/pretrusted-installer" || request.BootstrapHelperSHA256 != testDigest([]byte("installer")) || request.ReadinessHelperSHA256 != testDigest([]byte("readiness")) {
			t.Fatalf("recovery request lost independent binding: %+v", request)
		}
		return macosinstall.PartialInstallRecoveryEvidence{Schema: "openduck.partial-install-recovery.v1", Version: 1, State: "eligible"}, nil
	}
	quarantinePartialInstallRecovery = func(macosinstall.PartialInstallRecoveryRequest) (macosinstall.PartialInstallRecoveryEvidence, error) {
		t.Fatal("read-only recovery plan reached mutation route")
		return macosinstall.PartialInstallRecoveryEvidence{}, nil
	}
	readEnd, writeEnd, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = writeEnd
	err = run([]string{
		"--partial-install-recovery-plan",
		"--recovery-intent", macosinstall.PartialInstallRecoveryIntent,
		"--recovery-bootstrap-helper", "/private/tmp/pretrusted-installer",
		"--recovery-bootstrap-sha256", testDigest([]byte("installer")),
		"--recovery-readiness-sha256", testDigest([]byte("readiness")),
	})
	_ = writeEnd.Close()
	os.Stdout = priorOut
	if err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("read-only recovery plan did not reach inspector")
	}
	if output, readErr := io.ReadAll(readEnd); readErr != nil || string(output) != "{\"schema\":\"openduck.partial-install-recovery.v1\",\"version\":1,\"state\":\"eligible\"}\n" {
		t.Fatalf("unexpected bounded plan output %q err=%v", output, readErr)
	}
	_ = readEnd.Close()
}
