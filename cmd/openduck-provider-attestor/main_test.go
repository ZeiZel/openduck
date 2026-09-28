package main

import (
	"strings"
	"testing"
)

func TestStandaloneHelperNeverFabricatesAttestation(t *testing.T) {
	out, code := run()
	if code == 0 || len(out) > 512 || !strings.Contains(string(out), `"operational":false`) || !strings.Contains(string(out), `"reason_code":"authenticated_controller_channel_unavailable"`) {
		t.Fatalf("standalone helper did not fail closed: %q code=%d", out, code)
	}
}
