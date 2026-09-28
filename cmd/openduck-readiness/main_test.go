package main

import (
	"encoding/json"
	"openduck/internal/codexruntime"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLivePFHashUsesStdoutOnlyWhenPFCTLWritesNoticeToStderr(t *testing.T) {
	priorBoot := readCurrentBootID
	readCurrentBootID = func() string { return "boot-test" }
	t.Cleanup(func() { readCurrentBootID = priorBoot })
	root := t.TempDir()
	seatbelt := filepath.Join(root, "seatbelt")
	if err := os.Mkdir(seatbelt, 0755); err != nil {
		t.Fatal(err)
	}
	policy := []byte("fixed policy\n")
	if err := os.WriteFile(filepath.Join(seatbelt, "state"), policy, 0644); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(seatbelt)
	if err != nil {
		t.Fatal(err)
	}
	rules := []byte("pass out keep state\n")
	evidence := codexruntime.PFEvidence{SchemaVersion: codexruntime.PFEvidenceV1, BootID: currentBootID(), Anchor: "com.openduck", Enabled: true, PolicyDigest: digest(policy), RulesDigest: digest(rules), RootUID: 0, RootGID: 0, RootMode: 0755, RootDigest: readinessPFRootDigest(info)}
	raw, err := evidence.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(seatbelt, "pf-evidence.json"), raw, 0644); err != nil {
		t.Fatal(err)
	}
	prior := runReadinessCommand
	runReadinessCommand = func(_ string, args ...string) ([]byte, []byte, error) {
		if strings.Join(args, " ") == "-s info" {
			return []byte("Status: Enabled\n"), []byte("pfctl notice\n"), nil
		}
		return rules, []byte("pfctl noisy stderr\n"), nil
	}
	t.Cleanup(func() { runReadinessCommand = prior })
	if !livePFReady(root) {
		t.Fatal("stderr notice contaminated live PF hash")
	}
}

func TestCanaryEvidenceRequiresCurrentReleaseBootAndExactRequestResult(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	result := "sha256:" + strings.Repeat("b", 64)
	proof, _ := json.Marshal(canaryProof{Schema: "openduck-canary-proof.v1", ReleaseID: "release-current", BootID: "boot-current", RunID: "run_current", ChatID: "openduck-live-egress-canary", RequestDigest: digest, ResultDigest: result})
	ledger, _ := json.Marshal([]canaryLedgerRecord{{RunID: "run_historical", ChatID: "openduck-live-egress-canary", State: "completed", Version: 3, ResultDigest: result}, {RunID: "run_current", ChatID: "openduck-live-egress-canary", State: "completed", Version: 3, ResultDigest: result}})
	if !canaryEvidenceMatches(append(proof, '\n'), ledger, "release-current", "boot-current") {
		t.Fatal("current explicit canary request/result rejected")
	}
	for _, tc := range []struct {
		name, release, boot string
		ledger              []byte
	}{
		{"old-release", "release-old", "boot-current", ledger},
		{"old-boot", "release-current", "boot-old", ledger},
		{"historical-run-only", "release-current", "boot-current", mustLedger(t, []canaryLedgerRecord{{RunID: "run_historical", ChatID: "openduck-live-egress-canary", State: "completed", Version: 3, ResultDigest: result}})},
		{"wrong-result", "release-current", "boot-current", mustLedger(t, []canaryLedgerRecord{{RunID: "run_current", ChatID: "openduck-live-egress-canary", State: "completed", Version: 3, ResultDigest: digest}})},
		{"wrong-chat", "release-current", "boot-current", mustLedger(t, []canaryLedgerRecord{{RunID: "run_current", ChatID: "ordinary-chat", State: "completed", Version: 3, ResultDigest: result}})},
		{"pending-checkpoint", "release-current", "boot-current", mustLedger(t, []canaryLedgerRecord{{RunID: "run_current", ChatID: "openduck-live-egress-canary", State: "completed", Version: 3, ResultDigest: result, PendingToken: "pending"}})},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if canaryEvidenceMatches(append(proof, '\n'), tc.ledger, tc.release, tc.boot) {
				t.Fatal("stale or unbound canary evidence accepted")
			}
		})
	}
}

func mustLedger(t *testing.T, records []canaryLedgerRecord) []byte {
	t.Helper()
	b, err := json.Marshal(records)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
