package codexruntime

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestPinnedCodex01423FixtureBindsWireContract(t *testing.T) {
	raw, err := os.ReadFile("testdata/codex-0.142.3-app-server-fixture.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		CodexVersion  string   `json:"codex_version"`
		BinarySHA256  string   `json:"binary_sha256"`
		SchemaSHA256  string   `json:"schema_sha256"`
		SourceCommand string   `json:"source_command"`
		Protocol      string   `json:"protocol"`
		AccountMethod string   `json:"account_method"`
		ConfigMethod  string   `json:"config_method"`
		ThreadSandbox string   `json:"thread_sandbox"`
		LoginTypes    []string `json:"login_types"`
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	if f.CodexVersion != "0.142.3" || len(f.BinarySHA256) != 64 || len(f.SchemaSHA256) != 64 || !strings.Contains(f.SourceCommand, "generate-json-schema") || f.Protocol != "v2" || f.AccountMethod != "account/get" || f.ConfigMethod != "config/read" || f.ThreadSandbox != "read-only" || len(f.LoginTypes) != 2 {
		t.Fatalf("invalid pinned fixture: %+v", f)
	}
}
