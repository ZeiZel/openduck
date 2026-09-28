package main

import (
	"encoding/xml"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The broker is deliberately a forwarder. Keep this structural assertion near
// its composition root so a future convenience launch cannot silently merge
// the two Unix principals again.
func TestBrokerNeverImportsOrStartsCodexRuntime(t *testing.T) {
	b, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for _, forbidden := range []string{"internal/codexruntime\"", "os/exec", "exec.Command", "NewProductionRuntimeIsolation", "NewProductionBackend"} {
		if strings.Contains(s, forbidden) {
			t.Fatalf("broker must forward, found %q", forbidden)
		}
	}
	if !strings.Contains(s, "NewForwardingBackend") || !strings.Contains(s, "codexruntimewire.Issue") {
		t.Fatal("broker is missing the sealed runtime forwarding handoff")
	}
}

func TestInstallerBrokerPlistParsesWithDistinctPrincipals(t *testing.T) {
	f, err := os.Open(filepath.Join("..", "..", "deploy", "macos", "com.openduck.codex-broker.plist"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	args, err := brokerPlistArguments(f)
	if err != nil || len(args) < 2 {
		t.Fatalf("plist arguments: %v", err)
	}
	values := map[string]string{
		"CODEX_RUNTIME_ID": "codex-runtime-release", "CODEX_RUNTIME_DIGEST": "sha256:" + strings.Repeat("a", 64), "MODEL_ID": "gpt-5", "KEY_EPOCH": "1",
		"CONTROLLER_UID": "6101", "CONTROLLER_GID": "6201", "BROKER_UID": "6102", "BROKER_GID": "6202", "EGRESS_UID": "6103", "EGRESS_GID": "6203", "RUNTIME_UID": "6104", "RUNTIME_GID": "6204", "BROKER_CHANNEL_GID": "6301", "EGRESS_CHANNEL_GID": "6302", "RUNTIME_CHANNEL_GID": "6303",
	}
	for n := 1; n < len(args); n++ {
		if v, ok := values[args[n]]; ok {
			args[n] = v
		}
	}
	if _, err := parseBrokerOptions(args[1:]); err != nil {
		t.Fatalf("installer broker plist rejected by parser: %v", err)
	}
}

func brokerPlistArguments(r io.Reader) ([]string, error) {
	d := xml.NewDecoder(r)
	inArguments := false
	var args []string
	for {
		tok, err := d.Token()
		if err == io.EOF {
			return args, nil
		}
		if err != nil {
			return nil, err
		}
		switch v := tok.(type) {
		case xml.StartElement:
			if v.Name.Local == "array" {
				inArguments = true
			} else if inArguments && v.Name.Local == "string" {
				var s string
				if err := d.DecodeElement(&s, &v); err != nil {
					return nil, err
				}
				args = append(args, s)
			}
		case xml.EndElement:
			if v.Name.Local == "array" && inArguments {
				return args, nil
			}
		}
	}
}
