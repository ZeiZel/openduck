package main

import (
	"encoding/xml"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRuntimeHasNoControllerOrEgressConnector(t *testing.T) {
	b, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for _, forbidden := range []string{"internal/modelegress", "controller-socket", "egress-socket-root", "connectEgress"} {
		if strings.Contains(s, forbidden) {
			t.Fatalf("runtime must have only the broker-runtime channel, found %q", forbidden)
		}
	}
	if !strings.Contains(s, "codexruntimewire.ReadGrant") || !strings.Contains(s, "NewProductionBackend") {
		t.Fatal("runtime does not own the verified grant and child lifecycle")
	}
}

func TestInstallerRuntimePlistParsesWithDistinctPrincipals(t *testing.T) {
	f, err := os.Open(filepath.Join("..", "..", "deploy", "macos", "com.openduck.codex-runtime.plist"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	args, err := runtimePlistArguments(f)
	if err != nil || len(args) < 2 {
		t.Fatalf("plist arguments: %v", err)
	}
	values := map[string]string{
		"CODEX_RUNTIME_ID": "codex-runtime-release", "MODEL_ID": "gpt-5", "BOOT_ID": "boot-1", "KEY_EPOCH": "1",
		"RUNTIME_UID": "5101", "RUNTIME_GID": "5201", "BROKER_UID": "5102", "BROKER_GID": "5202", "EGRESS_UID": "5103", "EGRESS_GID": "5203", "RUNTIME_CHANNEL_GID": "5301",
	}
	for n := 1; n < len(args); n++ {
		if v, ok := values[args[n]]; ok {
			args[n] = v
		} else if strings.HasSuffix(args[n], "_DIGEST") {
			args[n] = "sha256:" + strings.Repeat("a", 64)
		}
	}
	if _, err := parse(args[1:]); err != nil {
		t.Fatalf("installer runtime plist rejected by parser: %v", err)
	}
}

func runtimePlistArguments(r io.Reader) ([]string, error) {
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
