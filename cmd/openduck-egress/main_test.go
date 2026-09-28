package main

import (
	"encoding/xml"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"openduck/internal/modelegress"
)

func TestRunFailsClosed(t *testing.T) {
	if err := run(nil); err == nil {
		t.Fatal("missing production flag accepted")
	}
	if err := run([]string{"-production-admission"}); err == nil {
		t.Fatalf("err=%v", err)
	}
	args := []string{"-production-admission", "-channel=c", "-socket-root=/tmp/socket", "-release-root=/tmp/release", "-key-root=/tmp/key", "-binary=/tmp/bin", "-policy=sha256:p", "-release-digest=sha256:r", "-socket-digest=sha256:s", "-key-file=k", "-uid=1", "-gid=2", "-peer-uid=3", "-peer-gid=4", "-epoch=1"}
	if err := run(args); err == nil {
		t.Fatal("missing installed roots accepted")
	}
}

func TestInstallerEgressPlistParsesWithDistinctPrincipals(t *testing.T) {
	f, err := os.Open(filepath.Join("..", "..", "deploy", "macos", "com.openduck.egress.plist"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	args, err := egressPlistArguments(f)
	if err != nil || len(args) < 2 {
		t.Fatalf("plist arguments: %v", err)
	}
	values := map[string]string{"EGRESS_UID": "7101", "EGRESS_GID": "7201", "BROKER_UID": "7102", "BROKER_GID": "7202", "EGRESS_CHANNEL_GID": "7301", "KEY_EPOCH": "1", "EGRESS_POLICY_DIGEST": "sha256:" + strings.Repeat("a", 64), "EGRESS_RELEASE_DIGEST": "sha256:" + strings.Repeat("b", 64), "EGRESS_SOCKET_DIGEST": "sha256:" + strings.Repeat("c", 64)}
	for n := 1; n < len(args); n++ {
		if v, ok := values[args[n]]; ok {
			args[n] = v
		}
	}
	opts, err := parseEgressOptions(args[1:])
	if err != nil {
		t.Fatalf("installer egress plist rejected by parser: %v", err)
	}
	if opts.rootGID != opts.localGID || opts.rootGID == opts.channelGID {
		t.Fatalf("egress verified roots use shared channel gid: %+v", opts)
	}
}

func TestComposePolicyPinValidationRequiresExactPolicyReleaseAndSocketDigests(t *testing.T) {
	release := "sha256:" + strings.Repeat("b", 64)
	socket := "sha256:" + strings.Repeat("c", 64)
	policy, err := modelegress.NewPolicy([]string{"api.openai.com"}, 7101, 7201, release, socket, 1)
	if err != nil {
		t.Fatal(err)
	}
	policyDigest, err := policy.Digest()
	if err != nil {
		t.Fatal(err)
	}
	opts := egressOptions{policyDigest: policyDigest, releaseDigest: release, socketDigest: socket, localUID: 7101, localGID: 7201, epoch: 1}
	if err := validatePolicyPins(opts, policy); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*egressOptions){
		func(o *egressOptions) { o.policyDigest = "sha256:" + strings.Repeat("d", 64) },
		func(o *egressOptions) { o.releaseDigest = "sha256:" + strings.Repeat("d", 64) },
		func(o *egressOptions) { o.socketDigest = "sha256:" + strings.Repeat("d", 64) },
	} {
		bad := opts
		mutate(&bad)
		if err := validatePolicyPins(bad, policy); err == nil {
			t.Fatal("mismatched compose policy pin accepted")
		}
	}
}

func egressPlistArguments(r io.Reader) ([]string, error) {
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
