package ownerauth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func helper(t *testing.T, body string) (string, string) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "helper.sh")
	if err := os.Chmod(filepath.Dir(p), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+body+"\n"), 0700); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(b)
	return p, hex.EncodeToString(h[:])
}

func request() Request {
	return Request{SessionID: "s1", DisplayInstance: "d1", ActionType: "reply.send", Title: "Synthetic approval", PreviewText: "Preview", Destination: "telegram:chat-1", Risk: "L1", ExpiresAt: "2026-08-13T01:00:00Z", PreviewDigest: stringsRepeat("a", 64), DestinationDigest: stringsRepeat("b", 64), Challenge: "c1", ProofRef: "opaque:controller-proof"}
}

func TestRunFakeHelper(t *testing.T) {
	p, hash := helper(t, `read line; awk 'BEGIN{print "{\"type\":\"rendered\",\"session_id\":\"s1\",\"display_instance_id\":\"d1\",\"display_nonce\":\"n1\",\"preview_digest\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"destination_digest\":\"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\"}"}'; read line; awk 'BEGIN{print "{\"type\":\"decision\",\"result\":{\"decision\":\"reject\",\"challenge\":\"c1\",\"session_id\":\"s1\",\"display_instance_id\":\"d1\",\"timestamp\":\"2026-08-13T00:00:00Z\"}}"}'`)
	r, err := (Config{Path: p, SHA256: hash, Timeout: 3 * time.Second}).Run(context.Background(), request())
	if err != nil || r.Decision != "reject" || r.ProofRef != request().ProofRef {
		t.Fatalf("result=%+v err=%v", r, err)
	}
}

func TestRejectHashAndSymlink(t *testing.T) {
	p, hash := helper(t, `:`)
	if _, err := (Config{Path: p, SHA256: stringsRepeat("0", 64)}).Run(context.Background(), request()); err == nil {
		t.Fatal("expected hash rejection")
	}
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(p, link); err != nil {
		t.Fatal(err)
	}
	if _, err := (Config{Path: link, SHA256: hash}).Run(context.Background(), request()); err == nil {
		t.Fatal("expected symlink rejection")
	}
}

func TestVerifiedDescriptorSurvivesPathSwap(t *testing.T) {
	p, hash := helper(t, `read line; printf '%s\n' '{"type":"rendered","session_id":"s1","display_instance_id":"d1","display_nonce":"n1","preview_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","destination_digest":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}'; read line; printf '%s\n' '{"type":"decision","result":{"decision":"reject","challenge":"c1","session_id":"s1","display_instance_id":"d1","timestamp":"2026-08-13T00:00:00Z"}}'`)
	old := p + ".old"
	verifiedHook = func() {
		if err := os.Rename(p, old); err != nil {
			t.Errorf("swap old: %v", err)
			return
		}
		if err := os.WriteFile(p, []byte("#!/bin/sh\nread line; printf '%s\\n' '{\"type\":\"rendered\",\"session_id\":\"s1\",\"display_instance_id\":\"d1\",\"display_nonce\":\"n1\",\"preview_digest\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"destination_digest\":\"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\"}'; read line; printf '%s\\n' '{\"type\":\"decision\",\"result\":{\"decision\":\"approve\",\"challenge\":\"c1\",\"session_id\":\"s1\",\"display_instance_id\":\"d1\",\"timestamp\":\"2026-08-13T00:00:00Z\"}}'\n"), 0700); err != nil {
			t.Errorf("swap new: %v", err)
		}
	}
	defer func() { verifiedHook = nil }()
	r, err := (Config{Path: p, SHA256: hash, Timeout: 3 * time.Second}).Run(context.Background(), request())
	if err != nil || r.Decision != "reject" {
		t.Fatalf("descriptor was not executed: result=%+v err=%v", r, err)
	}
}

func TestRejectsPathSwapBeforeHardLink(t *testing.T) {
	p, hash := helper(t, `:`)
	old := p + ".old"
	beforeLinkHook = func() {
		if err := os.Rename(p, old); err != nil {
			t.Errorf("swap old: %v", err)
			return
		}
		_ = os.WriteFile(p, []byte("#!/bin/sh\n:"), 0700)
	}
	defer func() { beforeLinkHook = nil }()
	if _, err := (Config{Path: p, SHA256: hash}).Run(context.Background(), request()); err == nil {
		t.Fatal("expected pre-link replacement rejection")
	}
}

func TestCleanupDoesNotRemoveReplacement(t *testing.T) {
	p, hash := helper(t, `:`)
	v, err := openVerifiedExecutable(p, hash)
	if err != nil {
		t.Fatal(err)
	}
	path := v.path
	if err := v.file.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("replacement"), 0700); err != nil {
		t.Fatal(err)
	}
	v.cleanup()
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("replacement was removed: %v", err)
	}
}

func TestRejectUnsafeParentDirectory(t *testing.T) {
	p, hash := helper(t, `:`)
	parent := filepath.Dir(p)
	if err := os.Chmod(parent, 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := (Config{Path: p, SHA256: hash}).Run(context.Background(), request()); err == nil {
		t.Fatal("expected non-private parent rejection")
	}
	private := t.TempDir()
	if err := os.Chmod(private, 0700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "private-link")
	if err := os.Symlink(private, link); err != nil {
		t.Fatal(err)
	}
	linked := filepath.Join(link, "helper.sh")
	if err := os.WriteFile(linked, []byte("#!/bin/sh\n:"), 0700); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(linked)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(b)
	if _, err := (Config{Path: linked, SHA256: hex.EncodeToString(sum[:])}).Run(context.Background(), request()); err == nil {
		t.Fatal("expected symlinked parent rejection")
	}
}

func TestOverflowAndTimeout(t *testing.T) {
	p, hash := helper(t, `head -c 70000 /dev/zero`)
	if _, err := (Config{Path: p, SHA256: hash, Timeout: time.Second}).Run(context.Background(), request()); err == nil {
		t.Fatal("expected overflow rejection")
	}
	p, hash = helper(t, `sleep 3`)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := (Config{Path: p, SHA256: hash, Timeout: time.Second}).Run(ctx, request()); err == nil {
		t.Fatal("expected timeout")
	}
}

func TestMalformedProtocol(t *testing.T) {
	p, hash := helper(t, `read line; awk 'BEGIN{print "not-json"}'`)
	if _, err := (Config{Path: p, SHA256: hash, Timeout: time.Second}).Run(context.Background(), request()); err == nil {
		t.Fatal("expected malformed protocol rejection")
	}
}

func stringsRepeat(s string, n int) string {
	out := ""
	for i := 0; i < n; i++ {
		out += s
	}
	return out
}
