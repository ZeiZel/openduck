// Command openduck-auth-canary performs a local, synthetic two-phase owner-auth
// probe. It never connects to Controller, reads accounts, or executes effects.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"openduck/internal/harness"
	"openduck/internal/nativeconfirm"
	"openduck/internal/ownerauth"
)

type canaryAuthority struct{}

func (canaryAuthority) Authorize(context.Context, string, string) (string, string, error) {
	return "synthetic-owner", "synthetic-proof-reference", nil
}

func runCanary(ctx context.Context, helperPath, digest string, timeout time.Duration) error {
	preview := []byte(`{"kind":"openduck-auth-canary","effect":"none"}`)
	destination := []byte(`{"channel":"synthetic","id":"canary"}`)
	previewDigest, err := harness.SHA256(json.RawMessage(preview))
	if err != nil {
		return err
	}
	if _, err := harness.SHA256(json.RawMessage(destination)); err != nil {
		return err
	}
	challenge := harness.DecisionChallenge{SchemaVersion: "decision-challenge.v1", SessionID: "canary-session", DisplayInstanceID: "canary-display", PreviewDigest: previewDigest, ExpiresAt: time.Now().Add(timeout).UTC()}
	adapter := nativeconfirm.NewOwnerAuthAdapter(ownerauth.Config{Path: helperPath, SHA256: digest, Timeout: timeout, Authority: canaryAuthority{}})
	ack, err := adapter.Render(ctx, nativeconfirm.RenderRequest{TaskID: "synthetic-canary", SessionID: challenge.SessionID, PreviewBytes: preview, PreviewDigest: previewDigest, DestinationSummary: destination, Challenge: challenge})
	if err != nil || ack.SessionID != challenge.SessionID || ack.DisplayNonce == "" || ack.PreviewDigest != previewDigest {
		adapter.Cancel(context.Background(), challenge.SessionID)
		return fmt.Errorf("render probe failed")
	}
	final := challenge
	final.DisplayNonce = ack.DisplayNonce
	result, err := adapter.Authenticate(ctx, nativeconfirm.AuthenticateRequest{TaskID: "synthetic-canary", SessionID: challenge.SessionID, Challenge: final})
	if err != nil || result.SessionID != challenge.SessionID || (result.Decision != "approve" && result.Decision != "reject") {
		adapter.Cancel(context.Background(), challenge.SessionID)
		return fmt.Errorf("authenticate probe failed")
	}
	return nil
}

func main() {
	helper := flag.String("helper", "", "absolute pinned helper executable")
	digest := flag.String("sha256", "", "trusted helper SHA-256 digest")
	timeout := flag.Duration("timeout", 90*time.Second, "synthetic probe deadline")
	flag.Parse()
	if *helper == "" || *digest == "" || *timeout <= 0 || *timeout > 5*time.Minute {
		fmt.Println("FAIL")
		os.Exit(2)
	}
	if err := runCanary(context.Background(), *helper, *digest, *timeout); err != nil {
		fmt.Println("FAIL")
		os.Exit(1)
	}
	fmt.Println("PASS")
}
