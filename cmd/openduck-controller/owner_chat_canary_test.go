package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"openduck/internal/codexruntime"
	"openduck/internal/ownergrant"
)

func TestWriteCanaryProofBindsReleaseBootRequestAndResult(t *testing.T) {
	path := filepath.Join(t.TempDir(), "canary-proof.json")
	release := strings.Repeat("a", 64)
	request := "sha256:" + strings.Repeat("b", 64)
	result := "sha256:" + strings.Repeat("c", 64)
	if err := writeCanaryProof(path, release, "boot-exact", "run_exact", liveEgressCanaryChatID, request, result); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var proof map[string]any
	if json.Unmarshal(raw, &proof) != nil || len(proof) != 7 || proof["release_id"] != release || proof["boot_id"] != "boot-exact" || proof["run_id"] != "run_exact" || proof["chat_id"] != liveEgressCanaryChatID || proof["request_digest"] != request || proof["result_digest"] != result {
		t.Fatalf("unbound canary proof: %s", raw)
	}
	if err := writeCanaryProof(path, release, "boot-exact", "run_exact", liveEgressCanaryChatID, "bad", result); err == nil {
		t.Fatal("invalid request digest accepted")
	}
}

func ownerOrder(id string) codexruntime.GeneralChatOrder {
	return codexruntime.GeneralChatOrder{SchemaVersion: codexruntime.GeneralChatOrderV1, ChatID: id, Prompt: "hello", Classification: "L0", MaxOutputBytes: 1024, ApprovalPolicy: "never", ReadOnly: true, ToolsDisabled: true, NetworkMode: "model_only", WorkspaceRoots: []string{}}
}
func signedGrant(t *testing.T, order codexruntime.GeneralChatOrder) (*checkpointGrant, string, string, string) {
	t.Helper()
	queue, caps := t.TempDir(), t.TempDir()
	if err := os.Chmod(queue, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(caps, 0700); err != nil {
		t.Fatal(err)
	}
	store, err := ownergrant.OpenCurrentStore(queue)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	digest, err := codexruntime.GeneralChatOrderDigest(order)
	if err != nil {
		t.Fatal(err)
	}
	p, err := store.Request(digest, order.ChatID, time.Now().UTC())
	if !errors.Is(err, ownergrant.ErrApprovalRequired) {
		t.Fatal(err)
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Consume(p.RequestID, caps, "owner.capability", private, os.Geteuid(), os.Getegid(), time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	return &checkpointGrant{public: public, root: caps, prefix: "owner.capability", queue: queue}, p.RequestID, queue, caps
}

func TestCheckpointGrantMismatchDoesNotConsumeFreshValidCapability(t *testing.T) {
	valid := ownerOrder("valid")
	grant, requestID, _, _ := signedGrant(t, valid)
	ctx := codexruntime.WithApprovalRequestID(context.Background(), requestID)
	if err := grant.AuthorizeOrder(ctx, ownerOrder("anonymous")); err == nil {
		t.Fatal("mismatched order authorized")
	}
	if err := grant.AuthorizeOrder(ctx, valid); err != nil {
		t.Fatalf("fresh valid order rejected after mismatch: %v", err)
	}
	if err := grant.AuthorizeOrder(ctx, valid); err == nil {
		t.Fatal("consumed capability reused")
	}
}
func TestCheckpointGrantConcurrentDoubleSpend(t *testing.T) {
	order := ownerOrder("concurrent")
	grant, requestID, _, _ := signedGrant(t, order)
	ctx := codexruntime.WithApprovalRequestID(context.Background(), requestID)
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for range 2 {
		wg.Add(1)
		go func() { defer wg.Done(); results <- grant.AuthorizeOrder(ctx, order) }()
	}
	wg.Wait()
	close(results)
	successes := 0
	for err := range results {
		if err == nil {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("successful spends=%d, want 1", successes)
	}
}
