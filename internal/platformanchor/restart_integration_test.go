package platformanchor_test

import (
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"openduck/internal/codexruntime"
	"openduck/internal/platformanchor"
)

type transportMode int

const (
	dropAfterCommit transportMode = iota
	dropBeforeCommit
)

// faultTransport is deliberately a connection-level seam. The first n
// requests are either committed and lose their response, or are dropped
// before reaching the server. Later requests use the real synthetic server.
type faultTransport struct {
	mu        sync.Mutex
	remaining int
	mode      transportMode
	store     *platformanchor.Store
	server    *platformanchor.Server
	peer      platformanchor.SyntheticPeer
}

func (t *faultTransport) dial(context.Context) (net.Conn, error) {
	client, server := net.Pipe()
	t.mu.Lock()
	drop := t.remaining > 0
	commit := drop && t.mode == dropAfterCommit && t.remaining == 2
	if drop {
		t.remaining--
	}
	t.mu.Unlock()
	if drop {
		go func() {
			defer server.Close()
			var req platformanchor.Request
			if platformanchor.ReadFrame(server, &req) != nil {
				return
			}
			if commit {
				_, _ = t.store.Request(req)
			}
		}()
		return client, nil
	}
	go func() { _ = t.server.ServeConn(context.Background(), server) }()
	return client, nil
}

func newChatFixture(t *testing.T, mode transportMode, drops int) (string, string, string, *platformanchor.Store, *faultTransport) {
	t.Helper()
	root := t.TempDir()
	state := filepath.Join(root, "anchor-state")
	checkpoint := filepath.Join(root, "anchor-checkpoint")
	store, err := platformanchor.NewSyntheticStoreWithCheckpoint(state, mustCheckpoint(t, checkpoint))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	server, err := platformanchor.NewSyntheticServer(store, platformanchor.SyntheticPeer{UID: 1, Executable: "synthetic", Socket: "pipe"})
	if err != nil {
		t.Fatal(err)
	}
	transport := &faultTransport{remaining: drops, mode: mode, store: store, server: server, peer: platformanchor.SyntheticPeer{UID: 1, Executable: "synthetic", Socket: "pipe"}}
	return root, filepath.Join(root, "ledger.enc"), checkpoint, store, transport
}

func mustCheckpoint(t *testing.T, dir string) platformanchor.AnchorCheckpoint {
	t.Helper()
	cp, err := platformanchor.NewSyntheticFileCheckpoint(dir)
	if err != nil {
		t.Fatal(err)
	}
	return cp
}

func newLedger(t *testing.T, path string, transport *faultTransport) (*codexruntime.ChatRunLedger, *platformanchor.Client) {
	t.Helper()
	client, err := platformanchor.NewSyntheticClient(transport.dial, transport.peer)
	if err != nil {
		t.Fatal(err)
	}
	cp, err := platformanchor.NewChatLedgerCheckpoint(client)
	if err != nil {
		t.Fatal(err)
	}
	key := []byte("01234567890123456789012345678901")
	ledger, err := codexruntime.NewEncryptedChatRunLedgerWithCheckpoint(path, key, cp)
	if err != nil {
		t.Fatal(err)
	}
	return ledger, client
}

func TestChatLedgerReconcileAfterCommittedLostReplyAndRestart(t *testing.T) {
	root, ledgerPath, checkpointPath, store, transport := newChatFixture(t, dropAfterCommit, 2)
	ledger, _ := newLedger(t, ledgerPath, transport)
	_, pending, err := ledger.BeginPending("chat-1", "token-1", time.Unix(100, 0))
	if !pending.Valid() {
		t.Fatalf("pending=%+v", pending)
	}
	if !errors.Is(err, platformanchor.ErrUncertain) {
		t.Fatalf("expected uncertain begin, got %v", err)
	}
	version, digest, err := mustLoadCheckpoint(t, checkpointPath)
	if err != nil || version != 1 || digest == "" {
		t.Fatalf("anchor after lost reply: version=%d digest=%q err=%v", version, digest, err)
	}
	_ = store.Close()

	restartedStore, err := platformanchor.NewSyntheticStoreWithCheckpoint(filepath.Join(root, "anchor-state"), mustCheckpoint(t, checkpointPath))
	if err != nil {
		t.Fatal(err)
	}
	defer restartedStore.Close()
	restartedServer, err := platformanchor.NewSyntheticServer(restartedStore, transport.peer)
	if err != nil {
		t.Fatal(err)
	}
	transport.store, transport.server, transport.remaining = restartedStore, restartedServer, 0
	restarted, _ := newLedger(t, ledgerPath, transport)
	record, err := restarted.ReconcilePendingCAS(pending)
	if err != nil || record.RunID != pending.RunID || record.State != "pending" {
		t.Fatalf("reconcile record=%+v err=%v", record, err)
	}
	version, reconciledDigest, err := mustLoadCheckpoint(t, checkpointPath)
	if err != nil || version != 1 || reconciledDigest != digest {
		t.Fatalf("anchor after reconcile: version=%d digest=%q err=%v", version, digest, err)
	}
}

func TestChatLedgerReconcileRetryWhenRequestWasNotCommitted(t *testing.T) {
	root, ledgerPath, checkpointPath, store, transport := newChatFixture(t, dropBeforeCommit, 2)
	ledger, _ := newLedger(t, ledgerPath, transport)
	_, pending, err := ledger.BeginPending("chat-2", "token-2", time.Unix(200, 0))
	if !pending.Valid() || !errors.Is(err, platformanchor.ErrUncertain) {
		t.Fatalf("begin pending=%+v err=%v", pending, err)
	}
	initialVersion, initialDigest, loadErr := mustLoadCheckpoint(t, checkpointPath)
	if loadErr != nil || initialVersion != 0 || initialDigest == "" {
		t.Fatalf("uncommitted anchor: version=%d digest=%q err=%v", initialVersion, initialDigest, loadErr)
	}
	_ = store.Close()
	restartedStore, err := platformanchor.NewSyntheticStoreWithCheckpoint(filepath.Join(root, "anchor-state"), mustCheckpoint(t, checkpointPath))
	if err != nil {
		t.Fatal(err)
	}
	defer restartedStore.Close()
	restartedServer, err := platformanchor.NewSyntheticServer(restartedStore, transport.peer)
	if err != nil {
		t.Fatal(err)
	}
	transport.store, transport.server, transport.remaining = restartedStore, restartedServer, 0
	restarted, _ := newLedger(t, ledgerPath, transport)
	if _, err := restarted.ReconcilePendingCAS(pending); err != nil {
		t.Fatal(err)
	}
	if version, digest, loadErr := mustLoadCheckpoint(t, checkpointPath); loadErr != nil || version != 1 || digest == initialDigest {
		t.Fatalf("retried anchor: version=%d digest=%q err=%v", version, digest, loadErr)
	}
}

func TestChatLedgerRejectsWrongDigestAndVersionEquivocation(t *testing.T) {
	_, ledgerPath, checkpointPath, _, transport := newChatFixture(t, dropAfterCommit, 0)
	ledger, _ := newLedger(t, ledgerPath, transport)
	_, pending, err := ledger.BeginPending("chat-3", "token-3", time.Unix(300, 0))
	if err != nil {
		t.Fatal(err)
	}
	wrongDigest := pending
	wrongDigest.Digest = codexruntime.ChatAnswerDigest("equivocated")
	if _, err := ledger.ReconcilePendingCAS(wrongDigest); err == nil {
		t.Fatal("wrong digest unexpectedly reconciled")
	}
	wrongVersion := pending
	wrongVersion.Expected, wrongVersion.Next = 2, 3
	if _, err := ledger.ReconcilePendingCAS(wrongVersion); err == nil {
		t.Fatal("wrong version unexpectedly reconciled")
	}
	version, digest, err := mustLoadCheckpoint(t, checkpointPath)
	if err != nil || version != 1 || digest == "" {
		t.Fatalf("equivocation changed anchor: version=%d digest=%q err=%v", version, digest, err)
	}
}

func mustLoadCheckpoint(t *testing.T, dir string) (uint64, string, error) {
	t.Helper()
	cp, err := platformanchor.NewSyntheticFileCheckpoint(dir)
	if err != nil {
		return 0, "", err
	}
	return cp.Load()
}

func TestAnchorCLIReusesCheckpointAndCleansStaleSocket(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("unix socket fixture")
	}
	bin := filepath.Join(t.TempDir(), "openduck-anchor")
	cmdDir, err := filepath.Abs(filepath.Join("..", "..", "cmd", "openduck-anchor"))
	if err != nil {
		t.Fatal(err)
	}
	build := exec.Command("go", "build", "-o", bin, ".")
	build.Dir = cmdDir
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	if err := os.Chmod(bin, 0700); err != nil {
		t.Fatal(err)
	}
	root, err := os.MkdirTemp("/private/tmp", "od-anchor-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	state, checkpoint := filepath.Join(root, "state"), filepath.Join(root, "checkpoint")
	socket := filepath.Join(state, "anchor.sock")
	args := []string{"-synthetic", "-state", state, "-socket", socket, "-checkpoint", checkpoint}
	start := func() *exec.Cmd {
		cmd := exec.Command(bin, args...)
		var output bytes.Buffer
		cmd.Stdout, cmd.Stderr = &output, &output
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		for i := 0; i < 300; i++ {
			if _, err := os.Stat(socket); err == nil {
				if conn, dialErr := net.DialTimeout("unix", socket, 25*time.Millisecond); dialErr == nil {
					_ = conn.Close()
					return cmd
				}
			}
			time.Sleep(10 * time.Millisecond)
		}
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		outputText := output.String()
		if strings.Contains(outputText, "operation not permitted") {
			t.Skipf("Unix socket unavailable in current execution sandbox: %s", outputText)
		}
		t.Fatalf("anchor socket did not appear: %s", outputText)
		return nil
	}
	first := start()
	client, err := platformanchor.NewSyntheticClient(func(context.Context) (net.Conn, error) { return net.Dial("unix", socket) }, platformanchor.SyntheticPeer{UID: 1, Executable: "fixture", Socket: socket})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Do(context.Background(), platformanchor.Request{SchemaVersion: platformanchor.SchemaVersion, RequestID: "cli-1", Namespace: platformanchor.NamespaceChat, Operation: "cas", Key: "run", ExpectedVersion: 0, NextVersion: 1, Digest: codexruntime.ChatAnswerDigest("cli")}); err != nil {
		t.Fatal(err)
	}
	_ = first.Process.Kill()
	_ = first.Wait()
	second := start()
	defer func() { _ = second.Process.Kill(); _ = second.Wait() }()
	resp, err := client.Do(context.Background(), platformanchor.Request{SchemaVersion: platformanchor.SchemaVersion, RequestID: "cli-load", Namespace: platformanchor.NamespaceChat, Operation: "load", Key: "run"})
	if err != nil || resp.Version != 1 || resp.Digest != codexruntime.ChatAnswerDigest("cli") {
		t.Fatalf("restart response=%+v err=%v", resp, err)
	}
}

func TestCanonicalizeAllowMissingRejectsPhysicalAliasAndSymlink(t *testing.T) {
	physicalVar, err := filepath.EvalSymlinks("/var")
	if err == nil && physicalVar != "/var" {
		logical := filepath.Join("/var", "openduck-nonexistent", "checkpoint")
		got, err := platformanchor.CanonicalizeAllowMissing(logical)
		want := filepath.Join(physicalVar, "openduck-nonexistent", "checkpoint")
		if err != nil || got != want {
			t.Fatalf("canonical /var alias: got=%q want=%q err=%v", got, want, err)
		}
	}
	base := t.TempDir()
	target := filepath.Join(base, "target")
	if err := os.Mkdir(target, 0700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := platformanchor.CanonicalizeAllowMissing(filepath.Join(link, "missing")); !errors.Is(err, platformanchor.ErrUnavailable) {
		t.Fatalf("non-system symlink accepted: %v", err)
	}
}
