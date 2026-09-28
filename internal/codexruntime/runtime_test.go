package codexruntime

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"openduck/internal/harness"
)

type scriptedProcess struct {
	scripted
	pid        int
	terminated bool
}

func (p *scriptedProcess) Close() error { return nil }
func (p *scriptedProcess) PID() int     { return p.pid }
func (p *scriptedProcess) Wait() error  { return nil }
func (p *scriptedProcess) Terminate() error {
	p.terminated = true
	return nil
}

type scriptedStarter struct{ process *scriptedProcess }

func (s scriptedStarter) Start(_ context.Context, l Launch) (Process, error) {
	if l.Home == "" || l.Profile.NetworkAccess || l.Profile.ApprovalPolicy != "never" || !strings.Contains(string(l.ProfileRaw), `"network_access":false`) {
		return nil, ErrUnsafeRuntime
	}
	return s.process, nil
}

type scripted struct {
	responses []string
	writes    []string
}

func (s *scripted) Write(p []byte) (int, error) {
	s.writes = append(s.writes, string(p))
	return len(p), nil
}
func (s *scripted) Read(p []byte) (int, error) {
	if len(s.responses) == 0 {
		return 0, errors.New("no response")
	}
	b := []byte(s.responses[0])
	if len(b) > len(p) {
		copy(p, b[:len(p)])
		s.responses[0] = string(b[len(p):])
		return len(p), nil
	}
	copy(p, b)
	s.responses = s.responses[1:]
	return len(b), nil
}

func response(id uint64, result string) string {
	return `{"jsonrpc":"2.0","id":` + itoa(id) + `,"result":` + result + "}\n"
}
func itoa(v uint64) string {
	if v == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for v > 0 {
		i--
		b[i] = byte('0' + v%10)
		v /= 10
	}
	return string(b[i:])
}

func TestProfileIsClosed(t *testing.T) {
	root := t.TempDir()
	root, _ = filepath.EvalSymlinks(root)
	p, d, e := GenerateProfile([]string{root}, []string{root + "/write"})
	if e != nil || d == "" {
		t.Fatal(e)
	}
	if p.NetworkAccess || p.AppsEnabled || p.PluginsEnabled || p.WebEnabled || p.MultiAgentEnabled || p.ApprovalPolicy != "never" {
		t.Fatal("profile widened")
	}
	if _, _, e = GenerateProfile([]string{"relative"}, []string{}); e == nil {
		t.Fatal("relative root accepted")
	}
	if _, _, e = GenerateProfile([]string{"/"}, []string{}); e == nil {
		t.Fatal("broad root accepted")
	}
}

func TestCleanRuntimeEnvironmentDoesNotInheritSecretsOrProxy(t *testing.T) {
	t.Setenv("OPENAI_API_KEY", "should-not-cross-boundary")
	t.Setenv("HTTPS_PROXY", "http://ambient-proxy.invalid")
	t.Setenv("HTTP_PROXY", "http://ambient-proxy.invalid")
	t.Setenv("ALL_PROXY", "socks5://ambient-proxy.invalid")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "should-not-cross-boundary")
	t.Setenv("OTEL_EXPORTER_OTLP_HEADERS", "authorization=secret")
	t.Setenv("CODEX_HOME", "/ambient/codex")
	t.Setenv("HOME", "/ambient/home")
	home := filepath.Join(t.TempDir(), "clean-home")
	env := cleanRuntimeEnvironment(home)
	got := make(map[string]string, len(env))
	for _, entry := range env {
		key, value, ok := strings.Cut(entry, "=")
		if !ok || key == "" {
			t.Fatalf("malformed environment entry %q", entry)
		}
		if _, duplicate := got[key]; duplicate {
			t.Fatalf("duplicate environment key %q", key)
		}
		got[key] = value
	}
	if len(got) != 5 || got["CODEX_HOME"] != home || got["HOME"] != home || got["PATH"] != "/usr/bin:/bin:/usr/sbin:/sbin" || got["LANG"] != "C" || got["LC_ALL"] != "C" {
		t.Fatalf("unexpected clean environment: %#v", got)
	}
	for _, forbidden := range []string{"OPENAI_API_KEY", "HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY", "NO_PROXY", "AWS_SECRET_ACCESS_KEY", "OTEL_EXPORTER_OTLP_HEADERS"} {
		if _, ok := got[forbidden]; ok {
			t.Fatalf("ambient authority %s crossed runtime boundary", forbidden)
		}
	}
}

func TestProtocolOrderingAndApproval(t *testing.T) {
	s := &scripted{responses: []string{response(1, `{}`), response(2, `{"thread":{"id":"th"}}`), response(3, `{"turn":{"id":"turn-1"}}`)}}
	c := NewClient(s)
	ctx := context.Background()
	if e := c.Initialize(ctx, InitializeParams{ProtocolVersion: "v1", ProfileDigest: "d"}); e != nil {
		t.Fatal(e)
	}
	if _, e := c.StartThread(ctx, ThreadParams{WorkOrderDigest: "d"}); e != nil {
		t.Fatal(e)
	}
	if e := c.StartTurn(ctx, TurnParams{ThreadID: "th", WorkOrderDigest: "d", Prompt: "x"}); e != nil {
		t.Fatal(e)
	}
	s.responses = []string{"{\"jsonrpc\":\"2.0\",\"method\":\"approval/request\",\"params\":{}}\n"}
	if _, e := c.ReadCompleted(ctx); !errors.Is(e, ErrApprovalRequested) {
		t.Fatalf("approval %v", e)
	}
}

func TestProtocolOversizeAndMalformed(t *testing.T) {
	s := &scripted{responses: []string{strings.Repeat("x", maxLineBytes+1) + "\n"}}
	c := NewClient(s)
	if _, e := c.call(context.Background(), "initialize", nil); !errors.Is(e, ErrProtocol) {
		t.Fatalf("oversize %v", e)
	}
	s.responses = []string{"not-json\n"}
	if _, e := c.call(context.Background(), "initialize", nil); e == nil {
		t.Fatal("malformed accepted")
	}
}

func TestProtocolUsesCodexAppServerShapes(t *testing.T) {
	s := &scripted{responses: []string{
		response(1, `{}`),
		response(2, `{"thread":{"id":"thread-1"}}`),
		response(3, `{"turn":{"id":"turn-1"}}`),
		`{"method":"item/started","params":{}}
{"method":"item/completed","params":{"item":{"type":"agentMessage","text":"{\"schema_version\":\"worker-result.v1\",\"status\":\"completed\",\"claims\":[],\"change_refs\":[],\"verification\":[],\"deviations\":[],\"residual_risks\":[],\"capabilities_used\":[],\"audit_refs\":[],\"completed_at\":\"2026-08-12T10:00:00Z\"}"}}}
{"method":"turn/completed","params":{"threadId":"thread-1","turn":{"id":"turn-1","status":"completed"}}}
`,
	}}
	c := NewClient(s)
	ctx := context.Background()
	if err := c.Initialize(ctx, InitializeParams{ClientInfo: ClientInfo{Name: "openduck", Version: "test"}}); err != nil {
		t.Fatal(err)
	}
	thread, err := c.StartThread(ctx, ThreadParams{})
	if err != nil || thread != "thread-1" {
		t.Fatalf("thread=%q err=%v", thread, err)
	}
	if err := c.StartTurn(ctx, TurnParams{ThreadID: thread, Prompt: "hello"}); err != nil {
		t.Fatal(err)
	}
	done, err := c.ReadCompleted(ctx)
	if err != nil || done.TurnID != "turn-1" || done.ThreadID != thread {
		t.Fatalf("done=%+v err=%v", done, err)
	}
	var init map[string]any
	if err := json.Unmarshal([]byte(s.writes[0]), &init); err != nil {
		t.Fatal(err)
	}
	params := init["params"].(map[string]any)
	if _, ok := params["clientInfo"]; !ok {
		t.Fatal("clientInfo missing")
	}
	if !strings.Contains(s.writes[1], `"method":"initialized"`) {
		t.Fatal("initialized notification missing")
	}
	if !strings.Contains(s.writes[3], `"threadId":"thread-1"`) || !strings.Contains(s.writes[3], `"input":[{"type":"text","text":"hello"}]`) || !strings.Contains(s.writes[3], `"approvalPolicy":"never"`) {
		t.Fatalf("non-canonical turn params: %s", s.writes[3])
	}
	if strings.Contains(s.writes[2], `"permissions"`) {
		t.Fatalf("unsupported app-server thread field emitted: %s", s.writes[2])
	}
}

func TestProtocolRejectsOutOfOrderEvent(t *testing.T) {
	s := &scripted{responses: []string{"{\"jsonrpc\":\"2.0\",\"method\":\"turn/completed\",\"params\":{}}\n"}}
	c := NewClient(s)
	if _, e := c.call(context.Background(), "initialize", nil); !errors.Is(e, ErrProtocol) {
		t.Fatalf("event accepted as response: %v", e)
	}
}

func TestWorkerResultCannotForgeEvidence(t *testing.T) {
	sh, _ := harness.SHA256("spec")
	w := harness.WorkOrder{WorkOrderID: "wo", TaskID: "task", SpecHash: sh, Role: "codex_implementer", Objective: "test", OwnedResources: []string{}, ContextCapsuleRefs: []string{}, AllowedTools: []string{}, AllowedEffectTypes: []string{}, WorkspaceCapabilityRefs: []string{}, ForbiddenActions: []string{"external_effect"}, AcceptanceChecks: []string{"check"}, EvidenceRequired: []string{"artifact"}, Budgets: map[string]int{"tokens": 1}, Lease: harness.Lease{ID: "lease", ExpiresAt: time.Now().Add(time.Hour).UTC()}, OutputSchema: "worker-result.v1", RuntimeConstraints: []string{"network=false"}, ProfileManifestDigest: sh, SandboxPolicyDigest: sh, WorkspaceDescriptor: "worktree", WorktreeBaseRef: "main"}
	if e := w.Seal(); e != nil {
		t.Fatal(e)
	}
	r := harness.WorkerResult{SchemaVersion: harness.WorkerResultV1, Status: "completed", Claims: []harness.EvidenceClaim{{Claim: "ok", EvidenceRefs: []string{"artifact"}}}, ChangeRefs: []string{"change"}, Verification: []harness.Verification{{CheckID: "check", CommandRef: "cmd", OutputRef: "out"}}, Deviations: []string{}, ResidualRisks: []string{}, CapabilitiesUsed: []string{}, AuditRefs: []string{}, CompletedAt: time.Now().UTC()}
	b, e := harness.BuildEvidenceBundle(w, "task", sh, r)
	if e != nil {
		t.Fatal(e)
	}
	if b.TaskID != "task" || b.WorkOrderID != "wo" || b.SpecHash != sh || b.Digest == "" {
		t.Fatal("controller did not bind evidence")
	}
}

func TestWorkerResultTimingBoundToLeaseAndObservation(t *testing.T) {
	sh, _ := harness.SHA256("spec")
	now := time.Now().UTC().Truncate(time.Microsecond)
	w := harness.WorkOrder{WorkOrderID: "wo", TaskID: "task", SpecHash: sh, Role: "codex_implementer", Objective: "test", OwnedResources: []string{}, ContextCapsuleRefs: []string{}, AllowedTools: []string{}, AllowedEffectTypes: []string{}, WorkspaceCapabilityRefs: []string{}, ForbiddenActions: []string{"external_effect"}, AcceptanceChecks: []string{"check"}, EvidenceRequired: []string{"artifact"}, Budgets: map[string]int{"tokens": 1}, Lease: harness.Lease{ID: "lease", ExpiresAt: now.Add(time.Minute)}, OutputSchema: "worker-result.v1", RuntimeConstraints: []string{"network=false"}, ProfileManifestDigest: sh, SandboxPolicyDigest: sh, WorkspaceDescriptor: "worktree", WorktreeBaseRef: "main"}
	if err := w.Seal(); err != nil {
		t.Fatal(err)
	}
	result := harness.WorkerResult{SchemaVersion: harness.WorkerResultV1, Status: "completed", Claims: []harness.EvidenceClaim{}, ChangeRefs: []string{}, Verification: []harness.Verification{}, Deviations: []string{}, ResidualRisks: []string{}, CapabilitiesUsed: []string{}, AuditRefs: []string{}, CompletedAt: now.Add(time.Second)}
	if _, err := harness.BuildEvidenceBundleAt(w, "task", sh, result, now); !errors.Is(err, harness.ErrLeaseExpired) {
		t.Fatalf("future completion accepted: %v", err)
	}
	result.CompletedAt = now.Add(2 * time.Minute)
	if _, err := harness.BuildEvidenceBundleAt(w, "task", sh, result, now.Add(3*time.Minute)); !errors.Is(err, harness.ErrLeaseExpired) {
		t.Fatalf("post-lease completion accepted: %v", err)
	}
}

func TestRunnerExecutesFrozenOrderAndBuildsObservedBinding(t *testing.T) {
	root := t.TempDir()
	root, _ = filepath.EvalSymlinks(root)
	profile, profileDigest, err := GenerateProfile([]string{root}, []string{root})
	if err != nil || profile.NetworkAccess {
		t.Fatal(err)
	}
	sandboxDigest, _ := harness.SHA256("synthetic-sandbox")
	specHash, _ := harness.SHA256("synthetic-spec")
	order := harness.WorkOrder{WorkOrderID: "wo_synthetic", TaskID: "task_synthetic", SpecHash: specHash, Role: "codex_implementer", Objective: "return bounded evidence", OwnedResources: []string{root}, ContextCapsuleRefs: []string{}, AllowedTools: []string{}, AllowedEffectTypes: []string{}, WorkspaceCapabilityRefs: []string{}, ForbiddenActions: []string{"external_effect", "network"}, AcceptanceChecks: []string{"worker-result"}, EvidenceRequired: []string{"synthetic"}, Budgets: map[string]int{"tokens": 1}, Lease: harness.Lease{ID: "lease_synthetic", ExpiresAt: time.Now().Add(time.Minute).UTC()}, OutputSchema: harness.WorkerResultV1, RuntimeConstraints: []string{"network=false", "approval=never"}, ProfileManifestDigest: profileDigest, SandboxPolicyDigest: sandboxDigest, WorkspaceDescriptor: "synthetic-worktree", WorktreeBaseRef: "main"}
	if err := order.Seal(); err != nil {
		t.Fatal(err)
	}
	workerJSON := `{"schema_version":"worker-result.v1","status":"completed","claims":[],"change_refs":[],"verification":[],"deviations":[],"residual_risks":[],"capabilities_used":[],"audit_refs":[],"completed_at":"2026-08-12T10:00:00Z"}`
	workerText, err := json.Marshal(workerJSON)
	if err != nil {
		t.Fatal(err)
	}
	p := &scriptedProcess{pid: 12345, scripted: scripted{responses: []string{response(1, `{}`), response(2, `{"thread":{"id":"thread-synthetic"}}`), response(3, `{"turn":{"id":"turn-synthetic"}}`), `{"method":"item/completed","params":{"item":{"type":"agentMessage","text":` + string(workerText) + `}}}
{"method":"turn/completed","params":{"threadId":"thread-synthetic","turn":{"id":"turn-synthetic","status":"completed"}}}
`}}}
	runner, err := NewRunner(Config{Binary: "codex", ReadRoots: []string{root}, WriteRoots: []string{root}, Worktree: root, Model: "synthetic", CodexVersion: "test-version", Starter: scriptedStarter{process: p}})
	if err != nil {
		t.Fatal(err)
	}
	result, err := runner.Execute(context.Background(), order)
	if err != nil {
		t.Fatal(err)
	}
	if result.Attestation.WorkOrderID != order.WorkOrderID || result.Attestation.ProcessIdentity != "pid:12345" || result.Attestation.GeneratedProfileDigest != profileDigest || result.Binding.WorkOrderID != order.WorkOrderID || result.Binding.WorkerRuntimeAttestationDigest != result.Attestation.AttestationDigest {
		t.Fatalf("bad observed binding: %+v %+v", result.Attestation, result.Binding)
	}
	if !p.terminated || !strings.Contains(strings.Join(p.writes, ""), order.Digest) {
		t.Fatal("process was not cleaned up or frozen order was not bound to the turn")
	}
}

func TestRunnerRejectsWorkOrderWithEffectsBeforeLaunch(t *testing.T) {
	root := t.TempDir()
	root, _ = filepath.EvalSymlinks(root)
	_, d, err := GenerateProfile([]string{root}, []string{root})
	if err != nil {
		t.Fatal(err)
	}
	sh, _ := harness.SHA256("s")
	policy, _ := harness.SHA256("p")
	order := harness.WorkOrder{WorkOrderID: "wo", TaskID: "task", SpecHash: sh, Role: "codex_implementer", Objective: "x", OwnedResources: []string{}, ContextCapsuleRefs: []string{}, AllowedTools: []string{}, AllowedEffectTypes: []string{"external"}, WorkspaceCapabilityRefs: []string{}, ForbiddenActions: []string{"network"}, AcceptanceChecks: []string{"x"}, EvidenceRequired: []string{"x"}, Budgets: map[string]int{"tokens": 1}, Lease: harness.Lease{ID: "l", ExpiresAt: time.Now().Add(time.Minute).UTC()}, OutputSchema: harness.WorkerResultV1, RuntimeConstraints: []string{"network=false"}, ProfileManifestDigest: d, SandboxPolicyDigest: policy, WorkspaceDescriptor: "w", WorktreeBaseRef: "main"}
	if err := order.Seal(); err != nil {
		t.Fatal(err)
	}
	runner, err := NewRunner(Config{Binary: "codex", ReadRoots: []string{root}, WriteRoots: []string{root}, Worktree: root, Model: "synthetic", CodexVersion: "test", Starter: scriptedStarter{process: &scriptedProcess{pid: 1}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = runner.Execute(context.Background(), order); !errors.Is(err, harness.ErrBindingMismatch) {
		t.Fatalf("effects order reached launcher: %v", err)
	}
}

func TestDispatchAndExecuteBindsObservedRuntimeBeforeEvidence(t *testing.T) {
	ctx := context.Background()
	controller, err := harness.NewController(ctx, &harness.MemoryRepository{})
	if err != nil {
		t.Fatal(err)
	}
	signal := harness.TaskSignal{SignalID: "sig_runtime", SourceRef: "synthetic", SourceVersion: 1, ObservedAt: time.Now().UTC(), Kind: "synthetic", Summary: "bounded", Facts: []harness.Fact{}, Urgency: "normal", MaxClass: "L1", Coverage: harness.Coverage{Complete: true, GapRefs: []string{}}, EvidenceRefs: []string{}, SuggestedRoute: "root", PolicyVersion: "synthetic"}
	if err := signal.Seal(); err != nil {
		t.Fatal(err)
	}
	task, err := controller.IngestSignal(ctx, "task-runtime", signal)
	if err != nil {
		t.Fatal(err)
	}
	draft := harness.TaskSpec{TaskID: task.ID, SpecVersion: 1, Title: "synthetic", Objective: "bounded worker", InScope: []string{"test"}, OutOfScope: []string{"effects"}, Constraints: []string{"network=false"}, AcceptanceChecks: []string{"worker-result"}, EvidenceRequired: []string{"synthetic"}, RiskClass: "L1", AllowedEffectTypes: []string{}, OwnerDecisions: []string{}, Status: "draft"}
	if err := draft.Seal(); err != nil {
		t.Fatal(err)
	}
	task, err = controller.DraftSpec(ctx, task.ID, task.Version, draft)
	if err != nil {
		t.Fatal(err)
	}
	frozen := draft
	frozen.Status = "frozen"
	frozen.ParentSpecHash = draft.SpecHash
	frozen.SpecHash = ""
	if err := frozen.Seal(); err != nil {
		t.Fatal(err)
	}
	task, err = controller.FreezeSpec(ctx, task.ID, task.Version, frozen)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	root, _ = filepath.EvalSymlinks(root)
	_, profileDigest, err := GenerateProfile([]string{root}, []string{root})
	if err != nil {
		t.Fatal(err)
	}
	policy, _ := harness.SHA256("synthetic-sandbox")
	order := harness.WorkOrder{WorkOrderID: "wo-runtime", TaskID: task.ID, SpecHash: frozen.SpecHash, Role: "codex_implementer", Objective: "return bounded evidence", OwnedResources: []string{root}, ContextCapsuleRefs: []string{}, AllowedTools: []string{}, AllowedEffectTypes: []string{}, WorkspaceCapabilityRefs: []string{}, ForbiddenActions: []string{"external_effect", "network"}, AcceptanceChecks: []string{"worker-result"}, EvidenceRequired: []string{"synthetic"}, Budgets: map[string]int{"tokens": 1}, Lease: harness.Lease{ID: "lease-runtime", ExpiresAt: time.Now().Add(time.Minute).UTC()}, OutputSchema: harness.WorkerResultV1, RuntimeConstraints: []string{"network=false", "approval=never"}, ProfileManifestDigest: profileDigest, SandboxPolicyDigest: policy, WorkspaceDescriptor: "synthetic-worktree", WorktreeBaseRef: "main"}
	if err := order.Seal(); err != nil {
		t.Fatal(err)
	}
	workerJSON := `{"schema_version":"worker-result.v1","status":"completed","claims":[],"change_refs":[],"verification":[],"deviations":[],"residual_risks":[],"capabilities_used":[],"audit_refs":[],"completed_at":"2026-08-12T10:00:00Z"}`
	quoted, _ := json.Marshal(workerJSON)
	p := &scriptedProcess{pid: 722, scripted: scripted{responses: []string{response(1, `{}`), response(2, `{"thread":{"id":"thread-runtime"}}`), response(3, `{"turn":{"id":"turn-runtime"}}`), `{"method":"item/completed","params":{"item":{"type":"agentMessage","text":` + string(quoted) + `}}}
{"method":"turn/completed","params":{"threadId":"thread-runtime","turn":{"id":"turn-runtime","status":"completed"}}}
`}}}
	runner, err := NewRunner(Config{Binary: "codex", ReadRoots: []string{root}, WriteRoots: []string{root}, Worktree: root, Model: "synthetic", CodexVersion: "test", Starter: scriptedStarter{process: p}})
	if err != nil {
		t.Fatal(err)
	}
	completed, result, err := DispatchAndExecute(ctx, controller, runner, task.ID, task.Version, order)
	if err != nil {
		t.Fatal(err)
	}
	if completed.State != harness.EvidenceReady || completed.Evidence == nil || completed.Binding == nil || completed.Binding.WorkerRuntimeAttestationDigest != result.Attestation.AttestationDigest || !p.terminated {
		t.Fatalf("runtime lifecycle not bound: task=%+v result=%+v", completed, result)
	}
}

// This is opt-in because it starts the host's experimental app-server. It
// performs initialize only: no model request, account use, task or effect.
func TestLiveCleanAppServerProbe(t *testing.T) {
	if os.Getenv("OPENDUCK_LIVE_APP_SERVER_PROBE") != "1" {
		t.Skip("set OPENDUCK_LIVE_APP_SERVER_PROBE=1 for host probe")
	}
	root := t.TempDir()
	root, _ = filepath.EvalSymlinks(root)
	binary := os.Getenv("OPENDUCK_CODEX_BINARY")
	if binary == "" {
		binary = "codex"
	}
	interpreter := os.Getenv("OPENDUCK_CODEX_INTERPRETER")
	runner, err := NewRunner(Config{Binary: binary, Interpreter: interpreter, ReadRoots: []string{root}, WriteRoots: []string{root}, Worktree: root, Model: "", CodexVersion: "live-probe"})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := runner.Probe(ctx); err != nil {
		t.Fatal(err)
	}
}
