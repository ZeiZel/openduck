package codexruntime

// This file owns the Controller-launched Codex app-server worker boundary.  It
// deliberately does not know about owner decisions, external effects, or any
// account credentials.  A caller supplies a frozen WorkOrder and receives a
// worker-authored, schema-checked result plus facts observed from the process
// it started.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"openduck/internal/harness"
)

var (
	ErrLaunch        = errors.New("codex runtime launch failed")
	ErrUnsafeRuntime = errors.New("unsafe codex runtime configuration")
)

// Process is the small process surface needed by Runner.  It is intentionally
// injectable: protocol and binding tests never need a real Codex account.
type Process interface {
	io.ReadWriteCloser
	PID() int
	Wait() error
	Terminate() error
}

type Starter interface {
	Start(context.Context, Launch) (Process, error)
}

type Launch struct {
	Binary      string
	Interpreter string
	Home        string
	Worktree    string
	Profile     Profile
	ProfileRaw  []byte
}

// Config is intentionally explicit.  Roots must belong to the task-specific
// worktree; ambient user roots, plugins, apps and network are rejected before
// a process can be launched.
type Config struct {
	Binary string
	// Interpreter is an optional, explicit absolute launcher (for example the
	// pinned node binary when Binary is the Codex JavaScript entrypoint). It is
	// never discovered through ambient PATH.
	Interpreter  string
	ReadRoots    []string
	WriteRoots   []string
	Worktree     string
	Model        string
	CodexVersion string // observed by a separate probe; never model supplied
	Starter      Starter
}

type Runner struct{ cfg Config }

func NewRunner(cfg Config) (*Runner, error) {
	if cfg.Binary == "" || cfg.Worktree == "" || !filepath.IsAbs(cfg.Worktree) || filepath.Clean(cfg.Worktree) != cfg.Worktree {
		return nil, ErrUnsafeRuntime
	}
	if cfg.Interpreter != "" && (!filepath.IsAbs(cfg.Interpreter) || filepath.Clean(cfg.Interpreter) != cfg.Interpreter) {
		return nil, ErrUnsafeRuntime
	}
	if cfg.Starter == nil {
		cfg.Starter = execStarter{}
	}
	profile, _, err := GenerateProfile(cfg.ReadRoots, cfg.WriteRoots)
	if err != nil || !withinRoots(cfg.Worktree, cfg.ReadRoots) || !withinRoots(cfg.Worktree, cfg.WriteRoots) {
		return nil, ErrUnsafeRuntime
	}
	_ = profile
	return &Runner{cfg: cfg}, nil
}

func withinRoots(path string, roots []string) bool {
	for _, root := range roots {
		if path == root || strings.HasPrefix(path, root+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

// Probe verifies only that a fresh private CODEX_HOME can start the pinned
// stdio app-server and complete JSON-RPC initialization. It sends no turn,
// does not require an account, and cannot execute a WorkOrder or effect.
func (r *Runner) Probe(ctx context.Context) error {
	profile, _, err := GenerateProfile(r.cfg.ReadRoots, r.cfg.WriteRoots)
	if err != nil {
		return ErrUnsafeRuntime
	}
	home, raw, err := cleanHome(profile)
	if err != nil {
		return err
	}
	defer os.RemoveAll(home)
	p, err := r.cfg.Starter.Start(ctx, Launch{Binary: r.cfg.Binary, Interpreter: r.cfg.Interpreter, Home: home, Worktree: r.cfg.Worktree, Profile: profile, ProfileRaw: raw})
	if err != nil {
		return fmt.Errorf("%w: %v", ErrLaunch, err)
	}
	defer func() { _ = p.Terminate(); _ = p.Wait() }()
	if err := NewClient(p).Initialize(ctx, InitializeParams{ClientInfo: ClientInfo{Name: "openduck-probe", Version: "0.1.0"}}); err != nil {
		return err
	}
	return nil
}

type Result struct {
	WorkerResult harness.WorkerResult
	Attestation  harness.WorkerRuntimeAttestation
	Binding      harness.WorkerDispatchBinding
}

// Session is a single-use, Controller-owned runtime. It is deliberately not
// serializable and its process/stdin handles never leave this package.
type Session struct {
	runner      *Runner
	order       harness.WorkOrder
	process     Process
	client      *Client
	home        string
	profileHash string
	attestation harness.WorkerRuntimeAttestation
	binding     harness.WorkerDispatchBinding
	mu          sync.Mutex
	used        bool
	closed      bool
}

func (s *Session) Attestation() harness.WorkerRuntimeAttestation { return s.attestation }
func (s *Session) Binding() harness.WorkerDispatchBinding        { return s.binding }

// Prepare observes a fresh process identity before dispatch. The caller must
// bind the returned attestation with Controller.Dispatch before invoking Run.
func (r *Runner) Prepare(ctx context.Context, order harness.WorkOrder) (*Session, error) {
	if err := order.Validate(); err != nil || order.Role != "codex_implementer" || order.OutputSchema != harness.WorkerResultV1 || hasEffect(order.AllowedEffectTypes) {
		return nil, harness.ErrBindingMismatch
	}
	profile, profileDigest, err := GenerateProfile(r.cfg.ReadRoots, r.cfg.WriteRoots)
	if err != nil || profileDigest != order.ProfileManifestDigest || profile.ApprovalPolicy != "never" || profile.NetworkAccess {
		return nil, ErrUnsafeRuntime
	}
	home, rawProfile, err := cleanHome(profile)
	if err != nil {
		return nil, err
	}
	process, err := r.cfg.Starter.Start(ctx, Launch{Binary: r.cfg.Binary, Interpreter: r.cfg.Interpreter, Home: home, Worktree: r.cfg.Worktree, Profile: profile, ProfileRaw: rawProfile})
	if err != nil {
		_ = os.RemoveAll(home)
		return nil, fmt.Errorf("%w: %v", ErrLaunch, err)
	}
	attestation, binding, err := r.attest(order, profileDigest, rawProfile, process.PID())
	if err != nil {
		_ = process.Terminate()
		_ = process.Wait()
		_ = os.RemoveAll(home)
		return nil, err
	}
	return &Session{runner: r, order: order, process: process, client: NewClient(process), home: home, profileHash: profileDigest, attestation: attestation, binding: binding}, nil
}

// Execute starts a fresh app-server, never resumes a prior thread, and accepts
// exactly one JSON WorkerResult agent message.  The WorkOrder digest is placed
// in the prompt solely as an integrity instruction; Controller-side binding is
// still the authority for task/spec identity and evidence.
func (r *Runner) Execute(ctx context.Context, order harness.WorkOrder) (Result, error) {
	session, err := r.Prepare(ctx, order)
	if err != nil {
		return Result{}, err
	}
	defer session.Close()
	result, err := session.Run(ctx)
	if err != nil {
		return Result{}, err
	}
	return Result{WorkerResult: result, Attestation: session.attestation, Binding: session.binding}, nil
}

// Run consumes the prepared session exactly once. It must be called only after
// the Controller has persisted the matching dispatch binding and transitioned
// the task to WORK_RUNNING.
func (s *Session) Run(ctx context.Context) (harness.WorkerResult, error) {
	s.mu.Lock()
	if s.used || s.closed {
		s.mu.Unlock()
		return harness.WorkerResult{}, ErrProtocol
	}
	s.used = true
	s.mu.Unlock()
	// Ensure cancellation can interrupt a blocked stdio read on real processes.
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = s.client.Close()
		case <-done:
		}
	}()
	defer close(done)
	if err := s.client.Initialize(ctx, InitializeParams{ClientInfo: ClientInfo{Name: "openduck-worker", Version: "0.1.0"}}); err != nil {
		return harness.WorkerResult{}, err
	}
	thread, err := s.client.StartThread(ctx, ThreadParams{CWD: s.runner.cfg.Worktree, Model: s.runner.cfg.Model, ApprovalPolicy: "never", Sandbox: "workspace-write"})
	if err != nil {
		return harness.WorkerResult{}, err
	}
	prompt := workerPrompt(s.order)
	if err = s.client.StartTurn(ctx, TurnParams{ThreadID: thread, WorkOrderDigest: s.order.Digest, Prompt: prompt, OutputSchema: workerResultSchema(), ApprovalPolicy: "never", CWD: s.runner.cfg.Worktree, Model: s.runner.cfg.Model, SandboxPolicy: map[string]any{"type": "workspaceWrite", "networkAccess": false, "writableRoots": append([]string(nil), s.runner.cfg.WriteRoots...), "excludeSlashTmp": true, "excludeTmpdirEnvVar": true}}); err != nil {
		return harness.WorkerResult{}, err
	}
	completed, err := s.client.ReadCompleted(ctx)
	if err != nil {
		return harness.WorkerResult{}, err
	}
	if completed.ThreadID != thread || completed.WorkerResult.Validate() != nil {
		return harness.WorkerResult{}, ErrProtocol
	}
	return completed.WorkerResult, nil
}

func workerResultSchema() map[string]any {
	return map[string]any{
		"type": "object", "additionalProperties": false,
		"required": []string{"schema_version", "status", "claims", "change_refs", "verification", "deviations", "residual_risks", "capabilities_used", "audit_refs", "completed_at"},
		"properties": map[string]any{
			"schema_version": map[string]any{"const": harness.WorkerResultV1}, "status": map[string]any{"const": "completed"},
			"claims": map[string]any{"type": "array"}, "change_refs": map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
			"verification": map[string]any{"type": "array"}, "deviations": map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
			"residual_risks": map[string]any{"type": "array", "items": map[string]any{"type": "string"}}, "capabilities_used": map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
			"audit_refs": map[string]any{"type": "array", "items": map[string]any{"type": "string"}}, "completed_at": map[string]any{"type": "string"},
		},
	}
}

func (s *Session) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	s.mu.Unlock()
	_ = s.client.Close()
	if err := s.process.Terminate(); err != nil {
		_ = os.RemoveAll(s.home)
		return err
	}
	if err := s.process.Wait(); err != nil {
		if _, ok := err.(*exec.ExitError); !ok {
			_ = os.RemoveAll(s.home)
			return fmt.Errorf("%w: process wait", ErrLaunch)
		}
	}
	return os.RemoveAll(s.home)
}

func workerPrompt(order harness.WorkOrder) string {
	// The worker never receives Controller secrets or an approval capability.
	return "Execute only this frozen synthetic WorkOrder. Do not request approvals, use network, or perform external effects. Return exactly one JSON object conforming to worker-result.v1. WorkOrder digest: " + order.Digest
}

func hasEffect(effects []string) bool { return len(effects) != 0 }

func cleanHome(profile Profile) (string, []byte, error) {
	home, err := os.MkdirTemp("", "openduck-codex-home-")
	if err != nil {
		return "", nil, err
	}
	if err = os.Chmod(home, 0700); err != nil {
		_ = os.RemoveAll(home)
		return "", nil, err
	}
	raw, err := harness.CanonicalJSON(profile)
	if err != nil {
		_ = os.RemoveAll(home)
		return "", nil, err
	}
	// An empty, private home is intentional.  Do not copy auth, plugins, skills,
	// hooks or user config into it.  The JSON profile is an audit artifact rather
	// than a Codex config file, so unknown config keys cannot silently widen it.
	if err = os.WriteFile(filepath.Join(home, "openduck-runtime-profile.json"), raw, 0600); err != nil {
		_ = os.RemoveAll(home)
		return "", nil, err
	}
	return home, raw, nil
}

func (r *Runner) attest(order harness.WorkOrder, profileDigest string, profileRaw []byte, pid int) (harness.WorkerRuntimeAttestation, harness.WorkerDispatchBinding, error) {
	if pid <= 0 || r.cfg.CodexVersion == "" {
		return harness.WorkerRuntimeAttestation{}, harness.WorkerDispatchBinding{}, ErrUnsafeRuntime
	}
	// The generated home contains only the private, deterministic profile file.
	// Its digest is therefore content-bound, not an unstable temporary path.
	homeDigest, err := harness.SHA256("clean-home-profile:\x00" + string(profileRaw))
	if err != nil {
		return harness.WorkerRuntimeAttestation{}, harness.WorkerDispatchBinding{}, err
	}
	instance, err := randomID("worker_")
	if err != nil {
		return harness.WorkerRuntimeAttestation{}, harness.WorkerDispatchBinding{}, err
	}
	att := harness.WorkerRuntimeAttestation{WorkerInstanceID: instance, WorkOrderID: order.WorkOrderID, CodexVersion: r.cfg.CodexVersion, AgentRole: "codex_implementer", LaunchSurface: "app_server", ProcessIdentity: fmt.Sprintf("pid:%d", pid), ModelRoute: r.cfg.Model, CleanHomeDigest: homeDigest, GeneratedProfileDigest: profileDigest, InstructionSources: []harness.SourceDigest{}, ToolInventory: []harness.SourceDigest{}, ApprovalPolicy: "never", SandboxMode: "workspace-write", SandboxPolicyDigest: order.SandboxPolicyDigest, WorkspaceDescriptorDigest: mustDigest(order.WorkspaceDescriptor), WorktreeBaseRef: order.WorktreeBaseRef, WritableResources: append([]string(nil), r.cfg.WriteRoots...), ReadableResources: append([]string(nil), r.cfg.ReadRoots...), NetworkPolicy: "false", CreatedAt: time.Now().UTC()}
	if err := att.Seal(); err != nil {
		return harness.WorkerRuntimeAttestation{}, harness.WorkerDispatchBinding{}, err
	}
	id, err := randomID("dispatch_")
	if err != nil {
		return harness.WorkerRuntimeAttestation{}, harness.WorkerDispatchBinding{}, err
	}
	binding := harness.WorkerDispatchBinding{DispatchBindingID: id, WorkOrderID: order.WorkOrderID, TaskID: order.TaskID, SpecHash: order.SpecHash, WorkerInstanceID: att.WorkerInstanceID, WorkerRuntimeAttestationDigest: att.AttestationDigest, ProfileManifestDigest: profileDigest, WorkspaceDescriptorDigest: mustDigest(order.WorkspaceDescriptor), WorktreeBaseRef: order.WorktreeBaseRef, SandboxPolicyDigest: order.SandboxPolicyDigest, LeaseID: order.Lease.ID, BoundAt: time.Now().UTC()}
	if err := binding.Seal(); err != nil {
		return harness.WorkerRuntimeAttestation{}, harness.WorkerDispatchBinding{}, err
	}
	return att, binding, nil
}

func mustDigest(v string) string { d, _ := harness.SHA256(v); return d }
func randomID(prefix string) (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return prefix + hex.EncodeToString(b), nil
}

type execProcess struct {
	stdin     io.WriteCloser
	stdout    io.ReadCloser
	cmd       *exec.Cmd
	closeOnce sync.Once
	killOnce  sync.Once
	waitOnce  sync.Once
	waitErr   error
}

func (p *execProcess) Read(b []byte) (int, error)  { return p.stdout.Read(b) }
func (p *execProcess) Write(b []byte) (int, error) { return p.stdin.Write(b) }
func (p *execProcess) Close() error {
	p.closeOnce.Do(func() { _ = p.stdin.Close(); _ = p.stdout.Close() })
	return nil
}
func (p *execProcess) PID() int {
	if p.cmd.Process == nil {
		return 0
	}
	return p.cmd.Process.Pid
}
func (p *execProcess) Wait() error {
	p.waitOnce.Do(func() { p.waitErr = p.cmd.Wait() })
	return p.waitErr
}
func (p *execProcess) Terminate() error {
	p.killOnce.Do(func() {
		if p.cmd.Process != nil {
			_ = p.cmd.Process.Kill()
		}
	})
	_ = p.Close()
	_ = p.Wait()
	return nil
}

type execStarter struct{}

func (execStarter) Start(ctx context.Context, l Launch) (Process, error) {
	program := l.Binary
	args := []string{"app-server", "--stdio", "--strict-config"}
	if l.Interpreter != "" {
		program = l.Interpreter
		args = append([]string{l.Binary}, args...)
	}
	cmd := exec.CommandContext(ctx, program, args...)
	// Never inherit the Controller environment. OPENAI_API_KEY, proxy settings,
	// cloud credentials, tracing exporters, shell hooks and user Codex settings
	// are all ambient authority. A future credential provisioner must be a
	// separate, explicitly reviewed interface; it must not widen this baseline.
	cmd.Env = cleanRuntimeEnvironment(l.Home)
	cmd.Dir = l.Worktree
	in, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err = cmd.Start(); err != nil {
		return nil, err
	}
	return &execProcess{stdin: in, stdout: out, cmd: cmd}, nil
}

func cleanRuntimeEnvironment(home string) []string {
	return []string{
		"CODEX_HOME=" + home,
		"HOME=" + home,
		"PATH=/usr/bin:/bin:/usr/sbin:/sbin",
		"LANG=C",
		"LC_ALL=C",
	}
}
