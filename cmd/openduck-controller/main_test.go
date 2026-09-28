package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"openduck/internal/admission"
	"openduck/internal/macoschannel"
	"openduck/internal/mesh"
	"openduck/internal/providerbridge"
	"openduck/internal/providerrevision"
	"openduck/internal/providertransport"
)

type e2eCheckpoint struct {
	mu sync.Mutex
	cp admission.LedgerCheckpoint
}

func (s *e2eCheckpoint) AttestedCheckpoint() {}
func (s *e2eCheckpoint) LoadCheckpoint() (admission.LedgerCheckpoint, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cp, nil
}
func (s *e2eCheckpoint) CommitCheckpoint(expected uint64, next admission.LedgerCheckpoint) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cp.Version != expected || next.Version != expected+1 {
		return admission.ErrCheckpointMismatch
	}
	s.cp = next
	return nil
}

func TestSyntheticComposedHandlerHTTPBoundary(t *testing.T) {
	work := t.TempDir()
	old, _ := os.Getwd()
	if err := os.Chdir(work); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(old)
	h, closeFn, err := syntheticHandler("127.0.0.1:8788", "http://127.0.0.1:8788", work, &e2eCheckpoint{})
	if err != nil {
		t.Fatal(err)
	}
	defer closeFn()
	call := func(method, path string, body []byte, headers map[string]string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, bytes.NewReader(body))
		r.Host = "127.0.0.1:8788"
		r.RemoteAddr = "127.0.0.1:9999"
		for k, v := range headers {
			r.Header.Set(k, v)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		return rec
	}
	boot := call(http.MethodPost, "http://127.0.0.1:8788/v1/ui/bootstrap", []byte(`{"client_nonce":"e2e-client"}`), map[string]string{"Origin": "http://127.0.0.1:8788", "Content-Type": "application/json"})
	if boot.Code != http.StatusOK {
		t.Fatalf("bootstrap=%d", boot.Code)
	}
	var session struct {
		Token       string `json:"token"`
		ClientNonce string `json:"client_nonce"`
	}
	if json.Unmarshal(boot.Body.Bytes(), &session) != nil || session.Token == "" {
		t.Fatal("invalid session")
	}
	auth := func(nonce string) map[string]string {
		return map[string]string{"Origin": "http://127.0.0.1:8788", "Authorization": "Bearer " + session.Token, "X-UI-Nonce": session.ClientNonce, "X-UI-Request-Nonce": nonce, "Content-Type": "application/octet-stream"}
	}
	if r := call(http.MethodPost, "http://127.0.0.1:8788/v1/composer", []byte("safe event"), auth("r1")); r.Code != http.StatusAccepted {
		t.Fatalf("cloud=%d body=%s headers=%v", r.Code, r.Body.String(), auth("debug"))
	}
	if r := call(http.MethodPost, "http://127.0.0.1:8788/v1/composer", []byte("safe event"), auth("r2")); r.Code == http.StatusAccepted {
		t.Fatal("replay accepted")
	}
	if r := call(http.MethodPost, "http://127.0.0.1:8788/v1/composer", []byte("Это ПД: local"), auth("r3")); r.Code != http.StatusAccepted {
		t.Fatalf("pd=%d", r.Code)
	}
	readHeaders := auth("r4")
	delete(readHeaders, "Content-Type")
	r := call(http.MethodGet, "http://127.0.0.1:8788/v1/read/health", nil, readHeaders)
	if r.Code != http.StatusOK {
		body, _ := io.ReadAll(r.Body)
		t.Fatalf("read=%d body=%s", r.Code, body)
	}
	meshHeaders := auth("mesh-read")
	delete(meshHeaders, "Content-Type")
	r = call(http.MethodGet, "http://127.0.0.1:8788/v1/plugin-reads/mesh", nil, meshHeaders)
	if r.Code != http.StatusOK {
		t.Fatalf("mesh=%d body=%s", r.Code, r.Body.String())
	}
}

func TestPrepareStatePathCreatesPrivateDirectory(t *testing.T) {
	work := t.TempDir()
	old, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(work); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(old) })

	path, err := prepareStatePath(".openduck/controller.enc")
	if err != nil {
		t.Fatal(err)
	}
	if path != filepath.Join(".openduck", "controller.enc") {
		t.Fatalf("path = %q", path)
	}
	info, err := os.Stat(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0700 {
		t.Fatalf("permissions = %o, want 700", info.Mode().Perm())
	}
}

func TestPrepareStatePathRejectsSymlinkParent(t *testing.T) {
	work := t.TempDir()
	if err := os.Symlink(t.TempDir(), filepath.Join(work, ".openduck")); err != nil {
		t.Fatal(err)
	}
	old, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(work); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(old) })
	if _, err := prepareStatePath(".openduck/controller.enc"); err == nil {
		t.Fatal("expected symlink parent to be rejected")
	}
}

func TestPrepareStatePathDoesNotChmodInsecureExistingDirectory(t *testing.T) {
	work := t.TempDir()
	parent := filepath.Join(work, ".openduck")
	if err := os.Mkdir(parent, 0755); err != nil {
		t.Fatal(err)
	}
	old, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(work); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(old) })
	if _, err := prepareStatePath(".openduck/controller.enc"); err == nil {
		t.Fatal("expected insecure directory to be rejected")
	}
	info, err := os.Stat(parent)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0755 {
		t.Fatalf("permissions changed to %o", info.Mode().Perm())
	}
}

func TestPrepareStatePathRejectsUntrustedParent(t *testing.T) {
	if _, err := prepareStatePath("/tmp/controller.enc"); err == nil {
		t.Fatal("expected absolute path to be rejected")
	}
	if _, err := prepareStatePath("nested/controller.enc"); err == nil {
		t.Fatal("expected arbitrary parent to be rejected")
	}
}

func TestProviderCompositionRejectsPartialFlagsBeforeControllerStartup(t *testing.T) {
	if err := run([]string{"-provider-artifact-root", t.TempDir()}); err == nil || err.Error() != "incomplete provider composition" {
		t.Fatalf("partial provider flags result=%v", err)
	}
}

func TestProductionMeshGateRejectsMissingAdmissionAndMixedInputs(t *testing.T) {
	if err := run([]string{"-production-mesh"}); err == nil || !strings.Contains(err.Error(), "requires production admission") {
		t.Fatalf("production mesh without admission result=%v", err)
	}
	if err := run([]string{"-production-admission", "-mesh-state-key-file", "mesh.key"}); err == nil || !strings.Contains(err.Error(), "requires production mesh") {
		t.Fatalf("mesh key without gate result=%v", err)
	}
}

func TestProductionMeshValidationRequiresCompleteSeparateComposition(t *testing.T) {
	o := productionAdmissionOptions{productionMesh: true, providerComposition: providerCompositionOptions{Root: "/Library/Application Support/OpenDuck/providers/inactive"}, providerTransport: providerTransportOptions{enabled: true}, meshStateKeyFile: "mesh.key", meshStateChannel: "mesh-state", channel: "platform-anchor", brokerChannel: "codex-control"}
	if err := validateProductionMeshOptions(o); err == nil {
		t.Fatal("incomplete production mesh accepted")
	}
}

func TestProviderTransportRejectsIncompleteFlagsBeforeControllerStartup(t *testing.T) {
	if err := run([]string{"-provider-transport"}); err == nil || err.Error() != "incomplete provider transport" {
		t.Fatalf("partial transport flags result=%v", err)
	}
	if _, err := descriptorPath("qwen.local-pd"); err == nil {
		t.Fatal("PD profile unexpectedly acquired a general provider route")
	}
}

func TestProviderTransportOptionsRequireSeparateExplicitChannelGroup(t *testing.T) {
	digest := strings.Repeat("a", 64)
	numeric := map[string]bool{"provider-transport-controller-uid": true, "provider-transport-controller-gid": true, "provider-transport-channel-gid": true, "provider-transport-key-epoch": true}
	options := providerTransportOptions{enabled: true, localRelease: macoschannel.ReleasePin{ReleaseID: "controller-release", BinaryDigest: digest, SocketDigest: digest, ManifestDigest: digest}, uid: 501, gid: 20, channelGID: 20, keyEpoch: 1, numeric: numeric}
	if options.valid() {
		t.Fatal("controller primary group accepted as provider channel group")
	}
	options.channelGID = 30
	if !options.valid() {
		t.Fatal("distinct explicitly supplied channel group rejected")
	}
}

func TestProviderTransportDescriptorFailuresReturnBeforeChannelOpen(t *testing.T) {
	installed := providerrevision.Installed{Bundle: providerrevision.Bundle{Profiles: []providerrevision.ProfileBundle{{Profile: providerrevision.ProfileDTO{ID: providerbridge.ProfileCodexChatGPT, MeshSpawnEnabled: true}}}}, Enabled: map[string]bool{providerbridge.ProfileCodexChatGPT: true}}
	options := providerTransportOptions{enabled: true}
	composition := providerCompositionOptions{Root: "/fixed/providers", OwnerUID: 0, OwnerGID: 1}
	for name, dependencies := range map[string]providerTransportDependencies{
		"path": {
			descriptorPath: func(string) (string, error) { return "", errors.New("missing descriptor") },
			load: func(providertransport.LoadConfig) (providertransport.Descriptor, error) {
				t.Fatal("load called after path failure")
				return providertransport.Descriptor{}, nil
			},
			open: func(macoschannel.ReleasePin, uint32, uint32, uint32, uint64, []providertransport.Descriptor) (providertransport.BoundDialer, func(), error) {
				t.Fatal("channel opened after path failure")
				return providertransport.BoundDialer{}, nil, nil
			},
		},
		"load": {
			descriptorPath: func(string) (string, error) { return "codex/runtime-descriptor.json", nil },
			load: func(providertransport.LoadConfig) (providertransport.Descriptor, error) {
				return providertransport.Descriptor{}, errors.New("unreadable descriptor")
			},
			open: func(macoschannel.ReleasePin, uint32, uint32, uint32, uint64, []providertransport.Descriptor) (providertransport.BoundDialer, func(), error) {
				t.Fatal("channel opened after load failure")
				return providertransport.BoundDialer{}, nil, nil
			},
		},
	} {
		t.Run(name, func(t *testing.T) {
			_, _, closeFn, err := openConfiguredProviderTransport(options, composition, installed, dependencies)
			if err == nil || closeFn != nil {
				t.Fatalf("err=%v close=%v", err, closeFn != nil)
			}
		})
	}
}

func TestProviderTransportPositiveInjectedWiring(t *testing.T) {
	installed := providerrevision.Installed{Bundle: providerrevision.Bundle{Profiles: []providerrevision.ProfileBundle{{Profile: providerrevision.ProfileDTO{ID: providerbridge.ProfileCodexChatGPT, MeshSpawnEnabled: true}}}}, Enabled: map[string]bool{providerbridge.ProfileCodexChatGPT: true}}
	want := providertransport.Descriptor{ProfileID: providerbridge.ProfileCodexChatGPT}
	opened, closed := false, false
	deps := providerTransportDependencies{descriptorPath: func(id string) (string, error) {
		if id != providerbridge.ProfileCodexChatGPT {
			t.Fatal("wrong profile")
		}
		return "codex/runtime-descriptor.json", nil
	}, load: func(c providertransport.LoadConfig) (providertransport.Descriptor, error) {
		if c.DescriptorLeaf != "codex/runtime-descriptor.json" || c.RootPath != "/fixed/providers" {
			t.Fatalf("load config=%+v", c)
		}
		return want, nil
	}, open: func(_ macoschannel.ReleasePin, _ uint32, _ uint32, _ uint32, _ uint64, d []providertransport.Descriptor) (providertransport.BoundDialer, func(), error) {
		opened = true
		if len(d) != 1 || d[0].ProfileID != want.ProfileID {
			t.Fatalf("descriptors=%+v", d)
		}
		return providertransport.BoundDialer{Builder: func(providertransport.Descriptor) (*macoschannel.Dialer, error) { return nil, errors.New("not dialed") }}, func() { closed = true }, nil
	}}
	descriptors, dial, closeFn, err := openConfiguredProviderTransport(providerTransportOptions{enabled: true}, providerCompositionOptions{Root: "/fixed/providers", OwnerGID: 20}, installed, deps)
	if err != nil || !opened || len(descriptors) != 1 || dial == nil || closeFn == nil {
		t.Fatalf("wired=%v descriptors=%d dial=%v close=%v err=%v", opened, len(descriptors), dial != nil, closeFn != nil, err)
	}
	closeFn()
	if !closed {
		t.Fatal("transport roots not closed")
	}
}

type startupRecoveryProbe struct {
	calls int
	ctx   context.Context
	err   error
}

func (p *startupRecoveryProbe) ReloadAndReplay(ctx context.Context) error {
	p.calls++
	p.ctx = ctx
	return p.err
}

func TestRecoverConfiguredMeshDisabledCompositionIsInert(t *testing.T) {
	closed := false
	if err := recoverConfiguredMesh(context.Background(), nil, func() { closed = true }); err != nil {
		t.Fatalf("disabled recovery=%v", err)
	}
	if closed {
		t.Fatal("disabled composition closed an unopened transport")
	}
}

func TestRecoverConfiguredMeshFailureClosesTransportBeforeStartupCanContinue(t *testing.T) {
	probe := &startupRecoveryProbe{err: errors.New("missing durable route proof")}
	closed := false
	ctx := context.WithValue(context.Background(), startupRecoveryContextKey{}, "startup-context")
	if err := recoverConfiguredMesh(ctx, probe, func() { closed = true }); err == nil {
		t.Fatal("recovery failure was accepted")
	}
	if probe.calls != 1 || probe.ctx != ctx {
		t.Fatalf("recovery did not use the startup context exactly once: calls=%d context=%v", probe.calls, probe.ctx == ctx)
	}
	if !closed {
		t.Fatal("failed recovery left provider transport open")
	}
}

type startupRecoveryContextKey struct{}

type startupRecoverySessions struct {
	starts     int
	recoveries []mesh.PersistedSessionRecovery
}

func (s *startupRecoverySessions) Start(_ context.Context, request mesh.StartRequest) (mesh.SessionRef, error) {
	if !request.SealValid() {
		return mesh.SessionRef{}, mesh.ErrDenied
	}
	s.starts++
	return mesh.SessionRef{ProviderSessionID: "provider-" + request.Binding.BindingID}, nil
}
func (*startupRecoverySessions) Send(context.Context, mesh.SessionRef, string) error { return nil }
func (*startupRecoverySessions) Steer(context.Context, mesh.SessionRef, string) error {
	return nil
}
func (*startupRecoverySessions) Cancel(context.Context, mesh.SessionRef, mesh.Cancellation) error {
	return nil
}
func (*startupRecoverySessions) Status(context.Context, mesh.SessionRef) (mesh.SessionStatus, error) {
	return mesh.SessionStatus{State: "running", UsageSource: "provider"}, nil
}
func (*startupRecoverySessions) Wait(context.Context, mesh.SessionRef, time.Time) (mesh.SessionStatus, error) {
	return mesh.SessionStatus{State: "running", UsageSource: "provider"}, nil
}
func (*startupRecoverySessions) Result(context.Context, mesh.SessionRef, string) (mesh.ResultEnvelope, error) {
	return mesh.ResultEnvelope{}, nil
}
func (s *startupRecoverySessions) RecoverPersistedSessions(_ context.Context, recoveries []mesh.PersistedSessionRecovery) error {
	s.recoveries = append([]mesh.PersistedSessionRecovery(nil), recoveries...)
	return nil
}

type startupRecoveryIDs struct{ next int }

func (i *startupRecoveryIDs) Next() string {
	i.next++
	return fmt.Sprintf("startup-recovery-%d", i.next)
}

func startupRecoveryLimits() mesh.ExecutionLimits {
	return mesh.ExecutionLimits{SchemaVersion: mesh.ExecutionLimitsV1, MaxDepth: 4, MaxChildrenPerParent: 4, MaxConcurrentRuns: 4, MaxInputTokens: 1024, MaxOutputTokens: 1024, MaxWallMS: 60_000, MaxAttempts: 1, MaxResultBytes: 1024, Cost: mesh.CostLimit{Kind: "non_monetary", Unit: "token", MaxQuantity: 1024}}
}

func startupRecoveryCoordinator(t *testing.T, repo mesh.Repository, sessions *startupRecoverySessions, ids *startupRecoveryIDs) *mesh.Coordinator {
	t.Helper()
	limits := startupRecoveryLimits()
	directory, err := mesh.NewStaticDirectory(mesh.Profile{ID: "startup-profile", Provider: "codex", Model: "model-1", Status: "compatible", LocalOnly: true, MeshSpawn: true, Limits: limits, MappingVerified: true, EvidenceCurrent: true, Supported: mesh.CapabilityEnvelope{Tools: []string{"spawn"}}})
	if err != nil {
		t.Fatal(err)
	}
	c, err := mesh.NewCoordinator(mesh.CoordinatorOptions{Repository: repo, Directory: directory, Starter: sessions, Sessions: sessions, Endpoints: mesh.NewEndpointAuthorizer(), ID: ids.Next, PolicyVersion: "startup-recovery.v1", BatchCaps: limits})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestRecoverConfiguredMeshCleanJournalDoesNotCallProviderRecovery(t *testing.T) {
	sessions := &startupRecoverySessions{}
	coordinator := startupRecoveryCoordinator(t, mesh.NewMemoryRepository(), sessions, &startupRecoveryIDs{})
	if err := recoverConfiguredMesh(context.Background(), coordinator, nil); err != nil {
		t.Fatalf("clean recovery=%v", err)
	}
	if len(sessions.recoveries) != 0 {
		t.Fatalf("clean journal reached provider recovery: %+v", sessions.recoveries)
	}
}

func TestRecoverConfiguredMeshClearsPoisonedRunningChildWithExactProof(t *testing.T) {
	ctx := context.WithValue(context.Background(), startupRecoveryContextKey{}, "startup-context")
	repo := mesh.NewMemoryRepository()
	ids := &startupRecoveryIDs{}
	firstSessions := &startupRecoverySessions{}
	first := startupRecoveryCoordinator(t, repo, firstSessions, ids)
	root, err := first.RegisterRoot(ctx, "startup-root", "startup-root-session", "startup-root-attempt", "startup-root-peer", "L1", "startup-workspace")
	if err != nil {
		t.Fatal(err)
	}
	limits := startupRecoveryLimits()
	proposal := mesh.SpawnProposal{SchemaVersion: mesh.SpawnProposalV1, ClientNonce: "startup-spawn", Objective: "recover the exact native route", InputArtifactRefs: []string{"artifact-1"}, PreferredProfile: "startup-profile", RequestedRole: "worker", OutputSchemaRef: "result-v1", RequestedLimits: limits, RequestedTools: []string{"spawn"}}
	raw, err := json.Marshal(proposal)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = first.ProposeSpawn(ctx, mesh.ProposalRequest{Endpoint: mesh.EndpointRequest{EndpointID: root.EndpointID, PeerID: root.PeerID, Audience: "mesh", Nonce: "startup-spawn-operation", MessageDigest: providerbridge.DigestBytes(raw)}, Proposal: proposal}); err != nil {
		t.Fatal(err)
	}

	restartedSessions := &startupRecoverySessions{}
	restarted := startupRecoveryCoordinator(t, repo, restartedSessions, ids)
	closed := false
	if err = recoverConfiguredMesh(ctx, restarted, func() { closed = true }); err != nil {
		t.Fatalf("valid persisted route recovery=%v", err)
	}
	if closed || len(restartedSessions.recoveries) != 1 || !restartedSessions.recoveries[0].Start.SealValid() {
		t.Fatalf("recovery did not publish exactly one sealed proof: closed=%v recoveries=%+v", closed, restartedSessions.recoveries)
	}
	if _, err = restarted.RegisterRoot(ctx, "post-recovery-root", "post-recovery-session", "post-recovery-attempt", "post-recovery-peer", "L1", "startup-workspace"); err != nil {
		t.Fatalf("valid recovery left coordinator poisoned: %v", err)
	}
}
