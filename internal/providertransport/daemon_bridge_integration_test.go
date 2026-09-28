package providertransport_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"openduck/internal/macoschannel"
	"openduck/internal/mesh"
	"openduck/internal/providerbridge"
	"openduck/internal/providerdaemon"
	"openduck/internal/providertransport"
)

type integrationAnchor struct {
	mu         sync.Mutex
	generation uint64
	digest     string
}

func (a *integrationAnchor) Current(context.Context) (uint64, string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.generation, a.digest, nil
}
func (a *integrationAnchor) Advance(_ context.Context, old, next uint64, digest string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.generation != old || next != old+1 {
		return errors.New("unexpected durable revision")
	}
	a.generation, a.digest = next, digest
	return nil
}

type integrationVerifier struct{}

func (integrationVerifier) VerifyEnablement(context.Context, providerdaemon.EnablementProof) error {
	return nil
}

type integrationAuthorizer struct{}

func (integrationAuthorizer) AuthorizeProviderRequest(context.Context, providerdaemon.AuthorizationAction, providerdaemon.Request, string) error {
	return nil
}

type integrationBridge struct {
	mu                           sync.Mutex
	starts, sends, cancellations int
}

func (b *integrationBridge) Start(context.Context, providerdaemon.Request) (string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.starts++
	return "native-daemon-session-1", nil
}
func (*integrationBridge) Reconcile(context.Context, providerdaemon.Receipt) (string, providerdaemon.State, error) {
	return "native-daemon-session-1", providerdaemon.Running, nil
}
func (*integrationBridge) Stop(context.Context, string) error { return nil }
func (b *integrationBridge) Send(context.Context, string, string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.sends++
	return nil
}
func (*integrationBridge) Steer(context.Context, string, string) error { return nil }
func (b *integrationBridge) Cancel(context.Context, string, string, string, string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.cancellations++
	return nil
}
func (*integrationBridge) Status(context.Context, string) (providerdaemon.SessionStatus, error) {
	return providerdaemon.SessionStatus{State: "running", UsageSource: "unknown"}, nil
}
func (*integrationBridge) Wait(context.Context, string, time.Time) (providerdaemon.SessionStatus, error) {
	return providerdaemon.SessionStatus{State: "running", UsageSource: "unknown"}, nil
}
func (*integrationBridge) Result(context.Context, string, string) (providerdaemon.SessionResult, error) {
	return providerdaemon.SessionResult{Status: "completed", OutputArtifactRef: "artifact-1", SchemaRef: "schema-1", ProvenanceDigest: "sha256:" + string(bytes.Repeat([]byte("a"), 64)), Classification: "L1"}, nil
}

type captureStarter struct {
	adapter *providertransport.Adapter
	request mesh.StartRequest
	ref     mesh.SessionRef
	calls   int
}

func (s *captureStarter) Start(ctx context.Context, request mesh.StartRequest) (mesh.SessionRef, error) {
	s.calls++
	s.request = request
	ref, err := s.adapter.Start(ctx, request)
	s.ref = ref
	return ref, err
}

func integrationDigest(char byte) string { return "sha256:" + string(bytes.Repeat([]byte{char}, 64)) }
func integrationLimits() mesh.ExecutionLimits {
	return mesh.ExecutionLimits{SchemaVersion: mesh.ExecutionLimitsV1, MaxDepth: 4, MaxChildrenPerParent: 4, MaxConcurrentRuns: 4, MaxInputTokens: 100, MaxOutputTokens: 100, MaxWallMS: 30_000, MaxAttempts: 1, MaxResultBytes: 1024, Cost: mesh.CostLimit{Kind: "non_monetary", Unit: "token", MaxQuantity: 100}}
}

func TestDaemonBridgeServerAdapterRestartThenControl(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	descriptor := providertransport.Descriptor{SchemaVersion: providertransport.DescriptorV1, Provider: "codex", ProfileID: "codex.chatgpt.app-server", ProfileRevision: "codex-app-server.v1", MappingDigest: integrationDigest('a'), RuntimeDigest: integrationDigest('b'), ProtocolDigest: integrationDigest('c'), Channel: "provider-codex", SocketLeaf: "control.sock", SocketRoot: "/Library/Application Support/OpenDuck/channels/providers/codex", PeerIdentity: "adapter", PeerUID: 501, PeerGID: 20, ChannelGID: 30, ReleaseID: "release-1", BinaryDigest: string(bytes.Repeat([]byte("d"), 64)), SocketDigest: string(bytes.Repeat([]byte("e"), 64)), ManifestDigest: string(bytes.Repeat([]byte("f"), 64)), KeyEpoch: 1, Audience: "mesh"}
	if err := descriptor.Seal(); err != nil {
		t.Fatal(err)
	}
	daemonDescriptor := providerdaemon.Descriptor{Provider: descriptor.Provider, Profile: descriptor.ProfileID, Revision: descriptor.ProfileRevision, MappingDigest: descriptor.MappingDigest, RuntimeDigest: descriptor.RuntimeDigest, ProtocolDigest: descriptor.ProtocolDigest, RootDescriptorPath: "/private/openduck-test/root.json", ReleaseFactPath: "/private/openduck-test/release.json", KeyFactPath: "/private/openduck-test/key.json"}
	proof := providerdaemon.EnablementProof{SchemaVersion: providerdaemon.EnablementSchemaV1, DescriptorDigest: providerdaemon.DescriptorDigest(daemonDescriptor), StaticIdentity: providerdaemon.Identity{Profile: daemonDescriptor.Profile, Revision: daemonDescriptor.Revision, Mapping: daemonDescriptor.MappingDigest, Runtime: daemonDescriptor.RuntimeDigest, Protocol: daemonDescriptor.ProtocolDigest, Route: daemonDescriptor.Provider}, KeyEpoch: 1, SignerKeyID: "test-owner-key", IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour), Signature: "test-signature"}
	providerdaemon.SealEnablementProof(&proof)
	daemonDescriptor.EnablementDigest = proof.Digest
	verified, err := providerdaemon.VerifyEnablement(context.Background(), daemonDescriptor, proof, integrationVerifier{}, now)
	if err != nil {
		t.Fatal(err)
	}
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	store, err := providerdaemon.OpenStore(verified.StoreConfig(root, "state.json", "state.lock", uint32(os.Geteuid()), uint32(os.Getegid()), &integrationAnchor{}), bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	bridge := &integrationBridge{}
	core, err := providerdaemon.NewEnabled(verified, store, bridge, integrationAuthorizer{})
	if err != nil {
		t.Fatal(err)
	}
	driver, err := providerdaemon.NewTransportDriver(core)
	if err != nil {
		t.Fatal(err)
	}
	controller := macoschannel.ReleasePin{ReleaseID: "controller-release-1", BinaryDigest: string(bytes.Repeat([]byte("a"), 64)), SocketDigest: string(bytes.Repeat([]byte("b"), 64)), ManifestDigest: string(bytes.Repeat([]byte("c"), 64))}
	newServer := func() *providertransport.Server {
		s, buildErr := providertransport.NewServer(providertransport.ServerConfig{Descriptor: descriptor, Driver: driver, ControllerUID: 701, ControllerGID: 702, ControllerRelease: controller})
		if buildErr != nil {
			t.Fatal(buildErr)
		}
		if recoverErr := s.Recover(context.Background()); recoverErr != nil {
			t.Fatal(recoverErr)
		}
		return s
	}
	first := newServer()
	adapter, err := providertransport.NewAdapter(descriptor, providertransport.NewTestServerLoopDialer(first, descriptor, controller))
	if err != nil {
		t.Fatal(err)
	}
	profile := mesh.Profile{ID: descriptor.ProfileID, Provider: descriptor.Provider, Model: "provider-model", Status: "compatible", LocalOnly: true, MeshSpawn: true, Limits: integrationLimits(), MappingVerified: true, EvidenceCurrent: true, Supported: mesh.CapabilityEnvelope{Tools: []string{"spawn"}}}
	directory, err := mesh.NewStaticDirectory(profile)
	if err != nil {
		t.Fatal(err)
	}
	capture := &captureStarter{adapter: adapter}
	ids := 0
	coordinator, err := mesh.NewCoordinator(mesh.CoordinatorOptions{Repository: mesh.NewMemoryRepository(), Directory: directory, Starter: capture, Sessions: adapter, Endpoints: mesh.NewEndpointAuthorizer(), Clock: func() time.Time { return now }, ID: func() string { ids++; return "integration-" + string(rune('a'+ids)) }, PolicyVersion: "integration-policy", BatchCaps: integrationLimits()})
	if err != nil {
		t.Fatal(err)
	}
	binding, err := coordinator.RegisterRoot(context.Background(), "root-run", "root-session", "root-attempt", "root-peer", "L1", "workspace")
	if err != nil {
		t.Fatal(err)
	}
	proposal := mesh.SpawnProposal{SchemaVersion: mesh.SpawnProposalV1, ClientNonce: "proposal-1", Objective: "restart proof integration", InputArtifactRefs: []string{"artifact-1"}, PreferredProfile: profile.ID, RequestedRole: "worker", OutputSchemaRef: "result-v1", RequestedLimits: integrationLimits(), RequestedTools: []string{"spawn"}}
	proposalRaw, err := json.Marshal(proposal)
	if err != nil {
		t.Fatal(err)
	}
	result, err := coordinator.ProposeSpawn(context.Background(), mesh.ProposalRequest{Endpoint: mesh.EndpointRequest{EndpointID: binding.EndpointID, PeerID: binding.PeerID, Audience: "mesh", Nonce: "proposal-call", MessageDigest: providerbridge.DigestBytes(proposalRaw)}, Proposal: proposal})
	if err != nil || capture.ref.ProviderSessionID == "" || capture.calls != 1 || !capture.request.SealValid() {
		t.Fatalf("initial Start failed: result=%+v calls=%d sealed=%t err=%v", result, capture.calls, capture.request.SealValid(), err)
	}

	second := newServer()
	recovered, err := providertransport.NewAdapter(descriptor, providertransport.NewTestServerLoopDialer(second, descriptor, controller))
	if err != nil {
		t.Fatal(err)
	}
	if err = recovered.RecoverPersistedSessions(context.Background(), []mesh.PersistedSessionRecovery{{ProviderSessionID: capture.ref.ProviderSessionID, Start: capture.request}}); err != nil {
		t.Fatal(err)
	}
	ref := mesh.SessionRef{ProviderSessionID: capture.ref.ProviderSessionID}
	if err = recovered.Send(context.Background(), ref, "revision-1"); err != nil {
		t.Fatal(err)
	}
	if err = recovered.Cancel(context.Background(), ref, mesh.Cancellation{Mode: mesh.CancellationUser, RevisionRef: "revision-1", ReasonRef: "reason-1"}); err != nil {
		t.Fatal(err)
	}
	bridge.mu.Lock()
	defer bridge.mu.Unlock()
	if bridge.starts != 1 || bridge.sends != 1 || bridge.cancellations != 1 {
		t.Fatalf("restart/control changed effects: starts=%d sends=%d cancellations=%d", bridge.starts, bridge.sends, bridge.cancellations)
	}
}
