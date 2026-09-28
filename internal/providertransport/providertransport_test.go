package providertransport

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"openduck/internal/macoschannel"
	"openduck/internal/mesh"
	"openduck/internal/meshui"
	"openduck/internal/providerbridge"
	"openduck/internal/providerrevision"
	"openduck/internal/verifiedroot"
)

type oneByteReader struct{ r *bytes.Reader }

func (r oneByteReader) Read(dst []byte) (int, error) {
	if len(dst) > 1 {
		dst = dst[:1]
	}
	return r.r.Read(dst)
}

type fakeInfo struct {
	name string
	size int64
	mode os.FileMode
	stat syscall.Stat_t
}

func (f fakeInfo) Name() string      { return f.name }
func (f fakeInfo) Size() int64       { return f.size }
func (f fakeInfo) Mode() os.FileMode { return f.mode }
func (fakeInfo) ModTime() time.Time  { return time.Time{} }
func (f fakeInfo) IsDir() bool       { return f.mode.IsDir() }
func (f fakeInfo) Sys() any          { s := f.stat; return &s }

type fakeLoadFile struct {
	*bytes.Reader
	info os.FileInfo
}

func (f *fakeLoadFile) Stat() (os.FileInfo, error) { return f.info, nil }
func (*fakeLoadFile) Close() error                 { return nil }

type fakeLoadRoot struct {
	root             []os.FileInfo
	provider         []os.FileInfo
	file             os.FileInfo
	raw              []byte
	rootN, providerN int
}

func (r *fakeLoadRoot) Stat(path string) (os.FileInfo, error) {
	if path != "." {
		return nil, os.ErrNotExist
	}
	i := r.rootN
	if i >= len(r.root) {
		i = len(r.root) - 1
	}
	r.rootN++
	return r.root[i], nil
}
func (r *fakeLoadRoot) Lstat(path string) (os.FileInfo, error) {
	if !strings.Contains(path, "/") {
		i := r.providerN
		if i >= len(r.provider) {
			i = len(r.provider) - 1
		}
		r.providerN++
		return r.provider[i], nil
	}
	return r.file, nil
}
func (r *fakeLoadRoot) Open(string) (loadFile, error) {
	return &fakeLoadFile{Reader: bytes.NewReader(r.raw), info: r.file}, nil
}
func (*fakeLoadRoot) Close() error { return nil }

type fakeLoadFS struct {
	parent, root   []os.FileInfo
	opened         *fakeLoadRoot
	parentN, rootN int
}

func (f *fakeLoadFS) Lstat(path string) (os.FileInfo, error) {
	values := f.root
	n := &f.rootN
	if path == "/trusted/providers" {
		values = f.parent
		n = &f.parentN
	}
	i := *n
	if i >= len(values) {
		i = len(values) - 1
	}
	(*n)++
	return values[i], nil
}
func (f *fakeLoadFS) OpenRoot(string) (loadRoot, error) { return f.opened, nil }
func info(name string, mode os.FileMode, uid, gid uint32, ino uint64, nlink uint16, size int64) os.FileInfo {
	return fakeInfo{name: name, size: size, mode: mode, stat: syscall.Stat_t{Uid: uid, Gid: gid, Ino: ino, Dev: 1, Nlink: nlink}}
}
func loaderFixture(t *testing.T, d Descriptor) (LoadConfig, *fakeLoadFS) {
	t.Helper()
	raw, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	parent := info("providers", os.ModeDir|0711, 0, 0, 1, 2, 0)
	root := info("inactive", os.ModeDir|0750, 501, 20, 2, 2, 0)
	provider := info(d.Provider, os.ModeDir|0750, 501, 20, 3, 2, 0)
	file := info("descriptor.json", 0440, 501, 20, 4, 1, int64(len(raw)))
	fs := &fakeLoadFS{parent: []os.FileInfo{parent, parent}, root: []os.FileInfo{root, root}, opened: &fakeLoadRoot{root: []os.FileInfo{root}, provider: []os.FileInfo{provider, provider}, file: file, raw: raw}}
	path, _ := descriptorPathForTest(d.Provider)
	return LoadConfig{RootPath: "/trusted/providers/inactive", DescriptorLeaf: path, OwnerUID: 501, OwnerGID: 20}, fs
}
func descriptorPathForTest(provider string) (string, bool) {
	switch provider {
	case "codex", "claude", "qwen", "kimi":
		return provider + "/runtime-descriptor.json", true
	case "deepseek":
		return provider + "/dsh-adapter-descriptor.json", true
	}
	return "", false
}

func descriptorFixture(t *testing.T, provider, profile string) Descriptor {
	t.Helper()
	d := Descriptor{SchemaVersion: DescriptorV1, Provider: provider, ProfileID: profile, ProfileRevision: "r1", MappingDigest: "sha256:" + strings.Repeat("a", 64), RuntimeDigest: "sha256:" + strings.Repeat("b", 64), ProtocolDigest: "sha256:" + strings.Repeat("c", 64), Channel: channelForProfile(profile), SocketLeaf: "control.sock", SocketRoot: socketRootForProfile(profile), PeerIdentity: "adapter", PeerUID: 501, PeerGID: 20, ChannelGID: 30, ReleaseID: "release-1", BinaryDigest: strings.Repeat("d", 64), SocketDigest: strings.Repeat("e", 64), ManifestDigest: strings.Repeat("f", 64), KeyEpoch: 1, Audience: "mesh"}
	if err := d.Seal(); err != nil {
		t.Fatal(err)
	}
	return d
}

func TestDescriptorCanonicalClosedSchema(t *testing.T) {
	d := descriptorFixture(t, "codex", "codex.chatgpt.app-server")
	raw, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeDescriptor(raw); err != nil {
		t.Fatal(err)
	}
	for _, bad := range [][]byte{
		append(append([]byte(nil), raw...), ' '),
		[]byte(`{"schema_version":"` + DescriptorV1 + `","schema_version":"` + DescriptorV1 + `"}`),
		[]byte(`{"schema_version":"` + DescriptorV1 + `","unknown":true}`),
		[]byte(`{"peer_uid":NaN}`),
		[]byte(`{"schema_version":"` + DescriptorV1 + `"}`),
		make([]byte, maxDescriptorBytes+1),
	} {
		if _, err := DecodeDescriptor(bad); !errors.Is(err, ErrInvalid) {
			t.Fatalf("accepted malformed descriptor: %v", err)
		}
	}
}

func TestDescriptorProviderRules(t *testing.T) {
	for _, tc := range []struct {
		provider, profile string
		valid             bool
	}{
		{"codex", "codex.chatgpt.app-server", true}, {"claude", "claude.code.cli", true}, {"qwen", "qwen.general.headless", true}, {"kimi", "kimi.code.acp", true}, {"deepseek", "deepseek.api", true}, {"deepseek", "deepseek.subscription", false}, {"claude", "codex.chatgpt.app-server", false},
	} {
		t.Run(tc.provider+tc.profile, func(t *testing.T) {
			d := descriptorFixture(t, "codex", "codex.chatgpt.app-server")
			d.Provider = tc.provider
			d.ProfileID = tc.profile
			d.Channel = channelForProfile(tc.profile)
			d.SocketRoot = socketRootForProfile(tc.profile)
			if !tc.valid {
				if err := d.Seal(); err == nil {
					t.Fatal("invalid profile sealed")
				}
			} else if err := d.Seal(); err != nil {
				t.Fatalf("valid fixture rejected: %v", err)
			}
		})
	}
}

func TestLoadNestedDescriptorsAndMetadataRaces(t *testing.T) {
	for _, v := range []struct{ provider, profile, path string }{{"codex", providerbridge.ProfileCodexChatGPT, "codex/runtime-descriptor.json"}, {"codex", providerbridge.ProfileCodexChatGPT, "codex/plugin-descriptor.json"}, {"claude", providerbridge.ProfileClaudeCode, "claude/runtime-descriptor.json"}, {"claude", providerbridge.ProfileClaudeCode, "claude/plugin-descriptor.json"}, {"qwen", providerbridge.ProfileQwenGeneral, "qwen/runtime-descriptor.json"}, {"qwen", providerbridge.ProfileQwenGeneral, "qwen/plugin-descriptor.json"}, {"kimi", providerbridge.ProfileKimiCode, "kimi/runtime-descriptor.json"}, {"kimi", providerbridge.ProfileKimiCode, "kimi/plugin-descriptor.json"}, {"deepseek", providerbridge.ProfileDeepSeekAPI, "deepseek/dsh-adapter-descriptor.json"}} {
		t.Run(strings.ReplaceAll(v.path, "/", "-"), func(t *testing.T) {
			d := descriptorFixture(t, v.provider, v.profile)
			cfg, fs := loaderFixture(t, d)
			cfg.DescriptorLeaf = v.path
			got, err := loadWithFS(cfg, fs)
			if err != nil || got.Digest != d.Digest {
				t.Fatalf("load err=%v", err)
			}
		})
	}
	d := descriptorFixture(t, "codex", providerbridge.ProfileCodexChatGPT)
	for name, mutate := range map[string]func(*fakeLoadFS){
		"final-symlink": func(f *fakeLoadFS) { x := f.opened.file.(fakeInfo); x.mode = os.ModeSymlink | 0777; f.opened.file = x },
		"intermediate-symlink": func(f *fakeLoadFS) {
			x := f.opened.provider[0].(fakeInfo)
			x.mode = os.ModeSymlink | 0750
			f.opened.provider = []os.FileInfo{x, x}
		},
		"hardlink":          func(f *fakeLoadFS) { x := f.opened.file.(fakeInfo); x.stat.Nlink = 2; f.opened.file = x },
		"wrong-file-mode":   func(f *fakeLoadFS) { x := f.opened.file.(fakeInfo); x.mode = 0640; f.opened.file = x },
		"wrong-file-uid":    func(f *fakeLoadFS) { x := f.opened.file.(fakeInfo); x.stat.Uid++; f.opened.file = x },
		"wrong-file-gid":    func(f *fakeLoadFS) { x := f.opened.file.(fakeInfo); x.stat.Gid++; f.opened.file = x },
		"root-replaced":     func(f *fakeLoadFS) { x := f.root[1].(fakeInfo); x.stat.Ino++; f.root[1] = x },
		"parent-replaced":   func(f *fakeLoadFS) { x := f.parent[1].(fakeInfo); x.stat.Ino++; f.parent[1] = x },
		"provider-replaced": func(f *fakeLoadFS) { x := f.opened.provider[1].(fakeInfo); x.stat.Ino++; f.opened.provider[1] = x },
		"ancestor-special-mode": func(f *fakeLoadFS) {
			x := f.parent[0].(fakeInfo)
			x.mode |= os.ModeSticky
			f.parent = []os.FileInfo{x, x}
		},
		"root-special-mode": func(f *fakeLoadFS) {
			x := f.root[0].(fakeInfo)
			x.mode |= os.ModeSetgid
			f.root = []os.FileInfo{x, x}
			f.opened.root = []os.FileInfo{x}
		},
		"provider-special-mode": func(f *fakeLoadFS) {
			x := f.opened.provider[0].(fakeInfo)
			x.mode |= os.ModeSetuid
			f.opened.provider = []os.FileInfo{x, x}
		},
		"file-special-mode": func(f *fakeLoadFS) {
			x := f.opened.file.(fakeInfo)
			x.mode |= os.ModeSetgid
			f.opened.file = x
		},
		"file-unix-special-mode": func(f *fakeLoadFS) {
			x := f.opened.file.(fakeInfo)
			x.stat.Mode |= 04000
			f.opened.file = x
		},
	} {
		t.Run(name, func(t *testing.T) {
			cfg, fs := loaderFixture(t, d)
			mutate(fs)
			if _, err := loadWithFS(cfg, fs); err == nil {
				t.Fatal("unsafe filesystem accepted")
			}
		})
	}
}

type fakeDialer struct{ fn func([]byte) []byte }

func (d fakeDialer) Dial(context.Context, Descriptor) (FrameConn, error) { return fakeFrame{d.fn}, nil }

type fakeFrame struct{ fn func([]byte) []byte }

func (f fakeFrame) Call(_ context.Context, b []byte) ([]byte, error) { return f.fn(b), nil }
func (fakeFrame) Close() error                                       { return nil }

type scriptedDialer struct {
	mu       sync.Mutex
	dials    int
	requests [][]byte
	call     func(int, []byte) ([]byte, error)
}

type serverLoopDialer struct {
	server     *Server
	descriptor Descriptor
	controller macoschannel.ReleasePin
}

func (d serverLoopDialer) Dial(context.Context, Descriptor) (FrameConn, error) {
	return serverLoopFrame(d), nil
}

type serverLoopFrame serverLoopDialer

func (f serverLoopFrame) Close() error { return nil }
func (f serverLoopFrame) Call(ctx context.Context, raw []byte) ([]byte, error) {
	c := &serverTestConn{ev: serverEvidence(f.descriptor, f.controller)}
	tag, err := c.Seal(frameBindingDomain, raw)
	if err != nil {
		return nil, err
	}
	wire, err := canonical(sealedFrame{Payload: raw, Tag: tag})
	if err != nil {
		return nil, err
	}
	var framed bytes.Buffer
	if err = writeFrame(ctx, &framed, wire); err != nil {
		return nil, err
	}
	c.in = bytes.NewReader(framed.Bytes())
	if err = f.server.ServeOnce(ctx, c); err != nil {
		return nil, err
	}
	reply, err := readFrame(ctx, bytes.NewReader(c.out.Bytes()))
	if err != nil {
		return nil, err
	}
	var envelope sealedFrame
	if decodeCanonical(reply, &envelope) != nil || c.Verify(frameBindingDomain, envelope.Payload, envelope.Tag) != nil {
		return nil, ErrDenied
	}
	return envelope.Payload, nil
}

func (d *scriptedDialer) Dial(context.Context, Descriptor) (FrameConn, error) {
	d.mu.Lock()
	d.dials++
	d.mu.Unlock()
	return scriptedFrame{dialer: d}, nil
}

type scriptedFrame struct{ dialer *scriptedDialer }

func (f scriptedFrame) Call(_ context.Context, raw []byte) ([]byte, error) {
	f.dialer.mu.Lock()
	copyRaw := append([]byte(nil), raw...)
	f.dialer.requests = append(f.dialer.requests, copyRaw)
	call, fn := len(f.dialer.requests), f.dialer.call
	f.dialer.mu.Unlock()
	return fn(call, copyRaw)
}
func (scriptedFrame) Close() error { return nil }

func matchingStartResponse(raw []byte, nativeSession string) ([]byte, error) {
	var q request
	if err := decodeCanonical(raw, &q); err != nil {
		return nil, err
	}
	out := response{SchemaVersion: ProtocolV1, Operation: q.Operation, RequestID: q.RequestID, ProfileID: q.ProfileID, ProfileRevision: q.ProfileRevision, MappingDigest: q.MappingDigest, RuntimeDigest: q.RuntimeDigest, ProtocolDigest: q.ProtocolDigest, Audience: q.Audience, SessionID: nativeSession, RunID: q.RunID, AttemptID: q.AttemptID}
	return canonical(out)
}

type capturingAdapterStarter struct {
	adapter *Adapter
	request mesh.StartRequest
	calls   int
}

func (s *capturingAdapterStarter) Start(ctx context.Context, request mesh.StartRequest) (mesh.SessionRef, error) {
	s.calls++
	s.request = request
	return s.adapter.Start(ctx, request)
}

func transportLimits() mesh.ExecutionLimits {
	return mesh.ExecutionLimits{SchemaVersion: mesh.ExecutionLimitsV1, MaxDepth: 4, MaxChildrenPerParent: 4, MaxConcurrentRuns: 8, MaxInputTokens: 100, MaxOutputTokens: 100, MaxWallMS: 30_000, MaxAttempts: 1, MaxResultBytes: 1024, Cost: mesh.CostLimit{Kind: "non_monetary", Unit: "token", MaxQuantity: 100}}
}

func startThroughCoordinator(t *testing.T, adapter *Adapter) (*capturingAdapterStarter, mesh.ProposalResult) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	adapter.now = func() time.Time { return now }
	profile := mesh.Profile{ID: adapter.descriptor.ProfileID, Provider: adapter.descriptor.Provider, Model: "provider-model", Status: "compatible", LocalOnly: true, MeshSpawn: true, Limits: transportLimits(), MappingVerified: true, EvidenceCurrent: true, Supported: mesh.CapabilityEnvelope{Tools: []string{"spawn"}}}
	directory, err := mesh.NewStaticDirectory(profile)
	if err != nil {
		t.Fatal(err)
	}
	nextID := 0
	ids := func() string {
		nextID++
		return "transport-mesh-" + fmt.Sprint(nextID)
	}
	capture := &capturingAdapterStarter{adapter: adapter}
	coordinator, err := mesh.NewCoordinator(mesh.CoordinatorOptions{Repository: mesh.NewMemoryRepository(), Directory: directory, Starter: capture, Sessions: adapter, Endpoints: mesh.NewEndpointAuthorizer(), Clock: func() time.Time { return now }, ID: ids, PolicyVersion: "transport-test-policy", BatchCaps: transportLimits()})
	if err != nil {
		t.Fatal(err)
	}
	binding, err := coordinator.RegisterRoot(context.Background(), "transport-root", "transport-root-session", "transport-root-attempt", "transport-root-peer", "L1", "transport-workspace")
	if err != nil {
		t.Fatal(err)
	}
	proposal := mesh.SpawnProposal{SchemaVersion: mesh.SpawnProposalV1, ClientNonce: "transport-proposal", Objective: "exercise sealed provider transport", InputArtifactRefs: []string{"artifact-1"}, PreferredProfile: profile.ID, RequestedRole: "worker", OutputSchemaRef: "result-v1", RequestedLimits: transportLimits(), RequestedTools: []string{"spawn"}}
	raw, err := json.Marshal(proposal)
	if err != nil {
		t.Fatal(err)
	}
	result, err := coordinator.ProposeSpawn(context.Background(), mesh.ProposalRequest{Endpoint: mesh.EndpointRequest{EndpointID: binding.EndpointID, PeerID: binding.PeerID, Audience: "mesh", Nonce: "transport-call", MessageDigest: providerbridge.DigestBytes(raw)}, Proposal: proposal})
	if err != nil {
		t.Fatal(err)
	}
	return capture, result
}

type countingDialer struct{ calls int }

func (d *countingDialer) Dial(context.Context, Descriptor) (FrameConn, error) {
	d.calls++
	return nil, ErrUnavailable
}

type fakeResolver map[string]providerbridge.ProfileResolution

func (r fakeResolver) Resolve(_ context.Context, id string, _ time.Time) (providerbridge.ProfileResolution, error) {
	v, ok := r[id]
	if !ok {
		return providerbridge.ProfileResolution{}, errors.New("missing")
	}
	return v, nil
}

type rejectedResolver struct {
	registryResolver
	profile string
}

func (r rejectedResolver) Resolve(ctx context.Context, id string, now time.Time) (providerbridge.ProfileResolution, error) {
	if id == r.profile {
		return providerbridge.ProfileResolution{}, providerbridge.ErrEvidenceUntrusted
	}
	return r.registryResolver.Resolve(ctx, id, now)
}

func TestAdapterRejectsCrossProfileResponseAndReconciliation(t *testing.T) {
	d := descriptorFixture(t, "codex", "codex.chatgpt.app-server")
	adapter, err := NewAdapter(d, fakeDialer{func(requestRaw []byte) []byte {
		var q request
		_ = json.Unmarshal(requestRaw, &q)
		out := response{SchemaVersion: ProtocolV1, Operation: q.Operation, RequestID: q.RequestID, ProfileID: "claude.code.cli", ProfileRevision: q.ProfileRevision, MappingDigest: q.MappingDigest, RuntimeDigest: q.RuntimeDigest, ProtocolDigest: q.ProtocolDigest, Audience: q.Audience, State: "running", UsageSource: "unknown"}
		b, _ := json.Marshal(out)
		return b
	}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := adapter.Status(context.Background(), mesh.SessionRef{ProviderSessionID: "missing"}); !errors.Is(err, mesh.ErrReconciliationNeeded) {
		t.Fatalf("restart/missing session was not explicit: %v", err)
	}
	adapter.sessions["route"] = "daemon-session"
	if _, err := adapter.Status(context.Background(), mesh.SessionRef{ProviderSessionID: "route"}); !errors.Is(err, mesh.ErrDenied) {
		t.Fatalf("cross-profile response accepted: %v", err)
	}
}

func TestAdapterReclaimsOnlyTerminalRouteAfterRecoveryWindow(t *testing.T) {
	d := descriptorFixture(t, "codex", providerbridge.ProfileCodexChatGPT)
	adapter, err := NewAdapter(d, &countingDialer{})
	if err != nil {
		t.Fatal(err)
	}
	clock := time.Now().UTC().Truncate(time.Second)
	adapter.now = func() time.Time { return clock }
	adapter.limit = 1
	adapter.sessions["terminal-route"] = "native-terminal"
	adapter.terminal["terminal-route"] = clock
	adapter.mu.Lock()
	adapter.reapTerminalLocked(clock)
	_, retained := adapter.sessions["terminal-route"]
	adapter.mu.Unlock()
	if !retained {
		t.Fatal("adapter reclaimed terminal route before recovery window")
	}
	clock = clock.Add(sessionRecoveryWindow + time.Second)
	adapter.mu.Lock()
	adapter.reapTerminalLocked(clock)
	_, retained = adapter.sessions["terminal-route"]
	adapter.mu.Unlock()
	if retained {
		t.Fatal("adapter retained terminal route past recovery window")
	}
}

func TestStartLostReplyRetriesExactStableRequestOnly(t *testing.T) {
	d := descriptorFixture(t, "codex", providerbridge.ProfileCodexChatGPT)
	seen := map[string]bool{}
	nativeEffects := 0
	dialer := &scriptedDialer{}
	dialer.call = func(call int, raw []byte) ([]byte, error) {
		var q request
		if err := decodeCanonical(raw, &q); err != nil {
			return nil, err
		}
		if !seen[q.RequestID] {
			seen[q.RequestID] = true
			nativeEffects++
		}
		if call == 1 {
			return nil, ErrUnavailable // native effect happened; ACK was lost.
		}
		return matchingStartResponse(raw, "native-session-1")
	}
	adapter, err := NewAdapter(d, dialer)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	adapter.now = func() time.Time { return now }
	out, err := adapter.callDeadlineTask(context.Background(), "start", "", d.ProfileRevision, "order-1", "order-hash-1", "binding-1", "binding-hash-1", "run-1", "attempt-1", "", "", now.Add(10*time.Second), mesh.TaskEnvelope{Objective: "test objective", InputArtifactRefs: []string{"artifact-1"}, RequestedRole: "worker", OutputSchemaRef: "result-v1"})
	if err != nil || out.SessionID != "native-session-1" {
		t.Fatalf("exact Start replay result=%+v err=%v", out, err)
	}
	dialer.mu.Lock()
	requests := append([][]byte(nil), dialer.requests...)
	dials := dialer.dials
	dialer.mu.Unlock()
	if nativeEffects != 1 || dials != 2 || len(requests) != 2 || !bytes.Equal(requests[0], requests[1]) {
		t.Fatalf("Start retry changed identity or duplicated effect: effects=%d dials=%d requests=%d equal=%t", nativeEffects, dials, len(requests), len(requests) == 2 && bytes.Equal(requests[0], requests[1]))
	}
	var q request
	if err = decodeCanonical(requests[0], &q); err != nil || !strings.HasPrefix(q.RequestID, "pt-start-") || q.Nonce != q.RequestID {
		t.Fatalf("unstable Start request identity: request=%+v err=%v", q, err)
	}
}

func TestStartAllRepliesLostReturnsTypedUncertainty(t *testing.T) {
	d := descriptorFixture(t, "codex", providerbridge.ProfileCodexChatGPT)
	dialer := &scriptedDialer{call: func(int, []byte) ([]byte, error) { return nil, ErrUnavailable }}
	adapter, err := NewAdapter(d, dialer)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	adapter.now = func() time.Time { return now }
	_, err = adapter.callDeadlineTask(context.Background(), "start", "", d.ProfileRevision, "order-1", "order-hash-1", "binding-1", "binding-hash-1", "run-1", "attempt-1", "", "", now.Add(10*time.Second), mesh.TaskEnvelope{Objective: "test objective", InputArtifactRefs: []string{"artifact-1"}, RequestedRole: "worker", OutputSchemaRef: "result-v1"})
	if !errors.Is(err, ErrReconcile) {
		t.Fatalf("lost Start ACKs were claimed denied/failed: %v", err)
	}
	dialer.mu.Lock()
	defer dialer.mu.Unlock()
	if len(dialer.requests) != 2 || !bytes.Equal(dialer.requests[0], dialer.requests[1]) {
		t.Fatalf("ambiguous Start changed request across retry: %d", len(dialer.requests))
	}
}

func TestAdapterSealAndDeterministicSessionHandle(t *testing.T) {
	d := descriptorFixture(t, "codex", providerbridge.ProfileCodexChatGPT)
	nativeSession := "native-session-1"
	dialer := &scriptedDialer{}
	dialer.call = func(_ int, raw []byte) ([]byte, error) { return matchingStartResponse(raw, nativeSession) }
	adapter, err := NewAdapter(d, dialer)
	if err != nil {
		t.Fatal(err)
	}
	capture, result := startThroughCoordinator(t, adapter)
	if capture.calls != 1 || !capture.request.SealValid() || result.RunID == "" {
		t.Fatalf("valid Controller-sealed Start failed: calls=%d request=%+v result=%+v", capture.calls, capture.request, result)
	}
	firstHandle := "ptv2-" + d.ProfileID + "-" + digestBytes([]byte(d.ProfileID+":"+capture.request.Binding.BindingID+":"+capture.request.Binding.BindingHash))
	if adapter.sessions[firstHandle] != nativeSession {
		t.Fatalf("deterministic Adapter handle was not content-bound: sessions=%+v", adapter.sessions)
	}
	if replay, err := adapter.Start(context.Background(), capture.request); err != nil || replay.ProviderSessionID != firstHandle {
		t.Fatalf("exact sealed Adapter replay failed: ref=%+v err=%v", replay, err)
	}
	dialer.mu.Lock()
	beforeDenials := len(dialer.requests)
	dialer.mu.Unlock()
	literal := mesh.StartRequest{Order: capture.request.Order, Binding: capture.request.Binding}
	if _, err := adapter.Start(context.Background(), literal); !errors.Is(err, mesh.ErrDenied) {
		t.Fatalf("matching literal fields minted Start authority: %v", err)
	}
	mutated := capture.request
	mutated.Order.Model = "mutated-model"
	if _, err := adapter.Start(context.Background(), mutated); !errors.Is(err, mesh.ErrDenied) {
		t.Fatalf("mutated sealed Start was accepted: %v", err)
	}
	crossOrder := capture.request
	crossOrder.Binding.OrderID = "foreign-order"
	if _, err := adapter.Start(context.Background(), crossOrder); !errors.Is(err, mesh.ErrDenied) {
		t.Fatalf("cross-order sealed Start was accepted: %v", err)
	}
	dialer.mu.Lock()
	afterDenials := len(dialer.requests)
	dialer.mu.Unlock()
	if afterDenials != beforeDenials {
		t.Fatalf("unsealed/mutated Start reached dialer: before=%d after=%d", beforeDenials, afterDenials)
	}

	// A provider that violates durable same-ID replay by returning another
	// native session can never overwrite the content-bound local handle.
	nativeSession = "native-session-2"
	if _, err := adapter.Start(context.Background(), capture.request); !errors.Is(err, mesh.ErrStartUncertain) || errors.Is(err, mesh.ErrDenied) {
		t.Fatalf("native-session collision was not typed uncertain: %v", err)
	}
	if adapter.sessions[firstHandle] != "native-session-1" {
		t.Fatalf("session collision overwrote prior route: %+v", adapter.sessions)
	}
}

func TestAdapterRecoveryRestoresStatusAndRejectsEveryForgedPin(t *testing.T) {
	d := descriptorFixture(t, "codex", providerbridge.ProfileCodexChatGPT)
	seed, err := NewAdapter(d, &scriptedDialer{call: func(_ int, raw []byte) ([]byte, error) { return matchingStartResponse(raw, "native-recovered-1") }})
	if err != nil {
		t.Fatal(err)
	}
	capture, _ := startThroughCoordinator(t, seed)
	buildProof := func(adapter *Adapter) PersistedSessionProof {
		q, raw, err := adapter.buildStartWire(capture.request)
		if err != nil {
			t.Fatal(err)
		}
		route := "ptv2-" + d.ProfileID + "-" + digestBytes([]byte(d.ProfileID+":"+q.BindingID+":"+q.BindingHash))
		return PersistedSessionProof{SchemaVersion: PersistedSessionProofV1, RouteRef: route, NativeSessionID: "native-recovered-1", ProfileID: q.ProfileID, ProfileRevision: q.ProfileRevision, MappingDigest: q.MappingDigest, RuntimeDigest: q.RuntimeDigest, ProtocolDigest: q.ProtocolDigest, OrderID: q.OrderID, OrderHash: q.OrderHash, BindingID: q.BindingID, BindingHash: q.BindingHash, RunID: q.RunID, AttemptID: q.AttemptID, RequestID: q.RequestID, RequestDigest: requestDigest(raw), State: "running"}
	}
	newRecoveryAdapter := func(mutate func(*PersistedSessionProof)) (*Adapter, mesh.PersistedSessionRecovery, *int) {
		calls := 0
		var adapter *Adapter
		dialer := &scriptedDialer{call: func(_ int, raw []byte) ([]byte, error) {
			calls++
			var q request
			if err := decodeCanonical(raw, &q); err != nil {
				return nil, err
			}
			if q.Operation == "status" {
				out := response{SchemaVersion: ProtocolV1, Operation: q.Operation, RequestID: q.RequestID, ProfileID: q.ProfileID, ProfileRevision: q.ProfileRevision, MappingDigest: q.MappingDigest, RuntimeDigest: q.RuntimeDigest, ProtocolDigest: q.ProtocolDigest, Audience: q.Audience, State: "running", UsageSource: "provider"}
				return canonical(out)
			}
			proof := buildProof(adapter)
			if mutate != nil {
				mutate(&proof)
			}
			out := response{SchemaVersion: ProtocolV1, Operation: q.Operation, RequestID: q.RequestID, ProfileID: q.ProfileID, ProfileRevision: q.ProfileRevision, MappingDigest: q.MappingDigest, RuntimeDigest: q.RuntimeDigest, ProtocolDigest: q.ProtocolDigest, Audience: q.Audience, Recovery: &proof}
			return canonical(out)
		}}
		adapter, err = NewAdapter(d, dialer)
		if err != nil {
			t.Fatal(err)
		}
		proof := buildProof(adapter)
		return adapter, mesh.PersistedSessionRecovery{ProviderSessionID: proof.RouteRef, Start: capture.request}, &calls
	}
	fresh, recovery, calls := newRecoveryAdapter(nil)
	if err := fresh.RecoverPersistedSessions(context.Background(), []mesh.PersistedSessionRecovery{recovery}); err != nil {
		t.Fatal(err)
	}
	if status, err := fresh.Status(context.Background(), mesh.SessionRef{ProviderSessionID: recovery.ProviderSessionID}); err != nil || status.State != "running" {
		t.Fatalf("recovered status=%+v err=%v", status, err)
	}
	if *calls != 2 {
		t.Fatalf("recovery/status calls=%d", *calls)
	}
	mutations := []struct {
		name string
		fn   func(*PersistedSessionProof)
	}{
		{"native", func(p *PersistedSessionProof) { p.NativeSessionID = "" }},
		{"profile", func(p *PersistedSessionProof) { p.ProfileID = providerbridge.ProfileClaudeCode }},
		{"revision", func(p *PersistedSessionProof) { p.ProfileRevision = "forged" }},
		{"mapping", func(p *PersistedSessionProof) { p.MappingDigest = "sha256:" + strings.Repeat("1", 64) }},
		{"runtime", func(p *PersistedSessionProof) { p.RuntimeDigest = "sha256:" + strings.Repeat("2", 64) }},
		{"protocol", func(p *PersistedSessionProof) { p.ProtocolDigest = "sha256:" + strings.Repeat("3", 64) }},
		{"order-id", func(p *PersistedSessionProof) { p.OrderID = "forged" }},
		{"order-hash", func(p *PersistedSessionProof) { p.OrderHash = "forged" }},
		{"binding-id", func(p *PersistedSessionProof) { p.BindingID = "forged" }},
		{"binding-hash", func(p *PersistedSessionProof) { p.BindingHash = "forged" }},
		{"run", func(p *PersistedSessionProof) { p.RunID = "forged" }},
		{"attempt", func(p *PersistedSessionProof) { p.AttemptID = "forged" }},
		{"request", func(p *PersistedSessionProof) { p.RequestID = "forged" }},
		{"request-digest", func(p *PersistedSessionProof) { p.RequestDigest = "sha256:" + strings.Repeat("4", 64) }},
		{"state", func(p *PersistedSessionProof) { p.State = "completed" }},
	}
	for _, tc := range mutations {
		t.Run(tc.name, func(t *testing.T) {
			adapter, recovery, _ := newRecoveryAdapter(tc.fn)
			if err := adapter.RecoverPersistedSessions(context.Background(), []mesh.PersistedSessionRecovery{recovery}); !errors.Is(err, mesh.ErrReconciliationNeeded) || len(adapter.sessions) != 0 {
				t.Fatalf("forged proof accepted/published: err=%v sessions=%+v", err, adapter.sessions)
			}
		})
	}
	var nth *Adapter
	nthCall := 0
	nthDialer := &scriptedDialer{call: func(_ int, raw []byte) ([]byte, error) {
		nthCall++
		var q request
		if err := decodeCanonical(raw, &q); err != nil {
			return nil, err
		}
		proof := buildProof(nth)
		if nthCall == 2 {
			proof.AttemptID = "forged-attempt"
		}
		out := response{SchemaVersion: ProtocolV1, Operation: q.Operation, RequestID: q.RequestID, ProfileID: q.ProfileID, ProfileRevision: q.ProfileRevision, MappingDigest: q.MappingDigest, RuntimeDigest: q.RuntimeDigest, ProtocolDigest: q.ProtocolDigest, Audience: q.Audience, Recovery: &proof}
		return canonical(out)
	}}
	nth, err = NewAdapter(d, nthDialer)
	if err != nil {
		t.Fatal(err)
	}
	nthProof := buildProof(nth)
	nthRecovery := mesh.PersistedSessionRecovery{ProviderSessionID: nthProof.RouteRef, Start: capture.request}
	if err := nth.RecoverPersistedSessions(context.Background(), []mesh.PersistedSessionRecovery{nthRecovery, nthRecovery}); !errors.Is(err, mesh.ErrReconciliationNeeded) || len(nth.sessions) != 0 {
		t.Fatalf("Nth proof failure published partial map: err=%v sessions=%+v", err, nth.sessions)
	}
	entered := make(chan struct{})
	release := make(chan struct{})
	var concurrent *Adapter
	concurrentDialer := &scriptedDialer{call: func(_ int, raw []byte) ([]byte, error) {
		var q request
		if err := decodeCanonical(raw, &q); err != nil {
			return nil, err
		}
		if q.Operation == "recover-session" {
			close(entered)
			<-release
			proof := buildProof(concurrent)
			out := response{SchemaVersion: ProtocolV1, Operation: q.Operation, RequestID: q.RequestID, ProfileID: q.ProfileID, ProfileRevision: q.ProfileRevision, MappingDigest: q.MappingDigest, RuntimeDigest: q.RuntimeDigest, ProtocolDigest: q.ProtocolDigest, Audience: q.Audience, Recovery: &proof}
			return canonical(out)
		}
		out := response{SchemaVersion: ProtocolV1, Operation: q.Operation, RequestID: q.RequestID, ProfileID: q.ProfileID, ProfileRevision: q.ProfileRevision, MappingDigest: q.MappingDigest, RuntimeDigest: q.RuntimeDigest, ProtocolDigest: q.ProtocolDigest, Audience: q.Audience, State: "running", UsageSource: "provider"}
		return canonical(out)
	}}
	concurrent, err = NewAdapter(d, concurrentDialer)
	if err != nil {
		t.Fatal(err)
	}
	concurrentProof := buildProof(concurrent)
	concurrentRecovery := mesh.PersistedSessionRecovery{ProviderSessionID: concurrentProof.RouteRef, Start: capture.request}
	recoverDone := make(chan error, 1)
	go func() {
		recoverDone <- concurrent.RecoverPersistedSessions(context.Background(), []mesh.PersistedSessionRecovery{concurrentRecovery})
	}()
	<-entered
	statusDone := make(chan error, 1)
	go func() {
		_, err := concurrent.Status(context.Background(), mesh.SessionRef{ProviderSessionID: concurrentRecovery.ProviderSessionID})
		statusDone <- err
	}()
	select {
	case err := <-statusDone:
		t.Fatalf("status observed partial recovery: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	if err := <-recoverDone; err != nil {
		t.Fatal(err)
	}
	if err := <-statusDone; err != nil {
		t.Fatalf("status after atomic recovery: %v", err)
	}
}

func TestAuthenticatedServerAdapterRestartRecoversWithoutStartAndControlsSession(t *testing.T) {
	d := descriptorFixture(t, "codex", providerbridge.ProfileCodexChatGPT)
	controller := macoschannel.ReleasePin{ReleaseID: "controller-release-1", BinaryDigest: strings.Repeat("a", 64), SocketDigest: strings.Repeat("b", 64), ManifestDigest: strings.Repeat("c", 64)}
	driver := newDurableStartDriver()
	driver.status = RuntimeStatus{State: "running", UsageSource: "provider"}
	driver.result = RuntimeResult{Status: "completed", OutputArtifactRef: "artifact-result", SchemaRef: "result-v1", ProvenanceDigest: "sha256:" + strings.Repeat("d", 64), Classification: "L1"}
	newServer := func(t *testing.T) *Server {
		t.Helper()
		s, err := NewServer(ServerConfig{Descriptor: d, Driver: driver, ControllerUID: 701, ControllerGID: 702, ControllerRelease: controller})
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := s.Recover(ctx); err != nil {
			t.Fatal(err)
		}
		return s
	}
	firstServer := newServer(t)
	firstAdapter, err := NewAdapter(d, serverLoopDialer{server: firstServer, descriptor: d, controller: controller})
	if err != nil {
		t.Fatal(err)
	}
	capture, result := startThroughCoordinator(t, firstAdapter)
	if result.RunID == "" {
		t.Fatal("initial authenticated Start failed")
	}
	driver.durableMu.Lock()
	beforeInvocations, beforeEffects := driver.invocations, driver.nativeEffects
	driver.durableMu.Unlock()
	newRecovered := func(t *testing.T) (*Adapter, mesh.PersistedSessionRecovery) {
		t.Helper()
		freshServer := newServer(t)
		freshAdapter, err := NewAdapter(d, serverLoopDialer{server: freshServer, descriptor: d, controller: controller})
		if err != nil {
			t.Fatal(err)
		}
		route := "ptv2-" + d.ProfileID + "-" + digestBytes([]byte(d.ProfileID+":"+capture.request.Binding.BindingID+":"+capture.request.Binding.BindingHash))
		recovery := mesh.PersistedSessionRecovery{ProviderSessionID: route, Start: capture.request}
		if err := freshAdapter.RecoverPersistedSessions(context.Background(), []mesh.PersistedSessionRecovery{recovery}); err != nil {
			t.Fatal(err)
		}
		return freshAdapter, recovery
	}
	statusAdapter, statusRecovery := newRecovered(t)
	if status, err := statusAdapter.Status(context.Background(), mesh.SessionRef{ProviderSessionID: statusRecovery.ProviderSessionID}); err != nil || status.State != "running" {
		t.Fatalf("recovered status=%+v err=%v", status, err)
	}
	resultAdapter, resultRecovery := newRecovered(t)
	if got, err := resultAdapter.Result(context.Background(), mesh.SessionRef{ProviderSessionID: resultRecovery.ProviderSessionID}, "revision-1"); err != nil || got.Status != "completed" {
		t.Fatalf("recovered result=%+v err=%v", got, err)
	}
	cancelAdapter, cancelRecovery := newRecovered(t)
	if err := cancelAdapter.Cancel(context.Background(), mesh.SessionRef{ProviderSessionID: cancelRecovery.ProviderSessionID}, mesh.Cancellation{Mode: mesh.CancellationUser, RevisionRef: "revision-1", ReasonRef: "reason-1"}); err != nil {
		t.Fatalf("recovered cancel=%v", err)
	}
	driver.durableMu.Lock()
	defer driver.durableMu.Unlock()
	if driver.invocations != beforeInvocations || driver.nativeEffects != beforeEffects || beforeEffects != 1 {
		t.Fatalf("restart duplicated Start: invocations=%d/%d effects=%d/%d", driver.invocations, beforeInvocations, driver.nativeEffects, beforeEffects)
	}
}

func TestMutatingControlsNeverRedispatchAfterPossibleEffect(t *testing.T) {
	for _, operation := range []string{"send", "steer", "cancel"} {
		t.Run(operation, func(t *testing.T) {
			d := descriptorFixture(t, "codex", providerbridge.ProfileCodexChatGPT)
			dialer := &scriptedDialer{call: func(int, []byte) ([]byte, error) { return nil, ErrUnavailable }}
			adapter, err := NewAdapter(d, dialer)
			if err != nil {
				t.Fatal(err)
			}
			adapter.sessions["route-1"] = "native-1"
			ref := mesh.SessionRef{ProviderSessionID: "route-1"}
			switch operation {
			case "send":
				err = adapter.Send(context.Background(), ref, "input-1")
			case "steer":
				err = adapter.Steer(context.Background(), ref, "input-1")
			default:
				err = adapter.Cancel(context.Background(), ref, mesh.Cancellation{Mode: mesh.CancellationUser, RevisionRef: "revision-1", ReasonRef: "reason-1"})
			}
			if !errors.Is(err, mesh.ErrControlUncertain) || !errors.Is(err, mesh.ErrReconciliationNeeded) {
				t.Fatalf("ambiguous %s result=%v", operation, err)
			}
			dialer.mu.Lock()
			calls, dials := len(dialer.requests), dialer.dials
			dialer.mu.Unlock()
			if calls != 1 || dials != 1 {
				t.Fatalf("ambiguous %s was redispatched: calls=%d dials=%d", operation, calls, dials)
			}
		})
	}
}

func TestAdapterRejectsStaleDeadline(t *testing.T) {
	d := descriptorFixture(t, "codex", "codex.chatgpt.app-server")
	a, err := NewAdapter(d, fakeDialer{})
	if err != nil {
		t.Fatal(err)
	}
	a.now = func() time.Time { return time.Unix(100, 0).UTC() }
	if _, err := a.Wait(context.Background(), mesh.SessionRef{ProviderSessionID: "x"}, time.Unix(99, 0)); !errors.Is(err, mesh.ErrDenied) {
		t.Fatalf("stale deadline accepted: %v", err)
	}
}

func TestAdapterCancellationAndOversizeFailBeforeProjection(t *testing.T) {
	d := descriptorFixture(t, "codex", providerbridge.ProfileCodexChatGPT)
	counter := &countingDialer{}
	a, err := NewAdapter(d, counter)
	if err != nil {
		t.Fatal(err)
	}
	a.sessions["route"] = "native"
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := a.Status(ctx, mesh.SessionRef{ProviderSessionID: "route"}); !errors.Is(err, mesh.ErrDenied) {
		t.Fatalf("cancel err=%v", err)
	}
	if counter.calls != 0 {
		t.Fatal("dial occurred after cancellation")
	}
	a, err = NewAdapter(d, fakeDialer{fn: func([]byte) []byte { return make([]byte, maxFrameBytes+1) }})
	if err != nil {
		t.Fatal(err)
	}
	a.sessions["route"] = "native"
	if _, err := a.Status(context.Background(), mesh.SessionRef{ProviderSessionID: "route"}); !errors.Is(err, mesh.ErrDenied) {
		t.Fatalf("oversize err=%v", err)
	}
}

func TestReadFrameHandlesPartialAndRejectsTruncation(t *testing.T) {
	var wire bytes.Buffer
	if err := writeFrame(context.Background(), &wire, []byte(`{"x":1}`)); err != nil {
		t.Fatal(err)
	}
	got, err := readFrame(context.Background(), oneByteReader{bytes.NewReader(wire.Bytes())})
	if err != nil || string(got) != "{\"x\":1}" {
		t.Fatalf("partial frame got=%q err=%v", got, err)
	}
	for _, raw := range [][]byte{wire.Bytes()[:3], wire.Bytes()[:len(wire.Bytes())-1]} {
		if _, err := readFrame(context.Background(), oneByteReader{bytes.NewReader(raw)}); err == nil {
			t.Fatal("truncated frame accepted")
		}
	}
}

func TestRequestOperationMatrix(t *testing.T) {
	d := descriptorFixture(t, "codex", "codex.chatgpt.app-server")
	base := request{SchemaVersion: ProtocolV1, Operation: "send", RequestID: "n1", Nonce: "n1", ProfileID: d.ProfileID, ProfileRevision: d.ProfileRevision, MappingDigest: d.MappingDigest, RuntimeDigest: d.RuntimeDigest, ProtocolDigest: d.ProtocolDigest, Audience: "mesh", SessionID: "session-1", InputRef: "input-1", Deadline: time.Now().UTC().Add(time.Minute)}
	if err := base.Validate(); err != nil {
		t.Fatal(err)
	}
	base.ReasonRef = "reason-1"
	if err := base.Validate(); err == nil {
		t.Fatal("send reason selector accepted")
	}
}

func TestTransportEnumsMatchMeshUI(t *testing.T) {
	if !state("completed") || !usage("attested") || state("succeeded") || usage("estimated") {
		t.Fatal("transport accepted non-UI enum")
	}
	response := meshui.MeshUIResponse{SchemaVersion: meshui.ResponseSchema, Kind: "mesh-status", Status: &meshui.SessionStatusOutput{State: "completed", UsageSource: "attested"}}
	if err := response.Validate("mesh-status"); err != nil {
		t.Fatalf("shared status rejected: %v", err)
	}
}

func TestClosedPerProfileTopology(t *testing.T) {
	profiles := []struct{ provider, profile string }{{"codex", "codex.chatgpt.app-server"}, {"claude", "claude.code.cli"}, {"qwen", "qwen.general.headless"}, {"kimi", "kimi.code.acp"}, {"deepseek", "deepseek.api"}}
	roots := map[string]bool{}
	channels := map[string]bool{}
	for _, v := range profiles {
		d := descriptorFixture(t, v.provider, v.profile)
		if d.Validate() != nil {
			t.Fatalf("%s descriptor rejected", v.provider)
		}
		if roots[d.SocketRoot] || channels[d.Channel] {
			t.Fatalf("shared topology %q/%q", d.SocketRoot, d.Channel)
		}
		roots[d.SocketRoot] = true
		channels[d.Channel] = true
	}
	d := descriptorFixture(t, "codex", "codex.chatgpt.app-server")
	d.SocketRoot = socketRootForProfile("claude.code.cli")
	if err := d.Seal(); err == nil {
		t.Fatal("cross-profile socket root accepted")
	}
	d = descriptorFixture(t, "codex", "codex.chatgpt.app-server")
	d.Channel = channelForProfile("claude.code.cli")
	if err := d.Seal(); err == nil {
		t.Fatal("cross-profile channel accepted")
	}
	d = descriptorFixture(t, "codex", providerbridge.ProfileCodexChatGPT)
	d.ChannelGID = d.PeerGID
	if err := d.Seal(); err == nil {
		t.Fatal("peer primary GID accepted as channel GID")
	}
	d = descriptorFixture(t, "codex", providerbridge.ProfileCodexChatGPT)
	d.ChannelGID++
	if err := d.Validate(); err == nil {
		t.Fatal("unsigned channel GID mutation accepted")
	}
}

func TestBoundEvidenceRejectsEverySubstitution(t *testing.T) {
	d := descriptorFixture(t, "codex", providerbridge.ProfileCodexChatGPT)
	base := macoschannel.Evidence{Channel: d.Channel, LocalRole: "controller", PeerRole: d.PeerIdentity, Peer: macoschannel.Peer{UID: d.PeerUID, GID: d.PeerGID}, PeerRelease: macoschannel.ReleasePin{ReleaseID: d.ReleaseID, BinaryDigest: d.BinaryDigest, SocketDigest: d.SocketDigest, ManifestDigest: d.ManifestDigest}, KeyEpoch: d.KeyEpoch}
	if err := validateEvidence(d, base); err != nil {
		t.Fatal(err)
	}
	mutations := map[string]func(*macoschannel.Evidence){"channel": func(e *macoschannel.Evidence) { e.Channel = "provider-claude" }, "local-role": func(e *macoschannel.Evidence) { e.LocalRole = "peer" }, "peer-role": func(e *macoschannel.Evidence) { e.PeerRole = "foreign" }, "uid": func(e *macoschannel.Evidence) { e.Peer.UID++ }, "gid": func(e *macoschannel.Evidence) { e.Peer.GID++ }, "release": func(e *macoschannel.Evidence) { e.PeerRelease.ReleaseID = "other" }, "binary": func(e *macoschannel.Evidence) { e.PeerRelease.BinaryDigest = strings.Repeat("0", 64) }, "socket": func(e *macoschannel.Evidence) { e.PeerRelease.SocketDigest = strings.Repeat("0", 64) }, "manifest": func(e *macoschannel.Evidence) { e.PeerRelease.ManifestDigest = strings.Repeat("0", 64) }, "epoch": func(e *macoschannel.Evidence) { e.KeyEpoch++ }}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			e := base
			mutate(&e)
			if validateEvidence(d, e) == nil {
				t.Fatal("substitution accepted")
			}
		})
	}
	foreign := d
	foreign.SocketRoot = socketRootForProfile(providerbridge.ProfileClaudeCode)
	if err := foreign.Seal(); err == nil {
		t.Fatal("foreign socket root sealed")
	}
}

func TestInstallerInventoryDefersPeersAndPD(t *testing.T) {
	for _, v := range BaseInstallerPrerequisites() {
		if strings.Contains(v.Path, "/codex") || strings.Contains(v.Path, ".key") || v.Path == FixedReleaseParent {
			t.Fatalf("base inventory contains peer material: %#v", v)
		}
	}
	post := PostPrincipalPrerequisites()
	if len(post) != 5 {
		t.Fatalf("post inventory=%d", len(post))
	}
	for _, v := range post {
		if !v.RequiresProvisionedPeer || v.ProfileID == "qwen.local-pd" || v.KeyLeaf == "" || v.Channel == "" {
			t.Fatalf("invalid post prerequisite: %#v", v)
		}
	}
	if _, ok := KeyLeaves()["qwen.local-pd"]; ok {
		t.Fatal("PD key exposed as cloud mesh prerequisite")
	}
}

func TestReleaseRootUsesExactPinnedChild(t *testing.T) {
	pin := macoschannel.ReleasePin{ReleaseID: "controller-release-7"}
	got, err := releaseRootForPin(pin)
	if err != nil || got != FixedReleaseParent+"/controller-release-7" {
		t.Fatalf("root=%q err=%v", got, err)
	}
	for _, id := range []string{"", ".", "..", "child/other", "/absolute", "child\\other"} {
		pin.ReleaseID = id
		if _, err := releaseRootForPin(pin); err == nil {
			t.Fatalf("unsafe release id %q accepted", id)
		}
	}
	pin.ReleaseID = "controller-release-7"
	req, err := releaseRequirement(pin, 77)
	if err != nil || req.Path == FixedReleaseParent || req.Mode != 0550 || req.Mode&^os.FileMode(0550) != 0 || req.UID != 0 || req.GID != 77 {
		t.Fatalf("unsafe release requirement: %#v err=%v", req, err)
	}
}

func TestReleaseRootRejectsSpecialFilesystemMode(t *testing.T) {
	path := t.TempDir() + "/release"
	if err := os.Mkdir(path, 0550); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0550|os.ModeSticky); err != nil {
		t.Fatal(err)
	}
	st, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode()&os.ModeSticky == 0 {
		t.Fatal("test filesystem did not retain sticky mode")
	}
	sys := st.Sys().(*syscall.Stat_t)
	req := verifiedroot.Requirement{Name: "controller-release", Path: path, UID: uint32(sys.Uid), GID: uint32(sys.Gid), Mode: 0550}
	if roots, err := verifiedroot.OpenAll([]verifiedroot.Requirement{req}); err == nil {
		verifiedroot.CloseAll(roots)
		t.Fatal("special-mode release root accepted")
	}
}

func TestFixedReleaseOpenerHasNoParentFallback(t *testing.T) {
	d := descriptorFixture(t, "codex", providerbridge.ProfileCodexChatGPT)
	local := macoschannel.ReleasePin{ReleaseID: "controller-release-7", BinaryDigest: strings.Repeat("a", 64), SocketDigest: strings.Repeat("b", 64), ManifestDigest: strings.Repeat("c", 64)}
	for _, failure := range []string{"symlink", "wrong-metadata"} {
		t.Run(failure, func(t *testing.T) {
			called := false
			opener := func(reqs []verifiedroot.Requirement) ([]openedRoot, func(), error) {
				called = true
				release := reqs[len(reqs)-1]
				if release.Path != FixedReleaseParent+"/controller-release-7" || release.Path == FixedReleaseParent || release.Mode != 0550 || release.Mode&^os.FileMode(0550) != 0 || release.UID != 0 || release.GID != 20 {
					t.Fatalf("release requirement=%+v", release)
				}
				return nil, nil, errors.New(failure)
			}
			if _, _, err := openFixedControllerChannelWith(local, 501, 20, 30, 1, []Descriptor{d}, opener); !errors.Is(err, ErrUnavailable) {
				t.Fatalf("err=%v", err)
			}
			if !called {
				t.Fatal("verified-root opener not called")
			}
		})
	}
	t.Run("nil-close", func(t *testing.T) {
		opener := func(reqs []verifiedroot.Requirement) ([]openedRoot, func(), error) {
			roots := make([]openedRoot, len(reqs))
			for i := range reqs {
				roots[i].path = reqs[i].Path
			}
			return roots, nil, nil
		}
		if _, _, err := openFixedControllerChannelWith(local, 501, 20, 30, 1, []Descriptor{d}, opener); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("nil close contract err=%v", err)
		}
	})
}

func TestFixedRootOpenerBindsCardinalityOrderKeyAndReleasePaths(t *testing.T) {
	descriptors := []Descriptor{descriptorFixture(t, "codex", providerbridge.ProfileCodexChatGPT), descriptorFixture(t, "claude", providerbridge.ProfileClaudeCode)}
	local := macoschannel.ReleasePin{ReleaseID: "controller-release-7", BinaryDigest: strings.Repeat("a", 64), SocketDigest: strings.Repeat("b", 64), ManifestDigest: strings.Repeat("c", 64)}
	mutations := map[string]func([]openedRoot) []openedRoot{
		"short": func(roots []openedRoot) []openedRoot { return roots[:len(roots)-1] },
		"extra": func(roots []openedRoot) []openedRoot { return append(roots, openedRoot{path: "/unexpected"}) },
		"reordered": func(roots []openedRoot) []openedRoot {
			roots[0], roots[1] = roots[1], roots[0]
			return roots
		},
		"wrong-key": func(roots []openedRoot) []openedRoot {
			roots[len(descriptors)].path = FixedKeyRoot + "-foreign"
			return roots
		},
		"wrong-release": func(roots []openedRoot) []openedRoot {
			roots[len(descriptors)+1].path = FixedReleaseParent
			return roots
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			closed := false
			opener := func(reqs []verifiedroot.Requirement) ([]openedRoot, func(), error) {
				handle, err := os.OpenRoot(t.TempDir())
				if err != nil {
					t.Fatal(err)
				}
				roots := make([]openedRoot, len(reqs))
				for i := range reqs {
					roots[i] = openedRoot{path: reqs[i].Path, handle: handle}
				}
				return mutate(roots), func() {
					closed = true
					_ = handle.Close()
				}, nil
			}
			if _, _, err := openFixedControllerChannelWith(local, 501, 20, 30, 1, descriptors, opener); !errors.Is(err, ErrUnavailable) {
				t.Fatalf("path/cardinality substitution err=%v", err)
			}
			if !closed {
				t.Fatal("substituted roots were not closed")
			}
		})
	}
	t.Run("nil-handle", func(t *testing.T) {
		closed := false
		opener := func(reqs []verifiedroot.Requirement) ([]openedRoot, func(), error) {
			handle, err := os.OpenRoot(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			roots := make([]openedRoot, len(reqs))
			for i := range reqs {
				roots[i] = openedRoot{path: reqs[i].Path, handle: handle}
			}
			roots[0].handle = nil
			return roots, func() {
				closed = true
				_ = handle.Close()
			}, nil
		}
		if _, _, err := openFixedControllerChannelWith(local, 501, 20, 30, 1, descriptors, opener); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("nil handle err=%v", err)
		}
		if !closed {
			t.Fatal("nil-handle roots were not closed")
		}
	})
}

func TestFixedRootOpenerBindsSignedChannelGID(t *testing.T) {
	d := descriptorFixture(t, "codex", providerbridge.ProfileCodexChatGPT)
	local := macoschannel.ReleasePin{ReleaseID: "controller-release-7", BinaryDigest: strings.Repeat("a", 64), SocketDigest: strings.Repeat("b", 64), ManifestDigest: strings.Repeat("c", 64)}
	called := false
	opener := func([]verifiedroot.Requirement) ([]openedRoot, func(), error) {
		called = true
		return nil, nil, errors.New("must not be called")
	}
	if _, _, err := openFixedControllerChannelWith(local, 501, 20, d.ChannelGID+1, 1, []Descriptor{d}, opener); !errors.Is(err, ErrDenied) {
		t.Fatalf("channel GID mismatch err=%v", err)
	}
	if called {
		t.Fatal("roots opened before channel GID mismatch denial")
	}
}

func TestResponseOperationMatrixRejectsCrossKinds(t *testing.T) {
	d := descriptorFixture(t, "codex", "codex.chatgpt.app-server")
	base := response{SchemaVersion: ProtocolV1, ProfileID: d.ProfileID, ProfileRevision: d.ProfileRevision, MappingDigest: d.MappingDigest, RuntimeDigest: d.RuntimeDigest, ProtocolDigest: d.ProtocolDigest, Audience: "mesh", RequestID: "r1"}
	cases := []response{
		func() response {
			v := base
			v.Operation = "start"
			v.SessionID = "s1"
			v.RunID = "run1"
			v.AttemptID = "attempt1"
			return v
		}(),
		func() response { v := base; v.Operation = "send"; return v }(), func() response { v := base; v.Operation = "steer"; return v }(), func() response { v := base; v.Operation = "cancel"; return v }(),
		func() response {
			v := base
			v.Operation = "status"
			v.State = "running"
			v.UsageSource = "provider"
			return v
		}(), func() response {
			v := base
			v.Operation = "wait"
			v.State = "completed"
			v.UsageSource = "attested"
			return v
		}(),
		func() response {
			v := base
			v.Operation = "result"
			v.RunID = "run1"
			v.AttemptID = "attempt1"
			v.Status = "completed"
			v.OutputArtifactRef = "artifact1"
			v.SchemaRef = "schema1"
			v.ProvenanceDigest = "sha256:" + strings.Repeat("a", 64)
			v.Classification = "L1"
			return v
		}(),
		func() response {
			v := base
			v.Operation = "collect"
			v.RunID = "run1"
			v.AttemptID = "attempt1"
			v.Status = "cancelled"
			v.OutputArtifactRef = "artifact1"
			v.SchemaRef = "schema1"
			v.ProvenanceDigest = "sha256:" + strings.Repeat("a", 64)
			v.Classification = "PD"
			return v
		}(),
	}
	for _, v := range cases {
		if err := v.Validate(); err != nil {
			t.Fatalf("%s rejected: %v", v.Operation, err)
		}
		v.OutputArtifactRef = "wrong"
		if v.Operation != "result" && v.Operation != "collect" && v.Validate() == nil {
			t.Fatalf("%s accepted cross-kind result", v.Operation)
		}
	}
}

func TestRequestOperationMatrixAllOperations(t *testing.T) {
	d := descriptorFixture(t, "codex", "codex.chatgpt.app-server")
	common := request{SchemaVersion: ProtocolV1, RequestID: "n1", Nonce: "n1", ProfileID: d.ProfileID, ProfileRevision: d.ProfileRevision, MappingDigest: d.MappingDigest, RuntimeDigest: d.RuntimeDigest, ProtocolDigest: d.ProtocolDigest, Audience: "mesh", Deadline: time.Now().UTC().Add(time.Minute)}
	makeReq := func(op string) request {
		q := common
		q.Operation = op
		switch op {
		case "start":
			q.OrderID = "order1"
			q.OrderHash = "hash1"
			q.BindingID = "binding1"
			q.BindingHash = "hash2"
			q.RunID = "run1"
			q.AttemptID = "attempt1"
			q.Task = mesh.TaskEnvelope{Objective: "test objective", InputArtifactRefs: []string{"artifact1"}, RequestedRole: "worker", OutputSchemaRef: "result1"}
		case "send", "steer":
			q.SessionID = "s1"
			q.InputRef = "input1"
		case "cancel":
			q.SessionID = "s1"
			q.CancelMode = mesh.CancellationUser
			q.RevisionRef = "revision1"
			q.ReasonRef = "reason1"
		case "status", "wait":
			q.SessionID = "s1"
		case "result", "collect":
			q.SessionID = "s1"
			q.RevisionRef = "revision1"
		}
		return q
	}
	for _, op := range []string{"start", "send", "steer", "cancel", "status", "wait", "result", "collect"} {
		q := makeReq(op)
		if err := q.Validate(); err != nil {
			t.Fatalf("%s rejected: %v", op, err)
		}
		q.Audience = "ui"
		if q.Validate() == nil {
			t.Fatalf("%s accepted wrong audience", op)
		}
	}
	user := makeReq("cancel")
	for name, mutate := range map[string]func(*request){
		"missing-mode":     func(q *request) { q.CancelMode = "" },
		"missing-revision": func(q *request) { q.RevisionRef = "" },
		"missing-reason":   func(q *request) { q.ReasonRef = "" },
		"arbitrary-mode":   func(q *request) { q.CancelMode = "reconcile" },
		"internal-as-user": func(q *request) {
			q.CancelMode, q.RevisionRef, q.ReasonRef = mesh.CancellationStartCompensation, "revision1", "start_commit_failed"
		},
	} {
		t.Run(name, func(t *testing.T) {
			q := user
			mutate(&q)
			if q.Validate() == nil {
				t.Fatal("invalid user cancellation accepted")
			}
		})
	}
	for _, c := range []struct {
		name, mode, reason string
		valid              bool
	}{
		{"start compensation", mesh.CancellationStartCompensation, "start_commit_failed", true},
		{"batch compensation", mesh.CancellationBatchCompensation, "batch_compensation", true},
		{"wrong start reason", mesh.CancellationStartCompensation, "batch_compensation", false},
		{"wrong batch reason", mesh.CancellationBatchCompensation, "start_commit_failed", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			q := user
			q.CancelMode, q.RevisionRef, q.ReasonRef = c.mode, "", c.reason
			if got := q.Validate() == nil; got != c.valid {
				t.Fatalf("valid=%v got=%v", c.valid, got)
			}
		})
	}
}

func TestAdapterCancelCarriesClosedRevisionReasonWire(t *testing.T) {
	d := descriptorFixture(t, "codex", providerbridge.ProfileCodexChatGPT)
	var seen []request
	a, err := NewAdapter(d, fakeDialer{fn: func(raw []byte) []byte {
		var q request
		if json.Unmarshal(raw, &q) != nil {
			t.Fatal("adapter produced invalid JSON")
		}
		seen = append(seen, q)
		out := response{SchemaVersion: ProtocolV1, Operation: q.Operation, RequestID: q.RequestID, ProfileID: q.ProfileID, ProfileRevision: q.ProfileRevision, MappingDigest: q.MappingDigest, RuntimeDigest: q.RuntimeDigest, ProtocolDigest: q.ProtocolDigest, Audience: q.Audience}
		b, _ := canonical(out)
		return b
	}})
	if err != nil {
		t.Fatal(err)
	}
	a.sessions["route"] = "native-session"
	user := mesh.Cancellation{Mode: mesh.CancellationUser, RevisionRef: "revision-1", ReasonRef: "reason-1"}
	if err := a.Cancel(context.Background(), mesh.SessionRef{ProviderSessionID: "route"}, user); err != nil {
		t.Fatal(err)
	}
	if len(seen) != 1 || seen[0].CancelMode != user.Mode || seen[0].RevisionRef != user.RevisionRef || seen[0].ReasonRef != user.ReasonRef {
		t.Fatalf("cancel wire lost bindings: %+v", seen)
	}
	if err := a.Cancel(context.Background(), mesh.SessionRef{ProviderSessionID: "route"}, mesh.Cancellation{Mode: mesh.CancellationUser, ReasonRef: "reason-1"}); !errors.Is(err, mesh.ErrDenied) {
		t.Fatalf("reason-only cancellation err=%v", err)
	}
	compensation := mesh.Cancellation{Mode: mesh.CancellationStartCompensation, ReasonRef: "start_commit_failed"}
	if err := a.Cancel(context.Background(), mesh.SessionRef{ProviderSessionID: "route"}, compensation); err != nil {
		t.Fatal(err)
	}
	if len(seen) != 2 || seen[1].CancelMode != compensation.Mode || seen[1].RevisionRef != "" || seen[1].ReasonRef != compensation.ReasonRef {
		t.Fatalf("compensation wire=%+v", seen)
	}
}

func TestNewAdaptersFailsClosedWithoutVerifiedEnabledRegistry(t *testing.T) {
	d := descriptorFixture(t, "codex", "codex.chatgpt.app-server")
	registry, err := providerbridge.NewRegistry(nil, nil, nil, nil, providerbridge.TrustRegistry{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	installed := providerrevision.Installed{Enabled: map[string]bool{d.ProfileID: true}}
	if _, err := NewAdapters(installed, registry, []Descriptor{d}, fakeDialer{}, time.Now().UTC()); err == nil {
		t.Fatal("descriptor bypassed empty/unverified registry")
	}
	if _, err := NewAdapters(installed, nil, []Descriptor{d}, fakeDialer{}, time.Now().UTC()); err == nil {
		t.Fatal("nil registry accepted")
	}
}

func TestNewAdaptersAdmitsFiveDistinctPinnedRoutesOnly(t *testing.T) {
	items := []struct{ provider, profile string }{{"codex", "codex.chatgpt.app-server"}, {"claude", "claude.code.cli"}, {"qwen", "qwen.general.headless"}, {"kimi", "kimi.code.acp"}, {"deepseek", "deepseek.api"}}
	installed := providerrevision.Installed{Enabled: map[string]bool{}, Bundle: providerrevision.Bundle{Profiles: make([]providerrevision.ProfileBundle, 0, len(items))}}
	resolver := fakeResolver{}
	descriptors := make([]Descriptor, 0, len(items))
	for _, v := range items {
		d := descriptorFixture(t, v.provider, v.profile)
		auth, runtimeKind := "subscription", "runtime"
		if d.ProfileID == providerbridge.ProfileDeepSeekAPI {
			auth, runtimeKind = "api-key", "deepseek-api"
		}
		descriptors = append(descriptors, d)
		installed.Enabled[d.ProfileID] = true
		installed.Bundle.Profiles = append(installed.Bundle.Profiles, providerrevision.ProfileBundle{Profile: providerrevision.ProfileDTO{ID: d.ProfileID, Provider: providerbridge.Provider(d.Provider), Model: "model1", RuntimeKind: runtimeKind, AuthModality: auth, AccountRef: "account1", MeshSpawnEnabled: true, MappingDigest: d.MappingDigest, Revision: d.ProfileRevision}})
		resolver[d.ProfileID] = providerbridge.ProfileResolution{Mapping: providerbridge.Mapping{Provider: providerbridge.Provider(d.Provider), ProfileID: d.ProfileID, ProfileRevision: d.ProfileRevision, Digest: d.MappingDigest, Maturity: providerbridge.CompatibilityPinned, RuntimeVersion: "runtime@1", RuntimeDigest: d.RuntimeDigest, ProtocolDigest: d.ProtocolDigest}, Profile: providerbridge.Profile{ID: d.ProfileID, Provider: providerbridge.Provider(d.Provider), Revision: d.ProfileRevision, AuthModality: auth, Status: providerbridge.StatusCompatible, MeshSpawnEnabled: true}, LimitsVerified: true, MappingVerified: true, EvidenceCurrent: true}
	}
	adapters, err := newAdaptersWithResolver(installed, resolver, descriptors, fakeDialer{}, time.Now().UTC())
	if err != nil || len(adapters) != 5 {
		t.Fatalf("five routes err=%v len=%d", err, len(adapters))
	}
	bad := descriptors[0]
	if _, err := newAdaptersWithResolver(installed, resolver, append(descriptors, bad), fakeDialer{}, time.Now().UTC()); err == nil {
		t.Fatal("duplicate route accepted")
	}
	foreign := descriptors[0]
	foreign.Provider = "claude"
	if err := foreign.Seal(); err == nil {
		t.Fatal("one provider satisfied another")
	}
	cloneResolver := func() fakeResolver {
		out := fakeResolver{}
		for k, v := range resolver {
			out[k] = v
		}
		return out
	}
	cloneInstalled := func() providerrevision.Installed {
		out := installed
		out.Bundle.Profiles = append([]providerrevision.ProfileBundle(nil), installed.Bundle.Profiles...)
		out.Enabled = map[string]bool{}
		for k, v := range installed.Enabled {
			out.Enabled[k] = v
		}
		return out
	}
	for name, mutate := range map[string]func(*providerrevision.Installed, fakeResolver, []Descriptor){
		"disabled": func(i *providerrevision.Installed, _ fakeResolver, _ []Descriptor) {
			i.Enabled[descriptors[0].ProfileID] = false
		},
		"mapping-unverified": func(_ *providerrevision.Installed, r fakeResolver, _ []Descriptor) {
			v := r[descriptors[0].ProfileID]
			v.MappingVerified = false
			r[descriptors[0].ProfileID] = v
		},
		"evidence-stale": func(_ *providerrevision.Installed, r fakeResolver, _ []Descriptor) {
			v := r[descriptors[0].ProfileID]
			v.EvidenceCurrent = false
			r[descriptors[0].ProfileID] = v
		},
		"synthetic": func(_ *providerrevision.Installed, r fakeResolver, _ []Descriptor) {
			v := r[descriptors[0].ProfileID]
			v.Mapping.Maturity = providerbridge.CompatibilitySynthetic
			r[descriptors[0].ProfileID] = v
		},
		"runtime-mismatch": func(_ *providerrevision.Installed, r fakeResolver, _ []Descriptor) {
			v := r[descriptors[0].ProfileID]
			v.Mapping.RuntimeDigest = "sha256:" + strings.Repeat("0", 64)
			r[descriptors[0].ProfileID] = v
		},
		"protocol-mismatch": func(_ *providerrevision.Installed, r fakeResolver, _ []Descriptor) {
			v := r[descriptors[0].ProfileID]
			v.Mapping.ProtocolDigest = "sha256:" + strings.Repeat("0", 64)
			r[descriptors[0].ProfileID] = v
		},
		"mapping-digest-mismatch": func(_ *providerrevision.Installed, r fakeResolver, _ []Descriptor) {
			v := r[descriptors[0].ProfileID]
			v.Mapping.Digest = "sha256:" + strings.Repeat("0", 64)
			r[descriptors[0].ProfileID] = v
		},
		"mapping-revision-mismatch": func(_ *providerrevision.Installed, r fakeResolver, _ []Descriptor) {
			v := r[descriptors[0].ProfileID]
			v.Mapping.ProfileRevision = "other"
			r[descriptors[0].ProfileID] = v
		},
		"resolved-profile-revision-mismatch": func(_ *providerrevision.Installed, r fakeResolver, _ []Descriptor) {
			v := r[descriptors[0].ProfileID]
			v.Profile.Revision = "other"
			r[descriptors[0].ProfileID] = v
		},
		"resolved-provider-mismatch": func(_ *providerrevision.Installed, r fakeResolver, _ []Descriptor) {
			v := r[descriptors[0].ProfileID]
			v.Profile.Provider = providerbridge.ProviderClaude
			r[descriptors[0].ProfileID] = v
		},
		"deepseek-modality": func(i *providerrevision.Installed, _ fakeResolver, _ []Descriptor) {
			for n := range i.Bundle.Profiles {
				if i.Bundle.Profiles[n].Profile.ID == providerbridge.ProfileDeepSeekAPI {
					i.Bundle.Profiles[n].Profile.AuthModality = "subscription"
				}
			}
		},
		"missing-route": func(_ *providerrevision.Installed, _ fakeResolver, d []Descriptor) { d[len(d)-1] = Descriptor{} },
	} {
		t.Run(name, func(t *testing.T) {
			i := cloneInstalled()
			r := cloneResolver()
			d := append([]Descriptor(nil), descriptors...)
			mutate(&i, r, d)
			if _, err := newAdaptersWithResolver(i, r, d, fakeDialer{}, time.Now().UTC()); err == nil {
				t.Fatal("gate bypass")
			}
		})
	}
	if _, err := newAdaptersWithResolver(installed, rejectedResolver{registryResolver: resolver, profile: descriptors[0].ProfileID}, descriptors, fakeDialer{}, time.Now().UTC()); err == nil {
		t.Fatal("revoked/untrusted resolution accepted")
	}
	pd := descriptorFixture(t, "qwen", "qwen.local-pd")
	i := cloneInstalled()
	i.Enabled[pd.ProfileID] = true
	i.Bundle.Profiles = append(i.Bundle.Profiles, providerrevision.ProfileBundle{Profile: providerrevision.ProfileDTO{ID: pd.ProfileID, Provider: providerbridge.ProviderQwen, Model: "model1", RuntimeKind: "runtime", AuthModality: "local", LocalOnly: true, MeshSpawnEnabled: true, MappingDigest: pd.MappingDigest, Revision: pd.ProfileRevision}})
	r := cloneResolver()
	r[pd.ProfileID] = providerbridge.ProfileResolution{Profile: providerbridge.Profile{ID: pd.ProfileID, MeshSpawnEnabled: true, LocalOnly: true}, LimitsVerified: true, MappingVerified: true, EvidenceCurrent: true, Mapping: providerbridge.Mapping{Maturity: providerbridge.CompatibilityPinned, RuntimeVersion: "runtime@1", RuntimeDigest: pd.RuntimeDigest, ProtocolDigest: pd.ProtocolDigest}}
	if _, err := newAdaptersWithResolver(i, r, append(descriptors, pd), fakeDialer{}, time.Now().UTC()); err == nil {
		t.Fatal("Qwen PD gained general route")
	}
}
