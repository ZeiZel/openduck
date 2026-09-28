package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"openduck/internal/mesh"
	"openduck/internal/providerbridge"
)

type directRouterAdapter struct {
	starts     int
	last       mesh.StartRequest
	native     string
	profile    string
	recoveries []mesh.PersistedSessionRecovery
	recoverErr error
}

func (a *directRouterAdapter) RecoverPersistedSessions(_ context.Context, recoveries []mesh.PersistedSessionRecovery) error {
	a.recoveries = append([]mesh.PersistedSessionRecovery(nil), recoveries...)
	return a.recoverErr
}

func (a *directRouterAdapter) ProfileID() string     { return a.profile }
func (*directRouterAdapter) ProfileRevision() string { return "revision-1" }
func (*directRouterAdapter) MappingDigest() string   { return "sha256:" + strings.Repeat("a", 64) }
func (*directRouterAdapter) RuntimeDigest() string   { return "sha256:" + strings.Repeat("b", 64) }
func (a *directRouterAdapter) Start(_ context.Context, request mesh.StartRequest) (mesh.SessionRef, error) {
	a.starts++
	a.last = request
	return mesh.SessionRef{ProviderSessionID: a.native}, nil
}
func (*directRouterAdapter) Send(context.Context, mesh.SessionRef, string) error  { return nil }
func (*directRouterAdapter) Steer(context.Context, mesh.SessionRef, string) error { return nil }
func (*directRouterAdapter) Cancel(context.Context, mesh.SessionRef, mesh.Cancellation) error {
	return nil
}
func (*directRouterAdapter) Status(context.Context, mesh.SessionRef) (mesh.SessionStatus, error) {
	return mesh.SessionStatus{State: "running", UsageSource: "provider"}, nil
}
func (*directRouterAdapter) Wait(context.Context, mesh.SessionRef, time.Time) (mesh.SessionStatus, error) {
	return mesh.SessionStatus{State: "running", UsageSource: "provider"}, nil
}
func (*directRouterAdapter) Result(context.Context, mesh.SessionRef, string) (mesh.ResultEnvelope, error) {
	return mesh.ResultEnvelope{}, nil
}

func TestProfileSessionRouterRequiresControllerSealAndUsesDeterministicHandle(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	profileID := providerbridge.ProfileCodexChatGPT
	adapter := &directRouterAdapter{native: "native-session-1", profile: profileID}
	router := &profileSessionRouter{routes: map[string]AttestedSessionAdapter{profileID: adapter}, sessions: map[string]routedSession{}}
	limits := meshApplicationLimits(4)
	profile := mesh.Profile{ID: profileID, Provider: "codex", Model: "codex-model", Status: "compatible", LocalOnly: true, MeshSpawn: true, Limits: limits, MappingVerified: true, EvidenceCurrent: true, Supported: mesh.CapabilityEnvelope{Tools: []string{"spawn"}}}
	directory, err := mesh.NewStaticDirectory(profile)
	if err != nil {
		t.Fatal(err)
	}
	nextID := 0
	coordinator, err := mesh.NewCoordinator(mesh.CoordinatorOptions{
		Repository: mesh.NewMemoryRepository(),
		Directory:  directory,
		Starter:    router,
		Sessions:   router,
		Endpoints:  mesh.NewEndpointAuthorizer(),
		Clock:      func() time.Time { return now },
		ID: func() string {
			nextID++
			return "router-test-" + fmt.Sprint(nextID)
		},
		PolicyVersion: "router-test-policy",
		BatchCaps:     limits,
	})
	if err != nil {
		t.Fatal(err)
	}
	binding, err := coordinator.RegisterRoot(context.Background(), "router-root", "router-root-session", "router-root-attempt", "router-root-peer", "L1", "router-workspace")
	if err != nil {
		t.Fatal(err)
	}
	proposal := mesh.SpawnProposal{SchemaVersion: mesh.SpawnProposalV1, ClientNonce: "router-proposal", Objective: "route sealed Start", InputArtifactRefs: []string{"artifact-1"}, PreferredProfile: profileID, RequestedRole: "worker", OutputSchemaRef: "result-v1", RequestedLimits: limits, RequestedTools: []string{"spawn"}}
	raw, err := json.Marshal(proposal)
	if err != nil {
		t.Fatal(err)
	}
	result, err := coordinator.ProposeSpawn(context.Background(), mesh.ProposalRequest{Endpoint: mesh.EndpointRequest{EndpointID: binding.EndpointID, PeerID: binding.PeerID, Audience: "mesh", Nonce: "router-start", MessageDigest: providerbridge.DigestBytes(raw)}, Proposal: proposal})
	if err != nil || result.RunID == "" || adapter.starts != 1 || !adapter.last.SealValid() {
		t.Fatalf("valid sealed route failed: result=%+v starts=%d sealed=%t err=%v", result, adapter.starts, adapter.last.SealValid(), err)
	}
	wantRoute := routeID(profileID, adapter.last.Binding.BindingID, adapter.last.Binding.BindingHash)
	if routed := router.sessions[wantRoute]; routed.adapter != adapter || routed.ref.ProviderSessionID != "native-session-1" {
		t.Fatalf("router handle was not content-bound: want=%s sessions=%+v", wantRoute, router.sessions)
	}
	fresh := &profileSessionRouter{routes: map[string]AttestedSessionAdapter{profileID: adapter}, sessions: map[string]routedSession{}, terminal: map[string]time.Time{}, limit: 1}
	beforeRecoveryStarts := adapter.starts
	if err := fresh.RecoverPersistedSessions(context.Background(), []mesh.PersistedSessionRecovery{{ProviderSessionID: wantRoute, Start: adapter.last}}); err != nil {
		t.Fatalf("router recovery failed: %v", err)
	}
	if adapter.starts != beforeRecoveryStarts || len(adapter.recoveries) != 1 || fresh.sessions[wantRoute].ref.ProviderSessionID != wantRoute {
		t.Fatalf("router recovery restarted or failed to publish: starts=%d/%d recoveries=%d sessions=%+v", adapter.starts, beforeRecoveryStarts, len(adapter.recoveries), fresh.sessions)
	}
	if err := fresh.RecoverPersistedSessions(context.Background(), []mesh.PersistedSessionRecovery{{ProviderSessionID: wantRoute, Start: adapter.last}}); err != nil {
		t.Fatalf("exact recovery replay at capacity failed: %v", err)
	}
	if status, err := fresh.Status(context.Background(), mesh.SessionRef{ProviderSessionID: wantRoute}); err != nil || status.State != "running" {
		t.Fatalf("recovered router status=%+v err=%v", status, err)
	}
	if _, err := fresh.Result(context.Background(), mesh.SessionRef{ProviderSessionID: wantRoute}, "revision-1"); err != nil {
		t.Fatalf("recovered router result=%v", err)
	}
	if err := fresh.Cancel(context.Background(), mesh.SessionRef{ProviderSessionID: wantRoute}, mesh.Cancellation{Mode: mesh.CancellationUser, RevisionRef: "revision-1", ReasonRef: "reason-1"}); err != nil {
		t.Fatalf("recovered router cancel=%v", err)
	}
	if replay, err := router.Start(context.Background(), adapter.last); err != nil || replay.ProviderSessionID != wantRoute || adapter.starts != 2 {
		t.Fatalf("exact sealed route replay failed: ref=%+v starts=%d err=%v", replay, adapter.starts, err)
	}

	beforeDenials := adapter.starts
	literal := mesh.StartRequest{Order: adapter.last.Order, Binding: adapter.last.Binding}
	if _, err := router.Start(context.Background(), literal); !errors.Is(err, mesh.ErrDenied) {
		t.Fatalf("literal matching fields minted router authority: %v", err)
	}
	mutated := adapter.last
	mutated.Order.Model = "mutated-model"
	if _, err := router.Start(context.Background(), mutated); !errors.Is(err, mesh.ErrDenied) {
		t.Fatalf("mutated sealed router request accepted: %v", err)
	}
	crossOrder := adapter.last
	crossOrder.Binding.OrderID = "foreign-order"
	if _, err := router.Start(context.Background(), crossOrder); !errors.Is(err, mesh.ErrDenied) {
		t.Fatalf("cross-order router request accepted: %v", err)
	}
	if adapter.starts != beforeDenials {
		t.Fatalf("router reached non-transport adapter before seal validation: before=%d after=%d", beforeDenials, adapter.starts)
	}

	adapter.native = "native-session-2"
	if _, err := router.Start(context.Background(), adapter.last); !errors.Is(err, mesh.ErrStartUncertain) || errors.Is(err, mesh.ErrDenied) {
		t.Fatalf("router collision was not typed uncertain: %v", err)
	}
	if routed := router.sessions[wantRoute]; routed.ref.ProviderSessionID != "native-session-1" {
		t.Fatalf("router collision overwrote prior route: %+v", routed)
	}
}

func TestProfileSessionRouterReclaimsOnlyTerminalRouteAfterRecoveryWindow(t *testing.T) {
	clock := time.Now().UTC().Truncate(time.Second)
	router := &profileSessionRouter{
		routes:   map[string]AttestedSessionAdapter{},
		sessions: map[string]routedSession{"terminal-route": {}},
		terminal: map[string]time.Time{"terminal-route": clock},
		now:      func() time.Time { return clock },
		limit:    1,
	}
	router.mu.Lock()
	router.reapTerminalLocked(clock)
	_, retained := router.sessions["terminal-route"]
	router.mu.Unlock()
	if !retained {
		t.Fatal("router reclaimed terminal route before recovery window")
	}
	clock = clock.Add(routerSessionRecoveryWindow + time.Second)
	router.mu.Lock()
	router.reapTerminalLocked(clock)
	_, retained = router.sessions["terminal-route"]
	router.mu.Unlock()
	if retained {
		t.Fatal("router retained terminal route past recovery window")
	}
}

func TestProfileSessionRouterAtomicallyRestoresRouteAndRejectsLegacyNamespace(t *testing.T) {
	profile := providerbridge.ProfileCodexChatGPT
	adapter := &directRouterAdapter{profile: profile}
	router := &profileSessionRouter{routes: map[string]AttestedSessionAdapter{profile: adapter}, sessions: map[string]routedSession{}, terminal: map[string]time.Time{}, limit: 2}
	now := time.Now().UTC().Truncate(time.Second)
	order := mesh.WorkOrderRecord{SchemaVersion: mesh.WorkOrderV2, OrderID: "order-1", OrderHash: "sha256:" + strings.Repeat("a", 64), RootRunID: "root-1", ParentRunID: "root-1", ParentSessionID: "root-session", RunID: "run-1", SessionID: "session-1", AttemptID: "attempt-1", ProfileID: profile, Provider: "codex", Model: "model-1", WorkspaceGroupID: "workspace-1", Classification: "L1", IdempotencyKey: "idem-1", LeaseID: "lease-1", PolicyVersion: "policy-1", Depth: 1, Limits: meshApplicationLimits(4), Requested: mesh.CapabilityEnvelope{Tools: []string{"spawn"}}, Effective: mesh.CapabilityEnvelope{Tools: []string{"spawn"}}, LeaseExpiry: now.Add(time.Minute), Task: mesh.TaskEnvelope{Objective: "recover", InputArtifactRefs: []string{"artifact-1"}, RequestedRole: "worker", OutputSchemaRef: "result-v1"}}
	binding := mesh.RunDispatchBinding{SchemaVersion: mesh.RunDispatchBindingV2, BindingID: "binding-1", BindingHash: "sha256:" + strings.Repeat("b", 64), OrderID: order.OrderID, OrderHash: order.OrderHash, RootRunID: order.RootRunID, RunID: order.RunID, SessionID: order.SessionID, AttemptID: order.AttemptID, EndpointID: "endpoint-1", Generation: 1, IssuedAt: now, ExpiresAt: order.LeaseExpiry}
	// Obtain a genuine Controller seal without exposing a constructor outside mesh.
	// An unsealed literal must be rejected before adapter recovery.
	literal := mesh.PersistedSessionRecovery{ProviderSessionID: "ptv2-" + profile + "-" + strings.Repeat("a", 64), Start: mesh.StartRequest{Order: order, Binding: binding}}
	if err := router.RecoverPersistedSessions(context.Background(), []mesh.PersistedSessionRecovery{literal}); !errors.Is(err, mesh.ErrReconciliationNeeded) || len(adapter.recoveries) != 0 {
		t.Fatalf("unsealed recovery reached adapter: %v", err)
	}
	if _, ok := routeProfile("route-" + profile + "-" + strings.Repeat("a", 64)); ok {
		t.Fatal("legacy route namespace accepted")
	}
	if _, ok := routeProfile("ptv2-" + profile + "-" + strings.Repeat("A", 64)); ok {
		t.Fatal("noncanonical ptv2 accepted")
	}
}
