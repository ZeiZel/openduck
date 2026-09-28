package main

import (
	"context"
	"errors"
	"sort"
	"strings"
	"sync"
	"time"

	"openduck/internal/mesh"
	"openduck/internal/providerbridge"
	"openduck/internal/providerrevision"
)

// AttestedSessionAdapter is the only production transport insertion seam.
// Native providers must be injected by a Controller-owned composition after an
// external attestation; this package never starts a subprocess or accepts a
// providerbridge synthetic adapter.
type AttestedSessionAdapter interface {
	ProfileID() string
	ProfileRevision() string
	MappingDigest() string
	RuntimeDigest() string
	mesh.SessionStarter
	mesh.SessionController
}

type routedSession struct {
	adapter AttestedSessionAdapter
	ref     mesh.SessionRef
}

type profileSessionRouter struct {
	mu       sync.RWMutex
	routes   map[string]AttestedSessionAdapter
	sessions map[string]routedSession
	terminal map[string]time.Time
	now      func() time.Time
	starting int
	limit    int
}

const (
	maxRoutedSessions           = 256
	routerSessionRecoveryWindow = 15 * time.Minute
)

func newProfileSessionRouter(installed providerrevision.Installed, registry *providerbridge.Registry, adapters []AttestedSessionAdapter, now time.Time) (*profileSessionRouter, error) {
	if registry == nil {
		return nil, mesh.ErrInvalidContract
	}
	// `now` is the signed-registry validation instant.  Route retention must
	// use a live clock instead: capturing this validation value would freeze
	// terminal entries forever in a long-running Controller.
	r := &profileSessionRouter{routes: make(map[string]AttestedSessionAdapter), sessions: make(map[string]routedSession), terminal: make(map[string]time.Time), now: time.Now, limit: maxRoutedSessions}
	for _, adapter := range adapters {
		if adapter == nil || r.routes[adapter.ProfileID()] != nil {
			return nil, mesh.ErrInvalidContract
		}
		profile, found := installedProfile(installed, adapter.ProfileID())
		mapping, err := registry.Mapping(adapter.ProfileID())
		resolution, resolveErr := registry.Resolve(context.Background(), adapter.ProfileID(), now.UTC())
		if !found || err != nil || resolveErr != nil || !resolution.MeshSpawnEnabled() || mapping.Maturity != providerbridge.CompatibilityPinned || strings.HasPrefix(mapping.RuntimeVersion, "synthetic/") || adapter.ProfileRevision() != profile.Revision || adapter.MappingDigest() != mapping.Digest || adapter.RuntimeDigest() != mapping.RuntimeDigest {
			return nil, mesh.ErrInvalidContract
		}
		r.routes[adapter.ProfileID()] = adapter
	}
	return r, nil
}

func installedProfile(installed providerrevision.Installed, id string) (providerbridge.Profile, bool) {
	for _, entry := range installed.Bundle.Profiles {
		if entry.Profile.ID == id {
			p := providerbridge.Profile{ID: entry.Profile.ID, Provider: entry.Profile.Provider, Model: entry.Profile.Model, RuntimeKind: entry.Profile.RuntimeKind, AuthModality: entry.Profile.AuthModality, AccountRef: entry.Profile.AccountRef, LocalOnly: entry.Profile.LocalOnly, MeshSpawnEnabled: entry.Profile.MeshSpawnEnabled, ExecutionLimitsDigest: entry.Profile.ExecutionLimitsDigest, MappingDigest: entry.Profile.MappingDigest, ProviderEvidenceDigest: entry.Profile.ProviderEvidenceDigest, Revision: entry.Profile.Revision, Status: entry.Profile.Status}
			p.MeshSpawnEnabled = installed.Enabled[id]
			return p, true
		}
	}
	return providerbridge.Profile{}, false
}

func (r *profileSessionRouter) Start(ctx context.Context, request mesh.StartRequest) (mesh.SessionRef, error) {
	if r == nil || !request.SealValid() || request.Order.ProfileID == "" {
		return mesh.SessionRef{}, mesh.ErrDenied
	}
	r.mu.RLock()
	adapter := r.routes[request.Order.ProfileID]
	r.mu.RUnlock()
	if adapter == nil {
		return mesh.SessionRef{}, mesh.ErrDenied
	}
	id := routeID(request.Order.ProfileID, request.Binding.BindingID, request.Binding.BindingHash)
	// Keep a local reservation before crossing the adapter boundary.  The
	// router deliberately has no durable native handle after restart, so it
	// must never accept a Start it cannot retain and later route safely.
	r.mu.Lock()
	reserved := false
	r.reapTerminalLocked(r.clock().UTC())
	if _, exists := r.sessions[id]; !exists {
		if len(r.sessions)+r.starting >= r.sessionLimitLocked() {
			r.mu.Unlock()
			return mesh.SessionRef{}, mesh.ErrReconciliationNeeded
		}
		r.starting++
		reserved = true
	}
	r.mu.Unlock()
	defer func() {
		if reserved {
			r.mu.Lock()
			r.starting--
			r.mu.Unlock()
		}
	}()
	ref, err := adapter.Start(ctx, request)
	if err != nil {
		return mesh.SessionRef{}, err
	}
	if ref.ProviderSessionID == "" {
		return mesh.SessionRef{}, errors.Join(mesh.ErrReconciliationNeeded, mesh.ErrStartUncertain)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if reserved && r.starting > 0 {
		r.starting--
	}
	reserved = false
	if prior, exists := r.sessions[id]; exists {
		if prior.adapter != adapter || prior.ref.ProviderSessionID != ref.ProviderSessionID {
			return mesh.SessionRef{}, errors.Join(mesh.ErrReconciliationNeeded, mesh.ErrStartUncertain)
		}
		return mesh.SessionRef{ProviderSessionID: id}, nil
	}
	r.sessions[id] = routedSession{adapter: adapter, ref: ref}
	delete(r.terminal, id)
	return mesh.SessionRef{ProviderSessionID: id}, nil
}

// RecoverPersistedSessions verifies provider batches before atomically
// publishing router-visible routes. The stable reference contains no native
// handle; every legacy route-* value is rejected before provider I/O.
func (r *profileSessionRouter) RecoverPersistedSessions(ctx context.Context, recoveries []mesh.PersistedSessionRecovery) error {
	if r == nil || ctx == nil || ctx.Err() != nil || len(recoveries) == 0 || len(recoveries) > r.sessionLimitLocked() {
		return mesh.ErrReconciliationNeeded
	}
	type group struct {
		adapter    AttestedSessionAdapter
		verifier   mesh.PersistedSessionRecoveryVerifier
		recoveries []mesh.PersistedSessionRecovery
	}
	groups := make(map[string]*group)
	candidate := make(map[string]routedSession, len(recoveries))
	r.mu.RLock()
	for _, recovery := range recoveries {
		profile, ok := routeProfile(recovery.ProviderSessionID)
		adapter := r.routes[profile]
		verifier, verified := adapter.(mesh.PersistedSessionRecoveryVerifier)
		if !ok || adapter == nil || !verified || !recovery.Start.SealValid() || recovery.Start.Order.ProfileID != profile || routeID(profile, recovery.Start.Binding.BindingID, recovery.Start.Binding.BindingHash) != recovery.ProviderSessionID {
			r.mu.RUnlock()
			return mesh.ErrReconciliationNeeded
		}
		if prior, exists := candidate[recovery.ProviderSessionID]; exists && prior.adapter != adapter {
			r.mu.RUnlock()
			return mesh.ErrReconciliationNeeded
		}
		candidate[recovery.ProviderSessionID] = routedSession{adapter: adapter, ref: mesh.SessionRef{ProviderSessionID: recovery.ProviderSessionID}}
		g := groups[profile]
		if g == nil {
			g = &group{adapter: adapter, verifier: verifier}
			groups[profile] = g
		}
		g.recoveries = append(g.recoveries, recovery)
	}
	r.mu.RUnlock()
	profiles := make([]string, 0, len(groups))
	for profile := range groups {
		profiles = append(profiles, profile)
	}
	sort.Strings(profiles)
	for _, profile := range profiles {
		if err := groups[profile].verifier.RecoverPersistedSessions(ctx, groups[profile].recoveries); err != nil {
			return mesh.ErrReconciliationNeeded
		}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	merged := make(map[string]routedSession, len(r.sessions)+len(candidate))
	for id, prior := range r.sessions {
		merged[id] = prior
	}
	for id, next := range candidate {
		if prior, exists := merged[id]; exists && (prior.adapter != next.adapter || prior.ref != next.ref) {
			return mesh.ErrReconciliationNeeded
		}
		merged[id] = next
	}
	if len(merged) > r.sessionLimitLocked() {
		return mesh.ErrReconciliationNeeded
	}
	r.sessions = merged
	for id := range candidate {
		delete(r.terminal, id)
	}
	return nil
}

func routeID(profile, bindingID, bindingHash string) string {
	return "ptv2-" + profile + "-" + strings.TrimPrefix(providerbridge.DigestBytes([]byte(profile+":"+bindingID+":"+bindingHash)), "sha256:")
}

func routeProfile(ref string) (string, bool) {
	if !strings.HasPrefix(ref, "ptv2-") {
		return "", false
	}
	v := strings.TrimPrefix(ref, "ptv2-")
	for _, profile := range []string{providerbridge.ProfileCodexChatGPT, providerbridge.ProfileClaudeCode, providerbridge.ProfileQwenGeneral, providerbridge.ProfileKimiCode, providerbridge.ProfileDeepSeekAPI} {
		if strings.HasPrefix(v, profile+"-") && validRouteSuffix(strings.TrimPrefix(v, profile+"-")) {
			return profile, true
		}
	}
	return "", false
}

func validRouteSuffix(v string) bool {
	if len(v) != 64 {
		return false
	}
	for _, c := range v {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func (r *profileSessionRouter) session(ref mesh.SessionRef) (routedSession, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	v, ok := r.sessions[ref.ProviderSessionID]
	if !ok || v.adapter == nil {
		// Routes are intentionally not persisted: provider-native session
		// handles are never written into the Controller repository. A restart
		// therefore requires explicit reconciliation rather than a blind retry
		// that could create a duplicate native turn.
		return routedSession{}, mesh.ErrReconciliationNeeded
	}
	return v, nil
}
func (r *profileSessionRouter) Send(ctx context.Context, ref mesh.SessionRef, revision string) error {
	v, e := r.session(ref)
	if e != nil {
		return e
	}
	return v.adapter.Send(ctx, v.ref, revision)
}
func (r *profileSessionRouter) Steer(ctx context.Context, ref mesh.SessionRef, revision string) error {
	v, e := r.session(ref)
	if e != nil {
		return e
	}
	return v.adapter.Steer(ctx, v.ref, revision)
}
func (r *profileSessionRouter) Cancel(ctx context.Context, ref mesh.SessionRef, cancellation mesh.Cancellation) error {
	if cancellation.Validate() != nil {
		return mesh.ErrDenied
	}
	v, e := r.session(ref)
	if e != nil {
		return e
	}
	if err := v.adapter.Cancel(ctx, v.ref, cancellation); err != nil {
		return err
	}
	r.markTerminal(ref.ProviderSessionID)
	return nil
}
func (r *profileSessionRouter) Status(ctx context.Context, ref mesh.SessionRef) (mesh.SessionStatus, error) {
	v, e := r.session(ref)
	if e != nil {
		return mesh.SessionStatus{}, e
	}
	status, err := v.adapter.Status(ctx, v.ref)
	if err == nil && routedTerminal(status.State) {
		r.markTerminal(ref.ProviderSessionID)
	}
	return status, err
}
func (r *profileSessionRouter) Wait(ctx context.Context, ref mesh.SessionRef, deadline time.Time) (mesh.SessionStatus, error) {
	v, e := r.session(ref)
	if e != nil {
		return mesh.SessionStatus{}, e
	}
	status, err := v.adapter.Wait(ctx, v.ref, deadline)
	if err == nil && routedTerminal(status.State) {
		r.markTerminal(ref.ProviderSessionID)
	}
	return status, err
}
func (r *profileSessionRouter) Result(ctx context.Context, ref mesh.SessionRef, revision string) (mesh.ResultEnvelope, error) {
	v, e := r.session(ref)
	if e != nil {
		return mesh.ResultEnvelope{}, e
	}
	result, err := v.adapter.Result(ctx, v.ref, revision)
	if err == nil && routedTerminal(result.Status) {
		r.markTerminal(ref.ProviderSessionID)
	}
	return result, err
}

func (r *profileSessionRouter) clock() time.Time {
	if r != nil && r.now != nil {
		return r.now()
	}
	return time.Now()
}

func routedTerminal(state string) bool {
	return state == "completed" || state == "failed" || state == "cancelled" || state == "uncertain"
}

func (r *profileSessionRouter) markTerminal(id string) {
	if r == nil || id == "" {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.sessions[id]; ok {
		if r.terminal == nil {
			r.terminal = map[string]time.Time{}
		}
		if r.terminal[id].IsZero() {
			r.terminal[id] = r.clock().UTC()
		}
	}
}

func (r *profileSessionRouter) reapTerminalLocked(now time.Time) {
	if r == nil || now.IsZero() || r.terminal == nil {
		return
	}
	for id, terminalAt := range r.terminal {
		if !terminalAt.IsZero() && !now.Before(terminalAt.Add(routerSessionRecoveryWindow)) {
			delete(r.sessions, id)
			delete(r.terminal, id)
		}
	}
}

func (r *profileSessionRouter) sessionLimitLocked() int {
	if r != nil && r.limit >= 1 && r.limit <= maxRoutedSessions {
		return r.limit
	}
	return maxRoutedSessions
}

// noAdapterRouter retains the coordinator/session interfaces while making the
// default absent revision unable to create a provider session.
type noAdapterRouter struct{}

func (noAdapterRouter) Start(context.Context, mesh.StartRequest) (mesh.SessionRef, error) {
	return mesh.SessionRef{}, mesh.ErrDenied
}
func (noAdapterRouter) Send(context.Context, mesh.SessionRef, string) error  { return mesh.ErrDenied }
func (noAdapterRouter) Steer(context.Context, mesh.SessionRef, string) error { return mesh.ErrDenied }
func (noAdapterRouter) Cancel(context.Context, mesh.SessionRef, mesh.Cancellation) error {
	return mesh.ErrDenied
}
func (noAdapterRouter) Status(context.Context, mesh.SessionRef) (mesh.SessionStatus, error) {
	return mesh.SessionStatus{}, mesh.ErrDenied
}
func (noAdapterRouter) Wait(context.Context, mesh.SessionRef, time.Time) (mesh.SessionStatus, error) {
	return mesh.SessionStatus{}, mesh.ErrDenied
}
func (noAdapterRouter) Result(context.Context, mesh.SessionRef, string) (mesh.ResultEnvelope, error) {
	return mesh.ResultEnvelope{}, mesh.ErrDenied
}

var _ mesh.SessionStarter = (*profileSessionRouter)(nil)
var _ mesh.SessionController = (*profileSessionRouter)(nil)
var _ mesh.PersistedSessionRecoveryVerifier = (*profileSessionRouter)(nil)
