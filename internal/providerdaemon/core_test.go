package providerdaemon

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"openduck/internal/mesh"
	"openduck/internal/providertransport"
)

type memoryAnchor struct {
	mu         sync.Mutex
	generation uint64
	digest     string
	fail       bool
}

func (a *memoryAnchor) Current(context.Context) (uint64, string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.generation, a.digest, nil
}
func (a *memoryAnchor) Advance(_ context.Context, expected, next uint64, digest string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.fail || a.generation != expected || next != expected+1 {
		return ErrUnavailable
	}
	a.generation, a.digest = next, digest
	return nil
}

type allowVerifier struct{ deny bool }

func (v allowVerifier) VerifyEnablement(context.Context, EnablementProof) error {
	if v.deny {
		return ErrUnavailable
	}
	return nil
}

type revocableVerifier struct {
	revoked atomic.Bool
	calls   atomic.Int32
}

func (v *revocableVerifier) VerifyEnablement(context.Context, EnablementProof) error {
	v.calls.Add(1)
	if v.revoked.Load() {
		return ErrUnavailable
	}
	return nil
}

type allowAuthorizer struct {
	deny        bool
	denyActions map[AuthorizationAction]bool
	calls       atomic.Int32
	actions     []AuthorizationAction
	mu          sync.Mutex
}

type exactAuthorizer struct {
	action AuthorizationAction
	want   Request
	digest string
}

func (a exactAuthorizer) AuthorizeProviderRequest(_ context.Context, action AuthorizationAction, r Request, digest string) error {
	if action != a.action || r != a.want || digest != a.digest {
		return ErrUnavailable
	}
	return nil
}

func (a *allowAuthorizer) AuthorizeProviderRequest(_ context.Context, action AuthorizationAction, _ Request, _ string) error {
	a.calls.Add(1)
	a.mu.Lock()
	a.actions = append(a.actions, action)
	a.mu.Unlock()
	if a.deny || a.denyActions[action] {
		return ErrUnavailable
	}
	return nil
}
func (a *allowAuthorizer) seen(action AuthorizationAction) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, got := range a.actions {
		if got == action {
			return true
		}
	}
	return false
}

type fakeBridge struct {
	mu                        sync.Mutex
	starts, reconciles, stops int
	failStart, failStop       bool
	empty                     bool
}

func (f *fakeBridge) Send(context.Context, string, string) error                   { return nil }
func (f *fakeBridge) Steer(context.Context, string, string) error                  { return nil }
func (f *fakeBridge) Cancel(context.Context, string, string, string, string) error { return nil }
func (f *fakeBridge) Status(context.Context, string) (SessionStatus, error) {
	return SessionStatus{State: "running", UsageSource: "unknown"}, nil
}
func (f *fakeBridge) Wait(context.Context, string, time.Time) (SessionStatus, error) {
	return SessionStatus{State: "running", UsageSource: "unknown"}, nil
}
func (f *fakeBridge) Result(context.Context, string, string) (SessionResult, error) {
	return SessionResult{Status: "completed", OutputArtifactRef: "artifact-1", SchemaRef: "schema-1", ProvenanceDigest: dg("provenance"), Classification: "L1"}, nil
}

func (f *fakeBridge) Start(context.Context, Request) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.starts++
	if f.failStart {
		return "", ErrUnavailable
	}
	if f.empty {
		return "", nil
	}
	return "session-1", nil
}
func (f *fakeBridge) Reconcile(context.Context, Receipt) (string, State, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reconciles++
	return "session-1", Running, nil
}
func (f *fakeBridge) Stop(context.Context, string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.stops++
	if f.failStop {
		return ErrUnavailable
	}
	return nil
}
func (f *fakeBridge) counts() (int, int, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.starts, f.reconciles, f.stops
}

type testClock struct{ nanos atomic.Int64 }

func newTestClock(t time.Time) *testClock {
	c := &testClock{}
	c.Set(t)
	return c
}
func (c *testClock) Now() time.Time  { return time.Unix(0, c.nanos.Load()).UTC() }
func (c *testClock) Set(t time.Time) { c.nanos.Store(t.UTC().UnixNano()) }

type controlledBridge struct {
	mu                                 sync.Mutex
	starts, reconciles, stops          int
	startEntered, startRelease         chan struct{}
	reconcileEntered, reconcileRelease chan struct{}
	stopEntered, stopRelease           chan struct{}
	startSession                       string
	startErr                           error
	reconcileSession                   string
	reconcileState                     State
	reconcileErr                       error
	stopErr                            error
	onStop                             func()
}

func (b *controlledBridge) Start(context.Context, Request) (string, error) {
	b.mu.Lock()
	b.starts++
	entered, release, session, err := b.startEntered, b.startRelease, b.startSession, b.startErr
	b.mu.Unlock()
	if entered != nil {
		entered <- struct{}{}
		<-release
	}
	if session == "" {
		session = "session-controlled"
	}
	return session, err
}
func (b *controlledBridge) Reconcile(context.Context, Receipt) (string, State, error) {
	b.mu.Lock()
	b.reconciles++
	entered, release := b.reconcileEntered, b.reconcileRelease
	session, state, err := b.reconcileSession, b.reconcileState, b.reconcileErr
	b.mu.Unlock()
	if entered != nil {
		entered <- struct{}{}
		<-release
	}
	if session == "" {
		session = "session-controlled"
	}
	if state == "" {
		state = Running
	}
	return session, state, err
}
func (b *controlledBridge) Stop(context.Context, string) error {
	b.mu.Lock()
	b.stops++
	err, hook, entered, release := b.stopErr, b.onStop, b.stopEntered, b.stopRelease
	b.mu.Unlock()
	if entered != nil {
		entered <- struct{}{}
		<-release
	}
	if hook != nil {
		hook()
	}
	return err
}
func (b *controlledBridge) counts() (int, int, int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.starts, b.reconciles, b.stops
}

func dg(v string) string { return digestBytes([]byte(v)) }
func privateDir(t *testing.T) string {
	t.Helper()
	raw := t.TempDir()
	root, e := filepath.EvalSymlinks(raw)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.Chmod(root, 0700); e != nil {
		t.Fatal(e)
	}
	return root
}
func descriptorFixture() Descriptor {
	return Descriptor{Provider: "codex", Profile: "codex.profile", Revision: "r1", MappingDigest: dg("mapping"), RuntimeDigest: dg("runtime"), ProtocolDigest: dg("protocol"), RootDescriptorPath: "/Library/Application Support/OpenDuck/root.json", ReleaseFactPath: "/Library/Application Support/OpenDuck/release.json", KeyFactPath: "/Library/Application Support/OpenDuck/key.json"}
}
func verifiedFixture(t *testing.T, now time.Time) (Descriptor, VerifiedEnablement) {
	return verifiedFixtureWith(t, now, allowVerifier{})
}
func verifiedFixtureWith(t *testing.T, now time.Time, verifier EnablementVerifier) (Descriptor, VerifiedEnablement) {
	t.Helper()
	d := descriptorFixture()
	p := EnablementProof{SchemaVersion: enablementSchemaV1, DescriptorDigest: descriptorDigest(d), StaticIdentity: d.identity(), KeyEpoch: 1, SignerKeyID: "owner-key-1", IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour), Signature: "signature-1"}
	SealEnablementProof(&p)
	d.EnablementDigest = p.Digest
	v, e := VerifyEnablement(context.Background(), d, p, verifier, now)
	if e != nil {
		t.Fatal(e)
	}
	return d, v
}
func storeFixture(t *testing.T, v VerifiedEnablement, a *memoryAnchor, hooks storeHooks) (*Store, string, []byte) {
	t.Helper()
	root := privateDir(t)
	c := v.StoreConfig(root, "state.json", "state.lock", uint32(os.Geteuid()), uint32(os.Getegid()), a)
	c.hooks = hooks
	key := bytes.Repeat([]byte{7}, 32)
	s, e := OpenStore(c, key)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s, root, key
}
func coreFixture(t *testing.T, b Bridge) (*Core, *Store, *memoryAnchor, *allowAuthorizer, time.Time, VerifiedEnablement) {
	t.Helper()
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	_, v := verifiedFixture(t, now)
	anchor := &memoryAnchor{}
	s, _, _ := storeFixture(t, v, anchor, storeHooks{})
	auth := &allowAuthorizer{}
	c, e := NewEnabled(v, s, b, auth)
	if e != nil {
		t.Fatal(e)
	}
	c.now = func() time.Time { return now }
	return c, s, anchor, auth, now, v
}
func requestFixture(v VerifiedEnablement, id string, now time.Time) Request {
	r := Request{ID: id, Identity: v.proof.StaticIdentity, ExpiresAt: now.Add(5 * time.Minute)}
	r.Identity.Binding = dg("binding-" + id)
	r.Identity.Request = RequestDigest(r)
	return r
}

func TestDisabledCoreNeverInvokesBridgeOperations(t *testing.T) {
	d := descriptorFixture()
	c, e := NewDisabled(d)
	if e != nil {
		t.Fatal(e)
	}
	b := &fakeBridge{}
	c.bridge = b
	if _, e = c.Start(context.Background(), Request{}); !errors.Is(e, ErrDisabled) {
		t.Fatal(e)
	}
	if _, e = c.Reconcile(context.Background(), "id"); !errors.Is(e, ErrDisabled) {
		t.Fatal(e)
	}
	if e = c.Stop(context.Background(), "id"); !errors.Is(e, ErrDisabled) {
		t.Fatal(e)
	}
	if e = c.Prune(context.Background()); !errors.Is(e, ErrDisabled) {
		t.Fatal(e)
	}
	if a, bn, d := b.counts(); a+bn+d != 0 {
		t.Fatal("disabled bridge invoked")
	}
}

func TestEnabledLifecycleReplayAndExactIdentity(t *testing.T) {
	b := &fakeBridge{}
	c, _, _, _, now, v := coreFixture(t, b)
	r := requestFixture(v, "request-1", now)
	got, e := c.Start(context.Background(), r)
	if e != nil || got.State != Running {
		t.Fatal(e, got)
	}
	again, e := c.Start(context.Background(), r)
	if e != nil || again.State != Running {
		t.Fatal(e, again)
	}
	if starts, _, _ := b.counts(); starts != 1 {
		t.Fatalf("starts=%d", starts)
	}
	mutations := []func(*Request){func(x *Request) { x.Identity.Profile = "other" }, func(x *Request) { x.Identity.Revision = "r2" }, func(x *Request) { x.Identity.Mapping = dg("other") }, func(x *Request) { x.Identity.Runtime = dg("other") }, func(x *Request) { x.Identity.Protocol = dg("other") }, func(x *Request) { x.Identity.Route = "claude" }, func(x *Request) { x.Identity.Binding = dg("other") }, func(x *Request) { x.Identity.Request = dg("other") }}
	for i, mutate := range mutations {
		x := requestFixture(v, "mutated-"+string(rune('a'+i)), now)
		mutate(&x)
		if _, e = c.Start(context.Background(), x); !errors.Is(e, ErrConflict) {
			t.Fatalf("mutation %d: %v", i, e)
		}
	}
	if starts, _, _ := b.counts(); starts != 1 {
		t.Fatalf("mutations reached bridge: %d", starts)
	}
}

func TestEnablementRequiresExactFreshTrustedProof(t *testing.T) {
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	d := descriptorFixture()
	base := EnablementProof{SchemaVersion: enablementSchemaV1, DescriptorDigest: descriptorDigest(d), StaticIdentity: d.identity(), KeyEpoch: 1, SignerKeyID: "owner-key", IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour), Signature: "signature"}
	SealEnablementProof(&base)
	d.EnablementDigest = base.Digest
	if _, e := VerifyEnablement(context.Background(), d, base, allowVerifier{}, now); e != nil {
		t.Fatal(e)
	}
	for name, mutate := range map[string]func(*EnablementProof){"descriptor": func(p *EnablementProof) { p.DescriptorDigest = dg("bad") }, "identity": func(p *EnablementProof) { p.StaticIdentity.Route = "claude" }, "epoch": func(p *EnablementProof) { p.KeyEpoch++ }, "signer": func(p *EnablementProof) { p.SignerKeyID = "secret-key" }, "issued": func(p *EnablementProof) { p.IssuedAt = now.Add(time.Minute) }, "expired": func(p *EnablementProof) { p.ExpiresAt = now }, "revoked": func(p *EnablementProof) { p.Revoked = true }, "digest": func(p *EnablementProof) { p.Digest = dg("bad") }} {
		p := base
		mutate(&p)
		if _, e := VerifyEnablement(context.Background(), d, p, allowVerifier{}, now); e == nil {
			t.Fatalf("%s accepted", name)
		}
	}
	if _, e := VerifyEnablement(context.Background(), d, base, allowVerifier{deny: true}, now); e == nil {
		t.Fatal("untrusted proof accepted")
	}
}

func TestExpiredEnablementDisablesEveryOperation(t *testing.T) {
	b := &fakeBridge{}
	c, _, _, _, now, v := coreFixture(t, b)
	c.now = func() time.Time { return now.Add(2 * time.Hour) }
	r := requestFixture(v, "request-1", now.Add(2*time.Hour))
	if _, e := c.Start(context.Background(), r); !errors.Is(e, ErrDisabled) {
		t.Fatal(e)
	}
	if _, e := c.Reconcile(context.Background(), r.ID); !errors.Is(e, ErrDisabled) {
		t.Fatal(e)
	}
	if e := c.Stop(context.Background(), r.ID); !errors.Is(e, ErrDisabled) {
		t.Fatal(e)
	}
	if a, bn, d := b.counts(); a+bn+d != 0 {
		t.Fatal("expired enablement invoked bridge")
	}
}

func TestSecretAndTaskShapedValuesNeverPersist(t *testing.T) {
	b := &fakeBridge{}
	c, s, _, _, now, v := coreFixture(t, b)
	for i, value := range []string{"task text with spaces", "sk-live-value", "api_token", "my-secret"} {
		r := requestFixture(v, "bad-"+string(rune('a'+i)), now)
		r.Identity.Binding = value
		r.Identity.Request = RequestDigest(r)
		if _, e := c.Start(context.Background(), r); !errors.Is(e, ErrConflict) {
			t.Fatalf("%q: %v", value, e)
		}
	}
	if len(s.Snapshot()) != 0 {
		t.Fatal("unsafe request persisted")
	}
	if starts, _, _ := b.counts(); starts != 0 {
		t.Fatal("unsafe request reached bridge")
	}
}

func transportStartFixture(v VerifiedEnablement, id string, now time.Time) providertransport.RuntimeStart {
	return providertransport.RuntimeStart{
		RequestID: id, RequestDigest: dg("wire-" + id),
		ProfileID: v.proof.StaticIdentity.Profile, ProfileRevision: v.proof.StaticIdentity.Revision,
		MappingDigest: v.proof.StaticIdentity.Mapping, RuntimeDigest: v.proof.StaticIdentity.Runtime, ProtocolDigest: v.proof.StaticIdentity.Protocol,
		OrderID: "order-1", OrderHash: dg("order-1"), BindingID: "binding-1", BindingHash: dg("binding-1"), RunID: "run-1", AttemptID: "attempt-1",
		Deadline: now.Add(2 * time.Minute),
	}
}

func TestTransportDriverPersistsDistinctWireAndDaemonIdentity(t *testing.T) {
	b := &fakeBridge{}
	c, s, _, auth, now, v := coreFixture(t, b)
	d, err := NewTransportDriver(c)
	if err != nil {
		t.Fatal(err)
	}
	start := transportStartFixture(v, "pt-start-1", now)
	got, err := d.Start(context.Background(), start)
	if err != nil || got.ID != "session-1" {
		t.Fatalf("start=%+v err=%v", got, err)
	}
	receipts := s.Snapshot()
	if len(receipts) != 1 {
		t.Fatalf("receipts=%d", len(receipts))
	}
	r := receipts[0]
	if r.Identity.WireRequest != start.RequestID || r.Identity.WireDigest != start.RequestDigest || r.Identity.Request == start.RequestDigest || r.Identity.Order != start.OrderID || r.Identity.BindingID != start.BindingID || r.Identity.BindingHash != start.BindingHash || r.Identity.Binding != start.BindingHash {
		t.Fatalf("identity did not retain both exact identities: %+v", r.Identity)
	}
	if _, err = d.Start(context.Background(), start); err != nil {
		t.Fatalf("same exact retry: %v", err)
	}
	if starts, _, _ := b.counts(); starts != 1 {
		t.Fatalf("native starts=%d", starts)
	}
	mutated := start
	mutated.RequestDigest = dg("other-wire")
	if _, err = d.Start(context.Background(), mutated); !errors.Is(err, providertransport.ErrDenied) {
		t.Fatalf("wire digest substitution err=%v", err)
	}
	other := start
	other.RequestID = "pt-start-2"
	other.RequestDigest = dg("wire-pt-start-2")
	if _, err = d.Start(context.Background(), other); !errors.Is(err, providertransport.ErrDenied) {
		t.Fatalf("binding replay err=%v", err)
	}
	if starts, _, _ := b.counts(); starts != 1 {
		t.Fatalf("substitution/replay reached native start: %d", starts)
	}
	if !auth.seen(AuthorizeStart) {
		t.Fatal("start was not individually authorized")
	}
}

func TestTransportDriverRecoveryProofNeverStartsAgainAndControlsAreActionBound(t *testing.T) {
	b := &fakeBridge{}
	c, _, _, auth, now, v := coreFixture(t, b)
	d, err := NewTransportDriver(c)
	if err != nil {
		t.Fatal(err)
	}
	start := transportStartFixture(v, "pt-start-recover", now)
	if _, err = d.Start(context.Background(), start); err != nil {
		t.Fatal(err)
	}
	if _, err = d.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	route := routeFor(start.ProfileID, start.BindingID, start.BindingHash)
	proof, err := d.RecoverSession(context.Background(), route)
	if err != nil {
		t.Fatal(err)
	}
	if proof.RequestID != start.RequestID || proof.RequestDigest != start.RequestDigest || proof.NativeSessionID != "session-1" || proof.RouteRef != route {
		t.Fatalf("bad recovery proof: %+v", proof)
	}
	if starts, _, _ := b.counts(); starts != 1 {
		t.Fatalf("recovery invoked native start: %d", starts)
	}
	if err = d.Send(context.Background(), providertransport.RuntimeSession{ID: proof.NativeSessionID}, "revision-1"); err != nil {
		t.Fatal(err)
	}
	if !auth.seen(AuthorizeReconcile) || !auth.seen(AuthorizeSend) {
		t.Fatalf("missing exact action fences: reconcile=%t send=%t", auth.seen(AuthorizeReconcile), auth.seen(AuthorizeSend))
	}
	if err = d.Cancel(context.Background(), providertransport.RuntimeSession{ID: proof.NativeSessionID}, mesh.Cancellation{Mode: mesh.CancellationUser, RevisionRef: "revision-1", ReasonRef: "reason-1"}); err != nil {
		t.Fatal(err)
	}
	if _, err = d.RecoverSession(context.Background(), route); !errors.Is(err, providertransport.ErrReconcile) {
		t.Fatalf("cancelled session recovered as running: %v", err)
	}
}

func TestStrictStateDecoderRejectsNoncanonicalAndInvalidReceipts(t *testing.T) {
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	_, v := verifiedFixture(t, now)
	a := &memoryAnchor{}
	s, _, key := storeFixture(t, v, a, storeHooks{})
	c := s.config
	r := requestFixture(v, "request-1", now)
	receipt := Receipt{r.ID, r.Identity, Running, "session-1", now, r.ExpiresAt, now}
	body := diskBody{stateSchemaV2, 1, "", c.DescriptorDigest, c.EnablementDigest, c.KeyEpoch, []Receipt{receipt}}
	br, _ := json.Marshal(body)
	m := hmacBytes(key, br)
	valid, _ := json.Marshal(diskState{body, m})
	if _, e := decodeDiskState(valid, key, c); e != nil {
		t.Fatal(e)
	}
	inputs := [][]byte{append(append([]byte(nil), valid...), ' '), []byte(`{"body":{},"body":{},"mac":"x"}`), []byte(`{"unknown":1}`), make([]byte, maxStateBytes+1)}
	for i, input := range inputs {
		if _, e := decodeDiskState(input, key, c); !errors.Is(e, ErrCorrupt) {
			t.Fatalf("input %d: %v", i, e)
		}
	}
	bad := receipt
	bad.Session = "secret-session"
	body.Receipts = []Receipt{bad}
	br, _ = json.Marshal(body)
	raw, _ := json.Marshal(diskState{body, hmacBytes(key, br)})
	if _, e := decodeDiskState(raw, key, c); !errors.Is(e, ErrCorrupt) {
		t.Fatal("secret session accepted")
	}
	body.SchemaVersion = stateSchemaV1
	body.Receipts = []Receipt{receipt}
	br, _ = json.Marshal(body)
	raw, _ = json.Marshal(diskState{body, hmacBytes(key, br)})
	if _, e := decodeDiskState(raw, key, c); !errors.Is(e, ErrCorrupt) {
		t.Fatal("legacy schema accepted without a safe migration")
	}
}
func hmacBytes(key, body []byte) string {
	m := hmac.New(sha256.New, key)
	_, _ = m.Write(body)
	return hex.EncodeToString(m.Sum(nil))
}

func TestStoreRejectsUnsafeRootStateAndLockMetadata(t *testing.T) {
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	_, v := verifiedFixture(t, now)
	key := bytes.Repeat([]byte{7}, 32)
	newConfig := func(root string, anchor *memoryAnchor) StoreConfig {
		return v.StoreConfig(root, "state.json", "state.lock", uint32(os.Geteuid()), uint32(os.Getegid()), anchor)
	}
	t.Run("root-mode", func(t *testing.T) {
		root := privateDir(t)
		if err := os.Chmod(root, 0755); err != nil {
			t.Fatal(err)
		}
		if _, err := OpenStore(newConfig(root, &memoryAnchor{}), key); err == nil {
			t.Fatal("unsafe root accepted")
		}
	})
	t.Run("root-symlink", func(t *testing.T) {
		target := privateDir(t)
		link := filepath.Join(privateDir(t), "linked-root")
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
		if _, err := OpenStore(newConfig(link, &memoryAnchor{}), key); err == nil {
			t.Fatal("symlink root accepted")
		}
	})
	t.Run("wrong-owner-contract", func(t *testing.T) {
		root := privateDir(t)
		config := newConfig(root, &memoryAnchor{})
		config.OwnerUID++
		if _, err := OpenStore(config, key); err == nil {
			t.Fatal("wrong UID accepted")
		}
	})
	t.Run("preexisting-lock-hardlink-has-no-collateral-chmod", func(t *testing.T) {
		root := privateDir(t)
		victim := filepath.Join(root, "victim")
		if err := os.WriteFile(victim, []byte("untouched"), 0644); err != nil {
			t.Fatal(err)
		}
		if err := os.Link(victim, filepath.Join(root, "state.lock")); err != nil {
			t.Fatal(err)
		}
		if _, err := OpenStore(newConfig(root, &memoryAnchor{}), key); err == nil {
			t.Fatal("hardlinked lock accepted")
		}
		info, err := os.Stat(victim)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0644 {
			t.Fatalf("victim mode changed to %o", info.Mode().Perm())
		}
	})
	for _, kind := range []string{"state-hardlink", "state-mode", "lock-hardlink"} {
		t.Run(kind, func(t *testing.T) {
			anchor := &memoryAnchor{}
			root := privateDir(t)
			config := newConfig(root, anchor)
			s, err := OpenStore(config, key)
			if err != nil {
				t.Fatal(err)
			}
			b := &fakeBridge{}
			auth := &allowAuthorizer{}
			c, err := NewEnabled(v, s, b, auth)
			if err != nil {
				t.Fatal(err)
			}
			c.now = func() time.Time { return now }
			if kind != "lock-hardlink" {
				if _, err = c.Start(context.Background(), requestFixture(v, "request-1", now)); err != nil {
					t.Fatal(err)
				}
			}
			if err = s.Close(); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "state-hardlink":
				err = os.Link(filepath.Join(root, "state.json"), filepath.Join(root, "state-copy"))
			case "state-mode":
				err = os.Chmod(filepath.Join(root, "state.json"), 0644)
			case "lock-hardlink":
				err = os.Link(filepath.Join(root, "state.lock"), filepath.Join(root, "lock-copy"))
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err = OpenStore(config, key); err == nil {
				t.Fatalf("%s accepted", kind)
			}
		})
	}
}

func TestStatePathSwapAfterOpenIsRejected(t *testing.T) {
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	_, v := verifiedFixture(t, now)
	anchor := &memoryAnchor{}
	key := bytes.Repeat([]byte{7}, 32)
	root := privateDir(t)
	config := v.StoreConfig(root, "state.json", "state.lock", uint32(os.Geteuid()), uint32(os.Getegid()), anchor)
	s, err := OpenStore(config, key)
	if err != nil {
		t.Fatal(err)
	}
	b := &fakeBridge{}
	c, _ := NewEnabled(v, s, b, &allowAuthorizer{})
	c.now = func() time.Time { return now }
	if _, err = c.Start(context.Background(), requestFixture(v, "request-1", now)); err != nil {
		t.Fatal(err)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	var once sync.Once
	config.hooks.afterStateOpen = func() {
		once.Do(func() {
			old := filepath.Join(root, "old-state")
			replacement := filepath.Join(root, "replacement")
			_ = os.WriteFile(replacement, []byte("replacement"), 0600)
			_ = os.Rename(filepath.Join(root, "state.json"), old)
			_ = os.Rename(replacement, filepath.Join(root, "state.json"))
		})
	}
	if _, err = OpenStore(config, key); err == nil {
		t.Fatal("state replacement accepted")
	}
}

func TestParentReplacementBeforeAndAfterRenameFailsClosed(t *testing.T) {
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	_, v := verifiedFixture(t, now)
	key := bytes.Repeat([]byte{7}, 32)
	for _, phase := range []string{"before", "after"} {
		t.Run(phase, func(t *testing.T) {
			anchor := &memoryAnchor{}
			root := privateDir(t)
			moved := root + "-moved"
			var once sync.Once
			swap := func() {
				once.Do(func() {
					if err := os.Rename(root, moved); err != nil {
						t.Fatal(err)
					}
					if err := os.Mkdir(root, 0700); err != nil {
						t.Fatal(err)
					}
				})
			}
			config := v.StoreConfig(root, "state.json", "state.lock", uint32(os.Geteuid()), uint32(os.Getegid()), anchor)
			if phase == "before" {
				config.hooks.beforeRename = swap
			} else {
				config.hooks.afterRename = swap
			}
			s, err := OpenStore(config, key)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			c, _ := NewEnabled(v, s, &fakeBridge{}, &allowAuthorizer{})
			c.now = func() time.Time { return now }
			if _, err = c.Start(context.Background(), requestFixture(v, "request-1", now)); err == nil {
				t.Fatal("parent replacement accepted")
			}
			if _, err = os.Lstat(filepath.Join(root, "state.json")); !os.IsNotExist(err) {
				t.Fatalf("state escaped into replacement root: %v", err)
			}
		})
	}
}

func TestTempReplacementBeforeRenameIsRejectedWithoutPublishing(t *testing.T) {
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	_, v := verifiedFixture(t, now)
	anchor := &memoryAnchor{}
	root := privateDir(t)
	key := bytes.Repeat([]byte{7}, 32)
	config := v.StoreConfig(root, "state.json", "state.lock", uint32(os.Geteuid()), uint32(os.Getegid()), anchor)
	config.hooks.beforeRename = func() {
		matches, _ := filepath.Glob(filepath.Join(root, ".provider-state-*"))
		if len(matches) != 1 {
			t.Fatalf("temps=%v", matches)
		}
		original := matches[0] + ".original"
		if err := os.Rename(matches[0], original); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(matches[0], []byte("replacement"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	s, err := OpenStore(config, key)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	c, _ := NewEnabled(v, s, &fakeBridge{}, &allowAuthorizer{})
	c.now = func() time.Time { return now }
	if _, err = c.Start(context.Background(), requestFixture(v, "request-1", now)); err == nil {
		t.Fatal("temp replacement accepted")
	}
	if _, err = os.Lstat(filepath.Join(root, "state.json")); !os.IsNotExist(err) {
		t.Fatalf("state published: %v", err)
	}
}

func TestFinalHardlinkAndRollbackAreRejected(t *testing.T) {
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	_, v := verifiedFixture(t, now)
	key := bytes.Repeat([]byte{7}, 32)
	t.Run("post-rename-hardlink", func(t *testing.T) {
		anchor := &memoryAnchor{}
		root := privateDir(t)
		config := v.StoreConfig(root, "state.json", "state.lock", uint32(os.Geteuid()), uint32(os.Getegid()), anchor)
		config.hooks.afterRename = func() { _ = os.Link(filepath.Join(root, "state.json"), filepath.Join(root, "state-hardlink")) }
		s, err := OpenStore(config, key)
		if err != nil {
			t.Fatal(err)
		}
		defer s.Close()
		c, _ := NewEnabled(v, s, &fakeBridge{}, &allowAuthorizer{})
		c.now = func() time.Time { return now }
		if _, err = c.Start(context.Background(), requestFixture(v, "request-1", now)); !errors.Is(err, ErrCommitUncertain) {
			t.Fatalf("hardlink result=%v", err)
		}
	})
	t.Run("valid-old-state", func(t *testing.T) {
		anchor := &memoryAnchor{}
		root := privateDir(t)
		config := v.StoreConfig(root, "state.json", "state.lock", uint32(os.Geteuid()), uint32(os.Getegid()), anchor)
		s, err := OpenStore(config, key)
		if err != nil {
			t.Fatal(err)
		}
		c, _ := NewEnabled(v, s, &fakeBridge{}, &allowAuthorizer{})
		c.now = func() time.Time { return now }
		if _, err = c.Start(context.Background(), requestFixture(v, "request-1", now)); err != nil {
			t.Fatal(err)
		}
		old, _ := os.ReadFile(filepath.Join(root, "state.json"))
		if _, err = c.Start(context.Background(), requestFixture(v, "request-2", now)); err != nil {
			t.Fatal(err)
		}
		if err = s.Close(); err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(filepath.Join(root, "state.json"), old, 0600); err != nil {
			t.Fatal(err)
		}
		if _, err = OpenStore(config, key); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("rollback=%v", err)
		}
	})
}

func TestLifetimeLockHasNoStaleFileDeadlock(t *testing.T) {
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	_, v := verifiedFixture(t, now)
	anchor := &memoryAnchor{}
	root := privateDir(t)
	key := bytes.Repeat([]byte{7}, 32)
	config := v.StoreConfig(root, "state.json", "state.lock", uint32(os.Geteuid()), uint32(os.Getegid()), anchor)
	first, err := OpenStore(config, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = OpenStore(config, key); err == nil {
		t.Fatal("second writer acquired lock")
	}
	if err = first.Close(); err != nil {
		t.Fatal(err)
	}
	second, err := OpenStore(config, key)
	if err != nil {
		t.Fatalf("persistent lock file became stale: %v", err)
	}
	_ = second.Close()
}

func TestUnanchoredCommittedStateRecoversExactlyOneGeneration(t *testing.T) {
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	_, v := verifiedFixture(t, now)
	anchor := &memoryAnchor{}
	s, root, key := storeFixture(t, v, anchor, storeHooks{})
	c, _ := NewEnabled(v, s, &fakeBridge{}, &allowAuthorizer{})
	c.now = func() time.Time { return now }
	anchor.fail = true
	if _, err := c.Start(context.Background(), requestFixture(v, "request-1", now)); !errors.Is(err, ErrCommitUncertain) {
		t.Fatalf("advance failure=%v", err)
	}
	_ = s.Close()
	anchor.fail = false
	config := v.StoreConfig(root, "state.json", "state.lock", uint32(os.Geteuid()), uint32(os.Getegid()), anchor)
	recovered, err := OpenStore(config, key)
	if err != nil {
		t.Fatal(err)
	}
	defer recovered.Close()
	got := recovered.Snapshot()
	if len(got) != 1 || got[0].State != Starting {
		t.Fatalf("recovered=%+v", got)
	}
}

func bulkReceipts(v VerifiedEnablement, now time.Time, count int, state State) map[string]Receipt {
	out := make(map[string]Receipt, count)
	for i := 0; i < count; i++ {
		id := fmt.Sprintf("receipt-%03d", i)
		request := requestFixture(v, id, now)
		session := ""
		if state == Running || state == Terminal {
			session = fmt.Sprintf("session-%03d", i)
		}
		out[id] = Receipt{ID: id, Identity: request.Identity, State: state, Session: session, CreatedAt: now, ExpiresAt: request.ExpiresAt, UpdatedAt: now}
	}
	return out
}

func TestCapacityNeverEvictsActiveOrUncertainReceipts(t *testing.T) {
	for _, state := range []State{Starting, Running, Uncertain} {
		t.Run(string(state), func(t *testing.T) {
			b := &fakeBridge{}
			c, s, _, _, now, v := coreFixture(t, b)
			candidate := bulkReceipts(v, now, MaxReceipts, state)
			s.mu.Lock()
			err := s.saveLocked(context.Background(), candidate)
			s.mu.Unlock()
			if err != nil {
				t.Fatal(err)
			}
			before := s.Snapshot()
			if _, err = c.Start(context.Background(), requestFixture(v, "overflow", now)); !errors.Is(err, ErrCapacity) {
				t.Fatalf("capacity=%v", err)
			}
			after := s.Snapshot()
			if len(after) != MaxReceipts || !reflect.DeepEqual(before, after) {
				t.Fatal("active receipt evicted")
			}
			if err = c.Prune(context.Background()); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(after, s.Snapshot()) {
				t.Fatal("prune removed nonterminal receipt")
			}
			existing := requestFixture(v, "receipt-000", now)
			if _, err = c.Start(context.Background(), existing); err != nil {
				t.Fatal(err)
			}
			if starts, _, _ := b.counts(); starts != 0 {
				t.Fatal("replay invoked bridge")
			}
		})
	}
}

func TestExpiredTerminalMakesCapacityWithoutEvictingRunning(t *testing.T) {
	b := &fakeBridge{}
	c, s, _, _, now, v := coreFixture(t, b)
	candidate := bulkReceipts(v, now, MaxReceipts, Running)
	expired := candidate["receipt-000"]
	expired.State = Terminal
	expired.ExpiresAt = now.Add(-time.Second)
	expired.CreatedAt = now.Add(-time.Hour)
	expired.UpdatedAt = now
	expired.Identity.Request = RequestDigest(expired.request())
	candidate[expired.ID] = expired
	s.mu.Lock()
	err := s.saveLocked(context.Background(), candidate)
	s.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = c.Start(context.Background(), requestFixture(v, "replacement", now)); err != nil {
		t.Fatal(err)
	}
	got := s.Snapshot()
	if len(got) != MaxReceipts {
		t.Fatalf("len=%d", len(got))
	}
	for _, r := range got {
		if r.ID == expired.ID {
			t.Fatal("expired terminal retained")
		}
	}
}

type blockingBridge struct {
	entered chan string
	release chan struct{}
	mu      sync.Mutex
	calls   int
}

func (b *blockingBridge) Start(_ context.Context, r Request) (string, error) {
	b.mu.Lock()
	b.calls++
	b.mu.Unlock()
	if r.ID == "blocked" {
		b.entered <- r.ID
		<-b.release
	}
	return "session-" + r.ID, nil
}
func (b *blockingBridge) Reconcile(context.Context, Receipt) (string, State, error) {
	return "session-reconciled", Running, nil
}
func (b *blockingBridge) Stop(context.Context, string) error { return nil }

func TestProviderIOHoldsNoCoreOrStoreMutex(t *testing.T) {
	b := &blockingBridge{entered: make(chan string, 1), release: make(chan struct{})}
	c, _, _, _, now, v := coreFixture(t, b)
	blocked := make(chan error, 1)
	go func() { _, e := c.Start(context.Background(), requestFixture(v, "blocked", now)); blocked <- e }()
	select {
	case <-b.entered:
	case <-time.After(time.Second):
		t.Fatal("bridge not entered")
	}
	other := make(chan error, 1)
	go func() { _, e := c.Start(context.Background(), requestFixture(v, "other", now)); other <- e }()
	select {
	case e := <-other:
		if e != nil {
			t.Fatal(e)
		}
	case <-time.After(time.Second):
		t.Fatal("unrelated request blocked by provider I/O")
	}
	same := make(chan error, 1)
	go func() { _, e := c.Start(context.Background(), requestFixture(v, "blocked", now)); same <- e }()
	select {
	case e := <-same:
		if !errors.Is(e, ErrInFlight) {
			t.Fatalf("same request=%v", e)
		}
	case <-time.After(time.Second):
		t.Fatal("same request deadlocked")
	}
	close(b.release)
	if e := <-blocked; e != nil {
		t.Fatal(e)
	}
}

type reentrantBridge struct {
	core    *Core
	request Request
	once    sync.Once
	err     error
}

func (b *reentrantBridge) Start(_ context.Context, r Request) (string, error) {
	if r.ID == "outer" {
		b.once.Do(func() { _, b.err = b.core.Start(context.Background(), b.request) })
	}
	return "session-" + r.ID, nil
}
func (b *reentrantBridge) Reconcile(context.Context, Receipt) (string, State, error) {
	return "session-reconciled", Running, nil
}
func (b *reentrantBridge) Stop(context.Context, string) error { return nil }
func TestReentrantBridgeDoesNotDeadlock(t *testing.T) {
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	_, v := verifiedFixture(t, now)
	anchor := &memoryAnchor{}
	s, _, _ := storeFixture(t, v, anchor, storeHooks{})
	bridge := &reentrantBridge{request: requestFixture(v, "inner", now)}
	c, e := NewEnabled(v, s, bridge, &allowAuthorizer{})
	if e != nil {
		t.Fatal(e)
	}
	c.now = func() time.Time { return now }
	bridge.core = c
	done := make(chan error, 1)
	go func() { _, e := c.Start(context.Background(), requestFixture(v, "outer", now)); done <- e }()
	select {
	case e := <-done:
		if e != nil || bridge.err != nil {
			t.Fatal(e, bridge.err)
		}
	case <-time.After(time.Second):
		t.Fatal("reentrant bridge deadlocked")
	}
	if len(s.Snapshot()) != 2 {
		t.Fatal("reentrant operation not persisted")
	}
}

func TestBridgeFailuresHaveDurableUncertainStateAndNoSecretSession(t *testing.T) {
	for _, mode := range []string{"error", "empty"} {
		t.Run(mode, func(t *testing.T) {
			b := &fakeBridge{failStart: mode == "error", empty: mode == "empty"}
			c, s, _, _, now, v := coreFixture(t, b)
			_, err := c.Start(context.Background(), requestFixture(v, "request-1", now))
			if err == nil {
				t.Fatal("failure accepted")
			}
			got := s.Snapshot()
			if len(got) != 1 || got[0].State != Uncertain || got[0].Session != "" {
				t.Fatalf("state=%+v", got)
			}
		})
	}
}

func TestPostIOExpiryPersistsCompensationBeforeUnlockedStop(t *testing.T) {
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	clock := newTestClock(now)
	_, v := verifiedFixture(t, now)
	anchor := &memoryAnchor{}
	s, _, _ := storeFixture(t, v, anchor, storeHooks{})
	observed := make(chan State, 1)
	b := &controlledBridge{startEntered: make(chan struct{}, 1), startRelease: make(chan struct{})}
	b.onStop = func() {
		got := s.Snapshot()
		if len(got) == 1 {
			observed <- got[0].State
		}
	}
	c, err := NewEnabled(v, s, b, &allowAuthorizer{})
	if err != nil {
		t.Fatal(err)
	}
	c.now = clock.Now
	r := requestFixture(v, "expired-start", now)
	done := make(chan struct {
		r Receipt
		e error
	}, 1)
	go func() {
		got, e := c.Start(context.Background(), r)
		done <- struct {
			r Receipt
			e error
		}{got, e}
	}()
	select {
	case <-b.startEntered:
	case <-time.After(time.Second):
		t.Fatal("start did not enter provider")
	}
	clock.Set(r.ExpiresAt.Add(time.Nanosecond))
	close(b.startRelease)
	result := <-done
	if !errors.Is(result.e, ErrExpired) || result.r.State != Terminal {
		t.Fatalf("result=%+v err=%v", result.r, result.e)
	}
	select {
	case state := <-observed:
		if state != Compensating {
			t.Fatalf("stop observed %s, want compensating", state)
		}
	default:
		t.Fatal("stop did not observe durable receipt")
	}
	if starts, _, stops := b.counts(); starts != 1 || stops != 1 {
		t.Fatalf("provider calls start=%d stop=%d", starts, stops)
	}
}

func TestDynamicRevocationAfterStartIOCannotPersistRunning(t *testing.T) {
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	clock := newTestClock(now)
	verifier := &revocableVerifier{}
	_, v := verifiedFixtureWith(t, now, verifier)
	s, _, _ := storeFixture(t, v, &memoryAnchor{}, storeHooks{})
	b := &controlledBridge{startEntered: make(chan struct{}, 1), startRelease: make(chan struct{})}
	c, err := NewEnabled(v, s, b, &allowAuthorizer{})
	if err != nil {
		t.Fatal(err)
	}
	c.now = clock.Now
	r := requestFixture(v, "revoked-start", now)
	done := make(chan error, 1)
	go func() { _, e := c.Start(context.Background(), r); done <- e }()
	select {
	case <-b.startEntered:
	case <-time.After(time.Second):
		t.Fatal("start did not enter provider")
	}
	verifier.revoked.Store(true)
	close(b.startRelease)
	if e := <-done; !errors.Is(e, ErrDisabled) {
		t.Fatalf("result=%v", e)
	}
	got := s.Snapshot()
	if len(got) != 1 || got[0].State != Terminal {
		t.Fatalf("revoked operation persisted %+v", got)
	}
	if verifier.calls.Load() < 3 { // verification, pre-I/O fence, post-I/O fence
		t.Fatalf("dynamic verifier calls=%d", verifier.calls.Load())
	}
}

func TestExpiredReconcileOnlyCompensatesAndUsesActionBoundGrant(t *testing.T) {
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	clock := newTestClock(now)
	_, v := verifiedFixture(t, now)
	s, _, _ := storeFixture(t, v, &memoryAnchor{}, storeHooks{})
	auth := &allowAuthorizer{}
	b := &controlledBridge{reconcileEntered: make(chan struct{}, 1), reconcileRelease: make(chan struct{})}
	c, err := NewEnabled(v, s, b, auth)
	if err != nil {
		t.Fatal(err)
	}
	c.now = clock.Now
	r := requestFixture(v, "expired-reconcile", now)
	if _, _, err = s.prepare(context.Background(), r, now); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct {
		r Receipt
		e error
	}, 1)
	go func() {
		got, e := c.Reconcile(context.Background(), r.ID)
		done <- struct {
			r Receipt
			e error
		}{got, e}
	}()
	select {
	case <-b.reconcileEntered:
	case <-time.After(time.Second):
		t.Fatal("reconcile did not enter provider")
	}
	clock.Set(r.ExpiresAt.Add(time.Nanosecond))
	close(b.reconcileRelease)
	result := <-done
	got, err := result.r, result.e
	if !errors.Is(err, ErrExpired) || got.State != Terminal {
		t.Fatalf("result=%+v err=%v", got, err)
	}
	if !auth.seen(AuthorizeReconcile) {
		t.Fatal("reconcile did not require its own action grant")
	}
	if starts, reconciles, stops := b.counts(); starts != 0 || reconciles != 1 || stops != 1 {
		t.Fatalf("provider calls start=%d reconcile=%d stop=%d", starts, reconciles, stops)
	}
}

func TestMismatchedActionGrantCannotReachProviderIO(t *testing.T) {
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	_, v := verifiedFixture(t, now)
	s, _, _ := storeFixture(t, v, &memoryAnchor{}, storeHooks{})
	r := requestFixture(v, "tampered-binding", now)
	if _, _, err := s.prepare(context.Background(), r, now); err != nil {
		t.Fatal(err)
	}
	// The verifier receives the exact sealed receipt binding. A grant for a
	// different binding is not authority to reconcile this provider session.
	wrong := r
	wrong.Identity.Binding = dg("other-binding")
	wrong.Identity.Request = RequestDigest(wrong)
	b := &controlledBridge{}
	auth := exactAuthorizer{action: AuthorizeReconcile, want: wrong, digest: v.proof.Digest}
	c, err := NewEnabled(v, s, b, auth)
	if err != nil {
		t.Fatal(err)
	}
	c.now = func() time.Time { return now }
	if _, err = c.Reconcile(context.Background(), r.ID); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("mismatched grant=%v", err)
	}
	if starts, reconciles, stops := b.counts(); starts+reconciles+stops != 0 {
		t.Fatalf("mismatched grant reached provider: %d/%d/%d", starts, reconciles, stops)
	}
}

func TestExpiredTeardownRetainsCompensatingAndReopenNeverRestarts(t *testing.T) {
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	clock := newTestClock(now)
	_, v := verifiedFixture(t, now)
	anchor := &memoryAnchor{}
	s, root, key := storeFixture(t, v, anchor, storeHooks{})
	auth := &allowAuthorizer{}
	b := &controlledBridge{stopErr: ErrUnavailable}
	c, err := NewEnabled(v, s, b, auth)
	if err != nil {
		t.Fatal(err)
	}
	c.now = clock.Now
	r := requestFixture(v, "retry-stop", now)
	if _, err = c.Start(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	clock.Set(r.ExpiresAt.Add(time.Nanosecond))
	if err = c.Stop(context.Background(), r.ID); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("failed stop=%v", err)
	}
	got := s.Snapshot()
	if len(got) != 1 || got[0].State != Compensating || got[0].Session == "" {
		t.Fatalf("failed teardown=%+v", got)
	}
	if _, err = c.Start(context.Background(), r); !errors.Is(err, ErrExpired) {
		t.Fatalf("expired replay=%v", err)
	}
	if starts, _, _ := b.counts(); starts != 1 {
		t.Fatalf("restarted provider %d times", starts)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenStore(v.StoreConfig(root, "state.json", "state.lock", uint32(os.Geteuid()), uint32(os.Getegid()), anchor), key)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	b.stopErr = nil
	recovered, err := NewEnabled(v, reopened, b, auth)
	if err != nil {
		t.Fatal(err)
	}
	recovered.now = clock.Now
	if err = recovered.Stop(context.Background(), r.ID); err != nil {
		t.Fatal(err)
	}
	got = reopened.Snapshot()
	if len(got) != 1 || got[0].State != Terminal {
		t.Fatalf("recovered teardown=%+v", got)
	}
	if starts, _, stops := b.counts(); starts != 1 || stops != 2 {
		t.Fatalf("provider calls start=%d stop=%d", starts, stops)
	}
}

func TestTeardownGrantAndInflightFencePreventDuplicateStop(t *testing.T) {
	b := &controlledBridge{stopEntered: make(chan struct{}, 1), stopRelease: make(chan struct{})}
	c, s, _, auth, now, v := coreFixture(t, b)
	r := requestFixture(v, "fenced-stop", now)
	if _, err := c.Start(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- c.Stop(context.Background(), r.ID) }()
	select {
	case <-b.stopEntered:
	case <-time.After(time.Second):
		t.Fatal("stop did not enter provider")
	}
	if err := c.Stop(context.Background(), r.ID); !errors.Is(err, ErrInFlight) {
		t.Fatalf("concurrent stop=%v", err)
	}
	close(b.stopRelease)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if !auth.seen(AuthorizeStart) || !auth.seen(AuthorizeTeardown) {
		t.Fatal("missing action-bound authorization")
	}
	if got := s.Snapshot(); len(got) != 1 || got[0].State != Terminal {
		t.Fatalf("teardown receipt=%+v", got)
	}
	if _, _, stops := b.counts(); stops != 1 {
		t.Fatalf("duplicate provider stops=%d", stops)
	}
}

func TestPartialProviderSuccessIsDurablyCompensatedAndPreservesCause(t *testing.T) {
	partial := errors.New("provider acknowledged session incompletely")
	for _, operation := range []string{"start", "reconcile"} {
		t.Run(operation, func(t *testing.T) {
			b := &controlledBridge{startErr: partial, reconcileErr: partial}
			c, s, _, _, now, v := coreFixture(t, b)
			r := requestFixture(v, "partial-"+operation, now)
			observed := make(chan State, 1)
			b.onStop = func() {
				got := s.Snapshot()
				if len(got) == 1 {
					observed <- got[0].State
				}
			}
			var (
				got Receipt
				err error
			)
			if operation == "start" {
				got, err = c.Start(context.Background(), r)
			} else {
				if _, _, err = s.prepare(context.Background(), r, now); err != nil {
					t.Fatal(err)
				}
				got, err = c.Reconcile(context.Background(), r.ID)
			}
			if !errors.Is(err, partial) || got.State != Terminal {
				t.Fatalf("receipt=%+v err=%v", got, err)
			}
			select {
			case state := <-observed:
				if state != Compensating {
					t.Fatalf("stop observed %s, want compensating", state)
				}
			default:
				t.Fatal("Stop did not observe durable Compensating receipt")
			}
			starts, reconciles, stops := b.counts()
			if stops != 1 || (operation == "start" && starts != 1) || (operation == "reconcile" && reconciles != 1) {
				t.Fatalf("provider calls start=%d reconcile=%d stop=%d", starts, reconciles, stops)
			}
		})
	}
}

func TestPartialProviderSuccessStopFailureReopensWithoutRestart(t *testing.T) {
	partial := errors.New("provider acknowledged session incompletely")
	for _, operation := range []string{"start", "reconcile"} {
		t.Run(operation, func(t *testing.T) {
			now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
			_, v := verifiedFixture(t, now)
			anchor := &memoryAnchor{}
			s, root, key := storeFixture(t, v, anchor, storeHooks{})
			b := &controlledBridge{startErr: partial, reconcileErr: partial, stopErr: ErrUnavailable}
			auth := &allowAuthorizer{}
			c, err := NewEnabled(v, s, b, auth)
			if err != nil {
				t.Fatal(err)
			}
			c.now = func() time.Time { return now }
			r := requestFixture(v, "partial-retry-"+operation, now)
			if operation == "start" {
				_, err = c.Start(context.Background(), r)
			} else {
				if _, _, err = s.prepare(context.Background(), r, now); err != nil {
					t.Fatal(err)
				}
				_, err = c.Reconcile(context.Background(), r.ID)
			}
			if !errors.Is(err, partial) || !errors.Is(err, ErrUnavailable) {
				t.Fatalf("partial stop error=%v", err)
			}
			got := s.Snapshot()
			if len(got) != 1 || got[0].State != Compensating || got[0].Session == "" {
				t.Fatalf("failed compensation=%+v", got)
			}
			beforeStarts, _, _ := b.counts()
			if replay, replayErr := c.Start(context.Background(), r); replayErr != nil || replay.State != Compensating {
				t.Fatalf("replay=%+v err=%v", replay, replayErr)
			}
			afterStarts, _, _ := b.counts()
			if afterStarts != beforeStarts {
				t.Fatalf("replay started a second provider session: %d -> %d", beforeStarts, afterStarts)
			}
			if err = s.Close(); err != nil {
				t.Fatal(err)
			}
			reopened, err := OpenStore(v.StoreConfig(root, "state.json", "state.lock", uint32(os.Geteuid()), uint32(os.Getegid()), anchor), key)
			if err != nil {
				t.Fatal(err)
			}
			defer reopened.Close()
			b.stopErr = nil
			recovered, err := NewEnabled(v, reopened, b, auth)
			if err != nil {
				t.Fatal(err)
			}
			recovered.now = func() time.Time { return now }
			if err = recovered.Stop(context.Background(), r.ID); err != nil {
				t.Fatal(err)
			}
			got = reopened.Snapshot()
			if len(got) != 1 || got[0].State != Terminal {
				t.Fatalf("recovered compensation=%+v", got)
			}
			starts, _, stops := b.counts()
			wantStarts := 0
			if operation == "start" {
				wantStarts = 1
			}
			if starts != wantStarts || stops != 2 {
				t.Fatalf("provider calls start=%d stop=%d", starts, stops)
			}
		})
	}
}

func TestUnsafePartialProviderSessionRemainsUncertain(t *testing.T) {
	partial := errors.New("provider returned unsafe handle")
	for _, operation := range []string{"start", "reconcile"} {
		t.Run(operation, func(t *testing.T) {
			b := &controlledBridge{startSession: "secret-session", startErr: partial, reconcileSession: "secret-session", reconcileErr: partial}
			c, s, _, _, now, v := coreFixture(t, b)
			r := requestFixture(v, "unsafe-partial-"+operation, now)
			var err error
			if operation == "start" {
				_, err = c.Start(context.Background(), r)
			} else {
				if _, _, err = s.prepare(context.Background(), r, now); err != nil {
					t.Fatal(err)
				}
				_, err = c.Reconcile(context.Background(), r.ID)
			}
			if !errors.Is(err, partial) {
				t.Fatal(err)
			}
			got := s.Snapshot()
			if len(got) != 1 || got[0].State != Uncertain || got[0].Session != "" {
				t.Fatalf("unsafe partial receipt=%+v", got)
			}
			if _, _, stops := b.counts(); stops != 0 {
				t.Fatalf("unsafe handle reached Stop %d times", stops)
			}
		})
	}
}

func TestPartialProviderSuccessComposesPostIOExpiryAndRevocation(t *testing.T) {
	partial := errors.New("provider acknowledged session incompletely")
	t.Run("start-expiry", func(t *testing.T) {
		now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
		clock := newTestClock(now)
		_, v := verifiedFixture(t, now)
		s, _, _ := storeFixture(t, v, &memoryAnchor{}, storeHooks{})
		b := &controlledBridge{startEntered: make(chan struct{}, 1), startRelease: make(chan struct{}), startErr: partial}
		c, err := NewEnabled(v, s, b, &allowAuthorizer{})
		if err != nil {
			t.Fatal(err)
		}
		c.now = clock.Now
		r := requestFixture(v, "partial-expiry", now)
		done := make(chan error, 1)
		go func() { _, err := c.Start(context.Background(), r); done <- err }()
		select {
		case <-b.startEntered:
		case <-time.After(time.Second):
			t.Fatal("Start did not enter provider")
		}
		clock.Set(r.ExpiresAt.Add(time.Nanosecond))
		close(b.startRelease)
		if err := <-done; !errors.Is(err, partial) || !errors.Is(err, ErrExpired) {
			t.Fatalf("composed expiry error=%v", err)
		}
		if got := s.Snapshot(); len(got) != 1 || got[0].State != Terminal {
			t.Fatalf("expiry compensation=%+v", got)
		}
	})
	t.Run("reconcile-revocation", func(t *testing.T) {
		now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
		clock := newTestClock(now)
		verifier := &revocableVerifier{}
		_, v := verifiedFixtureWith(t, now, verifier)
		s, _, _ := storeFixture(t, v, &memoryAnchor{}, storeHooks{})
		b := &controlledBridge{reconcileEntered: make(chan struct{}, 1), reconcileRelease: make(chan struct{}), reconcileErr: partial}
		c, err := NewEnabled(v, s, b, &allowAuthorizer{})
		if err != nil {
			t.Fatal(err)
		}
		c.now = clock.Now
		r := requestFixture(v, "partial-revocation", now)
		if _, _, err = s.prepare(context.Background(), r, now); err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() { _, err := c.Reconcile(context.Background(), r.ID); done <- err }()
		select {
		case <-b.reconcileEntered:
		case <-time.After(time.Second):
			t.Fatal("Reconcile did not enter provider")
		}
		verifier.revoked.Store(true)
		close(b.reconcileRelease)
		if err := <-done; !errors.Is(err, partial) || !errors.Is(err, ErrDisabled) {
			t.Fatalf("composed revocation error=%v", err)
		}
		if got := s.Snapshot(); len(got) != 1 || got[0].State != Terminal {
			t.Fatalf("revocation compensation=%+v", got)
		}
	})
}
