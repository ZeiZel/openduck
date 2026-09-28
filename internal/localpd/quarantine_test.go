package localpd

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"openduck/internal/admission"
)

const quarantineSentinel = "RAW_PD_SENTINEL_DO_NOT_PERSIST"
const qDigest = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func quarantineFixture(t *testing.T) (*Quarantine, *MemoryQuarantineCheckpointStore, string, PayloadBinding, time.Time) {
	t.Helper()
	dir := t.TempDir()
	_ = os.Chmod(dir, 0700)
	now := time.Now().UTC().Truncate(time.Second)
	runtime, config := qwenAttestations(now)
	b := PayloadBinding{7, qDigest, qDigest, qDigest, runtime.Digest, config.Digest}
	if !b.valid() || runtime.Validate() != nil || config.Validate() != nil {
		t.Fatalf("bad qwen fixture b=%+v runtime=%v config=%v", b, runtime.Validate(), config.Validate())
	}
	cp := NewMemoryQuarantineCheckpointStore()
	q, err := NewTestQuarantine(filepath.Join(dir, "quarantine"), []byte("01234567890123456789012345678901"), cp)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = q.Close() })
	return q, cp, dir, b, now
}

type testSigner struct{}

func (testSigner) Sign(b []byte) (string, error)  { return "sig:" + string(b[:min(8, len(b))]), nil }
func (testSigner) Verify(_ []byte, s string) bool { return len(s) > 4 && s[:4] == "sig:" }

type failingSigner struct{}

func (failingSigner) Sign([]byte) (string, error) { return "", errors.New("signer unavailable") }
func (failingSigner) Verify([]byte, string) bool  { return false }

type testVerifier struct{}

func (testVerifier) Verify(_ []byte, s string) bool {
	return s == qDigest || len(s) > 4 && s[:4] == "sig:"
}

type receiptConsumer struct{}

func (receiptConsumer) ConsumeIfMonotonic(_ QuarantineErasureReceipt, _ AuthorityMetadata) error {
	return nil
}

type acceptAuthority[T AuthoritativeContract] struct{}

func (acceptAuthority[T]) ConsumeIfMonotonic(_ T, _ AuthorityMetadata) error { return nil }

func qwenAttestations(now time.Time) (QwenRuntimeAttestation, QwenConfigAttestation) {
	r := QwenRuntimeAttestation{SchemaVersion: QwenRuntimeAttestationV1, RuntimeID: "qwen-runtime", ProcessDigest: qDigest, BinaryDigest: qDigest, Model: "qwen3:8b", EndpointDigest: qDigest, NetworkPolicy: "none", ToolsPolicy: "none", AttestedAt: now, ExpiresAt: now.Add(time.Hour), Nonce: "runtime-nonce", ControllerSignature: qDigest}
	u, _ := r.CanonicalUnsigned()
	r.Digest, _ = CanonicalDigest(json.RawMessage(u))
	c := QwenConfigAttestation{SchemaVersion: QwenConfigAttestationV1, ConfigID: "qwen-config", ConfigDigest: qDigest, Model: "qwen3:8b", NumCtx: 40960, ContextTokens: 32768, Thinking: "medium", NetworkPolicy: "none", ToolsPolicy: "none", ConfigVersion: 1, IssuedAt: now, ExpiresAt: now.Add(time.Hour), Nonce: "config-nonce", ControllerSignature: qDigest}
	u, _ = c.CanonicalUnsigned()
	c.Digest, _ = CanonicalDigest(json.RawMessage(u))
	return r, c
}

func TestQuarantineEncryptedRestartAndNoPublicRead(t *testing.T) {
	q, cp, dir, b, now := quarantineFixture(t)
	ref, err := q.Put([]byte(quarantineSentinel), b, now, now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(filepath.Join(dir, "quarantine"))
	if containsBytes(raw, []byte(quarantineSentinel)) {
		t.Fatal("plaintext persisted")
	}
	_ = q.Close()
	q2, err := NewTestQuarantine(filepath.Join(dir, "quarantine"), []byte("01234567890123456789012345678901"), cp)
	if err != nil {
		t.Fatal(err)
	}
	defer q2.Close()
	got, _, err := q2.readForTest(ref, now.Add(time.Minute))
	if err != nil || string(got) != quarantineSentinel {
		t.Fatalf("read=%q %v", got, err)
	}
}

func TestPurgeIsHonestSoftAndAuthoritative(t *testing.T) {
	q, _, _, b, now := quarantineFixture(t)
	ref, _ := q.Put([]byte("private"), b, now, now.Add(time.Second))
	rec, err := q.Purge(ref, now.Add(2*time.Second), testSigner{})
	if err != nil {
		t.Fatal(err)
	}
	if rec.DeletionStatus != "partial" || rec.CoverageComplete || rec.VerificationMethod == "authoritative_store_absence" {
		t.Fatalf("overclaim %+v", rec)
	}
	if err = VerifyAuthoritative(now.Add(3*time.Second), rec, testVerifier{}, receiptConsumer{}); err != nil {
		t.Fatalf("authoritative receipt: %v", err)
	}
	if _, _, err = q.readForTest(ref, now.Add(3*time.Second)); !errors.Is(err, ErrQuarantineNotFound) {
		t.Fatal(err)
	}
}

func TestPurgeSignerFailureRestartReconcileAndIdempotency(t *testing.T) {
	q, cp, dir, b, now := quarantineFixture(t)
	ref, _ := q.Put([]byte("private"), b, now, now.Add(time.Second))
	if _, err := q.Purge(ref, now.Add(2*time.Second), failingSigner{}); err == nil {
		t.Fatal("signer failure accepted")
	}
	if err := q.withLock(func() error {
		s, e := q.load()
		if e != nil {
			return e
		}
		r := s.Records[ref]
		if r.PurgeState != "pending" || len(r.PurgeIntent) == 0 || len(r.Ciphertext) == 0 || r.Purged {
			return errors.New("intent was not recoverable")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	_ = q.Close()
	q2, err := NewTestQuarantine(filepath.Join(dir, "quarantine"), []byte("01234567890123456789012345678901"), cp)
	if err != nil {
		t.Fatal(err)
	}
	defer q2.Close()
	receipts, err := q2.ReconcilePendingPurges(testSigner{})
	if err != nil || len(receipts) != 1 {
		t.Fatalf("reconcile=%+v %v", receipts, err)
	}
	again, err := q2.Purge(ref, now.Add(3*time.Second), testSigner{})
	if err != nil || again != receipts[0] {
		t.Fatalf("idempotent=%+v %v", again, err)
	}
}

type fakeTransport struct {
	fail  bool
	calls int
}

func (f *fakeTransport) infer(_ context.Context, req localInferenceRequest) ([]byte, error) {
	f.calls++
	if f.fail {
		return nil, errors.New("crash")
	}
	if req.pair.RuntimeDigest == "" || req.pair.ConfigDigest == "" {
		return nil, errors.New("missing pair binding")
	}
	return append([]byte("local:"), req.payload...), nil
}

type fakeResolver struct {
	snap               DispatchAuthoritySnapshot
	fail, finalizeFail bool
}

func (f fakeResolver) ResolveCandidate(_ context.Context, _ admission.LocalPDDispatch, _ time.Time) (DispatchAuthoritySnapshot, error) {
	if f.fail {
		return DispatchAuthoritySnapshot{}, errors.New("forged")
	}
	return f.snap, nil
}

type fakePairLease struct {
	pair       CurrentQwenPair
	done, fail bool
}

func (l *fakePairLease) binding() CurrentQwenPair { return l.pair }
func (l *fakePairLease) finalize(_ context.Context, r QwenInferenceReceipt) error {
	if l.fail || r.Pair != l.pair || !digestRE.MatchString(r.OutputDigest) || !validID(r.DispatchID) {
		return errors.New("bad receipt")
	}
	l.done = true
	return nil
}
func (l *fakePairLease) release() {}
func (f fakeResolver) AcquireCurrentQwenPairLease(_ context.Context, p CurrentQwenPair) (currentQwenPairLease, error) {
	if f.fail {
		return nil, errors.New("not current")
	}
	return &fakePairLease{pair: p, fail: f.finalizeFail}, nil
}

type blockingTransport struct {
	entered chan CurrentQwenPair
	release chan struct{}
}

func (b *blockingTransport) infer(_ context.Context, r localInferenceRequest) ([]byte, error) {
	b.entered <- r.pair
	<-b.release
	return append([]byte("local:"), r.payload...), nil
}

type spyPairResolver struct {
	mu                      sync.Mutex
	snap                    DispatchAuthoritySnapshot
	current                 CurrentQwenPair
	confirmCalls, successes int
	swapTo                  *CurrentQwenPair
	receipts                []QwenInferenceReceipt
}

func pairFromSnapshot(s DispatchAuthoritySnapshot) CurrentQwenPair {
	return CurrentQwenPair{RuntimeID: s.QwenRuntime.RuntimeID, ConfigID: s.QwenConfig.ConfigID, RuntimeDigest: s.QwenRuntime.Digest, ConfigDigest: s.QwenConfig.Digest, ConfigVersion: s.QwenConfig.ConfigVersion, PolicyVersion: s.QwenConfig.ConfigVersion, RuntimeNetworkPolicy: s.QwenRuntime.NetworkPolicy, RuntimeToolsPolicy: s.QwenRuntime.ToolsPolicy, ConfigNetworkPolicy: s.QwenConfig.NetworkPolicy, ConfigToolsPolicy: s.QwenConfig.ToolsPolicy}
}
func newSpyPairResolver(s DispatchAuthoritySnapshot) *spyPairResolver {
	return &spyPairResolver{snap: s, current: pairFromSnapshot(s)}
}
func (s *spyPairResolver) ResolveCandidate(_ context.Context, _ admission.LocalPDDispatch, _ time.Time) (DispatchAuthoritySnapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := s.snap
	if s.swapTo != nil {
		s.current = *s.swapTo
		s.swapTo = nil
	}
	return out, nil
}

type spyHeldLease struct {
	owner    *spyPairResolver
	pair     CurrentQwenPair
	released bool
}

func (l *spyHeldLease) binding() CurrentQwenPair { return l.pair }
func (l *spyHeldLease) finalize(_ context.Context, r QwenInferenceReceipt) error {
	if l.released {
		return errors.New("released")
	}
	if r.Pair != l.pair || !digestRE.MatchString(r.OutputDigest) || !validID(r.DispatchID) {
		l.release()
		return errors.New("receipt mismatch")
	}
	l.owner.successes++
	l.owner.receipts = append(l.owner.receipts, r)
	l.release()
	return nil
}
func (l *spyHeldLease) release() {
	if !l.released {
		l.released = true
		l.owner.mu.Unlock()
	}
}
func (s *spyPairResolver) AcquireCurrentQwenPairLease(_ context.Context, p CurrentQwenPair) (currentQwenPairLease, error) {
	s.mu.Lock()
	s.confirmCalls++
	if p != s.current {
		s.mu.Unlock()
		return nil, errors.New("pair swapped")
	}
	return &spyHeldLease{owner: s, pair: p}, nil
}
func (s *spyPairResolver) counts() (int, int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.confirmCalls, s.successes
}
func (s *spyPairResolver) receiptSnapshot() []QwenInferenceReceipt {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]QwenInferenceReceipt(nil), s.receipts...)
}

func sealedDispatch(t *testing.T, ref string, b PayloadBinding, now time.Time) (admission.LocalPDDispatch, DispatchAuthoritySnapshot) {
	t.Helper()
	runtime, config := qwenAttestations(now)
	d := admission.LocalPDDispatch{SchemaVersion: admission.LocalPDDispatchV1, DispatchID: "dispatch-1", Nonce: "nonce-1", IssuedAt: now, ExpiresAt: now.Add(time.Hour), PrivacyDecisionDigest: qDigest, ConversationScope: "scope", EventRevisionSetDigest: qDigest, ClassHighWater: admission.L2, ClassHighWaterVersion: 7, PayloadRef: ref, QwenModel: "qwen3:8b", QwenRuntimeAttestationDigest: runtime.Digest, QwenConfigDigest: config.Digest, LocalPDViewBindingDigest: qDigest, ToolsNetworkPolicy: "none", Fallback: "none"}
	u, _ := dispatchUnsigned(d)
	d.Digest, _ = admission.CanonicalDigest(json.RawMessage(u))
	d.ControllerSignature = qDigest
	s := DispatchAuthoritySnapshot{DecisionDigest: qDigest, ConversationScope: "scope", EventRevisionSetDigest: qDigest, ClassHighWater: "L2", ClassHighWaterVersion: 7, IngressGateDigest: b.IngressGateDigest, PDSessionDigest: b.PDSessionDigest, LocalPDViewDigest: qDigest, HighWaterVersion: b.HighWaterVersion, HighWaterDigest: b.HighWaterDigest, QwenRuntime: runtime, QwenConfig: config, ContextWindow: 40960}
	return d, s
}

func TestDispatchSignedBindingsReplayAndOpaqueOutput(t *testing.T) {
	q, _, _, b, now := quarantineFixture(t)
	ref, _ := q.Put([]byte("private"), b, now, now.Add(time.Hour))
	d, s := sealedDispatch(t, ref, b, now)
	tr := &fakeTransport{}
	rt, err := newTestSyntheticRuntime(q, tr, fakeResolver{snap: s}, testVerifier{}, mintTestTransportCapability())
	if err != nil {
		t.Fatal(err)
	}
	out, err := rt.Dispatch(context.Background(), d, b, now.Add(time.Minute))
	if err != nil || out.Ref == "" || out.Digest == "" || containsBytes([]byte(out.Ref+out.Digest), []byte("private")) {
		t.Fatalf("out=%+v err=%v", out, err)
	}
	if _, err = rt.Dispatch(context.Background(), d, b, now.Add(2*time.Minute)); !errors.Is(err, ErrQuarantineReplay) {
		t.Fatalf("replay=%v", err)
	}
	if tr.calls != 1 {
		t.Fatalf("transport calls=%d", tr.calls)
	}
	if _, _, err = q.readForTest(ref, now.Add(3*time.Minute)); !errors.Is(err, ErrQuarantineReplay) {
		t.Fatalf("consumed plaintext remained readable: %v", err)
	}
}

func TestForgedCurrentBindingRejectedBeforeTransport(t *testing.T) {
	q, _, _, b, now := quarantineFixture(t)
	ref, _ := q.Put([]byte("private"), b, now, now.Add(time.Hour))
	d, s := sealedDispatch(t, ref, b, now)
	s.HighWaterDigest = "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	tr := &fakeTransport{}
	rt, _ := newTestSyntheticRuntime(q, tr, fakeResolver{snap: s}, testVerifier{}, mintTestTransportCapability())
	if _, err := rt.Dispatch(context.Background(), d, b, now.Add(time.Minute)); !errors.Is(err, ErrRuntimeBinding) {
		t.Fatalf("forged=%v", err)
	}
	if tr.calls != 0 {
		t.Fatal("transport called")
	}
}

func TestForgedDispatchSignatureRejectedBeforeTransport(t *testing.T) {
	q, _, _, b, now := quarantineFixture(t)
	ref, _ := q.Put([]byte("private"), b, now, now.Add(time.Hour))
	d, s := sealedDispatch(t, ref, b, now)
	d.ControllerSignature = "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	tr := &fakeTransport{}
	rt, _ := newTestSyntheticRuntime(q, tr, fakeResolver{snap: s}, testVerifier{}, mintTestTransportCapability())
	if _, err := rt.Dispatch(context.Background(), d, b, now.Add(time.Minute)); !errors.Is(err, ErrRuntimeBinding) {
		t.Fatalf("forged signature=%v", err)
	}
	if tr.calls != 0 {
		t.Fatal("transport called")
	}
}

func TestExactQwenConfigurationAndDigestSpliceRejected(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*admission.LocalPDDispatch, *DispatchAuthoritySnapshot)
	}{
		{"num-ctx", func(d *admission.LocalPDDispatch, s *DispatchAuthoritySnapshot) {
			s.QwenConfig.NumCtx = 32768
			sealQwenConfig(&s.QwenConfig)
			d.QwenConfigDigest = s.QwenConfig.Digest
		}},
		{"context-window", func(_ *admission.LocalPDDispatch, s *DispatchAuthoritySnapshot) { s.ContextWindow = 32768 }},
		{"context-tokens", func(d *admission.LocalPDDispatch, s *DispatchAuthoritySnapshot) {
			s.QwenConfig.ContextTokens = 16384
			sealQwenConfig(&s.QwenConfig)
			d.QwenConfigDigest = s.QwenConfig.Digest
		}},
		{"thinking", func(d *admission.LocalPDDispatch, s *DispatchAuthoritySnapshot) {
			s.QwenConfig.Thinking = "high"
			sealQwenConfig(&s.QwenConfig)
			d.QwenConfigDigest = s.QwenConfig.Digest
		}},
		{"model", func(d *admission.LocalPDDispatch, s *DispatchAuthoritySnapshot) {
			s.QwenRuntime.Model = "qwen3:14b"
			sealQwenRuntime(&s.QwenRuntime)
			d.QwenModel = "qwen3:14b"
			d.QwenRuntimeAttestationDigest = s.QwenRuntime.Digest
		}},
		{"digest-splice", func(d *admission.LocalPDDispatch, s *DispatchAuthoritySnapshot) {
			d.QwenRuntimeAttestationDigest = s.QwenConfig.Digest
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			q, _, _, b, now := quarantineFixture(t)
			ref, _ := q.Put([]byte("private"), b, now, now.Add(time.Hour))
			d, s := sealedDispatch(t, ref, b, now)
			tc.mutate(&d, &s)
			u, _ := dispatchUnsigned(d)
			d.Digest, _ = admission.CanonicalDigest(json.RawMessage(u))
			expected := b
			expected.QwenRuntimeDigest = s.QwenRuntime.Digest
			expected.QwenConfigDigest = s.QwenConfig.Digest
			tr := &fakeTransport{}
			spy := newSpyPairResolver(s)
			rt, _ := newTestSyntheticRuntime(q, tr, spy, testVerifier{}, mintTestTransportCapability())
			if _, err := rt.Dispatch(context.Background(), d, expected, now.Add(time.Minute)); !errors.Is(err, ErrRuntimeBinding) {
				t.Fatalf("accepted: %v", err)
			}
			if tr.calls != 0 {
				t.Fatal("transport called")
			}
			if calls, success := spy.counts(); calls != 0 || success != 0 {
				t.Fatalf("invalid pair mutated current state calls=%d success=%d", calls, success)
			}
			if _, _, err := q.readForTest(ref, now.Add(2*time.Minute)); err != nil {
				t.Fatalf("invalid pair consumed payload: %v", err)
			}
		})
	}
}

func TestReusableCurrentQwenPairAndConcurrentSwap(t *testing.T) {
	q, _, _, b, now := quarantineFixture(t)
	ref1, _ := q.Put([]byte("one"), b, now, now.Add(time.Hour))
	ref2, _ := q.Put([]byte("two"), b, now, now.Add(time.Hour))
	d1, s := sealedDispatch(t, ref1, b, now)
	spy := newSpyPairResolver(s)
	rt, _ := newTestSyntheticRuntime(q, &fakeTransport{}, spy, testVerifier{}, mintTestTransportCapability())
	if _, err := rt.Dispatch(context.Background(), d1, b, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	d2, _ := sealedDispatch(t, ref2, b, now)
	d2.DispatchID = "dispatch-2"
	d2.Nonce = "nonce-2"
	u, _ := dispatchUnsigned(d2)
	d2.Digest, _ = admission.CanonicalDigest(json.RawMessage(u))
	if _, err := rt.Dispatch(context.Background(), d2, b, now.Add(2*time.Minute)); err != nil {
		t.Fatalf("reusable pair=%v", err)
	}
	if calls, success := spy.counts(); calls != 2 || success != 2 {
		t.Fatalf("pair was consumed calls=%d success=%d", calls, success)
	}
	ref3, _ := q.Put([]byte("three"), b, now, now.Add(time.Hour))
	d3, _ := sealedDispatch(t, ref3, b, now)
	d3.DispatchID = "dispatch-3"
	d3.Nonce = "nonce-3"
	u, _ = dispatchUnsigned(d3)
	d3.Digest, _ = admission.CanonicalDigest(json.RawMessage(u))
	swapped := spy.current
	swapped.ConfigID = "qwen-config-new"
	spy.mu.Lock()
	spy.swapTo = &swapped
	spy.mu.Unlock()
	if _, err := rt.Dispatch(context.Background(), d3, b, now.Add(3*time.Minute)); !errors.Is(err, ErrRuntimeBinding) {
		t.Fatalf("cross-swap accepted: %v", err)
	}
	if _, _, err := q.readForTest(ref3, now.Add(4*time.Minute)); err != nil {
		t.Fatalf("invalid pair mutated payload: %v", err)
	}
}

func TestPairLeaseHeldThroughInferenceAndReceiptExact(t *testing.T) {
	q, _, _, b, now := quarantineFixture(t)
	ref, _ := q.Put([]byte(quarantineSentinel), b, now, now.Add(time.Hour))
	d, s := sealedDispatch(t, ref, b, now)
	spy := newSpyPairResolver(s)
	bt := &blockingTransport{entered: make(chan CurrentQwenPair, 1), release: make(chan struct{})}
	rt, _ := newTestSyntheticRuntime(q, bt, spy, testVerifier{}, mintTestTransportCapability())
	type dispatchResult struct {
		out LocalResultRef
		err error
	}
	done := make(chan dispatchResult, 1)
	go func() {
		o, e := rt.Dispatch(context.Background(), d, b, now.Add(time.Minute))
		done <- dispatchResult{o, e}
	}()
	pair := <-bt.entered
	if pair != pairFromSnapshot(s) {
		t.Fatal("transport pair mismatch")
	}
	swapped := pair
	swapped.ConfigID = "qwen-config-new"
	swapDone := make(chan struct{})
	go func() { spy.mu.Lock(); spy.current = swapped; spy.mu.Unlock(); close(swapDone) }()
	select {
	case <-swapDone:
		t.Fatal("config swap crossed held lease")
	case <-time.After(50 * time.Millisecond):
	}
	close(bt.release)
	res := <-done
	if res.err != nil || res.out.Ref == "" || containsBytes([]byte(res.out.Ref+res.out.Digest), []byte(quarantineSentinel)) {
		t.Fatalf("result=%+v %v", res.out, res.err)
	}
	select {
	case <-swapDone:
	case <-time.After(time.Second):
		t.Fatal("swap remained blocked")
	}
	receipts := spy.receiptSnapshot()
	if len(receipts) != 1 || receipts[0].Pair != pair || receipts[0].OutputDigest != res.out.Digest || receipts[0].DispatchID != d.DispatchID {
		t.Fatalf("receipt=%+v", receipts)
	}
}

func TestFinalizeStaleMakesDispatchUncertainWithoutResult(t *testing.T) {
	q, _, _, b, now := quarantineFixture(t)
	ref, _ := q.Put([]byte("private"), b, now, now.Add(time.Hour))
	d, s := sealedDispatch(t, ref, b, now)
	rt, _ := newTestSyntheticRuntime(q, &fakeTransport{}, fakeResolver{snap: s, finalizeFail: true}, testVerifier{}, mintTestTransportCapability())
	out, err := rt.Dispatch(context.Background(), d, b, now.Add(time.Minute))
	if !errors.Is(err, ErrQuarantineUncertain) || out != (LocalResultRef{}) {
		t.Fatalf("out=%+v err=%v", out, err)
	}
	if _, _, err = q.readForTest(ref, now.Add(2*time.Minute)); !errors.Is(err, ErrQuarantineUncertain) {
		t.Fatalf("payload not uncertain: %v", err)
	}
}

func sealQwenRuntime(r *QwenRuntimeAttestation) {
	r.ControllerSignature = qDigest
	r.Digest = ""
	u, _ := r.CanonicalUnsigned()
	r.Digest, _ = CanonicalDigest(json.RawMessage(u))
}
func sealQwenConfig(c *QwenConfigAttestation) {
	c.ControllerSignature = qDigest
	c.Digest = ""
	u, _ := c.CanonicalUnsigned()
	c.Digest, _ = CanonicalDigest(json.RawMessage(u))
}

func TestDispatchNonceAndIDAreGlobalOneUse(t *testing.T) {
	q, _, _, b, now := quarantineFixture(t)
	ref1, _ := q.Put([]byte("first"), b, now, now.Add(time.Hour))
	ref2, _ := q.Put([]byte("second"), b, now, now.Add(time.Hour))
	d1, s := sealedDispatch(t, ref1, b, now)
	rt, _ := newTestSyntheticRuntime(q, &fakeTransport{}, fakeResolver{snap: s}, testVerifier{}, mintTestTransportCapability())
	if _, err := rt.Dispatch(context.Background(), d1, b, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	d2, s2 := sealedDispatch(t, ref2, b, now)
	d2.PayloadRef = ref2
	u, _ := dispatchUnsigned(d2)
	d2.Digest, _ = admission.CanonicalDigest(json.RawMessage(u))
	rt2, _ := newTestSyntheticRuntime(q, &fakeTransport{}, fakeResolver{snap: s2}, testVerifier{}, mintTestTransportCapability())
	if _, err := rt2.Dispatch(context.Background(), d2, b, now.Add(2*time.Minute)); !errors.Is(err, ErrQuarantineReplay) {
		t.Fatalf("global replay=%v", err)
	}
}

func TestIssuedFutureAndInferenceCrashBecomeUncertain(t *testing.T) {
	q, cp, dir, b, now := quarantineFixture(t)
	ref, _ := q.Put([]byte("private"), b, now, now.Add(time.Hour))
	d, s := sealedDispatch(t, ref, b, now)
	tr := &fakeTransport{fail: true}
	rt, _ := newTestSyntheticRuntime(q, tr, fakeResolver{snap: s}, testVerifier{}, mintTestTransportCapability())
	if _, err := rt.Dispatch(context.Background(), d, b, now.Add(-time.Second)); !errors.Is(err, ErrRuntimeBinding) {
		t.Fatalf("future=%v", err)
	}
	if _, err := rt.Dispatch(context.Background(), d, b, now.Add(time.Minute)); !errors.Is(err, ErrQuarantineUncertain) {
		t.Fatalf("crash=%v", err)
	}
	_ = q.Close()
	q2, err := NewTestQuarantine(filepath.Join(dir, "quarantine"), []byte("01234567890123456789012345678901"), cp)
	if err != nil {
		t.Fatal(err)
	}
	defer q2.Close()
	rt2, _ := newTestSyntheticRuntime(q2, &fakeTransport{}, fakeResolver{snap: s}, testVerifier{}, mintTestTransportCapability())
	if _, err = rt2.Dispatch(context.Background(), d, b, now.Add(2*time.Minute)); !errors.Is(err, ErrQuarantineUncertain) {
		t.Fatalf("uncertain retry=%v", err)
	}
}

func TestInterruptedReconcileAndSizeBounds(t *testing.T) {
	q, _, _, b, now := quarantineFixture(t)
	if _, err := q.Put(make([]byte, maxQuarantinePayload+1), b, now, now.Add(time.Hour)); !errors.Is(err, ErrQuarantineCorrupt) {
		t.Fatalf("oversize=%v", err)
	}
	ref, _ := q.Put(make([]byte, maxQuarantinePayload), b, now, now.Add(time.Hour))
	lease, err := q.acquireAndConsume(ref, "dispatch-x", "nonce-x", qDigest, b, now, now.Add(time.Hour), now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	lease.close()
	if err = q.ReconcileInterrupted(); err != nil {
		t.Fatal(err)
	}
	if _, err = q.acquireAndConsume(ref, "dispatch-x", "nonce-x", qDigest, b, now, now.Add(time.Hour), now.Add(2*time.Minute)); !errors.Is(err, ErrQuarantineUncertain) {
		t.Fatalf("retry=%v", err)
	}
}

func TestPersistCapacityFailureDoesNotBrickReload(t *testing.T) {
	q, _, _, b, now := quarantineFixture(t)
	ref, err := q.Put([]byte("survivor"), b, now, now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	err = q.withLock(func() error {
		s, e := q.load()
		if e != nil {
			return e
		}
		s.Version++
		s.Records["quarantine://payload/ffffffffffffffffffffffffffffffff"] = quarantineRecord{Ciphertext: make([]byte, maxQuarantineTotal+1)}
		return q.persist(s.Version-1, s)
	})
	if !errors.Is(err, ErrQuarantineLimit) {
		t.Fatalf("capacity=%v", err)
	}
	if got, _, err := q.readForTest(ref, now.Add(time.Minute)); err != nil || string(got) != "survivor" {
		t.Fatalf("reload=%q %v", got, err)
	}
}

func TestProductionRuntimeAndTransportAreFailClosed(t *testing.T) {
	q, _, _, _, _ := quarantineFixture(t)
	if _, err := NewProductionRuntime(q, productionIsolationAttestation{}); !errors.Is(err, ErrQuarantineIsolationRequired) {
		t.Fatal(err)
	}
	if _, err := newTestSyntheticRuntime(q, &fakeTransport{}, fakeResolver{}, testVerifier{}, testTransportCapability{}); !errors.Is(err, ErrRuntimeDisabled) {
		t.Fatal(err)
	}
}

func containsBytes(h, n []byte) bool {
	for i := 0; i+len(n) <= len(h); i++ {
		if string(h[i:i+len(n)]) == string(n) {
			return true
		}
	}
	return false
}
