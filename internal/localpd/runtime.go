package localpd

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"openduck/internal/admission"
)

var (
	ErrRuntimeDisabled = errors.New("synthetic local-pd runtime disabled")
	ErrRuntimeBinding  = errors.New("local-pd runtime binding mismatch")
)

type localPDTransport interface {
	infer(context.Context, localInferenceRequest) ([]byte, error)
}
type localInferenceRequest struct {
	payload []byte
	pair    CurrentQwenPair
}
type testTransportCapability struct{ token *struct{} }

func mintTestTransportCapability() testTransportCapability {
	return testTransportCapability{new(struct{})}
}

type TrustedDispatchResolver interface {
	ResolveCandidate(context.Context, admission.LocalPDDispatch, time.Time) (DispatchAuthoritySnapshot, error)
	AcquireCurrentQwenPairLease(context.Context, CurrentQwenPair) (currentQwenPairLease, error)
}
type currentQwenPairLease interface {
	binding() CurrentQwenPair
	finalize(context.Context, QwenInferenceReceipt) error
	release()
}
type CurrentQwenPair struct {
	RuntimeID, ConfigID, RuntimeDigest, ConfigDigest                                 string
	ConfigVersion, PolicyVersion                                                     uint64
	RuntimeNetworkPolicy, RuntimeToolsPolicy, ConfigNetworkPolicy, ConfigToolsPolicy string
}
type QwenInferenceReceipt struct {
	DispatchID, OutputDigest string
	Pair                     CurrentQwenPair
}
type DispatchAuthoritySnapshot struct {
	DecisionDigest, ConversationScope, EventRevisionSetDigest string
	ClassHighWater                                            string
	ClassHighWaterVersion                                     uint64
	IngressGateDigest, PDSessionDigest, LocalPDViewDigest     string
	HighWaterVersion                                          uint64
	HighWaterDigest                                           string
	QwenRuntime                                               QwenRuntimeAttestation
	QwenConfig                                                QwenConfigAttestation
	ContextWindow                                             uint32
}
type LocalResultRef struct{ Ref, Digest string }
type SyntheticRuntime struct {
	quarantine *Quarantine
	transport  localPDTransport
	resolver   TrustedDispatchResolver
	verifier   admission.SignatureVerifier
}

func newTestSyntheticRuntime(q *Quarantine, t localPDTransport, resolver TrustedDispatchResolver, verifier admission.SignatureVerifier, cap testTransportCapability) (*SyntheticRuntime, error) {
	if q == nil || t == nil || resolver == nil || verifier == nil || cap.token == nil {
		return nil, ErrRuntimeDisabled
	}
	return &SyntheticRuntime{q, t, resolver, verifier}, nil
}
func NewProductionRuntime(_ *Quarantine, _ productionIsolationAttestation) (*SyntheticRuntime, error) {
	return nil, ErrQuarantineIsolationRequired
}
func dispatchUnsigned(d admission.LocalPDDispatch) ([]byte, error) {
	d.ControllerSignature = ""
	d.Digest = ""
	return json.Marshal(d)
}

func (r *SyntheticRuntime) verifyDispatch(ctx context.Context, d admission.LocalPDDispatch, expected PayloadBinding, now time.Time) (currentQwenPairLease, error) {
	if d.Validate() != nil || !utc(now) || now.Before(d.IssuedAt) || !now.Before(d.ExpiresAt) || d.PayloadRef == "" {
		return nil, ErrRuntimeBinding
	}
	u, err := dispatchUnsigned(d)
	if err != nil {
		return nil, ErrRuntimeBinding
	}
	dg, err := admission.CanonicalDigest(json.RawMessage(u))
	if err != nil || dg != d.Digest || !r.verifier.Verify(u, d.ControllerSignature) {
		return nil, ErrRuntimeBinding
	}
	s, err := r.resolver.ResolveCandidate(ctx, d, now)
	if err != nil {
		return nil, ErrRuntimeBinding
	}
	if _, err = verifyAuthorityOnly(now, s.QwenRuntime, r.verifier); err != nil {
		return nil, ErrRuntimeBinding
	}
	if _, err = verifyAuthorityOnly(now, s.QwenConfig, r.verifier); err != nil {
		return nil, ErrRuntimeBinding
	}
	if s.DecisionDigest != d.PrivacyDecisionDigest || s.ConversationScope != d.ConversationScope || s.EventRevisionSetDigest != d.EventRevisionSetDigest || s.ClassHighWater != string(d.ClassHighWater) || s.ClassHighWaterVersion != uint64(d.ClassHighWaterVersion) || s.LocalPDViewDigest != d.LocalPDViewBindingDigest || s.QwenRuntime.Model != d.QwenModel || s.QwenRuntime.Digest != d.QwenRuntimeAttestationDigest || s.QwenConfig.Digest != d.QwenConfigDigest || s.HighWaterVersion != expected.HighWaterVersion || s.HighWaterDigest != expected.HighWaterDigest || s.IngressGateDigest != expected.IngressGateDigest || s.PDSessionDigest != expected.PDSessionDigest || s.QwenRuntime.Digest != expected.QwenRuntimeDigest || s.QwenConfig.Digest != expected.QwenConfigDigest {
		return nil, ErrRuntimeBinding
	}
	if s.QwenRuntime.Model != "qwen3:8b" || s.QwenConfig.Model != "qwen3:8b" || s.QwenConfig.NumCtx != 40960 || s.ContextWindow != 40960 || s.QwenConfig.ContextTokens != 32768 || s.QwenConfig.Thinking != "medium" || s.QwenRuntime.NetworkPolicy != "none" || s.QwenRuntime.ToolsPolicy != "none" || s.QwenConfig.NetworkPolicy != "none" || s.QwenConfig.ToolsPolicy != "none" || d.QwenModel != "qwen3:8b" {
		return nil, ErrRuntimeBinding
	}
	pair := CurrentQwenPair{RuntimeID: s.QwenRuntime.RuntimeID, ConfigID: s.QwenConfig.ConfigID, RuntimeDigest: s.QwenRuntime.Digest, ConfigDigest: s.QwenConfig.Digest, ConfigVersion: s.QwenConfig.ConfigVersion, PolicyVersion: s.QwenConfig.ConfigVersion, RuntimeNetworkPolicy: s.QwenRuntime.NetworkPolicy, RuntimeToolsPolicy: s.QwenRuntime.ToolsPolicy, ConfigNetworkPolicy: s.QwenConfig.NetworkPolicy, ConfigToolsPolicy: s.QwenConfig.ToolsPolicy}
	lease, err := r.resolver.AcquireCurrentQwenPairLease(ctx, pair)
	if err != nil || lease == nil || lease.binding() != pair {
		return nil, ErrRuntimeBinding
	}
	return lease, nil
}

func (r *SyntheticRuntime) Dispatch(ctx context.Context, d admission.LocalPDDispatch, expected PayloadBinding, now time.Time) (LocalResultRef, error) {
	if err := ctx.Err(); err != nil {
		return LocalResultRef{}, err
	}
	pairLease, err := r.verifyDispatch(ctx, d, expected, now)
	if err != nil {
		return LocalResultRef{}, err
	}
	defer pairLease.release()
	heldPair := pairLease.binding()
	lease, err := r.quarantine.acquireAndConsume(d.PayloadRef, d.DispatchID, d.Nonce, d.PrivacyDecisionDigest, expected, d.IssuedAt, d.ExpiresAt, now)
	if err != nil {
		return LocalResultRef{}, err
	}
	defer lease.close()
	in := lease.bytes()
	out, err := r.transport.infer(ctx, localInferenceRequest{payload: in, pair: heldPair})
	for i := range in {
		in[i] = 0
	}
	if err != nil {
		_ = r.quarantine.finishAttempt(lease.ref, lease.attempt, false)
		return LocalResultRef{}, ErrQuarantineUncertain
	}
	h := sha256.Sum256(out)
	for i := range out {
		out[i] = 0
	}
	b := make([]byte, 16)
	if _, err = rand.Read(b); err != nil {
		_ = r.quarantine.finishAttempt(lease.ref, lease.attempt, false)
		return LocalResultRef{}, err
	}
	outputDigest := "sha256:" + hex.EncodeToString(h[:])
	if err = pairLease.finalize(ctx, QwenInferenceReceipt{DispatchID: d.DispatchID, OutputDigest: outputDigest, Pair: heldPair}); err != nil {
		_ = r.quarantine.finishAttempt(lease.ref, lease.attempt, false)
		return LocalResultRef{}, ErrQuarantineUncertain
	}
	if err = r.quarantine.finishAttempt(lease.ref, lease.attempt, true); err != nil {
		return LocalResultRef{}, ErrQuarantineUncertain
	}
	return LocalResultRef{"local-result://" + hex.EncodeToString(b), outputDigest}, nil
}
