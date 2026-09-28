// Package syntheticadmission provides the provider-free admission authority
// used by the explicitly opt-in Controller mode. It deliberately accepts no
// credentials, model clients, network clients, or external effect sinks.
package syntheticadmission

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"openduck/internal/admission"
	"openduck/internal/dshbridge"
	"openduck/internal/platformanchor"
)

const (
	keyFile        = "runtime.key"
	ledgerFile     = "admission.enc"
	checkpointFile = "admission.checkpoint"
)

var (
	ErrSyntheticReplay = errors.New("synthetic admission replay")
	ErrSyntheticAuth   = errors.New("synthetic admission authentication failed")
)

// Authority is a durable, synthetic-only implementation of the bridge
// authority. The cloud path is admitted, reconciled against a signed local
// receipt, and reserved exactly once before returning its opaque ID.
type Authority struct {
	mu     sync.Mutex
	ledger *admission.Ledger
	append *appendStore
	key    []byte
	seenPD map[string]string
	closed bool
	clock  func() time.Time
}

// New creates an encrypted ledger and a durable checkpoint under dir. The
// directory and runtime key are owner-only; a random key is generated once
// and reused only to make the synthetic ledger restart-safe.
func New(dir string) (*Authority, error) {
	if dir == "" {
		return nil, errors.New("synthetic state directory required")
	}
	if err := ensurePrivateDir(dir); err != nil {
		return nil, err
	}
	key, err := loadOrCreateKey(filepath.Join(dir, keyFile))
	if err != nil {
		return nil, err
	}
	defer zeroBytes(key)
	cp, err := newCheckpoint(filepath.Join(dir, checkpointFile), key)
	if err != nil {
		return nil, err
	}
	l, err := admission.NewLedger(filepath.Join(dir, ledgerFile), key, cp)
	if err != nil {
		return nil, err
	}
	store, err := newAppendStore(dir)
	if err != nil {
		_ = l.Close()
		return nil, err
	}
	a := &Authority{ledger: l, append: store, key: append([]byte(nil), key...), seenPD: make(map[string]string), clock: func() time.Time { return time.Now().UTC() }}
	l.SetReceiptVerifier(a.verifyReceipt)
	if err := a.recover(context.Background()); err != nil {
		store.Close()
		_ = l.Close()
		return nil, err
	}
	return a, nil
}

// NewProduction constructs the production authority only from the opaque
// checkpoint capability issued by platformanchor. The concrete argument is
// intentionally impossible for foreign or synthetic implementations to mint.
func NewProduction(dir string, cp *platformanchor.ProductionAdmissionCheckpoint) (*Authority, error) {
	if cp == nil || !cp.Valid() {
		return nil, errors.New("external synthetic checkpoint required")
	}
	return newWithCheckpoint(dir, cp)
}

// NewSyntheticWithCheckpoint is an explicit test-only composition seam. It
// accepts a generic checkpoint because synthetic callers do not claim the
// production admission authority.
func NewSyntheticWithCheckpoint(dir string, cp admission.CheckpointStore) (*Authority, error) {
	if cp == nil {
		return nil, errors.New("external synthetic checkpoint required")
	}
	return newWithCheckpoint(dir, cp)
}

func newWithCheckpoint(dir string, cp admission.CheckpointStore) (*Authority, error) {
	if dir == "" || ensurePrivateDir(dir) != nil {
		return nil, errors.New("synthetic state directory unavailable")
	}
	key, err := loadOrCreateKey(filepath.Join(dir, keyFile))
	if err != nil {
		return nil, err
	}
	defer zeroBytes(key)
	l, err := admission.NewLedger(filepath.Join(dir, ledgerFile), key, cp)
	if err != nil {
		return nil, err
	}
	store, err := newAppendStore(dir)
	if err != nil {
		_ = l.Close()
		return nil, err
	}
	a := &Authority{ledger: l, append: store, key: append([]byte(nil), key...), seenPD: make(map[string]string), clock: func() time.Time { return time.Now().UTC() }}
	l.SetReceiptVerifier(a.verifyReceipt)
	if err := a.recover(context.Background()); err != nil {
		store.Close()
		_ = l.Close()
		return nil, err
	}
	return a, nil
}

// NewWithLedger is test-oriented construction for a fresh durable state. It
// is intentionally still backed by the same encrypted ledger and checkpoint.
func NewWithLedger(dir string) (*Authority, error) { return New(dir) }

func (a *Authority) AdmitCloud(ctx context.Context, payload []byte) (dshbridge.CloudAdmission, error) {
	if err := ctx.Err(); err != nil {
		return dshbridge.CloudAdmission{}, err
	}
	if len(payload) == 0 {
		return dshbridge.CloudAdmission{}, errors.New("empty synthetic payload")
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return dshbridge.CloudAdmission{}, errors.New("synthetic authority closed")
	}

	now := a.clock().UTC()
	p, err := a.prompt(payload, now)
	if err != nil {
		return dshbridge.CloudAdmission{}, err
	}
	if _, err = a.ledger.Admit(ctx, p, a); err != nil {
		if errors.Is(err, admission.ErrAdmissionReplay) {
			return dshbridge.CloudAdmission{}, ErrSyntheticReplay
		}
		return dshbridge.CloudAdmission{}, err
	}
	receipt, err := a.append.Append(p)
	if err != nil {
		return dshbridge.CloudAdmission{}, err
	}
	if _, err = a.ledger.Reconcile(ctx, p.AdmissionID, receipt); err != nil {
		_, _ = a.ledger.MarkUncertain(context.Background(), p.AdmissionID, "synthetic receipt rejected")
		return dshbridge.CloudAdmission{}, err
	}
	err = a.reserve(ctx, p)
	if err != nil {
		return dshbridge.CloudAdmission{}, err
	}
	return dshbridge.CloudAdmission{ID: p.AdmissionID, Status: "consumed"}, nil
}

// DispatchLocalPD creates only an opaque local handle. It never calls the
// cloud ledger and treats repeated payloads as replay.
func (a *Authority) DispatchLocalPD(ctx context.Context, payload []byte) (dshbridge.LocalPDAdmission, error) {
	if err := ctx.Err(); err != nil {
		return dshbridge.LocalPDAdmission{}, err
	}
	if len(payload) == 0 {
		return dshbridge.LocalPDAdmission{}, errors.New("empty synthetic payload")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return dshbridge.LocalPDAdmission{}, errors.New("synthetic authority closed")
	}
	d := digest(payload)
	if _, ok := a.seenPD[d]; ok {
		return dshbridge.LocalPDAdmission{}, ErrSyntheticReplay
	}
	id, err := opaqueID("pd")
	if err != nil {
		return dshbridge.LocalPDAdmission{}, err
	}
	a.seenPD[d] = id
	return dshbridge.LocalPDAdmission{Handle: id, Status: "queued"}, nil
}

// Close zeroes the in-memory signing key. The durable ledger remains intact.
func (a *Authority) Close() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.closed = true
	for i := range a.key {
		a.key[i] = 0
	}
	a.key = nil
	a.append.Close()
	return a.ledger.Close()
}

func (a *Authority) Consume(id, nonce string) error {
	if id == "" || nonce == "" {
		return ErrSyntheticAuth
	}
	return nil
}

func (a *Authority) recover(ctx context.Context) error {
	records, err := a.ledger.Snapshot(ctx)
	if err != nil {
		return err
	}
	for id, r := range records {
		switch r.State {
		case admission.StateConsuming:
			receipt, ok, qerr := a.append.Query(r.Prompt.IdempotencyKey)
			if qerr != nil {
				return qerr
			}
			if !ok {
				if _, uerr := a.ledger.MarkUncertain(ctx, id, "append absent after restart"); uerr != nil {
					return uerr
				}
				continue
			}
			if err := a.append.Verify(receipt); err != nil {
				if _, uerr := a.ledger.MarkUncertain(ctx, id, "append receipt ambiguous"); uerr != nil {
					return uerr
				}
				continue
			}
			if _, err := a.ledger.Reconcile(ctx, id, receipt); err != nil {
				if _, uerr := a.ledger.MarkUncertain(ctx, id, "append receipt ambiguous"); uerr != nil {
					return uerr
				}
				continue
			}
			if err := a.reserve(ctx, r.Prompt); err != nil {
				if _, uerr := a.ledger.MarkUncertain(ctx, id, "egress recovery failed"); uerr != nil {
					return uerr
				}
			}
		case admission.StateConsumed:
			receipt, ok, qerr := a.append.Query(r.Prompt.IdempotencyKey)
			if qerr != nil || !ok || a.append.Verify(receipt) != nil {
				return errors.New("synthetic append audit failed")
			}
			if r.Reservation == nil {
				if err := a.reserve(ctx, r.Prompt); err != nil {
					if _, uerr := a.ledger.MarkRecoveryUncertain(ctx, id, "egress recovery failed"); uerr != nil {
						return uerr
					}
				}
			}
		}
	}
	return nil
}

func (a *Authority) reserve(ctx context.Context, p admission.CloudAdmittedPrompt) error {
	snap := admission.AuthoritativeConversationSnapshot{SchemaVersion: admission.AuthoritativeConversationSnapshotV1, ConversationScope: p.ConversationScope, EventRevisionSetDigest: p.EventRevisionSetDigest, CompleteThroughWatermark: p.CompleteThroughWatermark, IngressGateStateDigest: p.IngressGateStateDigest, AuthoritativeCoverageDigest: p.AuthoritativeCoverageDigest, ClassHighWater: p.ClassHighWater, ClassHighWaterVersion: p.ClassHighWaterVersion, Digest: p.EventRevisionSetDigest}
	_, err := a.ledger.ReserveEgress(ctx, p.AdmissionID, admission.FinalGate{Snapshot: snap, RuntimeDigest: p.TargetRuntimeAttestationDigest, DSHDistributionDigest: p.TargetDSHDistributionAttestationDigest, ProfileDigest: p.TargetCodexProfileAttestationDigest, ModelTransportDigest: p.ModelTransportPolicyDigest, ToolsetDigest: p.ToolsetDigest, ToolNetworkDigest: p.ToolNetworkPolicyDigest, PolicyDigest: p.PolicyDigest, TargetSessionID: p.TargetSessionID, TargetCodexThreadID: p.TargetCodexThreadID, ExpectedRunnerBinding: p.ExpectedRunnerBinding})
	return err
}

func (a *Authority) prompt(payload []byte, now time.Time) (admission.CloudAdmittedPrompt, error) {
	d := digest([]byte("synthetic:" + digest(payload)))
	capsule := admission.SafeCapsule{SchemaVersion: admission.SafeCapsuleV1, Purpose: "synthetic-summary", Fields: map[string]string{"summary": "synthetic admitted payload"}, AllowedFields: []string{"summary"}, Constraints: []string{"provider-free", "effects-disabled"}, Classification: admission.L1, PostScanDigest: d}
	capsule.Digest, _ = admission.CanonicalDigest(capsule)
	content, err := admission.CanonicalDigest(json.RawMessage(mustJSON(capsule, true)))
	if err != nil {
		return admission.CloudAdmittedPrompt{}, err
	}
	p := admission.CloudAdmittedPrompt{SchemaVersion: admission.CloudAdmittedPromptV1, AdmissionID: "adm_" + d[7:], Nonce: "nonce_" + d[7:], IssuedAt: now, ExpiresAt: now.Add(5 * time.Minute), MaxUses: 1, TargetSessionID: "synthetic-session", TargetCodexThreadID: "synthetic-thread", ConversationScope: "synthetic", EventRevisionSetDigest: d, CompleteThroughWatermark: "synthetic:1", IngressGateStateDigest: d, AuthoritativeCoverageDigest: d, ClassHighWater: admission.L1, ClassHighWaterVersion: 1, ContentDigest: content, PrivacyDecisionDigest: d, PolicyDigest: d, SourceRefs: []string{"synthetic:event"}, Classification: admission.L1, Route: "codex_cloud", TargetRuntimeAttestationDigest: d, TargetDSHDistributionAttestationDigest: d, TargetCodexProfileAttestationDigest: d, ModelClass: "codex", ModelTransportPolicyDigest: d, ToolsetDigest: d, ToolNetworkPolicyDigest: d, DSHAppendStore: "synthetic-dsh", DSHAppendSchema: "synthetic-session.prompt.v1", IdempotencyKey: "idem_" + d[7:], ExpectedRunnerBinding: "synthetic-runner", SafeCapsule: capsule, CanonicalizationVersion: admission.CanonicalizationV1}
	p.CanonicalizationDigest, _ = admission.CanonicalDigest(p.CanonicalizationVersion)
	unsigned := p
	unsigned.Digest = ""
	unsigned.ControllerSignature = ""
	b, _ := json.Marshal(unsigned)
	p.Digest, _ = admission.CanonicalDigest(json.RawMessage(b))
	p.ControllerSignature = a.sign(b)
	if err := p.Validate(); err != nil {
		return p, fmt.Errorf("synthetic prompt: %w (content=%q canon=%q digest=%q sig=%q event=%q)", err, p.ContentDigest, p.CanonicalizationDigest, p.Digest, p.ControllerSignature, p.EventRevisionSetDigest)
	}
	return p, nil
}

func (a *Authority) verifyReceipt(r admission.CloudAppendReceipt) error { return a.append.Verify(r) }
func (a *Authority) sign(b []byte) string {
	h := hmac.New(sha256.New, a.key)
	_, _ = h.Write(b)
	// Contract digests intentionally use one canonical representation; the
	// synthetic signature is an HMAC value carried in that digest-shaped slot.
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}
func (a *Authority) verify(b []byte, sig string) bool {
	raw, err := hex.DecodeString(strings.TrimPrefix(sig, "sha256:"))
	if err != nil {
		return false
	}
	h := hmac.New(sha256.New, a.key)
	_, _ = h.Write(b)
	return hmac.Equal(raw, h.Sum(nil))
}
func (a *Authority) Verify(b []byte, sig string) bool { return a.verify(b, sig) }

func ensurePrivateDir(dir string) error {
	info, err := os.Stat(dir)
	if os.IsNotExist(err) {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return err
		}
		info, err = os.Stat(dir)
	}
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
		return errors.New("synthetic state directory must be private")
	}
	return nil
}
func loadOrCreateKey(path string) ([]byte, error) {
	if b, err := os.ReadFile(path); err == nil {
		if len(b) != 32 {
			return nil, errors.New("invalid synthetic runtime key")
		}
		return b, nil
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return nil, err
	}
	if _, err = f.Write(b); err != nil {
		_ = f.Close()
		return nil, err
	}
	if err = f.Close(); err != nil {
		return nil, err
	}
	return b, nil
}

func zeroBytes(value []byte) {
	for i := range value {
		value[i] = 0
	}
}

type checkpoint struct {
	Version     uint64 `json:"version"`
	StateDigest string `json:"state_digest"`
	MAC         string `json:"mac"`
}
type durableCheckpoint struct {
	path string
	key  []byte
	mu   sync.Mutex
}

func newCheckpoint(path string, key []byte) (*durableCheckpoint, error) {
	c := &durableCheckpoint{path: path, key: append([]byte(nil), key...)}
	if _, err := os.Stat(path); err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	return c, nil
}
func (c *durableCheckpoint) LoadCheckpoint() (admission.LedgerCheckpoint, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	b, err := os.ReadFile(c.path)
	if os.IsNotExist(err) {
		return admission.LedgerCheckpoint{}, nil
	}
	if err != nil {
		return admission.LedgerCheckpoint{}, admission.ErrCheckpointUnavailable
	}
	var v checkpoint
	if json.Unmarshal(b, &v) != nil || v.MAC != c.mac(v.Version, v.StateDigest) {
		return admission.LedgerCheckpoint{}, admission.ErrCheckpointMismatch
	}
	return admission.LedgerCheckpoint{Version: v.Version, StateDigest: v.StateDigest}, nil
}
func (c *durableCheckpoint) CommitCheckpoint(expected uint64, next admission.LedgerCheckpoint) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	current, err := c.loadUnlocked()
	if err != nil {
		return err
	}
	if current.Version != expected || next.Version != expected+1 || next.StateDigest == "" {
		return admission.ErrCheckpointMismatch
	}
	v := checkpoint{Version: next.Version, StateDigest: next.StateDigest}
	v.MAC = c.mac(v.Version, v.StateDigest)
	data, _ := json.Marshal(v)
	tmp, err := os.CreateTemp(filepath.Dir(c.path), ".checkpoint-*")
	if err != nil {
		return admission.ErrCheckpointUnavailable
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err = tmp.Chmod(0600); err == nil {
		_, err = tmp.Write(data)
	}
	if closeErr := tmp.Close(); err == nil {
		err = closeErr
	}
	if err != nil || os.Rename(name, c.path) != nil {
		return admission.ErrCheckpointUnavailable
	}
	return nil
}
func (c *durableCheckpoint) loadUnlocked() (admission.LedgerCheckpoint, error) {
	b, err := os.ReadFile(c.path)
	if os.IsNotExist(err) {
		return admission.LedgerCheckpoint{}, nil
	}
	if err != nil {
		return admission.LedgerCheckpoint{}, admission.ErrCheckpointUnavailable
	}
	var v checkpoint
	if json.Unmarshal(b, &v) != nil || v.MAC != c.mac(v.Version, v.StateDigest) {
		return admission.LedgerCheckpoint{}, admission.ErrCheckpointMismatch
	}
	return admission.LedgerCheckpoint{Version: v.Version, StateDigest: v.StateDigest}, nil
}
func (c *durableCheckpoint) mac(v uint64, digest string) string {
	h := hmac.New(sha256.New, c.key)
	_, _ = fmt.Fprintf(h, "%d\x00%s", v, digest)
	return hex.EncodeToString(h.Sum(nil))
}
func digest(b []byte) string { h := sha256.Sum256(b); return "sha256:" + hex.EncodeToString(h[:]) }
func opaqueID(prefix string) (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return prefix + "_" + hex.EncodeToString(b), nil
}
func mustOpaque(prefix string) string {
	id, err := opaqueID(prefix)
	if err != nil {
		panic(fmt.Sprintf("synthetic random id: %v", err))
	}
	return id
}
func mustJSON(v any, clearDigest bool) []byte {
	if clearDigest {
		switch x := v.(type) {
		case admission.SafeCapsule:
			x.Digest = ""
			v = x
		}
	}
	b, _ := json.Marshal(v)
	return b
}
