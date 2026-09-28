package localpd

// This file contains the in-process, synthetic LocalPDView authority.  A
// view is a bounded read-model binding only: payload bytes are deliberately
// not accepted by, stored in, or returned from this package.

import (
	"encoding/json"
	"errors"
	"sync"
	"time"
)

var (
	ErrViewNotFound     = errors.New("local-pd view not found")
	ErrViewExpired      = errors.New("local-pd view expired")
	ErrViewInvalidated  = errors.New("local-pd view invalidated")
	ErrViewLineageStale = errors.New("local-pd view lineage is stale")
	ErrViewTTL          = errors.New("local-pd view ttl is outside bound")
	ErrViewSigner       = errors.New("local-pd view signing failed")
	ErrViewCapacity     = errors.New("local-pd view capacity exceeded")
)

const MaxLocalPDViewTTL = 5 * time.Minute
const MaxLocalPDViews = 128

type ViewAuthorityVerifier interface{ VerifyView([]byte, string) bool }

// LocalPDViewEnvelope is the Controller-signed authority object. The binding
// digest/signature and envelope digest/signature are distinct domains.
type LocalPDViewEnvelope struct {
	Binding        LocalPDViewBinding `json:"binding"`
	GateDigest     string             `json:"gate_digest"`
	SessionDigest  string             `json:"session_digest"`
	PolicyDigest   string             `json:"policy_digest"`
	HighWater      uint64             `json:"high_water"`
	SourceVersion  uint64             `json:"source_version"`
	CoverageDigest string             `json:"coverage_digest"`
	Class          string             `json:"class"`
	Digest         string             `json:"digest"`
	Signature      string             `json:"signature"`
}

func (e LocalPDViewEnvelope) CanonicalUnsigned() ([]byte, error) {
	e.Digest, e.Signature = "", ""
	e.Binding.Digest, e.Binding.ControllerSignature = "", ""
	return json.Marshal(e)
}

// LocalPDViewIssue is metadata required to create a view.  Gate/session and
// policy lineage are kept in the Controller manager, never projected to DSH.
type LocalPDViewIssue struct {
	ViewID              string
	BindingVersion      uint64
	HighWater           uint64
	SourceVersion       uint64
	SourceDigest        string
	RedactionDigest     string
	GateDigest          string
	SessionDigest       string
	PolicyDigest        string
	CoverageDigest      string
	Class               string
	AllowedFields       []string
	IssuedAt            time.Time
	TTL                 time.Duration
	Nonce               string
	ControllerSignature string
	Digest              string
	EnvelopeDigest      string
	EnvelopeSignature   string
}

type viewLineage struct {
	gate, session, policy    string
	highWater, sourceVersion uint64
}

type viewRecord struct {
	binding     LocalPDViewBinding
	lineage     viewLineage
	invalidated bool
}

// LocalPDViewManager is intentionally memory-only. Production persistence or
// transport must be supplied by the Controller, never by DSH/browser state.
type LocalPDViewManager struct {
	mu        sync.Mutex
	views     map[string]viewRecord
	authority ViewAuthorityVerifier
}

func (m *LocalPDViewManager) setAuthorityVerifier(v ViewAuthorityVerifier) {
	if m != nil {
		m.mu.Lock()
		m.authority = v
		m.mu.Unlock()
	}
}

func viewLineageBytes(b LocalPDViewBinding, l viewLineage) ([]byte, error) {
	return json.Marshal(struct {
		Binding       LocalPDViewBinding `json:"binding"`
		Gate          string             `json:"gate_digest"`
		Session       string             `json:"session_digest"`
		Policy        string             `json:"policy_digest"`
		HighWater     uint64             `json:"high_water"`
		SourceVersion uint64             `json:"source_version"`
	}{b, l.gate, l.session, l.policy, l.highWater, l.sourceVersion})
}

func NewLocalPDViewManager() *LocalPDViewManager {
	return &LocalPDViewManager{views: make(map[string]viewRecord)}
}

func newLocalPDViewManagerWithAuthority(v ViewAuthorityVerifier) *LocalPDViewManager {
	return &LocalPDViewManager{views: make(map[string]viewRecord), authority: v}
}

func (m *LocalPDViewManager) Issue(issue LocalPDViewIssue) (LocalPDViewBinding, error) {
	if m == nil || issue.ViewID == "" || issue.BindingVersion == 0 || issue.HighWater == 0 || issue.SourceVersion == 0 || issue.GateDigest == "" || issue.SessionDigest == "" || issue.PolicyDigest == "" {
		return LocalPDViewBinding{}, ErrInvalidContract
	}
	if issue.TTL <= 0 || issue.TTL > MaxLocalPDViewTTL {
		return LocalPDViewBinding{}, ErrViewTTL
	}
	if !issue.IssuedAt.UTC().Equal(issue.IssuedAt) || issue.Nonce == "" || issue.ControllerSignature == "" || issue.Digest == "" {
		return LocalPDViewBinding{}, ErrInvalidContract
	}
	b := LocalPDViewBinding{SchemaVersion: LocalPDViewBindingV1, ViewID: issue.ViewID, BindingVersion: issue.BindingVersion, HighWater: issue.HighWater, SourceVersion: issue.SourceVersion, SourceDigest: issue.SourceDigest, RedactionDigest: issue.RedactionDigest, AllowedFields: append([]string(nil), issue.AllowedFields...), IssuedAt: issue.IssuedAt, ExpiresAt: issue.IssuedAt.Add(issue.TTL), Nonce: issue.Nonce, ControllerSignature: issue.ControllerSignature, Digest: issue.Digest}
	if b.Validate() != nil {
		return LocalPDViewBinding{}, ErrInvalidContract
	}
	if m.authority == nil || issue.EnvelopeDigest == "" || issue.EnvelopeSignature == "" {
		return LocalPDViewBinding{}, ErrViewSigner
	}
	unsigned, err := b.CanonicalUnsigned()
	if err != nil {
		return LocalPDViewBinding{}, ErrInvalidContract
	}
	digest, err := CanonicalDigest(json.RawMessage(unsigned))
	if err != nil || digest != b.Digest {
		return LocalPDViewBinding{}, ErrViewSigner
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.purgeLocked(b.IssuedAt)
	if len(m.views) >= MaxLocalPDViews {
		return LocalPDViewBinding{}, ErrViewCapacity
	}
	if _, exists := m.views[b.ViewID]; exists {
		return LocalPDViewBinding{}, ErrInvalidContract
	}
	lineage := viewLineage{issue.GateDigest, issue.SessionDigest, issue.PolicyDigest, issue.HighWater, issue.SourceVersion}
	envelope := LocalPDViewEnvelope{Binding: b, GateDigest: issue.GateDigest, SessionDigest: issue.SessionDigest, PolicyDigest: issue.PolicyDigest, HighWater: issue.HighWater, SourceVersion: issue.SourceVersion, CoverageDigest: issue.CoverageDigest, Class: issue.Class, Digest: issue.EnvelopeDigest, Signature: issue.EnvelopeSignature}
	payload, _ := envelope.CanonicalUnsigned()
	expected, _ := CanonicalDigest(json.RawMessage(payload))
	if expected != envelope.Digest || !m.authority.VerifyView(payload, envelope.Signature) {
		return LocalPDViewBinding{}, ErrViewSigner
	}
	m.views[b.ViewID] = viewRecord{binding: b, lineage: lineage}
	return b, nil
}

func (m *LocalPDViewManager) Get(viewID string, now time.Time) (LocalPDViewBinding, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.purgeLocked(now)
	r, ok := m.views[viewID]
	if !ok {
		return LocalPDViewBinding{}, ErrViewNotFound
	}
	if r.invalidated {
		return LocalPDViewBinding{}, ErrViewInvalidated
	}
	if !now.Before(r.binding.ExpiresAt) {
		return LocalPDViewBinding{}, ErrViewExpired
	}
	return r.binding, nil
}

func (m *LocalPDViewManager) Invalidate(viewID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.views[viewID]
	if !ok {
		return ErrViewNotFound
	}
	r.invalidated = true
	m.views[viewID] = r
	return nil
}

func (m *LocalPDViewManager) purgeLocked(now time.Time) {
	for id, r := range m.views {
		if !now.Before(r.binding.ExpiresAt) {
			delete(m.views, id)
		}
	}
}

func (m *LocalPDViewManager) CheckLineage(viewID, gate, session, policy string, highWater, sourceVersion uint64, now time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.views[viewID]
	if !ok {
		return ErrViewNotFound
	}
	if r.invalidated {
		return ErrViewInvalidated
	}
	if !now.Before(r.binding.ExpiresAt) {
		return ErrViewExpired
	}
	if r.lineage.gate != gate || r.lineage.session != session || r.lineage.policy != policy || highWater != r.lineage.highWater || sourceVersion != r.lineage.sourceVersion {
		return ErrViewLineageStale
	}
	return nil
}
