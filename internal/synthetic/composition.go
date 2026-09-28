// Package synthetic contains the explicitly opt-in, provider-free composition
// used for local acceptance tests. It never reads accounts, calls models, or
// performs effects; all values are deterministic opaque projections.
package synthetic

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"openduck/internal/dshbridge"
)

type Classifier struct{}

func (Classifier) Classify(payload []byte) (dshbridge.PrivacyClass, error) {
	if len(payload) == 0 {
		return "", errors.New("empty synthetic payload")
	}
	text := string(payload)
	// Explicit marker is the canonical route; any near miss mentioning PD is
	// quarantined locally rather than ever being sent to the cloud route.
	if strings.HasPrefix(text, "Это ПД") || strings.HasPrefix(text, "PD:") || strings.Contains(strings.ToLower(text), "пд") || strings.Contains(strings.ToLower(text), "pd") {
		return dshbridge.ClassL2, nil
	}
	return dshbridge.ClassL1, nil
}

// Authority is an in-memory synthetic admission consumer. It is deliberately
// replay rejecting and exposes only opaque identifiers.
type Authority struct {
	mu                     sync.Mutex
	seen                   map[string]struct{}
	CloudCalls, LocalCalls int
}

func NewAuthority() *Authority { return &Authority{seen: make(map[string]struct{})} }

func (a *Authority) AdmitCloud(ctx context.Context, payload []byte) (dshbridge.CloudAdmission, error) {
	return a.admit(ctx, payload, true)
}
func (a *Authority) DispatchLocalPD(ctx context.Context, payload []byte) (dshbridge.LocalPDAdmission, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return dshbridge.LocalPDAdmission{}, err
	}
	if len(payload) == 0 {
		return dshbridge.LocalPDAdmission{}, errors.New("empty synthetic payload")
	}
	id := digest(payload)
	if _, ok := a.seen[id]; ok {
		return dshbridge.LocalPDAdmission{}, errors.New("synthetic replay")
	}
	a.seen[id] = struct{}{}
	a.LocalCalls++
	return dshbridge.LocalPDAdmission{Handle: "pd_" + id[:16], Status: "queued"}, nil
}
func (a *Authority) admit(ctx context.Context, payload []byte, cloud bool) (dshbridge.CloudAdmission, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return dshbridge.CloudAdmission{}, err
	}
	if len(payload) == 0 {
		return dshbridge.CloudAdmission{}, errors.New("empty synthetic payload")
	}
	id := digest(payload)
	if _, ok := a.seen[id]; ok {
		return dshbridge.CloudAdmission{}, errors.New("synthetic replay")
	}
	a.seen[id] = struct{}{}
	a.CloudCalls++
	return dshbridge.CloudAdmission{ID: "adm_" + id[:16], Status: "accepted"}, nil
}

type Models struct{ now time.Time }

func NewModels(now time.Time) Models { return Models{now: now.UTC()} }
func (m Models) projection(class dshbridge.PrivacyClass) dshbridge.SafeProjection {
	return dshbridge.SafeProjection{Classification: class, Provenance: "controller:synthetic", Proof: "sha256:" + digest([]byte("synthetic-projection")), Version: 1, ExpiresAt: m.now.Add(time.Hour)}
}
func (m Models) ReadInbox(context.Context) (dshbridge.InboxReadModel, error) {
	return dshbridge.InboxReadModel{SchemaVersion: dshbridge.ReadModelV1, Projection: m.projection(dshbridge.ClassL1), Items: []dshbridge.InboxItem{}, GeneratedAt: m.now}, nil
}
func (m Models) ReadCalendar(context.Context) (dshbridge.CalendarReadModel, error) {
	return dshbridge.CalendarReadModel{SchemaVersion: dshbridge.ReadModelV1, Projection: m.projection(dshbridge.ClassL1), Items: []dshbridge.CalendarItem{}, GeneratedAt: m.now}, nil
}
func (m Models) ReadWorkGraph(context.Context) (dshbridge.WorkGraphReadModel, error) {
	return dshbridge.WorkGraphReadModel{SchemaVersion: dshbridge.ReadModelV1, Projection: m.projection(dshbridge.ClassL1), GraphID: "synthetic", BaselineVersion: "0", Nodes: []dshbridge.WorkGraphNode{}, Edges: []dshbridge.WorkGraphEdge{}, GeneratedAt: m.now}, nil
}
func (m Models) ReadTasks(context.Context) (dshbridge.TasksReadModel, error) {
	return dshbridge.TasksReadModel{SchemaVersion: dshbridge.ReadModelV1, Projection: m.projection(dshbridge.ClassL1), Items: []dshbridge.TaskItem{}, GeneratedAt: m.now}, nil
}
func (m Models) ReadTime(context.Context) (dshbridge.TimeReadModel, error) {
	return dshbridge.TimeReadModel{SchemaVersion: dshbridge.ReadModelV1, Projection: m.projection(dshbridge.ClassL1), PlannedSeconds: 0, SpentSeconds: 0, GeneratedAt: m.now}, nil
}
func (m Models) ReadReviews(context.Context) (dshbridge.ReviewsReadModel, error) {
	return dshbridge.ReviewsReadModel{SchemaVersion: dshbridge.ReadModelV1, Projection: m.projection(dshbridge.ClassL1), Items: []dshbridge.ReviewItem{}, GeneratedAt: m.now}, nil
}
func (m Models) ReadMemoryMetadata(context.Context) (dshbridge.MemoryMetadataReadModel, error) {
	return dshbridge.MemoryMetadataReadModel{SchemaVersion: dshbridge.ReadModelV1, Projection: m.projection(dshbridge.ClassL1), Items: []dshbridge.MemoryMetadata{}, GeneratedAt: m.now}, nil
}
func (m Models) ReadHealth(context.Context) (dshbridge.HealthReadModel, error) {
	return dshbridge.HealthReadModel{SchemaVersion: dshbridge.ReadModelV1, Projection: m.projection(dshbridge.ClassL1), Status: "synthetic", ControllerAvailable: true, EffectsEnabled: false, GeneratedAt: m.now}, nil
}

type ProjectionVerifier struct{}

func (ProjectionVerifier) Verify(route string, payload []byte, p dshbridge.SafeProjection, now time.Time) error {
	if p.Provenance != "controller:synthetic" || p.Proof != projectionProof(route, payload, p) || !p.ExpiresAt.After(now) {
		return fmt.Errorf("synthetic projection rejected")
	}
	return nil
}

func ProjectionSigner(route string, payload []byte, p dshbridge.SafeProjection) string {
	return projectionProof(route, payload, p)
}

var projectionKey = func() []byte {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		panic(err)
	}
	return key
}()

func projectionProof(route string, payload []byte, p dshbridge.SafeProjection) string {
	base := fmt.Sprintf("%s\x00%s\x00%s\x00%d\x00%s\x00%s", route, string(payload), p.Classification, p.Version, p.Provenance, p.ExpiresAt.UTC().Format(time.RFC3339Nano))
	h := sha256.New()
	_, _ = h.Write(projectionKey)
	_, _ = h.Write([]byte(base))
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}

func digest(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
