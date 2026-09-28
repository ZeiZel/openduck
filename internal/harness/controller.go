package harness

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"
)

type TaskState string

const (
	Observed      TaskState = "OBSERVED"
	SignalReady   TaskState = "SIGNAL_READY"
	SpecDraft     TaskState = "SPEC_DRAFT"
	SpecFrozen    TaskState = "SPEC_FROZEN"
	Dispatched    TaskState = "DISPATCHED"
	WorkRunning   TaskState = "WORK_RUNNING"
	EvidenceReady TaskState = "EVIDENCE_READY"
	Reviewing     TaskState = "REVIEWING"
	Accepted      TaskState = "ACCEPTED"
	Blocked       TaskState = "BLOCKED"
	Cancelled     TaskState = "CANCELLED"
)

var (
	ErrNotFound           = errors.New("task not found")
	ErrVersionConflict    = errors.New("task version conflict")
	ErrTransition         = errors.New("invalid task transition")
	ErrDecisionDenied     = errors.New("owner decision denied")
	ErrBindingMismatch    = errors.New("interaction binding mismatch")
	ErrLeaseExpired       = errors.New("work lease expired")
	ErrControllerPoisoned = errors.New("controller poisoned after uncertain commit")
)

type Transition struct {
	From    TaskState `json:"from"`
	To      TaskState `json:"to"`
	Actor   string    `json:"actor"`
	Reason  string    `json:"reason"`
	At      time.Time `json:"at"`
	Version uint64    `json:"version"`
}
type ApprovalRecord struct {
	DecisionEventID string    `json:"decision_event_id"`
	Decision        string    `json:"decision"`
	InteractionID   string    `json:"interaction_id"`
	PreviewDigest   string    `json:"preview_digest"`
	RecordedAt      time.Time `json:"recorded_at"` // Not an authority to execute any effect.
}
type TaskRecord struct {
	ID               string                                `json:"id"`
	Version          uint64                                `json:"version"`
	State            TaskState                             `json:"state"`
	Signal           TaskSignal                            `json:"signal"`
	Spec             *TaskSpec                             `json:"spec,omitempty"`
	WorkOrder        *WorkOrder                            `json:"work_order,omitempty"`
	Evidence         *EvidenceBundle                       `json:"evidence,omitempty"`
	Review           *ReviewVerdict                        `json:"review,omitempty"`
	Binding          *WorkerDispatchBinding                `json:"worker_dispatch_binding,omitempty"`
	Action           *ActionProposal                       `json:"action,omitempty"`
	DeliveryBinding  *InteractionDeliveryBinding           `json:"delivery_binding,omitempty"`
	Envelope         *OwnerInteractionEnvelope             `json:"envelope,omitempty"`
	Receipt          *InteractionRenderReceipt             `json:"receipt,omitempty"`
	Decisions        map[string]ApprovalRecord             `json:"decisions,omitempty"`
	CallbackSessions map[string]InteractionCallbackSession `json:"callback_sessions,omitempty"`
	Transitions      []Transition                          `json:"transitions"`
}
type ControllerSnapshot struct {
	SchemaVersion string                `json:"schema_version"`
	Tasks         map[string]TaskRecord `json:"tasks"`
}

func (s ControllerSnapshot) Validate() error {
	if s.SchemaVersion != "controller-snapshot.v1" {
		return ErrUnknownVersion
	}
	if s.Tasks == nil {
		return ErrInvalidContract
	}
	for id, t := range s.Tasks {
		if e := t.validate(id); e != nil {
			return e
		}
	}
	return nil
}

func (t TaskRecord) validate(key string) error {
	if key == "" || key != t.ID || t.Version == 0 || !validTaskState(t.State) {
		return ErrInvalidContract
	}
	if e := t.Signal.Validate(); e != nil {
		return e
	}
	if e := validateTransitions(t); e != nil {
		return e
	}
	if t.Spec != nil {
		if e := t.Spec.Validate(); e != nil {
			return e
		}
		if t.Spec.TaskID != t.ID {
			return ErrBindingMismatch
		}
	}
	if t.WorkOrder != nil {
		if t.Spec == nil || t.Spec.Status != "frozen" {
			return ErrBindingMismatch
		}
		if e := t.WorkOrder.Validate(); e != nil {
			return e
		}
		if t.WorkOrder.TaskID != t.ID || t.WorkOrder.SpecHash != t.Spec.SpecHash {
			return ErrBindingMismatch
		}
		if t.Binding == nil {
			return ErrBindingMismatch
		}
	}
	if t.Binding != nil {
		if t.WorkOrder == nil {
			return ErrBindingMismatch
		}
		if e := t.Binding.Validate(); e != nil {
			return e
		}
		w, b := t.WorkOrder, t.Binding
		if b.WorkOrderID != w.WorkOrderID || b.TaskID != t.ID || b.SpecHash != w.SpecHash || b.ProfileManifestDigest != w.ProfileManifestDigest || b.WorkspaceDescriptorDigest != digestString(w.WorkspaceDescriptor) || b.WorktreeBaseRef != w.WorktreeBaseRef || b.SandboxPolicyDigest != w.SandboxPolicyDigest || b.LeaseID != w.Lease.ID {
			return ErrBindingMismatch
		}
	}
	if t.Evidence != nil {
		if t.WorkOrder == nil || t.Spec == nil {
			return ErrBindingMismatch
		}
		if e := t.Evidence.Validate(); e != nil {
			return e
		}
		if t.Evidence.TaskID != t.ID || t.Evidence.WorkOrderID != t.WorkOrder.WorkOrderID || t.Evidence.SpecHash != t.Spec.SpecHash {
			return ErrBindingMismatch
		}
	}
	if t.Review != nil {
		if t.Evidence == nil || t.Spec == nil {
			return ErrBindingMismatch
		}
		if e := t.Review.Validate(); e != nil {
			return e
		}
		if t.Review.TaskID != t.ID || t.Review.SpecHash != t.Spec.SpecHash || t.Review.EvidenceBundleDigest != t.Evidence.Digest {
			return ErrBindingMismatch
		}
	}
	if t.Action != nil {
		if t.Spec == nil || t.State != Accepted {
			return ErrBindingMismatch
		}
		if e := t.Action.Validate(); e != nil {
			return e
		}
		if t.Action.TaskID != t.ID || t.Action.SpecHash != t.Spec.SpecHash {
			return ErrBindingMismatch
		}
		if t.DeliveryBinding == nil || t.Envelope == nil {
			return ErrBindingMismatch
		}
		if e := t.DeliveryBinding.Validate(); e != nil {
			return e
		}
	}
	if t.DeliveryBinding != nil && t.Action == nil {
		return ErrBindingMismatch
	}
	if t.Envelope != nil {
		if t.Action == nil || t.State != Accepted {
			return ErrBindingMismatch
		}
		if e := t.Envelope.Validate(); e != nil {
			return e
		}
		a, env := t.Action, t.Envelope
		if t.DeliveryBinding == nil || env.DeliveryBindingID != t.DeliveryBinding.DeliveryBindingID {
			return ErrBindingMismatch
		}
		if env.TaskID != t.ID || env.ActionID != a.ActionID || env.PayloadHash != a.PayloadHash || env.DestinationHash != a.DestinationHash || env.ReconciliationPolicyDigest != a.ReconciliationPolicyDigest || env.PolicyVersion != a.PolicyVersion {
			return ErrBindingMismatch
		}
		_, previewDigest, e := RenderPreview(*a, env.RenderingVersion)
		if e != nil || previewDigest != env.PreviewDigest || env.PreviewBytesRef != "preview:"+previewDigest || env.DisplayPayloadRef != "preview:"+previewDigest {
			return ErrBindingMismatch
		}
	}
	if t.Receipt != nil {
		if t.Envelope == nil {
			return ErrBindingMismatch
		}
		if e := t.Receipt.Validate(); e != nil {
			return e
		}
		env, r := t.Envelope, t.Receipt
		if r.InteractionID != env.InteractionID || r.DeliveryBindingID != env.DeliveryBindingID || r.EnvelopeDigest != env.EnvelopeDigest || r.PreviewDigest != env.PreviewDigest || r.RenderingVersion != env.RenderingVersion || r.RenderedAt.After(env.ExpiresAt) {
			return ErrBindingMismatch
		}
	}
	if len(t.Decisions) > 0 {
		if t.Action == nil || t.Envelope == nil || t.Receipt == nil {
			return ErrBindingMismatch
		}
		for key, d := range t.Decisions {
			if key == "" || key != d.DecisionEventID || (d.Decision != "approve" && d.Decision != "reject") || d.InteractionID != t.Envelope.InteractionID || d.PreviewDigest != t.Envelope.PreviewDigest || d.RecordedAt.IsZero() || d.RecordedAt.After(t.Envelope.ExpiresAt) {
				return ErrBindingMismatch
			}
		}
	}
	for key, session := range t.CallbackSessions {
		if key == "" || key != session.SessionID || session.TaskID != t.ID || t.Envelope == nil || t.Action == nil || session.InteractionID != t.Envelope.InteractionID {
			return ErrBindingMismatch
		}
		if e := session.Validate(); e != nil {
			return e
		}
		if session.Challenge.DeliveryBindingID != t.Envelope.DeliveryBindingID || session.Challenge.EnvelopeDigest != t.Envelope.EnvelopeDigest || session.Challenge.PreviewDigest != t.Envelope.PreviewDigest || session.Challenge.ActionID != t.Action.ActionID || session.Challenge.PayloadHash != t.Action.PayloadHash || session.Challenge.DestinationHash != t.Action.DestinationHash || session.Challenge.ReconciliationPolicyDigest != t.Action.ReconciliationPolicyDigest || session.Challenge.RenderingVersion != t.Envelope.RenderingVersion || session.Challenge.Nonce != t.Envelope.Nonce || session.Challenge.PolicyVersion != t.Envelope.PolicyVersion || session.Challenge.ExpiresAt.After(t.Envelope.ExpiresAt) {
			return ErrBindingMismatch
		}
		if session.State == "RENDERED" || session.State == "DECIDED" {
			if t.Receipt == nil || session.Challenge.DisplayInstanceID == "" || session.Challenge.RenderReceiptDigest == "" || t.Receipt.DisplayInstanceID != session.Challenge.DisplayInstanceID || t.Receipt.ReceiptDigest != session.Challenge.RenderReceiptDigest {
				return ErrBindingMismatch
			}
		}
		if session.State == "DECIDED" {
			if session.DecisionEventID == "" {
				return ErrBindingMismatch
			}
			if _, ok := t.Decisions[session.DecisionEventID]; !ok {
				return ErrBindingMismatch
			}
		}
	}
	return validateStateContents(t)
}

func validTaskState(s TaskState) bool {
	switch s {
	case Observed, SignalReady, SpecDraft, SpecFrozen, Dispatched, WorkRunning, EvidenceReady, Reviewing, Accepted, Blocked, Cancelled:
		return true
	}
	return false
}
func validTransition(from, to TaskState) bool {
	switch from {
	case "":
		return to == Observed
	case Observed:
		return to == SignalReady
	case SignalReady:
		return to == SpecDraft || to == Cancelled
	case SpecDraft:
		return to == SpecFrozen || to == Cancelled
	case SpecFrozen:
		return to == Dispatched || to == Cancelled
	case Dispatched:
		return to == WorkRunning || to == Cancelled
	case WorkRunning:
		return to == EvidenceReady || to == Blocked || to == Cancelled
	case EvidenceReady:
		return to == Reviewing || to == Cancelled
	case Reviewing:
		return to == Accepted || to == Blocked || to == Cancelled
	case Accepted:
		return to == Accepted
	}
	return false
}
func validateTransitions(t TaskRecord) error {
	if len(t.Transitions) == 0 || uint64(len(t.Transitions)) != t.Version {
		return ErrInvalidContract
	}
	previous := TaskState("")
	for i, tr := range t.Transitions {
		if tr.Version != uint64(i+1) || tr.From != previous || !validTransition(tr.From, tr.To) || tr.Actor == "" || tr.Reason == "" || tr.At.IsZero() {
			return ErrInvalidContract
		}
		previous = tr.To
	}
	if previous != t.State {
		return ErrInvalidContract
	}
	return nil
}
func validateStateContents(t TaskRecord) error {
	noLater := t.WorkOrder == nil && t.Binding == nil && t.Evidence == nil && t.Review == nil && t.Action == nil && t.DeliveryBinding == nil && t.Envelope == nil && t.Receipt == nil && len(t.Decisions) == 0 && len(t.CallbackSessions) == 0
	switch t.State {
	case SignalReady:
		if t.Spec != nil || !noLater {
			return ErrBindingMismatch
		}
	case SpecDraft:
		if t.Spec == nil || t.Spec.Status != "draft" || !noLater {
			return ErrBindingMismatch
		}
	case SpecFrozen:
		if t.Spec == nil || t.Spec.Status != "frozen" || !noLater {
			return ErrBindingMismatch
		}
	case Dispatched, WorkRunning:
		if t.Spec == nil || t.Spec.Status != "frozen" || t.WorkOrder == nil || t.Binding == nil || t.Evidence != nil || t.Review != nil || t.Action != nil || t.DeliveryBinding != nil || t.Envelope != nil || t.Receipt != nil || len(t.Decisions) != 0 {
			return ErrBindingMismatch
		}
	case EvidenceReady, Reviewing:
		if t.Spec == nil || t.Spec.Status != "frozen" || t.WorkOrder == nil || t.Binding == nil || t.Evidence == nil || t.Review != nil || t.Action != nil || t.DeliveryBinding != nil || t.Envelope != nil || t.Receipt != nil || len(t.Decisions) != 0 {
			return ErrBindingMismatch
		}
	case Accepted:
		if t.Spec == nil || t.Spec.Status != "frozen" || t.WorkOrder == nil || t.Binding == nil || t.Evidence == nil || t.Review == nil || t.Review.Verdict != "pass" {
			return ErrBindingMismatch
		}
	case Blocked:
		if t.Spec == nil || t.Spec.Status != "frozen" || t.WorkOrder == nil || t.Binding == nil || t.Review != nil || t.Action != nil || t.DeliveryBinding != nil || t.Envelope != nil || t.Receipt != nil || len(t.Decisions) != 0 {
			return ErrBindingMismatch
		}
	case Cancelled:
		if t.Review != nil || t.Action != nil || t.DeliveryBinding != nil || t.Envelope != nil || t.Receipt != nil || len(t.Decisions) != 0 {
			return ErrBindingMismatch
		}
	default:
		return ErrInvalidContract
	}
	return nil
}
func cloneSnapshot(s ControllerSnapshot) ControllerSnapshot {
	b, _ := json.Marshal(s)
	var out ControllerSnapshot
	_ = json.Unmarshal(b, &out)
	if out.Tasks == nil {
		out.Tasks = map[string]TaskRecord{}
	}
	return out
}

// DecisionAuthenticator is the delivery adapter boundary. Transcript/model/tool paths do not
// implement it. The default denies all decisions until a real attested callback adapter exists.
type DecisionAuthenticator interface {
	AuthenticateOwnerDecision(context.Context, InteractionDeliveryBinding, OwnerDecisionEvent) error
}

// CallbackVerifier authenticates an opaque callback handle without persisting the raw handle.
type CallbackVerifier interface {
	VerifyCallback(context.Context, DecisionChallenge, string, string) (string, string, error)
}
type denyCallbackVerifier struct{}

func (denyCallbackVerifier) VerifyCallback(context.Context, DecisionChallenge, string, string) (string, string, error) {
	return "", "", ErrDecisionDenied
}

type denyAuthenticator struct{}

func (denyAuthenticator) AuthenticateOwnerDecision(context.Context, InteractionDeliveryBinding, OwnerDecisionEvent) error {
	return ErrDecisionDenied
}

type Controller struct {
	mu       sync.Mutex
	repo     Repository
	auth     DecisionAuthenticator
	callback CallbackVerifier
	snapshot ControllerSnapshot
	poisoned bool
}

func NewController(ctx context.Context, repo Repository) (*Controller, error) {
	return NewControllerWithAuthenticator(ctx, repo, nil)
}
func NewControllerWithAuthenticator(ctx context.Context, repo Repository, auth DecisionAuthenticator) (*Controller, error) {
	return NewControllerWithAuthenticators(ctx, repo, auth, nil)
}
func NewControllerWithAuthenticators(ctx context.Context, repo Repository, auth DecisionAuthenticator, callback CallbackVerifier) (*Controller, error) {
	if repo == nil {
		return nil, errors.New("repository required")
	}
	cas, ok := repo.(CompareAndSwapRepository)
	if !ok || cas == nil {
		return nil, errors.New("compare-and-swap repository required")
	}
	s, e := repo.Load(ctx)
	if e != nil {
		return nil, e
	}
	if s.SchemaVersion == "" {
		s = ControllerSnapshot{SchemaVersion: "controller-snapshot.v1", Tasks: map[string]TaskRecord{}}
	}
	if e = s.Validate(); e != nil {
		return nil, e
	}
	// Callback sessions are deliberately single-process capabilities. Restart invalidates
	// every unfinished session before it can be used again.
	previous := cloneSnapshot(s)
	dirty := false
	for id, task := range s.Tasks {
		for sid, session := range task.CallbackSessions {
			if session.State == "ISSUED" || session.State == "RENDERED" {
				session.State = "INVALIDATED"
				if e := session.Seal(); e != nil {
					return nil, e
				}
				task.CallbackSessions[sid] = session
				dirty = true
			}
		}
		s.Tasks[id] = task
	}
	if dirty {
		if e := cas.CompareAndSwap(ctx, previous, s); e != nil {
			return nil, e
		}
	}
	if auth == nil {
		auth = denyAuthenticator{}
	}
	if callback == nil {
		callback = denyCallbackVerifier{}
	}
	return &Controller{repo: repo, auth: auth, callback: callback, snapshot: s}, nil
}

func (c *Controller) Snapshot(ctx context.Context) (ControllerSnapshot, error) {
	if e := ctx.Err(); e != nil {
		return ControllerSnapshot{}, e
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.poisoned {
		return ControllerSnapshot{}, ErrControllerPoisoned
	}
	return cloneSnapshot(c.snapshot), nil
}
func (c *Controller) Task(ctx context.Context, id string) (TaskRecord, error) {
	s, e := c.Snapshot(ctx)
	if e != nil {
		return TaskRecord{}, e
	}
	t, ok := s.Tasks[id]
	if !ok {
		return TaskRecord{}, ErrNotFound
	}
	return t, nil
}
func (c *Controller) persist(ctx context.Context, previous, next ControllerSnapshot) error {
	if c.poisoned {
		return ErrControllerPoisoned
	}
	var e error
	cas, ok := c.repo.(CompareAndSwapRepository)
	if !ok || cas == nil {
		return errors.New("compare-and-swap repository required")
	}
	e = cas.CompareAndSwap(ctx, previous, next)
	if e != nil {
		if errors.Is(e, ErrCommitUncertain) {
			c.poisoned = true
			if r, re := c.repo.Load(context.Background()); re == nil {
				c.snapshot = r
			}
			return fmt.Errorf("%w: %v", ErrControllerPoisoned, e)
		}
		return e
	}
	c.snapshot = next
	return nil
}
func (c *Controller) Reload(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	s, e := c.repo.Load(ctx)
	if e != nil {
		return e
	}
	if e := s.Validate(); e != nil {
		return e
	}
	c.snapshot = s
	c.poisoned = false
	return nil
}
func (c *Controller) mutate(ctx context.Context, id string, expected uint64, actor, reason string, allowed []TaskState, to TaskState, fn func(*TaskRecord) error) (TaskRecord, error) {
	if e := ctx.Err(); e != nil {
		return TaskRecord{}, e
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.poisoned {
		return TaskRecord{}, ErrControllerPoisoned
	}
	old, ok := c.snapshot.Tasks[id]
	if !ok {
		return TaskRecord{}, ErrNotFound
	}
	if old.Version != expected {
		return TaskRecord{}, ErrVersionConflict
	}
	valid := false
	for _, s := range allowed {
		if old.State == s {
			valid = true
		}
	}
	if !valid {
		return TaskRecord{}, fmt.Errorf("%w: %s -> %s", ErrTransition, old.State, to)
	}
	next := cloneSnapshot(c.snapshot)
	t := next.Tasks[id]
	if e := fn(&t); e != nil {
		return TaskRecord{}, e
	}
	t.Version++
	t.State = to
	t.Transitions = append(t.Transitions, Transition{From: old.State, To: to, Actor: actor, Reason: reason, At: time.Now().UTC(), Version: t.Version})
	next.Tasks[id] = t
	if e := c.persist(ctx, c.snapshot, next); e != nil {
		return TaskRecord{}, e
	}
	return cloneRecord(t), nil
}
func cloneRecord(t TaskRecord) TaskRecord {
	s := cloneSnapshot(ControllerSnapshot{SchemaVersion: "controller-snapshot.v1", Tasks: map[string]TaskRecord{"x": t}})
	return s.Tasks["x"]
}

func (c *Controller) IngestSignal(ctx context.Context, taskID string, s TaskSignal) (TaskRecord, error) {
	if e := s.Validate(); e != nil {
		return TaskRecord{}, e
	}
	if taskID == "" {
		return TaskRecord{}, ErrInvalidContract
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.poisoned {
		return TaskRecord{}, ErrControllerPoisoned
	}
	if old, ok := c.snapshot.Tasks[taskID]; ok {
		if old.Signal.Digest == s.Digest {
			return cloneRecord(old), nil
		}
		return TaskRecord{}, ErrVersionConflict
	}
	n := cloneSnapshot(c.snapshot)
	t := TaskRecord{ID: taskID, Version: 2, State: SignalReady, Signal: s, Decisions: map[string]ApprovalRecord{}, Transitions: []Transition{{From: "", To: Observed, Actor: "controller", Reason: "signal_observed", At: time.Now().UTC(), Version: 1}, {From: Observed, To: SignalReady, Actor: "controller", Reason: "valid_signal", At: time.Now().UTC(), Version: 2}}}
	n.Tasks[taskID] = t
	if e := c.persist(ctx, c.snapshot, n); e != nil {
		return TaskRecord{}, e
	}
	return cloneRecord(t), nil
}
func (c *Controller) DraftSpec(ctx context.Context, id string, version uint64, s TaskSpec) (TaskRecord, error) {
	if e := s.Validate(); e != nil {
		return TaskRecord{}, e
	}
	return c.mutate(ctx, id, version, "root", "draft_spec", []TaskState{SignalReady}, SpecDraft, func(t *TaskRecord) error {
		if s.TaskID != t.ID || s.Status != "draft" {
			return ErrBindingMismatch
		}
		t.Spec = &s
		return nil
	})
}
func (c *Controller) FreezeSpec(ctx context.Context, id string, version uint64, s TaskSpec) (TaskRecord, error) {
	if e := s.Validate(); e != nil {
		return TaskRecord{}, e
	}
	return c.mutate(ctx, id, version, "controller", "freeze_spec", []TaskState{SpecDraft}, SpecFrozen, func(t *TaskRecord) error {
		if t.Spec == nil || s.TaskID != id || s.Status != "frozen" || s.SpecVersion != t.Spec.SpecVersion || s.SpecHash == t.Spec.SpecHash {
			return ErrBindingMismatch
		}
		if s.ParentSpecHash != "" && s.ParentSpecHash != t.Spec.SpecHash {
			return ErrBindingMismatch
		}
		t.Spec = &s
		return nil
	})
}
func (c *Controller) Dispatch(ctx context.Context, id string, version uint64, w WorkOrder, a WorkerRuntimeAttestation, b WorkerDispatchBinding) (TaskRecord, error) {
	if e := w.Validate(); e != nil {
		return TaskRecord{}, e
	}
	if e := a.Validate(); e != nil {
		return TaskRecord{}, e
	}
	if e := b.Validate(); e != nil {
		return TaskRecord{}, e
	}
	return c.mutate(ctx, id, version, "controller", "dispatch", []TaskState{SpecFrozen}, Dispatched, func(t *TaskRecord) error {
		if !w.Lease.ExpiresAt.After(time.Now().UTC()) {
			return ErrLeaseExpired
		}
		if t.Spec == nil || w.TaskID != id || w.SpecHash != t.Spec.SpecHash || a.WorkOrderID != w.WorkOrderID || a.GeneratedProfileDigest != w.ProfileManifestDigest || a.SandboxPolicyDigest != w.SandboxPolicyDigest || a.WorkspaceDescriptorDigest != digestString(w.WorkspaceDescriptor) || a.WorktreeBaseRef != w.WorktreeBaseRef || b.WorkOrderID != w.WorkOrderID || b.TaskID != id || b.SpecHash != w.SpecHash || b.WorkerInstanceID != a.WorkerInstanceID || b.WorkerRuntimeAttestationDigest != a.AttestationDigest || b.ProfileManifestDigest != a.GeneratedProfileDigest || b.SandboxPolicyDigest != a.SandboxPolicyDigest || b.WorkspaceDescriptorDigest != a.WorkspaceDescriptorDigest || b.WorktreeBaseRef != a.WorktreeBaseRef || b.LeaseID != w.Lease.ID {
			return ErrBindingMismatch
		}
		t.WorkOrder = &w
		t.Binding = &b
		return nil
	})
}
func digestString(v string) string { d, _ := SHA256(v); return d }
func (c *Controller) StartWork(ctx context.Context, id string, version uint64) (TaskRecord, error) {
	return c.mutate(ctx, id, version, "worker", "work_started", []TaskState{Dispatched}, WorkRunning, func(t *TaskRecord) error {
		if t.WorkOrder == nil || !t.WorkOrder.Lease.ExpiresAt.After(time.Now().UTC()) {
			return ErrLeaseExpired
		}
		return nil
	})
}
func (c *Controller) submitTrustedEvidence(ctx context.Context, id string, version uint64, evidence EvidenceBundle) (TaskRecord, error) {
	if e := evidence.Validate(); e != nil {
		return TaskRecord{}, e
	}
	return c.mutate(ctx, id, version, "worker", "evidence_submitted", []TaskState{WorkRunning}, EvidenceReady, func(t *TaskRecord) error {
		if t.Spec == nil || t.WorkOrder == nil || evidence.TaskID != id || evidence.SpecHash != t.Spec.SpecHash || evidence.WorkOrderID != t.WorkOrder.WorkOrderID {
			return ErrBindingMismatch
		}
		if !t.WorkOrder.Lease.ExpiresAt.After(time.Now().UTC()) {
			return ErrLeaseExpired
		}
		t.Evidence = &evidence
		return nil
	})
}

// SubmitWorkerResult is the authority path for model output. The worker only
// supplies WorkerResult; task/spec identity, lease and evidence digest are
// taken from the Controller's stored WorkOrder.
func (c *Controller) SubmitWorkerResult(ctx context.Context, id string, version uint64, result WorkerResult, observedAt time.Time) (TaskRecord, error) {
	if e := result.Validate(); e != nil {
		return TaskRecord{}, e
	}
	return c.mutate(ctx, id, version, "worker", "evidence_submitted", []TaskState{WorkRunning}, EvidenceReady, func(t *TaskRecord) error {
		if t.WorkOrder == nil || !t.WorkOrder.Lease.ExpiresAt.After(observedAt.UTC()) {
			return ErrLeaseExpired
		}
		evidence, err := BuildEvidenceBundleForWorkOrder(*t.WorkOrder, result, observedAt)
		if err != nil {
			return err
		}
		t.Evidence = &evidence
		return nil
	})
}
func (c *Controller) BeginReview(ctx context.Context, id string, version uint64) (TaskRecord, error) {
	return c.mutate(ctx, id, version, "controller", "review_started", []TaskState{EvidenceReady}, Reviewing, func(*TaskRecord) error { return nil })
}
func (c *Controller) SubmitReview(ctx context.Context, id string, version uint64, review ReviewVerdict) (TaskRecord, error) {
	if e := review.Validate(); e != nil {
		return TaskRecord{}, e
	}
	return c.mutate(ctx, id, version, "reviewer", "review_submitted", []TaskState{Reviewing}, Accepted, func(t *TaskRecord) error {
		if t.Spec == nil || t.Evidence == nil || review.TaskID != id || review.SpecHash != t.Spec.SpecHash || review.EvidenceBundleDigest != t.Evidence.Digest {
			return ErrBindingMismatch
		}
		if review.Verdict != "pass" {
			return ErrTransition
		}
		t.Review = &review
		return nil
	})
}
func (c *Controller) Block(ctx context.Context, id string, version uint64, reason string) (TaskRecord, error) {
	return c.mutate(ctx, id, version, "controller", reason, []TaskState{WorkRunning, Reviewing}, Blocked, func(*TaskRecord) error { return nil })
}
func (c *Controller) Cancel(ctx context.Context, id string, version uint64, reason string) (TaskRecord, error) {
	return c.mutate(ctx, id, version, "owner", reason, []TaskState{SignalReady, SpecDraft, SpecFrozen, Dispatched, WorkRunning, EvidenceReady, Reviewing}, Cancelled, func(*TaskRecord) error { return nil })
}

type Preview struct {
	RenderingVersion           string          `json:"rendering_version"`
	ActionID                   string          `json:"action_id"`
	ActionType                 string          `json:"action_type"`
	Payload                    json.RawMessage `json:"canonical_payload"`
	Destination                json.RawMessage `json:"destination_descriptor"`
	ReconciliationPolicyDigest string          `json:"reconciliation_policy_digest"`
	Effects                    []string        `json:"effects"`
	RiskClass                  string          `json:"risk_class"`
	ExpiresAt                  time.Time       `json:"expires_at"`
}

func RenderPreview(a ActionProposal, renderingVersion string) ([]byte, string, error) {
	if e := a.Validate(); e != nil {
		return nil, "", e
	}
	if renderingVersion == "" {
		return nil, "", ErrInvalidContract
	}
	payload, e := canonicalRaw(a.CanonicalPayload)
	if e != nil {
		return nil, "", e
	}
	destination, e := canonicalRaw(a.DestinationDescriptor)
	if e != nil {
		return nil, "", e
	}
	p := Preview{RenderingVersion: renderingVersion, ActionID: a.ActionID, ActionType: a.ActionType, Payload: payload, Destination: destination, ReconciliationPolicyDigest: a.ReconciliationPolicyDigest, Effects: a.Effects, RiskClass: a.RiskClass, ExpiresAt: a.ExpiresAt.UTC()}
	b, e := CanonicalJSON(p)
	if e != nil {
		return nil, "", e
	}
	d, e := SHA256(json.RawMessage(b))
	return b, d, e
}
func randomID(prefix string) (string, error) {
	b := make([]byte, 16)
	if _, e := rand.Read(b); e != nil {
		return "", e
	}
	return prefix + hex.EncodeToString(b), nil
}
func (c *Controller) CreateActionPreview(ctx context.Context, id string, version uint64, binding InteractionDeliveryBinding, a ActionProposal, controllerAttestation string) (TaskRecord, []byte, error) {
	if e := binding.Validate(); e != nil {
		return TaskRecord{}, nil, e
	}
	if e := a.Validate(); e != nil {
		return TaskRecord{}, nil, e
	}
	if controllerAttestation == "" {
		return TaskRecord{}, nil, ErrInvalidContract
	}
	p, previewDigest, e := RenderPreview(a, binding.RenderingVersion)
	if e != nil {
		return TaskRecord{}, nil, e
	}
	iid, e := randomID("int_")
	if e != nil {
		return TaskRecord{}, nil, e
	}
	nonce, e := randomID("nonce_")
	if e != nil {
		return TaskRecord{}, nil, e
	}
	challenge, e := SHA256(nonce + "\x00" + a.ActionID)
	if e != nil {
		return TaskRecord{}, nil, e
	}
	env := OwnerInteractionEnvelope{InteractionID: iid, TaskID: id, Kind: "action_preview", DeliveryBindingID: binding.DeliveryBindingID, DisplayPayloadRef: "preview:" + previewDigest, SourceRefs: a.SourceRefs, Coverage: Coverage{Complete: true}, RiskClass: a.RiskClass, ActionID: a.ActionID, PayloadHash: a.PayloadHash, DestinationHash: a.DestinationHash, ReconciliationPolicyDigest: a.ReconciliationPolicyDigest, PreviewBytesRef: "preview:" + previewDigest, PreviewDigest: previewDigest, RenderingVersion: binding.RenderingVersion, Nonce: nonce, ChallengeDigest: challenge, ExpiresAt: a.ExpiresAt, PolicyVersion: a.PolicyVersion, ControllerAttestation: controllerAttestation}
	if e = env.Seal(); e != nil {
		return TaskRecord{}, nil, e
	}
	t, e := c.mutate(ctx, id, version, "controller", "action_preview", []TaskState{Accepted}, Accepted, func(t *TaskRecord) error {
		if t.Spec == nil || a.TaskID != id || a.SpecHash != t.Spec.SpecHash {
			return ErrBindingMismatch
		}
		t.Action = &a
		t.DeliveryBinding = &binding
		t.Envelope = &env
		t.Receipt = nil
		return nil
	})
	return t, p, e
}

// IssueCallbackSession creates a one-use opaque callback capability. Only its digest is
// persisted; the returned handle must be held by the delivery adapter and is never logged.
func (c *Controller) IssueCallbackSession(ctx context.Context, id string, version uint64, ttl time.Duration) (TaskRecord, DecisionChallenge, string, error) {
	if ttl <= 0 {
		return TaskRecord{}, DecisionChallenge{}, "", ErrInvalidContract
	}
	handle, e := randomID("cb_")
	if e != nil {
		return TaskRecord{}, DecisionChallenge{}, "", e
	}
	sid, e := randomID("session_")
	if e != nil {
		return TaskRecord{}, DecisionChallenge{}, "", e
	}
	now := time.Now().UTC()
	var out DecisionChallenge
	t, e := c.mutate(ctx, id, version, "controller", "callback_session_issued", []TaskState{Accepted}, Accepted, func(t *TaskRecord) error {
		if t.Action == nil || t.Envelope == nil || t.DeliveryBinding == nil || t.Receipt != nil {
			return ErrBindingMismatch
		}
		for _, existing := range t.CallbackSessions {
			if existing.State == "ISSUED" || existing.State == "RENDERED" {
				return ErrVersionConflict
			}
		}
		if now.After(t.Envelope.ExpiresAt) {
			return ErrDecisionDenied
		}
		expires := now.Add(ttl)
		if t.Envelope.ExpiresAt.Before(expires) {
			expires = t.Envelope.ExpiresAt
		}
		out = DecisionChallenge{InteractionID: t.Envelope.InteractionID, DeliveryBindingID: t.Envelope.DeliveryBindingID, EnvelopeDigest: t.Envelope.EnvelopeDigest, PreviewDigest: t.Envelope.PreviewDigest, ActionID: t.Action.ActionID, PayloadHash: t.Action.PayloadHash, DestinationHash: t.Action.DestinationHash, ReconciliationPolicyDigest: t.Action.ReconciliationPolicyDigest, RenderingVersion: t.Envelope.RenderingVersion, Nonce: t.Envelope.Nonce, ExpiresAt: expires, PolicyVersion: t.Envelope.PolicyVersion, SessionID: sid, HandleDigest: digestString(handle)}
		if e := out.Seal(); e != nil {
			return e
		}
		session := InteractionCallbackSession{SessionID: sid, TaskID: id, InteractionID: out.InteractionID, State: "ISSUED", Challenge: out, ChallengeDigest: out.ChallengeDigest, IssuedAt: now}
		if e := session.Seal(); e != nil {
			return e
		}
		if t.CallbackSessions == nil {
			t.CallbackSessions = map[string]InteractionCallbackSession{}
		}
		t.CallbackSessions[sid] = session
		return nil
	})
	return t, out, handle, e
}

// NativeCallbackSession is an in-process capability for the native delivery adapter.
// The callback handle is intentionally unexported: it cannot be serialized to the plugin
// or UI, and callers can only use it through the native adapter methods below.
type NativeCallbackSession struct {
	SessionID string
	Challenge DecisionChallenge
	handle    string
}

// IssueNativeCallbackSession issues a capability for a native helper. The helper receives
// only the public challenge; the opaque handle remains inside the Controller boundary.
func (c *Controller) IssueNativeCallbackSession(ctx context.Context, id string, version uint64, ttl time.Duration) (TaskRecord, NativeCallbackSession, error) {
	t, challenge, handle, err := c.IssueCallbackSession(ctx, id, version, ttl)
	if err != nil {
		return TaskRecord{}, NativeCallbackSession{}, err
	}
	return t, NativeCallbackSession{SessionID: challenge.SessionID, Challenge: challenge, handle: handle}, nil
}

// AcknowledgeNativeRendered accepts only an observed preview digest and display nonce from
// the native host. The Controller derives the display id, receipt and final challenge; no
// client-supplied receipt or hash is trusted.
func (c *Controller) AcknowledgeNativeRendered(ctx context.Context, id string, version uint64, session NativeCallbackSession, displayNonce, observedPreviewDigest string) (TaskRecord, InteractionRenderReceipt, DecisionChallenge, error) {
	if session.SessionID == "" || session.handle == "" || displayNonce == "" || observedPreviewDigest == "" || !isDigest(observedPreviewDigest) || !isDigest(digestString(session.handle)) {
		return TaskRecord{}, InteractionRenderReceipt{}, DecisionChallenge{}, ErrDecisionDenied
	}
	displayID, err := randomID("display_")
	if err != nil {
		return TaskRecord{}, InteractionRenderReceipt{}, DecisionChallenge{}, err
	}
	var receipt InteractionRenderReceipt
	var challenge DecisionChallenge
	t, err := c.mutate(ctx, id, version, "native_delivery_adapter", "native_render_acknowledged", []TaskState{Accepted}, Accepted, func(t *TaskRecord) error {
		s, ok := t.CallbackSessions[session.SessionID]
		now := time.Now().UTC()
		if !ok || s.State != "ISSUED" || t.Envelope == nil || t.Action == nil || subtle.ConstantTimeCompare([]byte(digestString(session.handle)), []byte(s.Challenge.HandleDigest)) != 1 || observedPreviewDigest != t.Envelope.PreviewDigest || now.After(s.Challenge.ExpiresAt) {
			return ErrDecisionDenied
		}
		receipt = InteractionRenderReceipt{InteractionID: t.Envelope.InteractionID, DeliveryBindingID: t.Envelope.DeliveryBindingID, DisplayInstanceID: displayID, DisplayNonce: displayNonce, EnvelopeDigest: t.Envelope.EnvelopeDigest, PreviewDigest: observedPreviewDigest, RenderingVersion: t.Envelope.RenderingVersion, RenderedAt: now}
		if err := receipt.Seal(); err != nil {
			return err
		}
		challenge = s.Challenge
		challenge.DisplayInstanceID, challenge.DisplayNonce, challenge.RenderReceiptDigest = displayID, displayNonce, receipt.ReceiptDigest
		if err := challenge.Seal(); err != nil {
			return err
		}
		s.State, s.RenderedAt, s.Challenge, s.ChallengeDigest = "RENDERED", now, challenge, challenge.ChallengeDigest
		if err := s.Seal(); err != nil {
			return err
		}
		t.Receipt = &receipt
		t.CallbackSessions[session.SessionID] = s
		return nil
	})
	return t, receipt, challenge, err
}

// RecordNativeAuthenticatedDecision consumes the internal capability and an already
// authenticated helper result. It is the only native path that creates an authoritative
// OwnerDecisionEvent; the helper never supplies event hashes or destination data.
func (c *Controller) RecordNativeAuthenticatedDecision(ctx context.Context, id string, version uint64, session NativeCallbackSession, decision, approverID, proofRef string) (TaskRecord, OwnerDecisionEvent, error) {
	if session.SessionID == "" || session.handle == "" || (decision != "approve" && decision != "reject") || approverID == "" || proofRef == "" {
		return TaskRecord{}, OwnerDecisionEvent{}, ErrDecisionDenied
	}
	var event OwnerDecisionEvent
	t, err := c.mutate(ctx, id, version, "native_owner_callback", "native_owner_decision_recorded", []TaskState{Accepted}, Accepted, func(t *TaskRecord) error {
		s, ok := t.CallbackSessions[session.SessionID]
		now := time.Now().UTC()
		if !ok || s.State != "RENDERED" || t.Envelope == nil || t.Receipt == nil || t.Action == nil || s.Challenge.DisplayInstanceID == "" || s.Challenge.DisplayNonce == "" || t.Receipt.DisplayInstanceID != s.Challenge.DisplayInstanceID || t.Receipt.DisplayNonce != s.Challenge.DisplayNonce || t.Receipt.ReceiptDigest != s.Challenge.RenderReceiptDigest || now.After(s.Challenge.ExpiresAt) || subtle.ConstantTimeCompare([]byte(digestString(session.handle)), []byte(s.Challenge.HandleDigest)) != 1 {
			return ErrDecisionDenied
		}
		verifiedID, verifiedProof, verifyErr := c.callback.VerifyCallback(ctx, s.Challenge, session.handle, decision)
		if verifyErr != nil || verifiedID == "" || verifiedProof == "" || (approverID != "" && approverID != verifiedID) || (proofRef != "" && proofRef != verifiedProof) {
			return ErrDecisionDenied
		}
		// Helper authentication may block; expiry is authoritative at commit time too.
		if now = time.Now().UTC(); now.After(s.Challenge.ExpiresAt) {
			return ErrDecisionDenied
		}
		eid, err := randomID("decision_")
		if err != nil {
			return err
		}
		event = OwnerDecisionEvent{DecisionEventID: eid, Decision: decision, InteractionID: t.Envelope.InteractionID, DeliveryBindingID: t.Envelope.DeliveryBindingID, DisplayInstanceID: s.Challenge.DisplayInstanceID, RenderReceiptDigest: t.Receipt.ReceiptDigest, EnvelopeDigest: t.Envelope.EnvelopeDigest, PreviewDigest: t.Envelope.PreviewDigest, RenderingVersion: t.Envelope.RenderingVersion, ActionID: t.Action.ActionID, PayloadHash: t.Action.PayloadHash, DestinationHash: t.Action.DestinationHash, ReconciliationPolicyDigest: t.Action.ReconciliationPolicyDigest, Nonce: t.Envelope.Nonce, ChallengeDigest: s.Challenge.ChallengeDigest, ExpiresAt: s.Challenge.ExpiresAt, PolicyVersion: t.Envelope.PolicyVersion, ApproverID: verifiedID, RecentAuthProofRef: verifiedProof, ReceivedAt: now}
		if err := event.Seal(); err != nil {
			return err
		}
		if t.Decisions == nil {
			t.Decisions = map[string]ApprovalRecord{}
		}
		t.Decisions[event.DecisionEventID] = ApprovalRecord{DecisionEventID: event.DecisionEventID, Decision: event.Decision, InteractionID: event.InteractionID, PreviewDigest: event.PreviewDigest, RecordedAt: now}
		s.State, s.DecidedAt, s.DecisionEventID = "DECIDED", now, event.DecisionEventID
		if err := s.Seal(); err != nil {
			return err
		}
		t.CallbackSessions[session.SessionID] = s
		return nil
	})
	return t, event, err
}

// RenderCallbackSession builds and persists the render receipt. It is a CAS from ISSUED to
// RENDERED and refreshes the challenge with the exact display/receipt tuple.
func (c *Controller) RenderCallbackSession(ctx context.Context, id string, version uint64, sessionID string) (TaskRecord, InteractionRenderReceipt, DecisionChallenge, error) {
	if sessionID == "" {
		return TaskRecord{}, InteractionRenderReceipt{}, DecisionChallenge{}, ErrInvalidContract
	}
	displayID, e := randomID("display_")
	if e != nil {
		return TaskRecord{}, InteractionRenderReceipt{}, DecisionChallenge{}, e
	}
	var receipt InteractionRenderReceipt
	var challenge DecisionChallenge
	t, e := c.mutate(ctx, id, version, "delivery_adapter", "callback_session_rendered", []TaskState{Accepted}, Accepted, func(t *TaskRecord) error {
		s, ok := t.CallbackSessions[sessionID]
		if !ok || s.State != "ISSUED" || t.Envelope == nil || t.Action == nil {
			return ErrDecisionDenied
		}
		now := time.Now().UTC()
		if now.After(s.Challenge.ExpiresAt) {
			return ErrDecisionDenied
		}
		receipt = InteractionRenderReceipt{InteractionID: t.Envelope.InteractionID, DeliveryBindingID: t.Envelope.DeliveryBindingID, DisplayInstanceID: displayID, DisplayNonce: s.Challenge.Nonce, EnvelopeDigest: t.Envelope.EnvelopeDigest, PreviewDigest: t.Envelope.PreviewDigest, RenderingVersion: t.Envelope.RenderingVersion, RenderedAt: now}
		if e := receipt.Seal(); e != nil {
			return e
		}
		challenge = s.Challenge
		challenge.DisplayInstanceID = displayID
		challenge.DisplayNonce = s.Challenge.Nonce
		challenge.RenderReceiptDigest = receipt.ReceiptDigest
		if e := challenge.Seal(); e != nil {
			return e
		}
		s.State, s.RenderedAt, s.Challenge, s.ChallengeDigest = "RENDERED", now, challenge, challenge.ChallengeDigest
		if e := s.Seal(); e != nil {
			return e
		}
		t.Receipt = &receipt
		t.CallbackSessions[sessionID] = s
		return nil
	})
	return t, receipt, challenge, e
}

// RecordAuthenticatedCallback constructs the authoritative decision event from persisted
// state, verifies the opaque handle, and performs a single CAS RENDERED→DECIDED.
func (c *Controller) RecordAuthenticatedCallback(ctx context.Context, id string, version uint64, sessionID, handle, decision string) (TaskRecord, OwnerDecisionEvent, error) {
	if sessionID == "" || handle == "" || (decision != "approve" && decision != "reject") {
		return TaskRecord{}, OwnerDecisionEvent{}, ErrDecisionDenied
	}
	var event OwnerDecisionEvent
	t, e := c.mutate(ctx, id, version, "owner_callback", "owner_decision_recorded", []TaskState{Accepted}, Accepted, func(t *TaskRecord) error {
		s, ok := t.CallbackSessions[sessionID]
		now := time.Now().UTC()
		if !ok || s.State != "RENDERED" || t.Envelope == nil || t.Receipt == nil || t.Action == nil || s.Challenge.DisplayInstanceID == "" || s.Challenge.RenderReceiptDigest == "" || t.Receipt.DisplayInstanceID != s.Challenge.DisplayInstanceID || t.Receipt.ReceiptDigest != s.Challenge.RenderReceiptDigest || now.After(s.Challenge.ExpiresAt) || subtle.ConstantTimeCompare([]byte(digestString(handle)), []byte(s.Challenge.HandleDigest)) != 1 {
			return ErrDecisionDenied
		}
		verifiedID, verifiedProof, e := c.callback.VerifyCallback(ctx, s.Challenge, handle, decision)
		if e != nil || verifiedID == "" || verifiedProof == "" {
			return ErrDecisionDenied
		}
		// Verification may block; expiry is checked again before it can authorize.
		now = time.Now().UTC()
		if now.After(s.Challenge.ExpiresAt) {
			return ErrDecisionDenied
		}
		eid, e := randomID("decision_")
		if e != nil {
			return e
		}
		event = OwnerDecisionEvent{DecisionEventID: eid, Decision: decision, InteractionID: t.Envelope.InteractionID, DeliveryBindingID: t.Envelope.DeliveryBindingID, DisplayInstanceID: s.Challenge.DisplayInstanceID, RenderReceiptDigest: t.Receipt.ReceiptDigest, EnvelopeDigest: t.Envelope.EnvelopeDigest, PreviewDigest: t.Envelope.PreviewDigest, RenderingVersion: t.Envelope.RenderingVersion, ActionID: t.Action.ActionID, PayloadHash: t.Action.PayloadHash, DestinationHash: t.Action.DestinationHash, ReconciliationPolicyDigest: t.Action.ReconciliationPolicyDigest, Nonce: t.Envelope.Nonce, ChallengeDigest: s.Challenge.ChallengeDigest, ExpiresAt: s.Challenge.ExpiresAt, PolicyVersion: t.Envelope.PolicyVersion, ApproverID: verifiedID, RecentAuthProofRef: verifiedProof, ReceivedAt: now}
		if e := event.Seal(); e != nil {
			return e
		}
		if t.Decisions == nil {
			t.Decisions = map[string]ApprovalRecord{}
		}
		t.Decisions[event.DecisionEventID] = ApprovalRecord{DecisionEventID: event.DecisionEventID, Decision: event.Decision, InteractionID: event.InteractionID, PreviewDigest: event.PreviewDigest, RecordedAt: now}
		s.State, s.DecidedAt, s.DecisionEventID = "DECIDED", now, event.DecisionEventID
		if e := s.Seal(); e != nil {
			return e
		}
		t.CallbackSessions[sessionID] = s
		return nil
	})
	return t, event, e
}

func (c *Controller) RecordRenderReceipt(ctx context.Context, id string, version uint64, r InteractionRenderReceipt) (TaskRecord, error) {
	if e := r.Validate(); e != nil {
		return TaskRecord{}, e
	}
	return c.mutate(ctx, id, version, "delivery_adapter", "render_receipt", []TaskState{Accepted}, Accepted, func(t *TaskRecord) error {
		if t.Envelope == nil || r.InteractionID != t.Envelope.InteractionID || r.DeliveryBindingID != t.Envelope.DeliveryBindingID || r.EnvelopeDigest != t.Envelope.EnvelopeDigest || r.PreviewDigest != t.Envelope.PreviewDigest || r.RenderingVersion != t.Envelope.RenderingVersion || r.RenderedAt.After(t.Envelope.ExpiresAt) {
			return ErrBindingMismatch
		}
		for _, session := range t.CallbackSessions {
			if session.State == "RENDERED" {
				return ErrVersionConflict
			}
		}
		t.Receipt = &r
		return nil
	})
}
func (c *Controller) RecordOwnerDecision(ctx context.Context, id string, version uint64, binding InteractionDeliveryBinding, event OwnerDecisionEvent) (TaskRecord, error) {
	if e := binding.Validate(); e != nil {
		return TaskRecord{}, e
	}
	if e := event.Validate(); e != nil {
		return TaskRecord{}, e
	}
	return c.mutate(ctx, id, version, "owner_callback", "owner_decision_recorded", []TaskState{Accepted}, Accepted, func(t *TaskRecord) error {
		if t.Envelope == nil || t.Receipt == nil || t.Action == nil {
			return ErrBindingMismatch
		}
		env, r, a := t.Envelope, t.Receipt, t.Action
		if t.DeliveryBinding == nil || binding.BindingDigest != t.DeliveryBinding.BindingDigest || binding.DeliveryBindingID != t.DeliveryBinding.DeliveryBindingID || binding.RenderingVersion != t.DeliveryBinding.RenderingVersion || env.DeliveryBindingID != t.DeliveryBinding.DeliveryBindingID {
			return ErrBindingMismatch
		}
		_, nowDigest, e := RenderPreview(*a, env.RenderingVersion)
		if e != nil || nowDigest != env.PreviewDigest {
			return ErrBindingMismatch
		}
		if event.ReceivedAt.After(event.ExpiresAt) || time.Now().UTC().After(event.ExpiresAt) || event.DecisionEventID == "" {
			return ErrDecisionDenied
		}
		if _, used := t.Decisions[event.DecisionEventID]; used {
			return ErrDecisionDenied
		}
		// An interaction nonce/challenge is single-use even when an attacker invents a
		// fresh event ID. A new decision requires a freshly rendered envelope.
		for _, prior := range t.Decisions {
			if prior.InteractionID == event.InteractionID {
				return ErrDecisionDenied
			}
		}
		if event.InteractionID != env.InteractionID || event.DeliveryBindingID != env.DeliveryBindingID || event.DisplayInstanceID != r.DisplayInstanceID || event.RenderReceiptDigest != r.ReceiptDigest || event.EnvelopeDigest != env.EnvelopeDigest || event.PreviewDigest != env.PreviewDigest || event.RenderingVersion != env.RenderingVersion || event.ActionID != a.ActionID || event.PayloadHash != a.PayloadHash || event.DestinationHash != a.DestinationHash || event.ReconciliationPolicyDigest != a.ReconciliationPolicyDigest || event.Nonce != env.Nonce || event.ChallengeDigest != env.ChallengeDigest || !event.ExpiresAt.Equal(env.ExpiresAt) || event.PolicyVersion != env.PolicyVersion {
			return ErrBindingMismatch
		}
		if e := c.auth.AuthenticateOwnerDecision(ctx, *t.DeliveryBinding, event); e != nil {
			return ErrDecisionDenied
		}
		if t.Decisions == nil {
			t.Decisions = make(map[string]ApprovalRecord)
		}
		t.Decisions[event.DecisionEventID] = ApprovalRecord{DecisionEventID: event.DecisionEventID, Decision: event.Decision, InteractionID: event.InteractionID, PreviewDigest: event.PreviewDigest, RecordedAt: event.ReceivedAt}
		return nil
	})
}
func ValidateRootAttestation(expected, observed RootRuntimeAttestation) error {
	if e := expected.Validate(); e != nil {
		return e
	}
	if e := observed.Validate(); e != nil {
		return e
	}
	if expected.AttestationDigest != observed.AttestationDigest {
		return ErrBindingMismatch
	}
	return nil
}
