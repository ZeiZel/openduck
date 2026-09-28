package mesh

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// OperationRequest is a closed operation-specific reference union. It never
// carries transcript or tool payload bodies. Exactly one reference shape is
// accepted for send/steer, cancellation, or revision-scoped operations.
type OperationRequest struct {
	Target      TargetRequest
	InputRef    string
	RevisionRef string
	ReasonRef   string
}
type SendReceipt struct {
	CallerEndpointID string `json:",omitempty"`
	CallerGeneration uint64 `json:",omitempty"`
	CallerRunID      string
	TargetRunID      string
	Operation        string `json:",omitempty"`
	// InputRef retains the pre-existing mesh-snapshot.v2 wire name
	// `RevisionRef`. The persisted value was always passed to Send/Steer; the
	// Go name now states that input semantics explicitly without rejecting old
	// encrypted journals under DisallowUnknownFields.
	InputRef string `json:"RevisionRef"`
	Digest   string
	State    string
}

// CancelReceipt is the durable exactly-once boundary for a native provider
// cancellation. It binds the authenticated caller endpoint generation to the
// child target and the operation-specific revision/reason references. The
// receipt deliberately stores opaque references only.
type CancelReceipt struct {
	CallerEndpointID string
	CallerGeneration uint64
	TargetRunID      string
	RevisionRef      string
	ReasonRef        string
	Digest           string
	State            string
}

const OperationDigestV1 = "mesh-operation-digest.v1"

const cancelReceiptV1 = "mesh-cancel-receipt.v1"
const inputReceiptV2 = "mesh-input-receipt.v2"

// operationDigestInput fixes both reference names and ordering before hashing,
// so the same opaque value cannot be substituted across operation fields.
type operationDigestInput struct {
	SchemaVersion string `json:"schema_version"`
	TargetRunID   string `json:"target_run_id"`
	Operation     string `json:"operation"`
	InputRef      string `json:"input_ref"`
	RevisionRef   string `json:"revision_ref"`
	ReasonRef     string `json:"reason_ref"`
}

// cancelReceiptDigestInput is separate from OperationRequest's endpoint
// digest: the request authenticates the operation, while this digest also
// makes durable replay specific to the endpoint capability generation that
// issued it.
type cancelReceiptDigestInput struct {
	SchemaVersion    string `json:"schema_version"`
	CallerEndpointID string `json:"caller_endpoint_id"`
	CallerGeneration uint64 `json:"caller_generation"`
	TargetRunID      string `json:"target_run_id"`
	RevisionRef      string `json:"revision_ref"`
	ReasonRef        string `json:"reason_ref"`
}

type inputReceiptDigestInput struct {
	SchemaVersion    string `json:"schema_version"`
	CallerEndpointID string `json:"caller_endpoint_id"`
	CallerGeneration uint64 `json:"caller_generation"`
	CallerRunID      string `json:"caller_run_id"`
	TargetRunID      string `json:"target_run_id"`
	Operation        string `json:"operation"`
	InputRef         string `json:"input_ref"`
}

func inputReceiptDigest(binding MeshEndpointBinding, targetRunID, operation, inputRef string) string {
	return hash(inputReceiptDigestInput{SchemaVersion: inputReceiptV2, CallerEndpointID: binding.EndpointID, CallerGeneration: binding.Generation, CallerRunID: binding.RunID, TargetRunID: targetRunID, Operation: operation, InputRef: inputRef})
}

func inputReceiptKey(binding MeshEndpointBinding, targetRunID, operation, inputRef string) string {
	return "input:" + inputReceiptDigest(binding, targetRunID, operation, inputRef)
}

func legacyInputReceiptKey(endpointID, targetRunID, operation, inputRef string) string {
	return operation + ":" + endpointID + ":" + targetRunID + ":" + inputRef
}

func cancelReceiptKey(endpointID string, generation uint64, targetRunID string) string {
	return "cancel:" + endpointID + ":" + fmt.Sprint(generation) + ":" + targetRunID
}

func cancelReceiptDigest(endpointID string, generation uint64, targetRunID, revisionRef, reasonRef string) string {
	return hash(cancelReceiptDigestInput{
		SchemaVersion:    cancelReceiptV1,
		CallerEndpointID: endpointID,
		CallerGeneration: generation,
		TargetRunID:      targetRunID,
		RevisionRef:      revisionRef,
		ReasonRef:        reasonRef,
	})
}

func inputControlFence(digest string) string  { return "input:" + digest }
func cancelControlFence(digest string) string { return "cancel:" + digest }

func validControlFence(fence string) bool {
	for _, prefix := range []string{"input:", "cancel:"} {
		if value, ok := strings.CutPrefix(fence, prefix); ok {
			return isDigest(value)
		}
	}
	return false
}

func controlFenceHasPendingReceipt(run Run, snapshot Snapshot) bool {
	matches := 0
	for _, receipt := range snapshot.SendReceipts {
		if receipt.TargetRunID == run.ID && receipt.State == "pending" && run.ControlFence == inputControlFence(receipt.Digest) {
			matches++
		}
	}
	for _, receipt := range snapshot.CancelReceipts {
		if receipt.TargetRunID == run.ID && receipt.State == "pending" && run.ControlFence == cancelControlFence(receipt.Digest) {
			matches++
		}
	}
	return matches == 1
}

// Digest returns the canonical endpoint digest only for an exact valid member
// of the operation reference union.
func (r OperationRequest) Digest() (string, error) {
	return r.digestFor(r.Target.Operation)
}

func (r OperationRequest) digestFor(operation string) (string, error) {
	if r.Target.Operation != operation || !validID(r.Target.TargetRunID) {
		return "", ErrInvalidContract
	}
	switch operation {
	case "send", "steer":
		if !validID(r.InputRef) || r.RevisionRef != "" || r.ReasonRef != "" {
			return "", ErrInvalidContract
		}
	case "cancel":
		if !validID(r.RevisionRef) || !validID(r.ReasonRef) || r.InputRef != "" {
			return "", ErrInvalidContract
		}
	case "wait", "collect", "status", "result", "list":
		if !validID(r.RevisionRef) || r.InputRef != "" || r.ReasonRef != "" {
			return "", ErrInvalidContract
		}
	default:
		return "", ErrInvalidContract
	}
	return hash(operationDigestInput{
		SchemaVersion: OperationDigestV1,
		TargetRunID:   r.Target.TargetRunID,
		Operation:     operation,
		InputRef:      r.InputRef,
		RevisionRef:   r.RevisionRef,
		ReasonRef:     r.ReasonRef,
	}), nil
}

// legacySendReceiptDigest is accepted only while replaying a receipt written
// before OperationDigestV1. It is never emitted for new work.
func legacySendReceiptDigest(targetRunID, operation, inputRef string) string {
	return hash(targetRunID + ":" + operation + ":" + inputRef)
}

// migrateLegacySendReceipt upgrades a legacy delimiter-keyed receipt only
// after the authenticated endpoint is proven to be the target's exact parent.
// It never turns the old, historically incorrect CallerRunID into provenance.
func (c *Coordinator) migrateLegacySendReceipt(ctx context.Context, snapshot Snapshot, oldKey, newKey string, binding MeshEndpointBinding, operation, inputRef string) error {
	receipt, ok := snapshot.SendReceipts[oldKey]
	if !ok || !legacySendReceiptMatchesBinding(oldKey, receipt, snapshot, binding, operation, inputRef) {
		return ErrReconciliationNeeded
	}
	next := snapshot.clone()
	delete(next.SendReceipts, oldKey)
	oldDigest := receipt.Digest
	receipt.CallerEndpointID = binding.EndpointID
	receipt.CallerGeneration = binding.Generation
	receipt.CallerRunID = binding.RunID
	receipt.Operation = operation
	receipt.Digest = inputReceiptDigest(binding, receipt.TargetRunID, operation, receipt.InputRef)
	next.SendReceipts[newKey] = receipt
	if receipt.State == "pending" {
		run, found := next.Runs[receipt.TargetRunID]
		if !found || run.State != RunRunning || (run.ControlFence != "" && run.ControlFence != inputControlFence(oldDigest)) {
			return ErrReconciliationNeeded
		}
		run.ControlFence = inputControlFence(receipt.Digest)
		next.Runs[run.ID] = run
	}
	return c.cas(ctx, snapshot, next)
}

func (c *Coordinator) authenticateOperation(ctx context.Context, r OperationRequest, operation string) (MeshEndpointBinding, error) {
	digest, err := r.digestFor(operation)
	if err != nil || r.Target.Endpoint.MessageDigest != digest {
		return MeshEndpointBinding{}, ErrUnauthorized
	}
	b, err := c.endpoints.AuthorizeOperationForPolicy(r.Target.Endpoint, c.now().UTC(), operation, digest, c.policyVersion)
	if err != nil {
		return MeshEndpointBinding{}, err
	}
	return b, nil
}

func (c *Coordinator) verifyOperation(ctx context.Context, r OperationRequest, operation string) (MeshEndpointBinding, error) {
	digest, err := r.digestFor(operation)
	if err != nil || r.Target.Endpoint.MessageDigest != digest {
		return MeshEndpointBinding{}, ErrUnauthorized
	}
	return c.endpoints.verifyOperationForPolicy(ctx, r.Target.Endpoint, c.now().UTC(), operation, digest, c.policyVersion)
}

func (c *Coordinator) authorizeOperationBinding(ctx context.Context, r OperationRequest, operation string) (MeshEndpointBinding, Run, error) {
	b, err := c.authenticateOperation(ctx, r, operation)
	if err != nil {
		return MeshEndpointBinding{}, Run{}, err
	}
	run, err := c.authorizeTarget(ctx, b, r.Target.TargetRunID, operation)
	if err != nil {
		return MeshEndpointBinding{}, Run{}, err
	}
	return b, run, nil
}

func (c *Coordinator) authorizeOperation(ctx context.Context, r OperationRequest, operation string) (Run, error) {
	_, run, err := c.authorizeOperationBinding(ctx, r, operation)
	return run, err
}
func (c *Coordinator) targetSession(ctx context.Context, r OperationRequest, operation string) (MeshEndpointBinding, Run, SessionRef, error) {
	binding, run, err := c.authorizeOperationBinding(ctx, r, operation)
	if err != nil {
		return MeshEndpointBinding{}, Run{}, SessionRef{}, err
	}
	if run.ControlFence != "" {
		return MeshEndpointBinding{}, Run{}, SessionRef{}, ErrReconciliationNeeded
	}
	// Input-producing operations are never safe against an admitted, starting,
	// terminal, or uncertain child. Observation operations deliberately keep
	// their terminal semantics and are handled below by the provider evidence
	// transition path.
	if (operation == "send" || operation == "steer") && run.State != RunRunning {
		return MeshEndpointBinding{}, Run{}, SessionRef{}, ErrDenied
	}
	if c.sessions == nil || run.ProviderSessionID == "" {
		return MeshEndpointBinding{}, Run{}, SessionRef{}, ErrReconciliationNeeded
	}
	return binding, run, SessionRef{ProviderSessionID: run.ProviderSessionID}, nil
}
func (c *Coordinator) Send(ctx context.Context, r OperationRequest) error {
	c.mu.Lock()
	locked := true
	defer func() {
		if locked {
			c.mu.Unlock()
		}
	}()
	binding, run, ref, e := c.targetSession(ctx, r, "send")
	if e != nil {
		return e
	}
	key := inputReceiptKey(binding, run.ID, "send", r.InputRef)
	legacyKey := legacyInputReceiptKey(binding.EndpointID, run.ID, "send", r.InputRef)
	d := inputReceiptDigest(binding, run.ID, "send", r.InputRef)
	persisted := false
	for i := 0; i < 8; i++ {
		s, err := c.repo.Load(ctx)
		if err != nil {
			return err
		}
		if old, ok := s.SendReceipts[key]; ok {
			if old.Digest != d {
				return ErrIdempotencyConflict
			}
			if old.State == "sent" {
				return nil
			}
			return ErrReconciliationNeeded
		}
		if _, legacy := s.SendReceipts[legacyKey]; legacy {
			if err = c.migrateLegacySendReceipt(ctx, s, legacyKey, key, binding, "send", r.InputRef); err == nil || errors.Is(err, ErrVersionConflict) {
				continue
			}
			return err
		}
		n := s.clone()
		target, ok := n.Runs[run.ID]
		if !ok || target.State != RunRunning || target.ControlFence != "" {
			return ErrReconciliationNeeded
		}
		target.ControlFence = inputControlFence(d)
		n.Runs[target.ID] = target
		n.SendReceipts[key] = SendReceipt{CallerEndpointID: binding.EndpointID, CallerGeneration: binding.Generation, CallerRunID: binding.RunID, TargetRunID: run.ID, Operation: "send", InputRef: r.InputRef, Digest: d, State: "pending"}
		if err = c.cas(ctx, s, n); err == nil {
			persisted = true
			break
		} else if !errors.Is(err, ErrVersionConflict) {
			return err
		}
	}
	if !persisted {
		// No durable pending receipt means no provider dispatch is safe.
		return ErrVersionConflict
	}
	// The control fence is durable. Do not hold the global coordinator mutex
	// across a native call: a competing control must be able to observe that
	// fence, and a monotone revoke/close must not wait on provider I/O.
	c.mu.Unlock()
	locked = false
	e = c.sessions.Send(ctx, ref, r.InputRef)
	return c.finalizeInputControl(ctx, key, d, run.ID, e)
}
func (c *Coordinator) Steer(ctx context.Context, r OperationRequest) error {
	c.mu.Lock()
	locked := true
	defer func() {
		if locked {
			c.mu.Unlock()
		}
	}()
	binding, run, ref, e := c.targetSession(ctx, r, "steer")
	if e != nil {
		return e
	}
	key := inputReceiptKey(binding, run.ID, "steer", r.InputRef)
	legacyKey := legacyInputReceiptKey(binding.EndpointID, run.ID, "steer", r.InputRef)
	d := inputReceiptDigest(binding, run.ID, "steer", r.InputRef)
	persisted := false
	for i := 0; i < 8; i++ {
		s, err := c.repo.Load(ctx)
		if err != nil {
			return err
		}
		if old, ok := s.SendReceipts[key]; ok {
			if old.Digest != d {
				return ErrIdempotencyConflict
			}
			if old.State == "sent" {
				return nil
			}
			return ErrReconciliationNeeded
		}
		if _, legacy := s.SendReceipts[legacyKey]; legacy {
			if err = c.migrateLegacySendReceipt(ctx, s, legacyKey, key, binding, "steer", r.InputRef); err == nil || errors.Is(err, ErrVersionConflict) {
				continue
			}
			return err
		}
		n := s.clone()
		target, ok := n.Runs[run.ID]
		if !ok || target.State != RunRunning || target.ControlFence != "" {
			return ErrReconciliationNeeded
		}
		target.ControlFence = inputControlFence(d)
		n.Runs[target.ID] = target
		n.SendReceipts[key] = SendReceipt{CallerEndpointID: binding.EndpointID, CallerGeneration: binding.Generation, CallerRunID: binding.RunID, TargetRunID: run.ID, Operation: "steer", InputRef: r.InputRef, Digest: d, State: "pending"}
		if err = c.cas(ctx, s, n); err == nil {
			persisted = true
			break
		} else if !errors.Is(err, ErrVersionConflict) {
			return err
		}
	}
	if !persisted {
		return ErrVersionConflict
	}
	c.mu.Unlock()
	locked = false
	e = c.sessions.Steer(ctx, ref, r.InputRef)
	return c.finalizeInputControl(ctx, key, d, run.ID, e)
}

// finalizeInputControl is the post-provider exactly-once boundary for Send and
// Steer. An ambiguous ACK closes the target run and its endpoints in the same
// durable CAS; a replay can only observe the uncertain receipt and never
// redispatch. A definitive pre-dispatch denial remains a failed receipt.
func (c *Coordinator) finalizeInputControl(ctx context.Context, key, digest, runID string, providerErr error) error {
	uncertain := errors.Is(providerErr, ErrControlUncertain) || errors.Is(providerErr, ErrReconciliationNeeded)
	for i := 0; i < 8; i++ {
		s, err := c.repo.Load(ctx)
		if err != nil {
			if uncertain {
				c.poisoned.Store(true)
			}
			return errors.Join(providerErr, err)
		}
		n := s.clone()
		x, ok := n.SendReceipts[key]
		if !ok || x.Digest != digest || x.State != "pending" || x.TargetRunID != runID {
			return ErrReconciliationNeeded
		}
		run, exists := n.Runs[runID]
		if !exists || run.State != RunRunning || run.ControlFence != inputControlFence(digest) {
			return ErrReconciliationNeeded
		}
		run.ControlFence = ""
		if uncertain {
			x.State = "uncertain"
			run.State = RunUncertain
			run.TerminalAt = c.now().UTC()
			for endpointID, binding := range n.EndpointBindings {
				if binding.RunID == runID {
					n.EndpointRevoked[endpointID] = true
				}
			}
			n.Events = append(n.Events, event(c.now().UTC(), "run_uncertain", run, "control_ack_uncertain"))
		} else if providerErr != nil {
			x.State = "failed"
		} else {
			x.State = "sent"
		}
		n.Runs[runID] = run
		n.SendReceipts[key] = x
		if err = c.casSafetyMonotone(ctx, s, n); err == nil {
			if uncertain {
				return errors.Join(ErrReconciliationNeeded, ErrControlUncertain, providerErr)
			}
			return providerErr
		} else if !errors.Is(err, ErrVersionConflict) {
			if uncertain {
				c.poisoned.Store(true)
			}
			return errors.Join(providerErr, err)
		}
	}
	if uncertain {
		c.poisoned.Store(true)
		return errors.Join(ErrReconciliationNeeded, ErrControlUncertain, providerErr)
	}
	return ErrReconciliationNeeded
}
func (c *Coordinator) Cancel(ctx context.Context, r OperationRequest) error {
	c.mu.Lock()
	locked := true
	defer func() {
		if locked {
			c.mu.Unlock()
		}
	}()
	binding, e := c.verifyOperation(ctx, r, "cancel")
	if e != nil {
		return e
	}
	// An exact durable cancelled receipt is the sole terminal-cancel replay
	// exception. Authenticate and check lineage without applying the public
	// live-control state gate; prepareCancel below permits only that receipt.
	if _, e = c.authorizeTargetLineage(ctx, binding, r.Target.TargetRunID, "cancel"); e != nil {
		return e
	}
	if c.sessions == nil {
		return ErrReconciliationNeeded
	}
	key := cancelReceiptKey(binding.EndpointID, binding.Generation, r.Target.TargetRunID)
	digest := cancelReceiptDigest(binding.EndpointID, binding.Generation, r.Target.TargetRunID, r.RevisionRef, r.ReasonRef)
	run, ref, replayed, e := c.prepareCancel(ctx, binding, r, key, digest)
	if e != nil {
		return e
	}
	if replayed {
		return nil
	}
	// prepareCancel has durably recorded the exact request and revoked every
	// target child endpoint in the same CAS. This is the only native dispatch.
	// A retry can only read this receipt; it can never call Cancel again.
	c.mu.Unlock()
	locked = false
	providerErr := c.sessions.Cancel(ctx, ref, Cancellation{Mode: CancellationUser, RevisionRef: r.RevisionRef, ReasonRef: r.ReasonRef})
	state, runState, eventName := "cancelled", RunCancelled, "run_cancelled"
	if providerErr != nil {
		// A timeout/error may be reported after the provider applied the cancel.
		// Preserve that ambiguity as a durable uncertain run, never as a retry.
		state, runState, eventName = "uncertain", RunUncertain, "run_uncertain"
	}
	if e = c.finalizeCancel(ctx, key, digest, run.ID, state, runState, eventName); e != nil {
		return errors.Join(ErrReconciliationNeeded, providerErr, e)
	}
	if providerErr != nil {
		return errors.Join(ErrReconciliationNeeded, providerErr)
	}
	return nil
}

// prepareCancel records a pending receipt and revokes every endpoint bound to
// the target in one CAS before the provider sees a cancellation request.
// Conflicts here are safe to retry because no provider action has happened.
func (c *Coordinator) prepareCancel(ctx context.Context, binding MeshEndpointBinding, r OperationRequest, key, digest string) (Run, SessionRef, bool, error) {
	for i := 0; i < 8; i++ {
		s, err := c.repo.Load(ctx)
		if err != nil {
			return Run{}, SessionRef{}, false, err
		}
		if old, ok := s.CancelReceipts[key]; ok {
			if old.Digest != digest {
				return Run{}, SessionRef{}, false, ErrIdempotencyConflict
			}
			if old.State == "cancelled" {
				return s.Runs[old.TargetRunID], SessionRef{}, true, nil
			}
			return Run{}, SessionRef{}, false, ErrReconciliationNeeded
		}
		current, endpointOK := s.EndpointBindings[binding.EndpointID]
		nonceKey := endpointNonceKey(binding, r.Target.Endpoint.Nonce)
		if !endpointOK || current.Generation != binding.Generation || current.PolicyVersion != c.policyVersion || current.RootRunID != binding.RootRunID || current.RunID != binding.RunID || current.SessionID != binding.SessionID || current.AttemptID != binding.AttemptID || s.EndpointRevoked[binding.EndpointID] || !current.ExpiresAt.After(c.now().UTC()) {
			return Run{}, SessionRef{}, false, ErrUnauthorized
		}
		if s.EndpointNonces[nonceKey] {
			return Run{}, SessionRef{}, false, ErrReplay
		}
		run, ok := s.Runs[r.Target.TargetRunID]
		if !ok || run.RootID != binding.RootRunID || run.ParentRunID != binding.RunID {
			return Run{}, SessionRef{}, false, ErrUnauthorized
		}
		// Cancellation is a native control operation. A terminal target is only
		// idempotent through an exact durable receipt above; a starting/admitted
		// target has no safely established provider session to control.
		if run.State.terminal() {
			return Run{}, SessionRef{}, false, ErrDenied
		}
		if run.State != RunRunning || run.ControlFence != "" || !validID(run.ProviderSessionID) {
			return Run{}, SessionRef{}, false, ErrReconciliationNeeded
		}
		n := s.clone()
		n.EndpointNonces[nonceKey] = true
		run.ControlFence = cancelControlFence(digest)
		n.Runs[run.ID] = run
		n.CancelReceipts[key] = CancelReceipt{
			CallerEndpointID: binding.EndpointID,
			CallerGeneration: binding.Generation,
			TargetRunID:      run.ID,
			RevisionRef:      r.RevisionRef,
			ReasonRef:        r.ReasonRef,
			Digest:           digest,
			State:            "pending",
		}
		for endpointID, targetBinding := range n.EndpointBindings {
			if targetBinding.RunID == run.ID {
				n.EndpointRevoked[endpointID] = true
			}
		}
		if err = c.casSafety(ctx, s, n); err == nil {
			return run, SessionRef{ProviderSessionID: run.ProviderSessionID}, false, nil
		}
		if !errors.Is(err, ErrVersionConflict) {
			return Run{}, SessionRef{}, false, err
		}
	}
	return Run{}, SessionRef{}, false, ErrVersionConflict
}

// finalizeCancel has deliberately no CAS retry. The provider has already
// observed the request, so a concurrent/uncertain outcome is a reconciliation
// boundary rather than an opportunity to infer success or dispatch again.
func (c *Coordinator) finalizeCancel(ctx context.Context, key, digest, runID, receiptState string, runState RunState, eventName string) error {
	s, err := c.repo.Load(ctx)
	if err != nil {
		return err
	}
	n := s.clone()
	receipt, ok := n.CancelReceipts[key]
	if !ok || receipt.Digest != digest || receipt.State != "pending" || receipt.TargetRunID != runID {
		return ErrReconciliationNeeded
	}
	run, ok := n.Runs[runID]
	if !ok || run.State != RunRunning || run.ControlFence != cancelControlFence(digest) {
		return ErrReconciliationNeeded
	}
	receipt.State = receiptState
	n.CancelReceipts[key] = receipt
	run.State = runState
	run.ControlFence = ""
	run.TerminalAt = c.now().UTC()
	n.Runs[runID] = run
	for endpointID, binding := range n.EndpointBindings {
		if binding.RunID == runID {
			n.EndpointRevoked[endpointID] = true
		}
	}
	n.Events = append(n.Events, event(c.now().UTC(), eventName, run, ""))
	return c.casSafetyMonotone(ctx, s, n)
}
func (c *Coordinator) Status(ctx context.Context, r OperationRequest) (SessionStatus, error) {
	c.mu.Lock()
	_, run, ref, e := c.targetSession(ctx, r, "status")
	c.mu.Unlock()
	if e != nil {
		return SessionStatus{}, e
	}
	out, e := c.sessions.Status(ctx, ref)
	if e != nil {
		return SessionStatus{}, e
	}
	if e = c.observeTerminal(ctx, run.ID, out.State); e != nil {
		return SessionStatus{}, e
	}
	return out, nil
}
func (c *Coordinator) Result(ctx context.Context, r OperationRequest) (ResultEnvelope, error) {
	c.mu.Lock()
	_, run, ref, e := c.targetSession(ctx, r, "result")
	c.mu.Unlock()
	if e != nil {
		return ResultEnvelope{}, e
	}
	out, e := c.sessions.Result(ctx, ref, r.RevisionRef)
	if e != nil {
		return ResultEnvelope{}, e
	}
	if out.RunID != run.ID || out.AttemptID != run.AttemptID || out.Classification == "" {
		return ResultEnvelope{}, ErrDenied
	}
	if e = c.observeTerminal(ctx, run.ID, out.Status); e != nil {
		return ResultEnvelope{}, e
	}
	return out, nil
}
func (c *Coordinator) Collect(ctx context.Context, r OperationRequest) (ResultEnvelope, error) {
	c.mu.Lock()
	_, run, ref, e := c.targetSession(ctx, r, "collect")
	c.mu.Unlock()
	if e != nil {
		return ResultEnvelope{}, e
	}
	out, e := c.sessions.Result(ctx, ref, r.RevisionRef)
	if e != nil {
		return ResultEnvelope{}, e
	}
	if out.RunID != run.ID || out.AttemptID != run.AttemptID || out.Classification == "" {
		return ResultEnvelope{}, ErrDenied
	}
	if e = c.observeTerminal(ctx, run.ID, out.Status); e != nil {
		return ResultEnvelope{}, e
	}
	return out, nil
}
func (c *Coordinator) Wait(ctx context.Context, r OperationRequest) (SessionStatus, error) {
	c.mu.Lock()
	_, run, ref, e := c.targetSession(ctx, r, "wait")
	c.mu.Unlock()
	if e != nil {
		return SessionStatus{}, e
	}
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = c.now().Add(time.Second)
	}
	out, e := c.sessions.Wait(ctx, ref, deadline)
	if e != nil {
		return SessionStatus{}, e
	}
	if e = c.observeTerminal(ctx, run.ID, out.State); e != nil {
		return SessionStatus{}, e
	}
	return out, nil
}

func terminalProviderState(state string) (RunState, string, bool) {
	switch state {
	case "completed":
		return RunCompleted, "run_completed", true
	case "failed":
		return RunFailed, "run_failed", true
	case "cancelled":
		return RunCancelled, "run_cancelled", true
	case "uncertain":
		return RunUncertain, "run_uncertain", true
	default:
		return "", "", false
	}
}

// observeTerminal turns trusted provider terminal evidence into a durable run
// transition before returning it to the caller. This also revokes every child
// endpoint bound to the target; no further input can be sent after a terminal
// observation even through a still-valid parent/root endpoint.
func (c *Coordinator) observeTerminal(ctx context.Context, runID, providerState string) error {
	state, eventName, terminal := terminalProviderState(providerState)
	if !terminal {
		return nil
	}
	if err := c.transitionRun(ctx, runID, state, eventName); err != nil {
		return errors.Join(ErrReconciliationNeeded, err)
	}
	return nil
}

type RunProjection struct {
	RunID, ParentRunID, SessionID, Provider, ProfileID, Status string
	Depth                                                      uint64
}

func (c *Coordinator) List(ctx context.Context, r OperationRequest) ([]RunProjection, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	target, err := c.authorizeOperation(ctx, r, "list")
	if err != nil {
		return nil, err
	}
	s, err := c.repo.Load(ctx)
	if err != nil {
		return nil, err
	}
	self, ok := s.Runs[target.ID]
	if !ok || self.ID != target.ID {
		return nil, ErrUnauthorized
	}
	out := []RunProjection{{RunID: self.ID, ParentRunID: self.ParentRunID, SessionID: self.SessionID, Provider: self.Provider, ProfileID: self.ProfileID, Status: string(self.State), Depth: self.Depth}}
	for _, run := range s.Runs {
		if run.ParentRunID == self.ID {
			out = append(out, RunProjection{RunID: run.ID, ParentRunID: run.ParentRunID, SessionID: run.SessionID, Provider: run.Provider, ProfileID: run.ProfileID, Status: string(run.State), Depth: run.Depth})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].RunID < out[j].RunID })
	return out, nil
}

type ProfileLister interface {
	List(context.Context) ([]Profile, error)
}
type ListProfilesRequest struct {
	Endpoint    EndpointRequest
	RevisionRef string
}

func (c *Coordinator) ListProfiles(ctx context.Context, r ListProfilesRequest) ([]Profile, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !validID(r.RevisionRef) || r.Endpoint.MessageDigest != hash("listProfiles:"+r.RevisionRef) {
		return nil, ErrUnauthorized
	}
	b, e := c.endpoints.AuthorizeOperationForPolicy(r.Endpoint, c.now().UTC(), "listProfiles", r.Endpoint.MessageDigest, c.policyVersion)
	if e != nil {
		return nil, e
	}
	if _, e = c.authorizeTarget(ctx, b, b.RunID, "list"); e != nil {
		return nil, e
	}
	l, ok := c.directory.(ProfileLister)
	if !ok {
		return nil, ErrDenied
	}
	all, e := l.List(ctx)
	if e != nil {
		return nil, e
	}
	out := make([]Profile, 0, len(all))
	for _, p := range all {
		if p.Eligible() {
			out = append(out, p)
		}
	}
	return out, nil
}
func (c *Coordinator) transitionRun(ctx context.Context, id string, state RunState, eventName string) error {
	if !state.terminal() {
		return ErrInvalidContract
	}
	for i := 0; i < 8; i++ {
		s, e := c.repo.Load(ctx)
		if e != nil {
			return e
		}
		r, ok := s.Runs[id]
		if !ok {
			return ErrNotFound
		}
		if r.ControlFence != "" {
			return ErrReconciliationNeeded
		}
		for _, receipt := range s.CancelReceipts {
			if receipt.TargetRunID == id && receipt.State == "pending" {
				// A provider observation cannot safely finalize a separately
				// authenticated cancellation receipt: its exact reason/revision
				// boundary must be reconciled without changing the receipt shape.
				return ErrReconciliationNeeded
			}
		}
		if r.State.terminal() {
			// A terminal observation is not authority to rewrite a durable
			// outcome, but it must still close a retained legacy endpoint if one
			// survived an older snapshot transition.
			n := s.clone()
			changed := false
			for endpointID, binding := range n.EndpointBindings {
				if binding.RunID == id && !n.EndpointRevoked[endpointID] {
					n.EndpointRevoked[endpointID] = true
					changed = true
				}
			}
			if !changed {
				return nil
			}
			if e = c.casSafetyMonotone(ctx, s, n); e == nil {
				return nil
			}
			if !errors.Is(e, ErrVersionConflict) {
				return e
			}
			continue
		}
		n := s.clone()
		r.State = state
		r.TerminalAt = c.now().UTC()
		n.Runs[id] = r
		for endpointID, binding := range n.EndpointBindings {
			if binding.RunID == id {
				n.EndpointRevoked[endpointID] = true
			}
		}
		n.Events = append(n.Events, event(c.now().UTC(), eventName, r, ""))
		if e = c.casSafetyMonotone(ctx, s, n); e == nil {
			return nil
		}
		if !errors.Is(e, ErrVersionConflict) {
			return e
		}
	}
	return ErrVersionConflict
}
