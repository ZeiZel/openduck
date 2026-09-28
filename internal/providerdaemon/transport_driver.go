package providerdaemon

// This file is the only package-level connection from the durable daemon
// receipt store to providertransport.  It converts one already authenticated
// transport request into a second, daemon-local operation identity while
// retaining the original wire identity verbatim.  In particular, the daemon
// RequestDigest is never passed off as the transport RequestDigest (or vice
// versa), which makes changed-digest replay and recovery substitutions fail
// closed.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"openduck/internal/mesh"
	"openduck/internal/providertransport"
)

const transportDriverRevision = "providerdaemon-receipts-v2"

// TransportDriver implements providertransport's narrow runtime seams.  It
// owns no listener, credentials, account state, task payload, or raw Store
// access.  Core remains the sole persistence and authorization boundary.
type TransportDriver struct{ core *Core }

func NewTransportDriver(core *Core) (*TransportDriver, error) {
	if core == nil || core.verified == nil || core.store == nil || core.authorizer == nil {
		return nil, ErrDisabled
	}
	return &TransportDriver{core: core}, nil
}

func (d *TransportDriver) Recover(ctx context.Context) (providertransport.RecoveryProof, error) {
	if d == nil || d.core == nil || ctx == nil || ctx.Err() != nil {
		return providertransport.RecoveryProof{}, providertransport.ErrReconcile
	}
	// An ambiguous durable receipt is reconciled through Bridge.Reconcile only;
	// this path never calls Start and therefore can never duplicate native work.
	for _, receipt := range d.core.store.Snapshot() {
		switch receipt.State {
		case Starting, Uncertain:
			resolved, err := d.core.Reconcile(ctx, receipt.ID)
			if err != nil || (resolved.State != Running && resolved.State != Terminal) {
				return providertransport.RecoveryProof{}, providertransport.ErrReconcile
			}
		case Running, Terminal, Compensating:
			// Running is projected by RecoverSession; Terminal is inert; a
			// Compensating receipt remains fail-closed until a later explicit
			// lifecycle teardown succeeds.
			if receipt.State == Compensating {
				return providertransport.RecoveryProof{}, providertransport.ErrReconcile
			}
		default:
			return providertransport.RecoveryProof{}, providertransport.ErrReconcile
		}
	}
	return providertransport.RecoveryProof{SchemaVersion: providertransport.RecoveryProofV1, ReceiptStoreRevision: d.core.receiptStoreRevision(), RequestIDRetention: true, BindingDigestRetention: true, InflightReconciled: true}, nil
}

func (d *TransportDriver) Start(ctx context.Context, start providertransport.RuntimeStart) (providertransport.RuntimeSession, error) {
	req, err := d.requestFromStart(start)
	if err != nil {
		return providertransport.RuntimeSession{}, providertransport.ErrDenied
	}
	receipt, err := d.core.Start(ctx, req)
	if err != nil || receipt.State != Running || !safeOpaque(receipt.Session, maxOpaqueBytes) {
		return providertransport.RuntimeSession{}, mapDriverError(err)
	}
	return providertransport.RuntimeSession{ID: receipt.Session}, nil
}

func (d *TransportDriver) Send(ctx context.Context, session providertransport.RuntimeSession, inputRef string) error {
	id, err := d.receiptIDForSession(session.ID)
	if err != nil {
		return err
	}
	return mapDriverError(d.core.Send(ctx, id, inputRef))
}
func (d *TransportDriver) Steer(ctx context.Context, session providertransport.RuntimeSession, inputRef string) error {
	id, err := d.receiptIDForSession(session.ID)
	if err != nil {
		return err
	}
	return mapDriverError(d.core.Steer(ctx, id, inputRef))
}
func (d *TransportDriver) Cancel(ctx context.Context, session providertransport.RuntimeSession, cancel mesh.Cancellation) error {
	if cancel.Validate() != nil {
		return providertransport.ErrDenied
	}
	id, err := d.receiptIDForSession(session.ID)
	if err != nil {
		return err
	}
	return mapDriverError(d.core.Cancel(ctx, id, cancel.Mode, cancel.RevisionRef, cancel.ReasonRef))
}
func (d *TransportDriver) Status(ctx context.Context, session providertransport.RuntimeSession) (providertransport.RuntimeStatus, error) {
	id, err := d.receiptIDForSession(session.ID)
	if err != nil {
		return providertransport.RuntimeStatus{}, err
	}
	v, err := d.core.Status(ctx, id)
	if err != nil {
		return providertransport.RuntimeStatus{}, mapDriverError(err)
	}
	return providertransport.RuntimeStatus{State: v.State, UsageSource: v.UsageSource}, nil
}
func (d *TransportDriver) Wait(ctx context.Context, session providertransport.RuntimeSession, deadline time.Time) (providertransport.RuntimeStatus, error) {
	id, err := d.receiptIDForSession(session.ID)
	if err != nil {
		return providertransport.RuntimeStatus{}, err
	}
	v, err := d.core.Wait(ctx, id, deadline)
	if err != nil {
		return providertransport.RuntimeStatus{}, mapDriverError(err)
	}
	return providertransport.RuntimeStatus{State: v.State, UsageSource: v.UsageSource}, nil
}
func (d *TransportDriver) Result(ctx context.Context, session providertransport.RuntimeSession, revisionRef string) (providertransport.RuntimeResult, error) {
	id, err := d.receiptIDForSession(session.ID)
	if err != nil {
		return providertransport.RuntimeResult{}, err
	}
	v, err := d.core.Result(ctx, id, revisionRef)
	if err != nil {
		return providertransport.RuntimeResult{}, mapDriverError(err)
	}
	return providertransport.RuntimeResult{Status: v.Status, OutputArtifactRef: v.OutputArtifactRef, SchemaRef: v.SchemaRef, ProvenanceDigest: v.ProvenanceDigest, Classification: v.Classification}, nil
}

// RecoverSession returns the complete identity proof that providertransport
// compares against Controller persistence. It is intentionally impossible to
// manufacture a proof from a native session ID alone.
func (d *TransportDriver) RecoverSession(ctx context.Context, routeRef string) (providertransport.PersistedSessionProof, error) {
	if d == nil || d.core == nil || ctx == nil || ctx.Err() != nil || !safeOpaque(routeRef, maxIDBytes) {
		return providertransport.PersistedSessionProof{}, providertransport.ErrReconcile
	}
	for _, receipt := range d.core.store.Snapshot() {
		if receipt.State != Running || !receipt.Identity.hasTransportBinding() || receipt.Identity.Binding != receipt.Identity.BindingHash {
			continue
		}
		if routeFor(receipt.Identity.Profile, receipt.Identity.BindingID, receipt.Identity.BindingHash) != routeRef {
			continue
		}
		// The exact receipt still requires a reconciliation authorization fence
		// before being returned as a fresh-daemon routing proof. The Core method
		// provides that fence without starting native work.
		checked, err := d.core.lookupAndAuthorize(ctx, receipt.ID, AuthorizeReconcile)
		if err != nil || checked != receipt || checked.State != Running {
			return providertransport.PersistedSessionProof{}, providertransport.ErrReconcile
		}
		return providertransport.PersistedSessionProof{
			SchemaVersion: providertransport.PersistedSessionProofV1,
			RouteRef:      routeRef, NativeSessionID: receipt.Session,
			ProfileID: receipt.Identity.Profile, ProfileRevision: receipt.Identity.Revision,
			MappingDigest: receipt.Identity.Mapping, RuntimeDigest: receipt.Identity.Runtime, ProtocolDigest: receipt.Identity.Protocol,
			OrderID: receipt.Identity.Order, OrderHash: receipt.Identity.OrderHash,
			BindingID: receipt.Identity.BindingID, BindingHash: receipt.Identity.BindingHash,
			RunID: receipt.Identity.Run, AttemptID: receipt.Identity.Attempt,
			RequestID: receipt.Identity.WireRequest, RequestDigest: receipt.Identity.WireDigest, State: "running",
		}, nil
	}
	return providertransport.PersistedSessionProof{}, providertransport.ErrReconcile
}

func (d *TransportDriver) requestFromStart(s providertransport.RuntimeStart) (Request, error) {
	if d == nil || d.core == nil || s.RequestID == "" || !validDigest(s.RequestDigest) || !safeOpaque(s.OrderID, maxIDBytes) || !safeOpaque(s.OrderHash, maxIDBytes) || !safeOpaque(s.BindingID, maxIDBytes) || !validDigest(s.BindingHash) || !safeOpaque(s.RunID, maxIDBytes) || !safeOpaque(s.AttemptID, maxIDBytes) || s.Deadline.IsZero() || !s.Deadline.Equal(s.Deadline.UTC()) {
		return Request{}, ErrConflict
	}
	identity := d.core.verified.proof.StaticIdentity
	if identity.Profile != s.ProfileID || identity.Revision != s.ProfileRevision || identity.Mapping != s.MappingDigest || identity.Runtime != s.RuntimeDigest || identity.Protocol != s.ProtocolDigest {
		return Request{}, ErrConflict
	}
	identity.Route = d.core.descriptor.Provider
	identity.Binding = s.BindingHash
	identity.WireRequest, identity.WireDigest = s.RequestID, s.RequestDigest
	identity.Order, identity.OrderHash = s.OrderID, s.OrderHash
	identity.BindingID, identity.BindingHash = s.BindingID, s.BindingHash
	identity.Run, identity.Attempt = s.RunID, s.AttemptID
	req := Request{ID: s.RequestID, Identity: identity, ExpiresAt: s.Deadline}
	req.Identity.Request = RequestDigest(req)
	if !validIdentity(req.Identity) {
		return Request{}, ErrConflict
	}
	return req, nil
}

func (d *TransportDriver) receiptIDForSession(sessionID string) (string, error) {
	if d == nil || d.core == nil || !safeOpaque(sessionID, maxOpaqueBytes) {
		return "", providertransport.ErrReconcile
	}
	var found string
	for _, receipt := range d.core.store.Snapshot() {
		if receipt.Session != sessionID {
			continue
		}
		if found != "" || receipt.State != Running || !receipt.Identity.hasTransportBinding() {
			return "", providertransport.ErrReconcile
		}
		found = receipt.ID
	}
	if found == "" {
		return "", providertransport.ErrReconcile
	}
	return found, nil
}

func (c *Core) receiptStoreRevision() string {
	if c == nil || c.store == nil {
		return ""
	}
	c.store.mu.Lock()
	defer c.store.mu.Unlock()
	if c.store.closed || c.store.poisoned {
		return ""
	}
	return fmt.Sprintf("%s-%d", transportDriverRevision, c.store.generation)
}

func routeFor(profile, bindingID, bindingHash string) string {
	sum := sha256.Sum256([]byte(profile + ":" + bindingID + ":" + bindingHash))
	return "ptv2-" + profile + "-" + hex.EncodeToString(sum[:])
}

func mapDriverError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, ErrConflict) || errors.Is(err, ErrExpired) || errors.Is(err, ErrDisabled) {
		return providertransport.ErrDenied
	}
	return providertransport.ErrReconcile
}

var _ providertransport.RuntimeDriver = (*TransportDriver)(nil)
var _ providertransport.PersistedSessionRecoveryDriver = (*TransportDriver)(nil)
