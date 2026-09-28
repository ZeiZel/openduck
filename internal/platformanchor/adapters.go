package platformanchor

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"

	"openduck/internal/admission"
	"openduck/internal/codexruntime"
	"openduck/internal/platformcheckpoint"
)

type Adapter struct {
	client    *Client
	namespace string
}

func NewAdapter(client *Client, namespace string) (*Adapter, error) {
	if client == nil || !validNamespace(namespace) {
		return nil, ErrUnavailable
	}
	return &Adapter{client: client, namespace: namespace}, nil
}
func (a *Adapter) requestID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("%w: entropy", ErrUnavailable)
	}
	return "req_" + hex.EncodeToString(b[:]), nil
}
func (a *Adapter) Load(key string) (uint64, string, error) {
	id, err := a.requestID()
	if err != nil {
		return 0, "", err
	}
	r, err := a.client.Do(contextless(), Request{SchemaVersion: SchemaVersion, RequestID: id, Namespace: a.namespace, Operation: "load", Key: key})
	if err != nil {
		return 0, "", err
	}
	return r.Version, r.Digest, nil
}
func (a *Adapter) CAS(key string, expected, next uint64, digest string) error {
	id, err := a.requestID()
	if err != nil {
		return err
	}
	_, err = a.client.Do(contextless(), Request{SchemaVersion: SchemaVersion, RequestID: id, Namespace: a.namespace, Operation: "cas", Key: key, ExpectedVersion: expected, NextVersion: next, Digest: digest})
	return err
}
func (a *Adapter) CASRetry(key string, expected, next uint64, digest string) error {
	id, err := a.requestID()
	if err != nil {
		return err
	}
	r := Request{SchemaVersion: SchemaVersion, RequestID: id, Namespace: a.namespace, Operation: "cas", Key: key, ExpectedVersion: expected, NextVersion: next, Digest: digest}
	for attempt := 0; attempt < 2; attempt++ {
		_, err := a.client.Do(contextless(), r)
		if err == nil {
			return nil
		}
		if !errors.Is(err, ErrUncertain) {
			return err
		}
	}
	return ErrUncertain
}
func (a *Adapter) CASRetryWithRequestID(requestID, key string, expected, next uint64, digest string) error {
	if requestID == "" {
		return ErrUnavailable
	}
	r := Request{SchemaVersion: SchemaVersion, RequestID: requestID, Namespace: a.namespace, Operation: "cas", Key: key, ExpectedVersion: expected, NextVersion: next, Digest: digest}
	for attempt := 0; attempt < 2; attempt++ {
		_, err := a.client.Do(contextless(), r)
		if err == nil {
			return nil
		}
		if !errors.Is(err, ErrUncertain) {
			return err
		}
	}
	return ErrUncertain
}

type admissionAdapter struct{ a *Adapter }

func NewAdmissionCheckpoint(client *Client) (admission.CheckpointStore, error) {
	a, err := NewAdapter(client, NamespaceAdmission)
	if err != nil {
		return nil, err
	}
	return &admissionAdapter{a: a}, nil
}
func (a *admissionAdapter) LoadCheckpoint() (admission.LedgerCheckpoint, error) {
	v, d, e := a.a.Load("ledger")
	return admission.LedgerCheckpoint{Version: v, StateDigest: d}, e
}
func (a *admissionAdapter) CommitCheckpoint(expected uint64, next admission.LedgerCheckpoint) error {
	return a.a.CASRetry("ledger", expected, next.Version, next.StateDigest)
}

type chatAdapter struct{ a *Adapter }

func NewChatLedgerCheckpoint(client *Client) (codexruntime.ChatLedgerCheckpoint, error) {
	a, err := NewAdapter(client, NamespaceChat)
	if err != nil {
		return nil, err
	}
	return &chatAdapter{a: a}, nil
}

// CompareAndSwapDigest binds the durable checkpoint to the caller-owned
// ledger/result digest.
func (a *chatAdapter) CompareAndSwapDigest(requestID, id string, expected, next uint64, digest string) error {
	return a.a.CASRetryWithRequestID(requestID, id, expected, next, digest)
}

// productionAdapter is intentionally distinct from Adapter. It can only be
// constructed from the sealed authenticated ProductionClient and carries the
// unexported production markers required by downstream constructors.
type productionAdapter struct {
	client    *ProductionClient
	namespace string
}

func (a *productionAdapter) requestID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("%w: entropy", ErrUnavailable)
	}
	return "req_" + hex.EncodeToString(b[:]), nil
}
func (a *productionAdapter) load(ctx context.Context, key string) (uint64, string, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	id, err := a.requestID()
	if err != nil {
		return 0, "", err
	}
	r, err := a.client.Do(ctx, Request{SchemaVersion: SchemaVersion, RequestID: id, Namespace: a.namespace, Operation: "load", Key: key})
	if err != nil {
		return 0, "", err
	}
	return r.Version, r.Digest, nil
}
func (a *productionAdapter) cas(requestID, key string, expected, next uint64, digest string) error {
	if requestID == "" {
		return ErrUnavailable
	}
	_, err := a.client.Do(context.Background(), Request{SchemaVersion: SchemaVersion, RequestID: requestID, Namespace: a.namespace, Operation: "cas", Key: key, ExpectedVersion: expected, NextVersion: next, Digest: digest})
	return err
}
func (a *productionAdapter) casRetry(requestID, key string, expected, next uint64, digest string) error {
	for attempt := 0; attempt < 2; attempt++ {
		err := a.cas(requestID, key, expected, next, digest)
		if err == nil || !errors.Is(err, ErrUncertain) {
			return err
		}
	}
	return ErrUncertain
}

func deterministicCASRequestID(namespace string, expected, next uint64, digest string) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s:%d:%d:%s", namespace, expected, next, digest)))
	return namespace + "_" + hex.EncodeToString(sum[:16])
}
func (a *productionAdapter) attestedAnchorCheckpoint() {}

func (a *productionAdapter) Load() (uint64, string, error) {
	return a.load(context.Background(), "checkpoint")
}

func (a *productionAdapter) Commit(expected, next uint64, digest string) error {
	// The request ID is stable across a lost reply and process restart. The
	// anchor service persists this ID before acknowledging the CAS.
	requestID := deterministicCASRequestID("anchor", expected, next, digest)
	return a.casRetry(requestID, "checkpoint", expected, next, digest)
}

func NewProductionAnchorCheckpoint(client *platformcheckpoint.ProductionClient) (*ProductionAnchorCheckpoint, error) {
	if client == nil || !client.Valid() {
		return nil, ErrProductionSealed
	}
	return &ProductionAnchorCheckpoint{client: client}, nil
}

// ProductionAdmissionCheckpoint is an opaque admission checkpoint capability.
// Its fields are private and the only production constructor requires an
// authenticated anchor ProductionClient.
type ProductionAdmissionCheckpoint struct{ a *productionAdapter }

// Valid reports whether the handle carries a live, authenticated anchor
// client. Zero and synthetic values are intentionally invalid.
func (a *ProductionAdmissionCheckpoint) Valid() bool {
	return a != nil && a.a != nil && a.a.client != nil && a.a.client.valid()
}

func NewProductionAdmissionCheckpoint(client *ProductionClient) (*ProductionAdmissionCheckpoint, error) {
	if !client.valid() {
		return nil, ErrProductionSealed
	}
	return &ProductionAdmissionCheckpoint{a: &productionAdapter{client: client, namespace: NamespaceAdmission}}, nil
}

func (a *ProductionAdmissionCheckpoint) LoadCheckpoint() (admission.LedgerCheckpoint, error) {
	return a.LoadCheckpointContext(context.Background())
}

// LoadCheckpointContext is the production startup probe. It preserves the
// caller's cancellation/deadline through authenticated dial and RPC.
func (a *ProductionAdmissionCheckpoint) LoadCheckpointContext(ctx context.Context) (admission.LedgerCheckpoint, error) {
	if a == nil || a.a == nil {
		return admission.LedgerCheckpoint{}, ErrProductionSealed
	}
	v, d, err := a.a.load(ctx, "ledger")
	return admission.LedgerCheckpoint{Version: v, StateDigest: d}, err
}
func (a *ProductionAdmissionCheckpoint) CommitCheckpoint(expected uint64, next admission.LedgerCheckpoint) error {
	if a == nil || a.a == nil {
		return ErrProductionSealed
	}
	return a.a.casRetry(deterministicCASRequestID("admission", expected, next.Version, next.StateDigest), "ledger", expected, next.Version, next.StateDigest)
}

// newProductionAdmissionCheckpointForTest is deliberately package-private;
// it exists only for deterministic transport tests and cannot be called by a
// production composition package.
func newProductionAdmissionCheckpointForTest(client *ProductionClient) *ProductionAdmissionCheckpoint {
	if client == nil {
		return nil
	}
	return &ProductionAdmissionCheckpoint{a: &productionAdapter{client: client, namespace: NamespaceAdmission}}
}

// ProductionChatCheckpoint is an opaque production chat-ledger capability.
// It is issued only by an authenticated platformanchor ProductionClient.
type ProductionChatCheckpoint struct{ a *productionAdapter }

func (a *ProductionChatCheckpoint) Valid() bool {
	return a != nil && a.a != nil && a.a.client != nil && a.a.client.valid()
}

func (a *ProductionChatCheckpoint) CompareAndSwapDigest(requestID, id string, expected, next uint64, digest string) error {
	if !a.Valid() {
		return ErrProductionSealed
	}
	return a.a.casRetry(requestID, id, expected, next, digest)
}

func NewProductionChatLedgerCheckpoint(client *ProductionClient) (*ProductionChatCheckpoint, error) {
	if !client.valid() {
		return nil, ErrProductionSealed
	}
	return &ProductionChatCheckpoint{a: &productionAdapter{client: client, namespace: NamespaceChat}}, nil
}

// NewProductionEncryptedChatRunLedger is kept in platformanchor to avoid a
// dependency cycle: the opaque capability is minted here, while the generic
// ledger remains provider-free in codexruntime.
func NewProductionEncryptedChatRunLedger(path string, key []byte, checkpoint *ProductionChatCheckpoint) (*codexruntime.ChatRunLedger, error) {
	if !checkpoint.Valid() {
		return nil, ErrProductionSealed
	}
	return codexruntime.NewEncryptedChatRunLedgerWithCheckpoint(path, key, checkpoint)
}

// contextless is intentionally tiny: adapter calls are synchronous and the
// caller's context is not part of the pre-existing checkpoint interfaces.
func contextless() context.Context { return context.Background() }
