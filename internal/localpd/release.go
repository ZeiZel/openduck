package localpd

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sync"
	"time"
)

var (
	ErrReleaseInput     = errors.New("local-pd release input rejected")
	ErrReleaseAuth      = errors.New("local-pd release owner authentication rejected")
	ErrReleaseStale     = errors.New("local-pd release snapshot is stale")
	ErrReleaseUsed      = errors.New("local-pd release already consumed")
	ErrReleaseUncertain = errors.New("local-pd release outcome uncertain")
	ErrReleaseRandom    = errors.New("local-pd release identity unavailable")
)

type ManualInputProvenance string

const (
	ManualKeyboardProvenance ManualInputProvenance = "owner_manual_keyboard"
	PasteProvenance          ManualInputProvenance = "paste"
	DropProvenance           ManualInputProvenance = "drop"
	AutofillProvenance       ManualInputProvenance = "autofill"
	AccessibilityProvenance  ManualInputProvenance = "accessibility"
	AppleScriptProvenance    ManualInputProvenance = "applescript"
	SyntheticProvenance      ManualInputProvenance = "synthetic"
)

type ManualReleaseInput struct {
	Bytes              []byte
	Provenance         ManualInputProvenance
	EditorID           string
	Revision           uint64
	EditorStartedBlank bool
	Prefilled          bool
	Attestation        NativeEditorAttestation
}
type NativeEditorAttestation struct {
	EditorID, EventID        string
	Revision                 uint64
	ByteDigest               string
	GenesisBlank, AppendOnly bool
	InputKind                ManualInputProvenance
}
type NativeEditorVerifier interface {
	VerifyNativeEditor(NativeEditorAttestation) bool
}
type OwnerAuthProof struct {
	Digest, AuthContextDigest, ChallengeDigest string
	At                                         time.Time
	OwnerID                                    string
}
type TrustedInputVerifier interface{ VerifyManualKeyboard(string, uint64) bool }
type OwnerAuthenticator interface {
	Authenticate(context.Context) (OwnerAuthProof, error)
}

// ReleaseLineage is compared immediately before the one-use decision CAS.
// Any source revision, policy, gate, or high-water change therefore denies.
type ReleaseLineage struct {
	ViewID, GateDigest, SessionDigest, PolicyDigest string
	HighWater, SourceVersion                        uint64
	RevisionSetDigest, CoverageDigest, ConfigDigest string
	Class                                           string
}

type CurrentReleaseState struct {
	GateDigest, SessionDigest, PolicyDigest, RevisionSetDigest, CoverageDigest, ConfigDigest string
	HighWater, SourceVersion                                                                 uint64
	Class                                                                                    string
	Complete, GapsClosed, Revoked, Deleted                                                   bool
}
type CurrentReleaseStateResolver interface {
	CurrentReleaseState(context.Context, ReleaseLineage) (CurrentReleaseState, error)
}

type ReleaseLifecycle string

const (
	ReleaseApproved  ReleaseLifecycle = "approved"
	ReleaseConsuming ReleaseLifecycle = "consuming"
	ReleaseConsumed  ReleaseLifecycle = "consumed"
	ReleaseUncertain ReleaseLifecycle = "uncertain"
)

type ReleaseReceipt struct {
	DecisionID, IdentityID, ReleasedDigest string
	State                                  ReleaseLifecycle
	IssuedAt                               time.Time
}
type ReleaseReservationStore interface {
	Reserve(string, string) error
	MarkConsumed(string, ReleaseReceipt) error
	MarkUncertain(string) error
}

// ReleaseAuthorityTransaction is the sole enabled-flow authority boundary.
// Its implementation must re-read current lineage and atomically perform
// reservation, decision consumption, identity persistence and receipt write.
type ReleaseAuthorityTransaction interface {
	Commit(context.Context, CurrentReleaseState, ReleaseLineage, DeclassificationDecision, []byte, OwnerAuthProof, PostscanAttestation) (CleanCloudIdentity, ReleaseReceipt, error)
	Reconcile(context.Context) error
}
type MemoryReleaseReservationStore struct {
	mu       sync.Mutex
	states   map[string]ReleaseLifecycle
	receipts map[string]ReleaseReceipt
}

func NewMemoryReleaseReservationStore() *MemoryReleaseReservationStore {
	return &MemoryReleaseReservationStore{states: map[string]ReleaseLifecycle{}, receipts: map[string]ReleaseReceipt{}}
}
func (s *MemoryReleaseReservationStore) Reserve(id, digest string) error {
	if id == "" || digest == "" {
		return ErrReleaseInput
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.states[id] != "" {
		return ErrReleaseUsed
	}
	s.states[id] = ReleaseConsuming
	return nil
}
func (s *MemoryReleaseReservationStore) MarkConsumed(id string, r ReleaseReceipt) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.states[id] != ReleaseConsuming || r.State != ReleaseConsumed {
		return ErrReleaseUncertain
	}
	s.states[id], s.receipts[id] = ReleaseConsumed, r
	return nil
}
func (s *MemoryReleaseReservationStore) MarkUncertain(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.states[id] != ReleaseConsuming {
		return ErrReleaseUncertain
	}
	s.states[id] = ReleaseUncertain
	return nil
}

type CleanCloudIdentity struct {
	IdentityID                                            string
	Payload                                               []byte
	Destination, Provider, RetentionDigest, PurposeDigest string
	History, Attachments, Handles, IndexLineage           []string
}

type ManualReleaseCoordinator struct {
	mu            syncMutex
	views         *LocalPDViewManager
	verifier      TrustedInputVerifier
	authority     SignatureVerifier
	auth          OwnerAuthenticator
	consumer      DeclassificationConsumer
	postscan      PostscanResolver
	used          map[string]struct{}
	stateResolver CurrentReleaseStateResolver
	store         ReleaseReservationStore
	transaction   ReleaseAuthorityTransaction
}

// syncMutex is a tiny alias to keep the coordinator's lock unexported.
type syncMutex struct{ mu chan struct{} }

func newSyncMutex() syncMutex { return syncMutex{mu: make(chan struct{}, 1)} }
func (m *syncMutex) Lock()    { m.mu <- struct{}{} }
func (m *syncMutex) Unlock()  { <-m.mu }

func NewManualReleaseCoordinator(views *LocalPDViewManager, verifier TrustedInputVerifier, authority SignatureVerifier, auth OwnerAuthenticator, postscan PostscanResolver, consumer DeclassificationConsumer) *ManualReleaseCoordinator {
	return &ManualReleaseCoordinator{mu: newSyncMutex(), views: views, verifier: verifier, authority: authority, auth: auth, postscan: postscan, consumer: consumer, used: make(map[string]struct{})}
}

func (c *ManualReleaseCoordinator) SetCurrentStateResolver(r CurrentReleaseStateResolver) {
	c.stateResolver = r
}
func (c *ManualReleaseCoordinator) SetReleaseStore(s ReleaseReservationStore) { c.store = s }
func (c *ManualReleaseCoordinator) setReleaseTransaction(t ReleaseAuthorityTransaction) {
	c.transaction = t
}

func (c *ManualReleaseCoordinator) Release(ctx context.Context, in ManualReleaseInput, d DeclassificationDecision, lineage ReleaseLineage, now time.Time) (CleanCloudIdentity, error) {
	if c == nil || c.views == nil || c.verifier == nil || c.authority == nil || c.auth == nil || c.postscan == nil || c.consumer == nil || c.stateResolver == nil || c.transaction == nil || len(in.Bytes) == 0 || len(in.Bytes) > maxQuarantinePayload || in.Provenance != ManualKeyboardProvenance || !in.EditorStartedBlank || in.Prefilled || in.EditorID == "" || in.Revision == 0 || lineage.ViewID == "" || d.MaxUses != 1 {
		return CleanCloudIdentity{}, ErrReleaseInput
	}
	if !c.verifier.VerifyManualKeyboard(in.EditorID, in.Revision) {
		return CleanCloudIdentity{}, ErrReleaseInput
	}
	if nv, ok := c.verifier.(NativeEditorVerifier); !ok || in.Attestation.EditorID != in.EditorID || in.Attestation.Revision != in.Revision || in.Attestation.EventID == "" || in.Attestation.InputKind != ManualKeyboardProvenance || !in.Attestation.GenesisBlank || !in.Attestation.AppendOnly || in.Attestation.ByteDigest != digestContent(in.Bytes) || !nv.VerifyNativeEditor(in.Attestation) {
		return CleanCloudIdentity{}, ErrReleaseInput
	}
	if err := c.views.CheckLineage(lineage.ViewID, lineage.GateDigest, lineage.SessionDigest, lineage.PolicyDigest, lineage.HighWater, lineage.SourceVersion, now); err != nil {
		return CleanCloudIdentity{}, ErrReleaseStale
	}
	if err := c.checkCurrentState(ctx, lineage); err != nil {
		return CleanCloudIdentity{}, ErrReleaseStale
	}
	proof, err := c.auth.Authenticate(ctx)
	if err != nil || proof.Digest == "" || proof.OwnerID == "" || proof.Digest != d.RecentAuthProofDigest || proof.OwnerID != d.ApproverID || proof.AuthContextDigest == "" || proof.AuthContextDigest != d.AuthContextDigest || !proof.At.UTC().Equal(proof.At) || now.Sub(proof.At) < 0 || now.Sub(proof.At) > 15*time.Minute {
		return CleanCloudIdentity{}, ErrReleaseAuth
	}
	released := digestContent(in.Bytes)
	if d.ReleasedDigest != released || d.InputDigest != released || d.CandidateDigest != released || d.SourceOrigin != "owner_manual_blank_editor" || d.CandidateOrigin != "owner_manual_blank_editor" || d.SessionBindingDigest != lineage.SessionDigest || d.PolicyDigest != lineage.PolicyDigest {
		return CleanCloudIdentity{}, ErrReleaseInput
	}
	if err := c.checkCurrentState(ctx, lineage); err != nil {
		return CleanCloudIdentity{}, ErrReleaseStale
	}
	postscan, err := c.postscan.ResolvePostscan(d.PostscanAttestationDigest)
	if err != nil || postscan.Digest != d.PostscanAttestationDigest || postscan.ReleasedDigest != released {
		return CleanCloudIdentity{}, ErrReleaseInput
	}
	state, err := c.stateResolver.CurrentReleaseState(ctx, lineage)
	if err != nil {
		return CleanCloudIdentity{}, ErrReleaseStale
	}
	identity, receipt, err := c.transaction.Commit(ctx, state, lineage, d, append([]byte(nil), in.Bytes...), proof, postscan)
	if err != nil {
		// A transaction implementation owns its terminal journal state.  Give it
		// one opportunity to poison any interrupted reservation before returning
		// no release result to the caller.
		_ = c.transaction.Reconcile(ctx)
		return CleanCloudIdentity{}, err
	}
	if err := validateCleanRelease(identity, receipt, in.Bytes, d); err != nil {
		_ = c.transaction.Reconcile(ctx)
		return CleanCloudIdentity{}, ErrReleaseUncertain
	}
	return identity, nil
}

// validateCleanRelease is deliberately narrow: a transaction may only return
// the exact owner-entered bytes and the declassification tuple.  It must not
// smuggle cloud history, attachments, handles, or index lineage across the
// local-PD boundary.
func validateCleanRelease(identity CleanCloudIdentity, receipt ReleaseReceipt, input []byte, d DeclassificationDecision) error {
	if !validID(identity.IdentityID) || !bytes.Equal(identity.Payload, input) || identity.Destination != d.DestinationRoute || identity.Provider != d.ProviderDigest || identity.RetentionDigest != d.RetentionPolicyDigest || identity.PurposeDigest != d.PurposeDigest || len(identity.History) != 0 || len(identity.Attachments) != 0 || len(identity.Handles) != 0 || len(identity.IndexLineage) != 0 || receipt.DecisionID != d.DecisionID || receipt.IdentityID != identity.IdentityID || receipt.ReleasedDigest != d.ReleasedDigest || receipt.State != ReleaseConsumed || receipt.IssuedAt.IsZero() || receipt.IssuedAt.Location() != time.UTC {
		return ErrReleaseUncertain
	}
	return nil
}

func (c *ManualReleaseCoordinator) checkCurrentState(ctx context.Context, lineage ReleaseLineage) error {
	state, err := c.stateResolver.CurrentReleaseState(ctx, lineage)
	if err != nil || state.GateDigest != lineage.GateDigest || state.SessionDigest != lineage.SessionDigest || state.PolicyDigest != lineage.PolicyDigest || state.HighWater != lineage.HighWater || state.SourceVersion != lineage.SourceVersion || state.RevisionSetDigest != lineage.RevisionSetDigest || state.CoverageDigest != lineage.CoverageDigest || state.ConfigDigest != lineage.ConfigDigest || state.Class != lineage.Class || !state.Complete || !state.GapsClosed || state.Revoked || state.Deleted {
		return ErrReleaseStale
	}
	return nil
}

func newIdentityID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return "cloud-identity/" + hex.EncodeToString(b[:]), nil
}
