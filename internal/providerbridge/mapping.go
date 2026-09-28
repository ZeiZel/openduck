package providerbridge

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// requiredMeshOperations is the complete Controller mesh surface. A pinned
// provider mapping must explicitly name every operation; omission is never an
// implicit provider-native fallback.
var requiredMeshOperations = []string{"listProfiles", "spawn", "spawnBatch", "send", "steer", "wait", "collect", "cancel", "list", "status", "result"}

// Seal calculates a mapping digest from the pinned provider protocol names.
func (m *Mapping) Seal() error {
	copy := *m
	copy.Digest = ""
	d, err := digest(copy)
	if err != nil {
		return err
	}
	m.Digest = d
	return nil
}

func (m Mapping) Validate() error {
	definition, found := definitionFor(m.ProfileID)
	if m.SchemaVersion != MappingV1 || !found || m.Provider != definition.Provider || m.ProfileRevision != definition.Revision || !validCompatibilityVersion(m.RuntimeVersion, m.Maturity) || !validCompatibilityVersion(m.ProtocolVersion, m.Maturity) || !validDigest(m.RuntimeDigest) || !validDigest(m.ProtocolDigest) || !validDigest(m.ToolSchemaDigest) || !validDigest(m.CompatibilityRecordDigest) || (m.Maturity != CompatibilitySynthetic && m.Maturity != CompatibilityPinned) || !validDigest(m.Digest) || m.EndpointAuthMode != "controller-bound-mcp.v1" || m.Cancellation != "bounded-cancel-then-quiescence" || m.Teardown != "bounded-teardown" {
		return ErrMappingMissing
	}
	copy := m
	actual := copy.Digest
	copy.Digest = ""
	expected, err := digest(copy)
	if err != nil || actual != expected {
		return ErrMappingMissing
	}
	if !validOperations(m.Operations) {
		return ErrMappingMissing
	}
	return nil
}

// OfflineMeshToolTransport is the compatibility-only subset of the
// consumer-owned MeshToolTransport contract. It never starts a real provider:
// it verifies a pinned event route through exposure, proposal, sealed spawn,
// collect, and cancel so one provider mapping cannot be substituted for
// another. Production composition must use separately attested adapters.
type OfflineMeshToolTransport interface {
	Mapping(context.Context, string) (Mapping, error)
	Attach(context.Context, EndpointBinding) (AttachedTransport, error)
	StartProvider(context.Context, AttachedTransport) (StartedTransport, error)
	ExposeTools(StartedTransport) ([]ToolExposure, error)
	Propose(StartedTransport, string, ToolProposal) (ToolProposal, error)
	Start(context.Context, StartedTransport, ToolProposal, SealedSpawn) (string, error)
	Invoke(context.Context, StartedTransport, string, string) (ToolResult, error)
	Collect(context.Context, string) (ToolResult, error)
	Cancel(context.Context, string) (ToolResult, error)
}

// PinnedAdapter is an offline fixture adapter. Its in-memory sessions only
// prove protocol compatibility; it has no executable, credentials, network,
// provider process, or model payload path.
type PinnedAdapter struct {
	mapping  Mapping
	mu       sync.Mutex
	sessions map[string]offlineSession
}

type offlineSession struct {
	profileID string
	terminal  string
}

func NewPinnedAdapter(mapping Mapping) (*PinnedAdapter, error) {
	if err := mapping.Validate(); err != nil || mapping.Maturity != CompatibilitySynthetic {
		if err == nil {
			err = ErrMappingMissing
		}
		return nil, err
	}
	return &PinnedAdapter{mapping: cloneMapping(mapping), sessions: map[string]offlineSession{}}, nil
}

func (a *PinnedAdapter) Mapping(ctx context.Context, profileID string) (Mapping, error) {
	if err := ctx.Err(); err != nil {
		return Mapping{}, err
	}
	if a == nil || profileID != a.mapping.ProfileID {
		return Mapping{}, ErrMappingMissing
	}
	return cloneMapping(a.mapping), nil
}

func (a *PinnedAdapter) Attach(ctx context.Context, binding EndpointBinding) (AttachedTransport, error) {
	if err := ctx.Err(); err != nil {
		return AttachedTransport{}, err
	}
	if a == nil || binding.BindingID == "" || binding.ProfileID != a.mapping.ProfileID || binding.Audience != "mesh" || binding.PeerID == "" || binding.ExpiresAt.IsZero() || !binding.ExpiresAt.After(time.Now().UTC()) {
		return AttachedTransport{}, ErrBindingInvalid
	}
	proof, err := attachmentProof(a.mapping.ProfileID, a.mapping.Digest, binding.BindingID)
	if err != nil {
		return AttachedTransport{}, ErrBindingInvalid
	}
	return AttachedTransport{ProfileID: a.mapping.ProfileID, Mapping: cloneMapping(a.mapping), BindingID: binding.BindingID, proof: proof}, nil
}

// OperationForRequestEvent converts a pinned provider-native tool event into a
// Controller mesh operation name. It accepts no payload and cannot dispatch a
// provider request, which keeps the adapter suitable for offline replay.
func (a *PinnedAdapter) OperationForRequestEvent(requestEvent string) (string, error) {
	if a == nil || requestEvent == "" {
		return "", ErrMappingMissing
	}
	for _, operation := range a.mapping.Operations {
		if operation.RequestEvent == requestEvent {
			return operation.Operation, nil
		}
	}
	return "", ErrMappingMissing
}

// StartProvider is a synthetic, keyless fixture acknowledgement. It
// intentionally cannot launch any runtime or establish compatibility.
func (a *PinnedAdapter) StartProvider(ctx context.Context, attached AttachedTransport) (StartedTransport, error) {
	if err := ctx.Err(); err != nil {
		return StartedTransport{}, err
	}
	if err := a.validateAttachment(attached); err != nil {
		return StartedTransport{}, err
	}
	proof, err := digest(struct {
		BindingID string
		Proof     string
	}{attached.BindingID, attached.proof})
	if err != nil {
		return StartedTransport{}, ErrBindingInvalid
	}
	return StartedTransport{ProfileID: attached.ProfileID, BindingID: attached.BindingID, attached: attached, proof: proof}, nil
}

// ExposeTools returns only the pinned tool names for the already attached
// endpoint. It cannot expose ambient/native provider tools.
func (a *PinnedAdapter) ExposeTools(started StartedTransport) ([]ToolExposure, error) {
	if err := a.validateStarted(started); err != nil {
		return nil, err
	}
	tools := make([]ToolExposure, 0, len(a.mapping.Operations))
	for _, operation := range a.mapping.Operations {
		tools = append(tools, ToolExposure{Operation: operation.Operation, RequestEvent: operation.RequestEvent, ResultEvent: operation.ResultEvent, CancelEvent: operation.CancelEvent})
	}
	return tools, nil
}

// Propose converts one exact provider-native spawn/spawnBatch tool event into
// a bounded, unsealed Controller proposal. A provider cannot inject a sealed
// Controller dispatch at this boundary.
func (a *PinnedAdapter) Propose(started StartedTransport, requestEvent string, proposal ToolProposal) (ToolProposal, error) {
	if err := a.validateStarted(started); err != nil {
		return ToolProposal{}, err
	}
	if proposal.SchemaVersion != ToolProposalV1 || proposal.ProfileID != a.mapping.ProfileID || proposal.MappingDigest != a.mapping.Digest || (proposal.Operation != "spawn" && proposal.Operation != "spawnBatch") || proposal.ClientNonce == "" || proposal.Objective == "" || proposal.RequestedRole == "" || proposal.OutputSchema == "" || proposal.Digest != "" {
		return ToolProposal{}, ErrMappingMissing
	}
	operation, err := a.OperationForRequestEvent(requestEvent)
	if err != nil || operation != proposal.Operation {
		return ToolProposal{}, ErrMappingMissing
	}
	if err := proposal.Seal(); err != nil {
		return ToolProposal{}, err
	}
	return proposal, nil
}

func (p *ToolProposal) Seal() error {
	copy := *p
	copy.Digest = ""
	d, err := digest(copy)
	if err != nil {
		return err
	}
	p.Digest = d
	return nil
}

func (p ToolProposal) validFor(mapping Mapping) bool {
	if p.SchemaVersion != ToolProposalV1 || p.ProfileID != mapping.ProfileID || p.MappingDigest != mapping.Digest || (p.Operation != "spawn" && p.Operation != "spawnBatch") || p.ClientNonce == "" || p.Objective == "" || p.RequestedRole == "" || p.OutputSchema == "" || !validDigest(p.Digest) {
		return false
	}
	copy := p
	actual := copy.Digest
	copy.Digest = ""
	expected, err := digest(copy)
	return err == nil && actual == expected
}

// Start accepts only a Controller-shaped sealed fixture bound to the exact
// proposal and endpoint. The resulting synthetic session contains no model or
// provider state and is kept solely for collect/cancel compatibility checks.
func (a *PinnedAdapter) Start(ctx context.Context, started StartedTransport, proposal ToolProposal, sealed SealedSpawn) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if err := a.validateStarted(started); err != nil || proposal.Operation != "spawn" || !proposal.validFor(a.mapping) || !sealed.validFor(proposal, started.BindingID) {
		return "", ErrMappingMissing
	}
	sessionID, err := fixtureSessionID(a.mapping.ProfileID, proposal.Digest, sealed.SealDigest)
	if err != nil {
		return "", fmt.Errorf("fixture session id: %w", err)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, found := a.sessions[sessionID]; !found {
		a.sessions[sessionID] = offlineSession{profileID: a.mapping.ProfileID, terminal: "running"}
	}
	return sessionID, nil
}

// Invoke proves the pinned request/result/cancel event mapping for every
// non-spawn mesh operation. It returns a typed mapping error for an unknown
// event or an operation that has no live synthetic session; it never attempts
// a provider-native fallback.
func (a *PinnedAdapter) Invoke(ctx context.Context, started StartedTransport, sessionID, requestEvent string) (ToolResult, error) {
	if err := ctx.Err(); err != nil {
		return ToolResult{}, err
	}
	if err := a.validateStarted(started); err != nil {
		return ToolResult{}, err
	}
	operationName, err := a.OperationForRequestEvent(requestEvent)
	if err != nil {
		return ToolResult{}, ErrMappingMissing
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	session, found := a.sessions[sessionID]
	if !found || session.profileID != a.mapping.ProfileID || session.terminal != "running" {
		return ToolResult{}, ErrMappingMissing
	}
	operation, found := mappingOperation(a.mapping, operationName)
	if !found || operation.RequestEvent != requestEvent {
		return ToolResult{}, ErrMappingMissing
	}
	if operationName == "cancel" {
		session.terminal = "cancelled"
		a.sessions[sessionID] = session
	}
	return ToolResult{SessionID: sessionID, Operation: operationName, ResultEvent: operation.ResultEvent, Terminal: session.terminal}, nil
}

func (a *PinnedAdapter) Collect(ctx context.Context, sessionID string) (ToolResult, error) {
	if err := ctx.Err(); err != nil {
		return ToolResult{}, err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	session, found := a.sessions[sessionID]
	if !found || session.profileID != a.mapping.ProfileID {
		return ToolResult{}, ErrMappingMissing
	}
	if session.terminal == "running" {
		session.terminal = "completed"
		a.sessions[sessionID] = session
	}
	operation, _ := mappingOperation(a.mapping, "collect")
	return ToolResult{SessionID: sessionID, Operation: "collect", ResultEvent: operation.ResultEvent, Terminal: session.terminal}, nil
}

func (a *PinnedAdapter) Cancel(ctx context.Context, sessionID string) (ToolResult, error) {
	if err := ctx.Err(); err != nil {
		return ToolResult{}, err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	session, found := a.sessions[sessionID]
	if !found || session.profileID != a.mapping.ProfileID || session.terminal != "running" {
		return ToolResult{}, ErrMappingMissing
	}
	session.terminal = "cancelled"
	a.sessions[sessionID] = session
	operation, _ := mappingOperation(a.mapping, "cancel")
	return ToolResult{SessionID: sessionID, Operation: "cancel", ResultEvent: operation.ResultEvent, Terminal: session.terminal}, nil
}

func (a *PinnedAdapter) validateAttachment(attached AttachedTransport) error {
	if a == nil || attached.ProfileID != a.mapping.ProfileID || attached.Mapping.Digest != a.mapping.Digest || attached.BindingID == "" {
		return ErrBindingInvalid
	}
	proof, err := attachmentProof(a.mapping.ProfileID, a.mapping.Digest, attached.BindingID)
	if err != nil || attached.proof != proof || attached.Mapping.Validate() != nil {
		return ErrBindingInvalid
	}
	return nil
}

func (a *PinnedAdapter) validateStarted(started StartedTransport) error {
	if a == nil || started.ProfileID != a.mapping.ProfileID || started.BindingID == "" || a.validateAttachment(started.attached) != nil || started.attached.BindingID != started.BindingID {
		return ErrBindingInvalid
	}
	proof, err := digest(struct {
		BindingID string
		Proof     string
	}{started.BindingID, started.attached.proof})
	if err != nil || proof != started.proof {
		return ErrBindingInvalid
	}
	return nil
}

func (s SealedSpawn) validFor(proposal ToolProposal, bindingID string) bool {
	if s.SchemaVersion != SealedSpawnV1 || s.ProfileID != proposal.ProfileID || s.MappingDigest != proposal.MappingDigest || s.ProposalDigest != proposal.Digest || s.BindingID != bindingID || !validDigest(s.SealDigest) {
		return false
	}
	copy := s
	actual := copy.SealDigest
	copy.SealDigest = ""
	expected, err := digest(copy)
	return err == nil && actual == expected
}

// sealOfflineFixture is deliberately unexported: production callers must use
// the Controller sealer, while package tests can prove the compatibility route.
func sealOfflineFixture(proposal ToolProposal, bindingID string) (SealedSpawn, error) {
	sealed := SealedSpawn{SchemaVersion: SealedSpawnV1, ProfileID: proposal.ProfileID, MappingDigest: proposal.MappingDigest, ProposalDigest: proposal.Digest, BindingID: bindingID}
	d, err := digest(sealed)
	if err != nil {
		return SealedSpawn{}, err
	}
	sealed.SealDigest = d
	return sealed, nil
}

func attachmentProof(profileID, mappingDigest, bindingID string) (string, error) {
	return digest(struct {
		ProfileID     string
		MappingDigest string
		BindingID     string
	}{profileID, mappingDigest, bindingID})
}

func fixtureSessionID(profileID, proposalDigest, sealDigest string) (string, error) {
	return digest(struct {
		ProfileID      string
		ProposalDigest string
		SealDigest     string
	}{profileID, proposalDigest, sealDigest})
}

func mappingOperation(mapping Mapping, name string) (OperationMapping, bool) {
	for _, operation := range mapping.Operations {
		if operation.Operation == name {
			return operation, true
		}
	}
	return OperationMapping{}, false
}

func cloneMapping(value Mapping) Mapping {
	value.Operations = append([]OperationMapping(nil), value.Operations...)
	return value
}
