package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"path/filepath"
	"time"

	"openduck/internal/dshbridge"
	"openduck/internal/macosattest"
	"openduck/internal/mesh"
	"openduck/internal/meshui"
	"openduck/internal/providerbridge"
	"openduck/internal/providerrevision"
)

const (
	providerBundleLeaf       = "provider-bundle.json"
	providerTrustLeaf        = "provider-trust.json"
	providerOperationLeaf    = "provider-lifecycle-operation.json"
	controllerOwnerTrustLeaf = "controller-owner-ed25519.json"
)

type providerCompositionOptions struct {
	Root, BundleDigest, TrustDigest, OwnerTrustDigest string
	OwnerUID, OwnerGID                                uint32
}

// verifiedMeshComposition is the single production mesh assembly. It owns one
// revision service, one transport router/Coordinator and one MeshUI source;
// callers must close it before releasing the state repository or transport.
type verifiedMeshComposition struct {
	app          *meshApplication
	dispatcher   *providerrevision.Dispatcher
	registration *providerrevision.UIRegistration
	close        func()
}

func newVerifiedMeshComposition(ctx context.Context, meshRepo mesh.Repository, revisionRepo *providerrevision.Repository, composition providerCompositionOptions, transport providerTransportOptions) (*verifiedMeshComposition, error) {
	if ctx == nil || meshRepo == nil || revisionRepo == nil || !composition.valid() || !transport.valid() {
		return nil, errors.New("verified mesh composition unavailable")
	}
	service, dispatcher, err := configuredRevisionService(revisionRepo, composition)
	if err != nil {
		return nil, err
	}
	operation, present, err := dispatcher.ReadPending(ctx)
	if err != nil {
		return nil, err
	}
	deferredUI := present && (operation.Action == "ui-register" || operation.Action == "ui-bind" || operation.Action == "ui-revoke" || operation.Action == "ui-rotate" || operation.Action == "root-close")
	if present && !deferredUI {
		if _, _, err = dispatcher.Dispatch(ctx); err != nil {
			return nil, err
		}
	}
	registry, installed, err := activeProviderRegistry(ctx, service)
	if err != nil {
		return nil, err
	}
	if !configuredTransportRequired(installed) {
		return nil, errors.New("verified mesh has no enabled provider route")
	}
	descriptors, dial, closeTransport, err := openConfiguredProviderTransport(transport, composition, installed, defaultProviderTransportDependencies())
	if err != nil {
		return nil, err
	}
	coordinator, err := newTransportMeshCoordinator(meshRepo, registry, installed, descriptors, dial, time.Now().UTC())
	if err != nil {
		closeTransport()
		return nil, err
	}
	if err = recoverConfiguredMesh(ctx, coordinator, closeTransport); err != nil {
		return nil, err
	}
	app := &meshApplication{coordinator: coordinator, revisions: service}
	if deferredUI {
		dispatcher.RegisterUIRoot = app.registerUIRoot
		dispatcher.VerifyUIBinding = app.verifyUIBinding
		dispatcher.RevokeUIEndpoint = app.revokeUIEndpoint
		dispatcher.RotateUIEndpoint = app.rotateUIEndpoint
		dispatcher.CloseRootEndpoint = app.closeRootEndpoint
		if _, _, err = dispatcher.Dispatch(ctx); err != nil {
			closeTransport()
			return nil, err
		}
		if operation.Action == "ui-register" {
			registration, registrationErr := service.Registration(ctx, operation.SessionID, operation.ChannelID)
			if registrationErr != nil || registration.RequestDigest != operation.Digest {
				closeTransport()
				return nil, errors.New("ui registration unavailable")
			}
			return &verifiedMeshComposition{app: app, dispatcher: dispatcher, registration: &registration, close: closeTransport}, nil
		}
	}
	return &verifiedMeshComposition{app: app, dispatcher: dispatcher, close: closeTransport}, nil
}

func (o providerCompositionOptions) configured() bool {
	return o.Root != "" && o.BundleDigest != "" && o.TrustDigest != "" && o.OwnerTrustDigest != ""
}
func (o providerCompositionOptions) valid() bool {
	return o.configured() && filepath.IsAbs(o.Root) && filepath.Clean(o.Root) == o.Root
}
func configuredRevisionService(repo *providerrevision.Repository, options providerCompositionOptions) (*providerrevision.Service, *providerrevision.Dispatcher, error) {
	if !options.valid() {
		return nil, nil, errors.New("provider composition incomplete")
	}
	trust := providerrevision.ArtifactTrustSource{RootPath: options.Root, TrustLeaf: providerTrustLeaf, ExpectedDigest: options.TrustDigest, OwnerUID: options.OwnerUID, OwnerGID: options.OwnerGID}
	service, err := providerrevision.NewService(repo, denyRevisionAuthority{}, trust)
	if err != nil {
		return nil, nil, err
	}
	dispatcher := &providerrevision.Dispatcher{Service: service, Bundle: providerrevision.LoadConfig{RootPath: options.Root, ManifestLeaf: providerBundleLeaf, TrustLeaf: providerTrustLeaf, ExpectedBundleDigest: options.BundleDigest, ExpectedTrustDigest: options.TrustDigest, OwnerUID: options.OwnerUID, OwnerGID: options.OwnerGID}, Operations: providerrevision.OperationLoadConfig{RootPath: options.Root, OperationLeaf: providerOperationLeaf, OwnerTrustLeaf: controllerOwnerTrustLeaf, ExpectedOwnerTrustDigest: options.OwnerTrustDigest, OwnerUID: options.OwnerUID, OwnerGID: options.OwnerGID}}
	return service, dispatcher, nil
}

// activeProviderRegistry keeps an installed candidate truthful: only an
// explicit activate operation creates an active registry. A candidate-only
// repository composes as an empty disabled directory instead of crashing or
// presenting the candidate as routable.
func activeProviderRegistry(ctx context.Context, service *providerrevision.Service) (*providerbridge.Registry, providerrevision.Installed, error) {
	if service == nil {
		return nil, providerrevision.Installed{}, providerrevision.ErrUnavailable
	}
	if _, err := service.Active(ctx); errors.Is(err, providerrevision.ErrUnavailable) {
		registry, registryErr := providerbridge.NewRegistry(nil, nil, nil, nil, providerbridge.TrustRegistry{}, nil)
		return registry, providerrevision.Installed{}, registryErr
	} else if err != nil {
		return nil, providerrevision.Installed{}, err
	}
	return service.Registry(ctx)
}

// meshApplication is the Controller composition owner. It retains the mesh
// coordinator, revision authority and UI seams even while the default
// installation has no artifact, trust source, root registration or adapter.
type meshApplication struct {
	coordinator        *mesh.Coordinator
	revisions          *providerrevision.Service
	nativeHosts        *macosattest.HostRegistry
	launchOfficialHost func(context.Context, *macosattest.HostRegistry, []byte, macosattest.HostLaunchSpec) (*macosattest.HostProcess, error)
	materializeQwen    func(string, string, string, string, int, int) error
}

func (a *meshApplication) LaunchOfficialHost(ctx context.Context, identity []byte, spec macosattest.HostLaunchSpec) (*macosattest.HostProcess, error) {
	if a == nil || a.nativeHosts == nil || a.launchOfficialHost == nil {
		return nil, macosattest.ErrUnavailable
	}
	return a.launchOfficialHost(ctx, a.nativeHosts, identity, spec)
}

func (a *meshApplication) MaterializeQwenClosure(archive, target, manifest, digest string, uid, gid int) error {
	if a == nil || a.materializeQwen == nil {
		return macosattest.ErrUnavailable
	}
	return a.materializeQwen(archive, target, manifest, digest, uid, gid)
}

func (a *meshApplication) MeshUIProjection(ctx context.Context) (meshui.ProjectionSnapshot, error) {
	if a == nil || a.revisions == nil {
		return meshui.ProjectionSnapshot{}, providerrevision.ErrUnavailable
	}
	v, err := a.revisions.Active(ctx)
	if err != nil {
		return meshui.ProjectionSnapshot{}, err
	}
	// Revalidate the current trust-backed registry before projecting an active
	// state; a persisted package alone never implies a usable provider route.
	// Directory is deliberately sourced from that registry rather than from the
	// stored bundle so evidence freshness and mesh eligibility cannot be
	// fabricated by Controller composition.
	registry, installed, err := a.revisions.Registry(ctx)
	if err != nil {
		return meshui.ProjectionSnapshot{}, err
	}
	if installed.Bundle.RevisionID != v.Bundle.RevisionID {
		return meshui.ProjectionSnapshot{}, providerrevision.ErrUnavailable
	}
	directory := registry.Directory(ctx, time.Now().UTC())
	ux, err := a.revisions.UXSnapshot(ctx)
	if err != nil {
		return meshui.ProjectionSnapshot{}, err
	}
	status := "disabled"
	for _, profile := range directory.Profiles() {
		if profile.MeshSpawn {
			status = "enabled"
			break
		}
	}
	templates := make([]meshui.Template, 0, len(ux.Templates))
	for _, value := range ux.Templates {
		templates = append(templates, meshui.Template{TemplateID: value.TemplateID, Version: value.Version})
	}
	approvals := make([]meshui.PolicyApproval, 0, len(ux.Approvals))
	for _, value := range ux.Approvals {
		approvals = append(approvals, meshui.PolicyApproval{DecisionType: value.DecisionType, Status: value.Status, ExpiresAt: value.ExpiresAt.UTC().Format(time.RFC3339Nano)})
	}
	return meshui.ProjectionSnapshot{RevisionID: v.Bundle.RevisionID, ProviderDirectory: directory, Package: &meshui.PackageSnapshot{PackageID: v.Bundle.BundleID, Digest: v.Bundle.Digest, Status: status}, Templates: &meshui.Templates{Approved: templates}, Policy: &meshui.Policy{Approvals: approvals}, Unavailable: []string{"deployment-diagnostics", "plugin-lifecycle", "run-synthesis"}}, nil
}

// InvokeMeshUI refuses by default. The principal requirement makes it
// impossible to turn a UI bearer into an endpoint credential; a future
// Controller lifecycle operation must persist a matching root/endpoint
// association before dispatch is implemented.
func (a *meshApplication) InvokeMeshUI(ctx context.Context, kind string, payload any) (meshui.MeshUIResponse, error) {
	principal, ok := dshbridge.PrincipalFromContext(ctx)
	if !ok || a == nil || a.coordinator == nil || a.revisions == nil {
		return meshui.MeshUIResponse{}, meshui.ErrUnavailable
	}
	association, err := a.revisions.Association(ctx, principal.SessionID, principal.ChannelID)
	if err != nil {
		return meshui.MeshUIResponse{}, meshui.ErrUnavailable
	}
	_, installed, err := a.revisions.Registry(ctx)
	if err != nil || installed.Bundle.RevisionID != association.RevisionID {
		return meshui.MeshUIResponse{}, meshui.ErrUnavailable
	}
	binding, err := a.coordinator.EndpointBinding(ctx, association.EndpointID)
	if err != nil || binding.Audience != "ui" || binding.RootRunID != association.RootRunID || binding.RunID != association.RunID || binding.SessionID != association.MeshSessionID || binding.AttemptID != association.AttemptID || binding.PeerID != association.PeerID || binding.Generation != association.EndpointGeneration || !binding.ExpiresAt.Equal(association.ExpiresAt) {
		return meshui.MeshUIResponse{}, meshui.ErrUnavailable
	}
	uiNonce, err := meshUINonce()
	if err != nil {
		return meshui.MeshUIResponse{}, meshui.ErrUnavailable
	}
	uiRaw, err := json.Marshal(struct {
		Kind    string `json:"kind"`
		Payload any    `json:"payload"`
	}{Kind: kind, Payload: payload})
	if err != nil || len(uiRaw) == 0 || len(uiRaw) > 1<<20 {
		return meshui.MeshUIResponse{}, meshui.ErrUnavailable
	}
	uiDigest := meshDigest(uiRaw)
	rootBinding, err := a.coordinator.AuthorizeUIOperation(ctx, mesh.EndpointRequest{EndpointID: binding.EndpointID, PeerID: binding.PeerID, Audience: "ui", Nonce: uiNonce, MessageDigest: uiDigest}, kind, uiDigest)
	if err != nil {
		return meshui.MeshUIResponse{}, meshui.ErrUnavailable
	}
	meshNonce, err := meshUINonce()
	if err != nil {
		return meshui.MeshUIResponse{}, meshui.ErrUnavailable
	}
	endpoint := func(digest string) mesh.EndpointRequest {
		return mesh.EndpointRequest{EndpointID: rootBinding.EndpointID, PeerID: rootBinding.PeerID, Audience: "mesh", Nonce: meshNonce, MessageDigest: digest}
	}
	// Read-only UI surfaces are projections of the already authenticated
	// association. They never create a revision, invoke a provider, or accept
	// data from the request as a replacement for Controller state.
	if kind == "provider-directory" || kind == "provider-diagnostics" || kind == "run-templates" || kind == "policy-approval-inspector" || kind == "deployment-diagnostics" || kind == "plugin-lifecycle" {
		snapshot, projectionErr := a.MeshUIProjection(ctx)
		if projectionErr != nil {
			return meshui.MeshUIResponse{}, meshui.ErrUnavailable
		}
		if kind == "provider-directory" {
			return meshui.MeshUIResponse{SchemaVersion: meshui.ResponseSchema, Kind: kind, Directory: &meshui.ProfilesOutput{Profiles: meshUIProfiles(snapshot.ProviderDirectory)}}, nil
		}
		if kind == "provider-diagnostics" {
			diagnostics := snapshot.Diagnostics
			if diagnostics == nil {
				entries := snapshot.ProviderDirectory.Profiles()
				values := make([]meshui.ProviderDiagnostic, 0, len(entries))
				for _, entry := range entries {
					values = append(values, meshui.ProviderDiagnostic{ProfileID: entry.ProfileID, Status: string(entry.Status), Freshness: string(entry.Freshness)})
				}
				diagnostics = &meshui.Diagnostics{Providers: values}
			}
			return meshui.MeshUIResponse{SchemaVersion: meshui.ResponseSchema, Kind: kind, Diagnostics: &meshui.DiagnosticsOutput{Diagnostics: *diagnostics}}, nil
		}
		if kind == "run-templates" && snapshot.Templates != nil {
			return meshui.MeshUIResponse{SchemaVersion: meshui.ResponseSchema, Kind: kind, Templates: &meshui.TemplatesOutput{Templates: *snapshot.Templates}}, nil
		}
		if kind == "policy-approval-inspector" && snapshot.Policy != nil {
			return meshui.MeshUIResponse{SchemaVersion: meshui.ResponseSchema, Kind: kind, Policy: &meshui.PolicyOutput{Policy: *snapshot.Policy}}, nil
		}
		// Plugin lifecycle is an owner-signed Controller operation.  A UI
		// proposal cannot honestly claim completion merely because a package is
		// installed, so keep this surface unavailable until its exact signed
		// receipt/dispatcher integration is present.
		if kind == "plugin-lifecycle" {
			return meshui.MeshUIResponse{}, meshui.ErrUnavailable
		}
		// Deployment status is not present in the current revision projection;
		// never claim health from successful association validation alone.
		if kind == "deployment-diagnostics" {
			return meshui.MeshUIResponse{}, meshui.ErrUnavailable
		}
		return meshui.MeshUIResponse{}, meshui.ErrUnavailable
	}
	switch kind {
	case "selection-revision":
		var fields struct {
			ProfileID      string `json:"profile_id"`
			Operation      string `json:"operation"`
			BaseRevisionID string `json:"base_revision_id"`
		}
		raw, marshalErr := json.Marshal(payload)
		if marshalErr != nil || json.Unmarshal(raw, &fields) != nil {
			return meshui.MeshUIResponse{}, meshui.ErrUnavailable
		}
		selection, _, err := a.revisions.SelectUI(ctx, association, fields.ProfileID, fields.Operation, fields.BaseRevisionID)
		if err != nil {
			return meshui.MeshUIResponse{}, meshui.ErrUnavailable
		}
		return meshui.MeshUIResponse{SchemaVersion: meshui.ResponseSchema, Kind: kind, Selection: &meshui.SelectionOutput{RevisionID: selection.RevisionID, ActiveTurnChanged: false}}, nil
	case "ui-session-graph":
		var fields struct {
			RootID string `json:"root_id"`
		}
		raw, marshalErr := json.Marshal(payload)
		if marshalErr != nil || json.Unmarshal(raw, &fields) != nil || fields.RootID != association.RootRunID {
			return meshui.MeshUIResponse{}, meshui.ErrUnavailable
		}
		req := mesh.OperationRequest{Target: mesh.TargetRequest{TargetRunID: association.RootRunID, Operation: "list"}, RevisionRef: association.RevisionID}
		digest, err := req.Digest()
		if err != nil {
			return meshui.MeshUIResponse{}, meshui.ErrUnavailable
		}
		req.Target.Endpoint = endpoint(digest)
		runs, err := a.coordinator.List(ctx, req)
		if err != nil {
			return meshui.MeshUIResponse{}, meshui.ErrUnavailable
		}
		nodes := make([]meshui.GraphNode, 0, len(runs))
		for _, run := range runs {
			// Root has no provider profile and is structurally represented by
			// the authenticated root request itself; never invent a profile to
			// make it fit the redacted DTO.
			if run.ProfileID != "" && run.Provider != "" {
				nodes = append(nodes, meshui.GraphNode{ID: run.RunID, Status: run.Status, Provider: run.Provider, ProfileID: run.ProfileID})
			}
		}
		return meshui.MeshUIResponse{SchemaVersion: meshui.ResponseSchema, Kind: kind, Graph: &meshui.GraphOutput{Graph: meshui.Graph{Nodes: nodes, Edges: []meshui.GraphEdge{}}}}, nil
	case "run-compare":
		var fields struct {
			RunIDs []string `json:"run_ids"`
		}
		raw, marshalErr := json.Marshal(payload)
		if marshalErr != nil || json.Unmarshal(raw, &fields) != nil || len(fields.RunIDs) == 0 || len(fields.RunIDs) > 64 {
			return meshui.MeshUIResponse{}, meshui.ErrUnavailable
		}
		req := mesh.OperationRequest{Target: mesh.TargetRequest{TargetRunID: association.RootRunID, Operation: "list"}, RevisionRef: association.RevisionID}
		digest, err := req.Digest()
		if err != nil {
			return meshui.MeshUIResponse{}, meshui.ErrUnavailable
		}
		req.Target.Endpoint = endpoint(digest)
		runs, err := a.coordinator.List(ctx, req)
		if err != nil {
			return meshui.MeshUIResponse{}, meshui.ErrUnavailable
		}
		byID := make(map[string]mesh.RunProjection, len(runs))
		for _, run := range runs {
			byID[run.RunID] = run
		}
		out := make([]meshui.CompareRun, 0, len(fields.RunIDs))
		seen := map[string]bool{}
		for _, runID := range fields.RunIDs {
			run, found := byID[runID]
			if !found || seen[runID] || run.ProfileID == "" || run.Provider == "" {
				return meshui.MeshUIResponse{}, meshui.ErrUnavailable
			}
			seen[runID] = true
			// Results are never inferred from a terminal status.  Until a
			// separately sealed result reference is present, comparison makes
			// its absence explicit rather than hiding failed/partial work.
			out = append(out, meshui.CompareRun{Provider: run.Provider, ProfileID: run.ProfileID, Status: run.Status, ResultAvailable: false})
		}
		return meshui.MeshUIResponse{SchemaVersion: meshui.ResponseSchema, Kind: kind, Compare: &meshui.CompareOutput{Compare: meshui.Comparison{Runs: out}}}, nil
	case "mesh-spawn":
		proposal, ok := payload.(mesh.SpawnProposal)
		if !ok {
			return meshui.MeshUIResponse{}, meshui.ErrUnavailable
		}
		result, err := a.coordinator.ProposeSpawn(ctx, mesh.ProposalRequest{Endpoint: endpoint(meshDigest(proposal)), Proposal: proposal})
		if err != nil {
			return meshui.MeshUIResponse{}, meshui.ErrUnavailable
		}
		return meshui.MeshUIResponse{SchemaVersion: meshui.ResponseSchema, Kind: kind, Spawn: &meshui.SpawnOutput{Proposal: meshui.ProposalOutput{ProposalID: result.ProposalID, RunID: result.RunID, SessionID: result.SessionID, OrderID: result.OrderID, BindingID: result.BindingID, Replayed: result.Replayed}}}, nil
	case "mesh-spawnBatch":
		proposals, ok := payload.([]mesh.SpawnProposal)
		if !ok {
			return meshui.MeshUIResponse{}, meshui.ErrUnavailable
		}
		result, err := a.coordinator.ProposeSpawnBatch(ctx, mesh.BatchProposalRequest{Endpoint: endpoint(meshDigest(proposals)), Proposals: proposals})
		if err != nil {
			return meshui.MeshUIResponse{}, meshui.ErrUnavailable
		}
		results := make([]meshui.ProposalOutput, 0, len(result.Results))
		for _, v := range result.Results {
			results = append(results, meshui.ProposalOutput{ProposalID: v.ProposalID, RunID: v.RunID, SessionID: v.SessionID, OrderID: v.OrderID, BindingID: v.BindingID, Replayed: v.Replayed})
		}
		if len(results) == 0 {
			return meshui.MeshUIResponse{}, meshui.ErrUnavailable
		}
		return meshui.MeshUIResponse{SchemaVersion: meshui.ResponseSchema, Kind: kind, SpawnBatch: &meshui.SpawnBatchOutput{BatchID: result.BatchID, Results: results, Partial: result.Partial}}, nil
	case "mesh-listProfiles":
		profiles, err := a.coordinator.ListProfiles(ctx, mesh.ListProfilesRequest{Endpoint: endpoint(meshDigest("listProfiles:" + association.RevisionID)), RevisionRef: association.RevisionID})
		if err != nil {
			return meshui.MeshUIResponse{}, meshui.ErrUnavailable
		}
		out := make([]meshui.Profile, 0, len(profiles))
		for _, p := range profiles {
			out = append(out, meshui.Profile{ProfileID: p.ID, Provider: p.Provider, Model: p.Model, Status: p.Status, MeshSpawn: p.MeshSpawn, LocalOnly: p.LocalOnly})
		}
		return meshui.MeshUIResponse{SchemaVersion: meshui.ResponseSchema, Kind: kind, ListProfiles: &meshui.ProfilesOutput{Profiles: out}}, nil
	case "mesh-send", "mesh-steer", "mesh-wait", "mesh-collect", "mesh-cancel", "mesh-list", "mesh-status", "mesh-result":
		var fields struct {
			RunID       string `json:"run_id"`
			RootID      string `json:"root_id"`
			InputRef    string `json:"input_ref"`
			RevisionRef string `json:"revision_ref"`
			ReasonRef   string `json:"reason_ref"`
		}
		raw, marshalErr := json.Marshal(payload)
		if marshalErr != nil || json.Unmarshal(raw, &fields) != nil {
			return meshui.MeshUIResponse{}, meshui.ErrUnavailable
		}
		operation := kind[len("mesh-"):]
		target := fields.RunID
		if operation == "list" {
			target = fields.RootID
		}
		if target == "" {
			return meshui.MeshUIResponse{}, meshui.ErrUnavailable
		}
		req := mesh.OperationRequest{Target: mesh.TargetRequest{TargetRunID: target, Operation: operation}}
		switch operation {
		case "send", "steer":
			if fields.InputRef == "" || fields.RevisionRef != "" || fields.ReasonRef != "" {
				return meshui.MeshUIResponse{}, meshui.ErrUnavailable
			}
			req.InputRef = fields.InputRef
		case "cancel":
			if fields.InputRef != "" || fields.RevisionRef == "" || fields.ReasonRef == "" {
				return meshui.MeshUIResponse{}, meshui.ErrUnavailable
			}
			req.RevisionRef, req.ReasonRef = fields.RevisionRef, fields.ReasonRef
		case "wait", "collect", "list", "status", "result":
			if fields.InputRef != "" || fields.ReasonRef != "" || fields.RevisionRef == "" {
				return meshui.MeshUIResponse{}, meshui.ErrUnavailable
			}
			req.RevisionRef = fields.RevisionRef
		default:
			return meshui.MeshUIResponse{}, meshui.ErrUnavailable
		}
		digest, err := req.Digest()
		if err != nil {
			return meshui.MeshUIResponse{}, meshui.ErrUnavailable
		}
		req.Target.Endpoint = endpoint(digest)
		switch operation {
		case "send":
			if err := a.coordinator.Send(ctx, req); err != nil {
				return meshui.MeshUIResponse{}, meshui.ErrUnavailable
			}
			return meshui.MeshUIResponse{SchemaVersion: meshui.ResponseSchema, Kind: kind, Send: &meshui.AcknowledgementOutput{Acknowledgement: meshui.OperationAcknowledgement{TargetRunID: target, InputRef: req.InputRef, Digest: digest, Status: "sent"}}}, nil
		case "steer":
			if err := a.coordinator.Steer(ctx, req); err != nil {
				return meshui.MeshUIResponse{}, meshui.ErrUnavailable
			}
			return meshui.MeshUIResponse{SchemaVersion: meshui.ResponseSchema, Kind: kind, Steer: &meshui.AcknowledgementOutput{Acknowledgement: meshui.OperationAcknowledgement{TargetRunID: target, InputRef: req.InputRef, Digest: digest, Status: "sent"}}}, nil
		case "cancel":
			if err := a.coordinator.Cancel(ctx, req); err != nil {
				return meshui.MeshUIResponse{}, meshui.ErrUnavailable
			}
			return meshui.MeshUIResponse{SchemaVersion: meshui.ResponseSchema, Kind: kind, Cancel: &meshui.AcknowledgementOutput{Acknowledgement: meshui.OperationAcknowledgement{TargetRunID: target, RevisionRef: req.RevisionRef, ReasonRef: req.ReasonRef, Digest: digest, Status: "cancelled"}}}, nil
		case "wait":
			status, err := a.coordinator.Wait(ctx, req)
			if err != nil {
				return meshui.MeshUIResponse{}, meshui.ErrUnavailable
			}
			return meshui.MeshUIResponse{SchemaVersion: meshui.ResponseSchema, Kind: kind, Wait: &meshui.SessionStatusOutput{State: status.State, UsageSource: status.UsageSource}}, nil
		case "status":
			status, err := a.coordinator.Status(ctx, req)
			if err != nil {
				return meshui.MeshUIResponse{}, meshui.ErrUnavailable
			}
			return meshui.MeshUIResponse{SchemaVersion: meshui.ResponseSchema, Kind: kind, Status: &meshui.SessionStatusOutput{State: status.State, UsageSource: status.UsageSource}}, nil
		case "collect":
			result, err := a.coordinator.Collect(ctx, req)
			if err != nil {
				return meshui.MeshUIResponse{}, meshui.ErrUnavailable
			}
			return meshui.MeshUIResponse{SchemaVersion: meshui.ResponseSchema, Kind: kind, Collect: &meshui.ResultEnvelopeOutput{RunID: result.RunID, AttemptID: result.AttemptID, Status: result.Status, OutputArtifactRef: result.OutputArtifactRef, SchemaRef: result.SchemaRef, ProvenanceDigest: result.ProvenanceDigest, Classification: result.Classification}}, nil
		case "result":
			result, err := a.coordinator.Result(ctx, req)
			if err != nil {
				return meshui.MeshUIResponse{}, meshui.ErrUnavailable
			}
			return meshui.MeshUIResponse{SchemaVersion: meshui.ResponseSchema, Kind: kind, Result: &meshui.ResultEnvelopeOutput{RunID: result.RunID, AttemptID: result.AttemptID, Status: result.Status, OutputArtifactRef: result.OutputArtifactRef, SchemaRef: result.SchemaRef, ProvenanceDigest: result.ProvenanceDigest, Classification: result.Classification}}, nil
		case "list":
			runs, err := a.coordinator.List(ctx, req)
			if err != nil {
				return meshui.MeshUIResponse{}, meshui.ErrUnavailable
			}
			out := make([]meshui.RunListItem, 0, len(runs))
			for _, run := range runs {
				// A root run deliberately has no provider profile. The UI request
				// already carries its root_id, so omit that structural entry rather
				// than inventing a provider/profile pair merely to fit a child-run
				// projection.
				if run.ProfileID == "" || run.Provider == "" {
					continue
				}
				out = append(out, meshui.RunListItem{RunID: run.RunID, ProfileID: run.ProfileID, Provider: run.Provider, Status: run.Status, Depth: run.Depth})
			}
			return meshui.MeshUIResponse{SchemaVersion: meshui.ResponseSchema, Kind: kind, List: &meshui.ListOutput{Runs: out}}, nil
		}
		return meshui.MeshUIResponse{}, meshui.ErrUnavailable
	default:
		return meshui.MeshUIResponse{}, meshui.ErrUnavailable
	}
}

func meshUIProfiles(directory providerbridge.DirectorySnapshot) []meshui.Profile {
	entries := directory.Profiles()
	profiles := make([]meshui.Profile, 0, len(entries))
	for _, entry := range entries {
		profiles = append(profiles, meshui.Profile{ProfileID: entry.ProfileID, Provider: string(entry.Provider), Model: entry.Model, Status: string(entry.Status), MeshSpawn: entry.MeshSpawn, LocalOnly: entry.LocalOnly})
	}
	return profiles
}

func meshUINonce() (string, error) {
	raw := make([]byte, 18)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return "ui-" + hex.EncodeToString(raw), nil
}
func meshDigest(v any) string {
	raw, _ := json.Marshal(v)
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func (a *meshApplication) verifyUIBinding(ctx context.Context, op providerrevision.ProviderLifecycleOperation) error {
	if a == nil || a.coordinator == nil || a.revisions == nil || op.Action != "ui-bind" {
		return errors.New("binding unavailable")
	}
	registration, err := a.revisions.Registration(ctx, op.SessionID, op.ChannelID)
	if err != nil || registration.RequestDigest == "" || registration.SessionID != op.SessionID || registration.ChannelID != op.ChannelID || registration.RootRunID != op.RootRunID || registration.RunID != op.RunID || registration.MeshSessionID != op.MeshSessionID || registration.AttemptID != op.AttemptID || registration.PeerID != op.PeerID || registration.EndpointID != op.EndpointID || registration.EndpointGeneration != op.EndpointGeneration || registration.RevisionID != op.RevisionID || !registration.ExpiresAt.Equal(op.EndpointExpiresAt) {
		return errors.New("registration mismatch")
	}
	b, err := a.coordinator.EndpointBinding(ctx, op.EndpointID)
	if err != nil || b.Audience != "ui" || b.RootRunID != op.RootRunID || b.RunID != op.RunID || b.SessionID != op.MeshSessionID || b.AttemptID != op.AttemptID || b.PeerID != op.PeerID || b.Generation != op.EndpointGeneration || !b.ExpiresAt.Equal(op.EndpointExpiresAt) {
		return errors.New("binding mismatch")
	}
	return nil
}

// registerUIRoot is the production-only first half of a UI binding. Its input
// is already owner-signed ui-register, but the result is deliberately only a
// pending registration: the UI endpoint remains unusable until a second owner
// signature over its dynamically minted exact identity arrives as ui-bind.
func (a *meshApplication) registerUIRoot(ctx context.Context, op providerrevision.ProviderLifecycleOperation) (providerrevision.UIRegistration, error) {
	if a == nil || a.coordinator == nil || a.revisions == nil || op.Action != "ui-register" {
		return providerrevision.UIRegistration{}, errors.New("ui registration unavailable")
	}
	root, err := a.coordinator.RegisterRoot(ctx, op.RootRunID, op.MeshSessionID, op.AttemptID, op.PeerID, op.Classification, op.WorkspaceGroupID)
	if err != nil {
		return providerrevision.UIRegistration{}, err
	}
	ui, err := a.coordinator.MintUIEndpoint(ctx, root)
	if err != nil || ui.Audience != "ui" || ui.RootRunID != op.RootRunID || ui.RunID != op.RunID || ui.SessionID != op.MeshSessionID || ui.AttemptID != op.AttemptID || ui.PeerID != op.PeerID {
		return providerrevision.UIRegistration{}, errors.New("ui endpoint unavailable")
	}
	return providerrevision.UIRegistration{RequestNonce: op.Nonce, RequestDigest: op.Digest, SessionID: op.SessionID, ChannelID: op.ChannelID, RootRunID: ui.RootRunID, RunID: ui.RunID, MeshSessionID: ui.SessionID, AttemptID: ui.AttemptID, PeerID: ui.PeerID, EndpointID: ui.EndpointID, EndpointGeneration: ui.Generation, RevisionID: op.RevisionID, ExpiresAt: ui.ExpiresAt}, nil
}

func (a *meshApplication) revokeUIEndpoint(ctx context.Context, endpointID string, generation uint64) error {
	if a == nil || a.coordinator == nil {
		return errors.New("endpoint revoke unavailable")
	}
	return a.coordinator.RevokeEndpoint(ctx, endpointID, generation)
}

func (a *meshApplication) rotateUIEndpoint(ctx context.Context, target providerrevision.UIRotateTarget) (providerrevision.UIRotateResult, error) {
	if a == nil || a.coordinator == nil {
		return providerrevision.UIRotateResult{}, errors.New("endpoint rotation unavailable")
	}
	old, err := a.coordinator.LifecycleRootBinding(ctx, target.Association.EndpointID, target.Association.EndpointGeneration)
	if err != nil || old.RootRunID != target.Association.RootRunID || old.RunID != target.Association.RunID || old.SessionID != target.Association.MeshSessionID || old.AttemptID != target.Association.AttemptID || old.PeerID != target.Association.PeerID || old.Generation != target.Association.EndpointGeneration || !old.ExpiresAt.Equal(target.Association.ExpiresAt) {
		return providerrevision.UIRotateResult{}, errors.New("rotation binding mismatch")
	}
	next, err := a.coordinator.RotateUIEndpointPair(ctx, old)
	if err != nil {
		return providerrevision.UIRotateResult{}, err
	}
	return providerrevision.UIRotateResult{EndpointID: next.EndpointID, Generation: next.Generation, ExpiresAt: next.ExpiresAt}, nil
}

func (a *meshApplication) closeRootEndpoint(ctx context.Context, target providerrevision.UIRotateTarget) error {
	if a == nil || a.coordinator == nil {
		return errors.New("root close unavailable")
	}
	binding, err := a.coordinator.LifecycleRootBinding(ctx, target.Association.EndpointID, target.Association.EndpointGeneration)
	if err != nil || binding.RootRunID != target.Association.RootRunID || binding.RunID != target.Association.RunID || binding.SessionID != target.Association.MeshSessionID || binding.AttemptID != target.Association.AttemptID || binding.PeerID != target.Association.PeerID || binding.Generation != target.Association.EndpointGeneration || !binding.ExpiresAt.Equal(target.Association.ExpiresAt) {
		return errors.New("root close binding mismatch")
	}
	return a.coordinator.CloseRootEndpoint(ctx, binding)
}

type denyRevisionAuthority struct{}

func (denyRevisionAuthority) Authorize(context.Context, providerrevision.Operation) error {
	return errors.New("disabled")
}

type unavailableTrustSource struct{}

func (unavailableTrustSource) Current(context.Context, string) (providerbridge.Ed25519TrustBundle, error) {
	return providerbridge.Ed25519TrustBundle{}, errors.New("trust unavailable")
}

func newDisabledRevisionService(repo *providerrevision.Repository) (*providerrevision.Service, error) {
	return providerrevision.NewService(repo, denyRevisionAuthority{}, unavailableTrustSource{})
}
