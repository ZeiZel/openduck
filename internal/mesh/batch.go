package mesh

import (
	"context"
	"errors"
	"time"
)

type BatchProposalRequest struct {
	Endpoint  EndpointRequest
	Proposals []SpawnProposal
}
type BatchResult struct {
	BatchID string
	Results []ProposalResult
	Partial bool
}

func batchRecordKey(binding MeshEndpointBinding, digest string) string {
	return hash(struct {
		SchemaVersion string `json:"schema_version"`
		Domain        string `json:"domain"`
		EndpointID    string `json:"endpoint_id"`
		Generation    uint64 `json:"generation"`
		RootRunID     string `json:"root_run_id"`
		RunID         string `json:"run_id"`
		SessionID     string `json:"session_id"`
		AttemptID     string `json:"attempt_id"`
		Digest        string `json:"digest"`
	}{SchemaVersion: callerScopeV2, Domain: "spawnBatch", EndpointID: binding.EndpointID, Generation: binding.Generation, RootRunID: binding.RootRunID, RunID: binding.RunID, SessionID: binding.SessionID, AttemptID: binding.AttemptID, Digest: digest})
}

func legacyBatchRecordKey(binding MeshEndpointBinding, digest string) string {
	return hash(legacyProposalScope(binding, digest))
}

func batchOwnedByBinding(snapshot Snapshot, batch BatchRecord, binding MeshEndpointBinding) bool {
	if len(batch.ProposalKeys) == 0 {
		return false
	}
	for _, key := range batch.ProposalKeys {
		proposal, ok := snapshot.Proposals[key]
		if !ok || !proposalOwnedByBinding(snapshot, proposal, binding) {
			return false
		}
	}
	return true
}

// ProposeSpawnBatch seals every child in one repository CAS before any adapter
// call. Admission errors therefore leave zero child runs/reservations.
func (c *Coordinator) ProposeSpawnBatch(ctx context.Context, req BatchProposalRequest) (BatchResult, error) {
	if c.poisoned.Load() {
		return BatchResult{}, ErrRepositoryPoisoned
	}
	if len(req.Proposals) == 0 || len(req.Proposals) > 16 {
		return BatchResult{}, ErrInvalidContract
	}
	for _, p := range req.Proposals {
		if p.Validate() != nil {
			return BatchResult{}, ErrInvalidContract
		}
	}
	digest := hash(req.Proposals)
	if req.Endpoint.MessageDigest != digest {
		return BatchResult{}, ErrUnauthorized
	}
	now := c.now().UTC()
	binding, e := c.endpoints.AuthorizeOperationForPolicy(req.Endpoint, now, "spawnBatch", digest, c.policyVersion)
	if e != nil {
		return BatchResult{}, e
	}
	if !operationAudience(binding.Audience) {
		return BatchResult{}, ErrUnauthorized
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	var allocated []string
	for tries := 0; tries < 8; tries++ {
		s, e := c.repo.Load(ctx)
		if e != nil {
			return BatchResult{}, e
		}
		parent, ok := s.Runs[binding.RunID]
		if !bindingIsCurrent(s, binding, c.policyVersion, now) || !ok || parent.RootID != binding.RootRunID || parent.SessionID != binding.SessionID || parent.AttemptID != binding.AttemptID || parent.State != RunRunning {
			return BatchResult{}, ErrUnauthorized
		}
		batchKey := batchRecordKey(binding, digest)
		if old, ok := s.Batches[batchKey]; ok {
			if !batchOwnedByBinding(s, old, binding) {
				return BatchResult{}, ErrRepositoryPoisoned
			}
			if old.Digest != digest {
				return BatchResult{}, ErrIdempotencyConflict
			}
			if old.State == "pending" || old.State == "uncertain" {
				return BatchResult{}, ErrReconciliationNeeded
			}
			return batchResult(s, old), nil
		}
		legacyBatchKey := legacyBatchRecordKey(binding, digest)
		if old, ok := s.Batches[legacyBatchKey]; ok && old.Digest == digest && batchOwnedByBinding(s, old, binding) && len(old.ProposalKeys) == len(req.Proposals) {
			migratable := true
			next := s.clone()
			delete(next.Batches, legacyBatchKey)
			old.Key = batchKey
			next.Batches[batchKey] = old
			for i, proposalKey := range old.ProposalKeys {
				proposal := next.Proposals[proposalKey]
				if proposal.Digest != hash(req.Proposals[i]) {
					migratable = false
					break
				}
				delete(next.NonceScopes, proposal.Scope)
				proposal.Scope = proposalScope(binding, req.Proposals[i].ClientNonce, "spawnBatch")
				proposal.CallerEndpointID = binding.EndpointID
				proposal.CallerGeneration = binding.Generation
				proposal.RootRunID = binding.RootRunID
				if claimed, exists := next.NonceScopes[proposal.Scope]; exists && claimed != proposalKey {
					migratable = false
					break
				}
				next.NonceScopes[proposal.Scope] = proposalKey
				next.Proposals[proposalKey] = proposal
			}
			if migratable {
				if e = c.cas(ctx, s, next); e == nil || errors.Is(e, ErrVersionConflict) {
					continue
				}
				return BatchResult{}, e
			}
		}
		profiles := make([]Profile, len(req.Proposals))
		disclosures := make([]CloudDisclosure, len(req.Proposals))
		scopes := make([]string, len(req.Proposals))
		keys := make([]string, len(req.Proposals))
		seen := map[string]bool{}
		for i, p := range req.Proposals {
			if seen[p.ClientNonce] {
				return BatchResult{}, ErrIdempotencyConflict
			}
			seen[p.ClientNonce] = true
			profile, err := c.directory.Lookup(ctx, p.PreferredProfile)
			if err != nil || !profile.Eligible() || !p.RequestedLimits.Narrows(profile.Limits) {
				return BatchResult{}, ErrDenied
			}
			if (parent.Classification == "PD" || parent.Classification == "L3") && !profile.LocalOnly {
				return BatchResult{}, ErrPDCloudRoute
			}
			if !profile.LocalOnly {
				if c.disclosure == nil {
					return BatchResult{}, ErrDisclosure
				}
				dr := CloudDisclosureRequest{RootRunID: parent.RootID, ParentRunID: parent.ID, ProfileID: profile.ID, DestinationProvider: profile.Provider, AccountHandleRef: profile.AccountHandleRef, Model: profile.Model, Classification: parent.Classification, PayloadDigest: hash(p.InputArtifactRefs), Purpose: "mesh_child_task", PolicyVersion: c.policyVersion, InputRevision: 1, ExpiresAt: now.Add(time.Duration(p.RequestedLimits.MaxWallMS) * time.Millisecond)}
				d, e := c.disclosure.AuthorizeCloudDisclosure(ctx, dr)
				if e != nil || d.ValidateFor(dr, now) != nil {
					return BatchResult{}, ErrDisclosure
				}
				disclosures[i] = d
			}
			scopes[i] = proposalScope(binding, p.ClientNonce, "spawnBatch")
			keys[i] = proposalRecordKey(scopes[i], hash(p))
			if oldKey, exists := s.NonceScopes[scopes[i]]; exists && oldKey != keys[i] {
				return BatchResult{}, ErrIdempotencyConflict
			}
			if _, exists := s.NonceScopes[scopes[i]]; exists {
				return BatchResult{}, ErrIdempotencyConflict
			}
			profiles[i] = profile
		}
		clouds := 0
		destinations := map[string]bool{}
		for i, p := range profiles {
			if !p.LocalOnly {
				clouds++
				destinations[disclosures[i].DestinationProvider+":"+disclosures[i].AccountHandleRef+":"+disclosures[i].Model] = true
			}
		}
		minDepth, minChildren, minConcurrent := uint64(^uint64(0)), uint64(^uint64(0)), uint64(^uint64(0))
		var sumInput, sumOutput, sumWall, sumResult uint64
		for _, p := range req.Proposals {
			l := p.RequestedLimits
			if l.MaxDepth < minDepth {
				minDepth = l.MaxDepth
			}
			if l.MaxChildrenPerParent < minChildren {
				minChildren = l.MaxChildrenPerParent
			}
			if l.MaxConcurrentRuns < minConcurrent {
				minConcurrent = l.MaxConcurrentRuns
			}
			if ^uint64(0)-sumInput < l.MaxInputTokens || ^uint64(0)-sumOutput < l.MaxOutputTokens || ^uint64(0)-sumWall < l.MaxWallMS || ^uint64(0)-sumResult < l.MaxResultBytes {
				return BatchResult{}, ErrCapacity
			}
			sumInput += l.MaxInputTokens
			sumOutput += l.MaxOutputTokens
			sumWall += l.MaxWallMS
			sumResult += l.MaxResultBytes
		}
		if sumInput > c.batchCaps.MaxInputTokens || sumOutput > c.batchCaps.MaxOutputTokens || sumWall > c.batchCaps.MaxWallMS || sumResult > c.batchCaps.MaxResultBytes {
			return BatchResult{}, ErrCapacity
		}
		if parent.Depth+1 > minDepth || activeChildren(s, parent.ID)+uint64(len(req.Proposals)) > minChildren || activeRuns(s, parent.RootID)+uint64(len(req.Proposals)) > minConcurrent || activeCloudReservations(s)+uint64(clouds) > 1 || len(destinations) > 1 {
			return BatchResult{}, ErrCapacity
		}
		if allocated == nil {
			allocated, e = c.allocateIDs(s, 1+8*len(req.Proposals))
			if e != nil {
				return BatchResult{}, e
			}
		} else if snapshotUsesAnyID(s, allocated) {
			return BatchResult{}, ErrUnavailable
		}
		batchID := allocated[0]
		n := s.clone()
		br := BatchRecord{Key: batchKey, BatchID: batchID, Digest: digest, State: "pending", ProposalKeys: keys, CreatedAt: now}
		n.Batches[batchKey] = br
		results := make([]ProposalResult, len(req.Proposals))
		for i, p := range req.Proposals {
			profile := profiles[i]
			offset := 1 + i*8
			proposalID, runID, sessionID, attemptID, orderID, bindingID := allocated[offset], allocated[offset+1], allocated[offset+2], allocated[offset+3], allocated[offset+4], allocated[offset+5]
			r := Run{ID: runID, RootID: parent.RootID, ParentRunID: parent.ID, ParentSessionID: parent.SessionID, SessionID: sessionID, AttemptID: attemptID, ProfileID: profile.ID, Provider: profile.Provider, Classification: parent.Classification, WorkspaceGroupID: parent.WorkspaceGroupID, Depth: parent.Depth + 1, State: RunAdmitted, CreatedAt: now}
			n.Runs[runID] = r
			order := WorkOrderRecord{SchemaVersion: WorkOrderV2, OrderID: orderID, RootRunID: r.RootID, ParentRunID: r.ParentRunID, ParentSessionID: r.ParentSessionID, RunID: r.ID, SessionID: r.SessionID, AttemptID: r.AttemptID, ProfileID: profile.ID, Provider: r.Provider, Model: profile.Model, Classification: r.Classification, WorkspaceGroupID: r.WorkspaceGroupID, IdempotencyKey: keys[i], LeaseID: allocated[offset+6], PolicyVersion: c.policyVersion, Depth: r.Depth, Limits: p.RequestedLimits, Requested: CapabilityEnvelope{Tools: append([]string(nil), p.RequestedTools...)}, Effective: IntersectCapabilities(CapabilityEnvelope{Tools: p.RequestedTools}, profile.Supported), DisclosurePlanID: disclosures[i].PlanID, FanoutGrantID: disclosures[i].FanoutGrantID, LeaseExpiry: now.Add(time.Duration(p.RequestedLimits.MaxWallMS) * time.Millisecond), Task: p.TaskEnvelope()}
			order.OrderHash = hash(order)
			n.NonceScopes[scopes[i]] = keys[i]
			n.Proposals[keys[i]] = ProposalRecord{Key: keys[i], Scope: scopes[i], Digest: hash(p), BatchID: batchID, ProposalID: proposalID, RunID: runID, SessionID: sessionID, OrderID: orderID, BindingID: bindingID, CallerEndpointID: binding.EndpointID, CallerGeneration: binding.Generation, RootRunID: binding.RootRunID, State: "pending", CreatedAt: now, Order: order}
			if !profiles[i].LocalOnly {
				n.Disclosures[runID] = DisclosureReservation{PlanID: disclosures[i].PlanID, FanoutGrantID: disclosures[i].FanoutGrantID, Destination: disclosures[i].DestinationProvider}
			}
			results[i] = ProposalResult{ProposalID: proposalID, RunID: runID, SessionID: sessionID, OrderID: orderID, BindingID: bindingID}
			n.Events = append(n.Events, event(now, "batch_admitted", r, ""))
		}
		if e = c.cas(ctx, s, n); e != nil {
			if errors.Is(e, ErrVersionConflict) {
				continue
			}
			return BatchResult{}, e
		}
		// Starts happen only after durable batch admission. Every post-admission
		// failure flows through finalizeBatchFailure: it is the only writer of a
		// terminal batch state, so an admitted state can never overwrite a
		// partial/failed/uncertain outcome.
		started := make([]batchStarted, 0, len(results))
		failure := batchFailure{index: -1}
		for i, r := range results {
			if c.starter == nil {
				failure = batchFailure{index: i, code: "starter_unconfigured", uncertain: true}
				break
			}
			run := n.Runs[r.RunID]
			offset := 1 + i*8
			order := n.Proposals[keys[i]].Order
			dispatch := RunDispatchBinding{SchemaVersion: RunDispatchBindingV2, BindingID: r.BindingID, OrderID: order.OrderID, OrderHash: order.OrderHash, RootRunID: run.RootID, RunID: run.ID, SessionID: run.SessionID, AttemptID: run.AttemptID, EndpointID: allocated[offset+7], Generation: 1, IssuedAt: now, ExpiresAt: order.LeaseExpiry}
			dispatch.BindingHash = hash(dispatch)
			ref, err := c.starter.Start(ctx, sealStartRequest(order, dispatch))
			if err != nil {
				if errors.Is(err, ErrStartUncertain) || errors.Is(err, ErrReconciliationNeeded) {
					failure = batchFailure{index: i, code: "start_uncertain", uncertain: true}
				} else {
					failure = batchFailure{index: i, code: "start_failed"}
				}
				break
			}
			if !validID(ref.ProviderSessionID) {
				// The adapter reported success without a cancellable provider
				// reference. Do not mint an endpoint or attempt a blind cancel.
				// The finalizer records an uncertain child for evidence-based
				// reconciliation.
				failure = batchFailure{index: i, code: "invalid_start_ref", uncertain: true}
				break
			}
			// The provider session exists as soon as Start returns, even when the
			// following journal write is uncertain. Track it before every durable
			// transition so the finalizer can compensate it exactly once.
			member := batchStarted{result: r, ref: ref, attemptID: run.AttemptID}
			started = append(started, member)
			if err := c.persistBatchStarted(ctx, batchKey, member); err != nil {
				// The native Start already returned. The finalizer owns the one
				// compensation attempt and revokes any endpoint that may have been
				// durably registered by a concurrent/uncertain path. Never proceed
				// to endpoint issue or report a partial batch as success here.
				finalErr := c.finalizeBatchFailure(ctx, batchKey, results, started, batchFailure{index: i, code: "start_commit_failed", uncertain: true})
				return BatchResult{BatchID: batchID, Results: results, Partial: true}, errors.Join(ErrReconciliationNeeded, err, finalErr)
			}
			endpoint := MeshEndpointBinding{SchemaVersion: EndpointBindingV1, EndpointID: dispatch.EndpointID, Audience: "mesh", RootRunID: run.RootID, RunID: run.ID, SessionID: run.SessionID, AttemptID: run.AttemptID, AllowedOperations: order.Effective.Tools, ToolDigest: hash(sortedStrings(order.Effective.Tools)), PeerID: "broker:" + run.SessionID, PolicyVersion: c.policyVersion, IssuedAt: now, ExpiresAt: order.LeaseExpiry, Generation: 1}
			if err := c.activateBatchStarted(ctx, batchKey, member, endpoint); err != nil {
				failure = batchFailure{index: i, code: "endpoint_issue_failed", uncertain: errors.Is(err, ErrRepositoryPoisoned)}
				break
			}
		}
		if failure.index >= 0 {
			if err := c.finalizeBatchFailure(ctx, batchKey, results, started, failure); err != nil {
				return BatchResult{BatchID: batchID, Results: results, Partial: true}, err
			}
			if failure.uncertain {
				return BatchResult{BatchID: batchID, Results: results, Partial: true}, errors.Join(ErrReconciliationNeeded, ErrStartUncertain)
			}
			return BatchResult{BatchID: batchID, Results: results, Partial: true}, nil
		}
		if err := c.markBatch(ctx, batchKey, "admitted"); err != nil {
			// A successful provider Start is not a completed admission until the
			// batch state is durably committed. Try the same central finalizer for
			// retryable errors; on uncertain commit it can at least compensate the
			// live sessions while the poisoned pending journal awaits replay.
			// finalizeBatchFailure always performs compensation before attempting
			// its terminal CAS, including when that CAS is itself uncertain.
			finalErr := c.finalizeBatchFailure(ctx, batchKey, results, started, batchFailure{index: 0, code: "batch_finalize_failed", uncertain: errors.Is(err, ErrRepositoryPoisoned) || errors.Is(err, ErrCommitUncertain)})
			return BatchResult{BatchID: batchID, Results: results, Partial: true}, errors.Join(ErrReconciliationNeeded, err, finalErr)
		}
		return BatchResult{BatchID: batchID, Results: results}, nil
	}
	return BatchResult{}, ErrVersionConflict
}

type batchStarted struct {
	result    ProposalResult
	ref       SessionRef
	attemptID string
}
type batchFailure struct {
	index     int
	code      string
	uncertain bool
}

func (c *Coordinator) persistBatchStarted(ctx context.Context, key string, member batchStarted) error {
	for i := 0; i < 8; i++ {
		s, e := c.repo.Load(ctx)
		if e != nil {
			return e
		}
		n := s.clone()
		p, ok := n.Proposals[keyForProposal(s.Batches[key], s, member.result.RunID)]
		if !ok {
			return ErrInvalidContract
		}
		r, ok := n.Runs[member.result.RunID]
		if !ok {
			return ErrInvalidContract
		}
		if p.State != "pending" || r.State != RunAdmitted {
			return ErrInvalidContract
		}
		r.State = RunStarting
		r.ProviderSessionID = member.ref.ProviderSessionID
		n.Runs[r.ID] = r
		b := n.Batches[key]
		b.Attempts = upsertBatchAttempt(b.Attempts, BatchAttemptOutcome{ProposalID: member.result.ProposalID, RunID: member.result.RunID, SessionID: member.result.SessionID, AttemptID: member.attemptID, StartReceipt: member.ref.ProviderSessionID, Status: "started", RecoveryState: "active"})
		n.Batches[key] = b
		n.Events = append(n.Events, event(c.now().UTC(), "run_starting", r, ""))
		if e = c.casSafety(ctx, s, n); e == nil {
			return nil
		}
		if !errors.Is(e, ErrVersionConflict) {
			return e
		}
	}
	return ErrVersionConflict
}

func (c *Coordinator) activateBatchStarted(ctx context.Context, key string, member batchStarted, endpoint MeshEndpointBinding) error {
	if endpoint.RunID != member.result.RunID || endpoint.Validate(c.now().UTC()) != nil {
		return ErrInvalidContract
	}
	for i := 0; i < 8; i++ {
		s, err := c.repo.Load(ctx)
		if err != nil {
			return err
		}
		batch, batchOK := s.Batches[key]
		proposalKey := keyForProposal(batch, s, member.result.RunID)
		proposal, proposalOK := s.Proposals[proposalKey]
		run, runOK := s.Runs[member.result.RunID]
		if !batchOK || !proposalOK || !runOK || batch.State != "pending" || proposal.State != "pending" || run.State != RunStarting || run.ProviderSessionID != member.ref.ProviderSessionID {
			return ErrInvalidContract
		}
		if _, exists := s.EndpointBindings[endpoint.EndpointID]; exists {
			return ErrInvalidContract
		}
		n := s.clone()
		n.EndpointBindings[endpoint.EndpointID] = endpoint
		run.State = RunRunning
		n.Runs[run.ID] = run
		proposal.State = "admitted"
		proposal.ResponseDigest = hash(ProposalResult{ProposalID: proposal.ProposalID, RunID: proposal.RunID, SessionID: proposal.SessionID, OrderID: proposal.OrderID, BindingID: proposal.BindingID})
		n.Proposals[proposalKey] = proposal
		n.Events = append(n.Events, event(c.now().UTC(), "run_running", run, ""))
		if err = c.casSafety(ctx, s, n); err == nil {
			return nil
		}
		if !errors.Is(err, ErrVersionConflict) {
			return err
		}
	}
	return ErrVersionConflict
}

func (c *Coordinator) markBatch(ctx context.Context, key, state string) error {
	for i := 0; i < 8; i++ {
		s, e := c.repo.Load(ctx)
		if e != nil {
			return e
		}
		n := s.clone()
		b := n.Batches[key]
		b.State = state
		n.Batches[key] = b
		if e = c.casSafety(ctx, s, n); e == nil {
			return nil
		}
		if !errors.Is(e, ErrVersionConflict) {
			return e
		}
	}
	return ErrVersionConflict
}

func keyForProposal(batch BatchRecord, s Snapshot, runID string) string {
	for _, key := range batch.ProposalKeys {
		if p, ok := s.Proposals[key]; ok && p.RunID == runID {
			return key
		}
	}
	return ""
}

func upsertBatchAttempt(existing []BatchAttemptOutcome, out BatchAttemptOutcome) []BatchAttemptOutcome {
	for i := range existing {
		if existing[i].RunID == out.RunID {
			existing[i] = out
			return existing
		}
	}
	return append(existing, out)
}

func (c *Coordinator) compensateStarted(ctx context.Context, started []batchStarted) map[string]error {
	outcomes := make(map[string]error, len(started))
	for _, member := range started {
		if c.sessions == nil {
			outcomes[member.result.RunID] = ErrReconciliationNeeded
			continue
		}
		outcomes[member.result.RunID] = c.sessions.Cancel(ctx, member.ref, Cancellation{Mode: CancellationBatchCompensation, ReasonRef: "batch_compensation"})
	}
	return outcomes
}

// finalizeBatchFailure is the sole terminal writer for an admitted batch. It
// records each compensation result and all untouched members in one CAS so a
// replay returns durable outcomes and never restarts a provider session.
func (c *Coordinator) finalizeBatchFailure(ctx context.Context, key string, results []ProposalResult, started []batchStarted, failure batchFailure) error {
	// Capabilities must be revoked before any provider cancellation or failure
	// is reported. If durable revocation cannot be proven, poison the
	// coordinator so no child endpoint remains usable while reconciliation is
	// pending; still attempt one exact provider compensation below.
	revokeErr := c.revokeBatchEndpoints(ctx, results)
	if revokeErr != nil {
		c.poisoned.Store(true)
	}
	compensation := c.compensateStarted(ctx, started)
	startedByRun := make(map[string]batchStarted, len(started))
	for _, member := range started {
		startedByRun[member.result.RunID] = member
	}
	for i := 0; i < 8; i++ {
		s, e := c.repo.Load(ctx)
		if e != nil {
			return errors.Join(revokeErr, e)
		}
		n := s.clone()
		batch, ok := n.Batches[key]
		if !ok || len(batch.ProposalKeys) != len(results) {
			return ErrInvalidContract
		}
		uncertain := failure.uncertain
		transitionAt := c.now().UTC()
		for index, result := range results {
			proposalKey := batch.ProposalKeys[index]
			proposal, proposalOK := n.Proposals[proposalKey]
			run, runOK := n.Runs[result.RunID]
			if !proposalOK || !runOK || proposal.RunID != result.RunID {
				return ErrInvalidContract
			}
			out := BatchAttemptOutcome{ProposalID: result.ProposalID, RunID: result.RunID, SessionID: result.SessionID, AttemptID: run.AttemptID, RecoveryState: "terminal"}
			if member, wasStarted := startedByRun[result.RunID]; wasStarted {
				out.StartReceipt = member.ref.ProviderSessionID
				out.PrimaryError = failure.code
				if err := compensation[result.RunID]; err != nil {
					run.State = RunUncertain
					out.Status, out.CompensationStatus, out.CompensationError, out.RecoveryState = "uncertain", "failed", "cancel_failed", "uncertain"
					uncertain = true
				} else {
					run.State = RunCancelled
					out.Status, out.CompensationStatus = "compensated", "cancelled"
				}
			} else if failure.uncertain {
				run.State = RunUncertain
				out.Status, out.PrimaryError, out.RecoveryState = "uncertain", failure.code, "uncertain"
			} else if index == failure.index {
				run.State = RunFailed
				out.Status, out.PrimaryError = "start_failed", failure.code
			} else {
				run.State = RunCancelled
				out.Status, out.PrimaryError = "cancelled", failure.code
			}
			run.TerminalAt = transitionAt
			proposal.State = "terminal"
			proposal.ResponseDigest = hash(ProposalResult{ProposalID: proposal.ProposalID, RunID: proposal.RunID, SessionID: proposal.SessionID, OrderID: proposal.OrderID, BindingID: proposal.BindingID})
			n.Proposals[proposalKey] = proposal
			n.Runs[result.RunID] = run
			for endpointID, endpoint := range n.EndpointBindings {
				if endpoint.RunID == result.RunID {
					n.EndpointRevoked[endpointID] = true
				}
			}
			n.Events = append(n.Events, event(transitionAt, "run_"+string(run.State), run, failure.code))
			batch.Attempts = upsertBatchAttempt(batch.Attempts, out)
		}
		if uncertain {
			batch.State = "uncertain"
		} else if len(started) == 0 {
			batch.State = "failed"
		} else {
			batch.State = "partial"
		}
		n.Batches[key] = batch
		if e = c.casSafetyMonotone(ctx, s, n); e == nil {
			return revokeErr
		}
		if !errors.Is(e, ErrVersionConflict) {
			return errors.Join(revokeErr, e)
		}
	}
	return errors.Join(revokeErr, ErrVersionConflict)
}

// revokeBatchEndpoints revokes only endpoints whose RunID is one of the
// affected children. The parent/root caller endpoint never matches this set.
func (c *Coordinator) revokeBatchEndpoints(ctx context.Context, results []ProposalResult) error {
	runs := make(map[string]struct{}, len(results))
	for _, result := range results {
		runs[result.RunID] = struct{}{}
	}
	for i := 0; i < 8; i++ {
		s, err := c.repo.Load(ctx)
		if err != nil {
			return err
		}
		n := s.clone()
		changed := false
		for endpointID, binding := range n.EndpointBindings {
			if _, affected := runs[binding.RunID]; affected && !n.EndpointRevoked[endpointID] {
				n.EndpointRevoked[endpointID] = true
				changed = true
			}
		}
		if !changed {
			return nil
		}
		// This is the same monotone fail-safe write used by single-run
		// compensation. It must remain possible after an earlier uncertain
		// transition poisoned normal lifecycle work.
		if err = c.repo.CompareAndSwap(ctx, s, n); err == nil {
			return nil
		}
		if errors.Is(err, ErrCommitUncertain) {
			c.poisoned.Store(true)
		}
		if !errors.Is(err, ErrVersionConflict) {
			return err
		}
	}
	return ErrVersionConflict
}
func keyFor(results []ProposalResult, keys []string, r ProposalResult) string {
	for i, x := range results {
		if x.RunID == r.RunID {
			return keys[i]
		}
	}
	return ""
}
func batchResult(s Snapshot, b BatchRecord) BatchResult {
	out := BatchResult{BatchID: b.BatchID}
	for _, k := range b.ProposalKeys {
		p := s.Proposals[k]
		out.Results = append(out.Results, ProposalResult{ProposalID: p.ProposalID, RunID: p.RunID, SessionID: p.SessionID, OrderID: p.OrderID, BindingID: p.BindingID, Replayed: true})
		if s.Runs[p.RunID].State != RunRunning {
			out.Partial = true
		}
	}
	return out
}

var _ = time.Time{}
