package nativemcp

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"

	"openduck/internal/mesh"
	"openduck/internal/providerrevision"
)

// ProcessAttestor is supplied by the Controller's platform boundary. It must
// bind the native host process (and its parent chain where supported) to the
// exact provider/profile session. A nil attestor fails closed.
type ProcessAttestor interface {
	VerifyNativeMCPPeer(context.Context, SessionContract, PeerIdentity) error
}

// AttestedBackend is a per-connection Controller capability. SocketServer
// binds the process proof obtained from the accepted Unix peer; it cannot be
// reused as a caller-supplied bearer on another connection.
type AttestedBackend interface {
	Backend
	BindProcessAttestor(ProcessAttestor) Backend
}

// ControllerBackend converts only the fixed MCP tool union into typed
// Coordinator requests. It never accepts a mesh EndpointRequest from a host
// and never exposes a provider endpoint, credential, or generic RPC method.
type ControllerBackend struct {
	Coordinator *mesh.Coordinator
	Revisions   *providerrevision.Service
	Attestor    ProcessAttestor
	Now         func() time.Time
}

// BindProcessAttestor returns a per-running-host copy. The base Controller
// composition never stores a mutable process capability; Launcher binds the
// attestor returned by the exact host launch for this one stdio session only.
func (b *ControllerBackend) BindProcessAttestor(attestor ProcessAttestor) Backend {
	if b == nil || attestor == nil {
		return nil
	}
	copy := *b
	copy.Attestor = attestor
	return &copy
}

func (b *ControllerBackend) now() time.Time {
	if b != nil && b.Now != nil {
		return b.Now().UTC()
	}
	return time.Now().UTC()
}

func (b *ControllerBackend) Authorize(ctx context.Context, contract SessionContract, peer PeerIdentity) error {
	if b == nil || b.Coordinator == nil || b.Revisions == nil || b.Attestor == nil || contract.Validate(b.now()) != nil || peer.Provider != contract.Provider || peer.PeerID != contract.PeerID || b.Attestor.VerifyNativeMCPPeer(ctx, contract, peer) != nil {
		return ErrUnauthorized
	}
	a, err := b.Revisions.Association(ctx, contract.UISessionID, contract.UIChannelID)
	if err != nil || a.SessionID != contract.UISessionID || a.ChannelID != contract.UIChannelID || a.RootRunID != contract.RootRunID || a.RunID != contract.RunID || a.MeshSessionID != contract.MeshSessionID || a.AttemptID != contract.AttemptID || a.PeerID != contract.PeerID || a.EndpointID != contract.EndpointID || a.EndpointGeneration != contract.Generation || a.RevisionID != contract.RevisionID || !a.ExpiresAt.Equal(contract.ExpiresAt) {
		return ErrUnauthorized
	}
	registry, installed, err := b.Revisions.Registry(ctx)
	if err != nil || installed.Bundle.RevisionID != contract.RevisionID {
		return ErrUnauthorized
	}
	profile, err := registry.Lookup(ctx, contract.ProfileID, b.now())
	if err != nil || string(profile.Provider) != contract.Provider || profile.Revision == "" {
		return ErrUnauthorized
	}
	endpoint, err := b.Coordinator.EndpointBinding(ctx, contract.EndpointID)
	if err != nil || endpoint.Audience != "ui" || endpoint.RootRunID != contract.RootRunID || endpoint.RunID != contract.RunID || endpoint.SessionID != contract.MeshSessionID || endpoint.AttemptID != contract.AttemptID || endpoint.PeerID != contract.PeerID || endpoint.Generation != contract.Generation || !endpoint.ExpiresAt.Equal(contract.ExpiresAt) {
		return ErrUnauthorized
	}
	return nil
}

func (b *ControllerBackend) Invoke(ctx context.Context, contract SessionContract, peer PeerIdentity, operation string, raw json.RawMessage) (json.RawMessage, error) {
	if !knownOperation(operation) || b.Authorize(ctx, contract, peer) != nil {
		return nil, ErrUnauthorized
	}
	digest := requestDigest(raw)
	nonce, err := requestNonce()
	if err != nil {
		return nil, ErrUnauthorized
	}
	root, err := b.Coordinator.AuthorizeUIOperation(ctx, mesh.EndpointRequest{EndpointID: contract.EndpointID, PeerID: contract.PeerID, Audience: "ui", Nonce: nonce, MessageDigest: digest}, "mesh-"+operation, digest)
	if err != nil {
		return nil, ErrUnauthorized
	}
	endpoint := func(d string) mesh.EndpointRequest {
		n, e := requestNonce()
		if e != nil {
			return mesh.EndpointRequest{}
		}
		return mesh.EndpointRequest{EndpointID: root.EndpointID, PeerID: root.PeerID, Audience: "mesh", Nonce: n, MessageDigest: d}
	}
	switch operation {
	case "spawn":
		proposal, err := mesh.DecodeSpawnProposal(raw)
		if err != nil {
			return nil, ErrInvalid
		}
		result, err := b.Coordinator.ProposeSpawn(ctx, mesh.ProposalRequest{Endpoint: endpoint(jsonDigest(proposal)), Proposal: proposal})
		if err != nil {
			return nil, err
		}
		return json.Marshal(result)
	case "spawnBatch":
		var in struct {
			Proposals []json.RawMessage `json:"proposals"`
		}
		if decodeExact(raw, &in) != nil {
			return nil, ErrInvalid
		}
		proposals := make([]mesh.SpawnProposal, 0, len(in.Proposals))
		for _, r := range in.Proposals {
			p, e := mesh.DecodeSpawnProposal(r)
			if e != nil {
				return nil, ErrInvalid
			}
			proposals = append(proposals, p)
		}
		result, err := b.Coordinator.ProposeSpawnBatch(ctx, mesh.BatchProposalRequest{Endpoint: endpoint(jsonDigest(proposals)), Proposals: proposals})
		if err != nil {
			return nil, err
		}
		return json.Marshal(result)
	case "listProfiles":
		var in struct {
			RevisionRef string `json:"revision_ref"`
		}
		if decodeExact(raw, &in) != nil {
			return nil, ErrInvalid
		}
		result, err := b.Coordinator.ListProfiles(ctx, mesh.ListProfilesRequest{Endpoint: endpoint(jsonDigest("listProfiles:" + in.RevisionRef)), RevisionRef: in.RevisionRef})
		if err != nil {
			return nil, err
		}
		return json.Marshal(result)
	}
	var in map[string]string
	if decodeExact(raw, &in) != nil {
		return nil, ErrInvalid
	}
	target := in["run_id"]
	if operation == "list" {
		target = in["root_id"]
	}
	req := mesh.OperationRequest{Target: mesh.TargetRequest{Endpoint: endpoint(""), TargetRunID: target, Operation: operation}, InputRef: in["input_ref"], RevisionRef: in["revision_ref"], ReasonRef: in["reason_ref"]}
	d, err := req.Digest()
	if err != nil {
		return nil, ErrInvalid
	}
	req.Target.Endpoint.MessageDigest = d
	switch operation {
	case "send":
		err = b.Coordinator.Send(ctx, req)
	case "steer":
		err = b.Coordinator.Steer(ctx, req)
	case "cancel":
		err = b.Coordinator.Cancel(ctx, req)
	case "wait":
		var v mesh.SessionStatus
		v, err = b.Coordinator.Wait(ctx, req)
		if err == nil {
			return json.Marshal(v)
		}
	case "collect":
		var v mesh.ResultEnvelope
		v, err = b.Coordinator.Collect(ctx, req)
		if err == nil {
			return json.Marshal(v)
		}
	case "list":
		var v []mesh.RunProjection
		v, err = b.Coordinator.List(ctx, req)
		if err == nil {
			return json.Marshal(v)
		}
	case "status":
		var v mesh.SessionStatus
		v, err = b.Coordinator.Status(ctx, req)
		if err == nil {
			return json.Marshal(v)
		}
	case "result":
		var v mesh.ResultEnvelope
		v, err = b.Coordinator.Result(ctx, req)
		if err == nil {
			return json.Marshal(v)
		}
	default:
		return nil, ErrInvalid
	}
	if err != nil {
		return nil, err
	}
	return json.Marshal(map[string]string{"status": "accepted"})
}

func knownOperation(v string) bool {
	for _, operation := range childOperations {
		if v == operation {
			return true
		}
	}
	return false
}
func requestDigest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}
func jsonDigest(value any) string { raw, _ := json.Marshal(value); return requestDigest(raw) }
func requestNonce() (string, error) {
	var raw [18]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return "mcp-" + hex.EncodeToString(raw[:]), nil
}

var _ Backend = (*ControllerBackend)(nil)
