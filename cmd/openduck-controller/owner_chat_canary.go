package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"openduck/internal/codexbroker"
	"openduck/internal/codexruntime"
	"openduck/internal/macoschannel"
	"openduck/internal/ownergrant"
	"openduck/internal/platformanchor"
	"openduck/internal/servicekey"
)

var errOwnerChatUnavailable = errors.New("owner chat unavailable")

const liveEgressCanaryChatID = "openduck-live-egress-canary"

type ownerChatComposition struct {
	service   *codexruntime.ChatRunService
	connector *codexbroker.ProductionConnector
}

func (c ownerChatComposition) Close(ctx context.Context) error {
	var first error
	if c.service != nil {
		first = c.service.Close()
	}
	if c.connector != nil {
		client, err := c.connector.Client()
		if err != nil {
			if first == nil {
				first = err
			}
		} else if err = client.Close(ctx); err != nil && first == nil {
			first = err
		}
	}
	return first
}

// composeOwnerChat accepts only authenticated typed capabilities. Runtime
// process/profile details are broker-owned and cannot enter this boundary.
func composeOwnerChat(ctx context.Context, anchor *platformanchor.ProductionClient, connector *codexbroker.ProductionConnector, ledgerPath string, ledgerKey []byte, authorizer codexruntime.OwnerAuthenticator, gate codexruntime.ProcessGate) (ownerChatComposition, error) {
	if anchor == nil || connector == nil || ledgerPath == "" || len(ledgerKey) != 32 || authorizer == nil || gate == nil {
		return ownerChatComposition{}, errOwnerChatUnavailable
	}
	cp, err := platformanchor.NewProductionChatLedgerCheckpoint(anchor)
	if err != nil {
		return ownerChatComposition{}, errOwnerChatUnavailable
	}
	client, err := connector.Client()
	if err != nil {
		return ownerChatComposition{}, errOwnerChatUnavailable
	}
	transport, err := codexruntime.NewBrokerChatTransportForProduction(client)
	if err != nil {
		return ownerChatComposition{}, errOwnerChatUnavailable
	}
	ledger, err := platformanchor.NewProductionEncryptedChatRunLedger(ledgerPath, ledgerKey, cp)
	if err != nil {
		return ownerChatComposition{}, errOwnerChatUnavailable
	}
	canary, err := codexruntime.NewBoundOwnerCanary(transport, authorizer, gate, nil)
	if err != nil {
		return ownerChatComposition{}, errOwnerChatUnavailable
	}
	service, err := codexruntime.NewChatRunService(canary, ledger)
	if err != nil {
		return ownerChatComposition{}, errOwnerChatUnavailable
	}
	_ = ctx
	return ownerChatComposition{service: service, connector: connector}, nil
}

type checkpointGrant struct {
	mu     sync.Mutex
	public ed25519.PublicKey
	root   string
	prefix string
	queue  string
}

func (g *checkpointGrant) Authorize(_ context.Context) error {
	return codexruntime.ErrOwnerAuthorization
}

// AuthorizeOrder validates and consumes the controller-owned, sealed owner
// capability only after the HTTP order is available. The checkpoint used for
// ledger durability is intentionally not an owner authenticator.
func (g *checkpointGrant) AuthorizeOrder(ctx context.Context, order codexruntime.GeneralChatOrder) error {
	if g == nil {
		return codexruntime.ErrOwnerAuthorization
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	digest, err := codexruntime.GeneralChatOrderDigest(order)
	if err != nil {
		return codexruntime.ErrOwnerAuthorization
	}
	if g.root == "" || filepath.IsAbs(g.root) == false || filepath.Clean(g.root) != g.root || g.prefix == "" || filepath.Base(g.prefix) != g.prefix {
		return codexruntime.ErrOwnerAuthorization
	}
	requestID := codexruntime.ApprovalRequestID(ctx)
	if requestID != "" {
		if err := ownergrant.VerifyAndConsume(g.root, g.prefix, requestID, g.public, digest, order.ChatID, time.Now().UTC()); err == nil {
			return nil
		}
		// A pending record for this exact request is an expected wait state. A
		// different order is rejected without consuming the signed capability.
		store, err := ownergrant.OpenCurrentStore(g.queue)
		if err != nil {
			return codexruntime.ErrOwnerAuthorization
		}
		pending, err := store.Read(requestID, time.Now().UTC())
		_ = store.Close()
		if err == nil && pending.OrderDigest == digest && pending.ChatID == order.ChatID {
			return codexruntime.ApprovalRequiredError{RequestID: pending.RequestID, OrderDigest: pending.OrderDigest, ExpiresAt: pending.ExpiresAt}
		}
		return codexruntime.ErrOwnerAuthorization
	}
	if g.queue == "" {
		return codexruntime.ErrOwnerAuthorization
	}
	pending, requestErr := ownergrant.Request(g.queue, digest, order.ChatID, time.Now().UTC())
	if requestErr == nil || errors.Is(requestErr, ownergrant.ErrApprovalRequired) {
		return codexruntime.ApprovalRequiredError{RequestID: pending.RequestID, OrderDigest: pending.OrderDigest, ExpiresAt: pending.ExpiresAt}
	}
	return codexruntime.ErrOwnerAuthorization
}

// newDefaultOwnerChat performs the real production composition from verified
// roots and an authenticated anchor client. No path enters the broker API.
func newDefaultOwnerChat(ctx context.Context, o productionAdmissionOptions, cap admissionCheckpointCapability, roots productionAdmissionRoots) (ownerChatService, func(), error) {
	if cap.client == nil || roots.brokerSocket == nil || roots.brokerKey == nil || roots.brokerRelease == nil {
		return nil, nil, errOwnerChatUnavailable
	}
	key, err := servicekey.New(roots.brokerKey, servicekey.Policy{FileName: o.brokerKeyFile, Channel: o.brokerChannel, OwnerUID: o.localUID, OwnerGID: o.localGID, Mode: 0600, RootUID: o.localUID, RootGID: o.localGID, RootMode: 0700})
	if err != nil {
		return nil, nil, errOwnerChatUnavailable
	}
	peerUID, peerGID := o.brokerUID, o.brokerGID
	cfg := macoschannel.Config{Contract: macoschannel.SocketContract{Channel: o.brokerChannel, LocalRole: o.brokerLocalRole, PeerRole: o.brokerPeerRole, SocketPath: o.brokerSocket, SocketRoot: o.brokerSocketRoot, ExpectedPeerUID: &peerUID, ExpectedPeerGID: &peerGID, ExpectedSocketRootUID: o.brokerUID, ExpectedSocketRootGID: o.brokerChannelGID, ExpectedSocketRootMode: 0750, ExpectedSocketUID: o.brokerUID, ExpectedSocketGID: o.brokerChannelGID, ExpectedSocketMode: 0660}, LocalRelease: o.localRelease, PeerRelease: o.brokerPeerRelease, ReleaseRoot: roots.brokerRelease, SocketRootFD: roots.brokerSocket, BinaryName: "openduck-controller", KeySource: key, ExpectedReleaseRootUID: 0, ExpectedReleaseRootGID: o.localGID, ExpectedReleaseRootMode: 0550, ExpectedManifestMode: 0440, ExpectedBinaryMode: 0550}
	dial, err := macoschannel.NewDialer(cfg)
	if err != nil {
		return nil, nil, errOwnerChatUnavailable
	}
	conn, err := dial.Dial(ctx)
	if err != nil {
		return nil, nil, errOwnerChatUnavailable
	}
	runtimeDigest, ok := exactDigest(o.brokerRuntimeDigest)
	if !ok {
		_ = conn.Close()
		return nil, nil, errOwnerChatUnavailable
	}
	brokerBinaryDigest, ok := exactDigest(o.brokerPeerRelease.BinaryDigest)
	if !ok {
		_ = conn.Close()
		return nil, nil, errOwnerChatUnavailable
	}
	policyDigest, ok := exactDigest(o.brokerPolicyDigest)
	if !ok {
		_ = conn.Close()
		return nil, nil, errOwnerChatUnavailable
	}
	releaseDigest, ok := exactDigest(o.brokerReleaseDigest)
	if !ok {
		_ = conn.Close()
		return nil, nil, errOwnerChatUnavailable
	}
	socketDigest, ok := exactDigest(o.brokerSocketDigest)
	if !ok {
		_ = conn.Close()
		return nil, nil, errOwnerChatUnavailable
	}
	egressReleaseDigest, ok := exactDigest(o.brokerEgressReleaseDigest)
	if !ok {
		_ = conn.Close()
		return nil, nil, errOwnerChatUnavailable
	}
	egressSocketDigest, ok := exactDigest(o.brokerEgressSocketDigest)
	if !ok {
		_ = conn.Close()
		return nil, nil, errOwnerChatUnavailable
	}
	identity := codexbroker.ExpectedRuntimeIdentity{RuntimeID: o.brokerRuntimeID, BrokerBinaryDigest: brokerBinaryDigest, RuntimeBinaryDigest: runtimeDigest, PolicyDigest: policyDigest, BrokerReleaseDigest: releaseDigest, BrokerSocketDigest: socketDigest, PeerUID: o.localUID, PeerGID: o.localGID, RuntimeUID: o.brokerUID, RuntimeGID: o.brokerGID, ExpectedEgressUID: o.egressUID, ExpectedEgressGID: o.egressGID, ExpectedEgressReleaseDigest: egressReleaseDigest, ExpectedEgressSocketDigest: egressSocketDigest, KeyEpoch: o.brokerKeyEpoch, Channel: o.brokerChannel, LocalRole: o.brokerPeerRole, PeerRole: o.brokerLocalRole}
	identity.BindingDigest = identity.ComputeBindingDigest(conn.Evidence())
	connector, err := codexbroker.NewProductionConnector(conn, identity)
	if err != nil {
		_ = conn.Close()
		return nil, nil, errOwnerChatUnavailable
	}
	client, err := connector.Client()
	if err != nil {
		return nil, nil, errOwnerChatUnavailable
	}
	probe, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if _, err = client.Attestation(probe); err != nil {
		return nil, nil, errOwnerChatUnavailable
	}
	if _, err = client.Inventory(probe); err != nil {
		return nil, nil, errOwnerChatUnavailable
	}
	cp, err := platformanchor.NewProductionChatLedgerCheckpoint(cap.client)
	if err != nil {
		return nil, nil, errOwnerChatUnavailable
	}
	ledgerKey, epoch, err := key.LoadContext(ctx, o.brokerChannel)
	if err != nil || epoch != o.brokerKeyEpoch {
		return nil, nil, errOwnerChatUnavailable
	}
	ledger, err := platformanchor.NewProductionEncryptedChatRunLedger(filepath.Join(o.state, "chat-ledger.enc"), ledgerKey, cp)
	for i := range ledgerKey {
		ledgerKey[i] = 0
	}
	if err != nil {
		return nil, nil, errOwnerChatUnavailable
	}
	transport, err := codexruntime.NewBrokerChatTransportForProduction(client)
	if err != nil {
		return nil, nil, errOwnerChatUnavailable
	}
	ownerPublic, err := ownergrant.LoadPublicKey(roots.key, o.ownerPublicKeyFile, int(o.localUID), int(o.localGID))
	if err != nil {
		return nil, nil, errOwnerChatUnavailable
	}
	grant := &checkpointGrant{public: append(ed25519.PublicKey(nil), ownerPublic...), root: filepath.Join("/Library/Application Support/OpenDuck", "operator", "owner-capabilities"), prefix: o.ownerCapabilityFile, queue: filepath.Join(roots.statePath, "owner-queue")}
	canary, err := codexruntime.NewBoundOwnerCanary(transport, grant, codexruntime.NewLocalProcessGate(), nil)
	for i := range ownerPublic {
		ownerPublic[i] = 0
	}
	if err != nil {
		return nil, nil, errOwnerChatUnavailable
	}
	service, err := codexruntime.NewChatRunService(canary, ledger)
	if err != nil {
		return nil, nil, errOwnerChatUnavailable
	}
	releaseID := strings.TrimPrefix(o.brokerRuntimeID, "codex-runtime-")
	bound := newCanaryEvidenceService(service, filepath.Join(roots.statePath, "canary-proof.json"), releaseID)
	if bound == nil {
		_ = service.Close()
		_ = client.Close(context.Background())
		zero(grant.public)
		return nil, nil, errOwnerChatUnavailable
	}
	return bound, func() { _ = service.Close(); _ = client.Close(context.Background()); zero(grant.public) }, nil
}

type canaryEvidenceService struct {
	inner     *codexruntime.ChatRunService
	proofPath string
	releaseID string
	mu        sync.Mutex
	requests  map[string]string
}

func newCanaryEvidenceService(inner *codexruntime.ChatRunService, proofPath, releaseID string) *canaryEvidenceService {
	if inner == nil || !validCanaryReleaseID(releaseID) || !filepath.IsAbs(proofPath) || filepath.Base(proofPath) != "canary-proof.json" {
		return nil
	}
	return &canaryEvidenceService{inner: inner, proofPath: proofPath, releaseID: releaseID, requests: map[string]string{}}
}

func (s *canaryEvidenceService) Start(ctx context.Context, order codexruntime.GeneralChatOrder) (codexruntime.AssistantTurnResult, error) {
	digest, err := codexruntime.GeneralChatOrderDigest(order)
	if err != nil {
		return codexruntime.AssistantTurnResult{}, err
	}
	result, err := s.inner.Start(ctx, order)
	if err == nil && result.ChatID != "" && order.ChatID == liveEgressCanaryChatID {
		s.mu.Lock()
		s.requests[result.ChatID] = digest
		s.mu.Unlock()
	}
	return result, err
}

func (s *canaryEvidenceService) Get(ctx context.Context, runID string) (codexruntime.AssistantTurnResult, error) {
	result, err := s.inner.Get(ctx, runID)
	if err != nil || result.State != "completed" || result.Validate() != nil {
		return result, err
	}
	s.mu.Lock()
	requestDigest := s.requests[runID]
	s.mu.Unlock()
	if requestDigest == "" {
		return result, nil
	}
	if err := writeCanaryProof(s.proofPath, s.releaseID, currentControllerBootID(), runID, liveEgressCanaryChatID, requestDigest, codexruntime.ChatAnswerDigest(result.Answer)); err != nil {
		return codexruntime.AssistantTurnResult{}, errOwnerChatUnavailable
	}
	return result, nil
}

func (s *canaryEvidenceService) Cancel(ctx context.Context, runID string) error {
	return s.inner.Cancel(ctx, runID)
}
func (s *canaryEvidenceService) Close() error { return s.inner.Close() }

func writeCanaryProof(path, releaseID, bootID, runID, chatID, requestDigest, resultDigest string) error {
	if !validCanaryReleaseID(releaseID) || bootID == "" || strings.ContainsAny(bootID, "\r\n\x00") || runID == "" || chatID != liveEgressCanaryChatID || !validCanaryDigest(requestDigest) || !validCanaryDigest(resultDigest) {
		return errOwnerChatUnavailable
	}
	proof := struct {
		Schema        string `json:"schema"`
		ReleaseID     string `json:"release_id"`
		BootID        string `json:"boot_id"`
		RunID         string `json:"run_id"`
		ChatID        string `json:"chat_id"`
		RequestDigest string `json:"request_digest"`
		ResultDigest  string `json:"result_digest"`
	}{"openduck-canary-proof.v1", releaseID, bootID, runID, chatID, requestDigest, resultDigest}
	b, err := json.Marshal(proof)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".canary-proof-")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(b)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err == nil {
		err = os.Rename(name, path)
	}
	if err != nil {
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	err = d.Sync()
	_ = d.Close()
	return err
}

func currentControllerBootID() string {
	b, err := exec.Command("/usr/sbin/sysctl", "-n", "kern.boottime").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func validCanaryReleaseID(s string) bool {
	return len(s) == 64 && strings.Trim(s, "0123456789abcdef") == ""
}
func validCanaryDigest(s string) bool {
	return len(s) == 71 && strings.HasPrefix(s, "sha256:") && strings.Trim(s[7:], "0123456789abcdef") == ""
}
