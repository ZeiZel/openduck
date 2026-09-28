package main

import (
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"openduck/internal/admission"
	"openduck/internal/dshbridge"
	"openduck/internal/macosattest"
	"openduck/internal/macoschannel"
	"openduck/internal/mesh"
	"openduck/internal/platformanchor"
	"openduck/internal/providerrevision"
)

func TestProductionMeshJournalKeysAreDomainSeparatedAndRejectCrossJournalDecrypt(t *testing.T) {
	root := bytes.Repeat([]byte{0x61}, 32)
	meshKey, revisionKey, err := deriveProductionMeshJournalKeys(root)
	if err != nil {
		t.Fatal(err)
	}
	defer zero(meshKey)
	defer zero(revisionKey)
	if len(meshKey) != 32 || len(revisionKey) != 32 || bytes.Equal(meshKey, revisionKey) {
		t.Fatalf("derived journal keys are not independently domain-separated")
	}
	otherMesh, otherRevision, err := deriveProductionMeshJournalKeys(bytes.Repeat([]byte{0x62}, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer zero(otherMesh)
	defer zero(otherRevision)
	if bytes.Equal(meshKey, otherMesh) || bytes.Equal(revisionKey, otherRevision) {
		t.Fatal("root key rotation did not change a derived journal key")
	}

	ctx := context.Background()
	meshPath := filepath.Join(t.TempDir(), "mesh.enc")
	meshRepo, err := mesh.NewEncryptedFileRepository(meshPath, meshKey)
	if err != nil {
		t.Fatal(err)
	}
	meshSnapshot, err := meshRepo.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err = meshRepo.CompareAndSwap(ctx, meshSnapshot, meshSnapshot); err != nil {
		t.Fatal(err)
	}
	if err = meshRepo.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = mesh.NewEncryptedFileRepository(meshPath, revisionKey); err == nil {
		t.Fatal("revision journal key decrypted mesh journal")
	}

	revisionPath := filepath.Join(t.TempDir(), "provider-revisions.enc")
	revisionRepo, err := providerrevision.NewRepository(revisionPath, revisionKey)
	if err != nil {
		t.Fatal(err)
	}
	revisionSnapshot, err := revisionRepo.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err = revisionRepo.CompareAndSwap(ctx, revisionSnapshot, revisionSnapshot); err != nil {
		t.Fatal(err)
	}
	if err = revisionRepo.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = providerrevision.NewRepository(revisionPath, meshKey); err == nil {
		t.Fatal("mesh journal key decrypted provider revision journal")
	}
}

func TestProductionMeshRuntimeComposeFailureClosesBothJournalRepositories(t *testing.T) {
	base := t.TempDir()
	o := productionMeshOptions(t, base)
	roots := openTestAdmissionRoots(t, o)
	defer roots.close()
	writeServiceKey(t, o.state, o.meshStateKeyFile, o.meshStateChannel, 9)

	var meshRepo *mesh.EncryptedFileRepository
	var revisionRepo *providerrevision.Repository
	deps := productionMeshRuntimeDependencies{
		newMeshRepository: func(path string, key []byte) (*mesh.EncryptedFileRepository, error) {
			var err error
			meshRepo, err = mesh.NewEncryptedFileRepository(path, key)
			return meshRepo, err
		},
		newRevisionRepository: func(path string, key []byte) (*providerrevision.Repository, error) {
			var err error
			revisionRepo, err = providerrevision.NewRepository(path, key)
			return revisionRepo, err
		},
		newComposition: func(context.Context, mesh.Repository, *providerrevision.Repository, providerCompositionOptions, providerTransportOptions) (*verifiedMeshComposition, error) {
			return nil, errors.New("composition denied")
		},
	}
	if runtime, err := newProductionMeshRuntimeWith(context.Background(), o, roots, deps); err == nil || runtime != nil {
		t.Fatalf("composition failure runtime=%v err=%v", runtime, err)
	}
	if meshRepo == nil || revisionRepo == nil {
		t.Fatal("factory did not construct both repositories before composition seam")
	}
	if _, err := meshRepo.Load(context.Background()); !errors.Is(err, mesh.ErrRepositoryClosed) {
		t.Fatalf("mesh repository retained after composition failure: %v", err)
	}
	if _, err := revisionRepo.Load(context.Background()); !errors.Is(err, providerrevision.ErrUnavailable) {
		t.Fatalf("revision repository retained after composition failure: %v", err)
	}
}

func TestProductionNativeMCPStartsOnlyAfterMeshCompositionAndCloses(t *testing.T) {
	base := t.TempDir()
	o := productionMeshOptions(t, base)
	o.nativeMCP = true
	roots := openTestAdmissionRoots(t, o)
	defer roots.close()
	writeServiceKey(t, o.state, o.meshStateKeyFile, o.meshStateChannel, 9)
	order := &productionMeshOrder{}
	listener := &nativeMCPListenerSpy{order: order}
	deps := defaultProductionMeshRuntimeDependencies()
	deps.newComposition = func(context.Context, mesh.Repository, *providerrevision.Repository, providerCompositionOptions, providerTransportOptions) (*verifiedMeshComposition, error) {
		order.add("composition")
		return &verifiedMeshComposition{app: &meshApplication{}, close: func() { order.add("composition-close") }}, nil
	}
	deps.startNative = func(_ context.Context, app *meshApplication, got productionAdmissionOptions, _ func(macosattest.SocketBoundary) (nativeMCPListener, error)) (nativeMCPRuntime, error) {
		if app == nil || !got.nativeMCP {
			t.Fatal("native socket started without composed native mode")
		}
		order.add("native-start")
		return listener, nil
	}
	runtime, err := newProductionMeshRuntimeWith(context.Background(), o, roots, deps)
	if err != nil {
		t.Fatal(err)
	}
	if !order.hasInOrder("composition", "native-start") {
		t.Fatalf("bad start order: %v", order.snapshot())
	}
	if err = runtime.Close(); err != nil {
		t.Fatal(err)
	}
	if !order.hasInOrder("native-start", "native-close", "composition-close") || listener.closeCount != 1 {
		t.Fatalf("bad close order: %v close=%d", order.snapshot(), listener.closeCount)
	}
}

type nativeMCPListenerSpy struct {
	order      *productionMeshOrder
	closeCount int
}

func (s *nativeMCPListenerSpy) Accept() (net.Conn, error) { return nil, errors.New("not used") }
func (s *nativeMCPListenerSpy) Close() error              { s.closeCount++; s.order.add("native-close"); return nil }

func TestProductionMeshRuntimeRejectsNilCompositionBeforeListener(t *testing.T) {
	base := t.TempDir()
	o := productionMeshOptions(t, base)
	roots := openTestAdmissionRoots(t, o)
	writeServiceKey(t, o.anchorKeyRoot, o.anchorKeyFile, o.channel, o.keyEpoch)
	writeServiceKey(t, o.state, o.meshStateKeyFile, o.meshStateChannel, 9)

	var order productionMeshOrder
	listenerCalled := false
	meshDeps := defaultProductionMeshRuntimeDependencies()
	meshDeps.newComposition = func(context.Context, mesh.Repository, *providerrevision.Repository, providerCompositionOptions, providerTransportOptions) (*verifiedMeshComposition, error) {
		order.add("composition")
		return nil, nil
	}
	meshDeps.closeRevisionRepository = func(repo *providerrevision.Repository) error {
		order.add("revision-close")
		return repo.Close()
	}
	meshDeps.closeMeshRepository = func(repo *mesh.EncryptedFileRepository) error {
		order.add("mesh-close")
		return repo.Close()
	}
	deps := productionAdmissionDependencies{
		openRoots: func(productionAdmissionOptions) (productionAdmissionRoots, error) { return roots, nil },
		newCheckpoint: func(macoschannel.Config, platformanchor.ProductionPolicy) (admissionCheckpointCapability, error) {
			return admissionCheckpointCapability{load: func(context.Context) (admission.LedgerCheckpoint, error) { return admission.LedgerCheckpoint{}, nil }}, nil
		},
		newMeshRuntime: func(ctx context.Context, options productionAdmissionOptions, opened productionAdmissionRoots) (productionMeshRuntime, error) {
			return newProductionMeshRuntimeWith(ctx, options, opened, meshDeps)
		},
		newAuthority: func(string, admissionCheckpointCapability) (productionAdmissionAuthority, error) {
			return nil, errors.New("authority must not be constructed")
		},
		listen: func(string, string) (net.Listener, error) {
			listenerCalled = true
			return nil, errors.New("listener must not be constructed")
		},
	}
	if err := runProductionAdmissionContext(context.Background(), o, deps); err == nil {
		t.Fatal("nil composition was accepted")
	}
	if listenerCalled {
		t.Fatal("nil composition reached listener construction")
	}
	if got := order.snapshot(); !slices.Equal(got, []string{"composition", "revision-close", "mesh-close"}) {
		t.Fatalf("nil composition cleanup order=%v", got)
	}
}

func TestProductionMeshRuntimeCompositionErrorClosesTransportThenRepositoriesAndJoinsErrors(t *testing.T) {
	base := t.TempDir()
	o := productionMeshOptions(t, base)
	roots := openTestAdmissionRoots(t, o)
	writeServiceKey(t, o.anchorKeyRoot, o.anchorKeyFile, o.channel, o.keyEpoch)
	writeServiceKey(t, o.state, o.meshStateKeyFile, o.meshStateChannel, 9)

	primaryErr := errors.New("composition failed after transport open")
	revisionCleanupErr := errors.New("revision cleanup failed")
	meshCleanupErr := errors.New("mesh cleanup failed")
	var order productionMeshOrder
	listenerCalled := false
	meshDeps := defaultProductionMeshRuntimeDependencies()
	meshDeps.newComposition = func(_ context.Context, meshRepo mesh.Repository, revisionRepo *providerrevision.Repository, _ providerCompositionOptions, _ providerTransportOptions) (*verifiedMeshComposition, error) {
		return &verifiedMeshComposition{close: func() {
			order.add("transport-close")
			if _, err := meshRepo.Load(context.Background()); err != nil {
				t.Fatalf("mesh repository closed before transport: %v", err)
			}
			if _, err := revisionRepo.Load(context.Background()); err != nil {
				t.Fatalf("revision repository closed before transport: %v", err)
			}
		}}, primaryErr
	}
	meshDeps.closeRevisionRepository = func(repo *providerrevision.Repository) error {
		order.add("revision-close")
		return errors.Join(repo.Close(), revisionCleanupErr)
	}
	meshDeps.closeMeshRepository = func(repo *mesh.EncryptedFileRepository) error {
		order.add("mesh-close")
		return errors.Join(repo.Close(), meshCleanupErr)
	}
	deps := productionAdmissionDependencies{
		openRoots: func(productionAdmissionOptions) (productionAdmissionRoots, error) { return roots, nil },
		newCheckpoint: func(macoschannel.Config, platformanchor.ProductionPolicy) (admissionCheckpointCapability, error) {
			return admissionCheckpointCapability{load: func(context.Context) (admission.LedgerCheckpoint, error) { return admission.LedgerCheckpoint{}, nil }}, nil
		},
		newMeshRuntime: func(ctx context.Context, options productionAdmissionOptions, opened productionAdmissionRoots) (productionMeshRuntime, error) {
			return newProductionMeshRuntimeWith(ctx, options, opened, meshDeps)
		},
		newAuthority: func(string, admissionCheckpointCapability) (productionAdmissionAuthority, error) {
			return nil, errors.New("authority must not be constructed")
		},
		listen: func(string, string) (net.Listener, error) {
			listenerCalled = true
			return nil, errors.New("listener must not be constructed")
		},
	}
	_, factoryErr := newProductionMeshRuntimeWith(context.Background(), o, roots, meshDeps)
	if !errors.Is(factoryErr, primaryErr) || !errors.Is(factoryErr, revisionCleanupErr) || !errors.Is(factoryErr, meshCleanupErr) {
		t.Fatalf("factory error did not preserve primary and cleanup failures: %v", factoryErr)
	}
	if got := order.snapshot(); !slices.Equal(got, []string{"transport-close", "revision-close", "mesh-close"}) {
		t.Fatalf("composition failure cleanup order=%v", got)
	}

	// Reopen fresh roots because the direct factory consumed and closed both
	// journal repositories; the admission path must reject the same adversarial
	// contract before it can bind a listener.
	order.events = nil
	if err := runProductionAdmissionContext(context.Background(), o, deps); err == nil {
		t.Fatal("composition error was accepted")
	}
	if listenerCalled {
		t.Fatal("composition error reached listener construction")
	}
	if got := order.snapshot(); !slices.Equal(got, []string{"transport-close", "revision-close", "mesh-close"}) {
		t.Fatalf("admission cleanup order=%v", got)
	}
}

type productionMeshOrder struct {
	mu     sync.Mutex
	events []string
}

func (o *productionMeshOrder) add(event string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.events = append(o.events, event)
}
func (o *productionMeshOrder) snapshot() []string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]string(nil), o.events...)
}
func (o *productionMeshOrder) hasInOrder(want ...string) bool {
	got := o.snapshot()
	i := 0
	for _, event := range got {
		if i < len(want) && event == want[i] {
			i++
		}
	}
	return i == len(want)
}

type productionMeshRuntimeSpy struct {
	app    *meshApplication
	order  *productionMeshOrder
	cancel context.CancelFunc
	mu     sync.Mutex
	closed int
}

func (s *productionMeshRuntimeSpy) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed++
	if s.order != nil {
		s.order.add("mesh-close")
	}
	return nil
}
func (s *productionMeshRuntimeSpy) meshApplication() (*meshApplication, error) {
	if s.order != nil {
		s.order.add("mesh-ui")
	}
	if s.cancel != nil {
		s.cancel()
	}
	return s.app, nil
}
func (s *productionMeshRuntimeSpy) closeCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed
}

type orderedAdmissionAuthority struct{ order *productionMeshOrder }

func (*orderedAdmissionAuthority) AdmitCloud(context.Context, []byte) (dshbridge.CloudAdmission, error) {
	return dshbridge.CloudAdmission{ID: "adm_abcdefgh", Status: "accepted"}, nil
}
func (a *orderedAdmissionAuthority) Close() error {
	a.order.add("authority-close")
	return nil
}

func productionMeshOptions(t *testing.T, base string) productionAdmissionOptions {
	t.Helper()
	o := productionOptions(t, base)
	digest := "sha256:" + string(bytes.Repeat([]byte("a"), 64))
	o.productionMesh = true
	o.meshStateKeyFile, o.meshStateChannel = "mesh-state.key", "mesh-state"
	o.providerComposition = providerCompositionOptions{Root: "/Library/Application Support/OpenDuck/providers/inactive", BundleDigest: digest, TrustDigest: digest, OwnerTrustDigest: digest, OwnerUID: 0, OwnerGID: o.localGID}
	o.providerTransport = providerTransportOptions{enabled: true, localRelease: o.localRelease, uid: o.localUID, gid: o.localGID, channelGID: o.localGID + 11, keyEpoch: 3, numeric: map[string]bool{"provider-transport-controller-uid": true, "provider-transport-controller-gid": true, "provider-transport-channel-gid": true, "provider-transport-key-epoch": true}}
	if err := validateProductionMeshOptions(o); err != nil {
		t.Fatalf("complete production mesh options rejected: %v", err)
	}
	return o
}

func TestProductionMeshStartupRunsRecoveryBeforeListenerAndClosesOnce(t *testing.T) {
	requireLoopbackTCP(t)
	base := t.TempDir()
	o := productionMeshOptions(t, base)
	roots := openTestAdmissionRoots(t, o)
	writeServiceKey(t, o.anchorKeyRoot, o.anchorKeyFile, o.channel, o.keyEpoch)
	order := &productionMeshOrder{}
	originalClose := roots.close
	roots.close = func() { order.add("roots-close"); originalClose() }
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runtime := &productionMeshRuntimeSpy{app: &meshApplication{}, order: order, cancel: cancel}
	listenerBound := false
	runtimeConstructed := 0
	deps := productionAdmissionDependencies{
		openRoots: func(productionAdmissionOptions) (productionAdmissionRoots, error) { return roots, nil },
		newCheckpoint: func(macoschannel.Config, platformanchor.ProductionPolicy) (admissionCheckpointCapability, error) {
			order.add("anchor-probe")
			return admissionCheckpointCapability{load: func(context.Context) (admission.LedgerCheckpoint, error) { return admission.LedgerCheckpoint{}, nil }}, nil
		},
		newMeshRuntime: func(context.Context, productionAdmissionOptions, productionAdmissionRoots) (productionMeshRuntime, error) {
			runtimeConstructed++
			order.add("mesh-recovery")
			return runtime, nil
		},
		listen: func(network, address string) (net.Listener, error) {
			if !order.hasInOrder("anchor-probe", "mesh-recovery") {
				t.Fatal("listener bound before mesh recovery")
			}
			listenerBound = true
			return net.Listen(network, address)
		},
		newAuthority: func(string, admissionCheckpointCapability) (productionAdmissionAuthority, error) {
			order.add("authority")
			return &orderedAdmissionAuthority{order: order}, nil
		},
		shutdownTimeout: time.Second,
	}
	if err := runProductionAdmissionContext(ctx, o, deps); err != nil {
		t.Fatalf("production mesh startup=%v events=%v", err, order.snapshot())
	}
	if !listenerBound || runtimeConstructed != 1 || runtime.closeCount() != 1 {
		t.Fatalf("listener=%v runtime constructions=%d closes=%d events=%v", listenerBound, runtimeConstructed, runtime.closeCount(), order.snapshot())
	}
	if !order.hasInOrder("anchor-probe", "mesh-recovery", "authority", "mesh-ui", "authority-close", "mesh-close", "roots-close") {
		t.Fatalf("production mesh lifecycle order=%v", order.snapshot())
	}
}

func TestProductionMeshRuntimeFailurePreventsListenerAndClosesReturnedCapability(t *testing.T) {
	base := t.TempDir()
	o := productionMeshOptions(t, base)
	roots := openTestAdmissionRoots(t, o)
	writeServiceKey(t, o.anchorKeyRoot, o.anchorKeyFile, o.channel, o.keyEpoch)
	defer roots.close()
	runtime := &productionMeshRuntimeSpy{app: &meshApplication{}}
	listenerCalled := false
	deps := productionAdmissionDependencies{
		openRoots: func(productionAdmissionOptions) (productionAdmissionRoots, error) { return roots, nil },
		newCheckpoint: func(macoschannel.Config, platformanchor.ProductionPolicy) (admissionCheckpointCapability, error) {
			return admissionCheckpointCapability{load: func(context.Context) (admission.LedgerCheckpoint, error) { return admission.LedgerCheckpoint{}, nil }}, nil
		},
		newMeshRuntime: func(context.Context, productionAdmissionOptions, productionAdmissionRoots) (productionMeshRuntime, error) {
			return runtime, errors.New("recovery denied")
		},
		newAuthority: func(string, admissionCheckpointCapability) (productionAdmissionAuthority, error) {
			return &orderedAdmissionAuthority{}, nil
		},
		listen: func(string, string) (net.Listener, error) {
			listenerCalled = true
			return nil, errors.New("must not listen")
		},
	}
	err := runProductionAdmissionContext(context.Background(), o, deps)
	if err == nil {
		t.Fatal("failed mesh runtime was accepted")
	}
	if listenerCalled || runtime.closeCount() != 1 {
		t.Fatalf("listener=%v runtime closes=%d err=%v", listenerCalled, runtime.closeCount(), err)
	}
}

func TestProductionMeshStateKeyFailureLeavesNoJournalFiles(t *testing.T) {
	base := t.TempDir()
	o := productionMeshOptions(t, base)
	roots := openTestAdmissionRoots(t, o)
	defer roots.close()
	if runtime, err := newProductionMeshRuntime(context.Background(), o, roots); err == nil || runtime != nil {
		t.Fatalf("missing mesh key runtime=%v err=%v", runtime, err)
	}
	for _, name := range []string{"mesh.enc", "provider-revisions.enc"} {
		if _, err := os.Stat(filepath.Join(o.state, name)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("state key preflight created %s: %v", name, err)
		}
	}
}
