package main

import (
	"context"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"openduck/internal/admission"
	"openduck/internal/codexruntime"
	"openduck/internal/core"
	"openduck/internal/dshbridge"
	"openduck/internal/dshbridgehttp"
	"openduck/internal/harness"
	"openduck/internal/harnesshttp"
	"openduck/internal/localpd"
	"openduck/internal/macosattest"
	"openduck/internal/macoschannel"
	"openduck/internal/mesh"
	"openduck/internal/meshui"
	"openduck/internal/platformanchor"
	"openduck/internal/providerbridge"
	"openduck/internal/providerrevision"
	"openduck/internal/sensor"
	"openduck/internal/servicekey"
	"openduck/internal/synthetic"
	"openduck/internal/syntheticadmission"
	"openduck/internal/verifiedroot"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"time"
)

type productionAdmissionOptions struct {
	enabled                                                          bool
	ownerChat                                                        bool
	ownerCapabilityFile, ownerPublicKeyFile                          string
	state, listen                                                    string
	anchorSocket, anchorSocketRoot, anchorKeyRoot, anchorKeyFile     string
	controllerReleaseRoot                                            string
	channel, localRole, peerRole                                     string
	localRelease, peerRelease                                        macoschannel.ReleasePin
	localUID, localGID, peerUID, peerGID                             uint32
	channelGID                                                       uint32
	keyEpoch                                                         uint64
	brokerSocket, brokerSocketRoot, brokerKeyRoot, brokerReleaseRoot string
	brokerKeyFile, brokerChannel, brokerLocalRole, brokerPeerRole    string
	brokerLocalRelease, brokerPeerRelease                            macoschannel.ReleasePin
	brokerUID, brokerGID, brokerChannelGID, egressUID, egressGID     uint32
	brokerKeyEpoch                                                   uint64
	brokerRuntimeID, brokerRuntimeDigest, brokerPolicyDigest         string
	brokerReleaseDigest, brokerSocketDigest                          string
	brokerEgressReleaseDigest, brokerEgressSocketDigest              string
	brokerNumeric                                                    map[string]bool
	numeric                                                          map[string]bool
	productionMesh                                                   bool
	nativeMCP                                                        bool
	providerComposition                                              providerCompositionOptions
	providerTransport                                                providerTransportOptions
	meshStateKeyFile, meshStateChannel                               string
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		// Keep operational failures generic; details stay out of process output.
		os.Exit(1)
	}
}

func run(args []string) error {
	fs := flag.NewFlagSet("openduck-controller", flag.ContinueOnError)
	addr := fs.String("listen", "127.0.0.1:8788", "loopback listen address")
	statePath := fs.String("state", ".openduck/controller.enc", "encrypted controller state path")
	callbackEnabled := fs.Bool("callback-enabled", false, "enable authenticated callback transport (requires explicit origin)")
	callbackOrigin := fs.String("callback-origin", "", "exact callback browser origin")
	originProbeEnabled := fs.Bool("origin-probe", false, "enable non-authoritative CORS origin probe")
	sensorEnabled := fs.Bool("sensor-enabled", false, "enable authenticated synthetic OpenClaw sensor ingress")
	syntheticEnabled := fs.Bool("synthetic", false, "enable provider-free synthetic mode (off by default)")
	commandCenterEnabled := fs.Bool("command-center", false, "serve the loopback synthetic Command Center (requires -synthetic)")
	ownerChat := fs.Bool("owner-chat", false, "compose authenticated typed owner chat with production admission")
	commandCenterOrigin := fs.String("command-center-origin", "", "exact loopback Command Center origin (defaults to the served listener origin)")
	commandCenterDir := fs.String("command-center-dir", "deploy/deepseek-harness/command-center", "static Command Center directory")
	prod := productionAdmissionOptions{numeric: map[string]bool{}}
	prod.brokerNumeric = map[string]bool{}
	providerComposition := providerCompositionOptions{OwnerUID: 0}
	providerTransport := providerTransportOptions{numeric: map[string]bool{}}
	providerOwnerUID := uint(0)
	providerOwnerGID := uint(0)
	fs.StringVar(&providerComposition.Root, "provider-artifact-root", "", "absolute root containing fixed installed provider artifacts")
	fs.StringVar(&providerComposition.BundleDigest, "provider-bundle-digest", "", "exact SHA-256 digest of provider-bundle.json")
	fs.StringVar(&providerComposition.TrustDigest, "provider-trust-digest", "", "exact SHA-256 digest of provider-trust.json")
	fs.StringVar(&providerComposition.OwnerTrustDigest, "provider-owner-trust-digest", "", "exact SHA-256 digest of controller-owner-ed25519.json")
	fs.UintVar(&providerOwnerUID, "provider-artifact-owner-uid", 0, "must be 0 for root-owned installed provider artifacts")
	fs.UintVar(&providerOwnerGID, "provider-artifact-owner-gid", 0, "required _openduck GID for installed provider artifacts")
	fs.BoolVar(&providerTransport.enabled, "provider-transport", false, "enable only the fixed attested provider transport roots")
	bindControllerPin(fs, &providerTransport.localRelease, "provider-transport-controller")
	bindControllerUint(fs, &providerTransport.uid, "provider-transport-controller-uid", providerTransport.numeric)
	bindControllerUint(fs, &providerTransport.gid, "provider-transport-controller-gid", providerTransport.numeric)
	bindControllerUint(fs, &providerTransport.channelGID, "provider-transport-channel-gid", providerTransport.numeric)
	bindControllerUint64(fs, &providerTransport.keyEpoch, "provider-transport-key-epoch", providerTransport.numeric)
	fs.BoolVar(&prod.productionMesh, "production-mesh", false, "enable verified provider mesh within production admission")
	fs.BoolVar(&prod.nativeMCP, "native-mcp", false, "enable the fixed attested native MCP socket (requires production mesh)")
	fs.StringVar(&prod.meshStateKeyFile, "mesh-state-key-file", "", "explicit mesh state service-key leaf (production mesh only)")
	fs.StringVar(&prod.meshStateChannel, "mesh-state-key-channel", "", "explicit mesh state service-key channel (production mesh only)")
	fs.BoolVar(&prod.enabled, "production-admission", false, "enable the explicitly provisioned production admission channel")
	fs.StringVar(&prod.anchorSocket, "anchor-socket", "", "pre-provisioned platform anchor socket leaf")
	fs.StringVar(&prod.anchorSocketRoot, "anchor-socket-root", "", "pre-provisioned platform anchor socket root")
	fs.StringVar(&prod.anchorKeyRoot, "anchor-key-root", "", "pre-provisioned platform anchor service-key root")
	fs.StringVar(&prod.anchorKeyFile, "anchor-key-file", "service.key", "platform anchor service-key leaf")
	fs.StringVar(&prod.ownerCapabilityFile, "owner-capability-file", "owner.capability", "request-scoped owner capability filename prefix")
	fs.StringVar(&prod.ownerPublicKeyFile, "owner-public-key-file", "owner.public", "owner Ed25519 public-key record leaf under the controller key root")
	fs.StringVar(&prod.controllerReleaseRoot, "controller-release-root", "", "pre-provisioned controller release root")
	fs.StringVar(&prod.channel, "anchor-channel", "platform-anchor", "platform anchor channel")
	fs.StringVar(&prod.localRole, "anchor-local-role", "controller", "controller role on anchor channel")
	fs.StringVar(&prod.peerRole, "anchor-peer-role", "anchor", "anchor peer role on anchor channel")
	bindControllerPin(fs, &prod.localRelease, "controller")
	bindControllerPin(fs, &prod.peerRelease, "anchor")
	bindControllerUint(fs, &prod.localUID, "controller-uid", prod.numeric)
	bindControllerUint(fs, &prod.localGID, "controller-gid", prod.numeric)
	bindControllerUint(fs, &prod.peerUID, "anchor-uid", prod.numeric)
	bindControllerUint(fs, &prod.peerGID, "anchor-gid", prod.numeric)
	bindControllerUint(fs, &prod.channelGID, "anchor-channel-gid", prod.numeric)
	bindControllerUint64(fs, &prod.keyEpoch, "anchor-key-epoch", prod.numeric)
	fs.StringVar(&prod.brokerSocket, "broker-socket", "", "broker channel socket leaf")
	fs.StringVar(&prod.brokerSocketRoot, "broker-socket-root", "", "broker channel root")
	fs.StringVar(&prod.brokerKeyRoot, "broker-key-root", "", "broker key root")
	fs.StringVar(&prod.brokerReleaseRoot, "broker-release-root", "", "controller local release root for the broker channel")
	fs.StringVar(&prod.brokerKeyFile, "broker-key-file", "service.key", "broker key leaf")
	fs.StringVar(&prod.brokerChannel, "broker-channel", "codex-control", "broker channel")
	fs.StringVar(&prod.brokerLocalRole, "broker-local-role", "controller", "broker local role")
	fs.StringVar(&prod.brokerPeerRole, "broker-peer-role", "broker", "broker peer role")
	fs.StringVar(&prod.brokerRuntimeID, "broker-runtime-id", "", "exact broker runtime identity")
	fs.StringVar(&prod.brokerRuntimeDigest, "broker-runtime-digest", "", "exact broker runtime binary digest")
	fs.StringVar(&prod.brokerPolicyDigest, "broker-policy-digest", "", "exact broker policy digest")
	fs.StringVar(&prod.brokerReleaseDigest, "broker-release-digest", "", "exact broker release manifest digest")
	fs.StringVar(&prod.brokerSocketDigest, "broker-socket-digest", "", "exact broker socket contract digest")
	fs.StringVar(&prod.brokerEgressReleaseDigest, "broker-egress-release-digest", "", "exact egress release digest")
	fs.StringVar(&prod.brokerEgressSocketDigest, "broker-egress-socket-digest", "", "exact egress socket digest")
	bindControllerPin(fs, &prod.brokerLocalRelease, "broker-local")
	bindControllerPin(fs, &prod.brokerPeerRelease, "broker-peer")
	bindControllerUint(fs, &prod.brokerUID, "broker-uid", prod.brokerNumeric)
	bindControllerUint(fs, &prod.brokerGID, "broker-gid", prod.brokerNumeric)
	bindControllerUint(fs, &prod.brokerChannelGID, "broker-channel-gid", prod.brokerNumeric)
	bindControllerUint(fs, &prod.egressUID, "egress-uid", prod.brokerNumeric)
	bindControllerUint(fs, &prod.egressGID, "egress-gid", prod.brokerNumeric)
	bindControllerUint64(fs, &prod.brokerKeyEpoch, "broker-key-epoch", prod.brokerNumeric)
	if err := fs.Parse(args); err != nil {
		return errors.New("invalid arguments")
	}
	if fs.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}
	if providerOwnerUID > uint(^uint32(0)) || providerOwnerGID > uint(^uint32(0)) {
		return errors.New("invalid provider artifact owner")
	}
	providerComposition.OwnerUID = uint32(providerOwnerUID)
	providerComposition.OwnerGID = uint32(providerOwnerGID)
	if providerComposition.Root != "" || providerComposition.BundleDigest != "" || providerComposition.TrustDigest != "" || providerComposition.OwnerTrustDigest != "" {
		gidSet := false
		fs.Visit(func(f *flag.Flag) {
			if f.Name == "provider-artifact-owner-gid" {
				gidSet = true
			}
		})
		if !providerComposition.valid() || providerComposition.OwnerUID != 0 || !gidSet {
			return errors.New("incomplete provider composition")
		}
	}
	if providerTransport.enabled && !providerTransport.valid() {
		return errors.New("incomplete provider transport")
	}
	if providerTransport.enabled && !providerComposition.configured() {
		return errors.New("provider transport requires provider composition")
	}
	prod.ownerChat = *ownerChat
	if !prod.enabled && prod.productionMesh {
		return errors.New("production mesh requires production admission")
	}
	if prod.nativeMCP && (!prod.enabled || !prod.productionMesh) {
		return errors.New("native mcp requires production mesh admission")
	}
	if prod.enabled {
		prod.providerComposition, prod.providerTransport = providerComposition, providerTransport
		if prod.productionMesh {
			if err := validateProductionMeshOptions(prod); err != nil {
				return err
			}
		} else if providerComposition.configured() || providerTransport.enabled || providerComposition.Root != "" || providerTransport.localRelease.ReleaseID != "" || prod.meshStateKeyFile != "" || prod.meshStateChannel != "" {
			return errors.New("provider composition requires production mesh")
		}
		if *callbackEnabled || *originProbeEnabled || *sensorEnabled || *syntheticEnabled || *commandCenterEnabled {
			return errors.New("production admission is mutually exclusive")
		}
		prod.listen, prod.state = *addr, *statePath
		prod.ownerChat = true
		if err := validateProductionAdmissionOptions(prod); err != nil {
			return err
		}
		return runProductionAdmission(prod)
	}
	host, _, err := net.SplitHostPort(*addr)
	if err != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() {
		return errors.New("invalid listen address")
	}
	if *commandCenterEnabled {
		if !*syntheticEnabled {
			return errors.New("command center requires synthetic mode")
		}
		return runSynthetic(*addr, *commandCenterOrigin, *commandCenterDir)
	}
	statePathValue, err := prepareStatePath(*statePath)
	if err != nil {
		return err
	}
	lock, err := os.OpenFile(statePathValue+".lock", os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return errors.New("controller lock unavailable")
	}
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = lock.Close()
		return errors.New("controller already running")
	}
	defer func() { _ = syscall.Flock(int(lock.Fd()), syscall.LOCK_UN); _ = lock.Close() }()
	ctx := context.Background()
	key, err := (core.MacOSKeychainProvider{Service: "openduck", Account: "controller-state"}).Key(ctx)
	if err != nil {
		return errors.New("controller key unavailable")
	}
	var queueKey, sensorKey []byte
	if *sensorEnabled {
		sensorKey, err = (core.MacOSKeychainProvider{Service: "openduck", Account: "sensor-hmac"}).Key(ctx)
		if err == nil {
			_, queueKey, err = sensor.DeriveKeys(key)
		}
		if err != nil {
			zero(key)
			return errors.New("sensor key derivation failed")
		}
		defer zero(sensorKey)
		defer zero(queueKey)
	}
	repo, err := harness.NewEncryptedFileRepository(statePathValue, key)
	if err != nil {
		zero(key)
		return errors.New("controller repository unavailable")
	}
	defer zero(key)
	defer func() { _ = repo.Close() }()
	meshRepo, err := mesh.NewEncryptedFileRepository(filepath.Join(filepath.Dir(statePathValue), "mesh.enc"), key)
	if err != nil {
		return errors.New("mesh repository unavailable")
	}
	defer func() { _ = meshRepo.Close() }()
	revisionRepo, err := providerrevision.NewRepository(filepath.Join(filepath.Dir(statePathValue), "provider-revisions.enc"), key)
	if err != nil {
		return errors.New("provider revision repository unavailable")
	}
	defer func() { _ = revisionRepo.Close() }()
	var revisionService *providerrevision.Service
	var providerRegistry *providerbridge.Registry
	var installedRevision providerrevision.Installed
	var lifecycleDispatcher *providerrevision.Dispatcher
	deferredUILifecycle := false
	deferredSafetyLifecycle := false
	if providerComposition.configured() {
		service, dispatcher, configureErr := configuredRevisionService(revisionRepo, providerComposition)
		if configureErr != nil {
			return errors.New("provider revision service unavailable")
		}
		operation, present, configureErr := dispatcher.ReadPending(ctx)
		if configureErr != nil {
			return errors.New("provider lifecycle operation unavailable")
		}
		// UI lifecycle effects require the Coordinator composition callbacks.
		// Keep every owner-only endpoint action deferred until that wiring exists.
		deferredUILifecycle = present && (operation.Action == "ui-bind" || operation.Action == "ui-revoke" || operation.Action == "ui-rotate" || operation.Action == "root-close")
		deferredSafetyLifecycle = present && (operation.Action == "ui-revoke" || operation.Action == "root-close")
		if present && !deferredUILifecycle {
			if _, _, configureErr = dispatcher.Dispatch(ctx); configureErr != nil {
				return errors.New("provider lifecycle operation unavailable")
			}
		}
		revisionService = service
		lifecycleDispatcher = dispatcher
		if deferredSafetyLifecycle {
			// Owner-signed close/revoke must remain able to use the mesh journal
			// when the provider artifact or trust revalidation is unavailable.
			// This empty registry has no routable profile and is used only to
			// construct a fail-closed Coordinator for exact safety callbacks.
			providerRegistry, configureErr = providerbridge.NewRegistry(nil, nil, nil, nil, providerbridge.TrustRegistry{}, nil)
			if configureErr != nil {
				return errors.New("provider directory unavailable")
			}
		} else {
			providerRegistry, installedRevision, configureErr = activeProviderRegistry(ctx, service)
			if configureErr != nil {
				return errors.New("provider directory unavailable")
			}
		}
	} else {
		revisionService, err = newDisabledRevisionService(revisionRepo)
		if err != nil {
			return errors.New("provider revision service unavailable")
		}
		providerRegistry, err = providerbridge.NewRegistry(nil, nil, nil, nil, providerbridge.TrustRegistry{}, nil)
		if err != nil {
			return errors.New("provider directory unavailable")
		}
	}
	controller, err := harness.NewController(ctx, repo)
	if err != nil {
		return errors.New("controller unavailable")
	}
	// An enabled, evidence-backed revision is not itself a transport route.
	// Refuse startup until the privileged boundary supplies the closed,
	// descriptor-backed router via newTransportMeshCoordinator; otherwise a
	// UI-visible profile could misleadingly appear usable and then fall back to
	// the no-adapter path.
	var meshCoordinator *mesh.Coordinator
	var closeProviderTransport func()
	if providerComposition.configured() && configuredTransportRequired(installedRevision) && !deferredSafetyLifecycle {
		if !providerTransport.valid() || providerComposition.Root != "/Library/Application Support/OpenDuck/providers/inactive" {
			return errors.New("provider transport router required")
		}
		descriptors, dial, closeFn, transportErr := openConfiguredProviderTransport(providerTransport, providerComposition, installedRevision, defaultProviderTransportDependencies())
		if transportErr != nil {
			return errors.New("provider transport unavailable")
		}
		closeProviderTransport = closeFn
		meshCoordinator, transportErr = newTransportMeshCoordinator(meshRepo, providerRegistry, installedRevision, descriptors, dial, time.Now().UTC())
		if transportErr != nil {
			closeProviderTransport()
			return errors.New("provider transport unavailable")
		}
		// A fresh Coordinator is intentionally poisoned when its journal retains a
		// running provider child. Recover it before composing any UI or HTTP
		// surface: this uses the startup context to verify the exact native route,
		// never to redispatch Start. A failed proof closes the transport roots and
		// prevents listener exposure.
		if transportErr = recoverConfiguredMesh(ctx, meshCoordinator, closeProviderTransport); transportErr != nil {
			return errors.New("provider session recovery unavailable")
		}
	}
	if closeProviderTransport != nil {
		defer closeProviderTransport()
	}
	// Mesh has an explicit disabled composition until provider evidence,
	// mappings, durable journal and an attested provider router are configured.
	if meshCoordinator == nil {
		meshCoordinator, err = newDisabledMeshCoordinator(meshRepo, providerRegistry)
		if err != nil {
			return errors.New("mesh controller unavailable")
		}
	}
	// This authenticated UI boundary is separate from DSH and the model path.
	// It exposes only declared metadata and typed fail-closed proposals while no
	// actual Coordinator endpoint binding has been provisioned.
	// No authenticated endpoint invoker is provisioned in this disabled
	// composition; the coordinator cannot be reached from UI requests.
	meshApp := &meshApplication{coordinator: meshCoordinator, revisions: revisionService}
	if deferredUILifecycle {
		lifecycleDispatcher.RegisterUIRoot = meshApp.registerUIRoot
		lifecycleDispatcher.VerifyUIBinding = meshApp.verifyUIBinding
		lifecycleDispatcher.RevokeUIEndpoint = meshApp.revokeUIEndpoint
		lifecycleDispatcher.RotateUIEndpoint = meshApp.rotateUIEndpoint
		lifecycleDispatcher.CloseRootEndpoint = meshApp.closeRootEndpoint
		if _, _, err = lifecycleDispatcher.Dispatch(ctx); err != nil {
			return errors.New("provider lifecycle operation unavailable")
		}
	}
	meshUI := meshui.NewProjectionServiceWithSource(meshApp, meshApp)
	uiSessions, err := dshbridge.NewSessionStore(dshbridge.Config{Origin: "http://" + *addr, Host: *addr})
	if err != nil {
		return errors.New("mesh ui unavailable")
	}
	harnessServer := &harnesshttp.Server{Controller: controller}
	if err := harnessServer.ConfigureCallback(harnesshttp.CallbackConfig{Enabled: *callbackEnabled, Origin: *callbackOrigin, Host: *addr, OriginProbeEnabled: *originProbeEnabled}); err != nil {
		return errors.New("invalid callback configuration")
	}
	handler := harnessServer.Handler()
	uiHandler := (&dshbridgehttp.Server{Bridge: &dshbridge.Bridge{Sessions: uiSessions}, Origin: "http://" + *addr, Host: *addr, MeshUI: meshUI}).Handler()
	uiMux := http.NewServeMux()
	uiMux.Handle("/v1/ui/bootstrap", uiHandler)
	uiMux.Handle("/v1/plugin-reads/mesh", uiHandler)
	uiMux.Handle("/v1/plugin-proposals/", uiHandler)
	uiMux.Handle("/", handler)
	handler = uiMux
	if *sensorEnabled {
		sensorQueue, queueErr := core.NewFileQueue(filepath.Join(filepath.Dir(statePathValue), "sensor.enc"), queueKey)
		if queueErr != nil {
			return errors.New("sensor queue unavailable")
		}
		sensorTransport, transportErr := sensor.NewWithReplay(sensorKey, queueKey, sensorQueue, controller, filepath.Join(filepath.Dir(statePathValue), "sensor-replay.enc"))
		if transportErr != nil {
			return errors.New("sensor transport unavailable")
		}
		mux := http.NewServeMux()
		mux.Handle("/v1/sensor/events", sensorTransport.Handler())
		mux.Handle("/", handler)
		handler = mux
	}
	srv := &http.Server{Addr: *addr, Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second}
	listener, err := net.Listen("tcp", *addr)
	if err != nil {
		return errors.New("controller listener unavailable")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	errs := make(chan error, 1)
	go func() {
		if e := srv.Serve(listener); e != nil && e != http.ErrServerClosed {
			errs <- e
		}
	}()
	var serveErr error
	select {
	case <-ctx.Done():
	case serveErr = <-errs:
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutdownCtx)
	if serveErr != nil {
		return errors.New("controller server failed")
	}
	return nil
}

func validateProductionMeshOptions(o productionAdmissionOptions) error {
	if !o.productionMesh || !o.providerComposition.configured() || !o.providerComposition.valid() || !o.providerTransport.enabled || !o.providerTransport.valid() {
		return errors.New("production mesh requires complete provider composition and transport")
	}
	if o.providerComposition.Root != "/Library/Application Support/OpenDuck/providers/inactive" {
		return errors.New("production mesh requires the fixed provider artifact root")
	}
	if o.meshStateKeyFile == "" || filepath.Base(o.meshStateKeyFile) != o.meshStateKeyFile || o.meshStateChannel == "" || o.meshStateChannel == o.channel || o.meshStateChannel == o.brokerChannel {
		return errors.New("production mesh requires a separate state key")
	}
	return nil
}

// meshRecovery is deliberately narrower than the full Coordinator surface so
// startup keeps the recovery boundary explicit and tests can prove that a
// failed proof occurs before listener-facing composition.
type meshRecovery interface {
	ReloadAndReplay(context.Context) error
}

// recoverConfiguredMesh runs only for the descriptor-backed provider
// composition. A nil recovery is the disabled composition and is inert. The
// caller supplies the already-open transport cleanup so a failed proof cannot
// leave authenticated provider roots live while startup returns an error.
func recoverConfiguredMesh(ctx context.Context, recovery meshRecovery, closeTransport func()) error {
	if recovery == nil {
		return nil
	}
	if err := recovery.ReloadAndReplay(ctx); err != nil {
		if closeTransport != nil {
			closeTransport()
		}
		return err
	}
	return nil
}

// runSynthetic is intentionally isolated from the normal Controller startup:
// no keychain, encrypted state, provider, model, MCP, or effect path is
// constructed. The route is reachable only with the explicit -synthetic and
// -command-center flags and is suitable for local acceptance tests.
func runSynthetic(addr, origin, staticDir string) error {
	return runSyntheticWithCheckpoint(addr, origin, staticDir, syntheticadmission.NewKeychainCheckpoint())
}

// runSyntheticWithCheckpoint exists as an explicit composition seam. The
// current Keychain adapter is cooperative only and is rejected by the
// production constructor until a separately attested anchor is available;
// tests inject an explicit attested fake and never touch credentials.
func runSyntheticWithCheckpoint(addr, origin, staticDir string, checkpoint admission.CheckpointStore) error {
	handler, closeAuthority, err := syntheticHandler(addr, origin, staticDir, checkpoint)
	if err != nil {
		return err
	}
	defer closeAuthority()
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return errors.New("synthetic listener unavailable")
	}
	defer listener.Close()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	srv := &http.Server{Addr: addr, Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second}
	errs := make(chan error, 1)
	go func() {
		if e := srv.Serve(listener); e != nil && e != http.ErrServerClosed {
			errs <- e
		}
	}()
	select {
	case <-ctx.Done():
	case <-errs:
		return errors.New("synthetic server failed")
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutdown)
	return nil
}

func syntheticHandler(addr, origin, staticDir string, checkpoint admission.CheckpointStore) (http.Handler, func(), error) {
	if origin == "" {
		origin = "http://" + addr
	}
	store, err := dshbridge.NewSessionStore(dshbridge.Config{Origin: origin, Host: addr})
	if err != nil {
		return nil, nil, errors.New("synthetic session configuration invalid")
	}
	// Establish the private parent before creating synthetic durable state.
	if _, err := prepareStatePath(".openduck/controller.enc"); err != nil {
		return nil, nil, errors.New("synthetic state directory unavailable")
	}
	// The production composition requires an independently hosted monotonic
	// checkpoint anchor. No such anchor is wired into this local binary yet;
	// fail closed instead of silently downgrading to the colocated test store.
	authority, err := syntheticadmission.NewSyntheticWithCheckpoint(filepath.Join(".openduck", "synthetic-state"), checkpoint)
	if err != nil {
		return nil, nil, errors.New("synthetic admission unavailable")
	}
	now := time.Now().UTC()
	bridge := &dshbridge.Bridge{Sessions: store, Models: synthetic.NewModels(now), Classifier: synthetic.Classifier{}, Authority: authority, ProjectionVerifier: synthetic.ProjectionVerifier{}}
	bridgeHandler := synthetic.FlatReadAdapter((&dshbridgehttp.Server{Bridge: bridge, Origin: origin, Host: addr, ProjectionSigner: synthetic.ProjectionSigner, PluginReads: synthetic.NewPluginReads(now), MeshUI: meshui.NewProjectionService(nil)}).Handler())
	mux := http.NewServeMux()
	mux.Handle("/v1/", bridgeHandler)
	mux.Handle("/", http.FileServer(http.Dir(staticDir)))
	return mux, func() { _ = authority.Close() }, nil
}

// prepareStatePath confines controller persistence to the private, repository-local
// .openduck directory. Existing directories are never chmod'd: they must already
// be private (0700), non-symlink directories. This intentionally leaves the final
// open/rename operations to the repository, so a narrow same-user TOCTOU window
// remains between validation and use.
func prepareStatePath(statePath string) (string, error) {
	clean := filepath.Clean(statePath)
	if clean == "." || filepath.IsAbs(clean) || filepath.Dir(clean) != ".openduck" {
		return "", errors.New("state path must be .openduck-relative")
	}
	if filepath.Base(clean) == "." || filepath.Base(clean) == ".." {
		return "", errors.New("invalid state path")
	}
	parent := filepath.Dir(clean)
	info, err := os.Lstat(parent)
	if os.IsNotExist(err) {
		if err := os.Mkdir(parent, 0700); err != nil {
			return "", errors.New("state directory unavailable")
		}
		info, err = os.Lstat(parent)
	}
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return "", errors.New("state directory unavailable")
	}
	if info.Mode().Perm() != 0700 {
		return "", errors.New("state directory permissions unavailable")
	}
	for _, path := range []string{clean, clean + ".lock"} {
		if existing, err := os.Lstat(path); err == nil {
			if existing.Mode()&os.ModeSymlink != 0 || !existing.Mode().IsRegular() {
				return "", errors.New("state path is not a regular file")
			}
		} else if !os.IsNotExist(err) {
			return "", errors.New("state path unavailable")
		}
	}
	return clean, nil
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func bindControllerPin(fs *flag.FlagSet, p *macoschannel.ReleasePin, prefix string) {
	fs.StringVar(&p.ReleaseID, prefix+"-release", "", prefix+" release id")
	fs.StringVar(&p.BinaryDigest, prefix+"-binary-digest", "", prefix+" binary digest")
	fs.StringVar(&p.SocketDigest, prefix+"-socket-digest", "", prefix+" socket digest")
	fs.StringVar(&p.ManifestDigest, prefix+"-manifest-digest", "", prefix+" manifest digest")
}

func bindControllerUint(fs *flag.FlagSet, p *uint32, name string, set map[string]bool) {
	fs.Func(name, name, func(raw string) error {
		n, err := strconv.ParseUint(raw, 10, 32)
		if err != nil {
			return err
		}
		*p = uint32(n)
		set[name] = true
		return nil
	})
}

func bindControllerUint64(fs *flag.FlagSet, p *uint64, name string, set map[string]bool) {
	fs.Func(name, name, func(raw string) error {
		n, err := strconv.ParseUint(raw, 10, 64)
		if err != nil || n == 0 {
			return errors.New("invalid positive integer")
		}
		*p = n
		set[name] = true
		return nil
	})
}

func validateProductionAdmissionOptions(o productionAdmissionOptions) error {
	if !o.enabled || o.state == "" || o.listen == "" || !filepath.IsAbs(o.state) || filepath.Clean(o.state) != o.state {
		return errors.New("production admission requires an absolute clean state path")
	}
	host, _, err := net.SplitHostPort(o.listen)
	if err != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() {
		return errors.New("invalid listen address")
	}
	for name, p := range map[string]string{"anchor-socket-root": o.anchorSocketRoot, "anchor-key-root": o.anchorKeyRoot, "controller-release-root": o.controllerReleaseRoot} {
		if p == "" || !filepath.IsAbs(p) || filepath.Clean(p) != p {
			return fmt.Errorf("production %s must be an absolute clean path", name)
		}
	}
	if o.ownerChat {
		if o.ownerCapabilityFile == "" || filepath.Base(o.ownerCapabilityFile) != o.ownerCapabilityFile || o.ownerPublicKeyFile == "" || filepath.Base(o.ownerPublicKeyFile) != o.ownerPublicKeyFile {
			return errors.New("production owner chat capability paths invalid")
		}
		for name, p := range map[string]string{"broker-socket-root": o.brokerSocketRoot, "broker-key-root": o.brokerKeyRoot, "broker-release-root": o.brokerReleaseRoot} {
			if p == "" || !filepath.IsAbs(p) || filepath.Clean(p) != p {
				return fmt.Errorf("production %s must be an absolute clean path", name)
			}
		}
		if o.brokerSocket == "" || filepath.Base(o.brokerSocket) != o.brokerSocket || o.brokerUID == 0 || o.brokerGID == 0 || o.brokerChannelGID == 0 || o.egressUID == 0 || o.egressGID == 0 || o.brokerKeyEpoch == 0 {
			return errors.New("production owner chat requires broker identity")
		}
		if o.brokerRuntimeID == "" {
			return errors.New("production owner chat requires broker runtime id")
		}
		for name, digest := range map[string]string{"broker-runtime-digest": o.brokerRuntimeDigest, "broker-policy-digest": o.brokerPolicyDigest, "broker-release-digest": o.brokerReleaseDigest, "broker-socket-digest": o.brokerSocketDigest, "broker-egress-release-digest": o.brokerEgressReleaseDigest, "broker-egress-socket-digest": o.brokerEgressSocketDigest} {
			if _, ok := exactDigest(digest); !ok {
				return fmt.Errorf("invalid %s", name)
			}
		}
	}
	if o.anchorSocket == "" || filepath.Base(o.anchorSocket) != o.anchorSocket || filepath.Clean(o.anchorSocket) != o.anchorSocket || o.channel == "" || o.localRole == "" || o.peerRole == "" || o.localRole == o.peerRole || o.anchorKeyFile == "" || filepath.Base(o.anchorKeyFile) != o.anchorKeyFile {
		return errors.New("invalid production admission channel")
	}
	if o.localUID == 0 || o.peerUID == 0 || o.localUID == o.peerUID || !o.numeric["controller-uid"] || !o.numeric["controller-gid"] || !o.numeric["anchor-uid"] || !o.numeric["anchor-gid"] || !o.numeric["anchor-channel-gid"] || !o.numeric["anchor-key-epoch"] || o.keyEpoch == 0 {
		return errors.New("production admission requires complete numeric identity")
	}
	if o.channelGID == o.localGID || o.channelGID == o.peerGID {
		return errors.New("anchor channel group must be distinct from service primary groups")
	}
	if o.localRelease.ReleaseID == "" || o.peerRelease.ReleaseID == "" {
		return errors.New("production admission requires release pins")
	}
	for _, pin := range []macoschannel.ReleasePin{o.localRelease, o.peerRelease} {
		for _, d := range []string{pin.BinaryDigest, pin.SocketDigest, pin.ManifestDigest} {
			if len(d) != 64 {
				return errors.New("invalid release digest")
			}
			if _, err := hex.DecodeString(d); err != nil {
				return errors.New("invalid release digest")
			}
		}
	}
	return nil
}

func exactDigest(raw string) (string, bool) {
	if len(raw) == 64 {
		if _, err := hex.DecodeString(raw); err == nil {
			return "sha256:" + raw, true
		}
	}
	if len(raw) == 71 && raw[:7] == "sha256:" {
		if _, err := hex.DecodeString(raw[7:]); err == nil {
			return raw, true
		}
	}
	return "", false
}

type productionClassifier struct{}

func (productionClassifier) Classify(payload []byte) (dshbridge.PrivacyClass, error) {
	sum := sha256.Sum256(payload)
	digest := "sha256:" + hex.EncodeToString(sum[:])
	detection, err := localpd.Detect(localpd.SourceEvent{
		ConversationID: "composer-" + hex.EncodeToString(sum[:16]), Revision: 1, SourceSequence: 1,
		IngestOrdinal: 1, ScannedThrough: 1, Complete: true, PolicyVersion: 1,
		PolicyDigest: digest, CoverageDigest: digest, RevisionSetDigest: digest, Content: append([]byte(nil), payload...),
	})
	if err != nil {
		return "", errors.New("production local scan rejected")
	}
	if detection.Mode == localpd.ModeNormal {
		switch detection.Class {
		case localpd.ClassL0:
			return dshbridge.ClassL0, nil
		case localpd.ClassL1:
			return dshbridge.ClassL1, nil
		default:
			return "", errors.New("production local scan rejected")
		}
	}
	if detection.Class == localpd.ClassL2 {
		return dshbridge.ClassL2, nil
	}
	if detection.Class == localpd.ClassL3 {
		return dshbridge.ClassL3, nil
	}
	return "", errors.New("production local scan quarantined")
}

type productionCloudAuthority struct {
	cloud interface {
		AdmitCloud(context.Context, []byte) (dshbridge.CloudAdmission, error)
	}
}

func (a productionCloudAuthority) AdmitCloud(ctx context.Context, payload []byte) (dshbridge.CloudAdmission, error) {
	return a.cloud.AdmitCloud(ctx, payload)
}
func (productionCloudAuthority) DispatchLocalPD(context.Context, []byte) (dshbridge.LocalPDAdmission, error) {
	return dshbridge.LocalPDAdmission{}, dshbridge.ErrLocalPDUnavailable
}

type admissionCheckpointCapability struct {
	opaque *platformanchor.ProductionAdmissionCheckpoint
	client *platformanchor.ProductionClient
	load   func(context.Context) (admission.LedgerCheckpoint, error)
}

type productionAdmissionRoots struct {
	state, socket, key, release, brokerSocket, brokerKey, brokerRelease *os.Root
	statePath                                                           string
	revalidateState                                                     func() error
	close                                                               func()
}

type productionAdmissionAuthority interface {
	AdmitCloud(context.Context, []byte) (dshbridge.CloudAdmission, error)
	Close() error
}

type ownerChatService interface {
	Start(context.Context, codexruntime.GeneralChatOrder) (codexruntime.AssistantTurnResult, error)
	Get(context.Context, string) (codexruntime.AssistantTurnResult, error)
	Cancel(context.Context, string) error
	Close() error
}

type productionAdmissionDependencies struct {
	openRoots             func(productionAdmissionOptions) (productionAdmissionRoots, error)
	newCheckpoint         func(macoschannel.Config, platformanchor.ProductionPolicy) (admissionCheckpointCapability, error)
	newAuthority          func(string, admissionCheckpointCapability) (productionAdmissionAuthority, error)
	newOwnerChat          func(context.Context, productionAdmissionOptions, admissionCheckpointCapability, productionAdmissionRoots) (ownerChatService, func(), error)
	newMeshRuntime        func(context.Context, productionAdmissionOptions, productionAdmissionRoots) (productionMeshRuntime, error)
	listen                func(string, string) (net.Listener, error)
	shutdownTimeout       time.Duration
	beforeHandlerRegister func(*http.Request)
}

// productionMeshRuntime owns every mesh-specific resource which is live after
// successful production composition. Keeping the repositories and transport
// behind one close operation makes the shutdown order explicit: stop the
// authenticated transport first, then erase revision and mesh journal keys.
type productionMeshRuntime interface {
	Close() error
	meshApplication() (*meshApplication, error)
}

type configuredProductionMeshRuntime struct {
	mu       sync.Mutex
	closed   bool
	closeErr error
	mesh     *verifiedMeshComposition
	revision *providerrevision.Repository
	repo     *mesh.EncryptedFileRepository
	native   nativeMCPRuntime
}

func (r *configuredProductionMeshRuntime) Close() error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return r.closeErr
	}
	r.closed = true
	if r.native != nil {
		if err := r.native.Close(); err != nil && r.closeErr == nil {
			r.closeErr = err
		}
	}
	// Never tear down mesh authority while a native request might still be
	// executing. A bounded-drain failure leaks capability until process exit,
	// which is safer than racing a live request against teardown.
	if r.closeErr != nil {
		return r.closeErr
	}
	// Stop accepting native MCP before tearing down the mesh capability; no
	// newly accepted shim request may race a closing Coordinator/transport.
	if r.mesh != nil && r.mesh.close != nil {
		r.mesh.close()
	}
	if r.revision != nil {
		r.closeErr = r.revision.Close()
	}
	if r.repo != nil {
		if err := r.repo.Close(); r.closeErr == nil {
			r.closeErr = err
		}
	}
	return r.closeErr
}

func (r *configuredProductionMeshRuntime) meshApplication() (*meshApplication, error) {
	if r == nil || r.mesh == nil || r.mesh.app == nil {
		return nil, errors.New("production mesh unavailable")
	}
	return r.mesh.app, nil
}

const productionMeshStateKDFSalt = "openduck.production.mesh.state-root.v1"

// deriveProductionMeshJournalKeys prevents one state-root service key from
// becoming a raw AES-GCM key for two independent durable journals. The labels
// are protocol constants, never flag or artifact input.
func deriveProductionMeshJournalKeys(root []byte) ([]byte, []byte, error) {
	if len(root) != 32 {
		return nil, nil, errors.New("production mesh state key invalid")
	}
	meshKey, err := hkdf.Key(sha256.New, root, []byte(productionMeshStateKDFSalt), "openduck.production.mesh.journal.v1", 32)
	if err != nil {
		return nil, nil, errors.New("production mesh key derivation failed")
	}
	revisionKey, err := hkdf.Key(sha256.New, root, []byte(productionMeshStateKDFSalt), "openduck.production.providerrevision.journal.v1", 32)
	if err != nil {
		zero(meshKey)
		return nil, nil, errors.New("production mesh key derivation failed")
	}
	return meshKey, revisionKey, nil
}

type productionMeshRuntimeDependencies struct {
	newMeshRepository       func(string, []byte) (*mesh.EncryptedFileRepository, error)
	newRevisionRepository   func(string, []byte) (*providerrevision.Repository, error)
	newComposition          func(context.Context, mesh.Repository, *providerrevision.Repository, providerCompositionOptions, providerTransportOptions) (*verifiedMeshComposition, error)
	closeMeshRepository     func(*mesh.EncryptedFileRepository) error
	closeRevisionRepository func(*providerrevision.Repository) error
	newNativeListener       func(macosattest.SocketBoundary) (nativeMCPListener, error)
	startNative             func(context.Context, *meshApplication, productionAdmissionOptions, func(macosattest.SocketBoundary) (nativeMCPListener, error)) (nativeMCPRuntime, error)
}

func defaultProductionMeshRuntimeDependencies() productionMeshRuntimeDependencies {
	return productionMeshRuntimeDependencies{
		newMeshRepository:     mesh.NewEncryptedFileRepository,
		newRevisionRepository: providerrevision.NewRepository,
		newComposition:        newVerifiedMeshComposition,
		closeMeshRepository:   func(repo *mesh.EncryptedFileRepository) error { return repo.Close() },
		closeRevisionRepository: func(repo *providerrevision.Repository) error {
			return repo.Close()
		},
		newNativeListener: func(boundary macosattest.SocketBoundary) (nativeMCPListener, error) {
			return macosattest.ListenFixed(boundary)
		},
		startNative: startNativeMCP,
	}
}

func newProductionMeshRuntime(ctx context.Context, o productionAdmissionOptions, roots productionAdmissionRoots) (productionMeshRuntime, error) {
	return newProductionMeshRuntimeWith(ctx, o, roots, defaultProductionMeshRuntimeDependencies())
}

// newProductionMeshRuntimeWith is a test seam around the resource-owning
// factory. It never changes the production crypto, key-loading or startup
// order and exists to prove that a failed composition cannot retain either
// repository key in a live object.
func newProductionMeshRuntimeWith(ctx context.Context, o productionAdmissionOptions, roots productionAdmissionRoots, deps productionMeshRuntimeDependencies) (productionMeshRuntime, error) {
	if ctx == nil || roots.state == nil {
		return nil, errors.New("production mesh state unavailable")
	}
	if deps.newMeshRepository == nil || deps.newRevisionRepository == nil || deps.newComposition == nil {
		return nil, errors.New("production mesh dependencies unavailable")
	}
	closeMeshRepository := deps.closeMeshRepository
	if closeMeshRepository == nil {
		closeMeshRepository = func(repo *mesh.EncryptedFileRepository) error { return repo.Close() }
	}
	closeRevisionRepository := deps.closeRevisionRepository
	if closeRevisionRepository == nil {
		closeRevisionRepository = func(repo *providerrevision.Repository) error { return repo.Close() }
	}
	stateKey, err := servicekey.New(roots.state, servicekey.Policy{FileName: o.meshStateKeyFile, Channel: o.meshStateChannel, OwnerUID: o.localUID, OwnerGID: o.localGID, Mode: 0600, RootUID: o.localUID, RootGID: o.localGID, RootMode: 0700})
	if err != nil {
		return nil, errors.New("production mesh state key unavailable")
	}
	keyCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	rootKey, epoch, err := stateKey.LoadContext(keyCtx, o.meshStateChannel)
	cancel()
	if err != nil || epoch == 0 {
		zero(rootKey)
		return nil, errors.New("production mesh state key preflight failed")
	}
	meshKey, revisionKey, err := deriveProductionMeshJournalKeys(rootKey)
	zero(rootKey)
	if err != nil {
		return nil, err
	}
	meshRepo, err := deps.newMeshRepository(filepath.Join(o.state, "mesh.enc"), meshKey)
	zero(meshKey)
	if err != nil {
		zero(revisionKey)
		return nil, errors.New("production mesh repository unavailable")
	}
	revisionRepo, err := deps.newRevisionRepository(filepath.Join(o.state, "provider-revisions.enc"), revisionKey)
	zero(revisionKey)
	if err != nil {
		_ = meshRepo.Close()
		return nil, errors.New("production mesh repository unavailable")
	}
	composition, err := deps.newComposition(ctx, meshRepo, revisionRepo, o.providerComposition, o.providerTransport)
	if err != nil || composition == nil {
		primary := err
		if primary == nil {
			primary = errors.New("production mesh composition unavailable")
		}
		if composition != nil && composition.close != nil {
			composition.close()
		}
		return nil, errors.Join(
			errors.New("production mesh composition unavailable"),
			primary,
			closeRevisionRepository(revisionRepo),
			closeMeshRepository(meshRepo),
		)
	}
	if composition.registration != nil {
		var requestErr error
		if composition.app == nil || composition.app.revisions == nil {
			requestErr = errors.New("production mesh ui registration unavailable")
		}
		var request uiBindSigningRequest
		if requestErr == nil {
			request, requestErr = uiBindSigningRequestFor(ctx, composition.app.revisions, *composition.registration)
		}
		if requestErr == nil {
			requestErr = publishUIBindSigningRequest(roots.state, request)
		}
		if requestErr != nil {
			if composition.close != nil {
				composition.close()
			}
			return nil, errors.Join(
				errors.New("production mesh ui registration unavailable"),
				closeRevisionRepository(revisionRepo),
				closeMeshRepository(meshRepo),
			)
		}
	}
	var native nativeMCPRuntime
	if o.nativeMCP {
		if deps.newNativeListener == nil || deps.startNative == nil {
			if composition.close != nil {
				composition.close()
			}
			return nil, errors.Join(errors.New("production native mcp unavailable"), closeRevisionRepository(revisionRepo), closeMeshRepository(meshRepo))
		}
		native, err = deps.startNative(ctx, composition.app, o, deps.newNativeListener)
		if err != nil {
			if composition.close != nil {
				composition.close()
			}
			return nil, errors.Join(errors.New("production native mcp unavailable"), err, closeRevisionRepository(revisionRepo), closeMeshRepository(meshRepo))
		}
	}
	return &configuredProductionMeshRuntime{mesh: composition, revision: revisionRepo, repo: meshRepo, native: native}, nil
}

func defaultProductionAdmissionDependencies() productionAdmissionDependencies {
	return productionAdmissionDependencies{
		openRoots: func(o productionAdmissionOptions) (productionAdmissionRoots, error) {
			reqs := []verifiedroot.Requirement{
				{Name: "state", Path: o.state, UID: o.localUID, GID: o.localGID, Mode: 0700},
				{Name: "anchor-socket", Path: o.anchorSocketRoot, UID: o.peerUID, GID: o.channelGID, Mode: 0750},
				{Name: "controller-anchor-key", Path: o.anchorKeyRoot, UID: o.localUID, GID: o.localGID, Mode: 0700},
				{Name: "controller-release", Path: o.controllerReleaseRoot, UID: 0, GID: o.localGID, Mode: 0550},
			}
			if o.ownerChat {
				reqs = append(reqs, verifiedroot.Requirement{Name: "broker-socket", Path: o.brokerSocketRoot, UID: o.brokerUID, GID: o.brokerChannelGID, Mode: 0750}, verifiedroot.Requirement{Name: "broker-key", Path: o.brokerKeyRoot, UID: o.localUID, GID: o.localGID, Mode: 0700}, verifiedroot.Requirement{Name: "controller-broker-release", Path: o.brokerReleaseRoot, UID: 0, GID: o.localGID, Mode: 0550})
			}
			roots, err := verifiedroot.OpenAll(reqs)
			if err != nil {
				return productionAdmissionRoots{}, err
			}
			out := productionAdmissionRoots{state: roots[0].Handle(), socket: roots[1].Handle(), key: roots[2].Handle(), release: roots[3].Handle(), statePath: roots[0].Path(), revalidateState: roots[0].Revalidate, close: func() { verifiedroot.CloseAll(roots) }}
			if o.ownerChat {
				out.brokerSocket, out.brokerKey, out.brokerRelease = roots[4].Handle(), roots[5].Handle(), roots[6].Handle()
			}
			return out, nil
		},
		newCheckpoint: func(cfg macoschannel.Config, policy platformanchor.ProductionPolicy) (admissionCheckpointCapability, error) {
			dial, err := macoschannel.NewDialer(cfg)
			if err != nil {
				return admissionCheckpointCapability{}, err
			}
			client, err := platformanchor.NewProductionClient(dial, policy)
			if err != nil {
				return admissionCheckpointCapability{}, err
			}
			checkpoint, err := platformanchor.NewProductionAdmissionCheckpoint(client)
			if err != nil {
				return admissionCheckpointCapability{}, err
			}
			return admissionCheckpointCapability{opaque: checkpoint, client: client, load: checkpoint.LoadCheckpointContext}, nil
		},
		newAuthority: func(state string, capability admissionCheckpointCapability) (productionAdmissionAuthority, error) {
			if capability.opaque == nil {
				return nil, errors.New("production checkpoint unavailable")
			}
			return syntheticadmission.NewProduction(state, capability.opaque)
		},
		newOwnerChat:    newDefaultOwnerChat,
		newMeshRuntime:  newProductionMeshRuntime,
		listen:          net.Listen,
		shutdownTimeout: 5 * time.Second,
	}
}

func runProductionAdmission(o productionAdmissionOptions) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return runProductionAdmissionContext(ctx, o, defaultProductionAdmissionDependencies())
}

func runProductionAdmissionContext(runCtx context.Context, o productionAdmissionOptions, deps productionAdmissionDependencies) error {
	if runCtx == nil || deps.openRoots == nil || deps.newCheckpoint == nil || deps.newAuthority == nil || deps.listen == nil {
		return errors.New("production admission dependencies unavailable")
	}
	if err := runCtx.Err(); err != nil {
		return errors.New("production admission cancelled")
	}
	roots, err := deps.openRoots(o)
	if err != nil {
		return errors.New("production roots unavailable")
	}
	if roots.close == nil || roots.revalidateState == nil || roots.state == nil || roots.socket == nil || roots.key == nil || roots.release == nil || roots.statePath != o.state {
		if roots.close != nil {
			roots.close()
		}
		return errors.New("production roots unavailable")
	}
	if o.ownerChat && (roots.brokerSocket == nil || roots.brokerKey == nil || roots.brokerRelease == nil || deps.newOwnerChat == nil) {
		roots.close()
		return errors.New("production owner chat roots unavailable")
	}
	defer roots.close()
	if err := runCtx.Err(); err != nil {
		return errors.New("production admission cancelled")
	}
	key, err := servicekey.New(roots.key, servicekey.Policy{FileName: o.anchorKeyFile, Channel: o.channel, OwnerUID: o.localUID, OwnerGID: o.localGID, Mode: 0600, RootUID: o.localUID, RootGID: o.localGID, RootMode: 0700})
	if err != nil {
		return errors.New("production anchor key unavailable")
	}
	cfg := macoschannel.Config{Contract: macoschannel.SocketContract{Channel: o.channel, LocalRole: o.localRole, PeerRole: o.peerRole, SocketPath: o.anchorSocket, SocketRoot: o.anchorSocketRoot, ExpectedPeerUID: &o.peerUID, ExpectedPeerGID: &o.peerGID, ExpectedSocketRootUID: o.peerUID, ExpectedSocketRootGID: o.channelGID, ExpectedSocketRootMode: 0750, ExpectedSocketUID: o.peerUID, ExpectedSocketGID: o.channelGID, ExpectedSocketMode: 0660}, LocalRelease: o.localRelease, PeerRelease: o.peerRelease, ReleaseRoot: roots.release, SocketRootFD: roots.socket, BinaryName: "openduck-controller", KeySource: key, ExpectedReleaseRootUID: 0, ExpectedReleaseRootGID: o.localGID, ExpectedReleaseRootMode: 0550, ExpectedManifestMode: 0440, ExpectedBinaryMode: 0550}
	ctx, cancel := context.WithTimeout(runCtx, 5*time.Second)
	keyBytes, epoch, keyErr := key.LoadContext(ctx, o.channel)
	cancel()
	zero(keyBytes)
	if keyErr != nil || epoch != o.keyEpoch {
		return errors.New("production anchor key preflight failed")
	}
	if err := runCtx.Err(); err != nil {
		return errors.New("production admission cancelled")
	}
	capability, err := deps.newCheckpoint(cfg, platformanchor.ProductionPolicy{Channel: o.channel, LocalRole: o.localRole, PeerRole: o.peerRole, LocalRelease: o.localRelease, PeerRelease: o.peerRelease, ExpectedLocalUID: &o.localUID, ExpectedLocalGID: &o.localGID, ExpectedPeerUID: &o.peerUID, ExpectedPeerGID: &o.peerGID, ExpectedKeyEpoch: o.keyEpoch})
	if err != nil {
		return errors.New("production anchor client unavailable")
	}
	if capability.load == nil {
		return errors.New("production admission checkpoint unavailable")
	}
	probeCtx, probeCancel := context.WithTimeout(runCtx, 5*time.Second)
	_, probeErr := capability.load(probeCtx)
	probeCancel()
	if probeErr != nil {
		return errors.New("production anchor unavailable")
	}
	if err := runCtx.Err(); err != nil {
		return errors.New("production admission cancelled")
	}
	var meshRuntime productionMeshRuntime
	if o.productionMesh {
		if deps.newMeshRuntime == nil {
			return errors.New("production mesh dependencies unavailable")
		}
		var meshErr error
		meshRuntime, meshErr = deps.newMeshRuntime(runCtx, o, roots)
		if meshErr != nil || meshRuntime == nil {
			if meshRuntime != nil {
				_ = meshRuntime.Close()
			}
			return errors.New("production mesh unavailable")
		}
		defer meshRuntime.Close()
	}
	listener, err := deps.listen("tcp", o.listen)
	if err != nil {
		return errors.New("controller listener unavailable")
	}
	defer listener.Close()
	if err := runCtx.Err(); err != nil {
		return errors.New("production admission cancelled")
	}
	if err := roots.revalidateState(); err != nil {
		return errors.New("production state root changed")
	}
	authority, err := deps.newAuthority(roots.statePath, capability)
	if err != nil {
		return errors.New("production admission authority unavailable")
	}
	defer authority.Close()
	var chatRuns ownerChatService
	var closeChat func()
	if o.ownerChat {
		chatRuns, closeChat, err = deps.newOwnerChat(runCtx, o, capability, roots)
		if err != nil || chatRuns == nil {
			return errors.New("production owner chat unavailable")
		}
		if closeChat == nil {
			closeChat = func() { _ = chatRuns.Close() }
		}
		defer closeChat()
	}
	if err := runCtx.Err(); err != nil {
		return errors.New("production admission cancelled")
	}
	store, err := dshbridge.NewSessionStore(dshbridge.Config{Origin: "http://" + o.listen, Host: o.listen})
	if err != nil {
		return errors.New("production session configuration invalid")
	}
	bridge := &dshbridge.Bridge{Sessions: store, Classifier: productionClassifier{}, Authority: productionCloudAuthority{cloud: authority}}
	var meshUI *meshui.Service
	if o.productionMesh {
		// The capability was constructed above and contains the one verified
		// Coordinator/Revision composition. Its UI source is intentionally
		// exposed only after recovery succeeded; see newProductionMeshRuntime.
		app, appErr := meshRuntime.meshApplication()
		if appErr != nil || app == nil {
			return errors.New("production mesh unavailable")
		}
		meshUI = meshui.NewProjectionServiceWithSource(app, app)
	} else {
		meshUI = meshui.NewProjectionService(nil)
	}
	baseHandler := (&dshbridgehttp.Server{Bridge: bridge, Origin: "http://" + o.listen, Host: o.listen, ChatRuns: chatRuns, MeshUI: meshUI}).Handler()
	var handlers sync.WaitGroup
	var handlerGate sync.Mutex
	stopping := false
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if deps.beforeHandlerRegister != nil {
			deps.beforeHandlerRegister(r)
		}
		handlerGate.Lock()
		if stopping {
			handlerGate.Unlock()
			http.Error(w, "controller unavailable", http.StatusServiceUnavailable)
			return
		}
		handlers.Add(1)
		handlerGate.Unlock()
		defer handlers.Done()
		baseHandler.ServeHTTP(w, r)
	})
	srv := &http.Server{Addr: o.listen, Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second}
	serveDone := make(chan error, 1)
	go func() {
		serveDone <- srv.Serve(listener)
	}()
	var serverFailed bool
	serverJoined := false
	select {
	case <-runCtx.Done():
	case e := <-serveDone:
		serverJoined = true
		serverFailed = e != nil && !errors.Is(e, http.ErrServerClosed)
	}
	shutdownTimeout := deps.shutdownTimeout
	if shutdownTimeout <= 0 {
		shutdownTimeout = 5 * time.Second
	}
	shutdown, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	shutdownErr := srv.Shutdown(shutdown)
	cancel()
	if shutdownErr != nil {
		_ = srv.Close()
	}
	if !serverJoined {
		e := <-serveDone
		serverFailed = serverFailed || (e != nil && !errors.Is(e, http.ErrServerClosed))
	}
	handlerGate.Lock()
	stopping = true
	handlerGate.Unlock()
	handlers.Wait()
	if shutdownErr != nil {
		return errors.New("controller shutdown failed")
	}
	if serverFailed {
		return errors.New("controller server failed")
	}
	return nil
}
