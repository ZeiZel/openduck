// Package macosinstall owns the offline, privileged macOS service-principal
// installation contract. Production construction is deliberately fixed to
// the system Application Support root; tests use an unexported fake-root
// constructor in this package and can therefore never make the CLI arbitrary.
package macosinstall

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"openduck/internal/codexruntime"
	"openduck/internal/macoschannel"
	"openduck/internal/macosrelease"
	"openduck/internal/modelegress"
	"openduck/internal/providertransport"
	"openduck/internal/releasecatalog"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"syscall"
	"time"
)

const SystemRoot = "/Library/Application Support/OpenDuck"

const fixedPFRules = "set block-policy drop\npass out quick on lo0 inet proto tcp from any to 127.0.0.1 port 8790 user _openduck_codex keep state\nblock out quick on lo0 inet proto tcp from any to 127.0.0.1 port 8790\nblock out quick user _openduck_codex\nblock out quick user _openduck_broker\npass out quick inet proto { tcp udp } from any to any user _openduck_egress keep state\n"
const legacyPFRules = "set block-policy drop\npass out quick on lo0 inet proto tcp from any to 127.0.0.1 port 8790 user _openduck_codex keep state\nblock out quick on lo0 inet proto tcp from any to 127.0.0.1 port 8790\nblock out quick user _openduck_codex\nblock out quick user _openduck_broker\npass out quick user _openduck_egress inet proto { tcp udp } keep state\n"
const fixedCodexSeatbelt = "(version 1)\n(deny default)\n(import \"system.sb\")\n(allow process*)\n(allow file-read* (subpath \"/System\") (subpath \"/usr\") (subpath \"/Library/Apple\"))\n(allow file-read* (subpath \"/Library/Application Support/OpenDuck/home/runtime\"))\n(allow file-write* (subpath \"/Library/Application Support/OpenDuck/home/runtime\"))\n(allow file-read* (subpath \"/Library/Application Support/OpenDuck/releases/codex\"))\n(allow network-outbound (remote tcp \"localhost:8790\"))\n"
const fixedEgressSeatbelt = "(version 1)\n(deny default)\n(import \"system.sb\")\n(allow process*)\n(allow file-read* (subpath \"/System\") (subpath \"/usr\") (subpath \"/Library/Apple\"))\n(allow file-read* (subpath \"/Library/Application Support/OpenDuck\"))\n(allow network-outbound)\n"

type Service struct{ Name, User, Group string }

var services = []Service{
	{Name: "checkpoint", User: "_openduck_checkpoint", Group: "_openduck_checkpoint"},
	{Name: "anchor", User: "_openduck_anchor", Group: "_openduck_anchor"},
	{Name: "egress", User: "_openduck_egress", Group: "_openduck_egress"},
	{Name: "runtime", User: "_openduck_codex", Group: "_openduck_codex"},
	{Name: "broker", User: "_openduck_broker", Group: "_openduck_broker"},
	{Name: "controller", User: "_openduck", Group: "_openduck"},
}

type channelKeyTopology struct {
	channel string
	paths   []string
}

// canonicalChannelKeyTopologies is the single inventory of service-key files
// written for each channel. Ownership and verification must use this same
// inventory so an endpoint cannot be chowned before it is created.
func canonicalChannelKeyTopologies() []channelKeyTopology {
	return []channelKeyTopology{
		{channel: "installer-journal", paths: []string{"keys/checkpoint-installer/journal.key", "keys/installer-checkpoint/journal.key"}},
		{channel: "installer-journal", paths: []string{"keys/anchor-installer/journal.key", "keys/installer-anchor/journal.key"}},
		{channel: "platform-anchor", paths: []string{"keys/anchor/service.key", "keys/controller/service.key", "keys/controller-anchor/service.key"}},
		{channel: "platform-checkpoint", paths: []string{"keys/anchor-checkpoint/checkpoint.key", "keys/checkpoint/service.key"}},
		{channel: "model-egress", paths: []string{"keys/egress/service.key", "keys/broker-egress/service.key"}},
		{channel: "codex-owner", paths: []string{"keys/broker-controller/service.key", "keys/controller-broker/service.key"}},
		{channel: "codex-runtime", paths: []string{"keys/runtime/service.key", "keys/broker-runtime/service.key"}},
		{channel: "broker-private", paths: []string{"keys/broker/service.key"}},
	}
}

type keyFileOwnership struct {
	path, user, group string
}

type keyRootOwnership struct {
	path, user, group string
}

func canonicalServiceKeyOwnership() []keyFileOwnership {
	return []keyFileOwnership{
		{path: "keys/checkpoint-installer/journal.key", user: "_openduck_checkpoint", group: "_openduck_checkpoint"},
		{path: "keys/installer-checkpoint/journal.key", user: "root", group: "wheel"},
		{path: "keys/anchor-installer/journal.key", user: "_openduck_anchor", group: "_openduck_anchor"},
		{path: "keys/installer-anchor/journal.key", user: "root", group: "wheel"},
		{path: "keys/anchor/service.key", user: "_openduck_anchor", group: "_openduck_anchor"},
		{path: "keys/controller/service.key", user: "_openduck", group: "_openduck"},
		{path: "keys/controller-anchor/service.key", user: "_openduck", group: "_openduck"},
		{path: "keys/anchor-checkpoint/checkpoint.key", user: "_openduck_anchor", group: "_openduck_anchor"},
		{path: "keys/checkpoint/service.key", user: "_openduck_checkpoint", group: "_openduck_checkpoint"},
		{path: "keys/egress/service.key", user: "_openduck_egress", group: "_openduck_egress"},
		{path: "keys/broker-egress/service.key", user: "_openduck_broker", group: "_openduck_broker"},
		{path: "keys/broker-controller/service.key", user: "_openduck_broker", group: "_openduck_broker"},
		{path: "keys/controller-broker/service.key", user: "_openduck", group: "_openduck"},
		{path: "keys/runtime/service.key", user: "_openduck_codex", group: "_openduck_codex"},
		{path: "keys/broker-runtime/service.key", user: "_openduck_broker", group: "_openduck_broker"},
		{path: "keys/broker/service.key", user: "_openduck_broker", group: "_openduck_broker"},
	}
}

func canonicalKeyRootOwnership() []keyRootOwnership {
	return []keyRootOwnership{
		{path: "keys/checkpoint-installer", user: "_openduck_checkpoint", group: "_openduck_checkpoint"},
		{path: "keys/installer-checkpoint", user: "root", group: "wheel"},
		{path: "keys/anchor-installer", user: "_openduck_anchor", group: "_openduck_anchor"},
		{path: "keys/installer-anchor", user: "root", group: "wheel"},
		{path: "keys/anchor-checkpoint", user: "_openduck_anchor", group: "_openduck_anchor"},
		{path: "keys/controller-anchor", user: "_openduck", group: "_openduck"},
		{path: "keys/controller-broker", user: "_openduck", group: "_openduck"},
		{path: "keys/broker-controller", user: "_openduck_broker", group: "_openduck_broker"},
		{path: "keys/broker-egress", user: "_openduck_broker", group: "_openduck_broker"},
		{path: "keys/broker-runtime", user: "_openduck_broker", group: "_openduck_broker"},
		{path: "keys/egress", user: "_openduck_egress", group: "_openduck_egress"},
		{path: "keys/runtime", user: "_openduck_codex", group: "_openduck_codex"},
	}
}

type Config struct {
	Root      string
	ReleaseID string
	BinaryDir string
	UID, GID  int
	Model     string
}
type Installer struct {
	root                   *os.Root
	stage                  *os.Root
	stageDigests           map[string]string
	providerRoots          map[string]os.FileInfo
	providerTransportRoots map[string]os.FileInfo
	// providerTransportPostPrincipal distinguishes the intentionally empty base
	// prerequisite roots from a separately provisioned, signed post-principal
	// inventory. The base installer never creates that latter state.
	providerTransportPostPrincipal bool
	admitted                       *macosrelease.ManifestV2
	admittedOperation              string
	admittedActivation             bool
	admissionIssuedAt              time.Time
	cfg                            Config
	fake                           bool
	created                        []string
	// backups makes atomic replacements reversible when a later provisioning
	// step fails. Existing state/auth/checkpoint files are never discarded.
	backups                  map[string][]byte
	backupExists             map[string]bool
	backupModes              map[string]os.FileMode
	principalUndo            []func(context.Context) error
	nativeMCPBoundaryCreated bool
	ops                      SystemOps
	runID                    string
	releaseDigest            string
	pfLease                  string
	auditEnabled             bool
	journalBinding           ProductionJournalBinding
	journalAuthority         journalAuthority // fake-installer seam only
	journal                  *ProvisioningJournal
}
type Plan struct {
	Root   string
	Users  []string
	Groups []string
	Paths  []string
	Plists []string
}

// DeploymentEvidence is a bounded, non-secret transaction projection. It is
// returned only after the candidate/active selectors were read back through
// the descriptor-rooted state machine.
type DeploymentEvidence struct {
	ReleaseID  string
	Configured bool
	Activated  bool
}

// Deploy is the production-shaped single-envelope transaction. The same
// Installer/run journal remains authoritative across Apply, verification and
// optional activation, so a restart can only resume a verified checkpoint and
// never publish active.release during configuration.
func (i *Installer) Deploy(ctx context.Context, activate bool) (DeploymentEvidence, error) {
	if i == nil || i.root == nil {
		return DeploymentEvidence{}, errors.New("installer unavailable")
	}
	if i.admitted != nil && (i.admittedOperation != "deploy" || i.admittedActivation != activate) {
		return DeploymentEvidence{}, errors.New("sealed deployment intent mismatch")
	}
	if err := i.requireJobsUnloaded(ctx); err != nil {
		return DeploymentEvidence{}, err
	}
	if err := i.journalTransition("deploy", "preflight"); err != nil {
		return DeploymentEvidence{}, err
	}
	if err := i.Apply(); err != nil {
		return DeploymentEvidence{}, err
	}
	if err := i.configuredCandidate(); err != nil {
		return DeploymentEvidence{}, err
	}
	evidence := DeploymentEvidence{ReleaseID: i.cfg.ReleaseID, Configured: true}
	if !activate {
		if err := i.journalTransition("deploy", "verify"); err != nil {
			return DeploymentEvidence{}, err
		}
		return evidence, nil
	}
	if err := i.Activate(ctx); err != nil {
		return DeploymentEvidence{}, err
	}
	active, err := i.readReleaseState("active.release")
	if err != nil || active != i.cfg.ReleaseID {
		return DeploymentEvidence{}, errors.New("deployment active pointer verification failed")
	}
	if err := i.journalTransition("deploy", "commit"); err != nil {
		return DeploymentEvidence{}, err
	}
	evidence.Activated = true
	return evidence, nil
}

// NewProduction is the only production constructor. It accepts the sealed
// admission/snapshot hand-off, never a caller-selected release ID or path.
func NewProduction(input macosrelease.DeploymentInput) (*Installer, error) {
	if runtime.GOOS != "darwin" {
		return nil, errors.New("macOS installer requires darwin")
	}
	if os.Geteuid() != 0 {
		return nil, errors.New("macOS installer requires root")
	}
	manifest, binaryDir, err := input.InstallerBinding()
	if err != nil || !validID(manifest.ReleaseID) || !isDigest(manifest.ReleaseDigest) || manifest.TargetRoot != SystemRoot {
		return nil, errors.New("sealed release input required")
	}
	operation, runID, activation, err := input.InstallerIntent()
	if err != nil {
		return nil, errors.New("sealed release intent required")
	}
	parent, err := os.OpenRoot("/Library/Application Support")
	if err != nil {
		return nil, fmt.Errorf("open trusted application-support root: %w", err)
	}
	r, err := openOrNormalizeInstallRoot(parent, "OpenDuck", 0, 0)
	closeErr := parent.Close()
	if err != nil {
		return nil, err
	}
	if closeErr != nil {
		_ = r.Close()
		return nil, fmt.Errorf("close trusted application-support root: %w", closeErr)
	}
	issuedAt, err := input.InstallerValidationTime()
	if err != nil {
		_ = r.Close()
		return nil, errors.New("sealed release validation time required")
	}
	return &Installer{root: r, cfg: Config{Root: SystemRoot, ReleaseID: manifest.ReleaseID, BinaryDir: binaryDir, UID: -1, GID: -1, Model: "gpt-5.6"}, admitted: &manifest, admittedOperation: operation, admittedActivation: activation, admissionIssuedAt: issuedAt, releaseDigest: manifest.ReleaseDigest, runID: runID, auditEnabled: true, backups: map[string][]byte{}, backupExists: map[string]bool{}, backupModes: map[string]os.FileMode{}, ops: newDarwinSystemOps()}, nil
}

// openOrNormalizeInstallRoot creates or opens leaf beneath an already trusted
// parent and normalizes the directory through its opened descriptor. Returning
// that same descriptor-rooted handle avoids reopening the security boundary by
// pathname after validation.
func openOrNormalizeInstallRoot(parent *os.Root, leaf string, uid, gid int) (*os.Root, error) {
	if parent == nil || leaf == "" || leaf == "." || leaf == ".." || filepath.Base(leaf) != leaf || uid < 0 || gid < 0 {
		return nil, errors.New("invalid fixed install root bootstrap")
	}
	before, err := parent.Lstat(leaf)
	if errors.Is(err, os.ErrNotExist) {
		if err = parent.Mkdir(leaf, 0711); err != nil && !errors.Is(err, os.ErrExist) {
			return nil, fmt.Errorf("bootstrap fixed install root: %w", err)
		}
		before, err = parent.Lstat(leaf)
	}
	if err != nil || !safeInstallRootCandidate(before, uint32(uid)) {
		return nil, errors.New("fixed install root is not a trusted directory")
	}

	root, err := parent.OpenRoot(leaf)
	if err != nil {
		return nil, fmt.Errorf("open fixed install root: %w", err)
	}
	f, err := root.Open(".")
	if err != nil {
		_ = root.Close()
		return nil, fmt.Errorf("open fixed install root descriptor: %w", err)
	}
	opened, statErr := f.Stat()
	if statErr != nil || !sameFileIdentity(before, opened) || !safeInstallRootCandidate(opened, uint32(uid)) {
		_ = f.Close()
		_ = root.Close()
		return nil, errors.New("fixed install root identity changed during bootstrap")
	}
	if err = f.Chown(uid, gid); err == nil {
		err = f.Chmod(0711)
	}
	if err == nil {
		err = f.Sync()
	}
	after, afterErr := f.Stat()
	closeErr := f.Close()
	pathAfter, pathErr := parent.Lstat(leaf)
	if err != nil || afterErr != nil || closeErr != nil {
		_ = root.Close()
		return nil, fmt.Errorf("normalize fixed install root: %w", errors.Join(err, afterErr, closeErr))
	}
	if pathErr != nil || !sameFileIdentity(opened, after) || !sameFileIdentity(after, pathAfter) || !trustedInstallRoot(after, uint32(uid), uint32(gid)) || !trustedInstallRoot(pathAfter, uint32(uid), uint32(gid)) {
		_ = root.Close()
		return nil, errors.New("fixed install root failed trusted revalidation")
	}
	return root, nil
}

func safeInstallRootCandidate(info os.FileInfo, uid uint32) bool {
	if info == nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 || info.Mode().Perm()&0022 != 0 {
		return false
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	return ok && st != nil && uint32(st.Uid) == uid
}

func trustedInstallRoot(info os.FileInfo, uid, gid uint32) bool {
	return safeInstallRootCandidate(info, uid) && info.Mode().Perm() == 0711 && ownedBy(info, uid, gid)
}

// newFakeInstaller is intentionally private: only package tests may choose a
// root. It also keeps the same descriptor-relative code path as production.
func newFakeInstaller(root, releaseID, binaryDir string) (*Installer, error) {
	if !filepath.IsAbs(root) || !validID(releaseID) || !filepath.IsAbs(binaryDir) {
		return nil, errors.New("invalid fixture")
	}
	if err := os.MkdirAll(root, 0700); err != nil {
		return nil, err
	}
	r, err := os.OpenRoot(root)
	if err != nil {
		return nil, err
	}
	return &Installer{root: r, cfg: Config{Root: root, ReleaseID: releaseID, BinaryDir: binaryDir, UID: os.Getuid(), GID: os.Getgid(), Model: "gpt-5.6"}, releaseDigest: DefaultReleaseDigest(releaseID), runID: newRunID(), fake: true, backups: map[string][]byte{}, backupExists: map[string]bool{}, backupModes: map[string]os.FileMode{}, ops: newFakeSystemOps(), journalAuthority: newFakeProvisioningJournalAuthority()}, nil
}

// newFakeAdmittedInstaller exercises the same ManifestV2 snapshot/preflight
// path as production while keeping the fixed-root and system-op seams inside
// package tests.
func newFakeAdmittedInstaller(root string, input macosrelease.DeploymentInput) (*Installer, error) {
	manifest, source, err := input.InstallerBinding()
	if err != nil || !filepath.IsAbs(root) || !validID(manifest.ReleaseID) || !isDigest(manifest.ReleaseDigest) {
		return nil, errors.New("invalid admitted fixture")
	}
	if err := os.MkdirAll(root, 0700); err != nil {
		return nil, err
	}
	r, err := os.OpenRoot(root)
	if err != nil {
		return nil, err
	}
	operation, runID, activation, err := input.InstallerIntent()
	if err != nil {
		_ = r.Close()
		return nil, errors.New("invalid admitted fixture intent")
	}
	issuedAt, err := input.InstallerValidationTime()
	if err != nil {
		_ = r.Close()
		return nil, errors.New("invalid admitted fixture validation time")
	}
	return &Installer{root: r, cfg: Config{Root: root, ReleaseID: manifest.ReleaseID, BinaryDir: source, UID: os.Getuid(), GID: os.Getgid(), Model: "gpt-5.6"}, admitted: &manifest, admittedOperation: operation, admittedActivation: activation, admissionIssuedAt: issuedAt, releaseDigest: manifest.ReleaseDigest, runID: runID, fake: true, backups: map[string][]byte{}, backupExists: map[string]bool{}, backupModes: map[string]os.FileMode{}, ops: newFakeSystemOps(), journalAuthority: newFakeProvisioningJournalAuthority()}, nil
}
func (i *Installer) Close() error {
	if i == nil || i.root == nil {
		return nil
	}
	return i.root.Close()
}

func (i *Installer) Plan() Plan {
	p := Plan{Root: i.cfg.Root, Users: make([]string, 0, len(services)), Groups: []string{"_openduck_channel", "_openduck_checkpoint_channel", "_openduck_egress_channel", "_openduck_broker_channel", "_openduck_runtime_channel", "_openduck_installer_checkpoint_channel", "_openduck_installer_anchor_channel"}}
	for _, s := range services {
		p.Users = append(p.Users, s.User)
		p.Groups = append(p.Groups, s.Group)
		p.Paths = append(p.Paths, "state/"+s.Name, "logs/"+s.Name, "home/"+s.Name, "keys/"+s.Name)
	}
	for _, keyRoot := range canonicalKeyRootOwnership() {
		if keyRoot.path == "keys/egress" || keyRoot.path == "keys/runtime" {
			// These roots are created and planned by the corresponding service
			// inventory above; do not request a second, conflicting mode.
			continue
		}
		p.Paths = append(p.Paths, keyRoot.path)
	}
	p.Paths = append(p.Paths, "home/controller/bin")
	p.Paths = append(p.Paths, "releases/"+i.cfg.ReleaseID, "releases/codex", "releases/anchor-checkpoint", "releases/checkpoint-installer", "releases/checkpoint-installer/"+i.cfg.ReleaseID, "releases/anchor-installer", "releases/anchor-installer/"+i.cfg.ReleaseID, "releases/installer-checkpoint", "releases/installer-checkpoint/"+i.cfg.ReleaseID, "releases/installer-anchor", "releases/installer-anchor/"+i.cfg.ReleaseID, "operator", "operator/owner-capabilities", "channels", "channels/platform-anchor", "channels/model-egress", "channels/codex-owner", "channels/codex-runtime", "channels/installer-checkpoint", "channels/installer-anchor", "checkpoint-channel", "checkpoint-channel/platform-checkpoint", "pf", "seatbelt")
	if len(i.optionalProviderDescriptorEntries()) != 0 {
		// These are the base, empty topology prerequisites only. Per-provider
		// directories, sockets, and keys are post-principal signed-gate state.
		p.Paths = append(p.Paths, "channels/providers", "keys/controller-provider")
	}
	for _, s := range services {
		label := serviceLabel(s.Name)
		p.Plists = append(p.Plists, "com.openduck."+label+".plist")
	}
	sort.Strings(p.Paths)
	sort.Strings(p.Groups)
	sort.Strings(p.Plists)
	return p
}

// Apply provisions only filesystem objects. Account/group creation and
// launchctl are represented by Plan and are intentionally an operator step.
func (i *Installer) Apply() (err error) {
	if i == nil || i.root == nil {
		return errors.New("installer unavailable")
	}
	i.created = nil
	i.backups = map[string][]byte{}
	i.backupExists = map[string]bool{}
	i.backupModes = map[string]os.FileMode{}
	i.principalUndo = nil
	if !i.fake && os.Geteuid() != 0 {
		return errors.New("apply requires root")
	}
	if i.cfg.BinaryDir == "" {
		return errors.New("apply requires staged binary directory")
	}
	if err := i.requireJobsUnloaded(context.Background()); err != nil {
		return err
	}
	if auditErr := i.audit("apply", "started", "started", "", "", true); auditErr != nil {
		if i.stage != nil {
			_ = i.stage.Close()
			i.stage, i.stageDigests = nil, nil
		}
		return fmt.Errorf("audit start: %w", auditErr)
	}
	journalStarted := false
	defer func() {
		if i.stage != nil {
			_ = i.stage.Close()
			i.stage = nil
			i.stageDigests = nil
		}
		if err != nil {
			compensation := errors.Join(i.rollbackPrincipals(context.Background()), i.cleanupWithError())
			if compensation != nil {
				err = &ProvisioningTransactionError{Primary: err, Compensation: fmt.Errorf("apply compensation failed: %w", compensation)}
			}
		} else {
			i.created, i.backups, i.backupExists, i.backupModes = nil, nil, nil, nil
			i.principalUndo = nil
		}
		// Cleanup is a separate authority outcome: a successful compensation must
		// not imply its journal/temporary-resource cleanup was proven.
		if journalStarted {
			if cleanupCheckpointErr := i.journalTransition("apply", "cleanup"); cleanupCheckpointErr != nil {
				if err == nil {
					err = cleanupCheckpointErr
				} else {
					err = &ProvisioningTransactionError{Primary: err, Compensation: cleanupCheckpointErr}
				}
			}
		}
		outcome, reason, scope := "succeeded", "", ""
		if err != nil {
			outcome, reason, scope = "failed", safeReasonCode(err), "installer"
		}
		if finishErr := i.audit("apply", "finished", outcome, reason, scope, true); finishErr != nil {
			if err == nil {
				err = fmt.Errorf("audit finish: %w", finishErr)
			} else {
				err = errors.Join(err, fmt.Errorf("audit finish: %w", finishErr))
			}
		}
		checkpointEvent := "commit"
		if err != nil {
			checkpointEvent = "compensate"
		}
		if journalStarted {
			if checkpointErr := i.journalTransition("apply", checkpointEvent); checkpointErr != nil {
				if err == nil {
					err = checkpointErr
				} else {
					err = &ProvisioningTransactionError{Primary: err, Compensation: checkpointErr}
				}
			}
		}
	}()
	// Audit is durable evidence of every accepted transaction attempt, including
	// a staged-artifact preflight rejection. It is deliberately before preflight,
	// while the journal remains below the read-only staging boundary.
	if err := i.preflight(); err != nil {
		return err
	}
	if err := i.journalTransition("apply", "preflight"); err != nil {
		return err
	}
	journalStarted = true
	if err := i.journalTransition("apply", "stage_plan"); err != nil {
		return err
	}
	if err := i.provisionPrincipals(context.Background()); err != nil {
		return err
	}
	if err := i.verifyDistinctPrincipalIDs(context.Background()); err != nil {
		return err
	}
	createdBoundary, boundaryErr := i.ops.PrepareNativeMCPBoundary(context.Background())
	if boundaryErr != nil {
		return boundaryErr
	}
	i.nativeMCPBoundaryCreated = createdBoundary
	dirs := []struct {
		p string
		m os.FileMode
	}{{"state", 0711}, {"logs", 0711}, {"home", 0711}, {"keys", 0711}, {"releases", 0711}, {"operator", 0700}, {"channels", 0711}, {"checkpoint-channel", 0711}, {"pf", 0700}, {"seatbelt", 0755}, {"launchd", 0700}}
	for _, d := range dirs {
		if err := i.mkdir(d.p, d.m); err != nil {
			return err
		}
	}
	for _, p := range []string{"channels/platform-anchor", "channels/model-egress", "channels/codex-owner", "channels/codex-runtime", "checkpoint-channel/platform-checkpoint", "channels/installer-checkpoint", "channels/installer-anchor"} {
		if err := i.mkdir(p, 0750); err != nil {
			return err
		}
	}
	for _, s := range services {
		for _, base := range []string{"state", "logs", "home", "keys"} {
			mode := os.FileMode(0700)
			if err := i.mkdir(base+"/"+s.Name, mode); err != nil {
				return err
			}
		}
	}
	if err := i.mkdir("home/runtime/bin", 0700); err != nil {
		return err
	}
	if err := i.mkdir("home/runtime/work", 0700); err != nil {
		return err
	}
	if err := i.mkdir("home/controller/bin", 0700); err != nil {
		return err
	}
	if err := i.prepareInactiveProviderRoots(); err != nil {
		return err
	}
	if err := i.prepareProviderTransportPrerequisites(); err != nil {
		return err
	}
	if err := i.mkdir("state/controller/owner-queue", 0700); err != nil {
		return err
	}
	if err := i.mkdir("operator/owner-capabilities", 0710); err != nil {
		return err
	}
	for _, keyRoot := range canonicalKeyRootOwnership() {
		if keyRoot.path == "keys/egress" || keyRoot.path == "keys/runtime" {
			// Service directories are created by the service inventory above.
			continue
		}
		mode := os.FileMode(0700)
		if err := i.mkdir(keyRoot.path, mode); err != nil {
			return err
		}
	}
	for _, s := range services {
		if err := i.mkdirRelease("releases/" + s.Name); err != nil {
			return err
		}
		if err := i.mkdirRelease("releases/" + s.Name + "/" + i.cfg.ReleaseID); err != nil {
			return err
		}
	}
	if err := i.mkdirRelease("releases/anchor-checkpoint"); err != nil {
		return err
	}
	if err := i.mkdirRelease("releases/anchor-checkpoint/" + i.cfg.ReleaseID); err != nil {
		return err
	}
	for _, service := range []string{"installer-checkpoint", "installer-anchor", "checkpoint-installer", "anchor-installer"} {
		if err := i.mkdirRelease("releases/" + service); err != nil {
			return err
		}
		if err := i.mkdirRelease("releases/" + service + "/" + i.cfg.ReleaseID); err != nil {
			return err
		}
	}
	if err := i.mkdir("releases/codex", 0755); err != nil {
		return err
	}
	if err := i.mkdir("releases/codex/"+i.cfg.ReleaseID, 0755); err != nil {
		return err
	}
	if err := i.copyRelease(); err != nil {
		return err
	}
	if err := i.copyJournalAuthorityReleases(); err != nil {
		return err
	}
	if err := i.persistAdmittedManifest(); err != nil {
		return err
	}
	if err := i.copyAnchorCheckpointRelease(); err != nil {
		return err
	}
	if err := i.copyCodexCLI(); err != nil {
		return err
	}
	if err := i.copyOperatorTools(); err != nil {
		return err
	}
	if err := i.copyInstallerBootstrap(); err != nil {
		return err
	}
	if err := i.copyInstallerJournalReleases(); err != nil {
		return err
	}
	if err := i.copyInactiveProviderArtifacts(); err != nil {
		return err
	}
	if err := i.writeRuntimeArtifacts(); err != nil {
		return err
	}
	if err := i.journalTransition("apply", "configure"); err != nil {
		return err
	}
	if err := i.writeLoginConfig(context.Background()); err != nil {
		return err
	}
	for _, pair := range canonicalChannelKeyTopologies() {
		record, err := i.existingChannelRecord(pair.channel, pair.paths)
		if err != nil {
			return err
		}
		if record == nil {
			raw := make([]byte, 32)
			if _, err := io.ReadFull(rand.Reader, raw); err != nil {
				return err
			}
			record = canonicalServiceKey(pair.channel, 1, raw)
			for n := range raw {
				raw[n] = 0
			}
		}
		for _, p := range pair.paths {
			if err := i.writeKeyBytes(p, record); err != nil {
				for n := range record {
					record[n] = 0
				}
				return err
			}
		}
		for n := range record {
			record[n] = 0
		}
	}
	if err := i.ensureOwnerKeyPair(); err != nil {
		return err
	}
	// An Apply-only candidate is not rollbackable. Preserve the old active
	// release separately only when it already has finalized evidence and all
	// release-scoped pins/plists required by Rollback.
	if prev, e := i.root.ReadFile("active.release"); e == nil {
		id := strings.TrimSpace(string(prev))
		if id != "" && id != i.cfg.ReleaseID && i.releaseRollbackReady(id) {
			if err := i.atomicText("pending.rollback", id+"\n", 0644); err != nil {
				return err
			}
		} else if !i.validExistingRollbackMarker("pending.rollback") && !i.validExistingRollbackMarker("previous.release") {
			if err := i.atomicRemove("pending.rollback"); err != nil {
				return err
			}
			if err := i.atomicRemove("previous.release"); err != nil {
				return err
			}
		}
	} else if errors.Is(e, os.ErrNotExist) && !i.validExistingRollbackMarker("pending.rollback") && !i.validExistingRollbackMarker("previous.release") {
		if err := i.atomicRemove("pending.rollback"); err != nil {
			return err
		}
		if err := i.atomicRemove("previous.release"); err != nil {
			return err
		}
	}
	// active.release is an operational commit pointer. Apply intentionally never
	// touches it: an upgrade must leave the last activated release selected
	// until Activate has completed every effect and written its activation
	// evidence.
	for _, s := range services {
		if s.Name == "runtime" || s.Name == "broker" {
			if _, e := i.root.Lstat("seatbelt/pf-evidence.json"); e != nil {
				continue
			}
		}
		label := serviceLabel(s.Name)
		plist := i.renderResolvedPlist(context.Background(), s)
		if plist == "" {
			return errors.New("runtime pins unavailable")
		}
		if err := i.atomicText("launchd/com.openduck."+label+".plist", plist, 0644); err != nil {
			return err
		}
	}
	for _, path := range []string{"pf/openduck.conf", "seatbelt/state", "seatbelt/codex.sb", "seatbelt/egress.sb"} {
		if err := i.applyFixedSharedPolicy(path); err != nil {
			return fmt.Errorf("policy upgrade: %w", err)
		}
	}
	if err := i.sealDaemonReleases(); err != nil {
		return err
	}
	if err := i.applyOwnership(context.Background()); err != nil {
		return err
	}
	if err := i.verifyProductionOwnership(context.Background(), true); err != nil {
		return err
	}
	// Candidate is only recorded after the complete scoped configuration has
	// converged. Verify accepts this non-operational selector; configured is
	// published only after it passes.
	if err := i.writeReleaseState("candidate.release", i.cfg.ReleaseID); err != nil {
		return err
	}
	if err := i.Verify(); err != nil {
		return err
	}
	if err := i.journalTransition("apply", "verify"); err != nil {
		return err
	}
	return i.writeReleaseState("configured.release", i.cfg.ReleaseID)
}

func (i *Installer) verifyInstalledAdmittedManifest() error {
	if i.admitted == nil {
		return nil
	}
	path := "releases/controller/" + i.cfg.ReleaseID + "/release-manifest.v2.json"
	raw, err := i.root.ReadFile(path)
	if err != nil {
		return errors.New("installed admitted manifest unavailable")
	}
	st, statErr := i.root.Lstat(path)
	expectedUID, expectedGID := uint32(0), uint32(0)
	if i.fake {
		expectedUID, expectedGID = uint32(i.cfg.UID), uint32(i.cfg.GID)
	}
	if statErr != nil || !safeExistingRegular(st, 0440, int64(len(raw))) || !ownedBy(st, expectedUID, expectedGID) {
		return errors.New("installed admitted manifest unsafe")
	}
	expected, err := json.Marshal(i.admitted)
	if err != nil || !bytes.Equal(raw, append(expected, '\n')) {
		return errors.New("installed admitted manifest mismatch")
	}
	return nil
}

func (i *Installer) validExistingRollbackMarker(path string) bool {
	b, err := i.root.ReadFile(path)
	return err == nil && i.validateRollbackRelease(strings.TrimSpace(string(b))) == nil
}

func (i *Installer) releaseRollbackReady(id string) bool {
	return i.validateRollbackRelease(id) == nil
}

// validateRollbackRelease is the single admission gate for both preserving a
// rollback target during Apply and consuming it during Rollback.  A release is
// rollbackable only after Activate wrote its root-owned marker and the complete
// immutable release closure still verifies.
func (i *Installer) validateRollbackRelease(id string) error {
	if !validID(id) {
		return errors.New("previous release unverified")
	}
	markerPath := "releases/controller/" + id + "/activated"
	marker, markerErr := i.root.ReadFile(markerPath)
	if markerErr != nil || !bytes.Equal(marker, []byte(id+"\n")) {
		return errors.New("previous release unverified")
	}
	markerInfo, markerStatErr := i.root.Lstat(markerPath)
	expectedUID, expectedGID := uint32(0), uint32(0)
	if i.fake {
		expectedUID, expectedGID = uint32(i.cfg.UID), uint32(i.cfg.GID)
	}
	if markerStatErr != nil || !safeExistingRegular(markerInfo, 0440, int64(len(marker))) || !ownedBy(markerInfo, expectedUID, expectedGID) {
		return errors.New("previous release unverified")
	}
	return i.validateImmutableReleaseClosure(id)
}

func (i *Installer) expectedImmutableOwner(user, group string) (uint32, uint32, error) {
	if i.fake {
		return uint32(i.cfg.UID), uint32(i.cfg.GID), nil
	}
	if user == "root" && group == "wheel" {
		return 0, 0, nil
	}
	_, gid, err := i.ops.PrincipalIDs(context.Background(), user, group)
	return 0, gid, err
}

func (i *Installer) validateImmutableReleaseClosure(id string) error {
	if !validID(id) {
		return errors.New("previous release unverified")
	}
	for _, s := range services {
		expectedUID, expectedGID, ownerErr := i.expectedImmutableOwner(s.User, s.Group)
		if ownerErr != nil {
			return errors.New("previous release ownership unavailable")
		}
		releaseRoot := "releases/" + s.Name + "/" + id
		manifest, err := i.root.ReadFile(releaseRoot + "/manifest.json")
		if err != nil {
			return errors.New("previous release unverified")
		}
		var m struct {
			ReleaseID    string `json:"release_id"`
			Binary       string `json:"binary"`
			BinaryDigest string `json:"binary_digest"`
		}
		if json.Unmarshal(manifest, &m) != nil || m.ReleaseID != id || m.Binary != binaryName(s.Name) || !isDigest(m.BinaryDigest) {
			return errors.New("previous release manifest invalid")
		}
		binary, err := i.root.ReadFile(releaseRoot + "/" + m.Binary)
		if err != nil || Digest(binary) != m.BinaryDigest {
			return errors.New("previous release binary invalid")
		}
		rootInfo, rootErr := i.root.Lstat(releaseRoot)
		manifestInfo, manifestErr := i.root.Lstat(releaseRoot + "/manifest.json")
		binaryInfo, binaryErr := i.root.Lstat(releaseRoot + "/" + m.Binary)
		if rootErr != nil || !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 || rootInfo.Mode().Perm() != 0550 ||
			manifestErr != nil || !safeExistingRegular(manifestInfo, 0440, int64(len(manifest))) ||
			binaryErr != nil || !safeExistingRegular(binaryInfo, 0550, int64(len(binary))) ||
			!ownedBy(rootInfo, expectedUID, expectedGID) || !ownedBy(manifestInfo, expectedUID, expectedGID) || !ownedBy(binaryInfo, expectedUID, expectedGID) {
			return errors.New("previous release metadata invalid")
		}
	}
	current := i.cfg.ReleaseID
	i.cfg.ReleaseID = id
	defer func() { i.cfg.ReleaseID = current }()
	if err := i.verifyReleasePins(id); err != nil {
		return err
	}
	pinOwners := map[string]Service{}
	for _, s := range services {
		pinOwners[s.Name] = s
	}
	for _, rel := range []string{"egress/local-release.json", "egress/peer-release.json", "broker/local-release.json", "broker/egress-release.json", "broker/runtime-release.json", "broker/controller-release.json", "controller/local-release.json", "controller/broker-release.json", "runtime/local-release.json", "runtime/broker-release.json"} {
		serviceName := strings.SplitN(rel, "/", 2)[0]
		s := pinOwners[serviceName]
		expectedUID, expectedGID, ownerErr := i.expectedImmutableOwner(s.User, s.Group)
		st, statErr := i.root.Lstat("releases/" + serviceName + "/" + id + "/" + strings.SplitN(rel, "/", 2)[1])
		if ownerErr != nil || statErr != nil || !ownedBy(st, expectedUID, expectedGID) {
			return errors.New("previous release pin ownership invalid")
		}
	}
	policyRaw, err := i.root.ReadFile("releases/egress/" + id + "/egress-policy.json")
	if err != nil {
		return errors.New("previous release policy unavailable")
	}
	policyInfo, policyStatErr := i.root.Lstat("releases/egress/" + id + "/egress-policy.json")
	egressUID, egressGID, egressOwnerErr := i.expectedImmutableOwner("_openduck_egress", "_openduck_egress")
	if policyStatErr != nil || egressOwnerErr != nil || !safeExistingRegular(policyInfo, 0440, int64(len(policyRaw))) || !ownedBy(policyInfo, egressUID, egressGID) {
		return errors.New("previous release policy metadata invalid")
	}
	var policy modelegress.Policy
	if json.Unmarshal(policyRaw, &policy) != nil {
		return errors.New("previous release policy invalid")
	}
	canonical, canonicalErr := policy.Canonical()
	manifest, manifestErr := i.root.ReadFile("releases/egress/" + id + "/manifest.json")
	if canonicalErr != nil || manifestErr != nil || !bytes.Equal(policyRaw, append(canonical, '\n')) || policy.ReleaseDigest != "sha256:"+Digest(manifest) {
		return errors.New("previous release policy pin invalid")
	}
	if err := i.verifyChannelAndAnchorCheckpointArtifacts(); err != nil {
		return err
	}
	anchorUID, anchorGID, anchorOwnerErr := i.expectedImmutableOwner("_openduck_anchor", "_openduck_anchor")
	anchorRoot := "releases/anchor-checkpoint/" + id
	for path, mode := range map[string]os.FileMode{anchorRoot: 0550, anchorRoot + "/manifest.json": 0440, anchorRoot + "/openduck-anchor": 0550} {
		st, statErr := i.root.Lstat(path)
		validMetadata := statErr == nil && st.Mode()&os.ModeSymlink == 0 && st.Mode().Perm() == mode
		if validMetadata && st.Mode().IsRegular() {
			validMetadata = safeExistingRegular(st, mode, st.Size())
		}
		if anchorOwnerErr != nil || !validMetadata || !ownedBy(st, anchorUID, anchorGID) {
			return errors.New("previous release anchor ownership invalid")
		}
	}
	if err := i.verifyCodexRelease(); err != nil {
		return err
	}
	codexUID, codexGID, codexOwnerErr := i.expectedImmutableOwner("root", "wheel")
	codexRoot := "releases/codex/" + id
	for _, path := range []string{codexRoot, codexRoot + "/manifest.json", codexRoot + "/codex"} {
		st, statErr := i.root.Lstat(path)
		if codexOwnerErr != nil || statErr != nil || !ownedBy(st, codexUID, codexGID) {
			return errors.New("previous Codex release ownership invalid")
		}
	}
	return nil
}

func (i *Installer) writeActivatedMarker(id string) error {
	path := "releases/controller/" + id + "/activated"
	if _, err := i.root.Lstat(path); err == nil {
		return i.validateRollbackRelease(id)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := i.validateImmutableReleaseClosure(id); err != nil {
		return err
	}
	if i.fake {
		// Tests run without uid 0 and therefore cannot create a file in the
		// production 0550 release directory.  Production never changes it.
		dir := "releases/controller/" + id
		if err := i.root.Chmod(dir, 0750); err != nil {
			return err
		}
		defer i.root.Chmod(dir, 0550) // best effort is sufficient only in fake roots
	}
	f, err := i.root.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0440)
	if err != nil {
		return err
	}
	if err = f.Chmod(0440); err == nil {
		_, err = io.WriteString(f, id+"\n")
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		_ = i.root.Remove(path)
	}
	return err
}

func (i *Installer) existingChannelRecord(channel string, paths []string) ([]byte, error) {
	var record []byte
	for _, p := range paths {
		b, err := i.readProtectedFile(p, 0600, 116)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if !validCanonicalServiceKey(b, channel, 1) {
			return nil, errors.New("existing channel key record unsafe")
		}
		if record == nil {
			record = append([]byte(nil), b...)
		} else if !bytes.Equal(record, b) {
			return nil, errors.New("existing endpoint key copies differ")
		}
	}
	return record, nil
}

func validCanonicalServiceKey(record []byte, channel string, epoch uint64) bool {
	if len(record) != 116 || len(channel) == 0 || len(channel) > 64 || string(record[:8]) != string([]byte{'O', 'D', 'K', 'E', 'Y', 'F', 'D', 1}) || record[8] != 1 || int(record[9]) != len(channel) || record[10] != 0 || record[11] != 0 || string(record[12:12+len(channel)]) != channel || binary.BigEndian.Uint64(record[76:84]) != epoch {
		return false
	}
	for _, b := range record[12+len(channel) : 76] {
		if b != 0 {
			return false
		}
	}
	return true
}

func (i *Installer) ensureOwnerKeyPair() error {
	privateRaw, privateErr := i.readProtectedFile("operator/owner-ed25519.key", 0600, ed25519.PrivateKeySize)
	publicRaw, publicErr := i.readProtectedFile("keys/controller-anchor/owner.public", 0600, ed25519.PublicKeySize)
	if privateErr == nil || publicErr == nil {
		if privateErr != nil || publicErr != nil || len(privateRaw) != ed25519.PrivateKeySize || len(publicRaw) != ed25519.PublicKeySize || !bytes.Equal(ed25519.PrivateKey(privateRaw).Public().(ed25519.PublicKey), publicRaw) {
			return errors.New("owner key pair mismatch")
		}
		for n := range privateRaw {
			privateRaw[n] = 0
		}
		return nil
	}
	pub, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	if err := i.writeBytesExact("operator/owner-ed25519.key", private, 0600); err != nil {
		return err
	}
	for n := range private {
		private[n] = 0
	}
	if err := i.writeBytesExact("keys/controller-anchor/owner.public", pub, 0600); err != nil {
		return err
	}
	return nil
}

func (i *Installer) readProtectedFile(path string, mode os.FileMode, size int64) ([]byte, error) {
	before, err := i.root.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !safeExistingRegular(before, mode, size) {
		return nil, errors.New("protected file metadata mismatch")
	}
	f, err := i.root.Open(path)
	if err != nil {
		return nil, err
	}
	after, statErr := f.Stat()
	b, readErr := io.ReadAll(io.LimitReader(f, size+1))
	closeErr := f.Close()
	if statErr != nil || readErr != nil || closeErr != nil || !sameFileIdentity(before, after) || !safeExistingRegular(after, mode, size) || int64(len(b)) != size {
		return nil, errors.New("protected file changed while opening")
	}
	return b, nil
}

func (i *Installer) writeRuntimeArtifacts() error {
	pin := func(service string) ([]byte, error) {
		path := "releases/" + service + "/" + i.cfg.ReleaseID + "/manifest.json"
		b, e := i.root.ReadFile(path)
		if e != nil {
			return nil, e
		}
		var m map[string]string
		if e = json.Unmarshal(b, &m); e != nil {
			return nil, e
		}
		v := map[string]string{"release_id": m["release_id"], "binary_digest": m["binary_digest"], "socket_digest": m["socket_digest"], "manifest_digest": Digest(b)}
		return json.Marshal(v)
	}
	egress, e := pin("egress")
	if e != nil {
		return e
	}
	broker, e := pin("broker")
	if e != nil {
		return e
	}
	controller, e := pin("controller")
	if e != nil {
		return e
	}
	runtime, e := pin("runtime")
	if e != nil {
		return e
	}
	for p, b := range map[string][]byte{"releases/egress/" + i.cfg.ReleaseID + "/local-release.json": egress, "releases/egress/" + i.cfg.ReleaseID + "/peer-release.json": broker, "releases/broker/" + i.cfg.ReleaseID + "/egress-release.json": egress, "releases/broker/" + i.cfg.ReleaseID + "/local-release.json": broker, "releases/broker/" + i.cfg.ReleaseID + "/runtime-release.json": runtime, "releases/broker/" + i.cfg.ReleaseID + "/controller-release.json": controller, "releases/controller/" + i.cfg.ReleaseID + "/local-release.json": controller, "releases/controller/" + i.cfg.ReleaseID + "/broker-release.json": broker, "releases/runtime/" + i.cfg.ReleaseID + "/local-release.json": runtime, "releases/runtime/" + i.cfg.ReleaseID + "/broker-release.json": broker} {
		if err := i.writeText(p, string(b)+"\n", 0440); err != nil {
			return err
		}
	}
	uid, gid, e := i.ops.PrincipalIDs(context.Background(), "_openduck_egress", "_openduck_egress_channel")
	if e != nil {
		return e
	}
	var ep struct {
		ManifestDigest string `json:"manifest_digest"`
		SocketDigest   string `json:"socket_digest"`
	}
	if e := json.Unmarshal(egress, &ep); e != nil || !isDigest(ep.ManifestDigest) || !isDigest(ep.SocketDigest) {
		return errors.New("invalid egress release pin")
	}
	policy, e := modelegress.NewPolicy([]string{"api.openai.com"}, uid, gid, "sha256:"+ep.ManifestDigest, "sha256:"+ep.SocketDigest, 1)
	if e != nil {
		return e
	}
	pb, e := policy.Canonical()
	if e != nil {
		return e
	}
	// The broker and egress run as distinct unprivileged principals and both
	// must read the same root-owned, digest-pinned public policy document.
	policyText := string(pb) + "\n"
	if err := i.writeText("releases/egress/"+i.cfg.ReleaseID+"/egress-policy.json", policyText, 0440); err != nil {
		return err
	}
	return i.atomicText("pf/egress-policy.json", policyText, 0644)
}

type serviceLoginConfig struct {
	Schema    string   `json:"schema"`
	ReleaseID string   `json:"release_id"`
	Binary    string   `json:"binary"`
	Args      []string `json:"args"`
}

func (i *Installer) resolvedLoginConfig(ctx context.Context) (serviceLoginConfig, error) {
	type manifest struct {
		BinaryDigest string `json:"binary_digest"`
		SocketDigest string `json:"socket_digest"`
	}
	load := func(service string) (manifest, string, error) {
		b, err := i.root.ReadFile("releases/" + service + "/" + i.cfg.ReleaseID + "/manifest.json")
		var m manifest
		if err != nil || json.Unmarshal(b, &m) != nil || !isDigest(m.BinaryDigest) || !isDigest(m.SocketDigest) {
			return m, "", errors.New("login release manifest unavailable")
		}
		return m, Digest(b), nil
	}
	controller, _, err := load("controller")
	if err != nil {
		return serviceLoginConfig{}, err
	}
	broker, brokerManifest, err := load("broker")
	if err != nil {
		return serviceLoginConfig{}, err
	}
	egress, egressManifest, err := load("egress")
	if err != nil {
		return serviceLoginConfig{}, err
	}
	codex, _, err := load("codex")
	if err != nil {
		return serviceLoginConfig{}, err
	}
	policyRaw, err := i.root.ReadFile("pf/egress-policy.json")
	if err != nil {
		return serviceLoginConfig{}, err
	}
	var policy modelegress.Policy
	if json.Unmarshal(policyRaw, &policy) != nil {
		return serviceLoginConfig{}, errors.New("login policy unavailable")
	}
	policyDigest, err := policy.Digest()
	if err != nil {
		return serviceLoginConfig{}, err
	}
	controllerUID, controllerGID, err := i.ops.PrincipalIDs(ctx, "_openduck", "_openduck")
	if err != nil {
		return serviceLoginConfig{}, err
	}
	brokerUID, brokerGID, err := i.ops.PrincipalIDs(ctx, "_openduck_broker", "_openduck_broker")
	if err != nil {
		return serviceLoginConfig{}, err
	}
	egressUID, egressGID, err := i.ops.PrincipalIDs(ctx, "_openduck_egress", "_openduck_egress")
	if err != nil {
		return serviceLoginConfig{}, err
	}
	_, channelGID, err := i.ops.PrincipalIDs(ctx, "_openduck", "_openduck_broker_channel")
	if err != nil {
		return serviceLoginConfig{}, err
	}
	add := func(args *[]string, key, value string) { *args = append(*args, key, value) }
	args := []string{"-production-admission", "-proof-file", SystemRoot + "/state/controller/login-proof.json", "-release-id", i.cfg.ReleaseID}
	for _, kv := range [][2]string{
		{"-channel", "codex-owner"}, {"-socket-root", SystemRoot + "/channels/codex-owner"}, {"-release-root", SystemRoot + "/releases/controller/" + i.cfg.ReleaseID}, {"-key-root", SystemRoot + "/keys/controller-broker"}, {"-key-file", "service.key"}, {"-socket", "owner.sock"}, {"-binary-name", "openduck-controller"}, {"-local-release", SystemRoot + "/releases/controller/" + i.cfg.ReleaseID + "/local-release.json"}, {"-broker-release", SystemRoot + "/releases/controller/" + i.cfg.ReleaseID + "/broker-release.json"}, {"-runtime-id", "codex-runtime-" + i.cfg.ReleaseID}, {"-runtime-digest", codex.BinaryDigest}, {"-broker-binary-digest", broker.BinaryDigest}, {"-policy-digest", policyDigest}, {"-release-digest", brokerManifest}, {"-socket-digest", broker.SocketDigest}, {"-egress-release-digest", egressManifest}, {"-egress-socket-digest", egress.SocketDigest}, {"-local-uid", fmt.Sprint(controllerUID)}, {"-local-gid", fmt.Sprint(controllerGID)}, {"-broker-uid", fmt.Sprint(brokerUID)}, {"-broker-gid", fmt.Sprint(brokerGID)}, {"-egress-uid", fmt.Sprint(egressUID)}, {"-egress-gid", fmt.Sprint(egressGID)}, {"-channel-gid", fmt.Sprint(channelGID)}, {"-epoch", "1"},
	} {
		add(&args, kv[0], kv[1])
	}
	_ = controller
	return serviceLoginConfig{Schema: "openduck-service-login.v1", ReleaseID: i.cfg.ReleaseID, Binary: SystemRoot + "/home/controller/bin/openduck-codex-login", Args: args}, nil
}

func (i *Installer) writeLoginConfig(ctx context.Context) error {
	cfg, err := i.resolvedLoginConfig(ctx)
	if err != nil {
		return err
	}
	b, err := json.Marshal(cfg)
	if err != nil {
		return err
	}
	return i.atomicText("operator/codex-login.json", string(b)+"\n", 0644)
}

func (i *Installer) ServiceLogin(ctx context.Context) error {
	if i == nil || i.root == nil || !i.fake && os.Geteuid() != 0 {
		return errors.New("service login wrapper requires root")
	}
	if err := i.Verify(); err != nil {
		return err
	}
	active, err := i.root.ReadFile("active.release")
	if err != nil || strings.TrimSpace(string(active)) != i.cfg.ReleaseID {
		return errors.New("service login active release mismatch")
	}
	st, err := i.root.Lstat("operator/codex-login.json")
	if err != nil || !safeExistingRegular(st, 0644, st.Size()) || !i.fake && !ownedBy(st, 0, 0) {
		return errors.New("unsafe service login config")
	}
	raw, err := i.root.ReadFile("operator/codex-login.json")
	if err != nil {
		return err
	}
	var got serviceLoginConfig
	if json.Unmarshal(raw, &got) != nil {
		return errors.New("invalid service login config")
	}
	want, err := i.resolvedLoginConfig(ctx)
	if err != nil {
		return err
	}
	gb, _ := json.Marshal(got)
	wb, _ := json.Marshal(want)
	if !bytes.Equal(gb, wb) {
		return errors.New("service login config does not match active release")
	}
	uid, gid, err := i.ops.PrincipalIDs(ctx, "_openduck", "_openduck")
	if err != nil {
		return err
	}
	_, channelGID, err := i.ops.PrincipalIDs(ctx, "_openduck", "_openduck_broker_channel")
	if err != nil {
		return err
	}
	return i.ops.ExecAs(ctx, uid, gid, []uint32{gid, channelGID}, got.Binary, got.Args)
}

func (i *Installer) renderResolvedPlist(ctx context.Context, s Service) string {
	p := renderPlist(s, i.cfg.ReleaseID)
	type resolvedRelease struct{ release, binary, manifest, socket string }
	digests := map[string]resolvedRelease{}
	policyDigest := ""
	if pb, e := i.root.ReadFile("pf/egress-policy.json"); e == nil {
		var policy modelegress.Policy
		if json.Unmarshal(pb, &policy) == nil {
			policyDigest, _ = policy.Digest()
		}
	}
	seatbeltDigest := ""
	if sb, e := i.root.ReadFile("seatbelt/codex.sb"); e == nil {
		seatbeltDigest = Digest(sb)
	}
	pfDigest := ""
	if pf, e := i.root.ReadFile("seatbelt/state"); e == nil {
		pfDigest = Digest(pf)
	}
	pfEvidenceDigest, pfRulesDigest, bootID := "", "", ""
	if raw, e := i.root.ReadFile("seatbelt/pf-evidence.json"); e == nil {
		var evidence codexruntime.PFEvidence
		if json.Unmarshal(raw, &evidence) == nil {
			if canonical, err := evidence.Canonical(); err == nil && bytes.Equal(canonical, raw) {
				pfEvidenceDigest = Digest(raw)
				pfRulesDigest = evidence.RulesDigest
				bootID = evidence.BootID
			}
		}
	}
	for _, v := range services {
		if b, e := i.root.ReadFile("releases/" + v.Name + "/" + i.cfg.ReleaseID + "/manifest.json"); e == nil {
			var m struct {
				BinaryDigest string `json:"binary_digest"`
				SocketDigest string `json:"socket_digest"`
			}
			if json.Unmarshal(b, &m) == nil {
				digests[v.Name] = resolvedRelease{i.cfg.ReleaseID, m.BinaryDigest, Digest(b), m.SocketDigest}
			}
		}
	}
	if b, e := i.root.ReadFile("releases/codex/" + i.cfg.ReleaseID + "/manifest.json"); e == nil {
		var m struct {
			BinaryDigest string `json:"binary_digest"`
			SocketDigest string `json:"socket_digest"`
		}
		_ = json.Unmarshal(b, &m)
		digests["codex"] = resolvedRelease{i.cfg.ReleaseID, m.BinaryDigest, Digest(b), m.SocketDigest}
	}
	if b, e := i.root.ReadFile("releases/anchor-checkpoint/" + i.cfg.ReleaseID + "/manifest.json"); e == nil {
		var m struct {
			BinaryDigest string `json:"binary_digest"`
			SocketDigest string `json:"socket_digest"`
		}
		if json.Unmarshal(b, &m) == nil {
			digests["anchor-checkpoint"] = resolvedRelease{i.cfg.ReleaseID, m.BinaryDigest, Digest(b), m.SocketDigest}
		}
	}
	for _, name := range []string{"checkpoint-installer", "anchor-installer", "installer-checkpoint", "installer-anchor"} {
		if b, e := i.root.ReadFile("releases/" + name + "/" + i.cfg.ReleaseID + "/manifest.json"); e == nil {
			var m struct {
				BinaryDigest string `json:"binary_digest"`
				SocketDigest string `json:"socket_digest"`
			}
			if json.Unmarshal(b, &m) == nil {
				digests[name] = resolvedRelease{i.cfg.ReleaseID, m.BinaryDigest, Digest(b), m.SocketDigest}
			}
		}
	}
	for _, v := range services {
		u, g, e := i.ops.PrincipalIDs(ctx, v.User, v.Group)
		if e != nil {
			return ""
		}
		prefix := map[string]string{"_openduck": "CONTROLLER", "_openduck_anchor": "ANCHOR", "_openduck_checkpoint": "CHECKPOINT", "_openduck_egress": "EGRESS", "_openduck_broker": "BROKER", "_openduck_codex": "RUNTIME"}[v.User]
		p = strings.ReplaceAll(p, prefix+"_UID", fmt.Sprint(u))
		p = strings.ReplaceAll(p, prefix+"_GID", fmt.Sprint(g))
	}
	if _, g, e := i.ops.PrincipalIDs(ctx, "_openduck_egress", "_openduck_egress_channel"); e == nil {
		p = strings.ReplaceAll(p, "EGRESS_CHANNEL_GID", fmt.Sprint(g))
	}
	if _, g, e := i.ops.PrincipalIDs(ctx, "_openduck_broker", "_openduck_broker_channel"); e == nil {
		p = strings.ReplaceAll(p, "BROKER_CHANNEL_GID", fmt.Sprint(g))
	}
	if _, g, e := i.ops.PrincipalIDs(ctx, "_openduck_codex", "_openduck_runtime_channel"); e == nil {
		p = strings.ReplaceAll(p, "RUNTIME_CHANNEL_GID", fmt.Sprint(g))
	}
	if _, g, e := i.ops.PrincipalIDs(ctx, "_openduck_checkpoint", "_openduck_checkpoint_channel"); e == nil {
		p = strings.ReplaceAll(p, "CHECKPOINT_CHANNEL_GID", fmt.Sprint(g))
	}
	if _, g, e := i.ops.PrincipalIDs(ctx, "_openduck_anchor", "_openduck_channel"); e == nil {
		p = strings.ReplaceAll(p, "CHANNEL_GID", fmt.Sprint(g))
	}
	if _, g, e := i.ops.PrincipalIDs(ctx, "_openduck_checkpoint", "_openduck_installer_checkpoint_channel"); e == nil {
		p = strings.ReplaceAll(p, "INSTALLER_CHECKPOINT_CHANNEL_GID", fmt.Sprint(g))
	}
	if _, g, e := i.ops.PrincipalIDs(ctx, "_openduck_anchor", "_openduck_installer_anchor_channel"); e == nil {
		p = strings.ReplaceAll(p, "INSTALLER_ANCHOR_CHANNEL_GID", fmt.Sprint(g))
	}
	p = strings.ReplaceAll(p, "MODEL_ID", i.cfg.Model)
	if rd := digests["codex"].binary; rd != "" {
		p = strings.ReplaceAll(p, "CODEX_RUNTIME_DIGEST", "sha256:"+rd)
	}
	cd := digests["codex"]
	p = strings.ReplaceAll(p, "CODEX_BINARY_DIGEST", "sha256:"+cd.binary)
	p = strings.ReplaceAll(p, "CODEX_MANIFEST_DIGEST", "sha256:"+cd.manifest)
	p = strings.ReplaceAll(p, "CODEX_SOCKET_DIGEST", "sha256:"+cd.socket)
	for _, token := range []string{"CODEX_RUNTIME_ID", "PF_DIGEST", "SEATBELT_DIGEST", "EGRESS_POLICY_DIGEST", "BROKER_POLICY_DIGEST"} {
		value := ""
		if token == "CODEX_RUNTIME_ID" {
			value = "codex-runtime-" + i.cfg.ReleaseID
		}
		if token == "SEATBELT_DIGEST" && seatbeltDigest != "" {
			value = seatbeltDigest
		}
		if token == "PF_DIGEST" && pfDigest != "" {
			value = pfDigest
		}
		if token == "EGRESS_POLICY_DIGEST" || token == "BROKER_POLICY_DIGEST" {
			value = policyDigest
		}
		p = strings.ReplaceAll(p, token, value)
	}
	p = strings.ReplaceAll(p, "BROKER_KEY_EPOCH", "1")
	p = strings.ReplaceAll(p, "KEY_EPOCH", "1")
	p = strings.ReplaceAll(p, "PF_EVIDENCE_DIGEST", pfEvidenceDigest)
	p = strings.ReplaceAll(p, "PF_RULES_DIGEST", pfRulesDigest)
	p = strings.ReplaceAll(p, "BOOT_ID", bootID)
	for _, token := range []string{"ANCHOR_CHECKPOINT_RELEASE_ID", "ANCHOR_CHECKPOINT_BINARY_DIGEST", "ANCHOR_CHECKPOINT_SOCKET_DIGEST", "ANCHOR_CHECKPOINT_MANIFEST_DIGEST", "CONTROLLER_ANCHOR_SOCKET_DIGEST"} {
		value := i.cfg.ReleaseID
		d := digests["anchor-checkpoint"]
		switch token {
		case "ANCHOR_CHECKPOINT_BINARY_DIGEST":
			value = d.binary
		case "ANCHOR_CHECKPOINT_SOCKET_DIGEST":
			value = d.socket
		case "ANCHOR_CHECKPOINT_MANIFEST_DIGEST":
			value = d.manifest
		case "CONTROLLER_ANCHOR_SOCKET_DIGEST":
			value = digests["controller"].socket
		}
		p = strings.ReplaceAll(p, token, value)
	}
	for _, pre := range []string{"CHECKPOINT", "ANCHOR", "CONTROLLER", "EGRESS", "BROKER", "RUNTIME"} {
		name := map[string]string{"CHECKPOINT": "checkpoint", "ANCHOR": "anchor", "CONTROLLER": "controller", "EGRESS": "egress", "BROKER": "broker", "RUNTIME": "runtime"}[pre]
		p = strings.ReplaceAll(p, pre+"_RELEASE_ID", digests[name].release)
		for _, suf := range []string{"RELEASE_DIGEST", "SOCKET_DIGEST", "BINARY_DIGEST", "MANIFEST_DIGEST", "POLICY_DIGEST"} {
			value := ""
			d := digests[name]
			if suf == "POLICY_DIGEST" && policyDigest != "" {
				value = policyDigest
			}
			if suf == "BINARY_DIGEST" {
				value = d.binary
			}
			if suf == "SOCKET_DIGEST" {
				value = d.socket
			}
			if suf == "MANIFEST_DIGEST" || suf == "RELEASE_DIGEST" {
				value = d.manifest
			}
			if (s.Name == "runtime" || s.Name == "egress") && pre == "EGRESS" && (suf == "RELEASE_DIGEST" || suf == "SOCKET_DIGEST") && value != "" {
				value = "sha256:" + value
			}
			p = strings.ReplaceAll(p, pre+"_"+suf, value)
		}
	}
	p = strings.ReplaceAll(p, "BROKER_LOCAL_RELEASE_ID", digests["controller"].release)
	p = strings.ReplaceAll(p, "BROKER_PEER_RELEASE_ID", digests["broker"].release)
	p = strings.ReplaceAll(p, "BROKER_LOCAL_BINARY_DIGEST", digests["controller"].binary)
	p = strings.ReplaceAll(p, "BROKER_PEER_BINARY_DIGEST", digests["broker"].binary)
	p = strings.ReplaceAll(p, "BROKER_LOCAL_SOCKET_DIGEST", digests["controller"].socket)
	p = strings.ReplaceAll(p, "BROKER_PEER_SOCKET_DIGEST", digests["broker"].socket)
	p = strings.ReplaceAll(p, "BROKER_LOCAL_MANIFEST_DIGEST", digests["controller"].manifest)
	p = strings.ReplaceAll(p, "BROKER_PEER_MANIFEST_DIGEST", digests["broker"].manifest)
	for _, spec := range []struct{ prefix, name string }{{"CHECKPOINT_JOURNAL", "checkpoint-installer"}, {"ANCHOR_JOURNAL", "anchor-installer"}, {"INSTALLER_CHECKPOINT", "installer-checkpoint"}, {"INSTALLER_ANCHOR", "installer-anchor"}} {
		d := digests[spec.name]
		p = strings.ReplaceAll(p, spec.prefix+"_RELEASE_ID", d.release)
		p = strings.ReplaceAll(p, spec.prefix+"_BINARY_DIGEST", d.binary)
		p = strings.ReplaceAll(p, spec.prefix+"_SOCKET_DIGEST", d.socket)
		p = strings.ReplaceAll(p, spec.prefix+"_MANIFEST_DIGEST", d.manifest)
	}
	if s.Name == "checkpoint" || s.Name == "anchor" {
		name := "installer-" + s.Name
		d := digests[name]
		p = strings.ReplaceAll(p, "INSTALLER_RELEASE_ID", d.release)
		p = strings.ReplaceAll(p, "INSTALLER_BINARY_DIGEST", d.binary)
		p = strings.ReplaceAll(p, "INSTALLER_MANIFEST_DIGEST", d.manifest)
	}
	for _, spec := range []struct{ prefix, name string }{{"JOURNAL_CP", "checkpoint-installer"}, {"JOURNAL_AN", "anchor-installer"}, {"JOURNAL_IC", "installer-checkpoint"}, {"JOURNAL_IA", "installer-anchor"}} {
		// Do not use the general release map here. These journal descriptors
		// intentionally have a distinct socket pin from the daemon's primary
		// release, so resolve them through their own fixed descriptor path.
		pin, pinErr := i.installedJournalPin(spec.name)
		if pinErr != nil {
			continue
		}
		p = strings.ReplaceAll(p, spec.prefix+"_RELEASE", pin.ReleaseID)
		p = strings.ReplaceAll(p, spec.prefix+"_BINARY", pin.BinaryDigest)
		p = strings.ReplaceAll(p, spec.prefix+"_SOCKET", pin.SocketDigest)
		p = strings.ReplaceAll(p, spec.prefix+"_MANIFEST", pin.ManifestDigest)
	}
	p = strings.ReplaceAll(p, "JOURNAL_INSTALLER_UID", "0")
	p = strings.ReplaceAll(p, "JOURNAL_INSTALLER_GID", "0")
	if _, g, e := i.ops.PrincipalIDs(ctx, "_openduck_checkpoint", "_openduck_installer_checkpoint_channel"); e == nil {
		p = strings.ReplaceAll(p, "JOURNAL_IC_GID", fmt.Sprint(g))
	}
	if _, g, e := i.ops.PrincipalIDs(ctx, "_openduck_anchor", "_openduck_installer_anchor_channel"); e == nil {
		p = strings.ReplaceAll(p, "JOURNAL_IA_GID", fmt.Sprint(g))
	}
	return p
}

func (i *Installer) applyOwnership(ctx context.Context) error {
	for _, p := range []string{".openduck-installer", ".openduck-native-mcp", ".openduck-provider-attestor", ".openduck-readiness", ".openduck-service-login", "operator/codex-login.json"} {
		if err := i.ops.Chown(ctx, filepath.Join(SystemRoot, p), "root", "wheel"); err != nil {
			return err
		}
	}
	for _, p := range []string{"releases/codex", "releases/codex/" + i.cfg.ReleaseID, "releases/codex/" + i.cfg.ReleaseID + "/manifest.json", "releases/codex/" + i.cfg.ReleaseID + "/codex"} {
		if err := i.ops.Chown(ctx, filepath.Join(SystemRoot, p), "root", "wheel"); err != nil {
			return err
		}
	}
	if err := i.ops.Chown(ctx, filepath.Join(SystemRoot, "home/runtime/work"), "_openduck_codex", "_openduck_codex"); err != nil {
		return err
	}
	for _, p := range []string{"home/controller/bin", "home/controller/bin/openduck-codex-login"} {
		if err := i.ops.Chown(ctx, filepath.Join(SystemRoot, p), "_openduck", "_openduck"); err != nil {
			return err
		}
	}
	if err := i.applyInactiveProviderOwnership(ctx); err != nil {
		return err
	}
	if err := i.applyProviderTransportPrerequisiteOwnership(ctx); err != nil {
		return err
	}
	for _, s := range services {
		for _, base := range []string{"state", "logs", "home", "keys"} {
			if err := i.ops.Chown(ctx, filepath.Join(SystemRoot, base, s.Name), s.User, s.Group); err != nil {
				return err
			}
		}
	}
	for _, v := range []struct{ p, g string }{{"releases/broker/" + i.cfg.ReleaseID + "/local-release.json", "_openduck_broker"}, {"releases/broker/" + i.cfg.ReleaseID + "/egress-release.json", "_openduck_broker"}, {"releases/broker/" + i.cfg.ReleaseID + "/runtime-release.json", "_openduck_broker"}, {"releases/broker/" + i.cfg.ReleaseID + "/controller-release.json", "_openduck_broker"}, {"releases/egress/" + i.cfg.ReleaseID + "/local-release.json", "_openduck_egress"}, {"releases/egress/" + i.cfg.ReleaseID + "/peer-release.json", "_openduck_egress"}, {"releases/controller/" + i.cfg.ReleaseID + "/local-release.json", "_openduck"}, {"releases/controller/" + i.cfg.ReleaseID + "/broker-release.json", "_openduck"}, {"releases/runtime/" + i.cfg.ReleaseID + "/local-release.json", "_openduck_codex"}, {"releases/runtime/" + i.cfg.ReleaseID + "/broker-release.json", "_openduck_codex"}} {
		if err := i.ops.Chown(ctx, filepath.Join(SystemRoot, v.p), "root", v.g); err != nil {
			return err
		}
	}
	if err := i.ops.Chown(ctx, filepath.Join(SystemRoot, "releases/egress", i.cfg.ReleaseID, "egress-policy.json"), "root", "_openduck_egress"); err != nil {
		return err
	}
	for _, p := range []string{"releases", "operator", "channels", "checkpoint-channel", "launchd"} {
		if err := i.ops.Chown(ctx, filepath.Join(SystemRoot, p), "root", "wheel"); err != nil {
			return err
		}
	}
	for _, v := range canonicalKeyRootOwnership() {
		if err := i.ops.Chown(ctx, filepath.Join(SystemRoot, v.path), v.user, v.group); err != nil {
			return err
		}
	}
	for _, v := range []struct{ p, u, g string }{{"channels/platform-anchor", "_openduck_anchor", "_openduck_channel"}, {"channels/model-egress", "_openduck_egress", "_openduck_egress_channel"}, {"channels/codex-owner", "_openduck_broker", "_openduck_broker_channel"}, {"channels/codex-runtime", "_openduck_codex", "_openduck_runtime_channel"}, {"checkpoint-channel/platform-checkpoint", "_openduck_checkpoint", "_openduck_checkpoint_channel"}, {"channels/installer-checkpoint", "_openduck_checkpoint", "_openduck_installer_checkpoint_channel"}, {"channels/installer-anchor", "_openduck_anchor", "_openduck_installer_anchor_channel"}} {
		if err := i.ops.Chown(ctx, filepath.Join(SystemRoot, v.p), v.u, v.g); err != nil {
			return err
		}
	}
	for _, s := range services {
		for _, p := range []string{"releases/" + s.Name, "releases/" + s.Name + "/" + i.cfg.ReleaseID} {
			if err := i.ops.Chown(ctx, filepath.Join(SystemRoot, p), "root", s.Group); err != nil {
				return err
			}
		}
		for _, p := range []string{"releases/" + s.Name + "/" + i.cfg.ReleaseID + "/manifest.json", "releases/" + s.Name + "/" + i.cfg.ReleaseID + "/" + binaryName(s.Name)} {
			if err := i.ops.Chown(ctx, filepath.Join(SystemRoot, p), "root", s.Group); err != nil {
				return err
			}
		}
	}
	if i.admitted != nil {
		if err := i.ops.Chown(ctx, filepath.Join(SystemRoot, "releases/controller", i.cfg.ReleaseID, "release-manifest.v2.json"), "root", "wheel"); err != nil {
			return err
		}
	}
	for _, p := range []string{"releases/anchor-checkpoint", "releases/anchor-checkpoint/" + i.cfg.ReleaseID, "releases/anchor-checkpoint/" + i.cfg.ReleaseID + "/manifest.json", "releases/anchor-checkpoint/" + i.cfg.ReleaseID + "/openduck-anchor"} {
		if err := i.ops.Chown(ctx, filepath.Join(SystemRoot, p), "root", "_openduck_anchor"); err != nil {
			return err
		}
	}
	for _, service := range []string{"installer-checkpoint", "installer-anchor"} {
		for _, p := range []string{"releases/" + service, "releases/" + service + "/" + i.cfg.ReleaseID, "releases/" + service + "/" + i.cfg.ReleaseID + "/manifest.json", "releases/" + service + "/" + i.cfg.ReleaseID + "/openduck-installer"} {
			if err := i.ops.Chown(ctx, filepath.Join(SystemRoot, p), "root", "wheel"); err != nil {
				return err
			}
		}
	}
	for _, spec := range []struct{ release, artifact, group string }{{"checkpoint-installer", "openduck-checkpoint", "_openduck_checkpoint"}, {"anchor-installer", "openduck-anchor", "_openduck_anchor"}} {
		for _, p := range []string{"releases/" + spec.release, "releases/" + spec.release + "/" + i.cfg.ReleaseID, "releases/" + spec.release + "/" + i.cfg.ReleaseID + "/manifest.json", "releases/" + spec.release + "/" + i.cfg.ReleaseID + "/" + spec.artifact} {
			if err := i.ops.Chown(ctx, filepath.Join(SystemRoot, p), "root", spec.group); err != nil {
				return err
			}
		}
	}
	for _, v := range canonicalServiceKeyOwnership() {
		if err := i.ops.Chown(ctx, filepath.Join(SystemRoot, v.path), v.user, v.group); err != nil {
			return err
		}
	}
	if err := i.ops.Chown(ctx, filepath.Join(SystemRoot, "keys/controller-anchor/owner.public"), "_openduck", "_openduck"); err != nil {
		return err
	}
	if err := i.ops.Chown(ctx, filepath.Join(SystemRoot, "operator/owner-ed25519.key"), "root", "wheel"); err != nil {
		return err
	}
	if err := i.ops.Chown(ctx, filepath.Join(SystemRoot, "operator/owner-capabilities"), "root", "_openduck"); err != nil {
		return err
	}
	if err := i.ops.Chown(ctx, filepath.Join(SystemRoot, "state/controller/owner-queue"), "_openduck", "_openduck"); err != nil {
		return err
	}
	return nil
}

func (i *Installer) applyInactiveProviderOwnership(ctx context.Context) error {
	entries := i.optionalProviderEntries()
	if len(entries) == 0 {
		return nil
	}
	if err := i.validateInactiveProviderRootBinding(); err != nil {
		return err
	}
	if err := i.ops.Chown(ctx, filepath.Join(SystemRoot, "providers"), "root", "wheel"); err != nil {
		return err
	}
	if err := i.ops.Chown(ctx, filepath.Join(SystemRoot, releasecatalog.InactiveProviderRoot), "root", "_openduck"); err != nil {
		return err
	}
	directories := map[string]bool{}
	files := make([]string, 0, len(entries))
	for _, artifact := range entries {
		mappings, ok := resolvePlanArtifacts(artifact, i.cfg.ReleaseID)
		if !ok {
			return errors.New("unresolved inactive provider ownership")
		}
		for _, mapping := range mappings {
			if !validInactiveProviderMapping(mapping) {
				return errors.New("invalid inactive provider ownership")
			}
			directory := filepath.Dir(mapping.target)
			if directory != releasecatalog.InactiveProviderRoot {
				directories[directory] = true
			}
			files = append(files, mapping.target)
		}
	}
	values := make([]string, 0, len(directories))
	for directory := range directories {
		values = append(values, directory)
	}
	sort.Strings(values)
	sort.Strings(files)
	for _, directory := range values {
		if err := i.ops.Chown(ctx, filepath.Join(SystemRoot, directory), "root", "_openduck"); err != nil {
			return err
		}
	}
	for _, file := range files {
		if err := i.ops.Chown(ctx, filepath.Join(SystemRoot, file), "root", "_openduck"); err != nil {
			return err
		}
	}
	return i.validateInactiveProviderRootBinding()
}

func (i *Installer) provisionPrincipals(ctx context.Context) error {
	groups := []string{"_openduck", "_openduck_anchor", "_openduck_checkpoint", "_openduck_egress", "_openduck_codex", "_openduck_broker", "_openduck_channel", "_openduck_checkpoint_channel", "_openduck_egress_channel", "_openduck_broker_channel", "_openduck_runtime_channel", "_openduck_installer_checkpoint_channel", "_openduck_installer_anchor_channel"}
	for _, g := range groups {
		exists, err := i.ops.GroupExists(ctx, g)
		if err != nil {
			return err
		}
		if err := i.ops.EnsureGroup(ctx, g); err != nil {
			return err
		}
		if !exists {
			i.principalUndo = append(i.principalUndo, func(c context.Context) error { return i.ops.DeleteGroup(c, g) })
		}
	}
	for _, s := range services {
		exists, err := i.ops.UserExists(ctx, s.User)
		if err != nil {
			return err
		}
		if err := i.ops.EnsureUser(ctx, s.User, s.Group); err != nil {
			return err
		}
		if !exists {
			user := s.User
			i.principalUndo = append(i.principalUndo, func(c context.Context) error { return i.ops.DeleteUser(c, user) })
		}
	}
	members := map[string][]string{"_openduck_channel": {"_openduck", "_openduck_anchor"}, "_openduck_checkpoint_channel": {"_openduck_checkpoint", "_openduck_anchor"}, "_openduck_egress_channel": {"_openduck_egress", "_openduck_broker"}, "_openduck_broker_channel": {"_openduck_broker", "_openduck"}, "_openduck_runtime_channel": {"_openduck_codex", "_openduck_broker"}, "_openduck_installer_checkpoint_channel": {"_openduck_checkpoint"}, "_openduck_installer_anchor_channel": {"_openduck_anchor"}}
	for g, users := range members {
		for _, u := range users {
			added, err := i.ops.AddGroupMember(ctx, g, u)
			if err != nil {
				return err
			}
			if added {
				group, user := g, u
				i.principalUndo = append(i.principalUndo, func(c context.Context) error { return i.ops.RemoveGroupMember(c, group, user) })
			}
		}
	}
	return nil
}

func (i *Installer) rollbackPrincipals(ctx context.Context) error {
	var result error
	for n := len(i.principalUndo) - 1; n >= 0; n-- {
		result = errors.Join(result, i.principalUndo[n](ctx))
	}
	i.principalUndo = nil
	return result
}

func (i *Installer) verifyDistinctPrincipalIDs(ctx context.Context) error {
	seenUID, seenGID := map[uint32]string{}, map[uint32]string{}
	for _, s := range services {
		uid, gid, err := i.ops.PrincipalIDs(ctx, s.User, s.Group)
		if err != nil || uid == 0 || gid == 0 {
			return errors.New("service principal IDs unavailable")
		}
		if previous := seenUID[uid]; previous != "" && previous != s.User {
			return fmt.Errorf("service UID collision: %s and %s", previous, s.User)
		}
		if previous := seenGID[gid]; previous != "" && previous != s.Group {
			return fmt.Errorf("service GID collision: %s and %s", previous, s.Group)
		}
		seenUID[uid], seenGID[gid] = s.User, s.Group
	}
	for _, pair := range []struct{ user, group string }{{"_openduck", "_openduck_channel"}, {"_openduck_anchor", "_openduck_checkpoint_channel"}, {"_openduck_broker", "_openduck_egress_channel"}, {"_openduck", "_openduck_broker_channel"}, {"_openduck_codex", "_openduck_runtime_channel"}, {"_openduck_checkpoint", "_openduck_installer_checkpoint_channel"}, {"_openduck_anchor", "_openduck_installer_anchor_channel"}} {
		_, gid, err := i.ops.PrincipalIDs(ctx, pair.user, pair.group)
		if err != nil || gid == 0 || seenGID[gid] != "" {
			return fmt.Errorf("channel GID collision or unavailable: %s", pair.group)
		}
		seenGID[gid] = pair.group
	}
	return nil
}

func (i *Installer) preflight() error {
	for _, p := range []string{"state", "logs", "home", "keys", "releases", "operator", "channels", "checkpoint-channel", "pf", "seatbelt", "launchd"} {
		if err := i.rejectPath(p); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	if !validID(i.cfg.ReleaseID) {
		return errors.New("invalid release id")
	}
	if i.admitted != nil && (i.admitted.ReleaseID != i.cfg.ReleaseID || i.admitted.ReleaseDigest != i.releaseDigest || (!i.fake && i.admitted.TargetRoot != i.cfg.Root) || i.admitted.Version == "") {
		return errors.New("admitted release binding drift")
	}
	if i.cfg.BinaryDir == "" {
		return nil
	}
	st, err := os.Lstat(i.cfg.BinaryDir)
	if err != nil {
		return fmt.Errorf("binary source: %w", err)
	}
	if !st.IsDir() || st.Mode()&os.ModeSymlink != 0 || st.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		return errors.New("binary source is not directory")
	}
	if i.admitted != nil && i.stage == nil {
		r, openErr := os.OpenRoot(i.cfg.BinaryDir)
		if openErr != nil {
			return openErr
		}
		digests, validateErr := validateAdmittedSnapshotRoot(r, *i.admitted, i.admissionIssuedAt)
		if validateErr != nil {
			_ = r.Close()
			return validateErr
		}
		i.stage, i.stageDigests = r, digests
	} else if !i.fake {
		return errors.New("production apply requires sealed release admission")
	} else if i.stage == nil {
		r, openErr := os.OpenRoot(i.artifactSourceDir())
		if openErr != nil {
			return openErr
		}
		i.stage = r
		i.stageDigests = map[string]string{}
	}
	return nil
}

// validateAdmittedSnapshotRoot is the production staging boundary. It pins
// every ManifestV2 artifact through the already-open root descriptor, rejects
// legacy release.manifest authority, and permits only outputs declared by the
// same closed resolver that drives PlanV2 and copy operations.
func validateAdmittedSnapshotRoot(root *os.Root, manifest macosrelease.ManifestV2, validationTime time.Time) (map[string]string, error) {
	if root == nil || validationTime.IsZero() || manifest.Schema != macosrelease.ManifestSchema || !validID(manifest.ReleaseID) || !isDigest(manifest.ReleaseDigest) || manifest.TargetRoot != SystemRoot || len(manifest.Artifacts) == 0 || len(manifest.Artifacts) > maxPlanOperations || !validClosedCatalogManifest(manifest) {
		return nil, errors.New("invalid admitted snapshot manifest")
	}
	selected := make([]releasecatalog.Entry, 0, len(manifest.Artifacts))
	for _, artifact := range manifest.Artifacts {
		entry, found := releasecatalog.EntryFor(artifact.Path)
		if !found || entry.Type != artifact.Type || entry.ActivationGroup != artifact.ActivationGroup || entry.Required != artifact.Required {
			return nil, errors.New("unresolved admitted snapshot artifact")
		}
		selected = append(selected, entry)
	}
	if validateCatalogSnapshotInventory(root, selected) != nil {
		return nil, errors.New("unsafe admitted snapshot inventory")
	}
	seenTarget, digests := map[string]bool{}, make(map[string]string, len(manifest.Artifacts))
	payloads := make(map[string][]byte, len(manifest.Artifacts))
	for _, artifact := range manifest.Artifacts {
		entry, _ := releasecatalog.EntryFor(artifact.Path)
		if !safePlanRelative(artifact.Path) || !isDigest(artifact.Digest) || artifact.Platform != runtime.GOOS || artifact.Arch != runtime.GOARCH || artifact.Version != manifest.Version {
			return nil, errors.New("invalid admitted snapshot artifact")
		}
		mappings, ok := resolvePlanArtifacts(artifact, manifest.ReleaseID)
		if !ok {
			return nil, errors.New("unresolved admitted snapshot artifact")
		}
		for _, mapping := range mappings {
			if seenTarget[mapping.target] {
				return nil, errors.New("admitted snapshot target collision")
			}
			seenTarget[mapping.target] = true
		}
		body, err := readCatalogSnapshotArtifact(root, artifact.Path, entry.Executable, catalogSnapshotMaxBytes(entry))
		if err != nil || Digest(body) != artifact.Digest {
			return nil, errors.New("admitted snapshot artifact changed")
		}
		digests[artifact.Path] = artifact.Digest
		payloads[artifact.Path] = body
	}
	if macosrelease.ValidateCatalogPayloads(payloads, validationTime.UTC()) != nil {
		return nil, errors.New("admitted snapshot catalog payload invalid")
	}
	return digests, nil
}

func validateCatalogSnapshotInventory(root *os.Root, selected []releasecatalog.Entry) error {
	expected := releasecatalog.ExpectedChildren(selected)
	for directory, children := range expected {
		names, err := catalogSnapshotDirectoryNames(root, directory)
		if err != nil || len(names) != len(children) {
			return errors.New("snapshot directory inventory mismatch")
		}
		for _, name := range names {
			if !children[name] {
				return errors.New("snapshot directory has unknown child")
			}
		}
	}
	return nil
}

func catalogSnapshotDirectoryNames(root *os.Root, directory string) ([]string, error) {
	before, err := root.Lstat(directory)
	if err != nil || !safeCatalogSnapshotDirectory(before) {
		return nil, errors.New("unsafe snapshot directory")
	}
	file, err := root.Open(directory)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !sameFileIdentity(before, opened) || !safeCatalogSnapshotDirectory(opened) {
		return nil, errors.New("snapshot directory changed while opening")
	}
	entries, err := file.ReadDir(-1)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.Name() == "." || entry.Name() == ".." || entry.Type()&os.ModeSymlink != 0 {
			return nil, errors.New("unsafe snapshot directory entry")
		}
		names = append(names, entry.Name())
	}
	after, err := root.Lstat(directory)
	if err != nil || !sameFileIdentity(before, after) || !safeCatalogSnapshotDirectory(after) {
		return nil, errors.New("snapshot directory changed")
	}
	sort.Strings(names)
	return names, nil
}

func readCatalogSnapshotArtifact(root *os.Root, path string, executable bool, maxBytes int64) ([]byte, error) {
	if maxBytes <= 0 || maxBytes > 64<<20 {
		return nil, errors.New("invalid snapshot artifact limit")
	}
	parts := strings.Split(path, "/")
	if validateCatalogSnapshotParents(root, parts) != nil {
		return nil, errors.New("unsafe snapshot parent")
	}
	before, err := root.Lstat(path)
	if err != nil || !safeCatalogSnapshotArtifact(before, executable, maxBytes) {
		return nil, errors.New("unsafe snapshot artifact")
	}
	file, err := root.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !sameFileIdentity(before, opened) || !safeCatalogSnapshotArtifact(opened, executable, maxBytes) {
		return nil, errors.New("snapshot artifact changed while opening")
	}
	body, err := io.ReadAll(io.LimitReader(file, maxBytes+1))
	if err != nil || len(body) == 0 || int64(len(body)) > maxBytes {
		return nil, errors.New("invalid snapshot artifact size")
	}
	afterOpened, statErr := file.Stat()
	afterNamed, namedErr := root.Lstat(path)
	if statErr != nil || namedErr != nil || !sameFileIdentity(before, afterOpened) || !sameFileIdentity(before, afterNamed) || !safeCatalogSnapshotArtifact(afterOpened, executable, maxBytes) || !safeCatalogSnapshotArtifact(afterNamed, executable, maxBytes) || afterOpened.Size() != before.Size() || afterNamed.Size() != before.Size() || int64(len(body)) != before.Size() || validateCatalogSnapshotParents(root, parts) != nil {
		return nil, errors.New("snapshot artifact changed during read")
	}
	return body, nil
}

func validateCatalogSnapshotParents(root *os.Root, parts []string) error {
	for index := range parts[:len(parts)-1] {
		info, err := root.Lstat(strings.Join(parts[:index+1], "/"))
		if err != nil || !safeCatalogSnapshotDirectory(info) {
			return errors.New("unsafe snapshot parent")
		}
	}
	return nil
}

func safeCatalogSnapshotDirectory(info os.FileInfo) bool {
	if info == nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 || info.Mode().Perm()&0o022 != 0 {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat != nil && uint32(stat.Mode)&0o7000 == 0
}

func safeCatalogSnapshotArtifact(info os.FileInfo, executable bool, maxBytes int64) bool {
	if !safeStagedArtifact(info) || info.Size() > maxBytes || info.Mode().Perm()&0o022 != 0 {
		return false
	}
	return (info.Mode().Perm()&0o111 != 0) == executable
}

func catalogSnapshotMaxBytes(entry releasecatalog.Entry) int64 {
	if entry.MaxBytes > 0 && entry.MaxBytes <= 64<<20 {
		return entry.MaxBytes
	}
	return 64 << 20
}

// validateStagedSnapshot verifies the signed-by-build manifest while the
// source is still behind one pinned descriptor. It accepts only the exact
// bin/ staging layout consumed by Apply.
func validateStagedSnapshot(dir string) error {
	r, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	defer r.Close()
	_, err = validateStagedRoot(r)
	return err
}

func validateStagedRoot(r *os.Root) (map[string]string, error) {
	b, err := r.ReadFile("release.manifest")
	if err != nil {
		return nil, fmt.Errorf("staged release.manifest: %w", err)
	}
	manifestInfo, err := r.Lstat("release.manifest")
	if err != nil || !safeStagedArtifact(manifestInfo) {
		return nil, errors.New("unsafe staged release.manifest")
	}
	binInfo, err := r.Lstat("bin")
	if err != nil || !binInfo.IsDir() || binInfo.Mode()&os.ModeSymlink != 0 || binInfo.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		return nil, errors.New("unsafe staged bin directory")
	}
	seen := map[string]bool{}
	expected := map[string]bool{}
	digests := map[string]string{}
	for _, name := range []string{"openduck-checkpoint", "openduck-anchor", "openduck-egress", "openduck-codex-broker", "openduck-codex-runtime", "openduck-controller", "codex", "openduck-owner-grant", "openduck-codex-login", "openduck-installer", "openduck-native-mcp", "openduck-provider-attestor", "openduck-readiness"} {
		expected["bin/"+name] = true
	}
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		if len(f) != 2 || !isDigest(f[0]) || seen[f[1]] || !expected[f[1]] {
			return nil, errors.New("invalid staged manifest entry")
		}
		seen[f[1]] = true
		st, e := r.Lstat(f[1])
		if e != nil || !safeStagedArtifact(st) {
			return nil, fmt.Errorf("unsafe staged artifact %s", f[1])
		}
		in, e := r.Open(f[1])
		if e != nil {
			return nil, e
		}
		h := sha256.New()
		_, e = io.Copy(h, in)
		_ = in.Close()
		if e != nil {
			return nil, e
		}
		if hex.EncodeToString(h.Sum(nil)) != f[0] {
			return nil, fmt.Errorf("staged hash mismatch: %s", f[1])
		}
		digests[f[1]] = f[0]
	}
	for name := range expected {
		if !seen[name] {
			return nil, fmt.Errorf("staged manifest missing %s", name)
		}
	}
	if len(seen) != len(expected) {
		return nil, errors.New("staged manifest has unexpected entries")
	}
	return digests, nil
}

func safeStagedArtifact(st os.FileInfo) bool {
	if st == nil || !st.Mode().IsRegular() || st.Mode()&os.ModeSymlink != 0 || st.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		return false
	}
	x, ok := st.Sys().(*syscall.Stat_t)
	return ok && x != nil && x.Nlink == 1 && uint32(x.Mode)&07000 == 0
}
func (i *Installer) rejectPath(p string) error {
	st, err := i.root.Lstat(p)
	if err != nil {
		return err
	}
	if st.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("symlink rejected: %s", p)
	}
	unixSpecial := false
	if stat, ok := st.Sys().(*syscall.Stat_t); ok && stat != nil {
		unixSpecial = uint32(stat.Mode)&07000 != 0
	}
	if st.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 || unixSpecial {
		return fmt.Errorf("special bits rejected: %s", p)
	}
	if !st.IsDir() && p != "active.release" {
		return fmt.Errorf("non-directory rejected: %s", p)
	}
	return nil
}
func (i *Installer) mkdir(p string, m os.FileMode) error {
	before, beforeErr := i.root.Lstat(p)
	if err := i.root.Mkdir(p, m); err != nil && !errors.Is(err, os.ErrExist) {
		return fmt.Errorf("mkdir %s: %w", p, err)
	}
	st, err := i.root.Lstat(p)
	if err != nil || !st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("unsafe directory %s", p)
	}
	if errors.Is(beforeErr, os.ErrNotExist) {
		if err := i.root.Chmod(p, m); err != nil {
			return fmt.Errorf("chmod %s: %w", p, err)
		}
		i.created = append(i.created, p)
	} else if beforeErr == nil && before.Mode().Perm() != m.Perm() {
		return fmt.Errorf("existing directory mode mismatch: %s", p)
	}
	return nil
}
func (i *Installer) mkdirRelease(p string) error {
	if st, err := i.root.Lstat(p); err == nil {
		if st.IsDir() && st.Mode()&os.ModeSymlink == 0 && (st.Mode().Perm() == 0550 || i.fake && st.Mode().Perm() == 0750) {
			return nil
		}
		return fmt.Errorf("existing immutable release directory mismatch: %s", p)
	}
	return i.mkdir(p, 0750)
}

func (i *Installer) sealDaemonReleases() error {
	for _, s := range services {
		for _, p := range []string{"releases/" + s.Name + "/" + i.cfg.ReleaseID, "releases/" + s.Name} {
			if err := i.root.Chmod(p, 0550); err != nil {
				return err
			}
		}
	}
	for _, p := range []string{"releases/anchor-checkpoint/" + i.cfg.ReleaseID, "releases/anchor-checkpoint"} {
		if err := i.root.Chmod(p, 0550); err != nil {
			return err
		}
	}
	for _, release := range []string{"checkpoint-installer", "anchor-installer", "installer-checkpoint", "installer-anchor"} {
		if i.fake {
			// Temp-root tests are unprivileged and cannot safely clean an
			// immutable directory. Production always seals these roots below.
			continue
		}
		for _, p := range []string{"releases/" + release + "/" + i.cfg.ReleaseID, "releases/" + release} {
			if err := i.root.Chmod(p, 0550); err != nil {
				return err
			}
		}
	}
	return nil
}
func (i *Installer) copyRelease() error {
	if i.stage == nil {
		return errors.New("staged root is not pinned")
	}
	for _, s := range services {
		name := binaryName(s.Name)
		in, err := i.stage.Open(i.stagedPath(name))
		if err != nil && i.fake {
			in, err = i.stage.Open(i.stagedPath("openduck"))
		}
		if err != nil {
			return fmt.Errorf("open %s release binary: %w", s.Name, err)
		}
		dst := "releases/" + s.Name + "/" + i.cfg.ReleaseID + "/" + name
		if err := i.requireDeclaredCopy(dst, name); err != nil {
			in.Close()
			return err
		}
		out, err := i.root.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0550)
		h := sha256.New()
		if err != nil {
			if errors.Is(err, os.ErrExist) {
				staged, readErr := io.ReadAll(in)
				in.Close()
				installed, installedErr := i.root.ReadFile(dst)
				if readErr != nil || installedErr != nil || !bytes.Equal(staged, installed) {
					return fmt.Errorf("existing release binary mismatch: %s", s.Name)
				}
				_, _ = h.Write(staged)
			} else {
				in.Close()
				return err
			}
		} else {
			if chmodErr := out.Chmod(0550); chmodErr != nil {
				_ = out.Close()
				_ = in.Close()
				return chmodErr
			}
			_, copyErr := io.Copy(out, io.TeeReader(in, h))
			closeErr := out.Close()
			in.Close()
			if copyErr != nil {
				return copyErr
			}
			if closeErr != nil {
				return closeErr
			}
			i.created = append(i.created, dst)
		}
		if want := i.stageDigests[i.stagedPath(name)]; want != "" && hex.EncodeToString(h.Sum(nil)) != want {
			return fmt.Errorf("post-copy staged hash mismatch: %s", name)
		}
		suid, sgid, e := i.ops.PrincipalIDs(context.Background(), s.User, channelGroup(s.Name))
		if e != nil {
			return e
		}
		socketDigest, e := macoschannel.SocketMetadataDigestForContract(socketName(s.Name), suid, sgid, 0660)
		if e != nil {
			return e
		}
		manifest := struct {
			ReleaseID    string `json:"release_id"`
			Binary       string `json:"binary"`
			Socket       string `json:"socket"`
			BinaryDigest string `json:"binary_digest"`
			SocketDigest string `json:"socket_digest"`
		}{i.cfg.ReleaseID, name, socketName(s.Name), hex.EncodeToString(h.Sum(nil)), socketDigest}
		mb, _ := json.Marshal(manifest)
		if err := i.writeText("releases/"+s.Name+"/"+i.cfg.ReleaseID+"/manifest.json", string(mb)+"\n", 0440); err != nil {
			return err
		}
	}
	return nil
}

// persistAdmittedManifest records the exact signed ManifestV2 projection next
// to the controller release. It is metadata for verification and rollback,
// not a replacement trust root; production admission already occurred before
// the installer opened its fixed root.
func (i *Installer) persistAdmittedManifest() error {
	if i.admitted == nil {
		return nil
	}
	if i.admitted.ReleaseID != i.cfg.ReleaseID || i.admitted.ReleaseDigest != i.releaseDigest {
		return errors.New("admitted manifest binding drift")
	}
	body, err := json.Marshal(i.admitted)
	if err != nil {
		return err
	}
	return i.writeText("releases/controller/"+i.cfg.ReleaseID+"/release-manifest.v2.json", string(body)+"\n", 0440)
}

// copyAnchorCheckpointRelease creates the distinct immutable release root
// used when the anchor process acts as the checkpoint client. The daemon
// validates that root independently from its platform-anchor server release.
func (i *Installer) copyAnchorCheckpointRelease() error {
	if i.stage == nil {
		return errors.New("staged root is not pinned")
	}
	in, err := i.stage.Open(i.stagedPath("openduck-anchor"))
	if err != nil && i.fake {
		in, err = i.stage.Open(i.stagedPath("openduck"))
	}
	if err != nil {
		return fmt.Errorf("open anchor checkpoint client binary: %w", err)
	}
	defer in.Close()
	dst := "releases/anchor-checkpoint/" + i.cfg.ReleaseID + "/openduck-anchor"
	if err := i.requireDeclaredCopy(dst, "openduck-anchor"); err != nil {
		return err
	}
	out, err := i.root.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0550)
	h := sha256.New()
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			staged, readErr := io.ReadAll(in)
			installed, installedErr := i.root.ReadFile(dst)
			if readErr != nil || installedErr != nil || !bytes.Equal(staged, installed) {
				return errors.New("existing anchor checkpoint binary mismatch")
			}
			_, _ = h.Write(staged)
		} else {
			return err
		}
	} else {
		if chmodErr := out.Chmod(0550); chmodErr != nil {
			_ = out.Close()
			return chmodErr
		}
		_, copyErr := io.Copy(out, io.TeeReader(in, h))
		closeErr := out.Close()
		if copyErr != nil {
			return copyErr
		}
		if closeErr != nil {
			return closeErr
		}
		i.created = append(i.created, dst)
	}
	if want := i.stageDigests[i.stagedPath("openduck-anchor")]; want != "" && hex.EncodeToString(h.Sum(nil)) != want {
		return errors.New("post-copy staged hash mismatch: openduck-anchor")
	}
	uid, gid, err := i.ops.PrincipalIDs(context.Background(), "_openduck_checkpoint", "_openduck_checkpoint_channel")
	if err != nil {
		return err
	}
	socketDigest, err := macoschannel.SocketMetadataDigestForContract("checkpoint.sock", uid, gid, 0660)
	if err != nil {
		return err
	}
	manifest := struct {
		ReleaseID    string `json:"release_id"`
		Binary       string `json:"binary"`
		Socket       string `json:"socket"`
		BinaryDigest string `json:"binary_digest"`
		SocketDigest string `json:"socket_digest"`
	}{i.cfg.ReleaseID, "openduck-anchor", "checkpoint.sock", hex.EncodeToString(h.Sum(nil)), socketDigest}
	b, _ := json.Marshal(manifest)
	return i.writeText("releases/anchor-checkpoint/"+i.cfg.ReleaseID+"/manifest.json", string(b)+"\n", 0440)
}

func (i *Installer) copyOperatorTools() error {
	for dst, name := range map[string]string{"operator/openduck-owner-grant": "openduck-owner-grant", "home/controller/bin/openduck-codex-login": "openduck-codex-login"} {
		if err := i.copyStagedArtifact(dst, name); err != nil {
			return err
		}
	}
	return nil
}

func (i *Installer) copyInstallerBootstrap() error {
	for _, artifact := range []string{"openduck-installer", "openduck-native-mcp", "openduck-provider-attestor", "openduck-readiness"} {
		if err := i.copyStagedArtifact("."+artifact, artifact); err != nil {
			return err
		}
	}
	if err := i.copyStagedArtifact(".openduck-service-login", "openduck-installer"); err != nil {
		return err
	}
	return nil
}

// copyInstallerJournalReleases materializes two immutable descriptors for the
// same reviewed helper.  Socket metadata is intentionally channel-specific,
// so a descriptor for checkpoint can never be replayed against anchor.
func (i *Installer) copyInstallerJournalReleases() error {
	if i.stage == nil {
		return errors.New("staged root is not pinned")
	}
	b, err := i.stage.ReadFile(i.stagedPath("openduck-installer"))
	if err != nil && i.fake {
		b, err = i.stage.ReadFile(i.stagedPath("openduck"))
	}
	if err != nil {
		return errors.New("installer journal artifact unavailable")
	}
	if want := i.stageDigests[i.stagedPath("openduck-installer")]; want != "" && Digest(b) != want {
		return errors.New("installer journal artifact mismatch")
	}
	for _, spec := range []struct{ name, group string }{{"installer-checkpoint", "_openduck_installer_checkpoint_channel"}, {"installer-anchor", "_openduck_installer_anchor_channel"}} {
		_, gid, err := i.ops.PrincipalIDs(context.Background(), "_openduck", spec.group)
		if err != nil {
			return errors.New("installer journal group unavailable")
		}
		dst := "releases/" + spec.name + "/" + i.cfg.ReleaseID + "/openduck-installer"
		if err = i.requireDeclaredCopy(dst, "openduck-installer"); err != nil {
			return err
		}
		if err = i.writeBytesExact(dst, b, 0550); err != nil {
			return err
		}
		socketDigest, err := macoschannel.SocketMetadataDigestForContract("journal.sock", map[string]uint32{"installer-checkpoint": 0, "installer-anchor": 0}[spec.name], gid, 0660)
		if err != nil {
			return err
		}
		manifest := fmt.Sprintf("{\"release_id\":%q,\"binary\":%q,\"socket\":%q,\"binary_digest\":%q,\"socket_digest\":%q}\n", i.cfg.ReleaseID, "openduck-installer", "journal.sock", Digest(b), socketDigest)
		if err = i.writeText("releases/"+spec.name+"/"+i.cfg.ReleaseID+"/manifest.json", manifest, 0440); err != nil {
			return err
		}
	}
	return nil
}

func (i *Installer) copyJournalAuthorityReleases() error {
	for _, spec := range []struct{ release, artifact, user, group string }{{"checkpoint-installer", "openduck-checkpoint", "_openduck_checkpoint", "_openduck_installer_checkpoint_channel"}, {"anchor-installer", "openduck-anchor", "_openduck_anchor", "_openduck_installer_anchor_channel"}} {
		b, err := i.stage.ReadFile(i.stagedPath(spec.artifact))
		if err != nil && i.fake {
			b, err = i.stage.ReadFile(i.stagedPath("openduck"))
		}
		if err != nil {
			return errors.New("journal authority artifact unavailable")
		}
		uid, gid, err := i.ops.PrincipalIDs(context.Background(), spec.user, spec.group)
		if err != nil {
			return errors.New("journal authority group unavailable")
		}
		dst := "releases/" + spec.release + "/" + i.cfg.ReleaseID + "/" + spec.artifact
		if err = i.requireDeclaredCopy(dst, spec.artifact); err != nil {
			return err
		}
		if err = i.writeBytesExact(dst, b, 0550); err != nil {
			return err
		}
		socketDigest, err := macoschannel.SocketMetadataDigestForContract("journal.sock", uid, gid, 0660)
		if err != nil {
			return err
		}
		manifest := fmt.Sprintf("{\"release_id\":%q,\"binary\":%q,\"socket\":%q,\"binary_digest\":%q,\"socket_digest\":%q}\n", i.cfg.ReleaseID, spec.artifact, "journal.sock", Digest(b), socketDigest)
		if err = i.writeText("releases/"+spec.release+"/"+i.cfg.ReleaseID+"/manifest.json", manifest, 0440); err != nil {
			return err
		}
	}
	return nil
}

func (i *Installer) copyStagedArtifact(dst, artifact string) error {
	if i.stage == nil {
		return errors.New("staged root is not pinned")
	}
	if err := i.requireDeclaredCopy(dst, artifact); err != nil {
		return err
	}
	b, err := i.stage.ReadFile(i.stagedPath(artifact))
	if err != nil && i.fake {
		b, err = i.stage.ReadFile(i.stagedPath("openduck"))
	}
	if err != nil {
		return fmt.Errorf("open staged artifact %s: %w", artifact, err)
	}
	if want := i.stageDigests[i.stagedPath(artifact)]; want != "" && Digest(b) != want {
		return fmt.Errorf("post-copy staged hash mismatch: %s", artifact)
	}
	if st, statErr := i.root.Lstat(dst); statErr == nil {
		if !safeExistingRegular(st, 0700, st.Size()) {
			return fmt.Errorf("unsafe installed artifact %s", dst)
		}
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return statErr
	}
	return i.atomicText(dst, string(b), 0700)
}

// prepareInactiveProviderRoots creates only the fixed trusted ancestry used by
// optional package metadata. The writable controller home is intentionally
// not an ancestor: `providers` is root:wheel 0711 and the inactive set is
// root:_openduck 0750 after applyOwnership.
func (i *Installer) prepareInactiveProviderRoots() error {
	entries := i.optionalProviderEntries()
	if len(entries) == 0 {
		i.providerRoots = nil
		return nil
	}
	if err := i.mkdir("providers", 0711); err != nil {
		return err
	}
	if err := i.mkdir(releasecatalog.InactiveProviderRoot, 0750); err != nil {
		return err
	}
	directories := map[string]bool{}
	for _, artifact := range entries {
		mappings, ok := resolvePlanArtifacts(artifact, i.cfg.ReleaseID)
		if !ok {
			return errors.New("unresolved inactive provider artifact")
		}
		for _, mapping := range mappings {
			if !validInactiveProviderMapping(mapping) {
				return errors.New("invalid inactive provider output")
			}
			directory := filepath.Dir(mapping.target)
			if directory != releasecatalog.InactiveProviderRoot {
				directories[directory] = true
			}
		}
	}
	values := make([]string, 0, len(directories))
	for directory := range directories {
		values = append(values, directory)
	}
	sort.Strings(values)
	for _, directory := range values {
		if err := i.mkdir(directory, 0750); err != nil {
			return err
		}
	}
	bound := make(map[string]os.FileInfo, len(values)+2)
	for _, directory := range append([]string{"providers", releasecatalog.InactiveProviderRoot}, values...) {
		info, statErr := i.root.Lstat(directory)
		if statErr != nil || !safeCatalogSnapshotDirectory(info) {
			return errors.New("unsafe inactive provider root")
		}
		wantMode := os.FileMode(0750)
		if directory == "providers" {
			wantMode = 0711
		}
		if info.Mode().Perm() != wantMode {
			return errors.New("inactive provider root mode mismatch")
		}
		bound[directory] = info
	}
	i.providerRoots = bound
	return i.validateInactiveProviderRootBinding()
}

// copyInactiveProviderArtifacts copies signed optional policy, descriptors,
// and disabled daemon executables before activation. The catalog contains no
// lifecycle operation, listener, owner key, native mount, or runtime start.
func (i *Installer) copyInactiveProviderArtifacts() error {
	if err := i.validateInactiveProviderRootBinding(); err != nil {
		return err
	}
	for _, artifact := range i.optionalProviderEntries() {
		mappings, ok := resolvePlanArtifacts(artifact, i.cfg.ReleaseID)
		if !ok {
			return errors.New("unresolved inactive provider artifact")
		}
		for _, mapping := range mappings {
			if !validInactiveProviderMapping(mapping) {
				return errors.New("invalid inactive provider output")
			}
			if err := i.copyAdmittedCatalogArtifact(mapping.target, artifact.Path, inactiveProviderMode(mapping)); err != nil {
				return err
			}
			if err := i.validateInactiveProviderRootBinding(); err != nil {
				return err
			}
		}
	}
	return nil
}

func (i *Installer) validateInactiveProviderRootBinding() error {
	entries := i.optionalProviderEntries()
	if len(entries) == 0 {
		return nil
	}
	if len(i.providerRoots) == 0 {
		return errors.New("inactive provider root not pinned")
	}
	for directory, before := range i.providerRoots {
		now, err := i.root.Lstat(directory)
		wantMode := os.FileMode(0750)
		if directory == "providers" {
			wantMode = 0711
		}
		if err != nil || !sameFileIdentity(before, now) || !safeCatalogSnapshotDirectory(now) || now.Mode().Perm() != wantMode {
			return errors.New("inactive provider root changed")
		}
	}
	return nil
}

func (i *Installer) verifyInactiveProviderArtifacts() error {
	entries := i.optionalProviderEntries()
	if len(entries) == 0 {
		return nil
	}
	expected, err := providerOutputInventory(entries, i.cfg.ReleaseID)
	if err != nil {
		return err
	}
	for directory, children := range expected {
		names, nameErr := catalogSnapshotDirectoryNames(i.root, directory)
		if nameErr != nil || len(names) != len(children) {
			return errors.New("inactive provider inventory mismatch")
		}
		for _, name := range names {
			if !children[name] {
				return errors.New("inactive provider unknown artifact")
			}
		}
		info, statErr := i.root.Lstat(directory)
		wantMode := os.FileMode(0750)
		if directory == "providers" {
			wantMode = 0711
		}
		if statErr != nil || info.Mode().Perm() != wantMode || !safeCatalogSnapshotDirectory(info) {
			return errors.New("inactive provider directory metadata mismatch")
		}
	}
	for _, artifact := range entries {
		mappings, ok := resolvePlanArtifacts(artifact, i.cfg.ReleaseID)
		if !ok {
			return errors.New("inactive provider resolver unavailable")
		}
		for _, mapping := range mappings {
			if !validInactiveProviderMapping(mapping) {
				return errors.New("inactive provider output invalid")
			}
			info, statErr := i.root.Lstat(mapping.target)
			if statErr != nil || !safeExistingRegular(info, inactiveProviderMode(mapping), info.Size()) {
				return errors.New("inactive provider artifact metadata mismatch")
			}
			got, readErr := i.root.ReadFile(mapping.target)
			want, stageErr := i.stage.ReadFile(artifact.Path)
			if readErr != nil || stageErr != nil || !bytes.Equal(got, want) || Digest(got) != artifact.Digest {
				return errors.New("inactive provider artifact content mismatch")
			}
		}
	}
	return nil
}

func (i *Installer) optionalProviderEntries() []macosrelease.Artifact {
	if i == nil || i.admitted == nil {
		return nil
	}
	entries := make([]macosrelease.Artifact, 0)
	for _, artifact := range i.admitted.Artifacts {
		entry, found := releasecatalog.EntryFor(artifact.Path)
		if found && !entry.Mandatory {
			entries = append(entries, artifact)
		}
	}
	return entries
}

func (i *Installer) optionalProviderDescriptorEntries() []macosrelease.Artifact {
	entries := i.optionalProviderEntries()
	if len(entries) == 0 {
		return nil
	}
	out := make([]macosrelease.Artifact, 0, len(entries))
	for _, artifact := range entries {
		entry, found := releasecatalog.EntryFor(artifact.Path)
		if found && !entry.Mandatory && (entry.Type == "provider_runtime" || entry.Type == "provider_plugin") {
			out = append(out, artifact)
		}
	}
	return out
}

// prepareProviderTransportPrerequisites creates only the empty roots exported
// by providertransport's base inventory. Peer-owned socket roots, service-key
// records, principals, launchd, and runtime start are intentionally absent:
// those require a later signed post-principal lifecycle gate.
func (i *Installer) prepareProviderTransportPrerequisites() error {
	if len(i.optionalProviderDescriptorEntries()) == 0 {
		i.providerTransportRoots = nil
		i.providerTransportPostPrincipal = false
		return nil
	}
	expected := map[string]struct {
		mode os.FileMode
		role string
	}{
		"channels/providers":       {mode: 0711, role: "root-wheel"},
		"keys/controller-provider": {mode: 0700, role: "controller"},
	}
	seen := map[string]bool{}
	for _, prerequisite := range providertransport.BaseInstallerPrerequisites() {
		relative, err := filepath.Rel(SystemRoot, prerequisite.Path)
		if err == nil && relative == "releases/controller" {
			// Controller release children are already sealed by the core release
			// topology. This parent is not a provider-transport prerequisite:
			// descriptors pin a specific release child after admission.
			continue
		}
		contract, known := expected[relative]
		if err != nil || !known || !safePlanRelative(relative) || prerequisite.Mode != contract.mode || prerequisite.OwnerRole != contract.role || seen[relative] {
			return errors.New("invalid provider transport prerequisite inventory")
		}
		seen[relative] = true
		if err := i.mkdir(relative, contract.mode); err != nil {
			return err
		}
	}
	if len(seen) != len(expected) {
		return errors.New("incomplete provider transport prerequisite inventory")
	}
	bound := make(map[string]os.FileInfo, 2)
	for _, relative := range []string{"channels/providers", "keys/controller-provider"} {
		info, err := i.root.Lstat(relative)
		if err != nil || !safeCatalogSnapshotDirectory(info) || info.Mode().Perm() != expected[relative].mode {
			return errors.New("unsafe provider transport prerequisite root")
		}
		bound[relative] = info
	}
	i.providerTransportRoots = bound
	postPrincipal, err := i.validateProviderTransportPostPrincipalInventory()
	if err != nil {
		return err
	}
	i.providerTransportPostPrincipal = postPrincipal
	return i.validateProviderTransportPrerequisiteBinding()
}

func (i *Installer) validateProviderTransportPrerequisiteBinding() error {
	if len(i.optionalProviderDescriptorEntries()) == 0 {
		return nil
	}
	if len(i.providerTransportRoots) != 2 {
		return errors.New("provider transport prerequisite roots not pinned")
	}
	for relative, mode := range map[string]os.FileMode{"channels/providers": 0711, "keys/controller-provider": 0700} {
		before, found := i.providerTransportRoots[relative]
		now, err := i.root.Lstat(relative)
		if !found || err != nil || !sameFileIdentity(before, now) || !safeCatalogSnapshotDirectory(now) || now.Mode().Perm() != mode {
			return errors.New("provider transport prerequisite root changed")
		}
	}
	postPrincipal, err := i.validateProviderTransportPostPrincipalInventory()
	if err != nil || postPrincipal != i.providerTransportPostPrincipal {
		return errors.New("provider transport prerequisite inventory changed")
	}
	return nil
}

func emptyCatalogDirectory(root *os.Root, path string) bool {
	names, err := catalogSnapshotDirectoryNames(root, path)
	return err == nil && len(names) == 0
}

type providerTransportPostPrincipalLeaf struct {
	profileID   string
	channelLeaf string // symbolic inventory only; P7 observes actual ownership.
	keyLeaf     string
}

// providerTransportPostPrincipalLeaves derives the sole post-principal
// inventory from the sealed optional runtime descriptors and transport's
// closed prerequisite table. It intentionally does not read a key, inspect a
// socket, or infer a principal from a pathname.
func (i *Installer) providerTransportPostPrincipalLeaves() ([]providerTransportPostPrincipalLeaf, error) {
	if i == nil || i.stage == nil {
		return nil, errors.New("provider transport stage unavailable")
	}
	prerequisites := make(map[string]providertransport.PostPrincipalPrerequisite)
	keyLeaves := providertransport.KeyLeaves()
	for _, prerequisite := range providertransport.PostPrincipalPrerequisites() {
		relative, err := filepath.Rel(SystemRoot, prerequisite.SocketRoot)
		if err != nil || !prerequisite.RequiresProvisionedPeer || !safePlanRelative(relative) || filepath.Dir(relative) != "channels/providers" || filepath.Base(relative) == "." || filepath.Base(relative) == ".." || prerequisite.ProfileID == "" || prerequisite.Channel == "" || !safePlanRelative(prerequisite.KeyLeaf) || filepath.Base(prerequisite.KeyLeaf) != prerequisite.KeyLeaf || keyLeaves[prerequisite.ProfileID] != prerequisite.KeyLeaf || prerequisites[prerequisite.ProfileID].ProfileID != "" {
			return nil, errors.New("invalid post-principal provider transport inventory")
		}
		prerequisites[prerequisite.ProfileID] = prerequisite
	}
	if len(prerequisites) == 0 {
		return nil, errors.New("missing post-principal provider transport inventory")
	}
	seenProfiles := make(map[string]bool)
	leaves := make([]providerTransportPostPrincipalLeaf, 0)
	for _, artifact := range i.optionalProviderDescriptorEntries() {
		entry, found := releasecatalog.EntryFor(artifact.Path)
		if !found || entry.Mandatory || entry.Type != "provider_runtime" {
			continue
		}
		body, err := readCatalogSnapshotArtifact(i.stage, artifact.Path, false, catalogSnapshotMaxBytes(entry))
		if err != nil || Digest(body) != artifact.Digest {
			return nil, errors.New("provider runtime descriptor changed")
		}
		descriptor, err := providertransport.DecodeInactiveDescriptor(body)
		if err != nil || descriptor.Provider != entry.Provider || descriptor.ProfileID != entry.ProfileID || descriptor.ProfileRevision != entry.ProfileRevision || seenProfiles[descriptor.ProfileID] {
			return nil, errors.New("invalid sealed provider runtime descriptor")
		}
		prerequisite, found := prerequisites[descriptor.ProfileID]
		if !found || keyLeaves[descriptor.ProfileID] != prerequisite.KeyLeaf {
			return nil, errors.New("provider transport descriptor/prerequisite mismatch")
		}
		seenProfiles[descriptor.ProfileID] = true
		leaves = append(leaves, providerTransportPostPrincipalLeaf{profileID: descriptor.ProfileID, channelLeaf: filepath.Base(prerequisite.SocketRoot), keyLeaf: prerequisite.KeyLeaf})
	}
	if len(leaves) == 0 {
		return nil, errors.New("provider transport descriptors absent")
	}
	sort.Slice(leaves, func(a, b int) bool { return leaves[a].profileID < leaves[b].profileID })
	return leaves, nil
}

// validateProviderTransportPostPrincipalInventory accepts either a pristine
// pair of empty base roots or a fully provisioned closed inventory. A mixed
// state, an unknown direct child, or an incomplete selected profile set fails
// closed. Socket contents are deliberately not inspected: sockets are dynamic
// peer-owned runtime state and this installer never creates or replaces them.
func (i *Installer) validateProviderTransportPostPrincipalInventory() (bool, error) {
	if _, err := i.providerTransportPostPrincipalLeaves(); err != nil {
		return false, err
	}
	channelNames, err := catalogSnapshotDirectoryNames(i.root, "channels/providers")
	if err != nil {
		return false, err
	}
	keyNames, err := catalogSnapshotDirectoryNames(i.root, "keys/controller-provider")
	if err != nil {
		return false, err
	}
	if len(channelNames) == 0 && len(keyNames) == 0 {
		return false, nil
	}
	// A disabled release has no active descriptor with an observed identity.
	// Any children are activation state and must be checked/owned by P7, not
	// guessed or normalized by a base installer rerun.
	return false, errors.New("post-principal provider transport state requires P7 active descriptor")
}

func (i *Installer) verifyProviderTransportPostPrincipalOwnership(ctx context.Context) error {
	if !i.providerTransportPostPrincipal {
		return nil
	}
	leaves, err := i.providerTransportPostPrincipalLeaves()
	if err != nil {
		return err
	}
	controllerUID, controllerGID, err := i.ops.PrincipalIDs(ctx, "_openduck", "_openduck")
	if err != nil {
		return errors.New("provider transport controller ownership unavailable")
	}
	for _, leaf := range leaves {
		keyInfo, keyErr := i.root.Lstat(filepath.Join("keys/controller-provider", leaf.keyLeaf))
		if keyErr != nil || !ownedBy(keyInfo, controllerUID, controllerGID) {
			return errors.New("provider transport post-principal ownership mismatch")
		}
	}
	return nil
}

func (i *Installer) applyProviderTransportPrerequisiteOwnership(ctx context.Context) error {
	if len(i.optionalProviderDescriptorEntries()) == 0 {
		return nil
	}
	if err := i.validateProviderTransportPrerequisiteBinding(); err != nil {
		return err
	}
	if i.providerTransportPostPrincipal {
		// A separate signed gate owns every peer channel child and key record.
		// Never normalize or chown that existing state during a release rerun.
		return nil
	}
	if err := i.ops.Chown(ctx, filepath.Join(SystemRoot, "channels/providers"), "root", "wheel"); err != nil {
		return err
	}
	if err := i.ops.Chown(ctx, filepath.Join(SystemRoot, "keys/controller-provider"), "_openduck", "_openduck"); err != nil {
		return err
	}
	return i.validateProviderTransportPrerequisiteBinding()
}

func (i *Installer) verifyProviderTransportPrerequisites(ctx context.Context) error {
	if len(i.optionalProviderDescriptorEntries()) == 0 {
		return nil
	}
	if err := i.validateProviderTransportPrerequisiteBinding(); err != nil {
		return err
	}
	if i.fake {
		for _, contract := range []struct {
			path      string
			mode      os.FileMode
			mustEmpty bool
		}{
			{path: "channels/providers", mode: 0711, mustEmpty: true},
			{path: "keys/controller-provider", mode: 0700, mustEmpty: true},
		} {
			info, statErr := i.root.Lstat(contract.path)
			if statErr != nil || !safeCatalogSnapshotDirectory(info) || info.Mode().Perm() != contract.mode || (contract.mustEmpty && !i.providerTransportPostPrincipal && !emptyCatalogDirectory(i.root, contract.path)) {
				return errors.New("provider transport prerequisite metadata mismatch")
			}
		}
		return nil
	}
	_, wheelGID, err := i.ops.PrincipalIDs(ctx, "root", "wheel")
	if err != nil {
		return errors.New("provider transport parent ownership unavailable")
	}
	controllerUID, controllerGID, err := i.ops.PrincipalIDs(ctx, "_openduck", "_openduck")
	if err != nil {
		return errors.New("provider transport controller ownership unavailable")
	}
	for _, contract := range []struct {
		path      string
		mode      os.FileMode
		uid, gid  uint32
		mustEmpty bool
	}{
		{path: "channels/providers", mode: 0711, uid: 0, gid: wheelGID, mustEmpty: true},
		{path: "keys/controller-provider", mode: 0700, uid: controllerUID, gid: controllerGID, mustEmpty: true},
	} {
		info, statErr := i.root.Lstat(contract.path)
		if statErr != nil || !safeCatalogSnapshotDirectory(info) || info.Mode().Perm() != contract.mode || !ownedBy(info, contract.uid, contract.gid) || (contract.mustEmpty && !i.providerTransportPostPrincipal && !emptyCatalogDirectory(i.root, contract.path)) {
			return errors.New("provider transport prerequisite ownership mismatch")
		}
	}
	return i.verifyProviderTransportPostPrincipalOwnership(ctx)
}

// verifyChannelTraversalRoots proves the POSIX ancestor contract used by all
// service socket roots: root:wheel 0711 lets a non-wheel service traverse to
// its own group-protected child while never granting it directory listing or
// write access to the parent.
func (i *Installer) verifyChannelTraversalRoots(ctx context.Context) error {
	for _, path := range []string{"channels", "checkpoint-channel"} {
		info, err := i.root.Lstat(path)
		if err != nil || !safeCatalogSnapshotDirectory(info) || info.Mode().Perm() != 0711 {
			return errors.New("channel traversal parent metadata mismatch")
		}
		if !i.fake {
			_, wheelGID, idErr := i.ops.PrincipalIDs(ctx, "root", "wheel")
			if idErr != nil || !ownedBy(info, 0, wheelGID) {
				return errors.New("channel traversal parent ownership mismatch")
			}
		}
	}
	return nil
}

func validInactiveProviderMapping(mapping planMapping) bool {
	return strings.HasPrefix(mapping.target, releasecatalog.InactiveProviderRoot+"/") && (mapping.mode == "0440" || mapping.mode == "0500" || mapping.mode == "0550") && mapping.owner == "root" && mapping.group == "_openduck" && safePlanRelative(mapping.target)
}

func inactiveProviderMode(mapping planMapping) os.FileMode {
	if mapping.mode == "0500" {
		return 0500
	}
	if mapping.mode == "0550" {
		return 0550
	}
	return 0440
}

func providerOutputInventory(entries []macosrelease.Artifact, release string) (map[string]map[string]bool, error) {
	children := map[string]map[string]bool{"providers": {"inactive": true}, releasecatalog.InactiveProviderRoot: {}}
	for _, artifact := range entries {
		mappings, ok := resolvePlanArtifacts(artifact, release)
		if !ok {
			return nil, errors.New("inactive provider resolver unavailable")
		}
		for _, mapping := range mappings {
			if !validInactiveProviderMapping(mapping) {
				return nil, errors.New("invalid inactive provider output")
			}
			parts := strings.Split(mapping.target, "/")
			parent := ""
			for index, part := range parts {
				if parent != "" && children[parent] == nil {
					children[parent] = map[string]bool{}
				}
				if parent != "" {
					children[parent][part] = true
				}
				if index == len(parts)-1 {
					break
				}
				if parent == "" {
					parent = part
				} else {
					parent += "/" + part
				}
			}
		}
	}
	return children, nil
}

func (i *Installer) copyAdmittedCatalogArtifact(dst, source string, mode os.FileMode) error {
	if i.stage == nil || !safePlanRelative(source) || !safePlanRelative(dst) || (mode.Perm() != 0440 && mode.Perm() != 0500 && mode.Perm() != 0550) {
		return errors.New("invalid catalog artifact copy")
	}
	if err := i.requireDeclaredCopyPath(dst, source); err != nil {
		return err
	}
	body, err := i.stage.ReadFile(source)
	if err != nil {
		return fmt.Errorf("open staged catalog artifact %s: %w", source, err)
	}
	if want := i.stageDigests[source]; want == "" || Digest(body) != want {
		return fmt.Errorf("post-copy staged hash mismatch: %s", source)
	}
	if existing, statErr := i.root.Lstat(dst); statErr == nil {
		if !safeExistingRegular(existing, mode, existing.Size()) {
			return fmt.Errorf("unsafe installed catalog artifact %s", dst)
		}
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return statErr
	}
	return i.atomicText(dst, string(body), mode)
}

func (i *Installer) stagedPath(name string) string {
	if i.fake && i.admitted == nil {
		return name
	}
	return "bin/" + name
}

// requireDeclaredCopy makes every production write traceable to the same
// ManifestV2 resolver used by PlanV2. Legacy package fixtures intentionally
// have no admitted manifest and remain test-only.
func (i *Installer) requireDeclaredCopy(dst, artifact string) error {
	return i.requireDeclaredCopyPath(dst, "bin/"+artifact)
}

func (i *Installer) requireDeclaredCopyPath(dst, source string) error {
	if i.admitted == nil {
		return nil
	}
	for _, admitted := range i.admitted.Artifacts {
		if admitted.Path != source {
			continue
		}
		mappings, ok := resolvePlanArtifacts(admitted, i.cfg.ReleaseID)
		if !ok {
			return errors.New("unresolved admitted copy source")
		}
		for _, mapping := range mappings {
			if mapping.target == dst {
				if i.stageDigests == nil || i.stageDigests[source] != admitted.Digest {
					return errors.New("admitted copy digest unavailable")
				}
				return nil
			}
		}
		return errors.New("admitted copy target mismatch")
	}
	return errors.New("admitted copy source missing")
}

func (i *Installer) artifactSourceDir() string {
	if st, err := os.Stat(filepath.Join(i.cfg.BinaryDir, "bin")); err == nil && st.IsDir() {
		return filepath.Join(i.cfg.BinaryDir, "bin")
	}
	return i.cfg.BinaryDir
}

func (i *Installer) copyCodexCLI() error {
	if err := i.copyStagedArtifact("home/runtime/bin/codex", "codex"); err != nil {
		return err
	}
	b, err := i.root.ReadFile("home/runtime/bin/codex")
	if err != nil {
		return err
	}
	dst := "releases/codex/" + i.cfg.ReleaseID + "/codex"
	if err := i.requireDeclaredCopy(dst, "codex"); err != nil {
		return err
	}
	f, err := i.root.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0755)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return nil
		}
		return err
	}
	if err = f.Chmod(0755); err != nil {
		_ = f.Close()
		return err
	}
	if _, err = f.Write(b); err != nil {
		_ = f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	i.created = append(i.created, "releases/codex/"+i.cfg.ReleaseID+"/codex")
	h := sha256.Sum256(b)
	// The Codex artifact is a root-owned immutable artifact.  Its socket
	// contract is therefore evaluated against root:root, independently of the
	// runtime daemon's service account.
	sd, err := macoschannel.SocketMetadataDigestForContract("runtime.sock", 0, 0, 0755)
	if err != nil {
		return err
	}
	manifest := fmt.Sprintf("{\"release_id\":%q,\"binary\":%q,\"socket\":%q,\"binary_digest\":%q,\"socket_digest\":%q}\n", i.cfg.ReleaseID, "codex", "runtime.sock", hex.EncodeToString(h[:]), sd)
	if err := i.writeText("releases/codex/"+i.cfg.ReleaseID+"/manifest.json", manifest, 0644); err != nil {
		return err
	}
	return nil
}
func binaryName(service string) string {
	if service == "broker" {
		return "openduck-codex-broker"
	}
	if service == "runtime" {
		return "openduck-codex-runtime"
	}
	return "openduck-" + service
}
func serviceLabel(service string) string {
	switch service {
	case "broker":
		return "codex-broker"
	case "runtime":
		return "codex-runtime"
	default:
		return service
	}
}
func socketName(service string) string {
	switch service {
	case "checkpoint":
		return "checkpoint.sock"
	case "anchor":
		return "anchor.sock"
	case "runtime":
		return "runtime.sock"
	case "broker":
		return "owner.sock"
	default:
		return "control.sock"
	}
}
func channelGroup(service string) string {
	switch service {
	case "checkpoint":
		return "_openduck_checkpoint_channel"
	case "anchor":
		return "_openduck_channel"
	case "egress":
		return "_openduck_egress_channel"
	case "broker":
		return "_openduck_broker_channel"
	case "runtime":
		return "_openduck_runtime_channel"
	default:
		return "_openduck"
	}
}
func (i *Installer) writeKey(p string) error {
	f, err := i.root.OpenFile(p, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			st, e := i.root.Lstat(p)
			if e != nil || st.Mode()&os.ModeSymlink != 0 || st.Size() != 32 || st.Mode().Perm() != 0600 {
				return errors.New("existing key unsafe")
			}
			return nil
		}
		return err
	}
	if err = f.Chmod(0600); err != nil {
		_ = f.Close()
		return err
	}
	defer f.Close()
	b := make([]byte, 32)
	if _, err = io.ReadFull(rand.Reader, b); err != nil {
		return err
	}
	_, err = f.Write(b)
	for n := range b {
		b[n] = 0
	}
	if err == nil {
		i.created = append(i.created, p)
	}
	return err
}

func (i *Installer) writeKeyBytes(p string, b []byte) error {
	f, err := i.root.OpenFile(p, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			st, e := i.root.Lstat(p)
			if e != nil || !safeExistingRegular(st, 0600, int64(len(b))) {
				return errors.New("existing key unsafe")
			}
			f, e := i.root.Open(p)
			if e != nil {
				return errors.New("existing key unsafe")
			}
			opened, statErr := f.Stat()
			got, readErr := io.ReadAll(io.LimitReader(f, int64(len(b))+1))
			closeErr := f.Close()
			if statErr != nil || readErr != nil || closeErr != nil || !sameFileIdentity(st, opened) || !safeExistingRegular(opened, 0600, int64(len(b))) || !bytes.Equal(got, b) {
				return errors.New("existing key content mismatch")
			}
			return nil
		}
		return err
	}
	if err = f.Chmod(0600); err != nil {
		_ = f.Close()
		return err
	}
	if _, err = io.Copy(f, bytes.NewReader(b)); err != nil {
		_ = f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	i.created = append(i.created, p)
	return nil
}

func canonicalServiceKey(channel string, epoch uint64, raw []byte) []byte {
	const recordSize = 116
	r := make([]byte, recordSize)
	copy(r[:8], []byte{'O', 'D', 'K', 'E', 'Y', 'F', 'D', 1})
	r[8] = 1
	r[9] = byte(len(channel))
	copy(r[12:12+len(channel)], channel)
	binary.BigEndian.PutUint64(r[76:84], epoch)
	copy(r[84:], raw)
	return r
}

func (i *Installer) writeBytesExact(p string, b []byte, mode os.FileMode) error {
	f, err := i.root.OpenFile(p, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			st, e := i.root.Lstat(p)
			if e != nil || !safeExistingRegular(st, mode, int64(len(b))) {
				return errors.New("existing protected key unsafe")
			}
			got, e := i.root.ReadFile(p)
			if e != nil || !bytes.Equal(got, b) {
				return errors.New("existing protected key content mismatch")
			}
			return nil
		}
		return err
	}
	if err = f.Chmod(mode); err != nil {
		_ = f.Close()
		return err
	}
	if _, err = f.Write(b); err != nil {
		_ = f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	i.created = append(i.created, p)
	return nil
}

func safeExistingRegular(st os.FileInfo, mode os.FileMode, size int64) bool {
	if st == nil || !st.Mode().IsRegular() || st.Mode()&os.ModeSymlink != 0 || st.Mode().Perm() != mode.Perm() || st.Size() != size || st.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		return false
	}
	x, ok := st.Sys().(*syscall.Stat_t)
	return ok && x != nil && x.Nlink == 1 && uint32(x.Mode)&07000 == 0
}

func sameFileIdentity(a, b os.FileInfo) bool {
	x, xok := a.Sys().(*syscall.Stat_t)
	y, yok := b.Sys().(*syscall.Stat_t)
	return xok && yok && x != nil && y != nil && x.Dev == y.Dev && x.Ino == y.Ino
}

func ownedBy(info os.FileInfo, uid, gid uint32) bool {
	st, ok := info.Sys().(*syscall.Stat_t)
	return ok && st != nil && uint32(st.Uid) == uid && uint32(st.Gid) == gid
}
func (i *Installer) writeText(p, s string, m os.FileMode) error {
	if st, err := i.root.Lstat(p); err == nil {
		if !safeExistingRegular(st, m, int64(len(s))) {
			return fmt.Errorf("existing file metadata mismatch: %s", p)
		}
		got, err := i.root.ReadFile(p)
		if err != nil || !bytes.Equal(got, []byte(s)) {
			return fmt.Errorf("existing file content mismatch: %s", p)
		}
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	err := i.root.WriteFile(p, []byte(s), m)
	if err == nil {
		err = i.root.Chmod(p, m)
	}
	if err == nil {
		i.created = append(i.created, p)
	}
	return err
}
func (i *Installer) atomicText(p, s string, m os.FileMode) error {
	if err := i.snapshotAtomicFile(p, true); err != nil {
		return err
	}
	tmp := filepath.Join(filepath.Dir(p), "."+filepath.Base(p)+".tmp")
	_ = i.root.Remove(tmp)
	f, e := i.root.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, m)
	if e != nil {
		return e
	}
	if e = f.Chmod(m); e != nil {
		_ = f.Close()
		_ = i.root.Remove(tmp)
		return e
	}
	if _, e = io.WriteString(f, s); e != nil {
		_ = f.Close()
		_ = i.root.Remove(tmp)
		return e
	}
	if e = f.Close(); e != nil {
		_ = i.root.Remove(tmp)
		return e
	}
	return i.root.Rename(tmp, p)
}

// writeReleaseState is deliberately outside Apply's mutable-artifact journal:
// it is the small durable state machine, not payload configuration. Values are
// closed release IDs and writes use the same fixed-root atomic rename protocol
// as other pointers.
func (i *Installer) writeReleaseState(path, releaseID string) error {
	if !validID(releaseID) {
		return errors.New("invalid release state")
	}
	tmp := filepath.Join(filepath.Dir(path), "."+filepath.Base(path)+".state.tmp")
	_ = i.root.Remove(tmp)
	f, err := i.root.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	if err = f.Chmod(0644); err == nil {
		_, err = io.WriteString(f, releaseID+"\n")
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		_ = i.root.Remove(tmp)
		return err
	}
	if err = i.root.Rename(tmp, path); err != nil {
		_ = i.root.Remove(tmp)
	}
	return err
}

func (i *Installer) readReleaseState(path string) (string, error) {
	b, err := i.root.ReadFile(path)
	if err != nil {
		return "", err
	}
	st, err := i.root.Lstat(path)
	if err != nil || !safeExistingRegular(st, 0644, int64(len(b))) {
		return "", errors.New("invalid release state")
	}
	id := strings.TrimSpace(string(b))
	if !validID(id) || string(b) != id+"\n" {
		return "", errors.New("invalid release state")
	}
	return id, nil
}

// validateExistingActiveSelection is read-only and closes the gap between a
// candidate configuration and a stale/tampered operational pointer. Absence is
// valid before first activation; any present selector must retain the same
// immutable, marker-backed rollback closure used by Activate and Rollback.
func (i *Installer) validateExistingActiveSelection() error {
	if i == nil || i.root == nil {
		return errors.New("installer unavailable")
	}
	if _, err := i.root.Lstat("active.release"); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return errors.New("active release selector invalid")
	}
	active, err := i.readReleaseState("active.release")
	if err != nil || i.validateRollbackRelease(active) != nil {
		return errors.New("active release selector invalid")
	}
	return nil
}

// configuredCandidate is the activation gate and the only recovery path for a
// crash after candidate verification but before configured.release. It never
// treats an arbitrary marker as operational state.
func (i *Installer) configuredCandidate() error {
	candidate, err := i.readReleaseState("candidate.release")
	if err != nil || candidate != i.cfg.ReleaseID {
		return errors.New("configured candidate unavailable")
	}
	configured, configuredErr := i.readReleaseState("configured.release")
	if configuredErr == nil {
		if configured != candidate {
			return errors.New("configured candidate mismatch")
		}
		return nil
	}
	if !errors.Is(configuredErr, os.ErrNotExist) {
		return configuredErr
	}
	if err := i.Verify(); err != nil {
		return fmt.Errorf("recover configured candidate: %w", err)
	}
	return i.writeReleaseState("configured.release", candidate)
}

func (i *Installer) snapshotAtomicFile(p string, markCreated bool) error {
	if _, seen := i.backupExists[p]; seen {
		return nil
	}
	old, err := i.root.ReadFile(p)
	if err == nil {
		st, statErr := i.root.Lstat(p)
		if statErr != nil || !st.Mode().IsRegular() || st.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("unsafe transaction file: %s", p)
		}
		i.backups[p] = append([]byte(nil), old...)
		i.backupExists[p] = true
		i.backupModes[p] = st.Mode().Perm()
		return nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	i.backupExists[p] = false
	if markCreated {
		i.created = append(i.created, p)
	}
	return nil
}

func (i *Installer) atomicRemove(p string) error {
	if err := i.snapshotAtomicFile(p, false); err != nil {
		return err
	}
	err := i.root.Remove(p)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

// applyFixedSharedPolicy is reachable only from Apply after STOP_REQUIRED has
// proven all jobs unloaded.  It upgrades only a fixed literal and journals the
// exact prior bytes/mode so a later Apply failure can restore them.
func (i *Installer) applyFixedSharedPolicy(path string) error {
	if err := i.requireJobsUnloaded(context.Background()); err != nil {
		return err
	}
	literal := ""
	switch path {
	case "pf/openduck.conf", "seatbelt/state":
		literal = fixedPFRules
	case "seatbelt/codex.sb":
		literal = fixedCodexSeatbelt
	case "seatbelt/egress.sb":
		literal = fixedEgressSeatbelt
	default:
		return errors.New("unsupported shared policy path")
	}
	const mode = os.FileMode(0644)
	st, err := i.root.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return i.atomicText(path, literal, mode)
	}
	if err != nil {
		return err
	}
	expectedUID, expectedGID := uint32(0), uint32(0)
	if i.fake {
		expectedUID, expectedGID = uint32(i.cfg.UID), uint32(i.cfg.GID)
	}
	if !safeExistingRegular(st, mode, st.Size()) || !ownedBy(st, expectedUID, expectedGID) {
		return fmt.Errorf("shared policy metadata mismatch: %s", path)
	}
	current, err := i.root.ReadFile(path)
	if err != nil {
		return err
	}
	if bytes.Equal(current, []byte(literal)) {
		return nil
	}
	if (path != "pf/openduck.conf" && path != "seatbelt/state") || !bytes.Equal(current, []byte(legacyPFRules)) {
		return fmt.Errorf("shared policy content mismatch: %s", path)
	}
	return i.atomicText(path, literal, mode)
}

func (i *Installer) cleanup() {
	_ = i.cleanupWithError()
}

func (i *Installer) cleanupWithError() error {
	var result error
	if i.nativeMCPBoundaryCreated {
		if err := i.ops.RemoveNativeMCPBoundary(context.Background()); err != nil {
			result = errors.Join(result, fmt.Errorf("remove native MCP boundary: %w", err))
		}
		i.nativeMCPBoundaryCreated = false
	}
	for p, old := range i.backups {
		if err := i.root.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
			result = errors.Join(result, fmt.Errorf("remove transaction file %s: %w", p, err))
			continue
		}
		mode := i.backupModes[p]
		if mode == 0 {
			mode = 0600
		}
		f, err := i.root.OpenFile(p, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
		if err != nil {
			result = errors.Join(result, fmt.Errorf("restore transaction file %s: %w", p, err))
			continue
		}
		if err = f.Chmod(mode); err == nil {
			_, err = f.Write(old)
		}
		if closeErr := f.Close(); err == nil {
			err = closeErr
		}
		if err != nil {
			result = errors.Join(result, fmt.Errorf("restore transaction file %s: %w", p, err))
		}
	}
	for n := len(i.created) - 1; n >= 0; n-- {
		if err := i.root.Remove(i.created[n]); err != nil && !errors.Is(err, os.ErrNotExist) {
			result = errors.Join(result, fmt.Errorf("remove created transaction path %s: %w", i.created[n], err))
		}
	}
	i.created = nil
	i.backups = nil
	i.backupExists = nil
	i.backupModes = nil
	return result
}

func (i *Installer) Verify() (err error) {
	if i == nil || i.root == nil {
		return errors.New("installer unavailable")
	}
	verified := false
	if auditErr := i.audit("verify", "started", "started", "", "", true); auditErr != nil {
		return fmt.Errorf("audit start: %w", auditErr)
	}
	defer func() {
		var finishErr error
		if verified {
			finishErr = i.audit("verify", "finished", "succeeded", "", "", true)
		} else {
			finishErr = i.audit("verify", "finished", "failed", "verification_failed", "", true)
		}
		if finishErr != nil {
			if err == nil {
				err = fmt.Errorf("audit finish: %w", finishErr)
			} else {
				err = errors.Join(err, fmt.Errorf("audit finish: %w", finishErr))
			}
		}
	}()
	if err := i.preflight(); err != nil {
		return err
	}
	if err := i.verifyInstalledAdmittedManifest(); err != nil {
		return err
	}
	for _, s := range services {
		if err := i.ops.VerifyPrincipal(context.Background(), s.User, s.Group); err != nil {
			return err
		}
	}
	if err := i.verifyDistinctPrincipalIDs(context.Background()); err != nil {
		return err
	}
	for g, users := range map[string][]string{"_openduck_channel": {"_openduck", "_openduck_anchor"}, "_openduck_checkpoint_channel": {"_openduck_checkpoint", "_openduck_anchor"}, "_openduck_egress_channel": {"_openduck_egress", "_openduck_broker"}, "_openduck_broker_channel": {"_openduck_broker", "_openduck"}, "_openduck_runtime_channel": {"_openduck_codex", "_openduck_broker"}, "_openduck_installer_checkpoint_channel": {"_openduck_checkpoint"}, "_openduck_installer_anchor_channel": {"_openduck_anchor"}} {
		for _, u := range users {
			if err := i.ops.VerifyMembership(context.Background(), g, u); err != nil {
				return err
			}
		}
	}
	for _, s := range services {
		for _, b := range []string{"state", "logs", "home", "keys"} {
			st, e := i.root.Lstat(b + "/" + s.Name)
			wantMode := os.FileMode(0700)
			if e != nil || !st.IsDir() || st.Mode().Perm() != wantMode.Perm() || st.Mode()&os.ModeSymlink != 0 {
				return fmt.Errorf("verify %s", b+"/"+s.Name)
			}
		}
		st, e := i.root.Lstat("keys/" + s.Name + "/service.key")
		if e != nil || st.Mode().Perm() != 0600 || st.Size() != 116 {
			return fmt.Errorf("verify key %s", s.Name)
		}
		releaseDir := "releases/" + s.Name + "/" + i.cfg.ReleaseID
		ms, me := i.root.ReadFile(releaseDir + "/manifest.json")
		if me != nil {
			return me
		}
		var m struct {
			ReleaseID    string `json:"release_id"`
			Binary       string `json:"binary"`
			Socket       string `json:"socket"`
			BinaryDigest string `json:"binary_digest"`
			SocketDigest string `json:"socket_digest"`
		}
		if json.Unmarshal(ms, &m) != nil || m.ReleaseID != i.cfg.ReleaseID || m.Binary != binaryName(s.Name) || m.Socket != socketName(s.Name) || len(m.BinaryDigest) != 64 || strings.Trim(m.BinaryDigest, "0123456789abcdef") != "" || len(m.SocketDigest) != 64 {
			return fmt.Errorf("verify manifest %s", s.Name)
		}
		bin, be := i.root.ReadFile(releaseDir + "/" + m.Binary)
		if be != nil {
			return be
		}
		if Digest(bin) != m.BinaryDigest {
			return fmt.Errorf("verify binary hash %s", s.Name)
		}
		rst, re := i.root.Lstat(releaseDir)
		mst2, me2 := i.root.Lstat(releaseDir + "/manifest.json")
		bst, be2 := i.root.Lstat(releaseDir + "/" + m.Binary)
		if re != nil || me2 != nil || be2 != nil || rst.Mode().Perm() != 0550 || mst2.Mode().Perm() != 0440 || bst.Mode().Perm() != 0550 {
			return fmt.Errorf("verify release modes %s", s.Name)
		}
	}
	scopedPolicyPath := "releases/egress/" + i.cfg.ReleaseID + "/egress-policy.json"
	scopedPolicy, scopedErr := i.root.ReadFile(scopedPolicyPath)
	sharedPolicy, sharedErr := i.root.ReadFile("pf/egress-policy.json")
	policyInfo, policyStatErr := i.root.Lstat(scopedPolicyPath)
	var verifiedPolicy modelegress.Policy
	if scopedErr != nil || sharedErr != nil || policyStatErr != nil || !safeExistingRegular(policyInfo, 0440, int64(len(scopedPolicy))) || !bytes.Equal(scopedPolicy, sharedPolicy) || json.Unmarshal(scopedPolicy, &verifiedPolicy) != nil {
		return errors.New("verify release-scoped egress policy")
	}
	canonicalPolicy, policyErr := verifiedPolicy.Canonical()
	egressManifest, manifestErr := i.root.ReadFile("releases/egress/" + i.cfg.ReleaseID + "/manifest.json")
	if policyErr != nil || manifestErr != nil || !bytes.Equal(scopedPolicy, append(canonicalPolicy, '\n')) || verifiedPolicy.ReleaseDigest != "sha256:"+Digest(egressManifest) {
		return errors.New("verify release-scoped egress policy pins")
	}
	if err := i.verifyChannelAndAnchorCheckpointArtifacts(); err != nil {
		return err
	}
	if err := i.verifyCodexRelease(); err != nil {
		return err
	}
	for _, path := range []string{"operator/openduck-owner-grant", "home/controller/bin/openduck-codex-login"} {
		st, e := i.root.Lstat(path)
		if e != nil || st.Mode().Perm() != 0700 || st.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("verify operator %s", path)
		}
	}
	for _, p := range []string{".openduck-installer", ".openduck-native-mcp", ".openduck-provider-attestor", ".openduck-readiness", ".openduck-service-login"} {
		if st, e := i.root.Lstat(p); e != nil || !safeExistingRegular(st, 0700, st.Size()) {
			return errors.New("verify operator bootstrap")
		}
	}
	if err := i.verifyInactiveProviderArtifacts(); err != nil {
		return err
	}
	if err := i.verifyChannelTraversalRoots(context.Background()); err != nil {
		return err
	}
	if err := i.verifyProviderTransportPrerequisites(context.Background()); err != nil {
		return err
	}
	if st, e := i.root.Lstat("operator/codex-login.json"); e != nil || !safeExistingRegular(st, 0644, st.Size()) {
		return errors.New("verify service login config")
	}
	if i.cfg.BinaryDir != "" {
		for _, p := range []struct{ installed, staged string }{{"operator/openduck-owner-grant", "openduck-owner-grant"}, {"home/controller/bin/openduck-codex-login", "openduck-codex-login"}, {".openduck-installer", "openduck-installer"}, {".openduck-native-mcp", "openduck-native-mcp"}, {".openduck-provider-attestor", "openduck-provider-attestor"}, {".openduck-readiness", "openduck-readiness"}, {".openduck-service-login", "openduck-installer"}, {"home/runtime/bin/codex", "codex"}, {"releases/codex/" + i.cfg.ReleaseID + "/codex", "codex"}} {
			got, err := i.root.ReadFile(p.installed)
			if err != nil {
				return fmt.Errorf("verify installed artifact %s", p.installed)
			}
			if i.stage == nil {
				return errors.New("staged root is not pinned during verification")
			}
			want, err := i.stage.ReadFile(i.stagedPath(p.staged))
			if err != nil && i.fake {
				want, err = i.stage.ReadFile(i.stagedPath("openduck"))
			}
			if err != nil || !bytes.Equal(got, want) {
				return fmt.Errorf("verify staged artifact equality %s", p.installed)
			}
		}
	}
	privateKey, privateErr := i.readProtectedFile("operator/owner-ed25519.key", 0600, ed25519.PrivateKeySize)
	publicKey, publicErr := i.readProtectedFile("keys/controller-anchor/owner.public", 0600, ed25519.PublicKeySize)
	if privateErr != nil || publicErr != nil || !bytes.Equal(ed25519.PrivateKey(privateKey).Public().(ed25519.PublicKey), publicKey) {
		return errors.New("verify owner key pair")
	}
	for n := range privateKey {
		privateKey[n] = 0
	}
	if st, e := i.root.Lstat("operator/owner-capabilities"); e != nil || st.Mode().Perm() != 0710 {
		return errors.New("verify owner capability root")
	}
	// Configuration verification is intentionally possible before activation.
	// Prefer the candidate selector during Apply (an older active pointer is
	// expected on upgrade), otherwise require the operational active pointer.
	selector := "active.release"
	if candidate, candidateErr := i.readReleaseState("candidate.release"); candidateErr == nil && candidate == i.cfg.ReleaseID {
		selector = "candidate.release"
	}
	selected, selectedErr := i.readReleaseState(selector)
	if selectedErr != nil || selected != i.cfg.ReleaseID {
		return errors.New("verify release selector")
	}
	verified = true
	return nil
}

func (i *Installer) verifyProductionOwnership(ctx context.Context, allowPendingPFPlists bool) error {
	if i.fake {
		return nil
	}
	if err := i.verifyChannelTraversalRoots(ctx); err != nil {
		return err
	}
	if err := i.verifyProviderTransportPrerequisites(ctx); err != nil {
		return err
	}
	for _, service := range services {
		uid, gid, err := i.ops.PrincipalIDs(ctx, service.User, service.Group)
		if err != nil {
			return err
		}
		for _, path := range []string{"state/" + service.Name, "logs/" + service.Name, "home/" + service.Name, "keys/" + service.Name} {
			st, statErr := i.root.Lstat(path)
			if statErr != nil || !ownedBy(st, uid, gid) {
				return fmt.Errorf("ownership mismatch: %s", path)
			}
		}
		for _, path := range []string{"releases/" + service.Name, "releases/" + service.Name + "/" + i.cfg.ReleaseID, "releases/" + service.Name + "/" + i.cfg.ReleaseID + "/manifest.json", "releases/" + service.Name + "/" + i.cfg.ReleaseID + "/" + binaryName(service.Name)} {
			st, statErr := i.root.Lstat(path)
			if statErr != nil || !ownedBy(st, 0, gid) {
				return fmt.Errorf("immutable release ownership mismatch: %s", path)
			}
		}
	}
	for _, contract := range []struct{ path, user, group string }{{"channels/platform-anchor", "_openduck_anchor", "_openduck_channel"}, {"channels/model-egress", "_openduck_egress", "_openduck_egress_channel"}, {"channels/codex-owner", "_openduck_broker", "_openduck_broker_channel"}, {"channels/codex-runtime", "_openduck_codex", "_openduck_runtime_channel"}, {"checkpoint-channel/platform-checkpoint", "_openduck_checkpoint", "_openduck_checkpoint_channel"}, {"channels/installer-checkpoint", "_openduck_checkpoint", "_openduck_installer_checkpoint_channel"}, {"channels/installer-anchor", "_openduck_anchor", "_openduck_installer_anchor_channel"}} {
		uid, gid, err := i.ops.PrincipalIDs(ctx, contract.user, contract.group)
		st, statErr := i.root.Lstat(contract.path)
		if err != nil || statErr != nil || !ownedBy(st, uid, gid) {
			return fmt.Errorf("ownership mismatch: %s", contract.path)
		}
	}
	for _, contract := range canonicalServiceKeyOwnership() {
		uid, gid, err := i.ops.PrincipalIDs(ctx, contract.user, contract.group)
		st, statErr := i.root.Lstat(contract.path)
		if err != nil || statErr != nil || !ownedBy(st, uid, gid) {
			return fmt.Errorf("ownership mismatch: %s", contract.path)
		}
	}
	for _, contract := range canonicalKeyRootOwnership() {
		uid, gid, err := i.ops.PrincipalIDs(ctx, contract.user, contract.group)
		st, statErr := i.root.Lstat(contract.path)
		if err != nil || statErr != nil || !ownedBy(st, uid, gid) {
			return fmt.Errorf("ownership mismatch: %s", contract.path)
		}
	}
	for _, contract := range []struct{ path, user, group string }{{"keys/controller-anchor/owner.public", "_openduck", "_openduck"}, {"home/controller/bin/openduck-codex-login", "_openduck", "_openduck"}} {
		uid, gid, err := i.ops.PrincipalIDs(ctx, contract.user, contract.group)
		st, statErr := i.root.Lstat(contract.path)
		if err != nil || statErr != nil || !ownedBy(st, uid, gid) {
			return fmt.Errorf("ownership mismatch: %s", contract.path)
		}
	}
	if err := i.verifyInactiveProviderOwnership(ctx); err != nil {
		return err
	}
	_, anchorGID, err := i.ops.PrincipalIDs(ctx, "_openduck_anchor", "_openduck_anchor")
	if err != nil {
		return err
	}
	for _, path := range []string{"releases/anchor-checkpoint", "releases/anchor-checkpoint/" + i.cfg.ReleaseID, "releases/anchor-checkpoint/" + i.cfg.ReleaseID + "/manifest.json", "releases/anchor-checkpoint/" + i.cfg.ReleaseID + "/openduck-anchor"} {
		st, statErr := i.root.Lstat(path)
		if statErr != nil || !ownedBy(st, 0, anchorGID) {
			return fmt.Errorf("ownership mismatch: %s", path)
		}
	}
	for _, contract := range []struct{ release, binary, user, group string }{{"checkpoint-installer", "openduck-checkpoint", "_openduck_checkpoint", "_openduck_checkpoint"}, {"anchor-installer", "openduck-anchor", "_openduck_anchor", "_openduck_anchor"}, {"installer-checkpoint", "openduck-installer", "root", "wheel"}, {"installer-anchor", "openduck-installer", "root", "wheel"}} {
		var gid uint32
		if contract.user != "root" {
			_, resolved, groupErr := i.ops.PrincipalIDs(ctx, contract.user, contract.group)
			if groupErr != nil {
				return errors.New("journal release ownership unavailable")
			}
			gid = resolved
		}
		for _, path := range []string{"releases/" + contract.release, "releases/" + contract.release + "/" + i.cfg.ReleaseID, "releases/" + contract.release + "/" + i.cfg.ReleaseID + "/manifest.json", "releases/" + contract.release + "/" + i.cfg.ReleaseID + "/" + contract.binary} {
			st, statErr := i.root.Lstat(path)
			if statErr != nil || !ownedBy(st, 0, gid) {
				return fmt.Errorf("journal release ownership mismatch: %s", path)
			}
		}
	}
	_, egressGID, err := i.ops.PrincipalIDs(ctx, "_openduck_egress", "_openduck_egress")
	if err != nil {
		return err
	}
	policyPath := "releases/egress/" + i.cfg.ReleaseID + "/egress-policy.json"
	if st, statErr := i.root.Lstat(policyPath); statErr != nil || !ownedBy(st, 0, egressGID) || st.Mode().Perm() != 0440 {
		return fmt.Errorf("immutable release ownership mismatch: %s", policyPath)
	}
	for _, path := range []string{".openduck-installer", ".openduck-native-mcp", ".openduck-provider-attestor", ".openduck-readiness", ".openduck-service-login", "operator/codex-login.json", "operator/openduck-owner-grant", "operator/owner-ed25519.key", "releases/codex", "releases/codex/" + i.cfg.ReleaseID, "releases/codex/" + i.cfg.ReleaseID + "/manifest.json", "releases/codex/" + i.cfg.ReleaseID + "/codex", "pf/openduck.conf", "pf/egress-policy.json", "seatbelt/state", "seatbelt/codex.sb", "seatbelt/egress.sb", "active.release"} {
		st, err := i.root.Lstat(path)
		if err != nil || !ownedBy(st, 0, 0) {
			return fmt.Errorf("root ownership mismatch: %s", path)
		}
	}
	for _, service := range services {
		path := "launchd/com.openduck." + serviceLabel(service.Name) + ".plist"
		if _, err := i.root.Lstat(path); errors.Is(err, os.ErrNotExist) && pendingPFPlistAllowed(service.Name, allowPendingPFPlists) {
			continue
		}
		st, err := i.root.Lstat(path)
		if err != nil || !ownedBy(st, 0, 0) {
			return fmt.Errorf("root ownership mismatch: %s", path)
		}
	}
	return nil
}

func (i *Installer) verifyInactiveProviderOwnership(ctx context.Context) error {
	entries := i.optionalProviderEntries()
	if len(entries) == 0 {
		return nil
	}
	_, wheelGID, err := i.ops.PrincipalIDs(ctx, "root", "wheel")
	if err != nil {
		return errors.New("provider parent ownership unavailable")
	}
	_, providerGID, err := i.ops.PrincipalIDs(ctx, "_openduck", "_openduck")
	if err != nil {
		return errors.New("provider ownership unavailable")
	}
	parent, parentErr := i.root.Lstat("providers")
	inactive, inactiveErr := i.root.Lstat(releasecatalog.InactiveProviderRoot)
	if parentErr != nil || inactiveErr != nil || !safeCatalogSnapshotDirectory(parent) || !safeCatalogSnapshotDirectory(inactive) || parent.Mode().Perm() != 0711 || inactive.Mode().Perm() != 0750 || !ownedBy(parent, 0, wheelGID) || !ownedBy(inactive, 0, providerGID) {
		return errors.New("provider root ownership mismatch")
	}
	seenDirectories := map[string]bool{}
	for _, artifact := range entries {
		mappings, ok := resolvePlanArtifacts(artifact, i.cfg.ReleaseID)
		if !ok {
			return errors.New("provider ownership resolver unavailable")
		}
		for _, mapping := range mappings {
			if !validInactiveProviderMapping(mapping) {
				return errors.New("provider ownership output invalid")
			}
			directory := filepath.Dir(mapping.target)
			if directory != releasecatalog.InactiveProviderRoot && !seenDirectories[directory] {
				info, statErr := i.root.Lstat(directory)
				if statErr != nil || !safeCatalogSnapshotDirectory(info) || info.Mode().Perm() != 0750 || !ownedBy(info, 0, providerGID) {
					return errors.New("provider subdirectory ownership mismatch")
				}
				seenDirectories[directory] = true
			}
			info, statErr := i.root.Lstat(mapping.target)
			if statErr != nil || !safeExistingRegular(info, inactiveProviderMode(mapping), info.Size()) || !ownedBy(info, 0, providerGID) {
				return errors.New("provider artifact ownership mismatch")
			}
		}
	}
	return nil
}

func pendingPFPlistAllowed(service string, allow bool) bool {
	return allow && (service == "runtime" || service == "broker")
}

func (i *Installer) verifyChannelAndAnchorCheckpointArtifacts() error {
	for _, pair := range canonicalChannelKeyTopologies() {
		if record, err := i.existingChannelRecord(pair.channel, pair.paths); err != nil || record == nil {
			return fmt.Errorf("verify channel key %s", pair.channel)
		}
	}
	anchorCheckpoint := "releases/anchor-checkpoint/" + i.cfg.ReleaseID
	manifestRaw, err := i.root.ReadFile(anchorCheckpoint + "/manifest.json")
	if err != nil {
		return errors.New("verify anchor checkpoint manifest")
	}
	var manifest struct {
		ReleaseID    string `json:"release_id"`
		Binary       string `json:"binary"`
		BinaryDigest string `json:"binary_digest"`
	}
	if json.Unmarshal(manifestRaw, &manifest) != nil || manifest.ReleaseID != i.cfg.ReleaseID || manifest.Binary != "openduck-anchor" || !isDigest(manifest.BinaryDigest) {
		return errors.New("verify anchor checkpoint manifest")
	}
	binary, err := i.root.ReadFile(anchorCheckpoint + "/openduck-anchor")
	if err != nil || Digest(binary) != manifest.BinaryDigest {
		return errors.New("verify anchor checkpoint binary")
	}
	for path, mode := range map[string]os.FileMode{anchorCheckpoint: 0550, anchorCheckpoint + "/manifest.json": 0440, anchorCheckpoint + "/openduck-anchor": 0550} {
		st, statErr := i.root.Lstat(path)
		if statErr != nil || st.Mode().Perm() != mode || st.Mode()&os.ModeSymlink != 0 {
			return errors.New("verify anchor checkpoint metadata")
		}
	}
	return i.verifyJournalTopology()
}

// verifyJournalTopology checks the additional installer-only authority
// surfaces independently of the ordinary checkpoint/anchor channels.  A
// collision here would let one listener or key substitute for the other.
func (i *Installer) verifyJournalTopology() error {
	type releaseContract struct{ release, binary, user, channelGroup string }
	contracts := []releaseContract{
		{"checkpoint-installer", "openduck-checkpoint", "_openduck_checkpoint", "_openduck_installer_checkpoint_channel"},
		{"anchor-installer", "openduck-anchor", "_openduck_anchor", "_openduck_installer_anchor_channel"},
		{"installer-checkpoint", "openduck-installer", "root", "_openduck_installer_checkpoint_channel"},
		{"installer-anchor", "openduck-installer", "root", "_openduck_installer_anchor_channel"},
	}
	type physicalRoot struct {
		name string
		info os.FileInfo
	}
	roots := make([]physicalRoot, 0, len(contracts)*2+6)
	appendRoot := func(path string, mode os.FileMode) error {
		st, err := i.root.Lstat(path)
		if err != nil || !st.IsDir() || st.Mode()&os.ModeSymlink != 0 || st.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
			return errors.New("journal root metadata invalid")
		}
		actual := st.Mode().Perm()
		if actual != mode.Perm() && !(i.fake && strings.HasPrefix(path, "releases/") && mode.Perm() == 0550 && actual == 0750) {
			return errors.New("journal root mode invalid")
		}
		roots = append(roots, physicalRoot{name: path, info: st})
		return nil
	}
	for _, contract := range contracts {
		parent := "releases/" + contract.release
		root := parent + "/" + i.cfg.ReleaseID
		if err := appendRoot(parent, 0550); err != nil {
			return fmt.Errorf("journal release metadata invalid: %s", contract.release)
		}
		if err := appendRoot(root, 0550); err != nil {
			return fmt.Errorf("journal release metadata invalid: %s", contract.release)
		}
		manifestRaw, err := i.root.ReadFile(root + "/manifest.json")
		if err != nil {
			return fmt.Errorf("journal release manifest unavailable: %s", contract.release)
		}
		var manifest struct {
			ReleaseID    string `json:"release_id"`
			Binary       string `json:"binary"`
			Socket       string `json:"socket"`
			BinaryDigest string `json:"binary_digest"`
			SocketDigest string `json:"socket_digest"`
		}
		if json.Unmarshal(manifestRaw, &manifest) != nil || manifest.ReleaseID != i.cfg.ReleaseID || manifest.Binary != contract.binary || manifest.Socket != "journal.sock" || !isDigest(manifest.BinaryDigest) || !isDigest(manifest.SocketDigest) {
			return fmt.Errorf("journal release manifest invalid: %s", contract.release)
		}
		binary, err := i.root.ReadFile(root + "/" + contract.binary)
		if err != nil || Digest(binary) != manifest.BinaryDigest {
			return fmt.Errorf("journal release binary invalid: %s", contract.release)
		}
		manifestInfo, manifestErr := i.root.Lstat(root + "/manifest.json")
		binaryInfo, binaryErr := i.root.Lstat(root + "/" + contract.binary)
		if manifestErr != nil || binaryErr != nil || !safeExistingRegular(manifestInfo, 0440, int64(len(manifestRaw))) || !safeExistingRegular(binaryInfo, 0550, int64(len(binary))) {
			return fmt.Errorf("journal release metadata invalid: %s", contract.release)
		}
		uid, gid := uint32(0), uint32(0)
		if contract.user != "root" {
			resolvedUID, resolvedGID, principalErr := i.ops.PrincipalIDs(context.Background(), contract.user, contract.channelGroup)
			if principalErr != nil {
				return errors.New("journal principal unavailable")
			}
			uid, gid = resolvedUID, resolvedGID
		} else {
			_, resolvedGID, principalErr := i.ops.PrincipalIDs(context.Background(), "_openduck", contract.channelGroup)
			if principalErr != nil {
				return errors.New("journal principal unavailable")
			}
			gid = resolvedGID
		}
		wantSocket, socketErr := macoschannel.SocketMetadataDigestForContract("journal.sock", uid, gid, 0660)
		if socketErr != nil || manifest.SocketDigest != wantSocket {
			return fmt.Errorf("journal socket pin invalid: %s", contract.release)
		}
	}
	for _, channel := range []struct{ path, user, group string }{{"channels/installer-checkpoint", "_openduck_checkpoint", "_openduck_installer_checkpoint_channel"}, {"channels/installer-anchor", "_openduck_anchor", "_openduck_installer_anchor_channel"}} {
		if err := appendRoot(channel.path, 0750); err != nil {
			return errors.New("journal socket root metadata invalid")
		}
		if !i.fake {
			uid, gid, principalErr := i.ops.PrincipalIDs(context.Background(), channel.user, channel.group)
			st := roots[len(roots)-1].info
			if principalErr != nil || !ownedBy(st, uid, gid) {
				return errors.New("journal socket root ownership invalid")
			}
		}
	}
	keyRecords := make([][]byte, 0, 2)
	for _, key := range []struct {
		root, file, user, group string
	}{{"keys/checkpoint-installer", "keys/checkpoint-installer/journal.key", "_openduck_checkpoint", "_openduck_checkpoint"}, {"keys/installer-checkpoint", "keys/installer-checkpoint/journal.key", "root", "wheel"}, {"keys/anchor-installer", "keys/anchor-installer/journal.key", "_openduck_anchor", "_openduck_anchor"}, {"keys/installer-anchor", "keys/installer-anchor/journal.key", "root", "wheel"}} {
		if err := appendRoot(key.root, 0700); err != nil {
			return errors.New("journal key root metadata invalid")
		}
		st, statErr := i.root.Lstat(key.file)
		if statErr != nil || !safeExistingRegular(st, 0600, 116) {
			return errors.New("journal key metadata invalid")
		}
		if !i.fake {
			uid, gid, principalErr := i.ops.PrincipalIDs(context.Background(), key.user, key.group)
			if principalErr != nil || !ownedBy(roots[len(roots)-1].info, uid, gid) || !ownedBy(st, uid, gid) {
				return errors.New("journal key ownership invalid")
			}
		}
	}
	for _, paths := range [][]string{{"keys/checkpoint-installer/journal.key", "keys/installer-checkpoint/journal.key"}, {"keys/anchor-installer/journal.key", "keys/installer-anchor/journal.key"}} {
		record, err := i.existingChannelRecord("installer-journal", paths)
		if err != nil || record == nil {
			return errors.New("journal key record invalid")
		}
		keyRecords = append(keyRecords, record)
	}
	if bytes.Equal(keyRecords[0], keyRecords[1]) {
		for _, record := range keyRecords {
			for n := range record {
				record[n] = 0
			}
		}
		return errors.New("journal channel key reused")
	}
	for _, record := range keyRecords {
		for n := range record {
			record[n] = 0
		}
	}
	for left := range roots {
		for right := left + 1; right < len(roots); right++ {
			if sameFileIdentity(roots[left].info, roots[right].info) {
				return errors.New("journal roots overlap")
			}
		}
	}
	return nil
}

func (i *Installer) verifyCodexRelease() error {
	root := "releases/codex/" + i.cfg.ReleaseID
	raw, err := i.root.ReadFile(root + "/manifest.json")
	if err != nil {
		return errors.New("verify Codex release manifest")
	}
	var manifest struct {
		ReleaseID    string `json:"release_id"`
		Binary       string `json:"binary"`
		Socket       string `json:"socket"`
		BinaryDigest string `json:"binary_digest"`
		SocketDigest string `json:"socket_digest"`
	}
	if json.Unmarshal(raw, &manifest) != nil || manifest.ReleaseID != i.cfg.ReleaseID || manifest.Binary != "codex" || manifest.Socket != "runtime.sock" || !isDigest(manifest.BinaryDigest) || !isDigest(manifest.SocketDigest) {
		return errors.New("verify Codex release manifest")
	}
	binary, err := i.root.ReadFile(root + "/codex")
	if err != nil || Digest(binary) != manifest.BinaryDigest {
		return errors.New("verify Codex release binary")
	}
	for path, mode := range map[string]os.FileMode{root: 0755, root + "/manifest.json": 0644, root + "/codex": 0755} {
		st, statErr := i.root.Lstat(path)
		if statErr != nil || st.Mode()&os.ModeSymlink != 0 || st.Mode().Perm() != mode {
			return errors.New("verify Codex release metadata")
		}
		if st.Mode().IsRegular() && !safeExistingRegular(st, mode, st.Size()) {
			return errors.New("verify Codex release metadata")
		}
	}
	return nil
}

func (i *Installer) Stop() (err error) {
	if i == nil || i.root == nil {
		return errors.New("installer unavailable")
	}
	if auditErr := i.audit("stop", "started", "started", "", "", true); auditErr != nil {
		return fmt.Errorf("audit start: %w", auditErr)
	}
	defer func() {
		outcome, reason := "succeeded", ""
		if err != nil {
			outcome, reason = "failed", "stop_failed"
		}
		if auditErr := i.audit("stop", "finished", outcome, reason, "", true); auditErr != nil {
			if err == nil {
				err = fmt.Errorf("audit finish: %w", auditErr)
			} else {
				err = errors.Join(err, fmt.Errorf("audit finish: %w", auditErr))
			}
		}
	}()
	var stopErr error
	for n := len(services) - 1; n >= 0; n-- {
		label := serviceLabel(services[n].Name)
		if err := i.ops.Bootout(context.Background(), "com.openduck."+label); err != nil {
			stopErr = errors.Join(stopErr, err)
		}
		if err := i.ops.DisableJob(context.Background(), "com.openduck."+label); err != nil {
			stopErr = errors.Join(stopErr, err)
		}
	}
	if pfErr := i.ops.PFUnload(context.Background()); pfErr != nil {
		stopErr = errors.Join(stopErr, pfErr)
	} else {
		stopErr = errors.Join(stopErr, i.releasePersistedPFLease(context.Background()))
	}
	if stopErr != nil {
		return stopErr
	}
	return i.writeText("lifecycle.stopped", "reverse-order\n", 0600)
}

type installedFileSnapshot struct {
	data   []byte
	exists bool
	mode   os.FileMode
}

func (i *Installer) snapshotRootFile(path string) (installedFileSnapshot, error) {
	b, err := i.root.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return installedFileSnapshot{}, nil
	}
	if err != nil {
		return installedFileSnapshot{}, err
	}
	st, err := i.root.Lstat(path)
	if err != nil || !st.Mode().IsRegular() || st.Mode()&os.ModeSymlink != 0 {
		return installedFileSnapshot{}, fmt.Errorf("unsafe transaction file: %s", path)
	}
	return installedFileSnapshot{data: append([]byte(nil), b...), exists: true, mode: st.Mode().Perm()}, nil
}

func validPFLeaseToken(raw []byte) (string, bool) {
	token := strings.TrimSpace(string(raw))
	return token, token != "" && strings.Trim(token, "0123456789") == "" && bytes.Equal(raw, []byte(token+"\n"))
}

func (i *Installer) snapshotPFToken() (installedFileSnapshot, error) {
	old, err := i.snapshotRootFile("pf/enable.token")
	if err != nil || !old.exists {
		return old, err
	}
	st, statErr := i.root.Lstat("pf/enable.token")
	expectedUID, expectedGID := uint32(0), uint32(0)
	if i.fake {
		expectedUID, expectedGID = uint32(i.cfg.UID), uint32(i.cfg.GID)
	}
	if _, ok := validPFLeaseToken(old.data); statErr != nil || !ok || !safeExistingRegular(st, 0600, int64(len(old.data))) || !ownedBy(st, expectedUID, expectedGID) {
		return installedFileSnapshot{}, errors.New("invalid PF lease token")
	}
	return old, nil
}

func (i *Installer) replaceRootFile(path string, data []byte, mode os.FileMode) error {
	tmp := filepath.Join(filepath.Dir(path), "."+filepath.Base(path)+".transaction")
	_ = i.root.Remove(tmp)
	f, err := i.root.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	if err = f.Chmod(mode); err == nil {
		_, err = f.Write(data)
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		_ = i.root.Remove(tmp)
		return err
	}
	return i.root.Rename(tmp, path)
}

func (i *Installer) restoreRootFile(path string, old installedFileSnapshot) error {
	if old.exists {
		return i.replaceRootFile(path, old.data, old.mode)
	}
	err := i.root.Remove(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

func (i *Installer) restoreRootFiles(files map[string]installedFileSnapshot) error {
	var result error
	paths := make([]string, 0, len(files))
	for path := range files {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	for _, path := range paths {
		result = errors.Join(result, i.restoreRootFile(path, files[path]))
	}
	return result
}

func restoreExternalPlists(ctx context.Context, ops SystemOps, files map[string]installedFileSnapshot) error {
	var result error
	for name, old := range files {
		if old.exists {
			result = errors.Join(result, ops.InstallPlist(ctx, name, old.data))
		} else {
			result = errors.Join(result, ops.RemovePlist(ctx, name))
		}
	}
	return result
}

func (i *Installer) retainPFLease(lease string) error {
	if lease == "" {
		return nil
	}
	if strings.Trim(lease, "0123456789") != "" {
		return errors.New("invalid PF lease token")
	}
	return i.replaceRootFile("pf/enable.token", []byte(lease+"\n"), 0600)
}

// compensatePFTransaction restores files first, restores the OpenDuck anchor
// while the newly acquired PF lease still protects the host, releases that
// lease last, and only then restores the previous token marker.
func (i *Installer) compensatePFTransaction(ctx context.Context, internal, external map[string]installedFileSnapshot, priorRules []byte, priorEnabled bool, lease string, priorToken installedFileSnapshot) error {
	if restoreErr := errors.Join(i.restoreRootFiles(internal), restoreExternalPlists(ctx, i.ops, external)); restoreErr != nil {
		return errors.Join(fmt.Errorf("pf restore: file restore failed: %w", restoreErr), i.retainPFLease(lease))
	}
	if restoreErr := i.ops.PFRestore(ctx, priorRules, priorEnabled); restoreErr != nil {
		return errors.Join(fmt.Errorf("pf restore: %w", restoreErr), i.retainPFLease(lease))
	}
	if releaseErr := i.ops.PFReleaseLease(ctx, lease); releaseErr != nil {
		return errors.Join(fmt.Errorf("pf restore: release lease: %w", releaseErr), i.retainPFLease(lease))
	}
	if tokenErr := i.restoreRootFile("pf/enable.token", priorToken); tokenErr != nil {
		return fmt.Errorf("pf restore: token restore failed: %w", tokenErr)
	}
	i.pfLease = ""
	return nil
}

// FinalizePFEvidence is the activation-gated second phase. Apply never
// invents live PF status/rules evidence; this phase derives it directly from
// the fixed SystemOps PF commands, then atomically installs the final disabled
// broker and runtime plists.
func (i *Installer) FinalizePFEvidence(ctx context.Context) (err error) {
	// A persisted token belongs to a prior completed transaction.  pfLease is
	// only the lease acquired by this invocation and therefore eligible for
	// compensation release.
	i.pfLease = ""
	if err = i.requireJobsUnloaded(ctx); err != nil {
		return err
	}
	if err = i.requireJobsDisabled(ctx); err != nil {
		return err
	}
	if err = i.validateExistingActiveSelection(); err != nil {
		return err
	}
	if auditErr := i.audit("finalize", "started", "started", "", "", true); auditErr != nil {
		return fmt.Errorf("audit start: %w", auditErr)
	}
	defer func() {
		var finishErr error
		if err != nil {
			finishErr = i.audit("finalize", "finished", "failed", safeReasonCode(err), "installer", true)
		} else {
			finishErr = i.audit("finalize", "finished", "succeeded", "", "", true)
		}
		if finishErr != nil {
			if err == nil {
				err = fmt.Errorf("audit finish: %w", finishErr)
			} else {
				err = errors.Join(err, fmt.Errorf("audit finish: %w", finishErr))
			}
		}
	}()
	// PF evidence is part of pre-activation verification. It is gated by the
	// durable configured candidate, not active.release, which is intentionally
	// unpublished until Activate's final commit.
	if err = i.configuredCandidate(); err != nil {
		return fmt.Errorf("configured candidate unavailable: %w", err)
	}
	// Resolve and reject every plist before the first live PF mutation.
	rendered := make(map[string]string, len(services))
	for _, s := range services {
		if s.Name == "runtime" || s.Name == "broker" {
			continue
		}
		p := i.renderResolvedPlist(ctx, s)
		if p == "" || strings.Contains(p, "_DIGEST") || strings.Contains(p, "_UID") || strings.Contains(p, "_GID") || strings.Contains(p, "<string></string>") {
			return fmt.Errorf("unresolved %s plist", s.Name)
		}
		rendered[serviceLabel(s.Name)] = p
	}
	if err = i.Verify(); err != nil {
		return fmt.Errorf("pre-finalize verify: %w", err)
	}
	internal := map[string]installedFileSnapshot{}
	for _, path := range []string{"seatbelt/pf-evidence.json"} {
		old, snapErr := i.snapshotRootFile(path)
		if snapErr != nil {
			return snapErr
		}
		internal[path] = old
	}
	for _, s := range services {
		path := "launchd/com.openduck." + serviceLabel(s.Name) + ".plist"
		old, snapErr := i.snapshotRootFile(path)
		if snapErr != nil {
			return snapErr
		}
		internal[path] = old
	}
	external := map[string]installedFileSnapshot{}
	for _, s := range services {
		name := "com.openduck." + serviceLabel(s.Name) + ".plist"
		b, exists, e := i.ops.ReadPlist(ctx, name)
		if e != nil {
			return e
		}
		external[name] = installedFileSnapshot{data: append([]byte(nil), b...), exists: exists}
	}
	priorToken, tokenErr := i.snapshotPFToken()
	if tokenErr != nil {
		return tokenErr
	}
	priorStatus, statusErr := i.ops.PFStatus(ctx)
	priorRules, rulesErr := i.ops.PFRules(ctx)
	if statusErr != nil || rulesErr != nil {
		return errors.New("prior PF state unavailable")
	}
	priorPFEnabled := strings.Contains(string(priorStatus), "Status: Enabled")
	pfMutated := false
	defer func() {
		if err == nil || !pfMutated {
			return
		}
		if compensation := i.compensatePFTransaction(context.Background(), internal, external, priorRules, priorPFEnabled, i.pfLease, priorToken); compensation != nil {
			err = &ProvisioningTransactionError{Primary: err, Compensation: fmt.Errorf("finalize compensation failed: %w", compensation)}
		}
	}()
	// PF mutation is isolated behind fixed SystemOps commands. Apply never
	// reaches this path; tests inject fake ops and therefore cannot touch pfctl.
	pfMutated = true // journal before the call: pfctl may mutate and still fail
	if err := i.ops.PFLoad(ctx); err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "syntax") {
			return fmt.Errorf("pf rules invalid: %w", err)
		}
		return fmt.Errorf("pf load: %w", err)
	}
	if !priorPFEnabled {
		lease, leaseErr := i.ops.PFEnableLease(ctx)
		if leaseErr != nil {
			return fmt.Errorf("pf load: %w", leaseErr)
		}
		i.pfLease = lease
		if err := i.retainPFLease(lease); err != nil {
			return err
		}
	}
	status, err := i.ops.PFStatus(ctx)
	if err != nil {
		return err
	}
	rules, err := i.ops.PFRules(ctx)
	if err != nil {
		return err
	}
	if !strings.Contains(string(status), "Status: Enabled") || len(bytes.TrimSpace(rules)) == 0 {
		return errors.New("live PF evidence unavailable")
	}
	rulesDigest := Digest(rules)
	// Finalization is the only phase allowed to materialize live PF evidence.
	// Keep the record small, canonical, and in the sandbox root named by the
	// runtime plist; Apply deliberately never creates this file.
	policyRaw, err := i.root.ReadFile("seatbelt/state")
	if err != nil {
		return err
	}
	bootID, err := i.ops.BootID(ctx)
	if err != nil {
		return err
	}
	seatbeltInfo, err := i.root.Lstat("seatbelt")
	if err != nil {
		return err
	}
	evidenceRecord := codexruntime.PFEvidence{SchemaVersion: codexruntime.PFEvidenceV1, BootID: bootID, Anchor: "com.openduck", Enabled: true, PolicyDigest: Digest(policyRaw), RulesDigest: rulesDigest, RootUID: 0, RootGID: 0, RootMode: 0755, RootDigest: pfRootMetadataDigest(seatbeltInfo)}
	evidence, err := evidenceRecord.Canonical()
	if err != nil {
		return err
	}
	if err := i.replaceRootFile("seatbelt/pf-evidence.json", evidence, 0644); err != nil {
		return err
	}
	for _, late := range []Service{{Name: "broker", User: "_openduck_broker", Group: "_openduck_broker"}, {Name: "runtime", User: "_openduck_codex", Group: "_openduck_codex"}} {
		p := i.renderResolvedPlist(ctx, late)
		if p == "" || strings.Contains(p, "_DIGEST") || strings.Contains(p, "_UID") || strings.Contains(p, "_GID") || strings.Contains(p, "<string></string>") {
			return fmt.Errorf("unresolved %s plist", late.Name)
		}
		rendered[serviceLabel(late.Name)] = p
	}
	for _, s := range services {
		label := serviceLabel(s.Name)
		plist := rendered[label]
		if err = i.replaceRootFile("launchd/com.openduck."+label+".plist", []byte(plist), 0644); err != nil {
			return err
		}
	}
	for _, s := range services {
		label := serviceLabel(s.Name)
		if err = i.ops.InstallPlist(ctx, "com.openduck."+label+".plist", []byte(rendered[label])); err != nil {
			return err
		}
	}
	for _, s := range services {
		label := serviceLabel(s.Name)
		name := "com.openduck." + label + ".plist"
		installed, exists, readErr := i.ops.ReadPlist(ctx, name)
		if readErr != nil || !exists || !bytes.Equal(installed, []byte(rendered[label])) {
			return fmt.Errorf("external plist verification failed: %s", label)
		}
	}
	if err = i.verifyProductionOwnership(ctx, false); err != nil {
		return err
	}
	if err = i.requireJobsUnloaded(ctx); err != nil {
		return err
	}
	if err = i.requireJobsDisabled(ctx); err != nil {
		return err
	}
	return nil
}

func (i *Installer) requireJobsUnloaded(ctx context.Context) error {
	if i == nil || i.ops == nil {
		return errors.New("STOP_REQUIRED: launchd job state unavailable")
	}
	for _, service := range services {
		label := "com.openduck." + serviceLabel(service.Name)
		loaded, err := i.ops.JobLoaded(ctx, label)
		if err != nil {
			return fmt.Errorf("STOP_REQUIRED: cannot prove %s is unloaded: %w", label, err)
		}
		if loaded {
			disabled, disabledErr := i.ops.JobDisabled(ctx, label)
			if disabledErr != nil {
				return fmt.Errorf("STOP_REQUIRED: cannot prove coherent state for %s: %w", label, disabledErr)
			}
			if disabled {
				return fmt.Errorf("STOP_REQUIRED: contradictory launchd state for %s: loaded and disabled", label)
			}
			return fmt.Errorf("STOP_REQUIRED: %s is loaded; run stop before upgrade", label)
		}
	}
	return nil
}

func (i *Installer) requireJobsDisabled(ctx context.Context) error {
	for _, service := range services {
		label := "com.openduck." + serviceLabel(service.Name)
		disabled, err := i.ops.JobDisabled(ctx, label)
		if err != nil {
			return fmt.Errorf("STOP_REQUIRED: cannot prove %s is disabled: %w", label, err)
		}
		if !disabled {
			return fmt.Errorf("STOP_REQUIRED: %s is enabled; run stop before activation", label)
		}
	}
	return nil
}

func pfRootMetadataDigest(info os.FileInfo) string {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st == nil {
		return ""
	}
	return Digest([]byte(fmt.Sprintf("pf-root-v1|%d|%d|%d|%d|%o", st.Dev, st.Ino, st.Uid, st.Gid, info.Mode().Perm())))
}

// Activate performs PF finalization and dependency-ordered launchd activation
// in one privileged process, eliminating the former human-sized freshness gap.
func (i *Installer) Activate(ctx context.Context) (err error) {
	recovery, recoveryErr := i.activationPointerRecoveryNeeded()
	if recoveryErr != nil {
		return recoveryErr
	}
	if !recovery {
		// Refuse a non-recovery activation before it writes audit/journal
		// evidence: a loaded older job is an explicit stop-required boundary,
		// not a transaction that may leave new durable state behind.
		if err = i.requireJobsUnloaded(ctx); err != nil {
			return err
		}
	}
	if auditErr := i.audit("activate", "started", "started", "", "", true); auditErr != nil {
		return fmt.Errorf("audit start: %w", auditErr)
	}
	defer func() {
		if err != nil {
			// A bounded durable failure selector is retained independently of audit
			// records, whose safe primary/compensation codes remain authoritative.
			_ = i.writeReleaseState("failed.release", i.cfg.ReleaseID)
		}
		var finishErr error
		if err != nil {
			finishErr = i.audit("activate", "finished", "failed", safeReasonCode(err), "installer", true)
		} else {
			finishErr = i.audit("activate", "finished", "succeeded", "", "", true)
		}
		if finishErr != nil {
			if err == nil {
				err = fmt.Errorf("audit finish: %w", finishErr)
			} else {
				err = errors.Join(err, fmt.Errorf("audit finish: %w", finishErr))
			}
		}
		// A failed recovery before the authorities could become live has no safe
		// journal capability yet. Do not create an unauthenticated replacement
		// journal for an existing protected run merely to record that failure.
		if i.journal == nil && !i.journalBinding.valid() && !(i.fake && i.journalAuthority != nil && i.journalAuthority.valid()) {
			return
		}
		checkpointEvent := "commit"
		if err != nil {
			checkpointEvent = "compensate"
		}
		if checkpointErr := i.journalTransition("activate", checkpointEvent); checkpointErr != nil {
			if err == nil {
				err = checkpointErr
			} else {
				err = &ProvisioningTransactionError{Primary: err, Compensation: checkpointErr}
			}
		}
	}()
	if recovery {
		return i.recoverActivationPointer(ctx)
	}
	if err := i.journalTransition("activate", "preflight"); err != nil {
		return err
	}
	if err = i.configuredCandidate(); err != nil {
		return err
	}
	if err = i.journalTransition("activate", "activate"); err != nil {
		return err
	}
	// Intent is durable before the first PF/launchd effect. A subsequent
	// process can distinguish an unconfigured candidate from an interrupted
	// activation and will only publish active.release after marker validation.
	if err = i.writeReleaseState("activation.intent", i.cfg.ReleaseID); err != nil {
		return err
	}
	if err = i.requireJobsUnloaded(ctx); err != nil {
		return err
	}
	if err = i.requireJobsDisabled(ctx); err != nil {
		return err
	}
	internal := map[string]installedFileSnapshot{}
	paths := []string{"seatbelt/pf-evidence.json", "pf/egress-policy.json", "pending.rollback", "previous.release"}
	for _, s := range services {
		paths = append(paths, "launchd/com.openduck."+serviceLabel(s.Name)+".plist")
	}
	for _, path := range paths {
		old, snapErr := i.snapshotRootFile(path)
		if snapErr != nil {
			return snapErr
		}
		internal[path] = old
	}
	priorToken, priorTokenErr := i.snapshotPFToken()
	if priorTokenErr != nil {
		return priorTokenErr
	}
	external := map[string]installedFileSnapshot{}
	for _, s := range services {
		name := "com.openduck." + serviceLabel(s.Name) + ".plist"
		b, exists, e := i.ops.ReadPlist(ctx, name)
		if e != nil {
			return e
		}
		external[name] = installedFileSnapshot{data: append([]byte(nil), b...), exists: exists}
	}
	priorStatus, statusErr := i.ops.PFStatus(ctx)
	priorRules, rulesErr := i.ops.PFRules(ctx)
	if statusErr != nil || rulesErr != nil {
		return errors.New("prior PF state unavailable")
	}
	priorPFEnabled := strings.Contains(string(priorStatus), "Status: Enabled")
	finalized := false
	shutdownFailed := false
	defer func() {
		if err == nil || !finalized || shutdownFailed {
			return
		}
		if compensation := i.compensatePFTransaction(context.Background(), internal, external, priorRules, priorPFEnabled, i.pfLease, priorToken); compensation != nil {
			err = &ProvisioningTransactionError{Primary: err, Compensation: fmt.Errorf("activation compensation failed: %w", compensation)}
		}
	}()
	if err = i.FinalizePFEvidence(ctx); err != nil {
		return err
	}
	finalized = true
	if err = i.requireJobsUnloaded(ctx); err != nil {
		return err
	}
	if err = i.requireJobsDisabled(ctx); err != nil {
		return err
	}
	order := []string{"checkpoint", "anchor", "egress", "codex-runtime", "codex-broker", "controller"}
	type launchdJournalEntry struct {
		label              string
		enableAttempted    bool
		bootstrapAttempted bool
	}
	journal := make([]launchdJournalEntry, 0, len(order))
	defer func() {
		if err == nil {
			return
		}
		var shutdownErr error
		for n := len(journal) - 1; n >= 0; n-- {
			entry := journal[n]
			full := "com.openduck." + entry.label
			if entry.bootstrapAttempted {
				shutdownErr = errors.Join(shutdownErr, i.ops.Bootout(context.Background(), full))
			}
			if entry.enableAttempted {
				shutdownErr = errors.Join(shutdownErr, i.ops.DisableJob(context.Background(), full))
			}
		}
		for _, entry := range journal {
			full := "com.openduck." + entry.label
			loaded, loadedErr := i.ops.JobLoaded(context.Background(), full)
			if loadedErr != nil {
				shutdownErr = errors.Join(shutdownErr, fmt.Errorf("cannot prove %s unloaded: %w", full, loadedErr))
			} else if loaded {
				shutdownErr = errors.Join(shutdownErr, fmt.Errorf("cannot prove %s unloaded", full))
			}
			disabled, disabledErr := i.ops.JobDisabled(context.Background(), full)
			if disabledErr != nil {
				shutdownErr = errors.Join(shutdownErr, fmt.Errorf("cannot prove %s disabled: %w", full, disabledErr))
			} else if !disabled {
				shutdownErr = errors.Join(shutdownErr, fmt.Errorf("cannot prove %s disabled", full))
			}
		}
		if shutdownErr != nil {
			shutdownFailed = true
			err = &ProvisioningTransactionError{Primary: err, Compensation: fmt.Errorf("launchd shutdown failed: %w", shutdownErr)}
		}
	}()
	for _, label := range order {
		name := "com.openduck." + label + ".plist"
		full := "com.openduck." + label
		journal = append(journal, launchdJournalEntry{label: label, enableAttempted: true})
		if err = i.ops.EnableJob(ctx, full); err != nil {
			return fmt.Errorf("enable %s: %w", label, err)
		}
		journal[len(journal)-1].bootstrapAttempted = true
		if err = i.ops.BootstrapPlist(ctx, name); err != nil {
			return fmt.Errorf("bootstrap %s: %w", label, err)
		}
		if err = i.ops.KickstartJob(ctx, full); err != nil {
			return fmt.Errorf("kickstart %s: %w", label, err)
		}
		if err = i.ops.VerifyJob(ctx, full); err != nil {
			return fmt.Errorf("activate %s: %w", label, err)
		}
	}
	// The first protected checkpoint is deliberately delayed until both
	// checkpoint and anchor jobs have started. It transitively seals every
	// fsynced local entry from fresh configure before any activation marker or
	// operational pointer can be published.
	if !i.fake {
		if err = i.bindInstalledProductionJournal(ctx); err != nil {
			return err
		}
	}
	if err = i.promoteJournal(); err != nil {
		return err
	}
	if pending, e := i.root.ReadFile("pending.rollback"); e == nil {
		id := strings.TrimSpace(string(pending))
		if i.validateRollbackRelease(id) == nil {
			if err = i.replaceRootFile("previous.release", []byte(id+"\n"), 0644); err != nil {
				return err
			}
			if err = i.root.Remove("pending.rollback"); err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
		}
	}
	if i.pfLease != "" {
		if err = i.retainPFLease(i.pfLease); err != nil {
			return err
		}
	}
	// This marker is the final transactional write.  Apply and Rollback trust
	// nothing without it, so every earlier failure remains merely a candidate.
	if err = i.writeActivatedMarker(i.cfg.ReleaseID); err != nil {
		return err
	}
	if err = i.journalTransition("activate", "verify"); err != nil {
		return err
	}
	if err = i.writeReleaseState("activated.release", i.cfg.ReleaseID); err != nil {
		return err
	}
	// active.release is the final operational commit pointer. Everything before
	// this point is recoverable candidate/activation evidence only.
	if err = i.writeReleaseState("active.release", i.cfg.ReleaseID); err != nil {
		return err
	}
	if removeErr := i.root.Remove("activation.intent"); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
		return removeErr
	}
	i.pfLease = ""
	return nil
}

// activationPointerRecoveryNeeded identifies only the durable final-pointer
// tail of a previously started activation. It deliberately performs no
// journal, launchd, PF, or pointer mutation: protected recovery below is the
// only code allowed to publish the operational selection.
func (i *Installer) activationPointerRecoveryNeeded() (bool, error) {
	if i == nil || i.root == nil {
		return false, errors.New("installer unavailable")
	}
	active, activeErr := i.readReleaseState("active.release")
	if activeErr == nil {
		// An existing active selection is not a recoverable final-pointer tail:
		// callers may have explicitly stopped the service set and need a full
		// activation, not just the two journal authorities. Validate the marker
		// before any new side effect so an orphaned active selector is never
		// treated as acceptable operational state.
		if active == i.cfg.ReleaseID {
			if err := i.validateRollbackRelease(i.cfg.ReleaseID); err != nil {
				return false, err
			}
		}
		return false, nil
	}
	if !errors.Is(activeErr, os.ErrNotExist) {
		return false, activeErr
	}
	activated, activatedErr := i.readReleaseState("activated.release")
	if activatedErr == nil {
		return activated == i.cfg.ReleaseID, nil
	}
	if !errors.Is(activatedErr, os.ErrNotExist) {
		return false, activatedErr
	}
	marker, markerErr := i.root.Lstat("releases/controller/" + i.cfg.ReleaseID + "/activated")
	if markerErr == nil {
		if marker.Mode()&os.ModeSymlink != 0 {
			return false, errors.New("activation marker invalid")
		}
		return true, nil
	}
	if !errors.Is(markerErr, os.ErrNotExist) {
		return false, markerErr
	}
	return false, nil
}

type journalAuthorityActivation struct {
	label              string
	enableAttempted    bool
	bootstrapAttempted bool
}

// startJournalAuthorities establishes only the checkpoint and anchor services
// needed for protected recovery. It does not touch PF, the other services, or
// any release pointer. Existing live authorities are merely health-checked;
// only effects made by this call are compensated on failure.
func (i *Installer) startJournalAuthorities(ctx context.Context) (func() error, error) {
	if i == nil || i.ops == nil {
		return nil, errors.New("protected journal authority unavailable")
	}
	entries := make([]journalAuthorityActivation, 0, 2)
	cleanup := func() error {
		var result error
		for n := len(entries) - 1; n >= 0; n-- {
			entry := entries[n]
			full := "com.openduck." + entry.label
			if entry.bootstrapAttempted {
				result = errors.Join(result, i.ops.Bootout(context.Background(), full))
			}
			if entry.enableAttempted {
				result = errors.Join(result, i.ops.DisableJob(context.Background(), full))
			}
		}
		return result
	}
	for _, label := range []string{"checkpoint", "anchor"} {
		full := "com.openduck." + label
		loaded, err := i.ops.JobLoaded(ctx, full)
		if err != nil {
			return cleanup, fmt.Errorf("journal authority state unavailable: %w", err)
		}
		if loaded {
			if err := i.ops.VerifyJob(ctx, full); err != nil {
				return cleanup, fmt.Errorf("journal authority unavailable: %w", err)
			}
			continue
		}
		disabled, err := i.ops.JobDisabled(ctx, full)
		if err != nil {
			return cleanup, fmt.Errorf("journal authority state unavailable: %w", err)
		}
		entry := journalAuthorityActivation{label: label}
		entries = append(entries, entry)
		if disabled {
			entries[len(entries)-1].enableAttempted = true
			if err := i.ops.EnableJob(ctx, full); err != nil {
				return cleanup, fmt.Errorf("enable journal authority: %w", err)
			}
		}
		entries[len(entries)-1].bootstrapAttempted = true
		if err := i.ops.BootstrapPlist(ctx, full+".plist"); err != nil {
			return cleanup, fmt.Errorf("bootstrap journal authority: %w", err)
		}
		if err := i.ops.KickstartJob(ctx, full); err != nil {
			return cleanup, fmt.Errorf("kickstart journal authority: %w", err)
		}
		if err := i.ops.VerifyJob(ctx, full); err != nil {
			return cleanup, fmt.Errorf("journal authority unavailable: %w", err)
		}
	}
	return cleanup, nil
}

// recoverActivationPointer starts/revalidates only the two authorities, binds
// the sealed typed clients from the fixed installed topology, and promotes the
// exact durable journal before it writes either recovery selector. A missing
// authority therefore cannot make an active selection appear successful.
func (i *Installer) recoverActivationPointer(ctx context.Context) (err error) {
	cleanup, err := i.startJournalAuthorities(ctx)
	if err != nil {
		return err
	}
	keepAuthorities := false
	defer func() {
		if err == nil || keepAuthorities {
			return
		}
		if cleanupErr := cleanup(); cleanupErr != nil {
			err = &ProvisioningTransactionError{Primary: err, Compensation: fmt.Errorf("journal authority recovery shutdown failed: %w", cleanupErr)}
		}
	}()
	if !i.fake {
		if err = i.bindInstalledProductionJournal(ctx); err != nil {
			return err
		}
	}
	// This is intentionally after binding. A reused run may already have a
	// durable protected checkpoint, which OpenProvisioningJournal rejects when
	// opened with a local bootstrap-only authority.
	if err = i.journalTransition("activate", "recover"); err != nil {
		return err
	}
	if err = i.promoteJournal(); err != nil {
		return err
	}
	recovered, recoverErr := i.recoverActivatedPointer()
	if recoverErr != nil {
		return recoverErr
	}
	if !recovered {
		return errors.New("activation recovery unavailable")
	}
	keepAuthorities = true
	return nil
}

// recoverActivatedPointer completes only the marker->pointer tail of an
// interrupted activation. It does not start jobs or guess health; a marker is
// accepted only through the same immutable rollback closure used by Rollback.
func (i *Installer) recoverActivatedPointer() (bool, error) {
	active, activeErr := i.readReleaseState("active.release")
	if activeErr == nil && active == i.cfg.ReleaseID {
		// Idempotent success is still an operational assertion: do not accept an
		// already-selected pointer unless both its immutable activation closure
		// and current protected journal can be proved. An active pointer without
		// the immutable marker can never have been published by this state
		// machine, so treating it as success would bypass protection.
		if err := i.validateRollbackRelease(i.cfg.ReleaseID); err != nil {
			return false, err
		}
		if err := i.requireProtectedJournal(); err != nil {
			return false, err
		}
		return true, nil
	}
	if activeErr != nil && !errors.Is(activeErr, os.ErrNotExist) {
		return false, activeErr
	}
	if err := i.validateRollbackRelease(i.cfg.ReleaseID); err != nil {
		return false, nil
	}
	if err := i.requireProtectedJournal(); err != nil {
		return false, err
	}
	if err := i.writeReleaseState("activated.release", i.cfg.ReleaseID); err != nil {
		return false, err
	}
	if err := i.writeReleaseState("active.release", i.cfg.ReleaseID); err != nil {
		return false, err
	}
	if err := i.root.Remove("activation.intent"); err != nil && !errors.Is(err, os.ErrNotExist) {
		return false, err
	}
	return true, nil
}

func (i *Installer) releasePersistedPFLease(ctx context.Context) error {
	raw, err := i.root.ReadFile("pf/enable.token")
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	token, valid := validPFLeaseToken(raw)
	if !valid {
		return errors.New("invalid PF lease token")
	}
	st, statErr := i.root.Lstat("pf/enable.token")
	expectedUID, expectedGID := uint32(0), uint32(0)
	if i.fake {
		expectedUID, expectedGID = uint32(i.cfg.UID), uint32(i.cfg.GID)
	}
	if statErr != nil || !safeExistingRegular(st, 0600, int64(len(raw))) || !ownedBy(st, expectedUID, expectedGID) {
		return errors.New("invalid PF lease token")
	}
	if err := i.ops.PFReleaseLease(ctx, token); err != nil {
		return fmt.Errorf("pf restore: %w", err)
	}
	return i.root.Remove("pf/enable.token")
}
func (i *Installer) Rollback() (err error) {
	if i == nil || i.root == nil {
		return errors.New("installer unavailable")
	}
	if i.admitted != nil && (i.admittedOperation != "rollback" || i.admittedActivation) {
		return errors.New("sealed rollback intent mismatch")
	}
	// Rollback starts a new run while the checkpoint and anchor authorities
	// are already operational. Seal that run before its first rollback mutation
	// instead of requiring a checkpoint that cannot yet exist.
	if !i.fake {
		if err := i.bindInstalledProductionJournal(context.Background()); err != nil {
			return err
		}
	}
	if err := i.promoteJournal(); err != nil {
		return err
	}
	if err := i.requireProtectedJournal(); err != nil {
		return err
	}
	if err := i.journalTransition("rollback", "preflight"); err != nil {
		return err
	}
	i.created = nil
	if auditErr := i.audit("rollback", "started", "started", "", "", true); auditErr != nil {
		return fmt.Errorf("audit start: %w", auditErr)
	}
	defer func() {
		outcome, reason := "succeeded", ""
		if err != nil {
			outcome, reason = "failed", safeReasonCode(err)
		}
		if auditErr := i.audit("rollback", "finished", outcome, reason, "", true); auditErr != nil {
			if err == nil {
				err = fmt.Errorf("audit finish: %w", auditErr)
			} else {
				err = errors.Join(err, fmt.Errorf("audit finish: %w", auditErr))
			}
		}
		checkpointEvent := "commit"
		if err != nil {
			checkpointEvent = "compensate"
		}
		if checkpointErr := i.journalTransition("rollback", checkpointEvent); checkpointErr != nil {
			if err == nil {
				err = checkpointErr
			} else {
				err = &ProvisioningTransactionError{Primary: err, Compensation: checkpointErr}
			}
		}
	}()
	prev, err := i.root.ReadFile("pending.rollback")
	if errors.Is(err, os.ErrNotExist) {
		prev, err = i.root.ReadFile("previous.release")
	}
	if err != nil {
		_ = i.writeReleaseState("rollback.failed", i.cfg.ReleaseID)
		return errors.New("rollback absent")
	}
	id := strings.TrimSpace(string(prev))
	if err := i.validateRollbackRelease(id); err != nil {
		_ = i.writeReleaseState("rollback.failed", i.cfg.ReleaseID)
		return err
	}
	if err := i.writeReleaseState("rollback.selected", id); err != nil {
		return err
	}
	if err := i.journalTransition("rollback", "rollback"); err != nil {
		return err
	}
	current := i.cfg.ReleaseID
	i.cfg.ReleaseID = id
	defer func() { i.cfg.ReleaseID = current }()
	previousPolicy, err := i.root.ReadFile("releases/egress/" + id + "/egress-policy.json")
	if err != nil {
		return errors.New("previous release policy unavailable")
	}
	type prior struct {
		data   []byte
		exists bool
	}
	priors := map[string]prior{}
	i.backups, i.backupExists, i.backupModes = map[string][]byte{}, map[string]bool{}, map[string]os.FileMode{}
	defer func() {
		if err == nil {
			i.created, i.backups, i.backupExists, i.backupModes = nil, nil, nil, nil
			return
		}
		var compensation error
		for name, old := range priors {
			if old.exists {
				compensation = errors.Join(compensation, i.ops.InstallPlist(context.Background(), name, old.data))
			} else {
				compensation = errors.Join(compensation, i.ops.RemovePlist(context.Background(), name))
			}
		}
		compensation = errors.Join(compensation, i.cleanupWithError())
		if compensation != nil {
			err = &ProvisioningTransactionError{Primary: err, Compensation: fmt.Errorf("rollback compensation failed: %w", compensation)}
		}
	}()
	if err = i.atomicText("pf/egress-policy.json", string(previousPolicy), 0644); err != nil {
		return err
	}
	type renderedPlist struct {
		label string
		data  string
	}
	var rendered []renderedPlist
	for _, s := range services {
		label := serviceLabel(s.Name)
		plist := i.renderResolvedPlist(context.Background(), s)
		if plist == "" || strings.Contains(plist, "_DIGEST") || strings.Contains(plist, "_UID") || strings.Contains(plist, "_GID") || strings.Contains(plist, "<string></string>") {
			return errors.New("previous release plist pins unavailable")
		}
		rendered = append(rendered, renderedPlist{label: label, data: plist})
	}
	for _, item := range rendered {
		name := "com.openduck." + item.label + ".plist"
		b, exists, e := i.ops.ReadPlist(context.Background(), name)
		if e != nil {
			return e
		}
		priors[name] = prior{append([]byte(nil), b...), exists}
	}
	if err := i.Stop(); err != nil {
		return err
	}
	for _, item := range rendered {
		path := "launchd/com.openduck." + item.label + ".plist"
		if err := i.atomicText(path, item.data, 0644); err != nil {
			return err
		}
		if err := i.ops.InstallPlist(context.Background(), filepath.Base(path), []byte(item.data)); err != nil {
			return err
		}
	}
	tmp := ".active.release.rollback"
	_ = i.root.Remove(tmp)
	f, err := i.root.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	if err = f.Chmod(0644); err != nil {
		_ = f.Close()
		_ = i.root.Remove(tmp)
		return err
	}
	if _, err = io.WriteString(f, id+"\n"); err != nil {
		_ = f.Close()
		_ = i.root.Remove(tmp)
		return err
	}
	if err = f.Close(); err != nil {
		_ = i.root.Remove(tmp)
		return err
	}
	if err = i.root.Rename(tmp, "active.release"); err != nil {
		_ = i.root.Remove(tmp)
		return err
	}
	if err = i.root.Remove("pending.rollback"); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err = i.journalTransition("rollback", "verify"); err != nil {
		return err
	}
	if err = i.writeReleaseState("rolled-back.release", id); err != nil {
		return err
	}
	return nil
}

func (i *Installer) verifyReleasePins(id string) error {
	manifestDigest := map[string]string{}
	for _, s := range []string{"egress", "broker", "runtime", "controller"} {
		b, err := i.root.ReadFile("releases/" + s + "/" + id + "/manifest.json")
		if err != nil {
			return err
		}
		manifestDigest[s] = Digest(b)
	}
	expected := map[string]string{
		"egress/local-release.json": "egress", "egress/peer-release.json": "broker",
		"broker/local-release.json": "broker", "broker/egress-release.json": "egress", "broker/runtime-release.json": "runtime", "broker/controller-release.json": "controller",
		"controller/local-release.json": "controller", "controller/broker-release.json": "broker",
		"runtime/local-release.json": "runtime", "runtime/broker-release.json": "broker",
	}
	for rel, service := range expected {
		path := "releases/" + strings.Split(rel, "/")[0] + "/" + id + "/" + strings.Split(rel, "/")[1]
		st, err := i.root.Lstat(path)
		if err != nil || !safeExistingRegular(st, 0440, st.Size()) {
			return errors.New("previous release pin metadata invalid")
		}
		b, err := i.root.ReadFile(path)
		if err != nil {
			return err
		}
		var p struct {
			ReleaseID      string `json:"release_id"`
			BinaryDigest   string `json:"binary_digest"`
			SocketDigest   string `json:"socket_digest"`
			ManifestDigest string `json:"manifest_digest"`
		}
		if json.Unmarshal(b, &p) != nil || p.ReleaseID != id || !isDigest(p.BinaryDigest) || !isDigest(p.SocketDigest) || p.ManifestDigest != manifestDigest[service] {
			return errors.New("previous release pin invalid")
		}
	}
	return nil
}

type plist struct {
	XMLName xml.Name  `xml:"plist"`
	Version string    `xml:"version,attr"`
	Dict    plistDict `xml:"dict"`
}
type plistDict struct {
	Label string `xml:"-"`
}

func renderPlist(s Service, release string) string {
	name := s.Name
	if name == "broker" {
		name = "codex-broker"
	}
	args := []string{SystemRoot + "/releases/" + s.Name + "/" + release + "/" + binaryName(s.Name)}
	add := func(k, v string) { args = append(args, k, v) }
	switch s.Name {
	case "checkpoint":
		add("-state", SystemRoot+"/state/checkpoint")
		add("-socket-root", SystemRoot+"/checkpoint-channel/platform-checkpoint")
		add("-socket", "checkpoint.sock")
		add("-key-root", SystemRoot+"/keys/checkpoint")
		add("-key-file", "service.key")
		add("-release-root", SystemRoot+"/releases/checkpoint/"+release)
		add("-channel", "platform-checkpoint")
		add("-local-role", "checkpoint")
		add("-peer-role", "anchor")
		add("-local-release", "CHECKPOINT_RELEASE_ID")
		add("-local-binary-digest", "CHECKPOINT_BINARY_DIGEST")
		add("-local-socket-digest", "CHECKPOINT_SOCKET_DIGEST")
		add("-local-manifest-digest", "CHECKPOINT_MANIFEST_DIGEST")
		add("-peer-release", "ANCHOR_CHECKPOINT_RELEASE_ID")
		add("-peer-binary-digest", "ANCHOR_CHECKPOINT_BINARY_DIGEST")
		add("-peer-socket-digest", "ANCHOR_CHECKPOINT_SOCKET_DIGEST")
		add("-peer-manifest-digest", "ANCHOR_CHECKPOINT_MANIFEST_DIGEST")
		add("-local-uid", "CHECKPOINT_UID")
		add("-local-gid", "CHECKPOINT_GID")
		add("-peer-uid", "ANCHOR_UID")
		add("-peer-gid", "ANCHOR_GID")
		add("-channel-gid", "CHECKPOINT_CHANNEL_GID")
		add("-key-epoch", "KEY_EPOCH")
		// The installer journal is a separate authenticated listener.  It must
		// never share the checkpoint<->anchor transport, key, or socket root.
		add("-journal-socket-root", SystemRoot+"/channels/installer-checkpoint")
		add("-journal-socket", "journal.sock")
		add("-journal-key-root", SystemRoot+"/keys/checkpoint-installer")
		add("-journal-key-file", "journal.key")
		add("-journal-release-root", SystemRoot+"/releases/checkpoint-installer/"+release)
		add("-journal-local-role", "checkpoint")
		add("-journal-peer-role", "installer")
		add("-journal-local-release", "CHECKPOINT_RELEASE_ID")
		add("-journal-local-binary-digest", "CHECKPOINT_BINARY_DIGEST")
		add("-journal-local-socket-digest", "JOURNAL_CP_SOCKET")
		add("-journal-local-manifest-digest", "JOURNAL_CP_MANIFEST")
		add("-journal-peer-release", "JOURNAL_IC_RELEASE")
		add("-journal-peer-binary-digest", "JOURNAL_IC_BINARY")
		add("-journal-peer-socket-digest", "JOURNAL_IC_SOCKET")
		add("-journal-peer-manifest-digest", "JOURNAL_IC_MANIFEST")
		add("-journal-peer-uid", "JOURNAL_INSTALLER_UID")
		add("-journal-peer-gid", "JOURNAL_INSTALLER_GID")
		add("-journal-channel-gid", "JOURNAL_IC_GID")
	case "anchor":
		add("-state", SystemRoot+"/state/anchor")
		add("-socket-root", SystemRoot+"/channels/platform-anchor")
		add("-socket", SystemRoot+"/channels/platform-anchor/anchor.sock")
		add("-key-root", SystemRoot+"/keys/anchor")
		add("-key-file", "service.key")
		add("-checkpoint-key-root", SystemRoot+"/keys/anchor-checkpoint")
		add("-checkpoint-key-file", "checkpoint.key")
		add("-release-root", SystemRoot+"/releases/anchor/"+release)
		add("-checkpoint-release-root", SystemRoot+"/releases/anchor-checkpoint/"+release)
		add("-checkpoint-socket-root", SystemRoot+"/checkpoint-channel/platform-checkpoint")
		add("-checkpoint-socket", "checkpoint.sock")
		add("-channel", "platform-anchor")
		add("-local-role", "anchor")
		add("-peer-role", "controller")
		add("-checkpoint-local-role", "anchor")
		add("-checkpoint-peer-role", "checkpoint")
		add("-local-release", "ANCHOR_RELEASE_ID")
		add("-local-binary-digest", "ANCHOR_BINARY_DIGEST")
		add("-local-socket-digest", "ANCHOR_SOCKET_DIGEST")
		add("-local-manifest-digest", "ANCHOR_MANIFEST_DIGEST")
		add("-peer-release", "CONTROLLER_RELEASE_ID")
		add("-peer-binary-digest", "CONTROLLER_BINARY_DIGEST")
		add("-peer-socket-digest", "CONTROLLER_ANCHOR_SOCKET_DIGEST")
		add("-peer-manifest-digest", "CONTROLLER_MANIFEST_DIGEST")
		add("-checkpoint-local-release", "ANCHOR_CHECKPOINT_RELEASE_ID")
		add("-checkpoint-local-binary-digest", "ANCHOR_CHECKPOINT_BINARY_DIGEST")
		add("-checkpoint-local-socket-digest", "ANCHOR_CHECKPOINT_SOCKET_DIGEST")
		add("-checkpoint-local-manifest-digest", "ANCHOR_CHECKPOINT_MANIFEST_DIGEST")
		add("-checkpoint-peer-release", "CHECKPOINT_RELEASE_ID")
		add("-checkpoint-peer-binary-digest", "CHECKPOINT_BINARY_DIGEST")
		add("-checkpoint-peer-socket-digest", "CHECKPOINT_SOCKET_DIGEST")
		add("-checkpoint-peer-manifest-digest", "CHECKPOINT_MANIFEST_DIGEST")
		add("-local-uid", "ANCHOR_UID")
		add("-local-gid", "ANCHOR_GID")
		add("-peer-uid", "CONTROLLER_UID")
		add("-peer-gid", "CONTROLLER_GID")
		add("-channel-gid", "CHANNEL_GID")
		add("-checkpoint-channel-gid", "CHECKPOINT_CHANNEL_GID")
		add("-checkpoint-local-uid", "ANCHOR_UID")
		add("-checkpoint-local-gid", "ANCHOR_GID")
		add("-checkpoint-peer-uid", "CHECKPOINT_UID")
		add("-checkpoint-peer-gid", "CHECKPOINT_GID")
		add("-key-epoch", "KEY_EPOCH")
		// This is deliberately distinct from both platform-anchor and
		// platform-checkpoint.  The installer obtains only the typed client.
		add("-journal-socket-root", SystemRoot+"/channels/installer-anchor")
		add("-journal-socket", "journal.sock")
		add("-journal-key-root", SystemRoot+"/keys/anchor-installer")
		add("-journal-key-file", "journal.key")
		add("-journal-release-root", SystemRoot+"/releases/anchor-installer/"+release)
		add("-journal-local-role", "anchor")
		add("-journal-peer-role", "installer")
		add("-journal-local-release", "ANCHOR_RELEASE_ID")
		add("-journal-local-binary-digest", "ANCHOR_BINARY_DIGEST")
		add("-journal-local-socket-digest", "JOURNAL_AN_SOCKET")
		add("-journal-local-manifest-digest", "JOURNAL_AN_MANIFEST")
		add("-journal-peer-release", "JOURNAL_IA_RELEASE")
		add("-journal-peer-binary-digest", "JOURNAL_IA_BINARY")
		add("-journal-peer-socket-digest", "JOURNAL_IA_SOCKET")
		add("-journal-peer-manifest-digest", "JOURNAL_IA_MANIFEST")
		add("-journal-peer-uid", "JOURNAL_INSTALLER_UID")
		add("-journal-peer-gid", "JOURNAL_INSTALLER_GID")
		add("-journal-channel-gid", "JOURNAL_IA_GID")
	case "egress":
		args = append(args, "-production-admission")
		add("-channel", "model-egress")
		add("-socket-root", SystemRoot+"/channels/model-egress")
		add("-control-socket", "control.sock")
		add("-release-root", SystemRoot+"/releases/egress/"+release)
		add("-key-root", SystemRoot+"/keys/egress")
		add("-binary", SystemRoot+"/releases/egress/"+release+"/openduck-egress")
		add("-policy", "EGRESS_POLICY_DIGEST")
		add("-policy-file", SystemRoot+"/pf/egress-policy.json")
		add("-release-digest", "EGRESS_RELEASE_DIGEST")
		add("-socket-digest", "EGRESS_SOCKET_DIGEST")
		add("-local-release", SystemRoot+"/releases/egress/"+release+"/local-release.json")
		add("-peer-release", SystemRoot+"/releases/egress/"+release+"/peer-release.json")
		add("-key-file", "service.key")
		add("-binary-name", "openduck-egress")
		add("-max-connections", "8")
		add("-proxy-address", "127.0.0.1:8790")
		add("-uid", "EGRESS_UID")
		add("-gid", "EGRESS_GID")
		add("-peer-uid", "BROKER_UID")
		add("-peer-gid", "BROKER_GID")
		add("-channel-gid", "EGRESS_CHANNEL_GID")
		add("-epoch", "KEY_EPOCH")
	case "runtime":
		args = append(args, "-production-admission")
		add("-runtime-binary-name", "openduck-codex-runtime")
		add("-runtime-id", "CODEX_RUNTIME_ID")
		add("-codex-release-root", SystemRoot+"/releases/codex/"+release)
		add("-codex-binary-name", "codex")
		add("-codex-release-id", release)
		add("-codex-binary-digest", "CODEX_BINARY_DIGEST")
		add("-codex-manifest-digest", "CODEX_MANIFEST_DIGEST")
		add("-codex-socket-digest", "CODEX_SOCKET_DIGEST")
		add("-codex-home", SystemRoot+"/home/runtime")
		add("-cwd", SystemRoot+"/home/runtime/work")
		add("-model", "MODEL_ID")
		add("-runtime-channel", "codex-runtime")
		add("-runtime-socket-root", SystemRoot+"/channels/codex-runtime")
		add("-runtime-socket", "runtime.sock")
		add("-runtime-release-root", SystemRoot+"/releases/runtime/"+release)
		add("-runtime-key-root", SystemRoot+"/keys/runtime")
		add("-runtime-key-file", "service.key")
		add("-runtime-local-release", SystemRoot+"/releases/runtime/"+release+"/local-release.json")
		add("-broker-runtime-release", SystemRoot+"/releases/runtime/"+release+"/broker-release.json")
		add("-sandbox-root", SystemRoot+"/seatbelt")
		add("-sandbox-exec", "/usr/bin/sandbox-exec")
		add("-pf-state-file", "state")
		add("-pf-digest", "PF_DIGEST")
		add("-pf-evidence-file", "pf-evidence.json")
		add("-pf-evidence-digest", "PF_EVIDENCE_DIGEST")
		add("-pf-rules-digest", "PF_RULES_DIGEST")
		add("-boot-id", "BOOT_ID")
		add("-seatbelt-profile", "codex.sb")
		add("-seatbelt-digest", "SEATBELT_DIGEST")
		add("-policy-digest", "BROKER_POLICY_DIGEST")
		add("-egress-release-digest", "EGRESS_RELEASE_DIGEST")
		add("-egress-socket-digest", "EGRESS_SOCKET_DIGEST")
		add("-runtime-uid", "RUNTIME_UID")
		add("-runtime-gid", "RUNTIME_GID")
		add("-broker-uid", "BROKER_UID")
		add("-broker-gid", "BROKER_GID")
		add("-runtime-channel-gid", "RUNTIME_CHANNEL_GID")
		add("-egress-uid", "EGRESS_UID")
		add("-egress-gid", "EGRESS_GID")
		add("-key-epoch", "KEY_EPOCH")
	case "broker":
		args = append(args, "-production-admission")
		add("-binary", SystemRoot+"/releases/broker/"+release+"/openduck-codex-broker")
		add("-runtime-id", "CODEX_RUNTIME_ID")
		add("-runtime-digest", "CODEX_RUNTIME_DIGEST")
		add("-model", "MODEL_ID")
		add("-channel", "codex-owner")
		add("-socket-root", SystemRoot+"/channels/codex-owner")
		add("-egress-socket-root", SystemRoot+"/channels/model-egress")
		add("-release-root", SystemRoot+"/releases/broker/"+release)
		add("-controller-key-root", SystemRoot+"/keys/broker-controller")
		add("-binary-name", "openduck-codex-broker")
		add("-controller-key-file", "service.key")
		add("-controller-socket", "owner.sock")
		add("-policy-file", SystemRoot+"/pf/egress-policy.json")
		add("-egress-local-release", SystemRoot+"/releases/broker/"+release+"/egress-release.json")
		add("-broker-egress-release", SystemRoot+"/releases/broker/"+release+"/local-release.json")
		add("-egress-key-root", SystemRoot+"/keys/broker-egress")
		add("-egress-key-file", "service.key")
		add("-runtime-channel", "codex-runtime")
		add("-runtime-socket-root", SystemRoot+"/channels/codex-runtime")
		add("-runtime-socket", "runtime.sock")
		add("-runtime-key-root", SystemRoot+"/keys/broker-runtime")
		add("-runtime-key-file", "service.key")
		add("-runtime-local-release", SystemRoot+"/releases/broker/"+release+"/runtime-release.json")
		add("-broker-runtime-release", SystemRoot+"/releases/broker/"+release+"/local-release.json")
		add("-broker-local-release", SystemRoot+"/releases/broker/"+release+"/local-release.json")
		add("-controller-local-release", SystemRoot+"/releases/broker/"+release+"/controller-release.json")
		add("-peer-uid", "CONTROLLER_UID")
		add("-peer-gid", "CONTROLLER_GID")
		add("-egress-uid", "EGRESS_UID")
		add("-egress-gid", "EGRESS_GID")
		add("-egress-channel-gid", "EGRESS_CHANNEL_GID")
		add("-broker-uid", "BROKER_UID")
		add("-broker-gid", "BROKER_GID")
		add("-channel-gid", "BROKER_CHANNEL_GID")
		add("-runtime-uid", "RUNTIME_UID")
		add("-runtime-gid", "RUNTIME_GID")
		add("-runtime-channel-gid", "RUNTIME_CHANNEL_GID")
		add("-epoch", "KEY_EPOCH")
	case "controller":
		args = append(args, "-production-admission")
		add("-listen", "127.0.0.1:8788")
		add("-state", SystemRoot+"/state/controller")
		add("-anchor-socket", "anchor.sock")
		add("-anchor-socket-root", SystemRoot+"/channels/platform-anchor")
		add("-anchor-key-root", SystemRoot+"/keys/controller-anchor")
		add("-anchor-key-file", "service.key")
		add("-owner-capability-file", "owner.capability")
		add("-owner-public-key-file", "owner.public")
		add("-broker-socket", "owner.sock")
		add("-broker-socket-root", SystemRoot+"/channels/codex-owner")
		add("-broker-key-root", SystemRoot+"/keys/controller-broker")
		add("-broker-key-file", "service.key")
		add("-broker-release-root", SystemRoot+"/releases/controller/"+release)
		add("-broker-channel", "codex-owner")
		add("-broker-local-role", "controller")
		add("-broker-peer-role", "broker")
		add("-controller-release-root", SystemRoot+"/releases/controller/"+release)
		add("-anchor-channel", "platform-anchor")
		add("-anchor-local-role", "controller")
		add("-anchor-peer-role", "anchor")
		add("-controller-release", "CONTROLLER_RELEASE_ID")
		add("-controller-binary-digest", "CONTROLLER_BINARY_DIGEST")
		add("-controller-socket-digest", "CONTROLLER_ANCHOR_SOCKET_DIGEST")
		add("-controller-manifest-digest", "CONTROLLER_MANIFEST_DIGEST")
		add("-anchor-release", "ANCHOR_RELEASE_ID")
		add("-anchor-binary-digest", "ANCHOR_BINARY_DIGEST")
		add("-anchor-socket-digest", "ANCHOR_SOCKET_DIGEST")
		add("-anchor-manifest-digest", "ANCHOR_MANIFEST_DIGEST")
		add("-controller-uid", "CONTROLLER_UID")
		add("-controller-gid", "CONTROLLER_GID")
		add("-anchor-uid", "ANCHOR_UID")
		add("-anchor-gid", "ANCHOR_GID")
		add("-anchor-channel-gid", "CHANNEL_GID")
		add("-anchor-key-epoch", "KEY_EPOCH")
		add("-broker-runtime-id", "CODEX_RUNTIME_ID")
		add("-broker-runtime-digest", "CODEX_RUNTIME_DIGEST")
		add("-broker-policy-digest", "BROKER_POLICY_DIGEST")
		add("-broker-release-digest", "BROKER_RELEASE_DIGEST")
		add("-broker-socket-digest", "BROKER_SOCKET_DIGEST")
		add("-broker-egress-release-digest", "EGRESS_RELEASE_DIGEST")
		add("-broker-egress-socket-digest", "EGRESS_SOCKET_DIGEST")
		add("-broker-local-release", "BROKER_LOCAL_RELEASE_ID")
		add("-broker-peer-release", "BROKER_PEER_RELEASE_ID")
		add("-broker-local-binary-digest", "BROKER_LOCAL_BINARY_DIGEST")
		add("-broker-peer-binary-digest", "BROKER_PEER_BINARY_DIGEST")
		add("-broker-local-socket-digest", "BROKER_LOCAL_SOCKET_DIGEST")
		add("-broker-peer-socket-digest", "BROKER_PEER_SOCKET_DIGEST")
		add("-broker-local-manifest-digest", "BROKER_LOCAL_MANIFEST_DIGEST")
		add("-broker-peer-manifest-digest", "BROKER_PEER_MANIFEST_DIGEST")
		add("-broker-uid", "BROKER_UID")
		add("-broker-gid", "BROKER_GID")
		add("-broker-channel-gid", "BROKER_CHANNEL_GID")
		add("-egress-uid", "EGRESS_UID")
		add("-egress-gid", "EGRESS_GID")
		add("-broker-key-epoch", "BROKER_KEY_EPOCH")
	}
	var b strings.Builder
	b.WriteString("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\"><dict>")
	tag := func(k, v string) { fmt.Fprintf(&b, "<key>%s</key><string>%s</string>", k, xmlEscape(v)) }
	label := serviceLabel(s.Name)
	tag("Label", "com.openduck."+label)
	tag("UserName", s.User)
	tag("GroupName", s.Group)
	b.WriteString("<key>ProgramArguments</key><array>")
	for _, a := range args {
		fmt.Fprintf(&b, "<string>%s</string>", xmlEscape(a))
	}
	b.WriteString("</array>")
	tag("WorkingDirectory", SystemRoot)
	b.WriteString("<key>RunAtLoad</key><false/><key>Disabled</key><true/><key>KeepAlive</key><false/></dict></plist>\n")
	return b.String()
}

// StaticPlistTemplate exposes the same argument renderer used by Apply so
// repository templates cannot drift from the production installer contract.
func StaticPlistTemplate(service, release string) (string, error) {
	for _, s := range services {
		if s.Name == service {
			return renderPlist(s, release), nil
		}
	}
	return "", errors.New("unknown service")
}
func xmlEscape(s string) string {
	b, _ := xml.Marshal(s)
	v := string(b)
	if strings.HasPrefix(v, "<string>") && strings.HasSuffix(v, "</string>") {
		return v[len("<string>") : len(v)-len("</string>")]
	}
	return v
}
func validID(s string) bool {
	if len(s) < 8 || len(s) > 128 {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
			return false
		}
	}
	return true
}
func Digest(data []byte) string { h := sha256.Sum256(data); return hex.EncodeToString(h[:]) }
func isDigest(s string) bool    { return len(s) == 64 && strings.Trim(s, "0123456789abcdef") == "" }
