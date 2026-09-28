// Command openduck-installer is the fixed-root operator entry point. It is
// intentionally boring: all filesystem policy lives in internal/macosinstall.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"openduck/internal/macosinstall"
	"openduck/internal/macosrelease"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

type productionInstaller interface {
	Close() error
	Deploy(context.Context, bool) (macosinstall.DeploymentEvidence, error)
	Apply() error
	Verify() error
	Stop() error
	Rollback() error
	FinalizePFEvidence(context.Context) error
	Activate(context.Context) error
	ServiceLogin(context.Context) error
	SetAuditRun(string, string) error
}

var newProduction = func(input macosrelease.DeploymentInput) (productionInstaller, error) {
	return macosinstall.NewProduction(input)
}
var nowUTC = func() time.Time { return time.Now().UTC() }
var acquireDeploymentLock = func() (io.Closer, error) { return macosinstall.AcquireDeploymentLock() }
var releaseNonceStore = func() macosrelease.NonceStore { return macosrelease.FileNonceStore{Path: releaseNonceStorePath} }
var materializeAdmission = func(a macosrelease.Admission) (macosrelease.Snapshot, error) {
	return a.MaterializeSnapshot(releaseSnapshotParent)
}
var inspectPartialInstallRecovery = macosinstall.InspectProductionPartialInstall
var quarantinePartialInstallRecovery = macosinstall.RecoverProductionPartialInstall
var resolveInstalledTrustAnchor = macosrelease.ResolveInstalledTrustAnchor
var bootstrapInstalledTrustAnchor = macosrelease.BootstrapInstalledTrustAnchor

const (
	installerVersion      = "1.0.0"
	releaseNonceStorePath = "/private/var/db/openduck-release-nonces.json"
	releaseSnapshotParent = "/private/var/db"
)

func main() {
	args := os.Args[1:]
	if filepath.Base(os.Args[0]) == ".openduck-service-login" {
		args = append([]string{"--service-login"}, args...)
	}
	if err := run(args); err != nil {
		if path, ok := errorJSONPath(args); ok {
			// The file is the sole authority channel. Keep stderr human-only so
			// warnings from a helper cannot be parsed as a lifecycle result.
			if writeErr := writeErrorJSON(path, macosinstall.SafeProvisioningError(args, err)); writeErr != nil {
				fmt.Fprintln(os.Stderr, "openduck-installer: unable to write designated error channel")
			}
			os.Exit(1)
		}
		fmt.Fprintln(os.Stderr, "openduck-installer:", err)
		os.Exit(1)
	}
}

func errorJSONPath(args []string) (string, bool) {
	for n := 0; n+1 < len(args); n++ {
		if args[n] == "--error-json-file" {
			return args[n+1], true
		}
	}
	return "", false
}

func writeErrorJSON(path string, payload []byte) error {
	if !validErrorJSONPath(path) {
		return errors.New("unsafe designated error path")
	}
	clean := filepath.Clean(path)
	// O_EXCL prevents a stale or concurrent error from being accepted as this
	// helper's result. The parent directory is created and owned by Ansible.
	f, err := os.OpenFile(clean, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.Write(payload); err != nil {
		return err
	}
	return f.Sync()
}

func validErrorJSONPath(path string) bool {
	clean := filepath.Clean(path)
	if filepath.Base(clean) != "helper-error.json" {
		return false
	}
	dir := filepath.Dir(clean)
	if filepath.Dir(dir) != "/private/var/run" || !strings.HasPrefix(filepath.Base(dir), "openduck-ansible-") {
		return false
	}
	suffix := strings.TrimPrefix(filepath.Base(dir), "openduck-ansible-")
	if len(suffix) < 6 || len(suffix) > 128 {
		return false
	}
	for _, char := range suffix {
		if !(char >= 'a' && char <= 'z') && !(char >= '0' && char <= '9') && char != '_' {
			return false
		}
	}
	return true
}

func hasLiteralFlag(args []string, flag string) bool {
	for _, arg := range args {
		if arg == flag {
			return true
		}
	}
	return false
}
func run(args []string) error {
	for _, legacy := range []string{"--apply", "--stop", "--activate"} {
		if hasLiteralFlag(args, legacy) {
			return errors.New("legacy mutation " + legacy + " is disabled; use --deploy with an operation-bound release envelope")
		}
	}
	fs := flag.NewFlagSet("openduck-installer", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	dry := fs.Bool("dry-run", false, "print the immutable provisioning plan")
	planJSON := fs.Bool("plan-json", false, "print the read-only desired plan as JSON")
	doctorJSON := fs.Bool("doctor-json", false, "print bounded read-only host posture as JSON")
	partialRecoveryPlan := fs.Bool("partial-install-recovery-plan", false, "inspect the explicit partial-install quarantine precondition")
	recoverPartialInstall := fs.Bool("recover-partial-install", false, "atomically quarantine one exact failed partial bootstrap root")
	bootstrapReleaseTrust := fs.Bool("bootstrap-release-trust", false, "one-time explicit fixed release trust-anchor bootstrap")
	recoveryIntent := fs.String("recovery-intent", "", "exact explicit partial-install recovery intent")
	recoveryBootstrapHelper := fs.String("recovery-bootstrap-helper", "", "independently pretrusted recovery helper path")
	recoveryBootstrapSHA256 := fs.String("recovery-bootstrap-sha256", "", "independent SHA-256 for the pretrusted recovery helper")
	recoveryReadinessSHA256 := fs.String("recovery-readiness-sha256", "", "independent catalog SHA-256 for the partial readiness helper")
	trustBootstrapSource := fs.String("trust-bootstrap-source", "", "root-owned operator-supplied release trust JSON for explicit one-time bootstrap")
	trustBootstrapSHA256 := fs.String("trust-bootstrap-sha256", "", "exact lowercase SHA-256 independently verified by the operator")
	var verifyScopes macosinstall.ScopeFlags
	fs.Var(&verifyScopes, "verify-json", "read-only verification JSON (repeatable or comma-separated scope list)")
	deploy := fs.Bool("deploy", false, "run the one sealed deployment transaction")
	activation := fs.Bool("activation", false, "explicit deploy activation intent (true or false)")
	rollback := fs.Bool("rollback", false, "rollback active release while retaining state")
	release := fs.String("release-id", "", "release identifier")
	releaseVersion := fs.String("release-version", "", "exact release semantic version required for mutation")
	releaseDigest := fs.String("release-digest", "", "redacted release token included in reports and audit")
	runID := fs.String("run-id", "", "safe audit run identifier")
	errorJSONFile := fs.String("error-json-file", "", "write a strict redacted machine error object to the designated per-run file")
	source := fs.String("binary-dir", "", "staged binary directory")
	envelopeFile := fs.String("release-envelope", "", "trusted release envelope JSON required for mutation")
	manifestFile := fs.String("release-manifest", "", "release manifest v2 JSON required for mutation")
	trustFile := fs.String("release-trust-bundle", "", "staged release trust JSON that must be byte-identical to the fixed installed anchor")
	nonceStore := fs.String("release-nonce-store", releaseNonceStorePath, "fixed durable nonce state (other values rejected)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}
	if err := macosinstall.ValidateRunID(*runID); err != nil {
		return err
	}
	if err := macosinstall.ValidateReleaseDigest(*releaseDigest); err != nil {
		return err
	}
	n := 0
	for _, v := range []bool{*dry, *planJSON, *doctorJSON, *partialRecoveryPlan, *recoverPartialInstall, *bootstrapReleaseTrust, len(verifyScopes) != 0, *deploy, *rollback} {
		if v {
			n++
		}
	}
	if n != 1 {
		return errors.New("exactly one operation is required")
	}
	if *bootstrapReleaseTrust {
		if *errorJSONFile != "" || *release != "" || *releaseVersion != "" || *releaseDigest != "" || *runID != "" || *source != "" || *envelopeFile != "" || *manifestFile != "" || *trustFile != "" || *nonceStore != releaseNonceStorePath || activationExplicit(args) ||
			*recoveryIntent != "" || *recoveryBootstrapHelper != "" || *recoveryBootstrapSHA256 != "" || *recoveryReadinessSHA256 != "" {
			return errors.New("release trust bootstrap accepts only its explicit trust authority inputs")
		}
		if *trustBootstrapSource == "" || *trustBootstrapSHA256 == "" {
			return errors.New("--trust-bootstrap-source and --trust-bootstrap-sha256 are required")
		}
		return bootstrapInstalledTrustAnchor(*trustBootstrapSource, *trustBootstrapSHA256)
	}
	if *partialRecoveryPlan || *recoverPartialInstall {
		if *errorJSONFile != "" || *release != "" || *releaseVersion != "" || *releaseDigest != "" || *runID != "" || *source != "" || *envelopeFile != "" || *manifestFile != "" || *trustFile != "" || *nonceStore != releaseNonceStorePath || activationExplicit(args) {
			return errors.New("partial-install recovery accepts only its explicit recovery authority inputs")
		}
		request := macosinstall.PartialInstallRecoveryRequest{
			Intent:                *recoveryIntent,
			BootstrapHelperPath:   *recoveryBootstrapHelper,
			BootstrapHelperSHA256: *recoveryBootstrapSHA256,
			ReadinessHelperSHA256: *recoveryReadinessSHA256,
		}
		var evidence macosinstall.PartialInstallRecoveryEvidence
		var recoveryErr error
		if *partialRecoveryPlan {
			evidence, recoveryErr = inspectPartialInstallRecovery(request)
		} else {
			evidence, recoveryErr = quarantinePartialInstallRecovery(request)
		}
		if recoveryErr != nil {
			return recoveryErr
		}
		payload, recoveryErr := evidence.JSON()
		if recoveryErr != nil {
			return recoveryErr
		}
		fmt.Println(string(payload))
		return nil
	}
	if *doctorJSON {
		b, err := macosinstall.DoctorJSON()
		if err != nil {
			return err
		}
		fmt.Println(string(b))
		return nil
	}
	if *errorJSONFile != "" {
		if !validErrorJSONPath(*errorJSONFile) {
			return errors.New("invalid designated error channel")
		}
	}
	if *dry {
		if *release == "" {
			*release = "offline"
		}
		i := &planOnly{release: *release}
		p := i.plan()
		fmt.Printf("root=%s\nrelease=%s\nusers=%v\ngroups=%v\npaths=%v\nplists=%v\nDRY-RUN: no users, files, launchd jobs, or state will be changed\n", p.Root, *release, p.Users, p.Groups, p.Paths, p.Plists)
		return nil
	}
	if *planJSON {
		if *release == "" || *runID == "" || !activationExplicit(args) || *releaseDigest == "" || *releaseVersion == "" || *source == "" || *envelopeFile == "" || *manifestFile == "" || *trustFile == "" || *nonceStore != releaseNonceStorePath {
			return errors.New("--plan-json requires complete explicit admitted release inputs")
		}
		fixedTrustFile, trustErr := resolveInstalledTrustAnchor(*trustFile)
		if trustErr != nil {
			return errors.New("installed release trust anchor is unavailable or staged copy differs")
		}
		admission, err := macosrelease.ValidateAdmission(macosrelease.AdmissionRequest{
			EnvelopePath: *envelopeFile, ManifestPath: *manifestFile, TrustBundlePath: fixedTrustFile, StagedRoot: *source,
			ExpectedReleaseID: *release, ExpectedReleaseDigest: *releaseDigest, ExpectedReleaseVersion: *releaseVersion,
			ExpectedTargetRoot: macosinstall.SystemRoot, ExpectedPlatform: runtime.GOOS, ExpectedArch: runtime.GOARCH,
			ExpectedOperation: "deploy", ExpectedRunID: *runID, ExpectedActivation: *activation,
			InstallerVersion: installerVersion, Now: nowUTC(),
		})
		if err != nil {
			return err
		}
		manifest, err := admission.PlanManifest(*runID, *activation)
		validationTime, timeErr := admission.ValidationTime()
		if err != nil || timeErr != nil || macosrelease.ValidateCatalogStage(*source, manifest, validationTime) != nil {
			return errors.New("closed release catalog stage validation failed")
		}
		plan, err := macosinstall.BuildDeploymentPlanV2(admission, *runID, *activation)
		if err != nil {
			return err
		}
		b, err := plan.JSON()
		if err != nil {
			return err
		}
		fmt.Println(string(b))
		return nil
	}
	if len(verifyScopes) != 0 {
		if *release == "" {
			return errors.New("-release-id required")
		}
		reportDigest := requestedDigest(*release, *releaseDigest)
		i, err := macosinstall.NewReadOnly(*release, reportDigest)
		if err != nil {
			return err
		}
		defer i.Close()
		if err := i.SetAuditRun(*runID, reportDigest); err != nil {
			return err
		}
		b, err := i.VerifyJSON(context.Background(), reportDigest, verifyScopes)
		if err != nil {
			return err
		}
		fmt.Println(string(b))
		return nil
	}
	if *release == "" || *runID == "" {
		return errors.New("-release-id required")
	}
	if *rollback && activationExplicit(args) {
		return errors.New("--activation is valid only with --deploy")
	}
	if *deploy && !activationExplicit(args) {
		return errors.New("--deploy requires explicit --activation=true or --activation=false")
	}
	if *releaseDigest == "" || *releaseVersion == "" || *source == "" || *envelopeFile == "" || *manifestFile == "" || *trustFile == "" || *nonceStore != releaseNonceStorePath {
		return errors.New("trusted release admission inputs required before mutation")
	}
	// This pure step must finish before a deployment lock or production
	// constructor can create/normalize the fixed root.
	fixedTrustFile, trustErr := resolveInstalledTrustAnchor(*trustFile)
	if trustErr != nil {
		return errors.New("installed release trust anchor is unavailable or staged copy differs")
	}
	admissionRequest := macosrelease.AdmissionRequest{
		EnvelopePath:           *envelopeFile,
		ManifestPath:           *manifestFile,
		TrustBundlePath:        fixedTrustFile,
		StagedRoot:             *source,
		ExpectedReleaseID:      *release,
		ExpectedReleaseDigest:  *releaseDigest,
		ExpectedReleaseVersion: *releaseVersion,
		ExpectedTargetRoot:     macosinstall.SystemRoot,
		ExpectedPlatform:       runtime.GOOS,
		ExpectedArch:           runtime.GOARCH,
		ExpectedOperation:      mutationOperation(*deploy, *rollback),
		ExpectedRunID:          *runID,
		ExpectedActivation:     *deploy && *activation,
		InstallerVersion:       installerVersion,
		Now:                    nowUTC(),
	}
	admission, err := macosrelease.ValidateAdmission(admissionRequest)
	if err != nil {
		return err
	}
	if *deploy {
		manifest, manifestErr := admission.PlanManifest(*runID, *activation)
		validationTime, timeErr := admission.ValidationTime()
		if manifestErr != nil || timeErr != nil || macosrelease.ValidateCatalogStage(*source, manifest, validationTime) != nil {
			return errors.New("closed release catalog stage validation failed")
		}
	}
	// This lock is deliberately acquired before NewProduction, whose
	// constructor may normalize the fixed root. Read-only operations returned
	// above never take it.
	lock, err := acquireDeploymentLock()
	if err != nil {
		return err
	}
	defer lock.Close()
	store := releaseNonceStore()
	if store == nil {
		return errors.New("fixed release nonce store unavailable")
	}
	if err = admission.ConsumeReleaseNonce(store); err != nil {
		return err
	}
	snapshot, err := materializeAdmission(admission)
	if err != nil {
		return err
	}
	defer snapshot.Remove()
	input, err := admission.DeploymentInput(snapshot)
	if err != nil {
		return err
	}
	i, err := newProduction(input)
	if err != nil {
		return err
	}
	defer i.Close()
	if err := i.SetAuditRun(*runID, requestedDigest(*release, *releaseDigest)); err != nil {
		return err
	}
	switch {
	case *deploy:
		_, err := i.Deploy(context.Background(), *activation)
		return err
	case *rollback:
		return i.Rollback()
	}
	return nil
}

func mutationOperation(deploy, rollback bool) string {
	if deploy {
		return "deploy"
	}
	if rollback {
		return "rollback"
	}
	return ""
}

func activationExplicit(args []string) bool {
	for _, arg := range args {
		if arg == "--activation=true" || arg == "--activation=false" {
			return true
		}
	}
	return false
}

type planOnly struct{ release string }

func requestedDigest(releaseID, supplied string) string {
	if supplied != "" {
		return supplied
	}
	return macosinstall.DefaultReleaseDigest(releaseID)
}

func (p *planOnly) planJSON(releaseDigest string) ([]byte, error) {
	if releaseDigest == "" {
		releaseDigest = requestedDigest(p.release, "")
	}
	if releaseDigest == "" {
		releaseDigest = "offline"
	}
	i, err := macosinstall.NewPlanning(releaseDigest)
	if err != nil {
		return nil, err
	}
	return i.PlanJSON(releaseDigest)
}

func (p *planOnly) plan() macosinstall.Plan {
	return macosinstall.Plan{
		Root:   macosinstall.SystemRoot,
		Users:  []string{"_openduck_checkpoint", "_openduck_anchor", "_openduck_egress", "_openduck_codex", "_openduck_broker", "_openduck"},
		Groups: []string{"_openduck_channel", "_openduck_checkpoint_channel", "_openduck_egress_channel", "_openduck_broker_channel", "_openduck_runtime_channel", "_openduck_installer_checkpoint_channel", "_openduck_installer_anchor_channel"},
		Paths: []string{
			"channels", "channels/installer-checkpoint", "channels/installer-anchor", "checkpoint-channel", "home", "keys", "releases", "releases/codex",
			"releases/checkpoint-installer", "releases/checkpoint-installer/" + p.release,
			"releases/anchor-installer", "releases/anchor-installer/" + p.release,
			"releases/installer-checkpoint", "releases/installer-checkpoint/" + p.release,
			"releases/installer-anchor", "releases/installer-anchor/" + p.release,
			"operator", "pf", "seatbelt", "state", "logs", "launchd",
		},
		Plists: []string{"com.openduck.anchor.plist", "com.openduck.codex-broker.plist", "com.openduck.checkpoint.plist", "com.openduck.controller.plist", "com.openduck.egress.plist", "com.openduck.codex-runtime.plist"},
	}
}
