package macosinstall

// This file contains the deliberately narrow, read-only reporting surface used
// by orchestration tools. Reports describe symbolic paths and reason codes only;
// they never expose key material, principal IDs, or command output.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	providerreadiness "openduck/internal/readiness"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
)

const provisioningSchema = "openduck.provisioning.v1"

// Provisioning errors are written to a dedicated, per-run file. stderr is
// deliberately not a protocol channel: command tools may emit notices there
// even when the command itself succeeded.
const provisioningErrorSchema = "openduck.provisioning-error.v2"
const DoctorSchema = "openduck.doctor.v1"

const (
	ErrorPhaseStop                      = "stop"
	ErrorPhaseApply                     = "apply"
	ErrorPhaseDeploy                    = "deploy"
	ErrorPhaseActivate                  = "activate"
	ErrorPhaseRollback                  = "rollback"
	ErrorPhaseVerify                    = "verify"
	ErrorPhasePlan                      = "plan"
	ErrorPhaseFinalize                  = "finalize"
	ErrorReasonPFRulesInvalid           = "pf_rules_invalid"
	ErrorReasonPFLoadFailed             = "pf_load_failed"
	ErrorReasonPFRestoreFailed          = "pf_restore_failed"
	ErrorReasonLaunchdEnableFailed      = "launchd_enable_failed"
	ErrorReasonLaunchdBootstrapFailed   = "launchd_bootstrap_failed"
	ErrorReasonLaunchdKickstartFailed   = "launchd_kickstart_failed"
	ErrorReasonLaunchdHealthFailed      = "launchd_health_failed"
	ErrorReasonLaunchdShutdownFailed    = "launchd_shutdown_failed"
	ErrorReasonRollbackAbsent           = "rollback_absent"
	ErrorReasonRollbackUnverified       = "rollback_unverified"
	ErrorReasonRollbackPlistUnavailable = "rollback_plist_unavailable"
	ErrorReasonRollbackRestoreFailed    = "rollback_restore_failed"
	ErrorReasonPolicyUpgradeFailed      = "policy_upgrade_failed"
	ErrorReasonApplyRestoreFailed       = "apply_restore_failed"
	ErrorReasonStopRequired             = "stop_required"
	ErrorReasonVerificationFailed       = "verification_failed"
	ErrorReasonProvisioningFailed       = "provisioning_failed"
	ErrorReasonPartialRecoveryUncertain = "partial_recovery_uncertain"
)

type ProvisioningError struct {
	Schema                 string `json:"schema"`
	Version                int    `json:"version"`
	RunID                  string `json:"run_id"`
	ReleaseDigest          string `json:"release_digest"`
	Phase                  string `json:"phase"`
	ReasonCode             string `json:"reason_code"`
	PrimaryReasonCode      string `json:"primary_reason_code"`
	CompensationReasonCode string `json:"compensation_reason_code"`
	Scope                  string `json:"scope"`
	RecoveryState          string `json:"recovery_state"`
}

type ProvisioningTransactionError struct {
	Primary      error
	Compensation error
}

func (e *ProvisioningTransactionError) Error() string {
	return fmt.Sprintf("transaction failed: %v; compensation failed: %v", e.Primary, e.Compensation)
}
func (e *ProvisioningTransactionError) Unwrap() []error { return []error{e.Primary, e.Compensation} }

// SafeProvisioningError deliberately classifies errors without serializing
// error text, command output, argv, paths, principal IDs, or rule bytes.
func SafeProvisioningError(args []string, err error) []byte {
	phase, digest, runID := "unknown", "", "unknown"
	for n := 0; n < len(args); n++ {
		switch args[n] {
		case "--apply":
			phase = "apply"
		case "--deploy":
			phase = ErrorPhaseDeploy
		case "--activation=true":
			if phase == ErrorPhaseDeploy {
				phase = ErrorPhaseActivate
			}
		case "--plan-json", "--dry-run":
			phase = "plan"
		case "--verify-json":
			phase = "verify"
		case "--activate":
			phase = "activate"
		case "--rollback":
			phase = "rollback"
		case "--finalize-pf":
			phase = ErrorPhaseFinalize
		case "--verify":
			phase = "verify"
		case "--stop":
			phase = "stop"
		case "--recover-partial-install":
			phase = "partial_install_recovery"
		case "--release-digest":
			if n+1 < len(args) && isDigest(args[n+1]) {
				digest = args[n+1]
				n++
			}
		case "--run-id":
			if n+1 < len(args) && validateRunID(args[n+1]) == nil {
				runID = args[n+1]
				n++
			}
		}
		if strings.HasPrefix(args[n], "--verify-json=") {
			phase = "verify"
		}
	}
	reason, compensation, scope := safeReasonCodes(err)
	recovery := "retry_safe"
	if reason == ErrorReasonRollbackAbsent || reason == ErrorReasonRollbackUnverified || reason == ErrorReasonRollbackPlistUnavailable {
		recovery = "rollback_unavailable"
	}
	if reason == ErrorReasonPFRestoreFailed || compensation != "" || reason == ErrorReasonRollbackRestoreFailed || reason == ErrorReasonPolicyUpgradeFailed || reason == ErrorReasonApplyRestoreFailed || reason == ErrorReasonPFRulesInvalid || strings.HasPrefix(reason, "launchd_") {
		recovery = "manual_review"
	}
	if reason == ErrorReasonPartialRecoveryUncertain {
		recovery = "manual_review"
	}
	b, _ := json.Marshal(ProvisioningError{Schema: provisioningErrorSchema, Version: 2, RunID: runID, ReleaseDigest: digest, Phase: phase, ReasonCode: reason, PrimaryReasonCode: reason, CompensationReasonCode: compensation, Scope: scope, RecoveryState: recovery})
	return b
}

func safeReasonCode(err error) string {
	primary, _, _ := safeReasonCodes(err)
	return primary
}

func safeReasonCodes(err error) (string, string, string) {
	var tx *ProvisioningTransactionError
	if errors.As(err, &tx) {
		return safeReasonCodePlain(tx.Primary), safeReasonCodePlain(tx.Compensation), "installer"
	}
	return safeReasonCodePlain(err), "", "installer"
}

func safeReasonCodePlain(err error) string {
	if err == nil {
		return ""
	}
	if errors.Is(err, ErrPartialInstallRecoveryUncertain) {
		return ErrorReasonPartialRecoveryUncertain
	}
	s := strings.ToLower(err.Error())
	switch {
	case strings.Contains(s, "apply compensation"):
		return ErrorReasonApplyRestoreFailed
	case strings.Contains(s, "pf restore"):
		return ErrorReasonPFRestoreFailed
	case strings.Contains(s, "rollback compensation"):
		return ErrorReasonRollbackRestoreFailed
	case strings.Contains(s, "policy upgrade"):
		return ErrorReasonPolicyUpgradeFailed
	case strings.Contains(s, "launchd shutdown"):
		return ErrorReasonLaunchdShutdownFailed
	case strings.Contains(s, "syntax") && strings.Contains(s, "pf"):
		return ErrorReasonPFRulesInvalid
	case strings.Contains(s, "pf load") || strings.Contains(s, "pfctl enable"):
		return ErrorReasonPFLoadFailed
	case strings.Contains(s, "previous release absent") || strings.Contains(s, "rollback absent"):
		return ErrorReasonRollbackAbsent
	case strings.Contains(s, "previous release unverified"):
		return ErrorReasonRollbackUnverified
	case strings.Contains(s, "plist pins unavailable"):
		return ErrorReasonRollbackPlistUnavailable
	case strings.Contains(s, "bootstrap"):
		return ErrorReasonLaunchdBootstrapFailed
	case strings.Contains(s, "kickstart"):
		return ErrorReasonLaunchdKickstartFailed
	case strings.Contains(s, "health"):
		return ErrorReasonLaunchdHealthFailed
	case strings.Contains(s, "enable "):
		return ErrorReasonLaunchdEnableFailed
	case strings.Contains(s, "stop_required"):
		return ErrorReasonStopRequired
	case strings.Contains(s, "verify") || strings.Contains(s, "verification"):
		return ErrorReasonVerificationFailed
	default:
		return "provisioning_failed"
	}
}

type reportScope struct {
	Name        string   `json:"name"`
	Changed     bool     `json:"changed"`
	Drift       bool     `json:"drift"`
	ReasonCodes []string `json:"reason_codes,omitempty"`
	Counts      Counts   `json:"counts"`
	Paths       []string `json:"paths,omitempty"`
}

type Counts struct {
	Checked int `json:"checked"`
	Drift   int `json:"drift"`
}

// InspectionReport is intentionally stable and machine-oriented. ReleaseDigest
// is an operator-supplied release token, not a digest derived from secrets.
type InspectionReport struct {
	Schema        string        `json:"schema"`
	Version       int           `json:"version"`
	ReleaseDigest string        `json:"release_digest"`
	Scopes        []reportScope `json:"scopes"`
}

// DoctorReport is a bounded read-only posture projection. It contains no
// credentials, command output, principal identifiers, or mutable operations.
type DoctorReport struct {
	Schema      string            `json:"schema"`
	Version     int               `json:"version"`
	Platform    string            `json:"platform"`
	Arch        string            `json:"arch"`
	FixedRoot   map[string]bool   `json:"fixed_root"`
	Markers     map[string]bool   `json:"markers"`
	Gates       map[string]string `json:"gates"`
	ReasonCodes []string          `json:"reason_codes"`
}

// DoctorJSON reads only fixed, non-secret release-state selectors. It never
// creates a root, runs a command, reads credentials, loads PF, starts jobs,
// logs in, or uses a network.
func DoctorJSON() ([]byte, error) {
	return doctorJSONForRoot(SystemRoot, runtime.GOOS, runtime.GOARCH, 0, 0)
}

// doctorJSONForRoot is the read-only implementation behind DoctorJSON. The
// root and expected owner are injected solely for rooted temporary tests; the
// exported entry point always supplies the fixed production root and root:wheel
// metadata. It never opens a caller-selected root from an external interface.
func doctorJSONForRoot(root, platform, arch string, expectedUID, expectedGID uint32) ([]byte, error) {
	path := func(relative string) string { return filepath.Join(root, relative) }
	regular := func(relative string) bool {
		info, err := os.Lstat(path(relative))
		return err == nil && info.Mode()&os.ModeSymlink == 0 && info.Mode().IsRegular()
	}
	directory := func(relative string) bool {
		info, err := os.Lstat(path(relative))
		return err == nil && info.Mode()&os.ModeSymlink == 0 && info.IsDir()
	}
	immutableManifest := func(relative string) bool {
		info, err := os.Lstat(path(relative))
		return err == nil && safeExistingRegular(info, 0440, info.Size()) && ownedBy(info, expectedUID, expectedGID)
	}
	releaseState := func(relative string) (string, bool) {
		info, err := os.Lstat(path(relative))
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm() != 0644 {
			return "", false
		}
		b, err := os.ReadFile(path(relative))
		if err != nil {
			return "", false
		}
		id := strings.TrimSpace(string(b))
		return id, validID(id) && string(b) == id+"\n"
	}
	info, err := os.Lstat(root)
	rootSafe := err == nil && info.Mode()&os.ModeSymlink == 0 && info.IsDir()
	candidate, candidateOK := releaseState("candidate.release")
	configured, configuredOK := releaseState("configured.release")
	active, activeOK := releaseState("active.release")
	activated, activatedOK := releaseState("activated.release")
	manifestOK := false
	if configuredOK {
		// configured.release is parsed as a strict safe ID above; never derive
		// a path from an unchecked selector or consult the legacy stage manifest.
		manifestOK = immutableManifest("releases/controller/" + configured + "/release-manifest.v2.json")
	}
	r := DoctorReport{Schema: DoctorSchema, Version: 1, Platform: platform, Arch: arch,
		FixedRoot: map[string]bool{"fixed": true, "safe_directory": rootSafe},
		Markers:   map[string]bool{"candidate": candidateOK, "configured": configuredOK, "active": activeOK, "activated": activatedOK, "activation_intent": regular("activation.intent"), "failed": regular("failed.release"), "rolled_back": regular("rolled-back.release"), "manifest": manifestOK},
		Gates:     map[string]string{"configuration_converged": "unknown", "activation_complete": "unknown", "operational_ready": "unavailable", "operator_gate": "required"}}
	if rootSafe && directory("releases") && directory("launchd") && directory("seatbelt") && candidateOK && configuredOK && candidate == configured {
		r.Gates["configuration_converged"] = "observed"
	}
	if activeOK && activatedOK && active == activated && r.Gates["configuration_converged"] == "observed" {
		r.Gates["activation_complete"] = "observed"
	}
	expected, topologyErr := providerreadiness.DiscoverExpected(root)
	evidence, evidenceErr := providerreadiness.LoadEvidence(root)
	report := providerreadiness.Evaluate(expected, evidence, providerreadiness.Activation{ReleaseID: configured, ActiveRelease: active, ActivatedRelease: activated, Complete: r.Gates["activation_complete"] == "observed"}, nil, time.Now().UTC())
	if topologyErr != nil {
		report.ReasonCodes = append(report.ReasonCodes, providerreadiness.ReasonTopologyInvalid)
	}
	if evidenceErr != nil {
		report.ReasonCodes = append(report.ReasonCodes, providerreadiness.ReasonEvidenceAbsent)
	}
	r.ReasonCodes = uniqueSorted(report.ReasonCodes)
	return json.Marshal(r)
}

func uniqueSorted(values []string) []string {
	seen := map[string]bool{}
	for _, value := range values {
		seen[value] = true
	}
	out := make([]string, 0, len(seen))
	for value := range seen {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

type scopeList []string

// ScopeFlags implements flag.Value for the CLI's repeatable --verify-json.
type ScopeFlags = scopeList

func (s *scopeList) String() string { return strings.Join(*s, ",") }
func (s *scopeList) Set(value string) error {
	for _, item := range strings.Split(value, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		switch item {
		case "principals", "layout", "artifacts", "ownership", "policy", "launchd", "full":
			*s = append(*s, item)
		default:
			return fmt.Errorf("invalid verify scope %q", item)
		}
	}
	return nil
}

func normalizeScopes(input []string) []string {
	if len(input) == 0 {
		return []string{"principals", "layout", "artifacts", "ownership", "policy", "launchd"}
	}
	seen := make(map[string]bool, len(input))
	result := make([]string, 0, len(input))
	for _, raw := range input {
		for _, item := range strings.Split(raw, ",") {
			item = strings.TrimSpace(item)
			if item != "" && !seen[item] {
				seen[item] = true
				result = append(result, item)
			}
		}
	}
	sort.Strings(result)
	return result
}

func validateRunID(value string) error {
	if len(value) < 8 || len(value) > 128 {
		return errors.New("run-id must be 8..128 characters")
	}
	for _, r := range value {
		if !((r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F') || (r >= '0' && r <= '9') || r == '-') {
			return errors.New("run-id must contain only hexadecimal characters and dashes")
		}
	}
	return nil
}

// ValidateRunID is exported for callers that must reject unsafe input before
// opening or normalizing the fixed installation root.
func ValidateRunID(value string) error {
	if value == "" {
		return nil
	}
	return validateRunID(value)
}

func ValidateReleaseDigest(value string) error {
	if value == "" {
		return nil
	}
	if !isDigest(value) {
		return errors.New("invalid release digest")
	}
	return nil
}

// DefaultReleaseDigest provides a stable non-secret report token when callers
// use the legacy release-id-only CLI form.
func DefaultReleaseDigest(releaseID string) string { return Digest([]byte(releaseID)) }

func newRunID() string {
	b := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		// A predictable run ID defeats the run-directory and journal boundary.
		// There is no safe degraded identifier, so refuse construction.
		panic("CSPRNG unavailable for provisioning run id")
	}
	return hex.EncodeToString(b)
}

// NewReadOnly opens the fixed root without creating or normalizing it. It is
// suitable for --verify-json and therefore cannot accidentally repair state.
func NewReadOnly(releaseID, releaseDigest string) (*Installer, error) {
	if !validID(releaseID) || !isDigest(releaseDigest) {
		return nil, errors.New("invalid release or release digest")
	}
	if runtime.GOOS != "darwin" {
		return nil, errors.New("macOS installer requires darwin")
	}
	r, err := os.OpenRoot(SystemRoot)
	if err != nil {
		return nil, fmt.Errorf("open fixed install root read-only: %w", err)
	}
	return &Installer{root: r, cfg: Config{Root: SystemRoot, ReleaseID: releaseID, UID: -1, GID: -1, Model: "gpt-5.6"}, runID: newRunID(), releaseDigest: releaseDigest, ops: newDarwinSystemOps()}, nil
}

// NewPlanning creates no filesystem handle and is used exclusively by the
// machine-readable desired-plan command.
func NewPlanning(releaseID string) (*Installer, error) {
	if !validID(releaseID) {
		return nil, errors.New("invalid release id")
	}
	return &Installer{cfg: Config{Root: SystemRoot, ReleaseID: releaseID}, releaseDigest: releaseID}, nil
}

func (i *Installer) SetAuditRun(runID, releaseDigest string) error {
	if runID == "" {
		runID = newRunID()
	}
	if err := validateRunID(runID); err != nil {
		return err
	}
	if releaseDigest == "" {
		releaseDigest = DefaultReleaseDigest(i.cfg.ReleaseID)
	}
	if !isDigest(releaseDigest) {
		return errors.New("invalid release digest")
	}
	i.runID, i.releaseDigest, i.journal = runID, releaseDigest, nil
	return nil
}

// BindProductionJournal installs the only production journal capability: a
// binding made from both concrete typed platform clients. There is no generic
// signer/anchor or raw socket fallback.
func (i *Installer) BindProductionJournal(binding ProductionJournalBinding) error {
	if i == nil || !binding.valid() {
		return errors.New("protected journal authority unavailable")
	}
	i.journalBinding, i.journal = binding, nil
	return nil
}

func (i *Installer) journalTransition(phase, event string) error {
	if i == nil || i.root == nil {
		return errors.New("protected journal authority unavailable")
	}
	if i.journal == nil {
		var authority journalAuthority
		if i.journalBinding.valid() {
			authority = i.journalBinding.authority
		} else if i.fake && i.journalAuthority != nil && i.journalAuthority.valid() {
			authority = i.journalAuthority
		}
		journal, err := OpenProvisioningJournal(i.root, i.runID, i.releaseDigest, authority)
		if err != nil {
			return err
		}
		i.journal = journal
	}
	return i.journal.Transition(phase, event)
}

// promoteJournal is the operational seal gate. It is intentionally separate
// from configuration transitions: fresh bootstrap remains unprotected until
// both authorities have actually started.
func (i *Installer) promoteJournal() error {
	if i == nil || (!i.journalBinding.valid() && !(i.fake && i.journalAuthority != nil && i.journalAuthority.valid())) {
		return errors.New("protected journal authority unavailable")
	}
	if i.journal == nil {
		if err := i.journalTransition("protection", "prepare"); err != nil {
			return err
		}
	}
	if i.journal == nil || (!i.journalBinding.valid() && !(i.fake && i.journalAuthority != nil && i.journalAuthority.valid())) {
		return errors.New("protected journal authority unavailable")
	}
	return i.journal.Promote()
}

func (i *Installer) requireProtectedJournal() error {
	if i == nil || (!i.journalBinding.valid() && !(i.fake && i.journalAuthority != nil && i.journalAuthority.valid())) {
		return errors.New("protected journal authority unavailable")
	}
	if i.journal == nil {
		if err := i.journalTransition("protection", "recover"); err != nil {
			return err
		}
	}
	if i.journal == nil || !i.journal.Protected() {
		return errors.New("protected journal unavailable")
	}
	return nil
}

func (i *Installer) PlanJSON(releaseDigest string) ([]byte, error) {
	if releaseDigest == "" {
		releaseDigest = DefaultReleaseDigest(i.cfg.ReleaseID)
	}
	if !isDigest(releaseDigest) {
		return nil, errors.New("invalid release digest")
	}
	p := i.Plan()
	paths := append([]string(nil), p.Paths...)
	sort.Strings(paths)
	r := InspectionReport{Schema: provisioningSchema, Version: 1, ReleaseDigest: releaseDigest, Scopes: []reportScope{{Name: "plan", Counts: Counts{Checked: len(paths)}, Paths: paths}}}
	return json.Marshal(r)
}

func (i *Installer) VerifyJSON(ctx context.Context, releaseDigest string, scopes []string) ([]byte, error) {
	if releaseDigest == "" {
		releaseDigest = i.cfg.ReleaseID
	}
	if !isDigest(releaseDigest) {
		return nil, errors.New("invalid release digest")
	}
	i.releaseDigest = releaseDigest
	for _, s := range scopes {
		if s != "principals" && s != "layout" && s != "artifacts" && s != "ownership" && s != "policy" && s != "launchd" && s != "full" {
			return nil, fmt.Errorf("invalid verify scope %q", s)
		}
	}
	result := InspectionReport{Schema: provisioningSchema, Version: 1, ReleaseDigest: releaseDigest}
	for _, name := range normalizeScopes(scopes) {
		r := reportScope{Name: name}
		r.Paths = i.scopePaths(name)
		r.Counts.Checked = len(r.Paths)
		var err error
		switch name {
		case "full":
			r.Counts.Checked = 1
			err = i.Verify()
			if err == nil {
				// Full configuration verification is candidate-aware during Apply,
				// but an existing active selector must still name a complete,
				// marker-backed immutable closure. Otherwise an arbitrary selector
				// could be projected as a healthy candidate while bypassing the
				// protected activation state machine.
				if candidate, candidateErr := i.readReleaseState("candidate.release"); candidateErr != nil || candidate != i.cfg.ReleaseID {
					active, readErr := i.readReleaseState("active.release")
					if readErr != nil || active != i.cfg.ReleaseID {
						err = errors.New("release selector mismatch")
					}
				}
				if err == nil {
					if selectionErr := i.validateExistingActiveSelection(); selectionErr != nil {
						err = selectionErr
					}
				}
			}
		case "principals":
			err = i.verifyReportPrincipals(ctx)
		case "layout":
			err = i.verifyReportPaths(r.Paths, true)
		case "artifacts":
			err = i.verifyReportPaths(r.Paths, false)
		case "ownership":
			err = i.verifyProductionOwnership(ctx, false)
		case "policy":
			err = i.verifyReportPaths(r.Paths, false)
		case "launchd":
			err = i.verifyReportPaths(r.Paths, false)
		}
		if err != nil {
			r.Drift, r.Changed, r.Counts.Drift = true, true, 1
			r.ReasonCodes = []string{reasonCode(err)}
		}
		result.Scopes = append(result.Scopes, r)
	}
	return json.Marshal(result)
}

func (i *Installer) scopePaths(scope string) []string {
	switch scope {
	case "principals":
		paths := make([]string, 0, len(services))
		for _, s := range services {
			paths = append(paths, "principal/"+s.User, "group/"+s.Group)
		}
		return paths
	case "layout":
		return []string{"state", "logs", "home", "keys", "releases", "operator", "channels", "checkpoint-channel", "pf", "seatbelt", "launchd"}
	case "artifacts":
		return []string{"active.release", "operator/codex-login.json", "operator/owner-ed25519.key", "keys/controller-anchor/owner.public"}
	case "ownership":
		return []string{"state", "logs", "home", "keys", "releases", "channels", "checkpoint-channel", "operator", "pf", "seatbelt", "active.release"}
	case "policy":
		return []string{"pf/egress-policy.json", "seatbelt/state", "seatbelt/codex.sb", "seatbelt/egress.sb"}
	case "launchd":
		paths := make([]string, 0, len(services))
		for _, s := range services {
			paths = append(paths, "launchd/com.openduck."+serviceLabel(s.Name)+".plist")
		}
		return paths
	case "full":
		return nil
	}
	return nil
}

func (i *Installer) verifyReportPrincipals(ctx context.Context) error {
	for _, s := range services {
		if err := i.ops.VerifyPrincipal(ctx, s.User, s.Group); err != nil {
			return err
		}
	}
	return nil
}

func (i *Installer) verifyReportPaths(paths []string, directories bool) error {
	for _, p := range paths {
		st, err := i.root.Lstat(p)
		if err != nil {
			return err
		}
		if directories && !st.IsDir() {
			return errors.New("expected directory")
		}
		if st.Mode()&os.ModeSymlink != 0 {
			return errors.New("symlink rejected")
		}
	}
	return nil
}

func reasonCode(err error) string {
	if errors.Is(err, os.ErrNotExist) {
		return "missing_path"
	}
	if strings.Contains(err.Error(), "Principal") || strings.Contains(err.Error(), "principal") {
		return "principal_mismatch"
	}
	if strings.Contains(err.Error(), "ownership") {
		return "ownership_mismatch"
	}
	return "verification_failed"
}

type auditEvent struct {
	Schema        string `json:"schema"`
	Version       int    `json:"version"`
	RunID         string `json:"run_id"`
	Phase         string `json:"phase"`
	Event         string `json:"event"`
	ReleaseDigest string `json:"release_digest"`
	Outcome       string `json:"outcome,omitempty"`
	ReasonCode    string `json:"reason_code,omitempty"`
	Scope         string `json:"scope,omitempty"`
}

func (i *Installer) audit(phase, event, outcome, reason, scope string, create bool) error {
	if i == nil || i.root == nil || !i.auditEnabled {
		return nil
	}
	if i.runID == "" {
		i.runID = newRunID()
	}
	if err := validateRunID(i.runID); err != nil {
		return err
	}
	if create {
		if err := i.ensureAuditDirectories(); err != nil {
			return err
		}
	} else {
		if st, err := i.root.Lstat("logs/provisioning"); err != nil || !st.IsDir() {
			if err != nil {
				return err
			}
			return errors.New("unsafe audit directory")
		}
	}
	if st, err := i.root.Lstat("logs/provisioning"); err != nil || st.Mode()&os.ModeSymlink != 0 || st.Mode().Perm() != 0700 || !st.IsDir() {
		if err != nil {
			return err
		}
		return errors.New("unsafe audit directory")
	}
	logPath := "logs/provisioning/" + i.runID + ".jsonl"
	if st, err := i.root.Lstat(logPath); err == nil {
		if st.Mode()&os.ModeSymlink != 0 || !st.Mode().IsRegular() || st.Mode().Perm() != 0600 {
			return errors.New("unsafe audit log")
		}
		if !i.fake && !ownedBy(st, 0, 0) {
			return errors.New("audit log ownership mismatch")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	e := auditEvent{Schema: provisioningSchema, Version: 1, RunID: i.runID, Phase: phase, Event: event, ReleaseDigest: i.releaseDigest, Outcome: outcome, ReasonCode: reason, Scope: scope}
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	f, err := i.root.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return err
	}
	if err := f.Chmod(0600); err != nil {
		_ = f.Close()
		return err
	}
	for len(b) > 0 {
		n, writeErr := f.Write(b)
		if writeErr != nil {
			_ = f.Close()
			return writeErr
		}
		if n == 0 {
			_ = f.Close()
			return io.ErrShortWrite
		}
		b = b[n:]
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

// ensureAuditDirectories deliberately bypasses Installer.created: audit
// evidence must survive a failed provisioning transaction and its cleanup.
func (i *Installer) ensureAuditDirectories() error {
	for _, item := range []struct {
		path string
		mode os.FileMode
	}{{"logs", 0711}, {"logs/provisioning", 0700}} {
		st, err := i.root.Lstat(item.path)
		created := false
		if errors.Is(err, os.ErrNotExist) {
			if err = i.root.Mkdir(item.path, item.mode); err != nil {
				return err
			}
			created = true
			st, err = i.root.Lstat(item.path)
		}
		if err != nil || st.Mode()&os.ModeSymlink != 0 || !st.IsDir() || st.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
			return errors.New("unsafe audit directory")
		}
		if !created {
			if st.Mode().Perm() != item.mode.Perm() || !i.fake && !ownedBy(st, 0, 0) {
				return errors.New("existing audit directory metadata mismatch")
			}
			continue
		}
		f, openErr := i.root.Open(item.path)
		if openErr != nil {
			return openErr
		}
		if !i.fake {
			if openErr = f.Chown(0, 0); openErr == nil {
				openErr = f.Chmod(item.mode)
			}
		} else {
			openErr = f.Chmod(item.mode)
		}
		if openErr == nil {
			openErr = f.Sync()
		}
		closeErr := f.Close()
		if openErr != nil || closeErr != nil {
			return errors.Join(openErr, closeErr)
		}
		st, err = i.root.Lstat(item.path)
		if err != nil || st.Mode().Perm() != item.mode.Perm() || st.Mode()&os.ModeSymlink != 0 {
			return errors.New("audit directory normalization failed")
		}
		if !i.fake && !ownedBy(st, 0, 0) {
			return errors.New("audit directory ownership mismatch")
		}
	}
	return nil
}
