package macosinstall

import (
	"encoding/json"
	"errors"
	"openduck/internal/macosrelease"
	"openduck/internal/releasecatalog"
	"runtime"
	"sort"
	"strings"
)

const DeploymentPlanSchemaV2 = "openduck.deployment-plan.v2"

const maxPlanOperations = 64

// DeploymentPlanV2 is the closed, non-authoritative projection of an already
// admitted release. It contains relative paths only; TargetRoot is the sole
// fixed-root binding.
type DeploymentPlanV2 struct {
	Schema         string          `json:"schema"`
	Version        int             `json:"version"`
	ReleaseID      string          `json:"release_id"`
	ReleaseVersion string          `json:"release_version"`
	ReleaseDigest  string          `json:"release_digest"`
	RunID          string          `json:"run_id"`
	TargetRoot     string          `json:"target_root"`
	Platform       string          `json:"platform"`
	Arch           string          `json:"arch"`
	Activation     bool            `json:"activation"`
	Operations     []PlanOperation `json:"operations"`
	RollbackPlan   []PlanOperation `json:"rollback_plan"`
	CleanupPlan    []PlanOperation `json:"cleanup_plan"`
}

type PlanOperation struct {
	Action        string   `json:"action"`
	Source        string   `json:"source"`
	Target        string   `json:"target"`
	ArtifactType  string   `json:"artifact_type"`
	Digest        string   `json:"digest"`
	Mode          string   `json:"mode"`
	Owner         string   `json:"owner"`
	Group         string   `json:"group"`
	Preconditions []string `json:"preconditions"`
}

type planMapping struct{ target, mode, owner, group string }

// BuildDeploymentPlanV2 never opens the fixed root, acquires a lock, consumes
// a nonce, or materializes staged bytes. The caller must first obtain a
// macosrelease.Admission through ValidateAdmission.
func BuildDeploymentPlanV2(admission macosrelease.Admission, runID string, activation bool) (DeploymentPlanV2, error) {
	m, err := admission.PlanManifest(runID, activation)
	if err != nil {
		return DeploymentPlanV2{}, errors.New("unverified release admission")
	}
	if m.Schema != macosrelease.ManifestSchema || !validID(m.ReleaseID) || !isDigest(m.ReleaseDigest) || !validPlanVersion(m.Version) || m.TargetRoot != SystemRoot || !validPlanRunID(runID) || len(m.Artifacts) == 0 || len(m.Artifacts) > maxPlanOperations || !validClosedCatalogManifest(m) {
		return DeploymentPlanV2{}, errors.New("invalid admitted release for plan")
	}
	plan := DeploymentPlanV2{Schema: DeploymentPlanSchemaV2, Version: 2, ReleaseID: m.ReleaseID, ReleaseVersion: m.Version, ReleaseDigest: m.ReleaseDigest, RunID: runID, TargetRoot: SystemRoot, Platform: runtime.GOOS, Arch: runtime.GOARCH, Activation: activation}
	seen := make(map[string]struct{}, len(m.Artifacts)*2)
	for _, artifact := range m.Artifacts {
		mappings, ok := resolvePlanArtifacts(artifact, m.ReleaseID)
		if !ok || artifact.Platform != runtime.GOOS || artifact.Arch != runtime.GOARCH || artifact.Version != m.Version || !isDigest(artifact.Digest) {
			return DeploymentPlanV2{}, errors.New("unmapped or inconsistent admitted artifact")
		}
		for _, mapping := range mappings {
			if _, duplicate := seen[mapping.target]; duplicate {
				return DeploymentPlanV2{}, errors.New("duplicate plan target")
			}
			seen[mapping.target] = struct{}{}
			base := PlanOperation{Source: artifact.Path, Target: mapping.target, ArtifactType: artifact.Type, Digest: artifact.Digest, Mode: mapping.mode, Owner: mapping.owner, Group: mapping.group}
			plan.Operations = append(plan.Operations, withPlanAction(base, "install", installPlanPreconditions))
			plan.RollbackPlan = append(plan.RollbackPlan, withPlanAction(base, "rollback", rollbackPlanPreconditions))
			plan.CleanupPlan = append(plan.CleanupPlan, withPlanAction(base, "cleanup", cleanupPlanPreconditions))
		}
	}
	sortPlanOperations(plan.Operations)
	sortPlanOperations(plan.RollbackPlan)
	sortPlanOperations(plan.CleanupPlan)
	if err := plan.Validate(); err != nil {
		return DeploymentPlanV2{}, err
	}
	return plan, nil
}

func withPlanAction(in PlanOperation, action string, preconditions []string) PlanOperation {
	in.Action, in.Preconditions = action, preconditions
	return in
}

func sortPlanOperations(values []PlanOperation) {
	sort.Slice(values, func(i, j int) bool { return values[i].Target < values[j].Target })
}

var (
	installPlanPreconditions  = []string{"admission-validated", "digest-match", "target-safe"}
	rollbackPlanPreconditions = []string{"previous-release-verified", "target-safe"}
	cleanupPlanPreconditions  = []string{"candidate-not-active", "target-safe"}
)

// resolvePlanArtifacts is deliberately the exact source-to-output inventory
// of Installer.Apply. A single signed input can have two immutable outputs
// (anchor checkpoint client, codex CLI, installer service-login); listing
// both prevents PlanV2 from concealing a write that deployment will perform.
func resolvePlanArtifacts(a macosrelease.Artifact, release string) ([]planMapping, bool) {
	outputs, ok := releasecatalog.Resolve(releasecatalog.Artifact{Type: a.Type, Path: a.Path, Platform: a.Platform, Arch: a.Arch, Version: a.Version, ActivationGroup: a.ActivationGroup, Required: a.Required}, release)
	return planMappings(outputs), ok
}

func resolvePlanArtifactSource(path, artifactType, release string) ([]planMapping, bool) {
	outputs, ok := releasecatalog.ResolveSource(path, artifactType, release)
	return planMappings(outputs), ok
}

func planMappings(outputs []releasecatalog.Output) []planMapping {
	if len(outputs) == 0 {
		return nil
	}
	mappings := make([]planMapping, len(outputs))
	for index, output := range outputs {
		mappings[index] = planMapping{target: output.TargetTemplate, mode: output.Mode, owner: output.Owner, group: output.Group}
	}
	return mappings
}

// validClosedCatalogManifest is the installer-side gate for the same neutral
// catalog used by the offline packager. Admission remains cryptographic
// authority; this rejects a correctly signed but operationally unsupported
// artifact inventory before any PlanV2 or copy target is derived.
func validClosedCatalogManifest(manifest macosrelease.ManifestV2) bool {
	if manifest.Version == "" || len(manifest.Artifacts) == 0 {
		return false
	}
	artifacts := make([]releasecatalog.Artifact, 0, len(manifest.Artifacts))
	for _, artifact := range manifest.Artifacts {
		artifacts = append(artifacts, releasecatalog.Artifact{Type: artifact.Type, Path: artifact.Path, Platform: artifact.Platform, Arch: artifact.Arch, Version: artifact.Version, ActivationGroup: artifact.ActivationGroup, Required: artifact.Required})
	}
	return releasecatalog.Validate(artifacts, runtime.GOOS, runtime.GOARCH, manifest.Version) == nil
}

func (p DeploymentPlanV2) Validate() error {
	if p.Schema != DeploymentPlanSchemaV2 || p.Version != 2 || !validID(p.ReleaseID) || !validPlanVersion(p.ReleaseVersion) || !isDigest(p.ReleaseDigest) || !validPlanRunID(p.RunID) || p.TargetRoot != SystemRoot || p.Platform != runtime.GOOS || p.Arch != runtime.GOARCH || len(p.Operations) == 0 || len(p.Operations) > maxPlanOperations || len(p.RollbackPlan) != len(p.Operations) || len(p.CleanupPlan) != len(p.Operations) {
		return errors.New("invalid deployment plan")
	}
	canonical := make(map[string]PlanOperation, len(p.Operations))
	for index, values := range [][]PlanOperation{p.Operations, p.RollbackPlan, p.CleanupPlan} {
		action, preconditions := "install", installPlanPreconditions
		if index == 1 {
			action, preconditions = "rollback", rollbackPlanPreconditions
		} else if index == 2 {
			action, preconditions = "cleanup", cleanupPlanPreconditions
		}
		seen := map[string]struct{}{}
		lastTarget := ""
		for _, op := range values {
			if !validPlanOperation(op, p.ReleaseID, action, preconditions) || op.Target <= lastTarget {
				return errors.New("invalid deployment plan operation")
			}
			if _, duplicate := seen[op.Target]; duplicate {
				return errors.New("duplicate deployment plan target")
			}
			seen[op.Target] = struct{}{}
			lastTarget = op.Target
			if index == 0 {
				canonical[op.Target] = op
			} else if baseline, ok := canonical[op.Target]; !ok || !samePlanPayload(baseline, op) {
				return errors.New("deployment plan phases disagree")
			}
		}
	}
	if !validPlanCatalogClosure(p.Operations, p) {
		return errors.New("deployment plan catalog closure invalid")
	}
	return nil
}

func validPlanOperation(op PlanOperation, release, action string, preconditions []string) bool {
	if op.Action != action || !safePlanRelative(op.Source) || !safePlanRelative(op.Target) || !isDigest(op.Digest) || !validPlanArtifactType(op.ArtifactType) || !validPlanMode(op.Mode) || !validPlanPrincipal(op.Owner) || !validPlanPrincipal(op.Group) || !sameStrings(op.Preconditions, preconditions) {
		return false
	}
	mappings, ok := resolvePlanArtifactSource(op.Source, op.ArtifactType, release)
	if !ok {
		return false
	}
	for _, mapping := range mappings {
		if op.Target == mapping.target && op.Mode == mapping.mode && op.Owner == mapping.owner && op.Group == mapping.group {
			return true
		}
	}
	return false
}

// validPlanCatalogClosure makes a plan include every fixed output for every
// selected source, and only source sets that form the mandatory base plus
// complete optional groups. A PlanV2 cannot conceal a partial copy or add an
// unbound provider output.
func validPlanCatalogClosure(operations []PlanOperation, plan DeploymentPlanV2) bool {
	bySource := make(map[string][]PlanOperation, len(operations))
	for _, operation := range operations {
		bySource[operation.Source] = append(bySource[operation.Source], operation)
	}
	artifacts := make([]releasecatalog.Artifact, 0, len(bySource))
	for source, operations := range bySource {
		artifactType := operations[0].ArtifactType
		for _, operation := range operations[1:] {
			if operation.ArtifactType != artifactType {
				return false
			}
		}
		entry, found := releasecatalog.EntryFor(source)
		if !found || entry.Type != artifactType {
			return false
		}
		expected, ok := resolvePlanArtifactSource(source, artifactType, plan.ReleaseID)
		if !ok || len(expected) != len(operations) {
			return false
		}
		matched := make(map[string]bool, len(expected))
		for _, operation := range operations {
			for _, mapping := range expected {
				if operation.Target == mapping.target && operation.Mode == mapping.mode && operation.Owner == mapping.owner && operation.Group == mapping.group {
					if matched[mapping.target] {
						return false
					}
					matched[mapping.target] = true
					break
				}
			}
		}
		if len(matched) != len(expected) {
			return false
		}
		artifacts = append(artifacts, releasecatalog.Artifact{Type: entry.Type, Path: entry.Path, Platform: plan.Platform, Arch: plan.Arch, Version: plan.ReleaseVersion, ActivationGroup: entry.ActivationGroup, Required: entry.Required})
	}
	sort.Slice(artifacts, func(i, j int) bool { return artifacts[i].Path < artifacts[j].Path })
	return releasecatalog.Validate(artifacts, plan.Platform, plan.Arch, plan.ReleaseVersion) == nil
}

func sameStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for n := range left {
		if left[n] != right[n] {
			return false
		}
	}
	return true
}

func samePlanPayload(left, right PlanOperation) bool {
	return left.Source == right.Source && left.Target == right.Target && left.ArtifactType == right.ArtifactType && left.Digest == right.Digest && left.Mode == right.Mode && left.Owner == right.Owner && left.Group == right.Group
}

func validPlanArtifactType(value string) bool {
	return value == "core" || value == "provider_runtime" || value == "provider_plugin" || value == "provider_daemon" || value == "provider_topology" || value == "provider_host_runtime" || value == "provider_host_closure" || value == "provider_host_identity" || value == "policy" || value == "helper"
}
func validPlanVersion(value string) bool {
	parts := strings.Split(value, ".")
	if len(parts) != 3 {
		return false
	}
	for _, part := range parts {
		if part == "" || len(part) > 9 || (len(part) > 1 && part[0] == '0') {
			return false
		}
		for _, r := range part {
			if r < '0' || r > '9' {
				return false
			}
		}
	}
	return true
}
func validPlanMode(value string) bool {
	return value == "0440" || value == "0500" || value == "0550" || value == "0700" || value == "0755"
}
func validPlanPrincipal(value string) bool {
	return value == "root" || value == "wheel" || strings.HasPrefix(value, "_openduck_") || value == "_openduck"
}
func safePlanRelative(value string) bool {
	if value == "" || len(value) > 512 || strings.HasPrefix(value, "/") || value != strings.TrimSpace(value) {
		return false
	}
	for _, part := range strings.Split(value, "/") {
		if part == "" || part == "." || part == ".." {
			return false
		}
	}
	return true
}
func validPlanRunID(value string) bool { return validateRunID(value) == nil && value != "" }

func (p DeploymentPlanV2) JSON() ([]byte, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(p)
}
