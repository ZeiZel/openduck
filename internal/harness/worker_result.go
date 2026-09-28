package harness

import "time"

const WorkerResultV1 = "worker-result.v1"

// WorkerResult is the only worker-authored completion payload. It deliberately
// has no task, work-order, spec, or digest fields; the Controller binds and
// seals those fields when constructing an EvidenceBundle.
type WorkerResult struct {
	SchemaVersion    string          `json:"schema_version"`
	Status           string          `json:"status"`
	Claims           []EvidenceClaim `json:"claims"`
	ChangeRefs       []string        `json:"change_refs"`
	Verification     []Verification  `json:"verification"`
	Deviations       []string        `json:"deviations"`
	ResidualRisks    []string        `json:"residual_risks"`
	CapabilitiesUsed []string        `json:"capabilities_used"`
	AuditRefs        []string        `json:"audit_refs"`
	CompletedAt      time.Time       `json:"completed_at"`
}

func (r WorkerResult) Validate() error {
	if r.SchemaVersion != WorkerResultV1 || r.Status != "completed" || r.CompletedAt.IsZero() || !isUTCTimestamp(r.CompletedAt) {
		return ErrInvalidContract
	}
	if r.Claims == nil || r.ChangeRefs == nil || r.Verification == nil || r.Deviations == nil || r.ResidualRisks == nil || r.CapabilitiesUsed == nil || r.AuditRefs == nil || !validStrings(r.ChangeRefs) || !validStrings(r.Deviations) || !validStrings(r.ResidualRisks) || !validStrings(r.CapabilitiesUsed) || !validStrings(r.AuditRefs) {
		return ErrInvalidContract
	}
	for _, c := range r.Claims {
		if c.Claim == "" || !validStrings(c.EvidenceRefs) {
			return ErrInvalidContract
		}
	}
	for _, v := range r.Verification {
		if v.CheckID == "" || v.CommandRef == "" || v.ExitCode != 0 || v.OutputRef == "" {
			return ErrInvalidContract
		}
	}
	return nil
}

// BuildEvidenceBundle performs the authority-side binding. No worker-supplied
// identifier or digest can influence the resulting evidence identity.
func BuildEvidenceBundle(work WorkOrder, taskID, specHash string, result WorkerResult) (EvidenceBundle, error) {
	return BuildEvidenceBundleAt(work, taskID, specHash, result, time.Now().UTC())
}

func BuildEvidenceBundleForWorkOrder(work WorkOrder, result WorkerResult, observedAt time.Time) (EvidenceBundle, error) {
	return BuildEvidenceBundleAt(work, work.TaskID, work.SpecHash, result, observedAt)
}

// BuildEvidenceBundleAt binds completion timing observed by the authority.
// Worker timestamps are accepted only when they are not in the future and do
// not outlive the work-order lease or the authority's observation.
func BuildEvidenceBundleAt(work WorkOrder, taskID, specHash string, result WorkerResult, observedAt time.Time) (EvidenceBundle, error) {
	if e := work.Validate(); e != nil {
		return EvidenceBundle{}, e
	}
	if e := result.Validate(); e != nil || taskID == "" || specHash == "" || specHash != work.SpecHash {
		return EvidenceBundle{}, ErrBindingMismatch
	}
	observedAt = observedAt.UTC()
	if observedAt.IsZero() || !isUTCTimestamp(observedAt) || result.CompletedAt.After(observedAt) || result.CompletedAt.After(work.Lease.ExpiresAt) {
		return EvidenceBundle{}, ErrLeaseExpired
	}
	b := EvidenceBundle{
		SchemaVersion:    EvidenceBundleV1,
		WorkOrderID:      work.WorkOrderID,
		TaskID:           taskID,
		SpecHash:         specHash,
		Status:           result.Status,
		Claims:           append([]EvidenceClaim(nil), result.Claims...),
		ChangeRefs:       append([]string(nil), result.ChangeRefs...),
		Verification:     append([]Verification(nil), result.Verification...),
		Deviations:       append([]string(nil), result.Deviations...),
		ResidualRisks:    append([]string(nil), result.ResidualRisks...),
		CapabilitiesUsed: append([]string(nil), result.CapabilitiesUsed...),
		AuditRefs:        append([]string(nil), result.AuditRefs...),
	}
	if e := b.Seal(); e != nil {
		return EvidenceBundle{}, e
	}
	return b, nil
}
