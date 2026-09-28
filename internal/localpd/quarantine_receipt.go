package localpd

import (
	"encoding/json"
	"errors"
	"time"
)

const QuarantineErasureReceiptV1 = "quarantine-erasure-receipt.v1"

type ErasureAuthority interface {
	Sign([]byte) (string, error)
	Verify([]byte, string) bool
}

// QuarantineErasureReceipt deliberately makes no claim about backups, swap,
// model memory, or another store. It proves only removal of this encrypted
// quarantine ciphertext. A future hard-erasure adapter must use a separately
// attested store-absence capability.
type QuarantineErasureReceipt struct {
	SchemaVersion        string    `json:"schema_version"`
	ReceiptID            string    `json:"receipt_id"`
	SessionBindingDigest string    `json:"session_binding_digest"`
	TargetDigest         string    `json:"target_digest"`
	ErasureVersion       uint64    `json:"erasure_version"`
	HighWater            uint64    `json:"high_water"`
	DeletionStatus       string    `json:"deletion_status"`
	VerificationMethod   string    `json:"verification_method"`
	CoverageComplete     bool      `json:"coverage_complete"`
	ErasedAt             time.Time `json:"erased_at"`
	ExpiresAt            time.Time `json:"expires_at"`
	EvidenceDigest       string    `json:"evidence_digest"`
	ControllerSignature  string    `json:"controller_signature"`
	Digest               string    `json:"digest"`
}

func (r QuarantineErasureReceipt) Validate() error {
	if r.validateUnsigned() != nil || !digestRE.MatchString(r.Digest) || r.ControllerSignature == "" {
		return errors.New("invalid quarantine erasure receipt")
	}
	return nil
}
func (r QuarantineErasureReceipt) validateUnsigned() error {
	if r.SchemaVersion != QuarantineErasureReceiptV1 || !validID(r.ReceiptID) ||
		!allDigest(r.SessionBindingDigest, r.TargetDigest, r.EvidenceDigest) ||
		r.ErasureVersion == 0 || r.HighWater == 0 || r.DeletionStatus != "partial" ||
		r.VerificationMethod != "quarantine_ciphertext_removed" || r.CoverageComplete ||
		!utc(r.ErasedAt) || !utc(r.ExpiresAt) || !r.ExpiresAt.After(r.ErasedAt) {
		return errors.New("invalid quarantine erasure receipt")
	}
	return nil
}
func (r QuarantineErasureReceipt) CanonicalUnsigned() ([]byte, error) {
	r.ControllerSignature, r.Digest = "", ""
	return json.Marshal(r)
}
func (r QuarantineErasureReceipt) AuthorityMetadata() AuthorityMetadata {
	return AuthorityMetadata{StreamID: r.ReceiptID, Version: r.ErasureVersion, HighWater: r.HighWater, IssuedAt: r.ErasedAt, ExpiresAt: r.ExpiresAt}
}
func (r QuarantineErasureReceipt) AuthoritySignature() string { return r.ControllerSignature }
func (r QuarantineErasureReceipt) AuthorityDigest() string    { return r.Digest }
