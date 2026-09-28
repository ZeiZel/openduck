package platformcheckpoint

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

const JournalSchemaVersion = "openduck.journal-checkpoint.v1"
const JournalAudience = "installer-journal"
const JournalMaxFrameSize = 64 << 10

type JournalRequest struct {
	SchemaVersion string `json:"schema_version"`
	RequestID     string `json:"request_id"`
	Audience      string `json:"audience"`
	Operation     string `json:"operation"`
	RunID         string `json:"run_id"`
	ReleaseDigest string `json:"release_digest"`
	Nonce         string `json:"nonce"`
	PayloadDigest string `json:"payload_digest"`
	Signature     string `json:"signature"`
	Sequence      uint64 `json:"sequence"`
}
type JournalResponse struct {
	SchemaVersion string `json:"schema_version"`
	RequestID     string `json:"request_id"`
	Audience      string `json:"audience"`
	RequestDigest string `json:"request_digest"`
	Signature     string `json:"signature"`
	Error         string `json:"error"`
	OK            bool   `json:"ok"`
}

func (r *JournalRequest) UnmarshalJSON(b []byte) error {
	if r == nil || duplicate(b) || !exactFields(b, "schema_version", "request_id", "audience", "operation", "run_id", "release_digest", "nonce", "payload_digest", "signature", "sequence") {
		return fmt.Errorf("%w: journal request fields", ErrProtocol)
	}
	type plain JournalRequest
	var decoded plain
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(&decoded); err != nil {
		return fmt.Errorf("%w: journal request json", ErrProtocol)
	}
	canonical, err := json.Marshal(decoded)
	if err != nil || !bytes.Equal(b, canonical) || JournalRequest(decoded).Validate() != nil {
		return fmt.Errorf("%w: journal request canonical", ErrProtocol)
	}
	*r = JournalRequest(decoded)
	return nil
}
func (r *JournalResponse) UnmarshalJSON(b []byte) error {
	if r == nil || duplicate(b) || !exactFields(b, "schema_version", "request_id", "audience", "request_digest", "signature", "error", "ok") {
		return fmt.Errorf("%w: journal response fields", ErrProtocol)
	}
	type plain JournalResponse
	var decoded plain
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(&decoded); err != nil {
		return fmt.Errorf("%w: journal response json", ErrProtocol)
	}
	canonical, err := json.Marshal(decoded)
	if err != nil || !bytes.Equal(b, canonical) || JournalResponse(decoded).Validate() != nil {
		return fmt.Errorf("%w: journal response canonical", ErrProtocol)
	}
	*r = JournalResponse(decoded)
	return nil
}

func (r JournalRequest) Validate() error {
	if r.SchemaVersion != JournalSchemaVersion || r.Audience != JournalAudience || !journalID(r.RequestID) || !journalID(r.RunID) || !journalID(r.Nonce) || !validDigest(r.ReleaseDigest) || !validDigest(r.PayloadDigest) || r.Sequence == 0 {
		return fmt.Errorf("%w: journal request", ErrProtocol)
	}
	if r.Operation != "sign" && r.Operation != "verify" {
		return fmt.Errorf("%w: journal operation", ErrProtocol)
	}
	if r.Operation == "sign" && r.Signature != "" {
		return fmt.Errorf("%w: journal sign", ErrProtocol)
	}
	if r.Operation == "verify" {
		if len(r.Signature) != 64 || !hexString(r.Signature) {
			return fmt.Errorf("%w: journal signature", ErrProtocol)
		}
	}
	return nil
}
func (r JournalResponse) Validate() error {
	if r.SchemaVersion != JournalSchemaVersion || r.Audience != JournalAudience || !journalID(r.RequestID) || !validDigest(r.RequestDigest) || len(r.Error) > 128 {
		return fmt.Errorf("%w: journal response", ErrProtocol)
	}
	if r.OK {
		if r.Error != "" || (r.Signature != "" && (len(r.Signature) != 64 || !hexString(r.Signature))) {
			return fmt.Errorf("%w: journal response", ErrProtocol)
		}
	} else if r.Error == "" || r.Signature != "" {
		return fmt.Errorf("%w: journal response", ErrProtocol)
	}
	return nil
}
func JournalFingerprint(r JournalRequest) string {
	b, _ := json.Marshal(r)
	s := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(s[:])
}
func JournalMarshal(v any) ([]byte, error) {
	b, e := json.Marshal(v)
	if e != nil || len(b) == 0 || len(b) > JournalMaxFrameSize {
		return nil, fmt.Errorf("%w: journal frame", ErrProtocol)
	}
	return b, nil
}
func DecodeJournalRequest(b []byte) (JournalRequest, error) {
	var r JournalRequest
	if len(b) == 0 || len(b) > JournalMaxFrameSize || duplicate(b) || !exactFields(b, "schema_version", "request_id", "audience", "operation", "run_id", "release_digest", "nonce", "payload_digest", "signature", "sequence") {
		return r, fmt.Errorf("%w: journal fields", ErrProtocol)
	}
	if json.Unmarshal(b, &r) != nil {
		return r, fmt.Errorf("%w: journal json", ErrProtocol)
	}
	c, _ := json.Marshal(r)
	if !bytes.Equal(b, c) || r.Validate() != nil {
		return r, fmt.Errorf("%w: journal canonical", ErrProtocol)
	}
	return r, nil
}
func journalID(s string) bool {
	if len(s) == 0 || len(s) > 128 {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
			return false
		}
	}
	return true
}
func hexString(s string) bool { _, e := hex.DecodeString(s); return e == nil }
