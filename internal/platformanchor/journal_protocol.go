package platformanchor

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

const JournalSchemaVersion = "openduck.journal-anchor.v1"
const JournalAudience = "installer-journal"

type JournalRequest struct {
	SchemaVersion    string `json:"schema_version"`
	RequestID        string `json:"request_id"`
	Audience         string `json:"audience"`
	Operation        string `json:"operation"`
	RunID            string `json:"run_id"`
	ReleaseDigest    string `json:"release_digest"`
	Nonce            string `json:"nonce"`
	ExpectedSequence uint64 `json:"expected_sequence"`
	NextSequence     uint64 `json:"next_sequence"`
	ExpectedDigest   string `json:"expected_digest"`
	NextDigest       string `json:"next_digest"`
}
type JournalResponse struct {
	SchemaVersion string `json:"schema_version"`
	RequestID     string `json:"request_id"`
	Audience      string `json:"audience"`
	OK            bool   `json:"ok"`
	Sequence      uint64 `json:"sequence"`
	Digest        string `json:"digest"`
	Error         string `json:"error"`
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
func (r JournalRequest) validate() error {
	if r.SchemaVersion != JournalSchemaVersion || r.Audience != JournalAudience || !journalID(r.RequestID) || !journalID(r.RunID) || !journalID(r.Nonce) || !digestPattern.MatchString(r.ReleaseDigest) {
		return ErrProtocol
	}
	if r.Operation == "load" {
		if r.ExpectedSequence != 0 || r.NextSequence != 0 || r.ExpectedDigest != "" || r.NextDigest != "" {
			return ErrProtocol
		}
		return nil
	}
	if r.Operation != "cas" || r.ExpectedSequence == ^uint64(0) || r.NextSequence != r.ExpectedSequence+1 || !digestPattern.MatchString(r.NextDigest) || (r.ExpectedSequence == 0 && r.ExpectedDigest != "") || (r.ExpectedSequence > 0 && !digestPattern.MatchString(r.ExpectedDigest)) {
		return ErrProtocol
	}
	return nil
}
func (r JournalResponse) validate() error {
	if r.SchemaVersion != JournalSchemaVersion || r.Audience != JournalAudience || !journalID(r.RequestID) || len(r.Error) > 128 {
		return ErrProtocol
	}
	if r.OK {
		if r.Error != "" || (r.Sequence == 0 && r.Digest != "") || (r.Sequence > 0 && !digestPattern.MatchString(r.Digest)) {
			return ErrProtocol
		}
	} else if r.Error != ErrCAS.Error() && r.Error != ErrReplay.Error() && r.Error != ErrUnavailable.Error() && r.Error != ErrProtocol.Error() {
		return ErrProtocol
	}
	return nil
}
func journalFingerprint(r JournalRequest) string {
	b, _ := json.Marshal(r)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
func (r *JournalRequest) UnmarshalJSON(b []byte) error {
	if r == nil || duplicateKeys(b) || !journalFields(b, "schema_version", "request_id", "audience", "operation", "run_id", "release_digest", "nonce", "expected_sequence", "next_sequence", "expected_digest", "next_digest") {
		return ErrProtocol
	}
	type plain JournalRequest
	var x plain
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(&x) != nil {
		return ErrProtocol
	}
	c, _ := json.Marshal(x)
	if !bytes.Equal(b, c) || JournalRequest(x).validate() != nil {
		return ErrProtocol
	}
	*r = JournalRequest(x)
	return nil
}
func (r *JournalResponse) UnmarshalJSON(b []byte) error {
	if r == nil || duplicateKeys(b) || !journalFields(b, "schema_version", "request_id", "audience", "ok", "sequence", "digest", "error") {
		return ErrProtocol
	}
	type plain JournalResponse
	var x plain
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(&x) != nil {
		return ErrProtocol
	}
	c, _ := json.Marshal(x)
	if !bytes.Equal(b, c) || JournalResponse(x).validate() != nil {
		return ErrProtocol
	}
	*r = JournalResponse(x)
	return nil
}
func journalFields(b []byte, names ...string) bool {
	var m map[string]json.RawMessage
	if json.Unmarshal(b, &m) != nil || len(m) != len(names) {
		return false
	}
	for _, n := range names {
		if _, ok := m[n]; !ok {
			return false
		}
	}
	return true
}
func journalKey(run, release string) string {
	h := sha256.Sum256([]byte("openduck.journal-anchor.v1\x00" + run + "\x00" + release))
	return "journal_" + hex.EncodeToString(h[:])
}
func journalRequestID(r JournalRequest) string {
	h := sha256.Sum256([]byte("openduck.journal-anchor.request.v1\x00" + r.RunID + "\x00" + r.ReleaseDigest + "\x00" + r.RequestID))
	return "journal_" + hex.EncodeToString(h[:])
}
