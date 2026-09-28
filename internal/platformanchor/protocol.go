// Package platformanchor contains the synthetic seam for the DR-020 platform
// checkpoint authority. It deliberately has no launchd, credential, or network
// installation code. The production constructor remains sealed until a real
// independently-owned service principal is implemented.
package platformanchor

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
)

const (
	SchemaVersion            = "platform-anchor.v1"
	NamespaceAdmission       = "admission"
	NamespaceChat            = "chat"
	NamespaceRuntimeLease    = "runtime-lease"
	journalInternalNamespace = "\x01installer-journal"
	MaxFrameSize             = 64 * 1024
	maxDigestSize            = 71
)

var digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

var (
	ErrProtocol         = errors.New("platform anchor protocol error")
	ErrUnknownNamespace = errors.New("platform anchor unknown namespace")
	ErrReplay           = errors.New("platform anchor request replay")
	ErrCAS              = errors.New("platform anchor compare-and-swap mismatch")
	ErrPeer             = errors.New("platform anchor peer attestation failed")
	ErrUncertain        = errors.New("platform anchor commit outcome uncertain")
	ErrUnavailable      = errors.New("platform anchor unavailable")
	ErrProductionSealed = errors.New("platform anchor production constructor is sealed")
)

type Request struct {
	SchemaVersion   string `json:"schema_version"`
	RequestID       string `json:"request_id"`
	Namespace       string `json:"namespace"`
	Operation       string `json:"operation"`
	Key             string `json:"key"`
	ExpectedVersion uint64 `json:"expected_version"`
	NextVersion     uint64 `json:"next_version"`
	Digest          string `json:"digest"`
}

type Response struct {
	SchemaVersion string `json:"schema_version"`
	RequestID     string `json:"request_id"`
	OK            bool   `json:"ok"`
	Namespace     string `json:"namespace"`
	Version       uint64 `json:"version"`
	Digest        string `json:"digest,omitempty"`
	Error         string `json:"error,omitempty"`
}

func (r Request) validate() error {
	if r.SchemaVersion != SchemaVersion || r.RequestID == "" || len(r.RequestID) > 128 || r.Key == "" || len(r.Key) > 256 || r.Operation != "load" && r.Operation != "cas" {
		return fmt.Errorf("%w: invalid request", ErrProtocol)
	}
	if !validNamespace(r.Namespace) {
		return ErrUnknownNamespace
	}
	if r.Operation == "cas" && (r.NextVersion != r.ExpectedVersion+1 || !digestPattern.MatchString(r.Digest)) {
		return fmt.Errorf("%w: invalid cas", ErrProtocol)
	}
	if r.Operation == "load" && (r.ExpectedVersion != 0 || r.NextVersion != 0 || r.Digest != "") {
		return fmt.Errorf("%w: invalid load", ErrProtocol)
	}
	return nil
}
func (r Response) validate() error {
	if r.SchemaVersion != SchemaVersion || r.RequestID == "" || len(r.RequestID) > 128 || !validNamespace(r.Namespace) {
		return fmt.Errorf("%w: invalid response", ErrProtocol)
	}
	if len(r.Error) > 512 {
		return fmt.Errorf("%w: response error too long", ErrProtocol)
	}
	if r.OK && r.Error != "" {
		return fmt.Errorf("%w: successful response has error", ErrProtocol)
	}
	if r.OK && ((r.Version == 0 && r.Digest != "") || (r.Version > 0 && !digestPattern.MatchString(r.Digest))) {
		return fmt.Errorf("%w: invalid response checkpoint", ErrProtocol)
	}
	if !r.OK && r.Error == "" {
		return fmt.Errorf("%w: failed response missing error", ErrProtocol)
	}
	if !r.OK && (r.Version != 0 || r.Digest != "") {
		return fmt.Errorf("%w: failed response carries checkpoint", ErrProtocol)
	}
	return nil
}
func validNamespace(n string) bool {
	return n == NamespaceAdmission || n == NamespaceChat || n == NamespaceRuntimeLease
}
func validStoredNamespace(n string) bool { return validNamespace(n) || n == journalInternalNamespace }

func encodeJSON(v any) ([]byte, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	if len(b) > MaxFrameSize {
		return nil, fmt.Errorf("%w: frame too large", ErrProtocol)
	}
	return b, nil
}
func decodeJSON(b []byte, v any) error {
	if len(b) == 0 || len(b) > MaxFrameSize {
		return fmt.Errorf("%w: frame size", ErrProtocol)
	}
	if duplicateKeys(b) {
		return fmt.Errorf("%w: duplicate json key", ErrProtocol)
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		return fmt.Errorf("%w: json: %v", ErrProtocol, err)
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return fmt.Errorf("%w: trailing json", ErrProtocol)
	}
	// json.Decoder passes a trimmed copy of a value to UnmarshalJSON.  Checking
	// the original framed bytes here is therefore necessary: otherwise a
	// JournalRequest with trailing whitespace is accepted even though the
	// request's own canonical decoder rejects non-canonical input.  Re-marshal
	// also preserves intentional `omitempty` fields while rejecting alternate
	// spellings, field orders, and explicit empty optional fields.
	canonical, err := encodeJSON(v)
	if err != nil || !bytes.Equal(b, canonical) {
		return fmt.Errorf("%w: non-canonical json", ErrProtocol)
	}
	return nil
}

func duplicateKeys(b []byte) bool {
	d := json.NewDecoder(bytes.NewReader(b))
	var walk func() bool
	walk = func() bool {
		tok, err := d.Token()
		if err != nil {
			return true
		}
		if delim, ok := tok.(json.Delim); ok {
			if delim == '{' {
				seen := map[string]bool{}
				for d.More() {
					kt, kerr := d.Token()
					k, ok := kt.(string)
					if kerr != nil {
						return true
					}
					if !ok || seen[k] {
						return true
					}
					seen[k] = true
					if walk() {
						return true
					}
				}
				_, err = d.Token()
				return err != nil
			}
			if delim == '[' {
				for d.More() {
					if walk() {
						return true
					}
				}
				_, err = d.Token()
				return err != nil
			}
		}
		return false
	}
	return walk()
}

// WriteFrame writes a bounded big-endian uint32 length followed by canonical
// JSON. A single frame is the only unit accepted by the synthetic transport.
func WriteFrame(w io.Writer, v any) error {
	b, err := encodeJSON(v)
	if err != nil {
		return err
	}
	var h [4]byte
	binary.BigEndian.PutUint32(h[:], uint32(len(b)))
	if _, err = w.Write(h[:]); err != nil {
		return err
	}
	_, err = w.Write(b)
	return err
}
func ReadFrame(r io.Reader, v any) error {
	var h [4]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return err
	}
	n := binary.BigEndian.Uint32(h[:])
	if n == 0 || n > MaxFrameSize {
		return fmt.Errorf("%w: frame size", ErrProtocol)
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		return err
	}
	return decodeJSON(b, v)
}
