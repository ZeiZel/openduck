// Package platformcheckpoint is the independent monotonic checkpoint authority.
// It intentionally has no dependency on platformanchor: this boundary is a
// small generation/digest CAS, not a general RPC namespace. The authority is
// the ultimate monotonic root for this local state. Coordinated rollback by
// the root user or the checkpoint service principal is outside this package's
// threat model; other principals are excluded by exact OS ownership checks,
// and retained-secret tampering fails closed through authenticated metadata.
// Restoration of a prior mutually authentic state/meta pair by that
// privileged principal, even with the retained unchanged secret, is explicitly
// outside this package's threat model and is not claimed to be detectable.
package platformcheckpoint

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"regexp"
)

const SchemaVersion = "platform-checkpoint.v1"
const MaxFrameSize = 4096
const maxID = 128

var digestRE = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
var (
	ErrProtocol    = errors.New("platform checkpoint protocol error")
	ErrCAS         = errors.New("platform checkpoint compare-and-swap mismatch")
	ErrReplay      = errors.New("platform checkpoint request replay")
	ErrUnavailable = errors.New("platform checkpoint unavailable")
	ErrUncertain   = errors.New("platform checkpoint commit outcome uncertain")
	ErrPeer        = errors.New("platform checkpoint peer rejected")
)

type Request struct {
	SchemaVersion string `json:"schema_version"`
	RequestID     string `json:"request_id"`
	Operation     string `json:"operation"`
	Expected      uint64 `json:"expected"`
	Next          uint64 `json:"next"`
	Digest        string `json:"digest"`
}
type Response struct {
	SchemaVersion string `json:"schema_version"`
	RequestID     string `json:"request_id"`
	OK            bool   `json:"ok"`
	Generation    uint64 `json:"generation"`
	Digest        string `json:"digest"`
	Error         string `json:"error"`
}

func (r *Request) UnmarshalJSON(b []byte) error {
	if r == nil || duplicate(b) || !exactFields(b, "schema_version", "request_id", "operation", "expected", "next", "digest") {
		return fmt.Errorf("%w: request fields", ErrProtocol)
	}
	type plain Request
	var decoded plain
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(&decoded); err != nil {
		return fmt.Errorf("%w: request json", ErrProtocol)
	}
	canonical, err := json.Marshal(decoded)
	if err != nil || !bytes.Equal(b, canonical) {
		return fmt.Errorf("%w: request non-canonical", ErrProtocol)
	}
	*r = Request(decoded)
	return nil
}

func (r *Response) UnmarshalJSON(b []byte) error {
	if r == nil || duplicate(b) || !exactFields(b, "schema_version", "request_id", "ok", "generation", "digest", "error") {
		return fmt.Errorf("%w: response fields", ErrProtocol)
	}
	type plain Response
	var decoded plain
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(&decoded); err != nil {
		return fmt.Errorf("%w: response json", ErrProtocol)
	}
	canonical, err := json.Marshal(decoded)
	if err != nil || !bytes.Equal(b, canonical) {
		return fmt.Errorf("%w: response non-canonical", ErrProtocol)
	}
	*r = Response(decoded)
	return nil
}

func exactFields(b []byte, required ...string) bool {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(b, &fields); err != nil || len(fields) != len(required) {
		return false
	}
	for _, name := range required {
		if _, ok := fields[name]; !ok {
			return false
		}
	}
	return true
}

func validDigest(s string) bool { return digestRE.MatchString(s) }
func (r Request) validate() error {
	if r.SchemaVersion != SchemaVersion || r.RequestID == "" || len(r.RequestID) > maxID {
		return fmt.Errorf("%w: request", ErrProtocol)
	}
	if r.Operation == "load" {
		if r.Expected != 0 || r.Next != 0 || r.Digest != "" {
			return fmt.Errorf("%w: load", ErrProtocol)
		}
		return nil
	}
	if r.Operation != "cas" || r.Expected == math.MaxUint64 || r.Next != r.Expected+1 || !validDigest(r.Digest) {
		return fmt.Errorf("%w: cas", ErrProtocol)
	}
	return nil
}
func (r Response) validate() error {
	if r.SchemaVersion != SchemaVersion || r.RequestID == "" || len(r.RequestID) > maxID || len(r.Error) > 512 {
		return fmt.Errorf("%w: response", ErrProtocol)
	}
	if r.OK && r.Error != "" {
		return fmt.Errorf("%w: response error", ErrProtocol)
	}
	if r.OK && ((r.Generation == 0 && r.Digest != "") || (r.Generation > 0 && !validDigest(r.Digest))) {
		return fmt.Errorf("%w: response digest", ErrProtocol)
	}
	if !r.OK && (r.Generation != 0 || r.Digest != "" || r.Error == "") {
		return fmt.Errorf("%w: failed response", ErrProtocol)
	}
	return nil
}
func marshal(v any) ([]byte, error) {
	b, err := json.Marshal(v)
	if err != nil || len(b) > MaxFrameSize {
		return nil, fmt.Errorf("%w: frame", ErrProtocol)
	}
	return b, err
}
func decode(b []byte, v any) error {
	if len(b) == 0 || len(b) > MaxFrameSize || duplicate(b) {
		return fmt.Errorf("%w: frame", ErrProtocol)
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		return fmt.Errorf("%w: json", ErrProtocol)
	}
	var x any
	if d.Decode(&x) != io.EOF {
		return fmt.Errorf("%w: trailing", ErrProtocol)
	}
	canonical, err := json.Marshal(v)
	if err != nil || !bytes.Equal(b, canonical) {
		return fmt.Errorf("%w: non-canonical", ErrProtocol)
	}
	return nil
}
func duplicate(b []byte) bool {
	d := json.NewDecoder(bytes.NewReader(b))
	var walk func() bool
	walk = func() bool {
		t, e := d.Token()
		if e != nil {
			return true
		}
		if x, ok := t.(json.Delim); ok {
			if x == '{' {
				seen := map[string]bool{}
				for d.More() {
					k, e := d.Token()
					s, ok := k.(string)
					if e != nil || !ok || seen[s] {
						return true
					}
					seen[s] = true
					if walk() {
						return true
					}
				}
				_, e = d.Token()
				return e != nil
			}
			if x == '[' {
				for d.More() {
					if walk() {
						return true
					}
				}
				_, e = d.Token()
				return e != nil
			}
		}
		return false
	}
	return walk()
}
func WriteFrame(w io.Writer, v any) error {
	b, e := marshal(v)
	if e != nil {
		return e
	}
	var h [4]byte
	binary.BigEndian.PutUint32(h[:], uint32(len(b)))
	if e = writeFull(w, h[:]); e != nil {
		return e
	}
	return writeFull(w, b)
}

func writeFull(w io.Writer, b []byte) error {
	for len(b) > 0 {
		n, err := w.Write(b)
		if err != nil {
			return err
		}
		if n <= 0 || n > len(b) {
			return io.ErrShortWrite
		}
		b = b[n:]
	}
	return nil
}
func ReadFrame(r io.Reader, v any) error {
	var h [4]byte
	if _, e := io.ReadFull(r, h[:]); e != nil {
		return e
	}
	n := binary.BigEndian.Uint32(h[:])
	if n == 0 || n > MaxFrameSize {
		return fmt.Errorf("%w: frame", ErrProtocol)
	}
	b := make([]byte, n)
	if _, e := io.ReadFull(r, b); e != nil {
		return e
	}
	return decode(b, v)
}
func Fingerprint(r Request) string {
	b, _ := json.Marshal(r)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
