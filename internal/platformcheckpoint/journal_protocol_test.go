package platformcheckpoint

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestJournalRequestClosedCanonical(t *testing.T) {
	r := JournalRequest{SchemaVersion: JournalSchemaVersion, RequestID: "request-1", Audience: JournalAudience, Operation: "sign", RunID: "run-0001", ReleaseDigest: "sha256:" + strings.Repeat("a", 64), Nonce: "nonce-01", PayloadDigest: "sha256:" + strings.Repeat("b", 64), Sequence: 1}
	b, e := JournalMarshal(r)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = DecodeJournalRequest(b); e != nil {
		t.Fatal(e)
	}
	if _, e = DecodeJournalRequest(append(b, []byte(" ")...)); e == nil {
		t.Fatal("trailing accepted")
	}
	r.Audience = "bad"
	if e = r.Validate(); e == nil {
		t.Fatal("audience accepted")
	}
}

func journalRequest(id, op string) JournalRequest {
	return JournalRequest{SchemaVersion: JournalSchemaVersion, RequestID: id, Audience: JournalAudience, Operation: op, RunID: "run-0001", ReleaseDigest: "sha256:" + strings.Repeat("a", 64), Nonce: "nonce-01", PayloadDigest: "sha256:" + strings.Repeat("b", 64), Sequence: 1}
}

func TestJournalStoreDurableReplayAndBindings(t *testing.T) {
	d := privateDir(t)
	s, err := NewStore(d)
	if err != nil {
		t.Fatal(err)
	}
	sign := journalRequest("sign-1", "sign")
	sig, err := s.JournalSign(sign)
	if err != nil || len(sig) != 64 {
		t.Fatalf("sign=(%q,%v)", sig, err)
	}
	if again, err := s.JournalSign(sign); err != nil || again != sig {
		t.Fatalf("replay=(%q,%v)", again, err)
	}
	for _, mutate := range []func(*JournalRequest){
		func(r *JournalRequest) { r.RunID = "run-0002" },
		func(r *JournalRequest) { r.ReleaseDigest = "sha256:" + strings.Repeat("c", 64) },
		func(r *JournalRequest) { r.Sequence++ },
		func(r *JournalRequest) { r.Nonce = "nonce-02" },
		func(r *JournalRequest) { r.PayloadDigest = "sha256:" + strings.Repeat("d", 64) },
	} {
		changed := sign
		mutate(&changed)
		if _, err := s.JournalSign(changed); !errors.Is(err, ErrReplay) {
			t.Fatalf("binding err=%v", err)
		}
	}
	verify := sign
	verify.RequestID, verify.Operation, verify.Signature = "verify-1", "verify", sig
	if err := s.JournalVerify(verify); err != nil {
		t.Fatalf("verify=%v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = NewStore(d)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if again, err := s.JournalSign(sign); err != nil || again != sig {
		t.Fatalf("restart replay=(%q,%v)", again, err)
	}
	if err := s.JournalVerify(verify); err != nil {
		t.Fatalf("restart verify=%v", err)
	}
}

func TestJournalStoreBadSignatureIsDurableAndConflictingReplayFailsClosed(t *testing.T) {
	d := privateDir(t)
	s, err := NewStore(d)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	bad := journalRequest("verify-bad", "verify")
	bad.Signature = strings.Repeat("0", 64)
	if err := s.JournalVerify(bad); !errors.Is(err, ErrReplay) {
		t.Fatalf("bad signature=%v", err)
	}
	if err := s.JournalVerify(bad); !errors.Is(err, ErrReplay) {
		t.Fatalf("bad replay=%v", err)
	}
	conflict := bad
	conflict.Signature = strings.Repeat("1", 64)
	if err := s.JournalVerify(conflict); !errors.Is(err, ErrReplay) {
		t.Fatalf("conflict=%v", err)
	}
}

func TestJournalStoreLedgerBoundIsDurable(t *testing.T) {
	s, err := NewStore(privateDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	// Build a full valid ledger in one durable transaction. This keeps the test
	// fast while exercising the on-disk bound and reload validator.
	err = s.withLock(func(st *diskState) error {
		for i := 0; i < retained; i++ {
			id := "entry-" + fmt.Sprintf("%04d", i)
			r := journalRequest(id, "sign")
			st.JournalRequests[id] = journalReplay{Fingerprint: JournalFingerprint(r), Response: JournalResponse{SchemaVersion: JournalSchemaVersion, RequestID: id, Audience: JournalAudience, RequestDigest: JournalFingerprint(r), OK: true, Signature: s.journalMAC(r)}}
			st.JournalOrder = append(st.JournalOrder, id)
		}
		return nil
	}, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Load(); err != nil {
		t.Fatalf("bounded reload=%v", err)
	}
}

func TestJournalRequestRejectsMalformedVariants(t *testing.T) {
	base := `{"schema_version":"openduck.journal-checkpoint.v1","request_id":"request-1","audience":"installer-journal","operation":"verify","run_id":"run-0001","release_digest":"sha256:` + strings.Repeat("a", 64) + `","nonce":"nonce-01","payload_digest":"sha256:` + strings.Repeat("b", 64) + `","signature":"` + strings.Repeat("c", 64) + `","sequence":1}`
	for _, raw := range []string{base + " ", strings.Replace(base, `"audience":"installer-journal"`, `"audience":"bad"`, 1), strings.Replace(base, `"operation":"verify"`, `"operation":"bad"`, 1), strings.Replace(base, `"nonce":"nonce-01"`, `"nonce":""`, 1), strings.Replace(base, `"signature":"`+strings.Repeat("c", 64)+`"`, `"signature":"bad"`, 1), strings.Replace(base, `"request_id":"request-1"`, `"request_id":"request-1","request_id":"two"`, 1), strings.Replace(base, `}`, `,"unknown":1}`, 1)} {
		if _, err := DecodeJournalRequest([]byte(raw)); err == nil {
			t.Fatalf("accepted %s", raw)
		}
	}
	if _, err := DecodeJournalRequest(make([]byte, JournalMaxFrameSize+1)); err == nil {
		t.Fatal("oversize accepted")
	}
}
