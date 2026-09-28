package platformanchor

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

func journalStoreRequest(id, nonce string, old, next uint64, oldD, newD string) JournalRequest {
	return JournalRequest{SchemaVersion: JournalSchemaVersion, RequestID: id, Audience: JournalAudience, Operation: "cas", RunID: "run-1", ReleaseDigest: "sha256:" + strings.Repeat("a", 64), Nonce: nonce, ExpectedSequence: old, NextSequence: next, ExpectedDigest: oldD, NextDigest: newD}
}
func TestJournalStoreExactCASReplayAndRestart(t *testing.T) {
	d := filepath.Join(t.TempDir(), "state")
	cp := NewTestMonotonicCheckpoint()
	s, e := NewSyntheticStoreWithCheckpoint(d, cp)
	if e != nil {
		t.Fatal(e)
	}
	r := journalStoreRequest("id-1", "nonce-1", 0, 1, "", "sha256:"+strings.Repeat("b", 64))
	if _, e = s.journalRequest(r); e != nil {
		t.Fatal(e)
	}
	if _, e = s.journalRequest(r); e != nil {
		t.Fatal(e)
	}
	stale := journalStoreRequest("id-2", "nonce-2", 1, 2, "sha256:"+strings.Repeat("c", 64), "sha256:"+strings.Repeat("d", 64))
	if _, e = s.journalRequest(stale); !errors.Is(e, ErrCAS) {
		t.Fatalf("digest=%v", e)
	}
	conflict := r
	conflict.Nonce = "nonce-3"
	if _, e = s.journalRequest(conflict); !errors.Is(e, ErrReplay) {
		t.Fatalf("replay=%v", e)
	}
	_ = s.Close()
	s, e = NewSyntheticStoreWithCheckpoint(d, cp)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	if _, e = s.journalRequest(r); e != nil {
		t.Fatalf("restart=%v", e)
	}
}
func TestPublicProtocolCannotAddressJournal(t *testing.T) {
	d := filepath.Join(t.TempDir(), "state")
	s, err := NewSyntheticStoreWithCheckpoint(d, NewTestMonotonicCheckpoint())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	r := journalStoreRequest("id-1", "nonce-1", 0, 1, "", "sha256:"+strings.Repeat("b", 64))
	if _, err = s.journalRequest(r); err != nil {
		t.Fatal(err)
	}
	for _, generic := range []Request{
		{SchemaVersion: SchemaVersion, RequestID: journalRequestID(r), Namespace: journalInternalNamespace, Operation: "load", Key: journalKey(r.RunID, r.ReleaseDigest)},
		{SchemaVersion: SchemaVersion, RequestID: "other", Namespace: journalInternalNamespace, Operation: "cas", Key: journalKey(r.RunID, r.ReleaseDigest), ExpectedVersion: 1, NextVersion: 2, Digest: "sha256:" + strings.Repeat("c", 64)},
	} {
		if _, err := s.Request(generic); !errors.Is(err, ErrUnknownNamespace) {
			t.Fatalf("request err=%v", err)
		}
	}
	got, err := s.journalRequest(JournalRequest{SchemaVersion: JournalSchemaVersion, RequestID: "load-1", Audience: JournalAudience, Operation: "load", RunID: r.RunID, ReleaseDigest: r.ReleaseDigest, Nonce: "nonce-2"})
	if err != nil || got.Sequence != 1 || got.Digest != r.NextDigest {
		t.Fatalf("state=%+v err=%v", got, err)
	}
}

func TestJournalProtocolClosedSchema(t *testing.T) {
	r := JournalRequest{SchemaVersion: JournalSchemaVersion, RequestID: "r1", Audience: JournalAudience, Operation: "load", RunID: "run", ReleaseDigest: "sha256:" + strings.Repeat("a", 64), Nonce: "n1"}
	b, err := encodeJSON(r)
	if err != nil {
		t.Fatal(err)
	}
	var decoded JournalRequest
	if err = decodeJSON(b, &decoded); err != nil {
		t.Fatal(err)
	}
	for _, raw := range [][]byte{append(b, ' '), []byte(`{"schema_version":"openduck.journal-anchor.v1","request_id":"r1","request_id":"r2","audience":"installer-journal","operation":"load","run_id":"run","release_digest":"sha256:` + strings.Repeat("a", 64) + `","nonce":"n1","expected_sequence":0,"next_sequence":0,"expected_digest":"","next_digest":""}`), []byte(`{"schema_version":"openduck.journal-anchor.v1","request_id":"r1","audience":"bad","operation":"load","run_id":"run","release_digest":"sha256:` + strings.Repeat("a", 64) + `","nonce":"n1","expected_sequence":0,"next_sequence":0,"expected_digest":"","next_digest":""}`)} {
		if err = decodeJSON(raw, &decoded); !errors.Is(err, ErrProtocol) {
			t.Fatalf("raw=%s err=%v", raw, err)
		}
	}
}

func TestCanonicalDecoderPreservesIntentionalOmitEmpty(t *testing.T) {
	response := Response{SchemaVersion: SchemaVersion, RequestID: "response-1", Namespace: NamespaceChat, OK: true}
	b, err := encodeJSON(response)
	if err != nil {
		t.Fatal(err)
	}
	var decoded Response
	if err := decodeJSON(b, &decoded); err != nil {
		t.Fatalf("canonical omitted response: %v", err)
	}
	if err := decodeJSON([]byte(`{"schema_version":"platform-anchor.v1","request_id":"response-1","ok":true,"namespace":"chat","version":0,"digest":"","error":""}`), &decoded); !errors.Is(err, ErrProtocol) {
		t.Fatalf("explicit empty optional fields err=%v", err)
	}
}
