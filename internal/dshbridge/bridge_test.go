package dshbridge

import (
	"context"
	"errors"
	"testing"
	"time"
)

type classifierFunc func([]byte) (PrivacyClass, error)

func (f classifierFunc) Classify(b []byte) (PrivacyClass, error) { return f(b) }

type authoritySpy struct{ cloud, local []byte }

func (a *authoritySpy) AdmitCloud(_ context.Context, b []byte) (CloudAdmission, error) {
	a.cloud = append([]byte(nil), b...)
	return CloudAdmission{ID: "adm_12345678", Status: "pending"}, nil
}
func (a *authoritySpy) DispatchLocalPD(_ context.Context, b []byte) (LocalPDAdmission, error) {
	a.local = append([]byte(nil), b...)
	return LocalPDAdmission{Handle: "pd_12345678", Status: "queued"}, nil
}

func testStore(t *testing.T) *SessionStore {
	t.Helper()
	now := time.Unix(100, 0).UTC()
	s, err := NewSessionStore(Config{Origin: "http://127.0.0.1:3000", Host: "127.0.0.1:8788", Clock: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestSessionIsBoundToOriginNonceAndOneRequestNonce(t *testing.T) {
	s := testStore(t)
	session, err := s.Issue("client-1")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Authorize(session.Token, "client-1", "request-1", session.Origin, session.Host); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(s.Authorize(session.Token, "client-1", "request-1", session.Origin, session.Host), ErrReplay) {
		t.Fatal("replay was accepted")
	}
	if !errors.Is(s.Authorize(session.Token, "client-1", "request-2", "http://127.0.0.1:3001", session.Host), ErrUnauthorized) {
		t.Fatal("wrong origin was accepted")
	}
	if !errors.Is(s.Authorize(session.Token, "other", "request-3", session.Origin, session.Host), ErrUnauthorized) {
		t.Fatal("wrong client nonce was accepted")
	}
	if _, err := s.Issue("client-1"); !errors.Is(err, ErrReplay) {
		t.Fatalf("bootstrap nonce replay error=%v", err)
	}
}

func TestAuthorizePrincipalIsStableOpaqueAndNeverBearer(t *testing.T) {
	s := testStore(t)
	session, err := s.Issue("principal-client")
	if err != nil {
		t.Fatal(err)
	}
	principal, err := s.AuthorizePrincipal(session.Token, session.ClientNonce, "principal-request", session.Origin, session.Host)
	if err != nil {
		t.Fatal(err)
	}
	if principal.SessionID != session.SessionID || principal.ChannelID != session.ChannelID || principal.SessionID == session.Token || principal.ChannelID == session.Token {
		t.Fatalf("principal leaked or changed: %#v", principal)
	}
	ctx := WithUIPrincipal(context.Background(), principal)
	got, ok := PrincipalFromContext(ctx)
	if !ok || got != principal {
		t.Fatal("principal was not safely injected")
	}
	if _, err := s.AuthorizePrincipal(session.Token, session.ClientNonce, "principal-request", session.Origin, session.Host); !errors.Is(err, ErrReplay) {
		t.Fatal("principal request replay accepted")
	}
}

func TestSessionExpires(t *testing.T) {
	now := time.Unix(100, 0).UTC()
	s, err := NewSessionStore(Config{Origin: "http://127.0.0.1:3000", Host: "127.0.0.1:8788", SessionTTL: time.Second, Clock: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	session, err := s.Issue("client")
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(2 * time.Second)
	if err := s.Authorize(session.Token, "client", "req", session.Origin, session.Host); !errors.Is(err, ErrExpired) && !errors.Is(err, ErrUnauthorized) {
		t.Fatal("expired session was accepted")
	}
}

func TestRequestNonceIsReplayBlockedAfterRequestTTL(t *testing.T) {
	now := time.Unix(100, 0).UTC()
	s, err := NewSessionStore(Config{Origin: "http://127.0.0.1:3000", Host: "127.0.0.1:8788", SessionTTL: time.Minute, RequestTTL: time.Second, Clock: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	session, err := s.Issue("client")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Authorize(session.Token, "client", "once", session.Origin, session.Host); err != nil {
		t.Fatal(err)
	}
	now = now.Add(2 * time.Second)
	if !errors.Is(s.Authorize(session.Token, "client", "once", session.Origin, session.Host), ErrReplay) {
		t.Fatal("expired request nonce was reusable")
	}
}

func TestComposeNeverReturnsPayloadOrQwenOutput(t *testing.T) {
	a := &authoritySpy{}
	b := &Bridge{Classifier: classifierFunc(func([]byte) (PrivacyClass, error) { return ClassL2, nil }), Authority: a}
	result, err := b.Compose(context.Background(), []byte("private-sentinel"))
	if err != nil {
		t.Fatal(err)
	}
	if result.Route != "local_pd" || result.LocalPDHandle != "pd_12345678" || result.Status != "queued" {
		t.Fatalf("result=%+v", result)
	}
	if string(a.local) != "private-sentinel" || result.AdmissionID != "" {
		t.Fatalf("local boundary leaked or wrong route: result=%+v", result)
	}
	if string(a.cloud) != "" {
		t.Fatal("cloud authority was called for PD")
	}
}

func TestComposeCloudRouteIsOpaque(t *testing.T) {
	a := &authoritySpy{}
	b := &Bridge{Classifier: classifierFunc(func([]byte) (PrivacyClass, error) { return ClassL1, nil }), Authority: a}
	result, err := b.Compose(context.Background(), []byte("safe-sentinel"))
	if err != nil {
		t.Fatal(err)
	}
	if result.Route != "cloud" || result.AdmissionID != "adm_12345678" || result.LocalPDHandle != "" {
		t.Fatalf("result=%+v", result)
	}
}

func TestComposeRejectsNonOpaqueAuthorityIDsAndStatuses(t *testing.T) {
	b := &Bridge{Classifier: classifierFunc(func([]byte) (PrivacyClass, error) { return ClassL1, nil }), Authority: admissionWithCloud{}}
	if _, err := b.Compose(context.Background(), []byte("x")); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("invalid authority was accepted: %v", err)
	}
}

type admissionWithCloud struct{}

func (admissionWithCloud) AdmitCloud(context.Context, []byte) (CloudAdmission, error) {
	return CloudAdmission{ID: "private-sentinel", Status: "nope"}, nil
}
func (admissionWithCloud) DispatchLocalPD(context.Context, []byte) (LocalPDAdmission, error) {
	return LocalPDAdmission{}, nil
}
