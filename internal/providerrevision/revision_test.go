package providerrevision

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"openduck/internal/providerbridge"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type testAuthority struct{}

func (testAuthority) Authorize(context.Context, Operation) error { return nil }

type testTrustSource struct{}

func (testTrustSource) Current(context.Context, string) (providerbridge.Ed25519TrustBundle, error) {
	return providerbridge.Ed25519TrustBundle{}, nil
}

func TestDecodeRejectsIncompleteAliasAndDuplicateBundles(t *testing.T) {
	b := Bundle{SchemaVersion: BundleV1, BundleID: "bundle-test", RevisionID: "revision-test", TrustBundleDigest: "sha256:0000000000000000000000000000000000000000000000000000000000000000"}
	if err := b.Seal(); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Decode(raw); err == nil {
		t.Fatal("incomplete bundle accepted")
	}
	if _, err := Decode([]byte(`{"schema_version":"controller-provider-bundle.v1","schema_version":"controller-provider-bundle.v1"}`)); err == nil {
		t.Fatal("duplicate key accepted")
	}
	if _, err := Decode([]byte(`{"SchemaVersion":"controller-provider-bundle.v1"}`)); err == nil {
		t.Fatal("Go field alias accepted")
	}
}

func TestValidateBundleRequiresExplicitValidationInstant(t *testing.T) {
	bundle := Bundle{SchemaVersion: BundleV1, BundleID: "bundle-test", RevisionID: "revision-test", TrustBundleDigest: "sha256:0000000000000000000000000000000000000000000000000000000000000000"}
	if err := bundle.Seal(); err != nil {
		t.Fatal(err)
	}
	if err := ValidateBundle(bundle, providerbridge.Ed25519TrustBundle{}, time.Time{}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("zero validation time err=%v, want invalid", err)
	}
	if err := ValidateBundle(bundle, providerbridge.Ed25519TrustBundle{}, time.Unix(1_700_000_000, 0).UTC()); !errors.Is(err, ErrInvalid) {
		t.Fatalf("malformed bundle/trust err=%v, want invalid", err)
	}
}

func TestFixedLeafSignedLifecycleOperationRejectsSubstitution(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0750); err != nil {
		t.Fatal(err)
	}
	pub, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	trust := OwnerTrust{SchemaVersion: "controller-owner-ed25519.v1", KeyID: "owner-1", PublicKey: hex.EncodeToString(pub)}
	trustRaw, _ := json.Marshal(trust)
	now := time.Now().UTC()
	op := ProviderLifecycleOperation{SchemaVersion: ProviderLifecycleOperationV1, Purpose: lifecyclePurpose, Action: "install", RevisionID: "revision-1", BundleDigest: "sha256:0000000000000000000000000000000000000000000000000000000000000000", TrustDigest: "sha256:1111111111111111111111111111111111111111111111111111111111111111", BaseVersion: 1, BaseCurrentRevision: "current-1", DecisionID: "decision-1", Nonce: "nonce-1", KeyID: "owner-1", IssuedAt: now, ExpiresAt: now.Add(time.Minute)}
	op.Seal()
	op.Signature = hex.EncodeToString(ed25519.Sign(private, []byte(op.Digest)))
	opRaw, _ := json.Marshal(op)
	if err := os.WriteFile(filepath.Join(root, "owner.json"), trustRaw, 0440); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "operation.json"), opRaw, 0440); err != nil {
		t.Fatal(err)
	}
	c := OperationLoadConfig{RootPath: root, OperationLeaf: "operation.json", OwnerTrustLeaf: "owner.json", ExpectedOwnerTrustDigest: digestBytes(trustRaw), OwnerUID: uint32(os.Geteuid()), OwnerGID: uint32(os.Getegid())}
	if got, err := LoadLifecycleOperation(c, now); err != nil || got.Nonce != op.Nonce {
		t.Fatalf("load=%#v err=%v", got, err)
	}
	for _, aliasField := range []struct{ canonical, alias string }{
		{`"schema_version"`, `"SchemaVersion"`},
		{`"base_version"`, `"BaseVersion"`},
		{`"base_current_revision"`, `"BaseCurrentRevision"`},
		{`"endpoint_expires_at"`, `"EndpointExpiresAt"`},
	} {
		alias := bytes.Replace(opRaw, []byte(aliasField.canonical), []byte(aliasField.alias), 1)
		if _, err := DecodeLifecycleOperation(alias); err == nil {
			t.Fatalf("Go-name operation alias %s accepted", aliasField.alias)
		}
	}
	op.Signature = "00"
	bad, _ := json.Marshal(op)
	if err := os.Chmod(filepath.Join(root, "operation.json"), 0640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "operation.json"), bad, 0440); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadLifecycleOperation(c, now); err == nil {
		t.Fatal("bad signature accepted")
	}
}

func TestFixedLeafRequiresExactExpectedGID(t *testing.T) {
	rootPath := t.TempDir()
	if err := os.Chmod(rootPath, 0750); err != nil {
		t.Fatal(err)
	}
	leaf := filepath.Join(rootPath, "owner.json")
	raw := []byte(`{"schema_version":"controller-owner-ed25519.v1"}`)
	if err := os.WriteFile(leaf, raw, 0440); err != nil {
		t.Fatal(err)
	}
	uid, gid := uint32(os.Geteuid()), uint32(os.Getegid())
	wrongGID := differentTestID(gid)
	info, err := os.Lstat(leaf)
	if err != nil {
		t.Fatal(err)
	}
	if !safeFile(info, uid, gid) {
		t.Fatal("fixed leaf was not accepted for its exact owner group")
	}
	if safeFile(info, uid, wrongGID) {
		t.Fatal("fixed leaf accepted a mismatched owner group")
	}
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if _, err := secureRead(root, "owner.json", uid, wrongGID, maxTrustBytes); err == nil {
		t.Fatal("secure read accepted a mismatched owner group")
	}

	digest := digestBytes(raw)
	if _, err := (ArtifactTrustSource{RootPath: rootPath, TrustLeaf: "owner.json", ExpectedDigest: digest, OwnerUID: uid, OwnerGID: wrongGID}).Current(context.Background(), digest); err == nil {
		t.Fatal("artifact trust source accepted a mismatched owner group")
	}
	if _, err := LoadLifecycleOperation(OperationLoadConfig{RootPath: rootPath, OperationLeaf: "operation.json", OwnerTrustLeaf: "owner.json", ExpectedOwnerTrustDigest: digest, OwnerUID: uid, OwnerGID: wrongGID}, time.Now().UTC()); err == nil {
		t.Fatal("lifecycle loader accepted a mismatched owner group")
	}
	if _, _, err := Load(LoadConfig{RootPath: rootPath, ManifestLeaf: "bundle.json", TrustLeaf: "owner.json", ExpectedBundleDigest: testDigest("a"), ExpectedTrustDigest: digest, OwnerUID: uid, OwnerGID: wrongGID}, time.Now().UTC()); err == nil {
		t.Fatal("bundle loader accepted a mismatched owner group")
	}
}

func TestOperationValidityWindowRejectsFutureIssuedAt(t *testing.T) {
	now := time.Date(2026, time.August, 26, 14, 0, 0, 0, time.UTC)
	legacy := Operation{SchemaVersion: "provider-revision-operation.v1", Action: "install", RevisionID: "revision-1", BundleDigest: testDigest("a"), TrustDigest: testDigest("b"), BaseVersion: 0, ExpectedVersion: 1, Nonce: "legacy-nonce", PayloadDigest: testDigest("c"), ApprovalID: "approval-1", IssuedAt: now, ExpiresAt: now.Add(time.Minute)}
	legacy.Seal()
	if !legacy.valid(now) {
		t.Fatal("legacy operation rejected at issued_at boundary")
	}
	legacy.IssuedAt = now.Add(time.Nanosecond)
	legacy.ExpiresAt = legacy.IssuedAt.Add(time.Minute)
	legacy.Seal()
	if legacy.valid(now) {
		t.Fatal("legacy future-issued operation accepted")
	}
	legacy.IssuedAt = now.Add(-time.Minute)
	legacy.ExpiresAt = now
	legacy.Seal()
	if legacy.valid(now) {
		t.Fatal("legacy operation accepted at expires_at boundary")
	}

	signed := testLifecycleOperation("install", now)
	if !signed.valid(now) {
		t.Fatal("signed operation rejected at issued_at boundary")
	}
	signed.IssuedAt = now.Add(time.Nanosecond)
	signed.ExpiresAt = signed.IssuedAt.Add(time.Minute)
	sealTestLifecycleOperation(&signed)
	if signed.valid(now) {
		t.Fatal("signed future-issued operation accepted")
	}
	signed = testLifecycleOperation("install", now)
	signed.IssuedAt = now.Add(-time.Minute)
	signed.ExpiresAt = now
	sealTestLifecycleOperation(&signed)
	if signed.valid(now) {
		t.Fatal("signed operation accepted at expires_at boundary")
	}
}

func TestProviderLifecycleOperationActionFieldMatrix(t *testing.T) {
	now := time.Date(2026, time.August, 26, 12, 0, 0, 0, time.UTC)
	actions := []string{"install", "activate", "profile-enable", "profile-disable", "ui-register", "ui-bind", "ui-revoke", "ui-rotate", "root-close"}
	for _, action := range actions {
		t.Run(action+"/valid", func(t *testing.T) {
			if !testLifecycleOperation(action, now).valid(now) {
				t.Fatalf("valid %s operation rejected", action)
			}
		})
	}

	installWithCurrent := testLifecycleOperation("install", now)
	installWithCurrent.BaseVersion = 7
	installWithCurrent.BaseCurrentRevision = "current-1"
	sealTestLifecycleOperation(&installWithCurrent)
	if !installWithCurrent.valid(now) {
		t.Fatal("install against a non-empty exact base was rejected")
	}

	for _, action := range actions {
		action := action
		t.Run(action+"/base", func(t *testing.T) {
			op := testLifecycleOperation(action, now)
			if action == "install" {
				op.BaseCurrentRevision = "current-1"
				sealTestLifecycleOperation(&op)
				if op.valid(now) {
					t.Fatal("initial install accepted a current revision")
				}
				op = testLifecycleOperation(action, now)
				op.BaseVersion = 7
				sealTestLifecycleOperation(&op)
				if op.valid(now) {
					t.Fatal("non-empty install base omitted current revision")
				}
				return
			}
			op.BaseVersion = 0
			sealTestLifecycleOperation(&op)
			if op.valid(now) {
				t.Fatal("non-install accepted an empty base version")
			}
			op = testLifecycleOperation(action, now)
			op.BaseCurrentRevision = ""
			sealTestLifecycleOperation(&op)
			if action == "activate" {
				if !op.valid(now) {
					t.Fatal("first activation rejected an exact empty current binding")
				}
				return
			}
			if op.valid(now) {
				t.Fatal("non-activation omitted its current revision binding")
			}
		})
	}

	for _, action := range []string{"install", "activate", "profile-enable", "profile-disable"} {
		action := action
		for _, field := range []struct {
			name  string
			apply func(*ProviderLifecycleOperation)
		}{
			{"session_id", func(o *ProviderLifecycleOperation) { o.SessionID = "session-foreign" }},
			{"channel_id", func(o *ProviderLifecycleOperation) { o.ChannelID = "channel-foreign" }},
			{"root_run_id", func(o *ProviderLifecycleOperation) { o.RootRunID = "root-foreign" }},
			{"run_id", func(o *ProviderLifecycleOperation) { o.RunID = "run-foreign" }},
			{"mesh_session_id", func(o *ProviderLifecycleOperation) { o.MeshSessionID = "mesh-foreign" }},
			{"attempt_id", func(o *ProviderLifecycleOperation) { o.AttemptID = "attempt-foreign" }},
			{"peer_id", func(o *ProviderLifecycleOperation) { o.PeerID = "peer-foreign" }},
			{"endpoint_id", func(o *ProviderLifecycleOperation) { o.EndpointID = "endpoint-foreign" }},
			{"endpoint_generation", func(o *ProviderLifecycleOperation) { o.EndpointGeneration = 1 }},
			{"association_digest", func(o *ProviderLifecycleOperation) { o.AssociationDigest = testDigest("c") }},
			{"endpoint_expires_at", func(o *ProviderLifecycleOperation) { o.EndpointExpiresAt = now.Add(time.Minute) }},
		} {
			field := field
			t.Run(action+"/rejects-"+field.name, func(t *testing.T) {
				op := testLifecycleOperation(action, now)
				field.apply(&op)
				sealTestLifecycleOperation(&op)
				if op.valid(now) {
					t.Fatalf("%s accepted foreign %s", action, field.name)
				}
			})
		}
	}

	for _, action := range []string{"install", "activate", "ui-register", "ui-bind", "ui-revoke", "ui-rotate", "root-close"} {
		action := action
		for _, field := range []struct {
			name  string
			apply func(*ProviderLifecycleOperation)
		}{
			{"profile_id", func(o *ProviderLifecycleOperation) { o.ProfileID = "profile-foreign" }},
			{"profile_revision", func(o *ProviderLifecycleOperation) { o.ProfileRevision = "profile-revision-foreign" }},
		} {
			field := field
			t.Run(action+"/rejects-"+field.name, func(t *testing.T) {
				op := testLifecycleOperation(action, now)
				field.apply(&op)
				sealTestLifecycleOperation(&op)
				if op.valid(now) {
					t.Fatalf("%s accepted foreign %s", action, field.name)
				}
			})
		}
	}

	for _, action := range actions {
		action := action
		t.Run(action+"/enabled", func(t *testing.T) {
			op := testLifecycleOperation(action, now)
			op.Enabled = !op.Enabled
			sealTestLifecycleOperation(&op)
			if op.valid(now) {
				t.Fatal("action accepted an inconsistent enabled intent")
			}
		})
	}

	for _, action := range []string{"profile-enable", "profile-disable"} {
		action := action
		for _, field := range []struct {
			name  string
			apply func(*ProviderLifecycleOperation)
		}{
			{"profile_id", func(o *ProviderLifecycleOperation) { o.ProfileID = "" }},
			{"profile_revision", func(o *ProviderLifecycleOperation) { o.ProfileRevision = "" }},
		} {
			field := field
			t.Run(action+"/requires-"+field.name, func(t *testing.T) {
				op := testLifecycleOperation(action, now)
				field.apply(&op)
				sealTestLifecycleOperation(&op)
				if op.valid(now) {
					t.Fatalf("%s accepted missing %s", action, field.name)
				}
			})
		}
	}

	for _, action := range []string{"ui-bind", "ui-revoke", "ui-rotate", "root-close"} {
		action := action
		for _, field := range []struct {
			name  string
			apply func(*ProviderLifecycleOperation)
		}{
			{"session_id", func(o *ProviderLifecycleOperation) { o.SessionID = "" }},
			{"channel_id", func(o *ProviderLifecycleOperation) { o.ChannelID = "" }},
			{"root_run_id", func(o *ProviderLifecycleOperation) { o.RootRunID = "" }},
			{"run_id", func(o *ProviderLifecycleOperation) { o.RunID = "" }},
			{"mesh_session_id", func(o *ProviderLifecycleOperation) { o.MeshSessionID = "" }},
			{"attempt_id", func(o *ProviderLifecycleOperation) { o.AttemptID = "" }},
			{"peer_id", func(o *ProviderLifecycleOperation) { o.PeerID = "" }},
			{"endpoint_id", func(o *ProviderLifecycleOperation) { o.EndpointID = "" }},
			{"endpoint_generation", func(o *ProviderLifecycleOperation) { o.EndpointGeneration = 0 }},
			{"endpoint_expires_at", func(o *ProviderLifecycleOperation) { o.EndpointExpiresAt = time.Time{} }},
		} {
			field := field
			t.Run(action+"/requires-"+field.name, func(t *testing.T) {
				op := testLifecycleOperation(action, now)
				field.apply(&op)
				sealTestLifecycleOperation(&op)
				if op.valid(now) {
					t.Fatalf("%s accepted missing %s", action, field.name)
				}
			})
		}
	}

	bind := testLifecycleOperation("ui-bind", now)
	bind.AssociationDigest = testDigest("d")
	sealTestLifecycleOperation(&bind)
	if bind.valid(now) {
		t.Fatal("ui-bind accepted a revoke-only association digest")
	}
	bind = testLifecycleOperation("ui-bind", now)
	bind.BaseCurrentRevision = "other-current-revision"
	sealTestLifecycleOperation(&bind)
	if bind.valid(now) {
		t.Fatal("ui-bind accepted a base for a different active revision")
	}
	revoke := testLifecycleOperation("ui-revoke", now)
	revoke.AssociationDigest = ""
	sealTestLifecycleOperation(&revoke)
	if revoke.valid(now) {
		t.Fatal("ui-revoke accepted a missing association digest")
	}
	rotate := testLifecycleOperation("ui-rotate", now)
	rotate.BaseCurrentRevision = "other-current-revision"
	sealTestLifecycleOperation(&rotate)
	if rotate.valid(now) {
		t.Fatal("ui-rotate accepted a base for a different active revision")
	}
	close := testLifecycleOperation("root-close", now)
	close.BaseCurrentRevision = "other-current-revision"
	sealTestLifecycleOperation(&close)
	if !close.valid(now) {
		t.Fatal("root-close rejected exact prior-revision cleanup")
	}
}

func testLifecycleOperation(action string, now time.Time) ProviderLifecycleOperation {
	op := ProviderLifecycleOperation{
		SchemaVersion:       ProviderLifecycleOperationV1,
		Purpose:             lifecyclePurpose,
		Action:              action,
		RevisionID:          "revision-1",
		BundleDigest:        testDigest("a"),
		TrustDigest:         testDigest("b"),
		BaseVersion:         7,
		BaseCurrentRevision: "current-1",
		DecisionID:          "decision-1",
		Nonce:               "nonce-1",
		KeyID:               "owner-1",
		IssuedAt:            now,
		ExpiresAt:           now.Add(time.Minute),
	}
	switch action {
	case "install":
		op.BaseVersion = 0
		op.BaseCurrentRevision = ""
	case "profile-enable":
		op.ProfileID, op.ProfileRevision, op.Enabled = "profile-1", "profile-revision-1", true
	case "profile-disable":
		op.ProfileID, op.ProfileRevision = "profile-1", "profile-revision-1"
	case "ui-bind":
		op.BaseCurrentRevision = op.RevisionID
		op.SessionID, op.ChannelID = "session-1", "channel-1"
		op.RootRunID, op.RunID = "root-1", "run-1"
		op.MeshSessionID, op.AttemptID = "mesh-session-1", "attempt-1"
		op.PeerID, op.EndpointID, op.EndpointGeneration = "peer-1", "endpoint-1", 1
		op.EndpointExpiresAt = now.Add(2 * time.Minute)
	case "ui-register":
		op.BaseCurrentRevision = op.RevisionID
		op.SessionID, op.ChannelID = "session-1", "channel-1"
		op.RootRunID, op.RunID = "root-1", "root-1"
		op.MeshSessionID, op.AttemptID = "mesh-session-1", "attempt-1"
		op.PeerID, op.Classification, op.WorkspaceGroupID = "peer-1", "L1", "workspace-1"
	case "ui-revoke":
		op.SessionID, op.ChannelID = "session-1", "channel-1"
		op.RootRunID, op.RunID = "root-1", "run-1"
		op.MeshSessionID, op.AttemptID = "mesh-session-1", "attempt-1"
		op.PeerID, op.EndpointID, op.EndpointGeneration = "peer-1", "endpoint-1", 1
		op.AssociationDigest = testDigest("c")
		// Revoke is intentionally valid for a stale association; the exact
		// stored expiry is checked during apply before removal.
		op.EndpointExpiresAt = now.Add(-time.Minute)
	case "ui-rotate", "root-close":
		op.SessionID, op.ChannelID = "session-1", "channel-1"
		op.RootRunID, op.RunID = "root-1", "root-1"
		op.MeshSessionID, op.AttemptID = "mesh-session-1", "attempt-1"
		op.PeerID, op.EndpointID, op.EndpointGeneration = "peer-1", "endpoint-1", 1
		op.AssociationDigest = testDigest("c")
		op.EndpointExpiresAt = now.Add(2 * time.Minute)
		if action == "ui-rotate" {
			op.BaseCurrentRevision = op.RevisionID
		}
	}
	sealTestLifecycleOperation(&op)
	return op
}

func TestUIRegistrationIsPendingAndFencesOwnerBind(t *testing.T) {
	now := time.Date(2026, time.August, 30, 14, 0, 0, 0, time.UTC)
	key := bytes.Repeat([]byte{9}, 32)
	repo, err := NewRepository(filepath.Join(t.TempDir(), "registration.enc"), key)
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	service, err := NewService(repo, testAuthority{}, testTrustSource{})
	if err != nil {
		t.Fatal(err)
	}
	service.now = func() time.Time { return now }
	bundle := testInstalledBundle("revision-registration")
	state := addTestRevision(t, repo, bundle, now, true)
	register := testLifecycleOperation("ui-register", now)
	register.RevisionID, register.BundleDigest, register.TrustDigest = bundle.RevisionID, bundle.Digest, bundle.TrustBundleDigest
	register.BaseVersion, register.BaseCurrentRevision, register.Nonce = state.Version, bundle.RevisionID, "nonce-register-1"
	sealTestLifecycleOperation(&register)
	endpointExpiry := now.Add(2 * time.Minute)
	callbackCalls := 0
	dispatcher := &Dispatcher{Service: service, RegisterUIRoot: func(_ context.Context, op ProviderLifecycleOperation) (UIRegistration, error) {
		callbackCalls++
		return UIRegistration{RequestNonce: op.Nonce, RequestDigest: op.Digest, SessionID: op.SessionID, ChannelID: op.ChannelID, RootRunID: op.RootRunID, RunID: op.RunID, MeshSessionID: op.MeshSessionID, AttemptID: op.AttemptID, PeerID: op.PeerID, EndpointID: "ui-endpoint-1", EndpointGeneration: 1, RevisionID: op.RevisionID, ExpiresAt: endpointExpiry}, nil
	}}
	if _, replayed, err := dispatcher.dispatchVerified(context.Background(), register, nil); err != nil || replayed {
		t.Fatalf("register err=%v replayed=%v", err, replayed)
	}
	registration, err := service.Registration(context.Background(), register.SessionID, register.ChannelID)
	if err != nil || registration.EndpointID != "ui-endpoint-1" {
		t.Fatalf("registration=%+v err=%v", registration, err)
	}
	if _, err := service.Association(context.Background(), register.SessionID, register.ChannelID); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("pending registration became UI authority: %v", err)
	}
	if _, replayed, err := dispatcher.dispatchVerified(context.Background(), register, nil); err != nil || !replayed || callbackCalls != 1 {
		t.Fatalf("register replay err=%v replayed=%v calls=%d", err, replayed, callbackCalls)
	}

	pending, baseVersion, err := service.RegistrationForBinding(context.Background(), register.SessionID, register.ChannelID)
	if err != nil || pending != registration {
		t.Fatalf("pending registration=%+v err=%v", pending, err)
	}
	bind := testLifecycleOperation("ui-bind", now)
	bind.RevisionID, bind.BundleDigest, bind.TrustDigest = bundle.RevisionID, bundle.Digest, bundle.TrustBundleDigest
	bind.BaseVersion, bind.BaseCurrentRevision, bind.Nonce = baseVersion, bundle.RevisionID, "nonce-bind-registration-1"
	bind.SessionID, bind.ChannelID = registration.SessionID, registration.ChannelID
	bind.RootRunID, bind.RunID = registration.RootRunID, registration.RunID
	bind.MeshSessionID, bind.AttemptID, bind.PeerID = registration.MeshSessionID, registration.AttemptID, registration.PeerID
	bind.EndpointID, bind.EndpointGeneration, bind.EndpointExpiresAt = registration.EndpointID, registration.EndpointGeneration, registration.ExpiresAt
	sealTestLifecycleOperation(&bind)
	verified := false
	dispatcher.VerifyUIBinding = func(_ context.Context, op ProviderLifecycleOperation) error {
		if op != bind {
			return ErrUnauthorized
		}
		verified = true
		return nil
	}
	if _, replayed, err := dispatcher.dispatchVerified(context.Background(), bind, nil); err != nil || replayed || !verified {
		t.Fatalf("bind err=%v replayed=%v verified=%v", err, replayed, verified)
	}
	association, err := service.Association(context.Background(), register.SessionID, register.ChannelID)
	if err != nil || association.EndpointID != registration.EndpointID || association.EndpointGeneration != registration.EndpointGeneration {
		t.Fatalf("association=%+v err=%v", association, err)
	}

	for _, mutate := range []func(*ProviderLifecycleOperation){
		func(op *ProviderLifecycleOperation) { op.EndpointID = "ui-endpoint-other" },
		func(op *ProviderLifecycleOperation) { op.EndpointGeneration++ },
		func(op *ProviderLifecycleOperation) { op.EndpointExpiresAt = op.EndpointExpiresAt.Add(time.Second) },
		func(op *ProviderLifecycleOperation) { op.PeerID = "peer-other" },
	} {
		foreign := bind
		foreign.Nonce = "nonce-foreign-" + fmt.Sprintf("%d", foreign.EndpointGeneration)
		mutate(&foreign)
		sealTestLifecycleOperation(&foreign)
		if _, _, err := dispatcher.dispatchVerified(context.Background(), foreign, nil); !errors.Is(err, ErrUnauthorized) {
			t.Fatalf("cross-binding operation err=%v, want unauthorized", err)
		}
	}
}

func sealTestLifecycleOperation(op *ProviderLifecycleOperation) {
	op.Seal()
	op.Signature = strings.Repeat("0", ed25519.SignatureSize*2)
}

func testDigest(character string) string { return "sha256:" + strings.Repeat(character, 64) }

func differentTestID(value uint32) uint32 {
	if value == ^uint32(0) {
		return value - 1
	}
	return value + 1
}

func TestUIAssociationIsDurableBoundAndReplaySafe(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	path := filepath.Join(t.TempDir(), "state.enc")
	repo, err := NewRepository(path, key)
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	service, err := NewService(repo, testAuthority{}, testTrustSource{})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	service.now = func() time.Time { return now }
	bundle := Bundle{SchemaVersion: BundleV1, BundleID: "bundle-1", RevisionID: "revision-1", TrustBundleDigest: "sha256:1111111111111111111111111111111111111111111111111111111111111111", Profiles: []ProfileBundle{{Profile: ProfileDTO{ID: "profile-1"}}}}
	_ = bundle.Seal()
	old, err := repo.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	next := cloneSnapshot(old)
	next.CurrentID = bundle.RevisionID
	next.Revisions[bundle.RevisionID] = Installed{Bundle: bundle, Enabled: map[string]bool{"profile-1": false}, InstalledAt: now}
	if err := repo.CompareAndSwap(context.Background(), old, next); err != nil {
		t.Fatal(err)
	}
	op := ProviderLifecycleOperation{SchemaVersion: ProviderLifecycleOperationV1, Purpose: lifecyclePurpose, Action: "ui-bind", RevisionID: bundle.RevisionID, BundleDigest: bundle.Digest, TrustDigest: bundle.TrustBundleDigest, BaseVersion: 1, BaseCurrentRevision: bundle.RevisionID, SessionID: "session-1", ChannelID: "channel-1", RootRunID: "root-1", RunID: "root-1", MeshSessionID: "mesh-session-1", AttemptID: "attempt-1", PeerID: "peer-1", EndpointID: "endpoint-1", EndpointGeneration: 1, DecisionID: "decision-1", Nonce: "nonce-1", KeyID: "owner-1", IssuedAt: now, ExpiresAt: now.Add(time.Minute), EndpointExpiresAt: now.Add(2 * time.Minute)}
	op.Seal()
	op.Signature = string(make([]byte, 128))
	for i := range op.Signature {
		op.Signature = op.Signature[:i] + "0" + op.Signature[i+1:]
	}
	if !op.valid(now) {
		t.Fatalf("operation invalid: %#v", op)
	}
	if !(UIAssociation{SessionID: op.SessionID, ChannelID: op.ChannelID, RootRunID: op.RootRunID, RunID: op.RunID, MeshSessionID: op.MeshSessionID, AttemptID: op.AttemptID, PeerID: op.PeerID, EndpointID: op.EndpointID, EndpointGeneration: op.EndpointGeneration, RevisionID: op.RevisionID, ExpiresAt: op.EndpointExpiresAt}).valid(now) {
		t.Fatal("association invalid")
	}
	if _, replayed, err := service.applyVerified(context.Background(), op, nil, nil); err != nil || replayed {
		t.Fatalf("apply=%v replay=%v", err, replayed)
	}
	if err := repo.Close(); err != nil {
		t.Fatal(err)
	}
	repo, err = NewRepository(path, key)
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	service, err = NewService(repo, testAuthority{}, testTrustSource{})
	if err != nil {
		t.Fatal(err)
	}
	service.now = func() time.Time { return now }
	a, err := service.Association(context.Background(), "session-1", "channel-1")
	if err != nil || a.EndpointID != "endpoint-1" {
		t.Fatalf("association=%#v err=%v", a, err)
	}
	if _, replayed, err := service.applyVerified(context.Background(), op, nil, nil); err != nil || !replayed {
		t.Fatalf("replay=%v replayed=%v", err, replayed)
	}
	now = now.Add(2 * time.Minute)
	if _, err := service.Association(context.Background(), "session-1", "channel-1"); err == nil {
		t.Fatal("expired association accepted")
	}
}

func TestUIRevokeBindsExactStaleAssociationAcrossRevision(t *testing.T) {
	started := time.Date(2026, time.August, 26, 13, 0, 0, 0, time.UTC)
	now := started
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	repo, err := NewRepository(filepath.Join(t.TempDir(), "state.enc"), key)
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	service, err := NewService(repo, testAuthority{}, testTrustSource{})
	if err != nil {
		t.Fatal(err)
	}
	service.now = func() time.Time { return now }

	revisionOne := testInstalledBundle("revision-1")
	state := addTestRevision(t, repo, revisionOne, now, true)
	bind := testLifecycleOperation("ui-bind", now)
	bind.RevisionID = revisionOne.RevisionID
	bind.BundleDigest = revisionOne.Digest
	bind.TrustDigest = revisionOne.TrustBundleDigest
	bind.BaseVersion = state.Version
	bind.BaseCurrentRevision = revisionOne.RevisionID
	bind.Nonce = "nonce-bind-1"
	bind.EndpointExpiresAt = now.Add(5 * time.Minute)
	sealTestLifecycleOperation(&bind)
	if _, replayed, err := service.applyVerified(context.Background(), bind, nil, nil); err != nil || replayed {
		t.Fatalf("bind err=%v replayed=%v", err, replayed)
	}
	state, err = repo.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	association := state.Associations[associationKey(bind.SessionID, bind.ChannelID)]
	if !association.valid(now) {
		t.Fatal("bound association is invalid")
	}

	revisionTwo := testInstalledBundle("revision-2")
	state = addTestRevision(t, repo, revisionTwo, now, true)
	if _, err := service.Association(context.Background(), bind.SessionID, bind.ChannelID); err == nil {
		t.Fatal("cross-revision association was exposed to the UI")
	}

	// The old association has become stale, but a specific signed revoke must
	// still be able to remove it after the active revision changed.
	now = now.Add(10 * time.Minute)
	revoke := testLifecycleOperation("ui-revoke", now)
	populateRevokeOperation(&revoke, association, revisionOne, state)
	revoke.Nonce = "nonce-revoke-1"
	sealTestLifecycleOperation(&revoke)
	if !revoke.valid(now) {
		t.Fatal("exact stale revoke rejected before apply")
	}
	if _, _, err := service.applyVerified(context.Background(), revoke, nil, nil); err != ErrUnauthorized {
		t.Fatalf("unconfirmed revoke err=%v, want unauthorized", err)
	}
	stillBound, err := repo.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := stillBound.Associations[associationKey(bind.SessionID, bind.ChannelID)]; !ok {
		t.Fatal("unconfirmed revoke removed association")
	}
	callbackCalls := 0
	dispatcher := &Dispatcher{Service: service, RevokeUIEndpoint: func(_ context.Context, endpointID string, generation uint64) error {
		if endpointID != association.EndpointID || generation != association.EndpointGeneration {
			t.Fatalf("callback target=%q/%d", endpointID, generation)
		}
		callbackCalls++
		return nil
	}}
	failedDispatcher := &Dispatcher{Service: service, RevokeUIEndpoint: func(context.Context, string, uint64) error { return ErrUnavailable }}
	if _, _, err := failedDispatcher.dispatchVerified(context.Background(), revoke, nil); err != ErrUnavailable {
		t.Fatalf("failed endpoint revoke err=%v, want unavailable", err)
	}
	stillBound, err = repo.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := stillBound.Associations[associationKey(bind.SessionID, bind.ChannelID)]; !ok {
		t.Fatal("failed endpoint revoke removed association")
	}

	wrongExpiry := revoke
	wrongExpiry.Nonce = "nonce-revoke-wrong-expiry"
	wrongExpiry.EndpointExpiresAt = association.ExpiresAt.Add(time.Second)
	sealTestLifecycleOperation(&wrongExpiry)
	if _, _, err := dispatcher.dispatchVerified(context.Background(), wrongExpiry, nil); err != ErrConflict {
		t.Fatalf("mismatched expiry competing with prepared revoke err=%v, want conflict", err)
	}
	wrongIdentity := revoke
	wrongIdentity.Nonce = "nonce-revoke-wrong-endpoint"
	wrongIdentity.EndpointID = "endpoint-other"
	sealTestLifecycleOperation(&wrongIdentity)
	if _, _, err := dispatcher.dispatchVerified(context.Background(), wrongIdentity, nil); err != ErrConflict {
		t.Fatalf("mismatched endpoint competing with prepared revoke err=%v, want conflict", err)
	}
	wrongRevision := revoke
	wrongRevision.Nonce = "nonce-revoke-wrong-revision"
	wrongRevision.RevisionID = revisionTwo.RevisionID
	wrongRevision.BundleDigest = revisionTwo.Digest
	wrongRevision.TrustDigest = revisionTwo.TrustBundleDigest
	sealTestLifecycleOperation(&wrongRevision)
	if _, _, err := dispatcher.dispatchVerified(context.Background(), wrongRevision, nil); err != ErrConflict {
		t.Fatalf("mismatched revision competing with prepared revoke err=%v, want conflict", err)
	}
	crossSession := revoke
	crossSession.Nonce = "nonce-revoke-cross-session"
	crossSession.SessionID = "session-other"
	sealTestLifecycleOperation(&crossSession)
	if _, _, err := dispatcher.dispatchVerified(context.Background(), crossSession, nil); err != ErrConflict {
		t.Fatalf("cross-session revoke raced prepared journal err=%v, want conflict", err)
	}

	if callbackCalls != 0 {
		t.Fatal("prevalidation invoked endpoint callback for a mismatched association")
	}
	if _, replayed, err := dispatcher.dispatchVerified(context.Background(), revoke, nil); err != nil || replayed {
		t.Fatalf("exact revoke err=%v replayed=%v", err, replayed)
	}
	afterRevoke, err := repo.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := afterRevoke.Associations[associationKey(bind.SessionID, bind.ChannelID)]; ok {
		t.Fatal("revoked association remained durable")
	}
	if _, replayed, err := dispatcher.dispatchVerified(context.Background(), revoke, nil); err != nil || !replayed {
		t.Fatalf("exact revoke replay err=%v replayed=%v", err, replayed)
	}
	if callbackCalls != 1 {
		t.Fatalf("receipt replay reached endpoint revoke callback: calls=%d", callbackCalls)
	}

	// Model the dangerous ordering where the exact mesh capability has been
	// durably revoked by the callback, but the revision-repository mutation is
	// interrupted before it can commit. The association must remain (rather
	// than silently claim deletion), and retrying the same signed operation
	// must safely reassert the idempotent endpoint revoke before committing.
	bindSecond := testLifecycleOperation("ui-bind", now)
	bindSecond.RevisionID = revisionTwo.RevisionID
	bindSecond.BundleDigest = revisionTwo.Digest
	bindSecond.TrustDigest = revisionTwo.TrustBundleDigest
	bindSecond.BaseVersion = afterRevoke.Version
	bindSecond.BaseCurrentRevision = revisionTwo.RevisionID
	bindSecond.Nonce = "nonce-bind-2"
	bindSecond.SessionID, bindSecond.ChannelID = "session-2", "channel-2"
	bindSecond.EndpointID, bindSecond.EndpointGeneration = "endpoint-2", 2
	bindSecond.EndpointExpiresAt = now.Add(5 * time.Minute)
	sealTestLifecycleOperation(&bindSecond)
	if _, replayed, err := service.applyVerified(context.Background(), bindSecond, nil, nil); err != nil || replayed {
		t.Fatalf("second bind err=%v replayed=%v", err, replayed)
	}
	afterBind, err := repo.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	secondAssociation, ok := afterBind.Associations[associationKey(bindSecond.SessionID, bindSecond.ChannelID)]
	if !ok {
		t.Fatal("second association missing")
	}
	uncertainRevoke := testLifecycleOperation("ui-revoke", now)
	populateRevokeOperation(&uncertainRevoke, secondAssociation, revisionTwo, afterBind)
	uncertainRevoke.Nonce = "nonce-revoke-post-callback-interrupt"
	sealTestLifecycleOperation(&uncertainRevoke)
	callbackContext, cancelCallback := context.WithCancel(context.Background())
	defer cancelCallback()
	uncertainCalls := 0
	uncertainDispatcher := &Dispatcher{Service: service, RevokeUIEndpoint: func(_ context.Context, endpointID string, generation uint64) error {
		if endpointID != secondAssociation.EndpointID || generation != secondAssociation.EndpointGeneration {
			t.Fatalf("uncertain callback target=%q/%d", endpointID, generation)
		}
		uncertainCalls++
		if uncertainCalls == 1 {
			cancelCallback()
		}
		return nil
	}}
	if _, _, err := uncertainDispatcher.dispatchVerified(callbackContext, uncertainRevoke, nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("post-callback repository interruption err=%v, want canceled", err)
	}
	afterInterrupted, err := repo.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := afterInterrupted.Associations[associationKey(bindSecond.SessionID, bindSecond.ChannelID)]; !ok {
		t.Fatal("interrupted revoke deleted association without a durable receipt")
	}
	if _, replayed, err := uncertainDispatcher.dispatchVerified(context.Background(), uncertainRevoke, nil); err != nil || replayed {
		t.Fatalf("retry after interruption err=%v replayed=%v", err, replayed)
	}
	if _, replayed, err := uncertainDispatcher.dispatchVerified(context.Background(), uncertainRevoke, nil); err != nil || !replayed {
		t.Fatalf("exact replay after interrupted revoke err=%v replayed=%v", err, replayed)
	}
	if uncertainCalls != 2 {
		t.Fatalf("interrupted revoke did not retry exact endpoint revoke: calls=%d", uncertainCalls)
	}
	afterUncertain, err := repo.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := afterUncertain.Associations[associationKey(bindSecond.SessionID, bindSecond.ChannelID)]; ok {
		t.Fatal("retried revoke left second association durable")
	}
	revokedAgain := revoke
	revokedAgain.Nonce = "nonce-revoke-after-revocation"
	revokedAgain.BaseVersion = afterUncertain.Version
	revokedAgain.BaseCurrentRevision = revisionTwo.RevisionID
	sealTestLifecycleOperation(&revokedAgain)
	if _, _, err := service.applyVerified(context.Background(), revokedAgain, nil, confirmedUIRevoke(revokedAgain)); err != ErrConflict {
		t.Fatalf("fresh revoke without durable preparation err=%v, want conflict", err)
	}
}

func TestPreparedUIEffectsConvergeAcrossUnrelatedRevisionCAS(t *testing.T) {
	for _, action := range []string{"ui-rotate", "root-close"} {
		t.Run(action, func(t *testing.T) {
			now := time.Date(2026, time.August, 26, 16, 0, 0, 0, time.UTC)
			key := make([]byte, 32)
			for i := range key {
				key[i] = byte(i + 1)
			}
			repo, err := NewRepository(filepath.Join(t.TempDir(), "state.enc"), key)
			if err != nil {
				t.Fatal(err)
			}
			defer repo.Close()
			service, err := NewService(repo, testAuthority{}, testTrustSource{})
			if err != nil {
				t.Fatal(err)
			}
			service.now = func() time.Time { return now }
			revision := testInstalledBundle("revision-effect")
			state := addTestRevision(t, repo, revision, now, true)
			bind := testLifecycleOperation("ui-bind", now)
			bind.RevisionID, bind.BundleDigest, bind.TrustDigest = revision.RevisionID, revision.Digest, revision.TrustBundleDigest
			bind.BaseVersion, bind.BaseCurrentRevision, bind.Nonce = state.Version, revision.RevisionID, "nonce-bind-effect"
			bind.RunID = bind.RootRunID
			bind.EndpointExpiresAt = now.Add(5 * time.Minute)
			sealTestLifecycleOperation(&bind)
			if _, _, err = service.applyVerified(context.Background(), bind, nil, nil); err != nil {
				t.Fatalf("bind: %v", err)
			}
			state, err = repo.Load(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			association := state.Associations[associationKey(bind.SessionID, bind.ChannelID)]
			if action == "root-close" {
				// The safety close must remain available for an exact association
				// after a later revision becomes current.
				state = addTestRevision(t, repo, testInstalledBundle("revision-effect-next"), now, true)
			}
			op := testLifecycleOperation(action, now)
			populateRevokeOperation(&op, association, revision, state)
			op.Action, op.Nonce = action, "nonce-"+action
			if action == "ui-rotate" {
				op.BaseCurrentRevision = revision.RevisionID
			}
			sealTestLifecycleOperation(&op)
			if !op.valid(now) {
				t.Fatalf("operation invalid: %+v", op)
			}
			callbacks := 0
			dispatcher := &Dispatcher{Service: service}
			if action == "ui-rotate" {
				dispatcher.RotateUIEndpoint = func(context.Context, UIRotateTarget) (UIRotateResult, error) {
					callbacks++
					bumpRevisionSnapshot(t, repo)
					return UIRotateResult{EndpointID: "endpoint-rotated", Generation: association.EndpointGeneration + 1, ExpiresAt: now.Add(10 * time.Minute)}, nil
				}
			} else {
				dispatcher.CloseRootEndpoint = func(context.Context, UIRotateTarget) error {
					callbacks++
					bumpRevisionSnapshot(t, repo)
					return nil
				}
			}
			if _, replayed, err := dispatcher.dispatchVerified(context.Background(), op, nil); err != nil || replayed {
				t.Fatalf("dispatch err=%v replayed=%v", err, replayed)
			}
			if callbacks != 1 {
				t.Fatalf("callbacks=%d", callbacks)
			}
			after, err := repo.Load(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if _, ok := after.Receipts[op.Nonce]; !ok {
				t.Fatal("effect receipt missing")
			}
			if len(after.Prepared) != 0 {
				t.Fatalf("prepared effect not consumed: %+v", after.Prepared)
			}
			if _, replayed, err := dispatcher.dispatchVerified(context.Background(), op, nil); err != nil || !replayed || callbacks != 1 {
				t.Fatalf("exact replay err=%v replayed=%v callbacks=%d", err, replayed, callbacks)
			}
		})
	}
}

func TestSafetyReceiptReserveAllowsPreparedRevokeAtSharedCapWithoutOrphanCallback(t *testing.T) {
	now := time.Date(2026, time.August, 27, 10, 0, 0, 0, time.UTC)
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	repo, err := NewRepository(filepath.Join(t.TempDir(), "state.enc"), key)
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	service, err := NewService(repo, testAuthority{}, testTrustSource{})
	if err != nil {
		t.Fatal(err)
	}
	service.now = func() time.Time { return now }
	revision := testInstalledBundle("revision-safety-cap")
	state := addTestRevision(t, repo, revision, now, true)
	association := UIAssociation{SessionID: "session-safety", ChannelID: "channel-safety", RootRunID: "root-safety", RunID: "child-safety", MeshSessionID: "mesh-safety", AttemptID: "attempt-safety", PeerID: "peer-safety", EndpointID: "endpoint-safety", EndpointGeneration: 1, RevisionID: revision.RevisionID, ExpiresAt: now.Add(2 * time.Minute)}
	next := cloneSnapshot(state)
	next.Associations[associationKey(association.SessionID, association.ChannelID)] = association
	for i := 0; i < maxReceipts-1; i++ {
		nonce := fmt.Sprintf("receipt-safety-%03d", i)
		next.Receipts[nonce] = Receipt{Action: "install", PayloadDigest: testDigest("a"), ResultDigest: testDigest("b"), BaseVersion: state.Version, ResultVersion: state.Version + 1, IssuedAt: now, ExpiresAt: now.Add(time.Minute)}
	}
	if err := repo.CompareAndSwap(context.Background(), state, next); err != nil {
		t.Fatal(err)
	}
	state, err = repo.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	op := testLifecycleOperation("ui-revoke", now)
	populateRevokeOperation(&op, association, revision, state)
	op.Nonce = "revoke-safety-cap"
	sealTestLifecycleOperation(&op)
	calls := 0
	dispatcher := &Dispatcher{Service: service, RevokeUIEndpoint: func(context.Context, string, uint64) error {
		calls++
		return nil
	}}
	if _, replayed, err := dispatcher.dispatchVerified(context.Background(), op, nil); err != nil || replayed {
		t.Fatalf("revoke at receipt/prepared cap err=%v replayed=%v", err, replayed)
	}
	after, err := repo.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if calls != 1 || len(after.Receipts) != maxReceipts || len(after.Prepared) != 0 {
		t.Fatalf("callback/receipt transition left an orphan: calls=%d receipts=%d prepared=%d", calls, len(after.Receipts), len(after.Prepared))
	}
	if _, ok := after.Associations[associationKey(association.SessionID, association.ChannelID)]; ok {
		t.Fatal("revoke at cap did not remove association")
	}
}

func TestPreparedSafetyPoolIsBoundedAcrossAssociations(t *testing.T) {
	now := time.Date(2026, time.August, 27, 11, 0, 0, 0, time.UTC)
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	repo, err := NewRepository(filepath.Join(t.TempDir(), "state.enc"), key)
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	service, err := NewService(repo, testAuthority{}, testTrustSource{})
	if err != nil {
		t.Fatal(err)
	}
	service.now = func() time.Time { return now }
	revision := testInstalledBundle("revision-safety-pool")
	state := addTestRevision(t, repo, revision, now, true)
	next := cloneSnapshot(state)
	for i := 0; i < maxReceipts-safetyReceiptSlots; i++ {
		nonce := fmt.Sprintf("receipt-normal-%03d", i)
		next.Receipts[nonce] = Receipt{Action: "install", PayloadDigest: testDigest("c"), ResultDigest: testDigest("d"), BaseVersion: state.Version, ResultVersion: state.Version + 1, IssuedAt: now, ExpiresAt: now.Add(time.Minute)}
	}
	associations := make([]UIAssociation, safetyReceiptSlots+1)
	for i := range associations {
		id := fmt.Sprintf("%02d", i)
		associations[i] = UIAssociation{SessionID: "session-pool-" + id, ChannelID: "channel-pool-" + id, RootRunID: "root-pool-" + id, RunID: "child-pool-" + id, MeshSessionID: "mesh-pool-" + id, AttemptID: "attempt-pool-" + id, PeerID: "peer-pool-" + id, EndpointID: "endpoint-pool-" + id, EndpointGeneration: 1, RevisionID: revision.RevisionID, ExpiresAt: now.Add(2 * time.Minute)}
		next.Associations[associationKey(associations[i].SessionID, associations[i].ChannelID)] = associations[i]
	}
	if err := repo.CompareAndSwap(context.Background(), state, next); err != nil {
		t.Fatal(err)
	}
	for i, association := range associations {
		state, err = repo.Load(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		op := testLifecycleOperation("ui-revoke", now)
		populateRevokeOperation(&op, association, revision, state)
		op.Nonce = fmt.Sprintf("revoke-pool-%02d", i)
		sealTestLifecycleOperation(&op)
		_, _, err = service.prepareUIEffect(context.Background(), op)
		if i < safetyReceiptSlots && err != nil {
			t.Fatalf("safety preparation %d/%d err=%v", i+1, safetyReceiptSlots, err)
		}
		if i == safetyReceiptSlots && err != ErrConflict {
			t.Fatalf("overflow safety preparation err=%v, want conflict", err)
		}
	}
	after, err := repo.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(after.Prepared) != safetyReceiptSlots || len(after.Receipts) != maxReceipts-safetyReceiptSlots {
		t.Fatalf("safety reserve escaped bounds: receipts=%d prepared=%d", len(after.Receipts), len(after.Prepared))
	}
}

func TestExpiredLifecycleEntriesArePrunedByTheNextDurableCommit(t *testing.T) {
	now := time.Date(2026, time.August, 27, 12, 0, 0, 0, time.UTC)
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	repo, err := NewRepository(filepath.Join(t.TempDir(), "state.enc"), key)
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	service, err := NewService(repo, testAuthority{}, testTrustSource{})
	if err != nil {
		t.Fatal(err)
	}
	service.now = func() time.Time { return now }
	revision := testInstalledBundle("revision-expired-gc")
	state := addTestRevision(t, repo, revision, now, true)
	expiredAssociation := UIAssociation{SessionID: "session-expired", ChannelID: "channel-expired", RootRunID: "root-expired", RunID: "child-expired", MeshSessionID: "mesh-expired", AttemptID: "attempt-expired", PeerID: "peer-expired", EndpointID: "endpoint-expired", EndpointGeneration: 1, RevisionID: revision.RevisionID, ExpiresAt: now.Add(time.Minute)}
	next := cloneSnapshot(state)
	next.Associations[associationKey(expiredAssociation.SessionID, expiredAssociation.ChannelID)] = expiredAssociation
	next.Receipts["receipt-expired"] = Receipt{Action: "install", PayloadDigest: testDigest("e"), ResultDigest: testDigest("f"), BaseVersion: state.Version, ResultVersion: state.Version + 1, IssuedAt: now.Add(-2 * time.Minute), ExpiresAt: now.Add(-time.Minute)}
	next.Prepared["prepared-expired"] = PreparedLifecycleEffect{Action: "ui-revoke", PayloadDigest: testDigest("a"), Association: expiredAssociation, IssuedAt: now.Add(-2 * time.Minute), ExpiresAt: now.Add(-time.Minute)}
	if err := repo.CompareAndSwap(context.Background(), state, next); err != nil {
		t.Fatal(err)
	}
	state, err = repo.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	bind := testLifecycleOperation("ui-bind", now)
	bind.RevisionID, bind.BundleDigest, bind.TrustDigest = revision.RevisionID, revision.Digest, revision.TrustBundleDigest
	bind.BaseVersion, bind.BaseCurrentRevision, bind.Nonce = state.Version, revision.RevisionID, "bind-prunes-expired"
	bind.SessionID, bind.ChannelID, bind.EndpointID = "session-fresh", "channel-fresh", "endpoint-fresh"
	bind.EndpointExpiresAt = now.Add(2 * time.Minute)
	sealTestLifecycleOperation(&bind)
	if _, _, err := service.applyVerified(context.Background(), bind, nil, nil); err != nil {
		t.Fatalf("commit after expiry err=%v", err)
	}
	after, err := repo.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(after.Prepared) != 0 || len(after.Receipts) != 1 {
		t.Fatalf("expired lifecycle entries survived durable GC: receipts=%+v prepared=%+v", after.Receipts, after.Prepared)
	}
}

func TestExpiredPreparedLifecycleNeverInvokesItsCallback(t *testing.T) {
	now := time.Date(2026, time.August, 27, 13, 0, 0, 0, time.UTC)
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	repo, err := NewRepository(filepath.Join(t.TempDir(), "state.enc"), key)
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	service, err := NewService(repo, testAuthority{}, testTrustSource{})
	if err != nil {
		t.Fatal(err)
	}
	service.now = func() time.Time { return now }
	revision := testInstalledBundle("revision-expired-callback")
	state := addTestRevision(t, repo, revision, now, true)
	bind := testLifecycleOperation("ui-bind", now)
	bind.RevisionID, bind.BundleDigest, bind.TrustDigest = revision.RevisionID, revision.Digest, revision.TrustBundleDigest
	bind.BaseVersion, bind.BaseCurrentRevision, bind.Nonce = state.Version, revision.RevisionID, "bind-expired-callback"
	bind.EndpointExpiresAt = now.Add(3 * time.Minute)
	sealTestLifecycleOperation(&bind)
	if _, _, err := service.applyVerified(context.Background(), bind, nil, nil); err != nil {
		t.Fatal(err)
	}
	state, err = repo.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	association := state.Associations[associationKey(bind.SessionID, bind.ChannelID)]
	op := testLifecycleOperation("ui-revoke", now)
	populateRevokeOperation(&op, association, revision, state)
	op.Nonce = "revoke-expired-callback"
	op.ExpiresAt = now.Add(time.Minute)
	sealTestLifecycleOperation(&op)
	if _, replayed, err := service.prepareUIEffect(context.Background(), op); err != nil || replayed {
		t.Fatalf("prepare err=%v replayed=%v", err, replayed)
	}
	now = op.ExpiresAt
	calls := 0
	dispatcher := &Dispatcher{Service: service, RevokeUIEndpoint: func(context.Context, string, uint64) error {
		calls++
		return nil
	}}
	if _, _, err := dispatcher.dispatchVerified(context.Background(), op, nil); err != ErrUnauthorized {
		t.Fatalf("expired prepared dispatch err=%v, want unauthorized", err)
	}
	after, err := repo.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if calls != 0 {
		t.Fatalf("expired lifecycle operation invoked callback %d times", calls)
	}
	if _, ok := after.Associations[associationKey(bind.SessionID, bind.ChannelID)]; !ok {
		t.Fatal("expired lifecycle operation mutated association")
	}
}

func TestLifecycleCallbackExpiryAtPrepareRevalidateBoundaryHasZeroEffects(t *testing.T) {
	for _, action := range []string{"ui-revoke", "ui-rotate", "root-close"} {
		t.Run(action, func(t *testing.T) {
			now := time.Date(2026, time.August, 27, 13, 30, 0, 0, time.UTC)
			key := make([]byte, 32)
			for i := range key {
				key[i] = byte(i + 1)
			}
			repo, err := NewRepository(filepath.Join(t.TempDir(), "state.enc"), key)
			if err != nil {
				t.Fatal(err)
			}
			defer repo.Close()
			service, err := NewService(repo, testAuthority{}, testTrustSource{})
			if err != nil {
				t.Fatal(err)
			}
			service.now = func() time.Time { return now }
			revision := testInstalledBundle("revision-boundary-" + action)
			state := addTestRevision(t, repo, revision, now, true)
			bind := testLifecycleOperation("ui-bind", now)
			bind.RevisionID, bind.BundleDigest, bind.TrustDigest = revision.RevisionID, revision.Digest, revision.TrustBundleDigest
			bind.BaseVersion, bind.BaseCurrentRevision, bind.Nonce = state.Version, revision.RevisionID, "bind-boundary-"+action
			if action != "ui-revoke" {
				bind.RunID = bind.RootRunID
			}
			bind.EndpointExpiresAt = now.Add(3 * time.Minute)
			sealTestLifecycleOperation(&bind)
			if _, _, err := service.applyVerified(context.Background(), bind, nil, nil); err != nil {
				t.Fatal(err)
			}
			state, err = repo.Load(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			association := state.Associations[associationKey(bind.SessionID, bind.ChannelID)]
			op := testLifecycleOperation(action, now)
			populateRevokeOperation(&op, association, revision, state)
			op.Action, op.Nonce, op.ExpiresAt = action, "expiry-boundary-"+action, now.Add(time.Minute)
			sealTestLifecycleOperation(&op)
			calls := 0
			dispatcher := &Dispatcher{Service: service, beforeLifecycleCallback: func() { now = op.ExpiresAt }}
			switch action {
			case "ui-revoke":
				dispatcher.RevokeUIEndpoint = func(context.Context, string, uint64) error { calls++; return nil }
			case "ui-rotate":
				dispatcher.RotateUIEndpoint = func(context.Context, UIRotateTarget) (UIRotateResult, error) {
					calls++
					return UIRotateResult{EndpointID: "endpoint-boundary-rotated", Generation: association.EndpointGeneration + 1, ExpiresAt: now.Add(time.Minute)}, nil
				}
			case "root-close":
				dispatcher.CloseRootEndpoint = func(context.Context, UIRotateTarget) error { calls++; return nil }
			}
			if _, _, err := dispatcher.dispatchVerified(context.Background(), op, nil); err != ErrUnauthorized {
				t.Fatalf("boundary expiry err=%v, want unauthorized", err)
			}
			after, err := repo.Load(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if calls != 0 || len(after.Prepared) != 1 || len(after.Receipts) != 1 {
				t.Fatalf("expiry boundary performed an effect: calls=%d prepared=%d receipts=%d", calls, len(after.Prepared), len(after.Receipts))
			}
			if _, ok := after.Associations[associationKey(bind.SessionID, bind.ChannelID)]; !ok {
				t.Fatal("expiry boundary removed association")
			}
		})
	}
}

func TestRotateAndCloseRetryAfterPostCallbackRepositoryInterruption(t *testing.T) {
	for _, action := range []string{"ui-rotate", "root-close"} {
		t.Run(action, func(t *testing.T) {
			now := time.Date(2026, time.August, 27, 14, 0, 0, 0, time.UTC)
			key := make([]byte, 32)
			for i := range key {
				key[i] = byte(i + 1)
			}
			repo, err := NewRepository(filepath.Join(t.TempDir(), "state.enc"), key)
			if err != nil {
				t.Fatal(err)
			}
			defer repo.Close()
			service, err := NewService(repo, testAuthority{}, testTrustSource{})
			if err != nil {
				t.Fatal(err)
			}
			service.now = func() time.Time { return now }
			revision := testInstalledBundle("revision-crash-" + action)
			state := addTestRevision(t, repo, revision, now, true)
			bind := testLifecycleOperation("ui-bind", now)
			bind.RevisionID, bind.BundleDigest, bind.TrustDigest = revision.RevisionID, revision.Digest, revision.TrustBundleDigest
			bind.BaseVersion, bind.BaseCurrentRevision, bind.Nonce = state.Version, revision.RevisionID, "bind-crash-"+action
			bind.RunID = bind.RootRunID
			bind.EndpointExpiresAt = now.Add(3 * time.Minute)
			sealTestLifecycleOperation(&bind)
			if _, _, err := service.applyVerified(context.Background(), bind, nil, nil); err != nil {
				t.Fatal(err)
			}
			state, err = repo.Load(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			association := state.Associations[associationKey(bind.SessionID, bind.ChannelID)]
			op := testLifecycleOperation(action, now)
			populateRevokeOperation(&op, association, revision, state)
			op.Action, op.Nonce = action, "effect-crash-"+action
			sealTestLifecycleOperation(&op)
			calls := 0
			callbackContext, cancel := context.WithCancel(context.Background())
			dispatcher := &Dispatcher{Service: service}
			if action == "ui-rotate" {
				dispatcher.RotateUIEndpoint = func(context.Context, UIRotateTarget) (UIRotateResult, error) {
					calls++
					if calls == 1 {
						cancel()
					}
					return UIRotateResult{EndpointID: "endpoint-crash-rotated", Generation: association.EndpointGeneration + 1, ExpiresAt: now.Add(5 * time.Minute)}, nil
				}
			} else {
				dispatcher.CloseRootEndpoint = func(context.Context, UIRotateTarget) error {
					calls++
					if calls == 1 {
						cancel()
					}
					return nil
				}
			}
			if _, _, err := dispatcher.dispatchVerified(callbackContext, op, nil); !errors.Is(err, context.Canceled) {
				t.Fatalf("post-callback interruption err=%v", err)
			}
			afterInterrupted, err := repo.Load(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if _, prepared := afterInterrupted.Prepared[op.Nonce]; !prepared {
				t.Fatal("post-callback interruption lost durable prepared effect")
			}
			if _, replayed, err := dispatcher.dispatchVerified(context.Background(), op, nil); err != nil || replayed {
				t.Fatalf("crash retry err=%v replayed=%v", err, replayed)
			}
			if calls != 2 {
				t.Fatalf("retry did not reassert exact callback: calls=%d", calls)
			}
			after, err := repo.Load(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if _, ok := after.Receipts[op.Nonce]; !ok || len(after.Prepared) != 0 {
				t.Fatalf("crash retry did not converge receipt/prepared state: %+v", after)
			}
		})
	}
}

func TestLegacyInstallAndSetEnabledUseOperationTimestampsAndRespectPrunableCapacity(t *testing.T) {
	now := time.Date(2026, time.August, 27, 15, 0, 0, 0, time.UTC)
	bundle, trust := validCandidateBundle(t, "revision-legacy-lifecycle", now)
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	repo, err := NewRepository(filepath.Join(t.TempDir(), "state.enc"), key)
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	service, err := NewService(repo, testAuthority{}, TrustSourceFunc(func(_ context.Context, digest string) (providerbridge.Ed25519TrustBundle, error) {
		if digest != bundle.TrustBundleDigest {
			return providerbridge.Ed25519TrustBundle{}, ErrUnavailable
		}
		return trust, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	service.now = func() time.Time { return now }
	if _, replayed, err := service.Install(context.Background(), bundle, "legacy-install-timestamp", "approval-install-timestamp", 0); err != nil || replayed {
		t.Fatalf("legacy install err=%v replayed=%v", err, replayed)
	}
	state, err := repo.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	installReceipt := state.Receipts["legacy-install-timestamp"]
	if !installReceipt.IssuedAt.Equal(now) || !installReceipt.ExpiresAt.Equal(now.Add(5*time.Minute)) {
		t.Fatalf("legacy install receipt timestamps=%+v", installReceipt)
	}
	activate := testLifecycleOperation("activate", now)
	activate.RevisionID, activate.BundleDigest, activate.TrustDigest = bundle.RevisionID, bundle.Digest, bundle.TrustBundleDigest
	activate.BaseVersion, activate.BaseCurrentRevision, activate.Nonce = state.Version, "", "activate-legacy-lifecycle"
	sealTestLifecycleOperation(&activate)
	if _, _, err := service.applyVerified(context.Background(), activate, nil, nil); err != nil {
		t.Fatalf("activate err=%v", err)
	}
	state, err = repo.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	next := cloneSnapshot(state)
	needed := lifecycleReceiptLimit("profile-enable") - len(next.Receipts)
	for i := 0; i < needed; i++ {
		nonce := fmt.Sprintf("legacy-live-cap-%03d", i)
		next.Receipts[nonce] = Receipt{Action: "install", PayloadDigest: testDigest("a"), ResultDigest: testDigest("b"), BaseVersion: state.Version, ResultVersion: state.Version + 1, IssuedAt: now, ExpiresAt: now.Add(5 * time.Minute)}
	}
	if err := repo.CompareAndSwap(context.Background(), state, next); err != nil {
		t.Fatal(err)
	}
	state, err = repo.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	profileID := bundle.Profiles[0].Profile.ID
	if err := service.SetEnabled(context.Background(), bundle.RevisionID, profileID, false, "legacy-enable-at-cap", "approval-enable-at-cap", state.Version); err != ErrConflict {
		t.Fatalf("legacy SetEnabled entered safety reserve: err=%v receipts=%d slots=%d limit=%d", err, len(state.Receipts), lifecycleSlots(state, now), lifecycleReceiptLimit("profile-enable"))
	}
	now = now.Add(6 * time.Minute)
	if err := service.SetEnabled(context.Background(), bundle.RevisionID, profileID, false, "legacy-enable-pruned", "approval-enable-pruned", state.Version); err != nil {
		t.Fatalf("legacy SetEnabled after expiry/prune err=%v", err)
	}
	after, err := repo.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	receipt, ok := after.Receipts["legacy-enable-pruned"]
	if !ok || len(after.Receipts) != 1 || receipt.Action != "set-enabled" || !receipt.IssuedAt.Equal(now) || !receipt.ExpiresAt.Equal(now.Add(5*time.Minute)) {
		t.Fatalf("legacy SetEnabled did not prune/capture timestamps: receipts=%+v", after.Receipts)
	}
}

func bumpRevisionSnapshot(t *testing.T, repo *Repository) {
	t.Helper()
	state, err := repo.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	next := cloneSnapshot(state)
	// Version-only bookkeeping is a stand-in for an unrelated signed lifecycle
	// commit; it keeps every association and current revision exact.
	next.Receipts["nonce-unrelated-cas"] = Receipt{Action: "profile-disable", PayloadDigest: testDigest("e"), ResultDigest: testDigest("f"), BaseVersion: state.Version, ResultVersion: state.Version + 1}
	if err = repo.CompareAndSwap(context.Background(), state, next); err != nil {
		t.Fatal(err)
	}
}

func TestCandidateInstallsRequireExplicitSignedActivation(t *testing.T) {
	now := time.Date(2026, time.August, 26, 15, 0, 0, 0, time.UTC)
	bundleOne, trust := validCandidateBundle(t, "revision-candidate-1", now)
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	repo, err := NewRepository(filepath.Join(t.TempDir(), "state.enc"), key)
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	service, err := NewService(repo, testAuthority{}, TrustSourceFunc(func(_ context.Context, digest string) (providerbridge.Ed25519TrustBundle, error) {
		if digest != bundleOne.TrustBundleDigest {
			return providerbridge.Ed25519TrustBundle{}, ErrUnavailable
		}
		return trust, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	service.now = func() time.Time { return now }

	if _, replayed, err := service.Install(context.Background(), bundleOne, "legacy-install-1", "approval-1", 0); err != nil || replayed {
		t.Fatalf("legacy candidate install err=%v replayed=%v", err, replayed)
	}
	state, err := repo.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if state.CurrentID != "" {
		t.Fatalf("legacy candidate selected current revision %q", state.CurrentID)
	}
	if _, err := service.Active(context.Background()); err != ErrUnavailable {
		t.Fatalf("candidate unexpectedly active: %v", err)
	}
	if err := service.SetEnabled(context.Background(), bundleOne.RevisionID, bundleOne.Profiles[0].Profile.ID, false, "legacy-candidate-enable", "approval-candidate-enable", state.Version); err != ErrConflict {
		t.Fatalf("legacy profile mutation on inactive candidate err=%v, want conflict", err)
	}

	activate := testLifecycleOperation("activate", now)
	activate.RevisionID = bundleOne.RevisionID
	activate.BundleDigest = bundleOne.Digest
	activate.TrustDigest = bundleOne.TrustBundleDigest
	activate.BaseVersion = state.Version
	activate.BaseCurrentRevision = ""
	activate.Nonce = "activate-candidate-1"
	sealTestLifecycleOperation(&activate)
	if !activate.valid(now) {
		t.Fatal("first activation from a nonzero empty current snapshot was rejected")
	}
	if _, replayed, err := service.applyVerified(context.Background(), activate, nil, nil); err != nil || replayed {
		t.Fatalf("first activation err=%v replayed=%v", err, replayed)
	}
	if active, err := service.Active(context.Background()); err != nil || active.Bundle.RevisionID != bundleOne.RevisionID {
		t.Fatalf("active=%+v err=%v", active, err)
	}

	bundleTwo, _ := validCandidateBundle(t, "revision-candidate-2", now)
	state, err = repo.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, replayed, err := service.Install(context.Background(), bundleTwo, "legacy-install-2", "approval-2", state.Version); err != nil || replayed {
		t.Fatalf("second legacy candidate install err=%v replayed=%v", err, replayed)
	}
	state, err = repo.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if state.CurrentID != bundleOne.RevisionID {
		t.Fatalf("legacy candidate changed existing current revision to %q", state.CurrentID)
	}
	if err := service.SetEnabled(context.Background(), bundleTwo.RevisionID, bundleTwo.Profiles[0].Profile.ID, false, "legacy-second-candidate-enable", "approval-second-candidate-enable", state.Version); err != ErrConflict {
		t.Fatalf("legacy mutation of non-current candidate err=%v, want conflict", err)
	}
	profileCandidate := testLifecycleOperation("profile-disable", now)
	profileCandidate.RevisionID = bundleTwo.RevisionID
	profileCandidate.BundleDigest = bundleTwo.Digest
	profileCandidate.TrustDigest = bundleTwo.TrustBundleDigest
	profileCandidate.ProfileID = bundleTwo.Profiles[0].Profile.ID
	profileCandidate.ProfileRevision = bundleTwo.Profiles[0].Profile.Revision
	profileCandidate.BaseVersion = state.Version
	profileCandidate.BaseCurrentRevision = bundleOne.RevisionID
	profileCandidate.Nonce = "signed-second-candidate-disable"
	sealTestLifecycleOperation(&profileCandidate)
	if _, _, err := service.applyVerified(context.Background(), profileCandidate, nil, nil); err != ErrConflict {
		t.Fatalf("signed mutation of non-current candidate err=%v, want conflict", err)
	}

	bundleThree, _ := validCandidateBundle(t, "revision-candidate-3", now)
	signedInstall := testLifecycleOperation("install", now)
	signedInstall.RevisionID = bundleThree.RevisionID
	signedInstall.BundleDigest = bundleThree.Digest
	signedInstall.TrustDigest = bundleThree.TrustBundleDigest
	signedInstall.BaseVersion = state.Version
	signedInstall.BaseCurrentRevision = bundleOne.RevisionID
	signedInstall.Nonce = "signed-install-3"
	sealTestLifecycleOperation(&signedInstall)
	if _, replayed, err := service.applyVerified(context.Background(), signedInstall, &bundleThree, nil); err != nil || replayed {
		t.Fatalf("signed candidate install err=%v replayed=%v", err, replayed)
	}
	state, err = repo.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if state.CurrentID != bundleOne.RevisionID {
		t.Fatalf("signed candidate changed existing current revision to %q", state.CurrentID)
	}
}

func TestActivationReplayRequiresStillCurrentRevision(t *testing.T) {
	now := time.Date(2026, time.August, 26, 16, 0, 0, 0, time.UTC)
	first, trust := validCandidateBundle(t, "revision-activate-1", now)
	second, _ := validCandidateBundle(t, "revision-activate-2", now)
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	repo, err := NewRepository(filepath.Join(t.TempDir(), "state.enc"), key)
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	service, err := NewService(repo, testAuthority{}, TrustSourceFunc(func(_ context.Context, digest string) (providerbridge.Ed25519TrustBundle, error) {
		if digest != first.TrustBundleDigest {
			return providerbridge.Ed25519TrustBundle{}, ErrUnavailable
		}
		return trust, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	service.now = func() time.Time { return now }
	state := addTestRevision(t, repo, first, now, false)
	state = addTestRevision(t, repo, second, now, false)

	activate := func(bundle Bundle, base Snapshot, nonce string) ProviderLifecycleOperation {
		op := testLifecycleOperation("activate", now)
		op.RevisionID = bundle.RevisionID
		op.BundleDigest = bundle.Digest
		op.TrustDigest = bundle.TrustBundleDigest
		op.BaseVersion = base.Version
		op.BaseCurrentRevision = base.CurrentID
		op.Nonce = nonce
		sealTestLifecycleOperation(&op)
		return op
	}
	activateFirst := activate(first, state, "activate-first")
	if _, replayed, err := service.applyVerified(context.Background(), activateFirst, nil, nil); err != nil || replayed {
		t.Fatalf("first activate err=%v replayed=%v", err, replayed)
	}
	state, err = repo.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	activateSecond := activate(second, state, "activate-second")
	if _, replayed, err := service.applyVerified(context.Background(), activateSecond, nil, nil); err != nil || replayed {
		t.Fatalf("second activate err=%v replayed=%v", err, replayed)
	}
	if _, replayed, err := service.applyVerified(context.Background(), activateFirst, nil, nil); err != ErrConflict || replayed {
		t.Fatalf("historical activate replay err=%v replayed=%v, want conflict", err, replayed)
	}
	if _, replayed, err := service.applyVerified(context.Background(), activateSecond, nil, nil); err != nil || !replayed {
		t.Fatalf("current activate replay err=%v replayed=%v", err, replayed)
	}

	state, err = repo.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	stale := activate(first, Snapshot{Version: state.Version - 1, CurrentID: first.RevisionID}, "activate-stale-cas")
	if _, _, err := service.applyVerified(context.Background(), stale, nil, nil); err != ErrConflict {
		t.Fatalf("stale activation CAS err=%v, want conflict", err)
	}
}

func validCandidateBundle(t *testing.T, revision string, now time.Time) (Bundle, providerbridge.Ed25519TrustBundle) {
	t.Helper()
	profile := providerbridge.DeclaredProfiles()[0]
	operations, err := providerbridge.PinnedMappings()
	if err != nil {
		t.Fatal(err)
	}
	var events []providerbridge.OperationMapping
	for _, mapping := range operations {
		if mapping.ProfileID == profile.ID {
			events = append([]providerbridge.OperationMapping(nil), mapping.Operations...)
			break
		}
	}
	if len(events) == 0 {
		t.Fatal("missing pinned operations")
	}
	runtimeVersion, protocolVersion := "codex-app-server@2026.8.25", "app-server-thread.v1"
	eventBytes, err := json.Marshal(events)
	if err != nil {
		t.Fatal(err)
	}
	compatibility := providerbridge.CompatibilityRecord{SchemaVersion: providerbridge.CompatibilityRecordV1, Maturity: providerbridge.CompatibilityPinned, Provider: profile.Provider, ProfileID: profile.ID, ProfileRevision: profile.Revision, Model: profile.Model, AuthModality: profile.AuthModality, RuntimeVersion: runtimeVersion, ProtocolVersion: protocolVersion, RuntimeArtifactDigest: providerbridge.DigestBytes([]byte("runtime:" + runtimeVersion)), ProtocolSchemaDigest: providerbridge.DigestBytes([]byte("protocol:" + protocolVersion)), MeshToolSchemaDigest: providerbridge.DigestBytes([]byte("mesh-tools.v1")), TranscriptDigest: providerbridge.DigestBytes(eventBytes), Operations: events, Handshake: "success", Start: "success", Stream: "success", Cancel: "cancelled", Teardown: "quiescent", Health: "success", GeneratorVersion: "offline-fixture.v1", GeneratedAt: now.Add(-time.Minute), SourceReferences: []providerbridge.CompatibilitySource{{Reference: "https://evidence.example/compatibility/codex", Digest: providerbridge.DigestBytes([]byte("compatibility-source"))}}}
	if err := compatibility.Seal(); err != nil {
		t.Fatal(err)
	}
	mapping, err := providerbridge.MappingFromCompatibility(compatibility)
	if err != nil {
		t.Fatal(err)
	}
	limits := providerbridge.ExecutionLimits{SchemaVersion: providerbridge.ExecutionLimitsV1, MaxDepth: 1, MaxChildrenPerParent: 1, MaxConcurrentRuns: 1, MaxInputTokens: 1, MaxOutputTokens: 1, MaxWallMS: 1, MaxAttempts: 1, MaxResultBytes: 1, Cost: providerbridge.CostLimit{Kind: "non_monetary", Unit: "token", MaxQuantity: 1}}
	limitsDigest, err := limits.Digest()
	if err != nil {
		t.Fatal(err)
	}
	technical := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, ed25519.SeedSize))
	security := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{2}, ed25519.SeedSize))
	trust := providerbridge.Ed25519TrustBundle{SchemaVersion: providerbridge.Ed25519TrustBundleV1, PublicKeys: map[string]string{"security-ed25519": hex.EncodeToString(security.Public().(ed25519.PublicKey)), "technical-ed25519": hex.EncodeToString(technical.Public().(ed25519.PublicKey))}, TrustedTechnical: []string{"technical-ed25519"}, TrustedSecurity: []string{"security-ed25519"}, Revoked: []string{}}
	evidence := providerbridge.ProviderEvidenceRecord{SchemaVersion: providerbridge.EvidenceRecordV1, Provider: profile.Provider, ProfileID: profile.ID, ProfileRevision: profile.Revision, AuthModality: profile.AuthModality, OfficialURLs: []string{"https://evidence.example/codex"}, RetrievedAt: now.Add(-time.Minute), FreshUntil: now.Add(time.Hour), RuntimeVersion: compatibility.RuntimeVersion, ProtocolVersion: compatibility.ProtocolVersion, Model: profile.Model, ClaimModalities: map[string]string{"official-provider-route": profile.AuthModality}, SourceContentDigest: providerbridge.DigestBytes([]byte(profile.ID + ":source")), RuntimeArtifactDigest: compatibility.RuntimeArtifactDigest, SchemaDigest: compatibility.ProtocolSchemaDigest, CompatibilityRecordDigest: compatibility.Digest, ProtocolSchemaDigest: compatibility.ProtocolSchemaDigest, MeshToolSchemaDigest: compatibility.MeshToolSchemaDigest, EvidenceGeneratorVersion: "offline-fixture.v1"}
	if err := evidence.Seal(); err != nil {
		t.Fatal(err)
	}
	evidence.Approvals = []providerbridge.EvidenceApproval{
		{SchemaVersion: "provider-evidence-approval.v1", Role: "technical", ReviewerKeyID: "technical-ed25519", ProfileID: profile.ID, ProfileRevision: profile.Revision, EvidenceDigest: evidence.Digest, FreshUntil: evidence.FreshUntil, DecisionRef: "decision-tech-candidate", Signature: hex.EncodeToString(ed25519.Sign(technical, []byte(evidence.Digest)))},
		{SchemaVersion: "provider-evidence-approval.v1", Role: "security", ReviewerKeyID: "security-ed25519", ProfileID: profile.ID, ProfileRevision: profile.Revision, EvidenceDigest: evidence.Digest, FreshUntil: evidence.FreshUntil, DecisionRef: "decision-security-candidate", Signature: hex.EncodeToString(ed25519.Sign(security, []byte(evidence.Digest)))},
	}
	profileDTO := ProfileDTO{ID: profile.ID, Provider: profile.Provider, Model: profile.Model, RuntimeKind: profile.RuntimeKind, AuthModality: profile.AuthModality, AccountRef: profile.AccountRef, LocalOnly: profile.LocalOnly, MeshSpawnEnabled: false, ExecutionLimitsDigest: limitsDigest, MappingDigest: mapping.Digest, ProviderEvidenceDigest: evidence.Digest, Revision: profile.Revision, Status: providerbridge.StatusDisabled}
	trustRaw, err := json.Marshal(trust)
	if err != nil {
		t.Fatal(err)
	}
	bundle := Bundle{SchemaVersion: BundleV1, BundleID: "bundle-" + revision, RevisionID: revision, TrustBundleDigest: providerbridge.DigestBytes(trustRaw), Profiles: []ProfileBundle{{Profile: profileDTO, Limits: limits, Mapping: mapping, Compatibility: compatibility, Evidence: evidence, ActivationIntent: false}}}
	if err := bundle.Seal(); err != nil {
		t.Fatal(err)
	}
	if err := validateBundle(bundle, trust, now); err != nil {
		t.Fatalf("candidate bundle invalid: %v", err)
	}
	return bundle, trust
}

func testInstalledBundle(revision string) Bundle {
	bundle := Bundle{
		SchemaVersion:     BundleV1,
		BundleID:          "bundle-" + revision,
		RevisionID:        revision,
		TrustBundleDigest: testDigest("b"),
		Profiles:          []ProfileBundle{{Profile: ProfileDTO{ID: "profile-1"}}},
	}
	_ = bundle.Seal()
	return bundle
}

func addTestRevision(t *testing.T, repo *Repository, bundle Bundle, now time.Time, current bool) Snapshot {
	t.Helper()
	old, err := repo.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	next := cloneSnapshot(old)
	enabled := make(map[string]bool, len(bundle.Profiles))
	for _, profile := range bundle.Profiles {
		enabled[profile.Profile.ID] = false
	}
	next.Revisions[bundle.RevisionID] = Installed{Bundle: bundle, Enabled: enabled, InstalledAt: now}
	if current {
		next.CurrentID = bundle.RevisionID
	}
	if err := repo.CompareAndSwap(context.Background(), old, next); err != nil {
		t.Fatal(err)
	}
	updated, err := repo.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return updated
}

func populateRevokeOperation(op *ProviderLifecycleOperation, association UIAssociation, bundle Bundle, state Snapshot) {
	op.RevisionID = association.RevisionID
	op.BundleDigest = bundle.Digest
	op.TrustDigest = bundle.TrustBundleDigest
	op.BaseVersion = state.Version
	op.BaseCurrentRevision = state.CurrentID
	op.SessionID = association.SessionID
	op.ChannelID = association.ChannelID
	op.RootRunID = association.RootRunID
	op.RunID = association.RunID
	op.MeshSessionID = association.MeshSessionID
	op.AttemptID = association.AttemptID
	op.PeerID = association.PeerID
	op.EndpointID = association.EndpointID
	op.EndpointGeneration = association.EndpointGeneration
	op.EndpointExpiresAt = association.ExpiresAt
	op.AssociationDigest = digestValue(association)
}

func confirmedUIRevoke(op ProviderLifecycleOperation) *UIRevokeTarget {
	return &UIRevokeTarget{EndpointID: op.EndpointID, Generation: op.EndpointGeneration}
}

func TestRepositoryRejectsCorruptionAcrossRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "provider-revisions.enc")
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	repo, err := NewRepository(path, key)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := repo.Load(context.Background()); err != nil || got.CurrentID != "" {
		t.Fatalf("empty=%#v err=%v", got, err)
	}
	if err := repo.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("corrupt"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewRepository(path, key); err == nil {
		t.Fatal("corrupt repository accepted")
	}
}

func TestSelectUIIsImmutableAssociationBoundAndDurable(t *testing.T) {
	now := time.Date(2026, time.August, 30, 13, 0, 0, 0, time.UTC)
	bundle, trust := validCandidateBundle(t, "revision-ui-selection", now)
	bundle.Profiles[0].Profile.MeshSpawnEnabled = true
	bundle.Profiles[0].Profile.Status = providerbridge.StatusCompatible
	bundle.Profiles[0].Profile.AccountRef = "opaque-account-ref.v1:ui-test"
	bundle.Profiles[0].ActivationIntent = true
	if err := bundle.Seal(); err != nil {
		t.Fatal(err)
	}
	if err := validateBundle(bundle, trust, now); err != nil {
		t.Fatalf("selection bundle invalid: %v", err)
	}
	key := bytes.Repeat([]byte{7}, 32)
	repo, err := NewRepository(filepath.Join(t.TempDir(), "selection.enc"), key)
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	service, err := NewService(repo, testAuthority{}, TrustSourceFunc(func(_ context.Context, digest string) (providerbridge.Ed25519TrustBundle, error) {
		if digest != bundle.TrustBundleDigest {
			return providerbridge.Ed25519TrustBundle{}, ErrUnavailable
		}
		return trust, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	service.now = func() time.Time { return now }
	state := addTestRevision(t, repo, bundle, now, true)
	next := cloneSnapshot(state)
	next.Revisions[bundle.RevisionID] = Installed{Bundle: bundle, Trust: trust, Enabled: map[string]bool{bundle.Profiles[0].Profile.ID: true}, InstalledAt: now}
	association := UIAssociation{SessionID: "session-ui", ChannelID: "channel-ui", RootRunID: "root-ui", RunID: "root-ui", MeshSessionID: "mesh-ui", AttemptID: "attempt-ui", PeerID: "peer-ui", EndpointID: "endpoint-ui", EndpointGeneration: 1, RevisionID: bundle.RevisionID, ExpiresAt: now.Add(time.Minute)}
	next.Associations[associationKey(association.SessionID, association.ChannelID)] = association
	if err = repo.CompareAndSwap(context.Background(), state, next); err != nil {
		t.Fatal(err)
	}
	first, replayed, err := service.SelectUI(context.Background(), association, bundle.Profiles[0].Profile.ID, "new-child", bundle.RevisionID)
	if err != nil || replayed || first.BaseRevisionID != bundle.RevisionID || first.AssociationDigest != digestValue(association) {
		t.Fatalf("first selection=%+v replayed=%v err=%v", first, replayed, err)
	}
	if got, replayed, err := service.SelectUI(context.Background(), association, bundle.Profiles[0].Profile.ID, "new-child", bundle.RevisionID); err != nil || !replayed || got != first {
		t.Fatalf("selection replay=%+v replayed=%v err=%v", got, replayed, err)
	}
	after, err := repo.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if after.CurrentID != bundle.RevisionID || len(after.UX.Selections) != 1 {
		t.Fatalf("selection mutated active/current state: %+v", after)
	}
	if _, _, err := service.SelectUI(context.Background(), association, bundle.Profiles[0].Profile.ID, "new-root", "other-revision"); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale base selection err=%v", err)
	}
	association.PeerID = "other-peer"
	if _, _, err := service.SelectUI(context.Background(), association, bundle.Profiles[0].Profile.ID, "clean-fork", bundle.RevisionID); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("foreign association selection err=%v", err)
	}
	if err = repo.Close(); err != nil {
		t.Fatal(err)
	}
	restarted, err := NewRepository(filepath.Join(filepath.Dir(repo.path), filepath.Base(repo.path)), key)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	state, err = restarted.Load(context.Background())
	if err != nil || state.UX.Selections[first.RevisionID] != first {
		t.Fatalf("restart selection=%+v err=%v", state.UX.Selections, err)
	}
}
