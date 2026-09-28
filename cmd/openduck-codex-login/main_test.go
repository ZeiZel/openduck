package main

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"openduck/internal/codexbroker"
)

type fakeClient struct{}

func (fakeClient) Attestation(context.Context) (codexbroker.BoundaryAttestation, error) {
	return codexbroker.BoundaryAttestation{}, nil
}
func (fakeClient) Inventory(context.Context) (codexbroker.Inventory, error) {
	return codexbroker.Inventory{}, nil
}
func (fakeClient) LoginStart(context.Context, codexbroker.LoginStart) (codexbroker.LoginStarted, error) {
	return codexbroker.LoginStarted{LoginID: "l", AuthorizationURL: "https://example.test/device", UserCode: "ABCD-1234"}, nil
}
func (fakeClient) LoginCompleted(_ context.Context, id string) (codexbroker.LoginCompleted, error) {
	return codexbroker.LoginCompleted{LoginID: id, Success: true}, nil
}
func (fakeClient) Turn(context.Context, codexbroker.Turn) (codexbroker.TurnResult, error) {
	return codexbroker.TurnResult{}, nil
}
func (fakeClient) Cancel(context.Context, codexbroker.Cancel) error { return nil }
func (fakeClient) Close(context.Context) error                      { return nil }

func TestLoginEmitsOnlyDeviceData(t *testing.T) {
	var out bytes.Buffer
	if err := runWithClient(context.Background(), fakeClient{}, &out); err != nil {
		t.Fatal(err)
	}
	got := out.String()
	if !strings.Contains(got, "authorization_url") || !strings.Contains(got, "ABCD-1234") || strings.Contains(got, "token") || strings.Contains(got, "auth.json") {
		t.Fatalf("unsafe login output: %q", got)
	}
}

func TestLoginRejectsArbitraryCLIData(t *testing.T) {
	if err := run([]string{"-production-admission", "-authorization-url", "https://evil.test"}, &bytes.Buffer{}); err == nil {
		t.Fatal("arbitrary URL accepted")
	}
}
