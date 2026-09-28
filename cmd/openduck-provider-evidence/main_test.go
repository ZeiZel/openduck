package main

import "testing"

func TestHashIsStable(t *testing.T) {
	if got := hash([]byte("sanitized")); got != "sha256:44d8b78bec6ce60168d0849c40fd060d7ddf8d50d9194d99ce1f1240d84f7cbd" {
		t.Fatal(got)
	}
}
