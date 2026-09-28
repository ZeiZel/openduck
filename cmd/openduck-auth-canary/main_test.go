package main

import (
	"context"
	"testing"
	"time"
)

func TestInvalidCanaryArgumentsFailClosed(t *testing.T) {
	if err := runCanary(context.Background(), "", "", time.Second); err == nil {
		t.Fatal("expected invalid helper")
	}
}
