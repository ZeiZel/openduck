package macoschannel

import (
	"context"
	"testing"
)

func TestDialerZeroValueIsNotValid(t *testing.T) {
	var d Dialer
	if d.Valid() {
		t.Fatal("zero dialer reported valid")
	}
	if _, err := d.Dial(context.Background()); err == nil {
		t.Fatal("zero dialer dial succeeded")
	}
}
