package deepseek

import (
	"context"
	"errors"
	"openduck/internal/providerdaemon"
)

var ErrSubscriptionUnsupported = errors.New("deepseek subscription is unsupported; API access required")

type OfficialBridge struct {
	Inner         providerdaemon.Bridge
	APIConfigured bool
	Subscription  bool
}

func (b OfficialBridge) Start(c context.Context, r providerdaemon.Request) (string, error) {
	if b.Subscription {
		return "", ErrSubscriptionUnsupported
	}
	if !b.APIConfigured || b.Inner == nil {
		return "", providerdaemon.ErrUnavailable
	}
	return b.Inner.Start(c, r)
}
func (b OfficialBridge) Reconcile(c context.Context, r providerdaemon.Receipt) (string, providerdaemon.State, error) {
	if b.Subscription {
		return "", providerdaemon.Uncertain, ErrSubscriptionUnsupported
	}
	if !b.APIConfigured || b.Inner == nil {
		return "", providerdaemon.Uncertain, providerdaemon.ErrUnavailable
	}
	return b.Inner.Reconcile(c, r)
}
func (b OfficialBridge) Stop(c context.Context, s string) error {
	if b.Subscription || !b.APIConfigured || b.Inner == nil {
		return providerdaemon.ErrUnavailable
	}
	return b.Inner.Stop(c, s)
}
