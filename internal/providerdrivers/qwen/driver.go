package qwen

import (
	"context"
	"openduck/internal/providerdaemon"
)

type OfficialBridge struct{ Inner providerdaemon.Bridge }

func (b OfficialBridge) Start(c context.Context, r providerdaemon.Request) (string, error) {
	if b.Inner == nil {
		return "", providerdaemon.ErrUnavailable
	}
	return b.Inner.Start(c, r)
}
func (b OfficialBridge) Reconcile(c context.Context, r providerdaemon.Receipt) (string, providerdaemon.State, error) {
	if b.Inner == nil {
		return "", providerdaemon.Uncertain, providerdaemon.ErrUnavailable
	}
	return b.Inner.Reconcile(c, r)
}
func (b OfficialBridge) Stop(c context.Context, s string) error {
	if b.Inner == nil {
		return providerdaemon.ErrUnavailable
	}
	return b.Inner.Stop(c, s)
}
