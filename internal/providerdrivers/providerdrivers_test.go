package providerdrivers_test

import (
	"context"
	"errors"
	"testing"

	"openduck/internal/providerdaemon"
	"openduck/internal/providerdrivers/claude"
	"openduck/internal/providerdrivers/codex"
	"openduck/internal/providerdrivers/deepseek"
	"openduck/internal/providerdrivers/kimi"
	"openduck/internal/providerdrivers/qwen"
)

type bridge struct{ starts, reconciles, stops int }

func (b *bridge) Start(context.Context, providerdaemon.Request) (string, error) {
	b.starts++
	return "session", nil
}
func (b *bridge) Reconcile(context.Context, providerdaemon.Receipt) (string, providerdaemon.State, error) {
	b.reconciles++
	return "session", providerdaemon.Running, nil
}
func (b *bridge) Stop(context.Context, string) error { b.stops++; return nil }

func exercise(t *testing.T, value providerdaemon.Bridge) {
	t.Helper()
	if _, err := value.Start(context.Background(), providerdaemon.Request{}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := value.Reconcile(context.Background(), providerdaemon.Receipt{}); err != nil {
		t.Fatal(err)
	}
	if err := value.Stop(context.Background(), "session"); err != nil {
		t.Fatal(err)
	}
}

func TestOfficialDriversAreNarrowPassThroughs(t *testing.T) {
	for name, makeBridge := range map[string]func(providerdaemon.Bridge) providerdaemon.Bridge{
		"codex":  func(inner providerdaemon.Bridge) providerdaemon.Bridge { return codex.OfficialBridge{Inner: inner} },
		"claude": func(inner providerdaemon.Bridge) providerdaemon.Bridge { return claude.OfficialBridge{Inner: inner} },
		"qwen":   func(inner providerdaemon.Bridge) providerdaemon.Bridge { return qwen.OfficialBridge{Inner: inner} },
		"kimi":   func(inner providerdaemon.Bridge) providerdaemon.Bridge { return kimi.OfficialBridge{Inner: inner} },
	} {
		t.Run(name, func(t *testing.T) {
			inner := &bridge{}
			exercise(t, makeBridge(inner))
			if inner.starts != 1 || inner.reconciles != 1 || inner.stops != 1 {
				t.Fatalf("counts=%+v", inner)
			}
			if _, err := makeBridge(nil).Start(context.Background(), providerdaemon.Request{}); !errors.Is(err, providerdaemon.ErrUnavailable) {
				t.Fatal(err)
			}
		})
	}
}

func TestDeepSeekIsAPIOnlyAndNeverTreatsSubscriptionAsAccess(t *testing.T) {
	inner := &bridge{}
	api := deepseek.OfficialBridge{Inner: inner, APIConfigured: true}
	exercise(t, api)
	for name, value := range map[string]deepseek.OfficialBridge{
		"subscription": {Inner: inner, APIConfigured: true, Subscription: true},
		"no-api":       {Inner: inner},
	} {
		t.Run(name, func(t *testing.T) {
			before := inner.starts
			if _, err := value.Start(context.Background(), providerdaemon.Request{}); err == nil {
				t.Fatal("start accepted")
			}
			if inner.starts != before {
				t.Fatal("denied route reached inner bridge")
			}
		})
	}
	subscription := deepseek.OfficialBridge{Inner: inner, APIConfigured: true, Subscription: true}
	if _, _, err := subscription.Reconcile(context.Background(), providerdaemon.Receipt{}); !errors.Is(err, deepseek.ErrSubscriptionUnsupported) {
		t.Fatal(err)
	}
	if err := subscription.Stop(context.Background(), "session"); err == nil {
		t.Fatal("subscription stop reached provider")
	}
}
