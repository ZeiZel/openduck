package core

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
)

// DurablePseudonymizer derives stable tokens and persists only the reversible
// token mapping in the separately encrypted local store.
type DurablePseudonymizer struct {
	key   []byte
	store *PersistentPseudonymStore
}

func NewDurablePseudonymizer(key []byte, store *PersistentPseudonymStore) (*DurablePseudonymizer, error) {
	if len(key) != 32 || store == nil {
		return nil, errors.New("durable pseudonymizer requires 32-byte key and store")
	}
	return &DurablePseudonymizer{key: append([]byte(nil), key...), store: store}, nil
}

func (p *DurablePseudonymizer) Token(scope, value string) (string, error) {
	if strings.TrimSpace(scope) == "" || value == "" {
		return "", errors.New("scope and value required")
	}
	m := hmac.New(sha256.New, p.key)
	_, _ = m.Write([]byte(scope + "\x00" + value))
	token := "P-" + strings.ToUpper(hex.EncodeToString(m.Sum(nil))[:32])
	ctx := context.Background()
	if old, ok, err := p.store.Get(ctx, scope, token); err != nil {
		return "", err
	} else if ok {
		if old != value {
			return "", errors.New("pseudonym collision")
		}
		return token, nil
	}
	if err := p.store.Put(ctx, scope, token, value); err != nil {
		return "", err
	}
	return token, nil
}

func (p *DurablePseudonymizer) SessionRef(owner, purpose, adapter, account, channel, conversation string) (string, error) {
	t, err := p.Token(strings.Join([]string{owner, purpose, adapter, account, channel}, "/"), conversation)
	if err != nil {
		return "", err
	}
	return "psn_" + t[2:], nil
}

func (p *DurablePseudonymizer) RehydrateResponse(ctx context.Context, scope, text string) (string, error) {
	return p.store.RehydrateResponse(ctx, scope, text)
}
func (p *DurablePseudonymizer) PurgeScope(ctx context.Context, scope string) error {
	return p.store.PurgeScope(ctx, scope)
}
func (p *DurablePseudonymizer) Purge(ctx context.Context) error { return p.store.Purge(ctx) }
