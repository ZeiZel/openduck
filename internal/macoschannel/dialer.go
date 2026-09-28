package macoschannel

import "context"

// Dialer is the only production outbound channel factory. It captures the
// validated socket/release contract and exposes no raw connection dial hook.
type Dialer struct {
	cfg         Config
	initialized bool
}

func NewDialer(cfg Config) (*Dialer, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	if cfg.KeySource == nil {
		return nil, ErrUnavailable
	}
	return &Dialer{cfg: cfg, initialized: true}, nil
}

// Valid distinguishes a constructor-produced dialer from a forgeable zero
// value. The configuration remains private and is still validated by Dial.
func (d *Dialer) Valid() bool { return d != nil && d.initialized }

func (d *Dialer) Dial(ctx context.Context) (Conn, error) {
	if !d.Valid() {
		return nil, ErrUnavailable
	}
	return Dial(ctx, d.cfg)
}
