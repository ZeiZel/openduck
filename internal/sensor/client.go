package sensor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"openduck/internal/core"
	"strings"
	"time"
)

var ErrControllerRejected = errors.New("sensor controller rejected event")

// Send posts an authenticated envelope only to the fixed loopback Controller.
func (c *Client) Send(ctx context.Context, event core.InboundEvent) (map[string]any, error) {
	e, err := c.Sign(event)
	if err != nil {
		return nil, err
	}
	return c.sendEnvelope(ctx, e)
}

// ReplayCanary signs once, submits the exact same authenticated envelope twice,
// and reports only whether the second request was rejected. It is intended for
// bounded synthetic operational verification; the raw envelope and signature
// are never returned or printed.
func (c *Client) ReplayCanary(ctx context.Context, event core.InboundEvent) (map[string]any, bool, error) {
	return c.DurableReplayCanary(ctx, event, 0)
}

// DurableReplayCanary is identical to ReplayCanary but waits before the exact
// replay so an operator can restart Controller during the bounded interval.
func (c *Client) DurableReplayCanary(ctx context.Context, event core.InboundEvent, beforeReplay time.Duration) (map[string]any, bool, error) {
	e, err := c.Sign(event)
	if err != nil {
		return nil, false, err
	}
	ack, err := c.sendEnvelope(ctx, e)
	if err != nil {
		return nil, false, err
	}
	if beforeReplay > 0 {
		timer := time.NewTimer(beforeReplay)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return nil, false, ctx.Err()
		case <-timer.C:
		}
	}
	_, replayErr := c.sendEnvelope(ctx, e)
	replayed := errors.Is(replayErr, ErrControllerRejected) && strings.Contains(replayErr.Error(), "status 401")
	return ack, replayed, nil
}

func (c *Client) sendEnvelope(ctx context.Context, e Envelope) (map[string]any, error) {
	b, err := json.Marshal(e)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base, bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("%w: status %d", ErrControllerRejected, resp.StatusCode)
	}
	return out, nil
}
