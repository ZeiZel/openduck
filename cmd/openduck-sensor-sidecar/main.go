// Command openduck-sensor-sidecar is a bounded stdio bridge for a read-only
// local sensor. The sensor supplies synthetic InboundEvent JSON on stdin;
// this process obtains the signing key from Keychain and talks only to the
// fixed loopback Controller endpoint. No key or raw envelope is printed.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"openduck/internal/core"
	"openduck/internal/sensor"
	"os"
	"time"
)

func main() {
	if err := run(); err != nil {
		os.Exit(1)
	}
}

func run() error {
	fs := flag.NewFlagSet("openduck-sensor-sidecar", flag.ContinueOnError)
	endpoint := fs.String("controller", "http://127.0.0.1:8788/v1/sensor/events", "fixed local Controller endpoint")
	replayCanary := fs.Bool("replay-canary", false, "submit one synthetic envelope twice and report replay rejection")
	replayAfter := fs.Duration("replay-after", 0, "bounded delay before exact replay (operational restart canary)")
	if err := fs.Parse(os.Args[1:]); err != nil || *endpoint != "http://127.0.0.1:8788/v1/sensor/events" {
		return errors.New("invalid controller endpoint")
	}
	if *replayAfter < 0 || *replayAfter > 15*time.Second || (*replayAfter > 0 && !*replayCanary) {
		return errors.New("invalid replay delay")
	}
	master, err := (core.MacOSKeychainProvider{Service: "openduck", Account: "sensor-hmac"}).Key(context.Background())
	if err != nil {
		return errors.New("sensor key unavailable")
	}
	defer zero(master)
	client, err := sensor.NewClient(master, *endpoint)
	if err != nil {
		return err
	}
	defer client.Close()
	dec := json.NewDecoder(io.LimitReader(os.Stdin, 64<<10))
	enc := json.NewEncoder(os.Stdout)
	for {
		var event core.InboundEvent
		err := dec.Decode(&event)
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return errors.New("invalid sensor input")
		}
		if *replayCanary {
			ack, rejected, err := client.DurableReplayCanary(context.Background(), event, *replayAfter)
			if err != nil || !rejected {
				return errors.New("sensor replay canary failed")
			}
			out := map[string]any{"schema_version": "sensor-replay-canary.v1", "accepted": ack["accepted"], "task_id": ack["task_id"], "state": ack["state"], "replay_rejected": true}
			if err := enc.Encode(out); err != nil {
				return err
			}
			// A replay canary is deliberately single-event.
			return nil
		}
		ack, err := client.Send(context.Background(), event)
		if err != nil {
			return err
		}
		if err := enc.Encode(ack); err != nil {
			return err
		}
	}
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
