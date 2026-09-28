package harness

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestDispatchAndStartRejectExpiredLease(t *testing.T) {
	c := must(NewController(context.Background(), &MemoryRepository{}))
	id := "expired"
	r := must(c.IngestSignal(context.Background(), id, testSignal(t)))
	draft := testSpec(t, id, "draft", 1, "")
	r = must(c.DraftSpec(context.Background(), id, r.Version, draft))
	frozen := testSpec(t, id, "frozen", 1, draft.SpecHash)
	r = must(c.FreezeSpec(context.Background(), id, r.Version, frozen))
	w := testWork(t, id, frozen.SpecHash)
	w.Lease.ExpiresAt = time.Now().Add(-time.Second).UTC()
	w = seal(t, w)
	a := testWorker(t, w)
	b := testBinding(t, id, w, a)
	if _, e := c.Dispatch(context.Background(), id, r.Version, w, a, b); !errors.Is(e, ErrLeaseExpired) {
		t.Fatalf("dispatch error = %v", e)
	}
	r = must(c.IngestSignal(context.Background(), "running", testSignal(t)))
	r = must(c.DraftSpec(context.Background(), "running", r.Version, testSpec(t, "running", "draft", 1, "")))
	r = must(c.FreezeSpec(context.Background(), "running", r.Version, testSpec(t, "running", "frozen", 1, r.Spec.SpecHash)))
	w = testWork(t, "running", r.Spec.SpecHash)
	w.Lease.ExpiresAt = time.Now().Add(20 * time.Millisecond).UTC()
	w = seal(t, w)
	a = testWorker(t, w)
	b = testBinding(t, "running", w, a)
	r = must(c.Dispatch(context.Background(), "running", r.Version, w, a, b))
	time.Sleep(30 * time.Millisecond)
	if _, e := c.StartWork(context.Background(), "running", r.Version); !errors.Is(e, ErrLeaseExpired) {
		t.Fatalf("start error = %v", e)
	}
}
