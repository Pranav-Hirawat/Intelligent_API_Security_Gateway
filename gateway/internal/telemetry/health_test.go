package telemetry

import (
	"context"
	"sync"
	"testing"
	"time"
)

type captureHealth struct {
	mu   sync.Mutex
	recs []Health
	got  chan struct{}
}

func (c *captureHealth) WriteEvent(_ context.Context, rec Health) error {
	c.mu.Lock()
	c.recs = append(c.recs, rec)
	c.mu.Unlock()
	select {
	case c.got <- struct{}{}:
	default:
	}
	return nil
}

func (c *captureHealth) all() []Health {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]Health, len(c.recs))
	copy(out, c.recs)
	return out
}

type fakeQueue struct {
	dropped uint64
	depth   int
	cap     int
}

func (f fakeQueue) Dropped() uint64 { return f.dropped }
func (f fakeQueue) Depth() int      { return f.depth }
func (f fakeQueue) Capacity() int   { return f.cap }

type fixedInFlight int64

func (f fixedInFlight) InFlight() int64 { return int64(f) }

// The sequence is what proves the gateway was up for a whole window. A gap in
// it means a window is short for a reason that has nothing to do with the
// traffic in it, which otherwise reads as a quiet minute.
func TestHeartbeatSequenceIncrementsWithoutGaps(t *testing.T) {
	sink := &captureHealth{got: make(chan struct{}, 8)}
	stop := make(chan struct{})
	defer close(stop)

	(&Heartbeat{Writer: sink, Interval: 5 * time.Millisecond}).Start(stop)

	deadline := time.After(2 * time.Second)
	for len(sink.all()) < 3 {
		select {
		case <-sink.got:
		case <-deadline:
			t.Fatalf("only %d heartbeats arrived", len(sink.all()))
		}
	}

	for i, rec := range sink.all()[:3] {
		if rec.Seq != int64(i+1) {
			t.Fatalf("heartbeat %d has seq %d", i, rec.Seq)
		}
		if rec.At.IsZero() {
			t.Fatalf("heartbeat %d has no timestamp", i)
		}
	}
}

// The whole reason the heartbeat exists: telemetry loss is invisible in the
// event stream, because the records that would show it are the ones that were
// lost. AsyncWriter.Dropped() has existed and gone unread; this is what reads
// it.
func TestHeartbeatReportsDroppedTelemetryAndQueueDepth(t *testing.T) {
	sink := &captureHealth{got: make(chan struct{}, 4)}
	beat := &Heartbeat{
		Writer:   sink,
		Events:   fakeQueue{dropped: 12, depth: 3, cap: 1024},
		Arrivals: fakeQueue{dropped: 7, depth: 1, cap: 512},
		Requests: fixedInFlight(4),
	}

	rec := beat.sample(1, time.Now())
	if rec.DroppedTotal != 12 || rec.QueueLen != 3 || rec.QueueCap != 1024 {
		t.Fatalf("event queue not reported: %+v", rec)
	}
	if rec.ArrivalsDroppedTotal != 7 || rec.ArrivalQueueLen != 1 || rec.ArrivalQueueCap != 512 {
		t.Fatalf("arrival queue not reported: %+v", rec)
	}
	if rec.InFlight != 4 {
		t.Fatalf("in flight = %d, want 4", rec.InFlight)
	}
}

// Every input is optional, and the sequence alone still answers "was the
// gateway up". A heartbeat that panicked on a missing queue would take the
// gateway down for the sake of a diagnostic.
func TestHeartbeatSurvivesMissingInputs(t *testing.T) {
	rec := (&Heartbeat{}).sample(9, time.Now())
	if rec.Seq != 9 || rec.DroppedTotal != 0 || rec.InFlight != 0 {
		t.Fatalf("unexpected sample: %+v", rec)
	}
	// No writer means no goroutine, and no panic either.
	(&Heartbeat{}).Start(make(chan struct{}))
}

// A real AsyncWriter satisfies QueueStats. Without this the heartbeat could
// compile against fakes forever while never fitting the thing it reports on.
func TestAsyncWriterIsAQueueStats(t *testing.T) {
	var _ QueueStats = NewNamedAsyncWriter[Event](&captureWriter{}, 4, time.Second, "")
	var _ QueueStats = NewNamedAsyncWriter[Arrival](&captureArrivals{}, 4, time.Second, "")
	var _ InFlightSource = &Recorder{}
}
